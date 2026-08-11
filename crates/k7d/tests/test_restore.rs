//! Integration test for Milestone 8: CoW mmap restore.
//! Requires KVM, /dev/vhost-vsock, built guest kernel, and built initramfs.

use std::path::PathBuf;
use std::time::{Duration, Instant};

use k7d::vm::Vm;

fn workspace_path(relative: &str) -> PathBuf {
    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    manifest_dir
        .parent()
        .and_then(|p| p.parent())
        .expect("workspace root")
        .join(relative)
}

fn create_test_vm() -> Vm {
    let kernel = workspace_path("guest/kernel/vmlinux");
    let initrd = workspace_path("guest/rootfs/initramfs.cpio.gz");

    assert!(kernel.exists(), "guest kernel not found at {kernel:?}");
    assert!(initrd.exists(), "initramfs not found at {initrd:?}");

    Vm::builder()
        .kernel(&kernel)
        .initrd(&initrd)
        .memory_mb(256)
        .vsock(true)
        .build()
        .expect("VM should create")
}

/// Helper: create a booted VM, write state, snapshot, shut down. Returns snapshot dir.
fn create_snapshot_of_booted_vm() -> tempfile::TempDir {
    let mut vm = create_test_vm();
    vm.start().unwrap();
    let mut agent = vm
        .connect_agent(Duration::from_secs(90))
        .expect("should connect to agent");

    agent
        .exec(&["sh", "-c", "echo 'restore-test' > /tmp/marker"])
        .unwrap();

    let snapshot_dir = tempfile::tempdir().unwrap();
    vm.snapshot(snapshot_dir.path()).unwrap();
    vm.shutdown();

    snapshot_dir
}

#[test]
fn test_restore_from_snapshot_preserves_state() {
    let _ = env_logger::builder().is_test(true).try_init();

    let snapshot_dir = create_snapshot_of_booted_vm();

    // Restore from snapshot
    let mut restored = Vm::restore(snapshot_dir.path()).unwrap();
    assert!(restored.is_restored(), "VM should be marked as restored");

    restored.start().unwrap();
    let mut agent = restored
        .connect_agent(Duration::from_secs(30))
        .expect("should connect to restored agent");

    // Verify state was preserved
    let marker = agent.exec(&["cat", "/tmp/marker"]).unwrap();
    assert_eq!(marker.stdout.trim(), "restore-test");

    restored.shutdown();
}

#[test]
fn test_restore_vsock_works() {
    let _ = env_logger::builder().is_test(true).try_init();

    let snapshot_dir = create_snapshot_of_booted_vm();

    let mut restored = Vm::restore(snapshot_dir.path()).unwrap();
    restored.start().unwrap();

    // Give the guest time to process the TRANSPORT_RESET event
    // and re-establish the vsock listener.
    std::thread::sleep(Duration::from_secs(2));

    let mut agent = restored
        .connect_agent(Duration::from_secs(30))
        .expect("should connect via vsock");

    let pong = agent.ping().unwrap();
    assert_eq!(pong.version, "0.1.0");

    let exec = agent.exec(&["echo", "hello-from-restored"]).unwrap();
    assert_eq!(exec.exit_code, 0);
    assert_eq!(exec.stdout.trim(), "hello-from-restored");

    restored.shutdown();
}

#[test]
fn test_restore_new_cid() {
    let _ = env_logger::builder().is_test(true).try_init();

    let snapshot_dir = create_snapshot_of_booted_vm();

    let mut restored1 = Vm::restore(snapshot_dir.path()).unwrap();
    let mut restored2 = Vm::restore(snapshot_dir.path()).unwrap();

    let cid1 = restored1.guest_cid();
    let cid2 = restored2.guest_cid();

    assert_ne!(cid1, cid2, "each restored VM should get a unique CID");
    assert_ne!(cid1, 3, "restored VM should not reuse the default CID");
    assert_ne!(cid2, 3, "restored VM should not reuse the default CID");

    // Both should be connectable
    restored1.start().unwrap();
    let mut agent1 = restored1.connect_agent(Duration::from_secs(30)).unwrap();
    agent1.ping().unwrap();
    restored1.shutdown();

    restored2.start().unwrap();
    let mut agent2 = restored2.connect_agent(Duration::from_secs(30)).unwrap();
    agent2.ping().unwrap();
    restored2.shutdown();
}

#[test]
fn test_restore_memory_independence() {
    let _ = env_logger::builder().is_test(true).try_init();

    let snapshot_dir = create_snapshot_of_booted_vm();

    // Restore two VMs from the same snapshot
    let mut vm1 = Vm::restore(snapshot_dir.path()).unwrap();
    vm1.start().unwrap();
    let mut agent1 = vm1.connect_agent(Duration::from_secs(30)).unwrap();

    // Write to VM1
    agent1
        .exec(&["sh", "-c", "echo 'vm1-only' > /tmp/vm1-marker"])
        .unwrap();

    // Restore a second VM
    let mut vm2 = Vm::restore(snapshot_dir.path()).unwrap();
    vm2.start().unwrap();
    let mut agent2 = vm2.connect_agent(Duration::from_secs(30)).unwrap();

    // VM2 should NOT have the file written by VM1 (CoW independence)
    let result = agent2.exec(&["cat", "/tmp/vm1-marker"]).unwrap();
    assert_ne!(result.exit_code, 0, "vm2 should not see vm1's writes");

    // Both should still have the original marker
    let marker1 = agent1.exec(&["cat", "/tmp/marker"]).unwrap();
    assert_eq!(marker1.stdout.trim(), "restore-test");

    let marker2 = agent2.exec(&["cat", "/tmp/marker"]).unwrap();
    assert_eq!(marker2.stdout.trim(), "restore-test");

    vm1.shutdown();
    vm2.shutdown();
}

#[test]
fn test_restore_can_be_resnapshotted() {
    let _ = env_logger::builder().is_test(true).try_init();

    let snapshot_dir = create_snapshot_of_booted_vm();

    // Restore → modify → snapshot again → restore from second snapshot
    let mut vm1 = Vm::restore(snapshot_dir.path()).unwrap();
    vm1.start().unwrap();
    let mut agent1 = vm1.connect_agent(Duration::from_secs(30)).unwrap();

    agent1
        .exec(&["sh", "-c", "echo 'second-gen' > /tmp/gen2"])
        .unwrap();

    let snapshot2 = tempfile::tempdir().unwrap();
    vm1.snapshot(snapshot2.path()).unwrap();
    vm1.shutdown();

    // Restore from second-generation snapshot
    let mut vm2 = Vm::restore(snapshot2.path()).unwrap();
    vm2.start().unwrap();
    let mut agent2 = vm2.connect_agent(Duration::from_secs(30)).unwrap();

    let gen2 = agent2.exec(&["cat", "/tmp/gen2"]).unwrap();
    assert_eq!(gen2.stdout.trim(), "second-gen");

    // Original marker should also be there
    let marker = agent2.exec(&["cat", "/tmp/marker"]).unwrap();
    assert_eq!(marker.stdout.trim(), "restore-test");

    vm2.shutdown();
}

/// internal notes: a pre-17b on-disk snapshot — `cpu.json`
/// holding a single bare `CpuState` object (no `lapic`/`mp_state`
/// fields) and the LAPIC stored VM-scoped in `irqchip.json` — still
/// restores correctly. Synthesized by down-converting a fresh
/// snapshot to the old shape.
#[test]
fn test_legacy_snapshot_readable() {
    let _ = env_logger::builder().is_test(true).try_init();

    let snapshot_dir = create_snapshot_of_booted_vm();

    // Down-convert cpu.json: [state] → bare object without the 17b
    // per-vCPU fields, moving the LAPIC into irqchip.json's legacy
    // VM-scoped slot (exactly what a pre-17b snapshot looks like).
    let cpu_path = snapshot_dir.path().join("cpu.json");
    let cpu_json: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&cpu_path).unwrap()).unwrap();
    let states = cpu_json.as_array().expect("17b cpu.json is an array");
    assert_eq!(states.len(), 1, "single-vCPU snapshot expected");
    let mut state = states[0].clone();
    let obj = state.as_object_mut().unwrap();
    let lapic = obj.remove("lapic").expect("17b snapshots carry lapic");
    obj.remove("mp_state");
    std::fs::write(&cpu_path, serde_json::to_string_pretty(&state).unwrap()).unwrap();

    let irqchip_path = snapshot_dir.path().join("irqchip.json");
    let mut irqchip: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&irqchip_path).unwrap()).unwrap();
    irqchip
        .as_object_mut()
        .unwrap()
        .insert("lapic".into(), lapic);
    std::fs::write(
        &irqchip_path,
        serde_json::to_string_pretty(&irqchip).unwrap(),
    )
    .unwrap();

    // The legacy-shape snapshot restores like any other.
    let mut restored = Vm::restore(snapshot_dir.path()).expect("legacy snapshot must restore");
    assert_eq!(restored.vcpu_count(), 1);
    restored.start().unwrap();
    let mut agent = restored
        .connect_agent(Duration::from_secs(30))
        .expect("agent should connect on the legacy-restored VM");
    let marker = agent.exec(&["cat", "/tmp/marker"]).unwrap();
    assert_eq!(marker.stdout.trim(), "restore-test");
    restored.shutdown();
}

#[test]
fn test_restore_latency_under_budget() {
    let _ = env_logger::builder().is_test(true).try_init();

    let snapshot_dir = create_snapshot_of_booted_vm();

    // Measure just the restore (mmap + KVM setup), NOT agent reconnect
    let start = Instant::now();
    let mut vm = Vm::restore(snapshot_dir.path()).unwrap();
    vm.start().unwrap();
    let elapsed = start.elapsed();

    println!("restore latency (mmap + KVM + start): {elapsed:?}");
    assert!(
        elapsed < Duration::from_millis(10),
        "restore should be <10ms, was {elapsed:?}"
    );

    // Verify VM is actually running
    let mut agent = vm.connect_agent(Duration::from_secs(30)).unwrap();
    agent.ping().unwrap();

    vm.shutdown();
}
