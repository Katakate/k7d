//! Integration test: memory snapshot.
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

#[test]
fn test_snapshot_creates_valid_files() {
    let _ = env_logger::builder().is_test(true).try_init();

    let mut vm = create_test_vm();
    vm.start().unwrap();
    let mut agent = vm
        .connect_agent(Duration::from_secs(90))
        .expect("should connect to agent");

    // Write some state inside VM
    agent
        .exec(&["sh", "-c", "echo 'snapshot-test' > /tmp/marker"])
        .unwrap();

    let snapshot_dir = tempfile::tempdir().unwrap();
    vm.snapshot(snapshot_dir.path()).unwrap();

    // Verify snapshot files exist and are non-empty
    assert!(snapshot_dir.path().join("memory.bin").exists());
    assert!(snapshot_dir.path().join("cpu.json").exists());
    assert!(snapshot_dir.path().join("devices.json").exists());
    assert!(snapshot_dir.path().join("metadata.json").exists());

    let mem_size = std::fs::metadata(snapshot_dir.path().join("memory.bin"))
        .unwrap()
        .len();
    assert!(mem_size > 0, "memory dump should be non-empty");
    assert_eq!(
        mem_size,
        256 * 1024 * 1024,
        "memory dump should be exactly 256MB"
    );

    let cpu_json = std::fs::read_to_string(snapshot_dir.path().join("cpu.json")).unwrap();
    let cpus: serde_json::Value = serde_json::from_str(&cpu_json).unwrap();
    // Cpu.json is an array, one entry per vCPU.
    let cpus_arr = cpus.as_array().expect("cpu.json should be an array");
    assert_eq!(cpus_arr.len(), 1, "1-vCPU VM captures one CpuState");
    let cpu = &cpus_arr[0];
    assert!(cpu.get("regs").is_some(), "cpu.json should have regs");
    assert!(cpu.get("sregs").is_some(), "cpu.json should have sregs");
    assert!(cpu.get("fpu").is_some(), "cpu.json should have fpu");
    let msrs = cpu.get("msrs").expect("cpu.json should have msrs");
    assert!(msrs.is_array(), "msrs should be an array");
    let msrs_arr = msrs.as_array().unwrap();
    assert!(!msrs_arr.is_empty(), "should have at least one MSR saved");

    let devices_json = std::fs::read_to_string(snapshot_dir.path().join("devices.json")).unwrap();
    let devices: Vec<serde_json::Value> = serde_json::from_str(&devices_json).unwrap();
    assert!(!devices.is_empty(), "should have at least one device");

    let metadata_json = std::fs::read_to_string(snapshot_dir.path().join("metadata.json")).unwrap();
    let metadata: serde_json::Value = serde_json::from_str(&metadata_json).unwrap();
    assert_eq!(
        metadata["memory_size_bytes"],
        256 * 1024 * 1024,
        "metadata should record memory size"
    );

    vm.shutdown();
}

#[test]
fn test_snapshot_pause_and_resume() {
    let _ = env_logger::builder().is_test(true).try_init();

    let mut vm = create_test_vm();
    vm.start().unwrap();
    let mut agent = vm
        .connect_agent(Duration::from_secs(90))
        .expect("should connect to agent");

    // Write state before snapshot
    agent
        .exec(&["sh", "-c", "echo 'before-snapshot' > /tmp/marker"])
        .unwrap();

    // Snapshot (pauses and resumes automatically)
    let snapshot_dir = tempfile::tempdir().unwrap();
    vm.snapshot(snapshot_dir.path()).unwrap();

    // VM should be running again after snapshot — reconnect agent (vsock may need new connection)
    let mut agent2 = vm
        .connect_agent(Duration::from_secs(30))
        .expect("should reconnect after resume");

    // State should still be there
    let result = agent2.exec(&["cat", "/tmp/marker"]).unwrap();
    assert_eq!(result.stdout.trim(), "before-snapshot");

    vm.shutdown();
}

#[test]
fn test_snapshot_completes_under_500ms() {
    let _ = env_logger::builder().is_test(true).try_init();

    let mut vm = create_test_vm();
    vm.start().unwrap();
    let _agent = vm
        .connect_agent(Duration::from_secs(90))
        .expect("should connect to agent");

    let snapshot_dir = tempfile::tempdir().unwrap();
    let start = Instant::now();
    vm.snapshot(snapshot_dir.path()).unwrap();
    let elapsed = start.elapsed();

    println!("snapshot latency: {elapsed:?}");
    assert!(
        elapsed < Duration::from_millis(500),
        "snapshot of 256MB VM should be <500ms, was {elapsed:?}"
    );

    vm.shutdown();
}
