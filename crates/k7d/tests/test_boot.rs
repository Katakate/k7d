//! Integration test for Milestone 1: Boot a VM and see serial output.
//! Requires KVM (/dev/kvm) and a built guest kernel at guest/kernel/vmlinux.

use std::path::PathBuf;
use std::time::Duration;

use k7d::vm::Vm;

/// Resolve a path relative to the workspace root (two levels up from crate dir).
fn workspace_path(relative: &str) -> PathBuf {
    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    manifest_dir
        .parent()
        .and_then(|p| p.parent())
        .expect("workspace root")
        .join(relative)
}

#[test]
fn test_vm_boots_and_prints_to_serial() {
    let _ = env_logger::builder().is_test(true).try_init();

    let kernel = workspace_path("guest/kernel/vmlinux");
    assert!(
        kernel.exists(),
        "guest kernel not found at {kernel:?} — run `make build-guest-kernel` on the node first"
    );

    let mut vm = Vm::builder()
        .kernel(&kernel)
        .memory_mb(256)
        .build()
        .expect("VM should create");

    vm.start().expect("VM should start");

    let output = vm.serial_output(Duration::from_secs(30));
    assert!(
        output.contains("Linux version"),
        "kernel should boot — serial output:\n{}",
        &output[..output.len().min(2000)]
    );
    assert!(
        output.contains("Kernel panic") || output.contains("Freeing"),
        "kernel should reach init — serial output (last 2000 chars):\n{}",
        &output[output.len().saturating_sub(2000)..]
    );

    vm.shutdown();
}

/// internal notes: a 2-vCPU VM boots with both CPUs online — the guest
/// discovers the second CPU from the MP table (ACPI is compiled out)
/// and brings it up via INIT/SIPI. The CPU count through the agent
/// must report 2, both vCPU threads must publish kernel TIDs, and
/// teardown must join both run-loop threads.
#[test]
fn test_boot_multi_vcpu() {
    let _ = env_logger::builder().is_test(true).try_init();

    let kernel = workspace_path("guest/kernel/vmlinux");
    let initrd = workspace_path("guest/rootfs/initramfs.cpio.gz");
    assert!(kernel.exists(), "guest kernel not found at {kernel:?}");
    assert!(initrd.exists(), "initramfs not found at {initrd:?}");

    let mut vm = Vm::builder()
        .kernel(&kernel)
        .initrd(&initrd)
        .memory_mb(256)
        .vcpus(2)
        .vsock(true)
        .build()
        .expect("2-vCPU VM should build");

    vm.start().expect("VM should start");

    // Both run-loop threads publish their kernel TIDs.
    let tids = vm
        .vcpu_kernel_tids(Duration::from_secs(5))
        .expect("both vCPU threads should publish TIDs");
    assert_eq!(tids.len(), 2, "expected 2 vCPU kernel TIDs, got {tids:?}");
    assert!(tids[0] != tids[1], "vCPU TIDs must be distinct: {tids:?}");

    let mut agent = vm
        .connect_agent(Duration::from_secs(90))
        .expect("agent should connect on a 2-vCPU guest");

    // The busybox initramfs has no `nproc`; count CPUs from /proc.
    let nproc = agent
        .exec(&["sh", "-c", "grep -c ^processor /proc/cpuinfo"])
        .expect("cpu count should run");
    assert_eq!(nproc.exit_code, 0);
    assert_eq!(
        nproc.stdout.trim(),
        "2",
        "guest must see 2 CPUs (MP table + SMP bring-up); serial:\n{}",
        vm.serial_output(Duration::from_secs(1))
    );

    // Pause joins both threads and recovers both vCPU fds; resume
    // restarts both.
    vm.pause().expect("pause should join both vCPU threads");
    assert!(vm.vcpu_fd().is_some(), "vCPU fds recovered on pause");
    vm.resume()
        .expect("resume should restart both vCPU threads");
    let exec = agent.exec(&["echo", "alive"]).expect("exec after resume");
    assert_eq!(exec.stdout.trim(), "alive");

    vm.shutdown();
}

/// internal notes: a 2-vCPU VM snapshots and restores like a 1-vCPU VM.
/// Both CPUs run a counter before the snapshot; after the `CoW`
/// restore the guest still sees 2 CPUs, both counters advance (both
/// vCPUs execute), and dmesg is free of TSC-unstable / soft-lockup
/// splats (Inc 6 clock sanity).
#[test]
fn test_multi_vcpu_snapshot_restore_roundtrip() {
    let _ = env_logger::builder().is_test(true).try_init();

    let kernel = workspace_path("guest/kernel/vmlinux");
    let initrd = workspace_path("guest/rootfs/initramfs.cpio.gz");
    assert!(kernel.exists(), "guest kernel not found at {kernel:?}");
    assert!(initrd.exists(), "initramfs not found at {initrd:?}");

    let mut vm = Vm::builder()
        .kernel(&kernel)
        .initrd(&initrd)
        .memory_mb(256)
        .vcpus(2)
        .vsock(true)
        .build()
        .expect("2-vCPU VM should build");
    vm.start().expect("VM should start");
    let mut agent = vm
        .connect_agent(Duration::from_secs(90))
        .expect("agent should connect");

    // One counter per CPU (busybox has no taskset; two background
    // loops on a 2-CPU guest schedule across both CPUs). Fully
    // redirect the background jobs' stdio or the exec waits on the
    // inherited pipes forever; write-then-rename keeps reads atomic.
    agent
        .exec(&[
            "sh",
            "-c",
            "for i in 0 1; do (c=0; while true; do c=$((c+1)); \
             echo $c > /tmp/ctr$i.tmp && mv /tmp/ctr$i.tmp /tmp/ctr$i; done) \
             </dev/null >/dev/null 2>&1 & echo $! > /tmp/ctrpid$i; done",
        ])
        .expect("counters should start");
    std::thread::sleep(Duration::from_millis(300));

    let snapshot_dir = tempfile::tempdir().unwrap();
    vm.snapshot(snapshot_dir.path())
        .expect("2-vCPU snapshot should succeed");
    vm.shutdown();
    drop(vm);

    let restore_start = std::time::Instant::now();
    let mut restored = Vm::restore(snapshot_dir.path()).expect("2-vCPU restore should succeed");
    let restore_elapsed = restore_start.elapsed();
    assert_eq!(restored.vcpu_count(), 2, "restored VM must carry 2 vCPUs");
    assert!(
        restore_elapsed <= k7d::latency::RESTORE_2VCPU,
        "2-vCPU CoW restore took {restore_elapsed:?} (budget {:?})",
        k7d::latency::RESTORE_2VCPU
    );
    restored.start().expect("restored VM should start");
    let mut agent2 = restored
        .connect_agent(Duration::from_secs(30))
        .expect("agent should reconnect after restore");

    let nproc = agent2
        .exec(&["sh", "-c", "grep -c ^processor /proc/cpuinfo"])
        .expect("cpu count should run");
    assert_eq!(
        nproc.stdout.trim(),
        "2",
        "restored guest must still see 2 CPUs"
    );

    // Both counters must advance post-restore (both vCPUs execute).
    for i in 0..2 {
        let path = format!("/tmp/ctr{i}");
        let before = agent2.exec(&["cat", &path]).expect("read counter");
        std::thread::sleep(Duration::from_millis(500));
        let after = agent2.exec(&["cat", &path]).expect("read counter");
        let (b, a): (u64, u64) = (
            before.stdout.trim().parse().expect("counter is a number"),
            after.stdout.trim().parse().expect("counter is a number"),
        );
        assert!(a > b, "counter {i} must advance post-restore ({b} -> {a})");
    }

    // Stop the spin loops — two busy vCPUs starve the remaining
    // agent execs on a 2-CPU guest.
    agent2
        .exec(&["sh", "-c", "kill $(cat /tmp/ctrpid0) $(cat /tmp/ctrpid1)"])
        .expect("counters should stop");

    // Inc 6 clock sanity: no TSC-unstable / soft-lockup splats.
    let dmesg = agent2
        .exec(&[
            "sh",
            "-c",
            "dmesg | grep -ci 'tsc unstable\\|soft lockup\\|clocksource.*unstable' || true",
        ])
        .expect("dmesg should run");
    assert_eq!(
        dmesg.stdout.trim(),
        "0",
        "restored 2-vCPU guest logged clock instability"
    );

    // Guest time is monotonic and alive: /proc/uptime must advance
    // across a host-side sleep (shell builtins only — the busybox
    // initramfs has no `date` symlink). A frozen clock (CHALLENGES.md
    // #40 class of bug) would return the same value twice.
    let read_uptime = |agent: &mut k7d::api::AgentClient| -> f64 {
        let out = agent
            .exec(&["sh", "-c", "read up rest < /proc/uptime; echo $up"])
            .expect("uptime read should run");
        assert_eq!(
            out.exit_code, 0,
            "uptime read failed: stdout={:?} stderr={:?}",
            out.stdout, out.stderr
        );
        out.stdout.trim().parse().expect("uptime seconds")
    };
    let s1 = read_uptime(&mut agent2);
    std::thread::sleep(Duration::from_millis(1100));
    let s2 = read_uptime(&mut agent2);
    assert!(
        s2 > s1,
        "guest clock frozen or backwards after restore: {s1} -> {s2}"
    );

    restored.shutdown();
}
