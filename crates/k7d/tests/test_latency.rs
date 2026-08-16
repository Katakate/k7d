//! Latency regression tests — enforce performance budgets.
//!
//! Budgets are defined in [`k7d::latency`] (the single source of truth).
//! If a code change causes a regression, the test fails with measured vs budget.

use std::time::{Duration, Instant};

use k7d::latency;
use k7d::vm::Vm;

fn create_vm_with_virtiofs() -> (Vm, tempfile::TempDir) {
    let state_dir = tempfile::tempdir().unwrap();
    let vm = Vm::builder()
        .kernel_and_initrd()
        .memory_mb(256)
        .vsock(true)
        .virtiofs(state_dir.path(), "/mnt/state")
        .build()
        .expect("VM should build");
    (vm, state_dir)
}

#[test]
fn test_latency_vm_build() {
    let start = Instant::now();
    let state_dir = tempfile::tempdir().unwrap();
    let _vm = Vm::builder()
        .kernel_and_initrd()
        .memory_mb(256)
        .vsock(true)
        .virtiofs(state_dir.path(), "/mnt/state")
        .build()
        .expect("VM should build");
    let elapsed = start.elapsed();

    eprintln!("VM build latency: {elapsed:?}");
    assert!(
        elapsed < latency::VM_BUILD,
        "VM build should be <{:?}, was {elapsed:?}",
        latency::VM_BUILD
    );
}

#[test]
fn test_latency_vm_boot_to_agent() {
    let (mut vm, _state_dir) = create_vm_with_virtiofs();

    let start = Instant::now();
    vm.start().unwrap();
    let _agent = vm
        .connect_agent(Duration::from_secs(90))
        .expect("should connect to agent");
    let elapsed = start.elapsed();

    eprintln!("VM boot to agent ready: {elapsed:?}");
    assert!(
        elapsed < latency::VM_BOOT_TO_AGENT,
        "VM boot to agent should be <{:?}, was {elapsed:?}",
        latency::VM_BOOT_TO_AGENT
    );

    vm.shutdown();
}

#[test]
fn test_latency_agent_ping() {
    let (mut vm, _state_dir) = create_vm_with_virtiofs();
    vm.start().unwrap();
    let mut agent = vm
        .connect_agent(Duration::from_secs(90))
        .expect("should connect");

    agent.ping().unwrap();

    let start = Instant::now();
    agent.ping().unwrap();
    let elapsed = start.elapsed();

    eprintln!("Agent ping RTT: {elapsed:?}");
    assert!(
        elapsed < latency::AGENT_PING_RTT,
        "Agent ping RTT should be <{:?}, was {elapsed:?}",
        latency::AGENT_PING_RTT
    );

    vm.shutdown();
}

#[test]
fn test_latency_agent_exec() {
    let (mut vm, _state_dir) = create_vm_with_virtiofs();
    vm.start().unwrap();
    let mut agent = vm
        .connect_agent(Duration::from_secs(90))
        .expect("should connect");

    agent.exec(&["echo", "warmup"]).unwrap();

    let start = Instant::now();
    let result = agent.exec(&["echo", "hello"]).unwrap();
    let elapsed = start.elapsed();

    assert_eq!(result.exit_code, 0);
    assert_eq!(result.stdout.trim(), "hello");

    eprintln!("Agent exec RTT: {elapsed:?}");
    assert!(
        elapsed < latency::AGENT_EXEC_RTT,
        "Agent exec RTT should be <{:?}, was {elapsed:?}",
        latency::AGENT_EXEC_RTT
    );

    vm.shutdown();
}

#[test]
fn test_latency_snapshot_256mb() {
    let (mut vm, _state_dir) = create_vm_with_virtiofs();
    vm.start().unwrap();
    let _agent = vm
        .connect_agent(Duration::from_secs(90))
        .expect("should connect");

    let snapshot_dir = tempfile::tempdir().unwrap();
    let start = Instant::now();
    vm.snapshot(snapshot_dir.path()).unwrap();
    let elapsed = start.elapsed();

    eprintln!("Snapshot 256MB VM: {elapsed:?}");
    assert!(
        elapsed < latency::SNAPSHOT_256MB,
        "Snapshot 256MB VM should be <{:?}, was {elapsed:?}",
        latency::SNAPSHOT_256MB
    );

    vm.shutdown();
}

#[test]
fn test_latency_vm_shutdown() {
    let (mut vm, _state_dir) = create_vm_with_virtiofs();
    vm.start().unwrap();
    let _agent = vm
        .connect_agent(Duration::from_secs(90))
        .expect("should connect");

    let start = Instant::now();
    vm.shutdown();
    let elapsed = start.elapsed();

    eprintln!("VM shutdown: {elapsed:?}");
    assert!(
        elapsed < latency::VM_SHUTDOWN,
        "VM shutdown should be <{:?}, was {elapsed:?}",
        latency::VM_SHUTDOWN
    );
}

#[test]
fn test_latency_exec_sequential_5x() {
    let (mut vm, _state_dir) = create_vm_with_virtiofs();
    vm.start().unwrap();
    let mut agent = vm
        .connect_agent(Duration::from_secs(90))
        .expect("should connect");

    agent.exec(&["echo", "warmup"]).unwrap();

    let start = Instant::now();
    for i in 0..5 {
        let r = agent.exec(&["echo", &format!("iter-{i}")]).unwrap();
        assert_eq!(r.exit_code, 0);
    }
    let elapsed = start.elapsed();

    eprintln!("5x sequential exec: {elapsed:?} ({:?}/exec)", elapsed / 5);
    assert!(
        elapsed < latency::EXEC_SEQUENTIAL_5X,
        "5x sequential exec should be <{:?}, was {elapsed:?}",
        latency::EXEC_SEQUENTIAL_5X
    );

    vm.shutdown();
}

#[test]
fn test_latency_restore_cow() {
    let (mut vm, _state_dir) = create_vm_with_virtiofs();
    vm.start().unwrap();
    let _agent = vm
        .connect_agent(Duration::from_secs(90))
        .expect("should connect");

    let snapshot_dir = tempfile::tempdir().unwrap();
    vm.snapshot(snapshot_dir.path()).unwrap();
    vm.shutdown();
    drop(_agent);
    drop(vm);
    drop(_state_dir);

    let start = Instant::now();
    let mut restored = Vm::restore(snapshot_dir.path()).unwrap();
    restored.start().unwrap();
    let elapsed = start.elapsed();

    eprintln!("CoW restore: {elapsed:?}");
    assert!(
        elapsed < latency::RESTORE_COW,
        "CoW restore should be <{:?}, was {elapsed:?}",
        latency::RESTORE_COW
    );

    restored.shutdown();
}

#[test]
fn test_latency_restore_agent_reconnect() {
    let (mut vm, _state_dir) = create_vm_with_virtiofs();
    vm.start().unwrap();
    let _agent = vm
        .connect_agent(Duration::from_secs(90))
        .expect("should connect");

    let snapshot_dir = tempfile::tempdir().unwrap();
    vm.snapshot(snapshot_dir.path()).unwrap();
    vm.shutdown();
    drop(_agent);
    drop(vm);
    drop(_state_dir);

    let mut restored = Vm::restore(snapshot_dir.path()).unwrap();
    restored.start().unwrap();

    let start = Instant::now();
    let mut agent = restored
        .connect_agent(Duration::from_secs(30))
        .expect("should reconnect");
    agent.ping().unwrap();
    let elapsed = start.elapsed();

    eprintln!("Agent reconnect after restore: {elapsed:?}");
    assert!(
        elapsed < latency::RESTORE_AGENT_RECONNECT,
        "Agent reconnect should be <{:?}, was {elapsed:?}",
        latency::RESTORE_AGENT_RECONNECT
    );

    restored.shutdown();
}

#[test]
fn test_latency_fork_cold() {
    let (mut vm, _state_dir) = create_vm_with_virtiofs();
    vm.start().unwrap();
    let _agent = vm
        .connect_agent(Duration::from_secs(90))
        .expect("should connect");

    let start = Instant::now();
    let mut forked = vm.fork("latency-fork-cold").unwrap();
    forked.start().unwrap();
    let elapsed = start.elapsed();

    eprintln!("Fork (cold source): {elapsed:?}");
    assert!(
        elapsed < latency::FORK_COLD,
        "Fork (cold source) should be <{:?}, was {elapsed:?}",
        latency::FORK_COLD
    );

    forked.shutdown();
    vm.shutdown();
}

#[test]
fn test_latency_fork_agent_reconnect() {
    let (mut vm, _state_dir) = create_vm_with_virtiofs();
    vm.start().unwrap();
    let _agent = vm
        .connect_agent(Duration::from_secs(90))
        .expect("should connect");

    let mut forked = vm.fork("latency-fork-reconnect").unwrap();
    forked.start().unwrap();

    let start = Instant::now();
    let mut fork_agent = forked
        .connect_agent(Duration::from_secs(30))
        .expect("should reconnect to fork");
    fork_agent.ping().unwrap();
    let elapsed = start.elapsed();

    eprintln!("Fork agent reconnect: {elapsed:?}");
    assert!(
        elapsed < latency::FORK_AGENT_RECONNECT,
        "Fork agent reconnect should be <{:?}, was {elapsed:?}",
        latency::FORK_AGENT_RECONNECT
    );

    forked.shutdown();
    vm.shutdown();
}

#[test]
fn test_latency_virtiofs_read() {
    let (mut vm, state_dir) = create_vm_with_virtiofs();
    std::fs::write(state_dir.path().join("test.txt"), "hello from host").unwrap();

    vm.start().unwrap();
    let mut agent = vm
        .connect_agent(Duration::from_secs(90))
        .expect("should connect");
    // Same settle as the write test: long enough for the mount, short
    // enough that haltpoll has not HLTed past its poll window.
    std::thread::sleep(Duration::from_millis(50));

    agent.exec(&["cat", "/mnt/state/test.txt"]).unwrap();

    let start = Instant::now();
    let result = agent.exec(&["cat", "/mnt/state/test.txt"]).unwrap();
    let elapsed = start.elapsed();

    assert_eq!(result.stdout.trim(), "hello from host");

    eprintln!("Virtiofs read: {elapsed:?}");
    assert!(
        elapsed < latency::VIRTIOFS_READ,
        "Virtiofs read should be <{:?}, was {elapsed:?}",
        latency::VIRTIOFS_READ
    );

    vm.shutdown();
}

#[test]
fn test_latency_virtiofs_write() {
    let (mut vm, state_dir) = create_vm_with_virtiofs();

    vm.start().unwrap();
    let mut agent = vm
        .connect_agent(Duration::from_secs(90))
        .expect("should connect");
    // Guest haltpoll polls for `guest_halt_poll_ns` (200 µs)
    // then HLT. A 1 s gap is many governor cycles past that window, so
    // the timed write takes the HLT+vmexit path (~1.9 ms, flaky against
    // the 2 ms budget). 50 ms is enough for the mount to finish coming
    // up after `connect_agent`, and two warmups leave the next request
    // inside the poll window of the previous wakeup (measured 1.14 ms
    // mean / 1.26 ms max at 200 µs, 10/10).
    std::thread::sleep(Duration::from_millis(50));

    agent
        .exec(&["sh", "-c", "echo warmup > /mnt/state/warmup.txt"])
        .unwrap();
    agent
        .exec(&["sh", "-c", "echo warmup2 > /mnt/state/warmup2.txt"])
        .unwrap();

    let start = Instant::now();
    agent
        .exec(&["sh", "-c", "echo hello > /mnt/state/write-test.txt"])
        .unwrap();
    let elapsed = start.elapsed();

    let content = std::fs::read_to_string(state_dir.path().join("write-test.txt")).unwrap();
    assert_eq!(content.trim(), "hello");

    eprintln!("Virtiofs write: {elapsed:?}");
    assert!(
        elapsed < latency::VIRTIOFS_WRITE,
        "Virtiofs write should be <{:?}, was {elapsed:?}",
        latency::VIRTIOFS_WRITE
    );

    vm.shutdown();
}

/// Chunk 2b.2: `PodVolumes::prepare` must come in under
/// [`latency::POD_VOLUMES_SETUP`] for a typical pod (handful of
/// kubelet volumes).
///
/// Builds a fake `/var/lib/kubelet/pods/<uid>/volumes/` tree with
/// 6 volumes — one of each supported plugin class plus an extra
/// configmap — under a temp pod uid, then measures
/// `PodVolumes::prepare` end-to-end. The fake tree's parent path
/// is `/var/lib/kubelet/pods/<uid>/`, which is the real path
/// `PodVolumes::prepare` scans (the const lives in
/// `crates/k7d/src/volumes.rs`), so we have to use a real-looking
/// path. We pick a synthetic uid like `00000000-test-latency-<pid>`
/// to keep collisions impossible across concurrent test runs.
///
/// Cleanup at the end is best-effort — kubelet (had this been a
/// real pod) would GC `/var/lib/kubelet/pods/<uid>/` itself. We
/// also umount the binds + remove our `/var/lib/k7d/pods/<uid>/`
/// scratch tree via `PodVolumes::cleanup`.
#[test]
fn test_latency_pod_volumes_setup() {
    use std::fs;
    use std::path::PathBuf;

    let pid = std::process::id();
    let uid = format!("00000000-0000-0000-0000-pvtest{pid:08x}");
    let pod_dir = PathBuf::from("/var/lib/kubelet/pods").join(&uid);
    let volumes_dir = pod_dir.join("volumes");

    // 6 volumes, one of each supported class plus a second
    // configmap (mirroring a typical pod that mounts both
    // app-config and service-account-token-projected).
    let fixtures: &[(&str, &str, &[(&str, &str)])] = &[
        (
            "kubernetes.io~configmap",
            "app-config",
            &[("greeting", "hi")],
        ),
        (
            "kubernetes.io~configmap",
            "feature-flags",
            &[("flags.yaml", "x: 1")],
        ),
        ("kubernetes.io~secret", "creds", &[("api-key", "sk-pv")]),
        ("kubernetes.io~empty-dir", "scratch", &[]),
        ("kubernetes.io~downward-api", "info", &[("podname", "x")]),
        ("kubernetes.io~projected", "tok", &[("token", "abc")]),
    ];

    // Cleanup any leftover from a previous failed run.
    let _ = std::process::Command::new("umount")
        .arg("-l")
        .arg(&pod_dir)
        .output();
    let _ = fs::remove_dir_all(&pod_dir);

    for (plugin, name, files) in fixtures {
        let dir = volumes_dir.join(plugin).join(name);
        fs::create_dir_all(&dir).expect("mkdir fixture dir");
        for (k, v) in *files {
            fs::write(dir.join(k), v).expect("write fixture file");
        }
    }

    // Measure: this is the work the shim does inline in sandbox
    // `Create`. Includes the kubelet enumeration, the 6 per-volume
    // `mount --bind` fork+execs, and the per-pod scratch tree
    // creation. Does NOT include virtiofsd spawn (that's in
    // VM_BUILD) or the etc-files / hostPath workload-time binds
    // (those run at workload Create, smaller scope).
    let start = Instant::now();
    let pv = k7d::volumes::PodVolumes::prepare(Some(&uid), "sandbox-id-irrelevant-for-latency")
        .expect("PodVolumes::prepare");
    let elapsed = start.elapsed();
    eprintln!(
        "PodVolumes::prepare (6 kubelet volumes): {elapsed:?} \
         (rewrites={})",
        pv.rewrites.len()
    );

    // Sanity: all 6 volumes ended up in the rewrite map.
    assert_eq!(
        pv.rewrites.len(),
        6,
        "should have wired all 6 fixture volumes; got {}",
        pv.rewrites.len()
    );

    assert!(
        elapsed < latency::POD_VOLUMES_SETUP,
        "PodVolumes::prepare should be <{:?}, was {elapsed:?}",
        latency::POD_VOLUMES_SETUP
    );

    // Cleanup: umount + rmtree our scratch + the fake kubelet
    // fixture dir.
    pv.cleanup();
    let _ = fs::remove_dir_all(&pod_dir);
}
