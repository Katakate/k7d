//! Integration test: fork — CoW memory + reflink disk.
//! Requires KVM, /dev/vhost-vsock, virtiofsd, built guest kernel, and built initramfs.

use std::time::Duration;

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

fn create_vm_without_virtiofs() -> Vm {
    Vm::builder()
        .kernel_and_initrd()
        .memory_mb(256)
        .vsock(true)
        .build()
        .expect("VM should build")
}

#[test]
fn test_fork_creates_independent_copy() {
    let _ = env_logger::builder().is_test(true).try_init();

    let mut vm = create_vm_without_virtiofs();
    vm.start().unwrap();
    let mut agent = vm
        .connect_agent(Duration::from_secs(90))
        .expect("should connect to agent");

    agent
        .exec(&["sh", "-c", "echo 'original' > /tmp/data.txt"])
        .unwrap();

    let mut forked = vm.fork("fork-1").unwrap();
    forked.start().unwrap();
    std::thread::sleep(Duration::from_secs(2));
    let mut fork_agent = forked
        .connect_agent(Duration::from_secs(60))
        .expect("should connect to forked agent");

    // Forked VM should have the original state
    let data = fork_agent.exec(&["cat", "/tmp/data.txt"]).unwrap();
    assert_eq!(data.stdout.trim(), "original");

    // Write different data in fork
    fork_agent
        .exec(&["sh", "-c", "echo 'forked' > /tmp/data.txt"])
        .unwrap();

    // Reconnect to source (vsock disrupted by pause/resume during fork)
    let mut source_agent = vm
        .connect_agent(Duration::from_secs(30))
        .expect("should reconnect to source");
    let source_data = source_agent.exec(&["cat", "/tmp/data.txt"]).unwrap();
    assert_eq!(source_data.stdout.trim(), "original");

    forked.shutdown();
    vm.shutdown();
}

#[test]
fn test_fork_with_virtiofs_state() {
    let _ = env_logger::builder().is_test(true).try_init();

    let (mut vm, state_dir) = create_vm_with_virtiofs();
    std::fs::write(state_dir.path().join("host-file.txt"), "from host").unwrap();

    vm.start().unwrap();
    let mut agent = vm
        .connect_agent(Duration::from_secs(90))
        .expect("should connect to agent");

    // Wait for virtiofs mount
    std::thread::sleep(Duration::from_secs(1));

    // Write state via virtiofs
    agent
        .exec(&["sh", "-c", "echo 'vm-data' > /mnt/state/vm-file.txt"])
        .unwrap();

    let mut forked = vm.fork("fork-vfs").unwrap();
    forked.start().unwrap();
    let mut fork_agent = forked
        .connect_agent(Duration::from_secs(30))
        .expect("should connect to forked agent");

    // In-memory state should be preserved
    let ping = fork_agent.ping().unwrap();
    assert_eq!(ping.version, "0.1.0");

    // Verify the fork is running
    let exec = fork_agent.exec(&["echo", "hello-from-fork"]).unwrap();
    assert_eq!(exec.exit_code, 0);
    assert_eq!(exec.stdout.trim(), "hello-from-fork");

    forked.shutdown();
    vm.shutdown();
}

#[test]
fn test_fork_unique_cids() {
    let _ = env_logger::builder().is_test(true).try_init();

    let mut vm = create_vm_without_virtiofs();
    vm.start().unwrap();
    let _agent = vm
        .connect_agent(Duration::from_secs(90))
        .expect("should connect");

    let forked1 = vm.fork("fork-cid-1").unwrap();
    let forked2 = vm.fork("fork-cid-2").unwrap();

    let cid1 = forked1.guest_cid();
    let cid2 = forked2.guest_cid();
    let source_cid = vm.guest_cid();

    assert_ne!(cid1, cid2, "forks should have different CIDs");
    assert_ne!(cid1, source_cid, "fork should differ from source");
    assert_ne!(cid2, source_cid, "fork should differ from source");

    drop(forked1);
    drop(forked2);
    vm.shutdown();
}

#[test]
fn test_fork_source_continues_running() {
    let _ = env_logger::builder().is_test(true).try_init();

    let mut vm = create_vm_without_virtiofs();
    vm.start().unwrap();
    let mut agent = vm
        .connect_agent(Duration::from_secs(90))
        .expect("should connect");

    agent
        .exec(&["sh", "-c", "echo 'before-fork' > /tmp/marker"])
        .unwrap();

    let mut forked = vm.fork("fork-resume").unwrap();
    forked.start().unwrap();

    // Reconnect to source (vsock disrupted by pause/resume during fork)
    std::thread::sleep(Duration::from_secs(2));
    let mut source_agent = vm
        .connect_agent(Duration::from_secs(60))
        .expect("should reconnect to source");

    // Source should still be running and responsive
    let result = source_agent.exec(&["cat", "/tmp/marker"]).unwrap();
    assert_eq!(result.stdout.trim(), "before-fork");

    // Source can still do work after fork
    source_agent
        .exec(&["sh", "-c", "echo 'after-fork' > /tmp/marker2"])
        .unwrap();
    let result2 = source_agent.exec(&["cat", "/tmp/marker2"]).unwrap();
    assert_eq!(result2.stdout.trim(), "after-fork");

    forked.shutdown();
    vm.shutdown();
}

#[test]
fn test_fork_memory_independence() {
    let _ = env_logger::builder().is_test(true).try_init();

    let mut vm = create_vm_without_virtiofs();
    vm.start().unwrap();
    let mut agent = vm
        .connect_agent(Duration::from_secs(90))
        .expect("should connect");

    agent
        .exec(&["sh", "-c", "echo 'shared' > /tmp/shared.txt"])
        .unwrap();

    let mut forked = vm.fork("fork-mem").unwrap();
    forked.start().unwrap();
    std::thread::sleep(Duration::from_secs(2));
    let mut fork_agent = forked
        .connect_agent(Duration::from_secs(60))
        .expect("should connect to fork");

    // Reconnect to source (vsock disrupted by pause/resume during fork)
    let mut source_agent = vm
        .connect_agent(Duration::from_secs(60))
        .expect("should reconnect to source");

    // Both should see the shared file
    let src_data = source_agent.exec(&["cat", "/tmp/shared.txt"]).unwrap();
    assert_eq!(src_data.stdout.trim(), "shared");
    let fork_data = fork_agent.exec(&["cat", "/tmp/shared.txt"]).unwrap();
    assert_eq!(fork_data.stdout.trim(), "shared");

    // Write only in fork
    fork_agent
        .exec(&["sh", "-c", "echo 'fork-only' > /tmp/fork-only.txt"])
        .unwrap();

    // Source should NOT see fork-only file
    let src_check = source_agent.exec(&["cat", "/tmp/fork-only.txt"]).unwrap();
    assert_ne!(src_check.exit_code, 0, "source should not see fork's file");

    forked.shutdown();
    vm.shutdown();
}

#[test]
fn test_fork_warm_under_50ms() {
    let _ = env_logger::builder().is_test(true).try_init();

    let mut source = create_vm_without_virtiofs();
    source.start().unwrap();
    let mut agent = source
        .connect_agent(Duration::from_secs(90))
        .expect("should connect to agent");
    agent.ping().unwrap();

    // Prepare as fork source (one-time cost, not measured).
    source
        .prepare_fork_source()
        .expect("prepare_fork_source should succeed");
    let mut agent = source
        .connect_agent(Duration::from_secs(30))
        .expect("reconnect after prepare_fork_source");

    // Dirty a few pages inside the guest.
    agent
        .exec(&["sh", "-c", "echo warm-fork-test > /tmp/marker"])
        .unwrap();

    let start = std::time::Instant::now();
    let mut forked = source.fork_warm("bench-warm").expect("warm fork");
    let elapsed = start.elapsed();

    eprintln!("warm fork latency: {elapsed:?}");
    assert!(
        elapsed < k7d::latency::FORK_WARM,
        "warm fork should be <{:?}, was {elapsed:?}",
        k7d::latency::FORK_WARM
    );

    forked.start().unwrap();
    let mut fork_agent = forked
        .connect_agent(Duration::from_secs(30))
        .expect("forked VM should be reachable via vsock");
    fork_agent.ping().unwrap();
    let marker = fork_agent.exec(&["cat", "/tmp/marker"]).unwrap();
    assert_eq!(marker.stdout.trim(), "warm-fork-test");

    forked.shutdown();
    source.shutdown();
}

#[test]
fn test_fork_warm_source_undisturbed() {
    let _ = env_logger::builder().is_test(true).try_init();

    let mut source = create_vm_without_virtiofs();
    source.start().unwrap();
    let _ = source
        .connect_agent(Duration::from_secs(90))
        .expect("initial agent connect");

    source
        .prepare_fork_source()
        .expect("prepare_fork_source should succeed");
    let mut agent = source
        .connect_agent(Duration::from_secs(30))
        .expect("reconnect after prepare_fork_source");
    agent
        .exec(&["sh", "-c", "echo undisturbed > /tmp/marker"])
        .unwrap();

    let mut forked = source.fork_warm("nodisrupt").expect("warm fork");

    // CRITICAL: source agent still works WITHOUT reconnect. Warm fork must
    // NOT inject TRANSPORT_RESET into the source's memory.
    let alive = agent
        .exec(&["echo", "still-alive"])
        .expect("source agent should stay connected across warm fork");
    assert_eq!(alive.stdout.trim(), "still-alive");

    forked.start().unwrap();
    forked.shutdown();
    source.shutdown();
}

#[test]
fn test_fork_warm_batch_10() {
    let _ = env_logger::builder().is_test(true).try_init();

    let mut source = create_vm_without_virtiofs();
    source.start().unwrap();
    let _ = source
        .connect_agent(Duration::from_secs(90))
        .expect("initial agent connect");
    source.prepare_fork_source().expect("prepare_fork_source");
    let mut agent = source
        .connect_agent(Duration::from_secs(30))
        .expect("reconnect after prepare_fork_source");
    agent.exec(&["echo", "state"]).unwrap();

    let ids: Vec<String> = (0..10).map(|i| format!("batch-{i}")).collect();
    let id_refs: Vec<&str> = ids.iter().map(String::as_str).collect();

    let start = std::time::Instant::now();
    let forks = source
        .fork_warm_batch(&id_refs, None)
        .expect("batch warm fork");
    let elapsed = start.elapsed();

    eprintln!("10× warm fork batch latency: {elapsed:?}");
    assert_eq!(forks.len(), 10);
    assert!(
        elapsed < Duration::from_millis(200),
        "10 warm forks should be <200ms, was {elapsed:?}"
    );

    for mut f in forks {
        f.shutdown();
    }
    source.shutdown();
}

/// Warm-fork a 2-vCPU source. The child sees 2 CPUs, memory
/// independence holds, the source stays undisturbed, and both child
/// vCPU kernel TIDs land in a per-VM CPU cgroup (all-N-TIDs coverage,
/// the `apply_cpu_cap` contract).
#[test]
fn test_fork_warm_multi_vcpu() {
    let _ = env_logger::builder().is_test(true).try_init();

    let mut source = Vm::builder()
        .kernel_and_initrd()
        .memory_mb(256)
        .vcpus(2)
        .vsock(true)
        .build()
        .expect("2-vCPU VM should build");
    source.start().unwrap();
    let _ = source
        .connect_agent(Duration::from_secs(90))
        .expect("initial agent connect");

    source
        .prepare_fork_source()
        .expect("2-vCPU prepare_fork_source should succeed");
    assert_eq!(
        source.vcpu_count(),
        2,
        "prepare swap must preserve the vCPU count"
    );
    let mut agent = source
        .connect_agent(Duration::from_secs(30))
        .expect("reconnect after prepare_fork_source");
    agent
        .exec(&["sh", "-c", "echo mvcpu-source > /tmp/marker"])
        .unwrap();

    let start = std::time::Instant::now();
    let mut forked = source.fork_warm("mvcpu-warm").expect("2-vCPU warm fork");
    let elapsed = start.elapsed();
    eprintln!("2-vCPU warm fork latency: {elapsed:?}");
    assert!(
        elapsed < k7d::latency::FORK_WARM_2VCPU,
        "2-vCPU warm fork should be <{:?}, was {elapsed:?}",
        k7d::latency::FORK_WARM_2VCPU
    );
    assert_eq!(forked.vcpu_count(), 2, "fork must inherit 2 vCPUs");

    forked.start().unwrap();
    let mut fork_agent = forked
        .connect_agent(Duration::from_secs(30))
        .expect("forked VM reachable via vsock");

    // Child sees 2 CPUs and inherits the source's memory.
    let nproc = fork_agent
        .exec(&["sh", "-c", "grep -c ^processor /proc/cpuinfo"])
        .unwrap();
    assert_eq!(nproc.stdout.trim(), "2", "fork must see 2 CPUs");
    let marker = fork_agent.exec(&["cat", "/tmp/marker"]).unwrap();
    assert_eq!(marker.stdout.trim(), "mvcpu-source");

    // Both child vCPU TIDs land in a per-VM CPU cgroup.
    let tids = forked
        .vcpu_kernel_tids(Duration::from_secs(5))
        .expect("child vCPU threads publish kernel TIDs");
    assert_eq!(tids.len(), 2, "expected 2 child vCPU TIDs, got {tids:?}");
    let cgroup = k7d::cgroup::VmCpuCgroup::create("test-mvcpu-fork", 200_000, 100_000)
        .expect("create per-VM CPU cgroup");
    for &tid in &tids {
        cgroup
            .add_thread(tid)
            .unwrap_or_else(|e| panic!("add child vCPU TID {tid} to cgroup: {e}"));
    }
    let threads = std::fs::read_to_string(cgroup.dir().join("cgroup.threads")).unwrap();
    for &tid in &tids {
        assert!(
            threads.split_whitespace().any(|t| t == tid.to_string()),
            "vCPU TID {tid} missing from cgroup.threads: {threads:?}"
        );
    }

    // Memory independence: child-only writes stay invisible to source.
    fork_agent
        .exec(&["sh", "-c", "echo child > /tmp/child-only"])
        .unwrap();
    let src_check = agent
        .exec(&["cat", "/tmp/child-only"])
        .expect("source agent stays connected across warm fork");
    assert_ne!(
        src_check.exit_code, 0,
        "source must not see the fork's file"
    );
    let alive = agent.exec(&["echo", "still-alive"]).unwrap();
    assert_eq!(alive.stdout.trim(), "still-alive");

    forked.shutdown();
    drop(cgroup);
    source.shutdown();
}

#[test]
fn test_fork_latency_cold_source() {
    let _ = env_logger::builder().is_test(true).try_init();

    let mut vm = create_vm_without_virtiofs();
    vm.start().unwrap();
    let _agent = vm
        .connect_agent(Duration::from_secs(90))
        .expect("should connect");

    let start = std::time::Instant::now();
    let mut forked = vm.fork("bench-cold").unwrap();
    forked.start().unwrap();
    let elapsed = start.elapsed();

    eprintln!("fork (cold source) latency: {elapsed:?}");
    assert!(
        elapsed < k7d::latency::FORK_COLD,
        "fork should be <{:?}, was {elapsed:?}",
        k7d::latency::FORK_COLD
    );

    let mut fork_agent = forked
        .connect_agent(Duration::from_secs(30))
        .expect("forked VM should be reachable");
    fork_agent.ping().unwrap();

    forked.shutdown();
    vm.shutdown();
}

/// Regression: an external interrupt captured *mid-injection*
/// (the pause signal cancels `KVM_RUN` between KVM staging the injection and
/// the VM entry delivering it) must be re-queued on the restored vCPU. The
/// interrupt controller has already ACKed the vector by that point, so
/// dropping it strands the 8259 waiting for an EOI that never comes and the
/// fork is permanently deaf on that IRQ line (~1% of warm forks).
///
/// Deterministic: force `interrupt.injected = 1, nr = 0x35` (the vsock IRQ
/// vector the repro loop observed) into the captured state and assert the
/// restored vCPU reports it queued before its first `KVM_RUN`. The spurious
/// injection is harmless — the guest handler finds an empty ring and EOIs.
#[test]
fn test_fork_requeues_interrupted_injection() {
    let _ = env_logger::builder().is_test(true).try_init();

    let mut source = create_vm_without_virtiofs();
    source.start().unwrap();
    let _ = source
        .connect_agent(Duration::from_secs(90))
        .expect("initial agent connect");
    source.prepare_fork_source().expect("prepare_fork_source");
    let mut agent = source
        .connect_agent(Duration::from_secs(30))
        .expect("reconnect after prepare_fork_source");
    agent.exec(&["echo", "warm"]).unwrap();

    // Capture by hand (what fork_warm does) so vcpu_events is editable.
    let base_path = source
        .fork_source_base_path()
        .expect("fork source prepared")
        .to_path_buf();
    // KVM only stages an external interrupt when the guest can take one
    // (RFLAGS.IF set, no STI/MOV-SS shadow), so forcing one onto any
    // other capture is a state KVM never produces. VMX refuses to enter
    // it (exit 0x80000021, SDM 26.3.1.5); SVM injects it anyway (#97).
    // Capture again until the guest is interruptible.
    // kvm_vcpu_events layout: interrupt.injected at byte 8, nr at 9, shadow at 11.
    let (dirty, mut state) = (0..200)
        .find_map(|_| {
            source.pause().expect("pause source");
            let dirty = source.get_and_accumulate_dirty().unwrap().to_vec();
            let state = k7d::snapshot::capture_vm_state(&source).expect("capture state");
            let events = state.cpus[0]
                .vcpu_events
                .as_ref()
                .expect("capture records vcpu_events");
            if state.cpus[0].regs.rflags & 0x200 != 0 && events.data[11] == 0 {
                return Some((dirty, state));
            }
            source.resume().expect("resume source");
            std::thread::sleep(Duration::from_millis(5));
            None
        })
        .expect("vCPU 0 was never interruptible across 200 captures");
    let src_mem = source.mem_host_addr();

    let events = state.cpus[0].vcpu_events.as_mut().unwrap();
    events.data[8] = 1;
    events.data[9] = 0x35;

    let fork = k7d::fork::restore_vm_from_state(
        &base_path, &dirty, src_mem, &state, "reinject", None, false,
    );
    source.resume().expect("resume source");
    let mut fork = fork.expect("materialise fork");

    // Before the first KVM_RUN the queued injection must be visible.
    let restored_events = fork
        .vcpu_fd()
        .expect("restored vCPU fd available before start")
        .get_vcpu_events()
        .expect("KVM_GET_VCPU_EVENTS on restored vCPU");
    assert_eq!(
        restored_events.interrupt.injected, 1,
        "restore must re-queue the in-flight interrupt injection"
    );
    assert_eq!(
        restored_events.interrupt.nr, 0x35,
        "re-queued injection must carry the captured vector"
    );
    assert_eq!(
        restored_events.exception.injected, 0,
        "exception state stays dropped (AMD #BR workaround)"
    );

    // And the fork must still come up reachable after the spurious vector.
    fork.start().unwrap();
    let mut fork_agent = fork
        .connect_agent(Duration::from_secs(30))
        .expect("fork with re-queued injection reachable via vsock");
    fork_agent.ping().unwrap();

    fork.shutdown();
    source.shutdown();
}

/// Stress regression: 100 back-to-back warm forks, each with
/// agent traffic immediately before the pause (the window that puts a vsock
/// interrupt mid-injection), each fork probed over vsock. Pre-fix this
/// failed ~6% per fork (18/300 in the diagnostic loop); post-fix it is
/// deterministic and the whole loop runs in a few seconds.
#[test]
fn test_fork_warm_repeated_reachable() {
    let _ = env_logger::builder().is_test(true).try_init();

    let mut source = create_vm_without_virtiofs();
    source.start().unwrap();
    let _ = source
        .connect_agent(Duration::from_secs(90))
        .expect("initial agent connect");
    source.prepare_fork_source().expect("prepare_fork_source");
    let mut agent = source
        .connect_agent(Duration::from_secs(30))
        .expect("reconnect after prepare_fork_source");

    for i in 0..100 {
        // Traffic right before the pause keeps vsock interrupts in flight.
        agent
            .exec(&["sh", "-c", "echo x > /tmp/m"])
            .unwrap_or_else(|e| panic!("source exec before fork {i}: {e:?}"));
        let mut fork = source
            .fork_warm(&format!("stress-{i}"))
            .unwrap_or_else(|e| panic!("warm fork {i}: {e:?}"));
        fork.start().unwrap();
        let mut fork_agent = fork
            .connect_agent(Duration::from_secs(30))
            .unwrap_or_else(|e| panic!("fork {i} unreachable via vsock: {e:?}"));
        fork_agent
            .ping()
            .unwrap_or_else(|e| panic!("fork {i} ping: {e:?}"));
        drop(fork_agent);
        fork.shutdown();
    }

    source.shutdown();
}
