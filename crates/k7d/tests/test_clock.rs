//! What time the guest thinks it is, across snapshot, restore and fork.
//!
//! The guest has no RTC: kvmclock is the only thing that tells it the
//! wall clock at boot, and `KVM_SET_CLOCK` at restore is the only thing
//! that moves it on afterwards. The guest used to have neither —
//! it ran on the TSC, so a VM restored from a snapshot resumed with the
//! clock frozen at the instant of capture and no way to notice. These
//! tests put a deliberate gap either side of every transition, because
//! a warm-pool template is forked long after it was minted and a
//! before/after that leaves no time in between proves nothing.

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use k7d::api::AgentClient;
use k7d::vm::Vm;

/// How far the guest's wall clock may sit from the host's.
const MAX_SKEW_SECS: i64 = 2;

/// Wall time left to pass across each transition. Stands in for the
/// hours a snapshot spends at rest; large enough that a guest whose
/// clock froze fails by a margin no scheduling jitter can explain.
const TRANSITION_GAP: Duration = Duration::from_secs(5);

fn boot_vm() -> Vm {
    let mut vm = Vm::builder()
        .kernel_and_initrd()
        .memory_mb(256)
        .vsock(true)
        .build()
        .expect("VM should build");
    vm.start().expect("VM should start");
    vm
}

fn host_epoch() -> i64 {
    i64::try_from(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("host clock is past the epoch")
            .as_secs(),
    )
    .expect("host epoch fits in i64")
}

fn guest_sh(agent: &mut AgentClient, script: &str) -> String {
    let out = agent
        .exec(&["sh", "-c", script])
        .expect("guest command runs");
    assert_eq!(out.exit_code, 0, "`{script}` failed in the guest: {out:?}");
    out.stdout.trim().to_string()
}

/// Assert the guest agrees with the host about what time it is.
fn check_clock(agent: &mut AgentClient, when: &str) {
    let guest = guest_sh(agent, "date +%s")
        .parse::<i64>()
        .expect("guest `date +%s` prints a number");
    let skew = guest - host_epoch();
    eprintln!("  guest wall clock {when}: skew {skew}s");
    assert!(
        skew.abs() <= MAX_SKEW_SECS,
        "guest wall clock {when} is {skew}s off the host's"
    );
}

/// The clock the guest reads must be the one k7d can re-base. Left to
/// itself the guest picks `tsc`, which no `KVM_SET_CLOCK` can reach —
/// the wall-clock assertions above would then hold only for as long as
/// the VM is never suspended.
fn check_clocksource(agent: &mut AgentClient) {
    let clocksource = guest_sh(
        agent,
        "cat /sys/devices/system/clocksource/clocksource0/current_clocksource",
    );
    assert_eq!(
        clocksource, "kvm-clock",
        "guest is not reading the clock k7d owns"
    );
}

#[test]
fn test_clock_correct_across_snapshot_restore_and_fork() {
    let _ = env_logger::builder().is_test(true).try_init();

    let mut vm = boot_vm();
    let mut agent = vm
        .connect_agent(Duration::from_secs(90))
        .expect("agent should connect");
    check_clocksource(&mut agent);
    check_clock(&mut agent, "after cold boot");

    let snapshot_dir = tempfile::tempdir().unwrap();
    vm.snapshot(snapshot_dir.path()).expect("snapshot");
    vm.shutdown();
    drop(agent);
    drop(vm);

    std::thread::sleep(TRANSITION_GAP);

    let mut restored = Vm::restore(snapshot_dir.path()).expect("restore");
    restored.start().expect("restored VM should start");
    let mut restored_agent = restored
        .connect_agent(Duration::from_secs(30))
        .expect("restored agent should connect");
    check_clocksource(&mut restored_agent);
    check_clock(&mut restored_agent, "after restore");

    // A cold fork is a snapshot and a restore of a VM that is itself
    // restored — second-generation clock arithmetic, where an origin
    // taken from the wrong VM's kvmclock would show up doubled.
    let mut forked = restored.fork("clock-cold-fork").expect("cold fork");
    forked.start().expect("fork should start");
    std::thread::sleep(TRANSITION_GAP);
    let mut fork_agent = forked
        .connect_agent(Duration::from_secs(30))
        .expect("fork agent should connect");
    check_clock(&mut fork_agent, "after cold fork");

    // The forward jump is a suspend as far as the guest is concerned,
    // and KVM_KVMCLOCK_CTRL is what stops it being reported as a
    // stalled CPU. Nothing should have gone unstable.
    let splats = guest_sh(
        &mut fork_agent,
        "dmesg | grep -ci 'soft lockup\\|clocksource.*unstable\\|rcu_sched detected' || true",
    );
    assert_eq!(splats, "0", "the guest complained about the clock jump");

    forked.shutdown();
    restored.shutdown();
}

/// The warm-pool shape: a prepared source sits idle, then forks. The
/// fork inherits the source's memory — including the timekeeping state
/// the source's kernel had — so its clock is only right if the fork's
/// own kvmclock is re-based onto the host's.
#[test]
fn test_clock_correct_across_warm_fork() {
    let _ = env_logger::builder().is_test(true).try_init();

    let mut source = boot_vm();
    let _ = source
        .connect_agent(Duration::from_secs(90))
        .expect("agent should connect");
    source
        .prepare_fork_source()
        .expect("prepare_fork_source should succeed");
    let mut agent = source
        .connect_agent(Duration::from_secs(30))
        .expect("reconnect after prepare_fork_source");
    check_clock(&mut agent, "on the prepared fork source");

    std::thread::sleep(TRANSITION_GAP);

    let mut forked = source.fork_warm("clock-warm-fork").expect("warm fork");
    forked.start().expect("fork should start");
    let mut fork_agent = forked
        .connect_agent(Duration::from_secs(30))
        .expect("fork agent should connect");
    check_clocksource(&mut fork_agent);
    check_clock(&mut fork_agent, "after warm fork");

    forked.shutdown();
    source.shutdown();
}
