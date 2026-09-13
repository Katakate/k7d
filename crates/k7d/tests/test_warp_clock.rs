//! "It is now N seconds later", said to a live cluster.
//!
//! A warp advances the guest-visible clock of every VM of a cluster by
//! the same delta while all of them are paused, so the guests' backoffs,
//! probe periods and lease TTLs behave as if that much wall time had
//! passed. Two things have to be true for that to be a mechanism rather
//! than a trick:
//!
//! 1. **Lockstep.** All three nodes move by the same amount, and the
//!    spread between them stays inside the skew bound `test_clock.rs`
//!    already holds the guests to. etcd heartbeats, lease TTLs and TLS
//!    skew checks tolerate a uniform jump, not a skewed one.
//! 2. **Timers re-arm.** A guest whose clock moved but whose armed
//!    timers did not is a guest that thinks it is later and still waits
//!    out the old delay. The proof is functional and adversarial: a pod
//!    parked in a CrashLoopBackOff wait longer than 60 s restarts within
//!    seconds of the warp instead of a minute later.
//!
//! The clock survey measured that `IA32_TSC_DEADLINE` is never armed on
//! this guest — it uses the LAPIC one-shot timer, because
//! `KVM_GET_SUPPORTED_CPUID` on host kernels before 6.14 does not report
//! `CPUID.1:ECX[24]`. So the deadline-MSR write-back in
//! `Vm::warp_clock` is not what re-arms anything here; the pod above is
//! the only honest evidence, and this test is where it is produced.

mod common;

use std::time::{Duration, Instant};

use k7d::latency::WARP_CLUSTER_3VM;
use k7d::vm::{warp_clock_lockstep, Vm};

use common::ubuntu::{connect_or_dump, sh_ok};
use common::ubuntu_k3s::{
    bring_up_cluster, kubectl, pod_restarts, settle_cluster, wait_nodes_ready, CONVERGE,
};
use common::warp::{
    check_clockevent, check_clocksource, check_no_ntp_client, check_no_splats, delete_crashloop,
    guest_ahead_of_host, guest_clocks, kubectl_round_trip, pending_backoff, start_crashloop,
    wait_for_long_backoff, CRASHLOOP_POD, MAX_SKEW,
};

/// The spec's headline jump: "it is now two minutes later".
const WARP: Duration = Duration::from_secs(120);

/// A pod sitting in a backoff must restart *because of* the warp, not
/// because the backoff expired on its own. The remaining wait is > 60 s
/// when the warp lands, so anything inside this window is the warp.
const RESTART_AFTER_WARP: Duration = Duration::from_secs(20);

/// Shortest previous backoff that proves the pod is in the kubelet's
/// long-wait regime. The sequence is 10 s, 20 s, 40 s, 80 s, …, so an
/// observed 40 s wait means the *pending* one is ~80 s.
const MIN_OBSERVED_BACKOFF: Duration = Duration::from_secs(40);

/// Forward jump used for the backoff proof. Must exceed the pending
/// backoff (~2× the observed one) for the restart to be attributable to
/// the warp at all — asserted, not assumed.
const BACKOFF_WARP: Duration = Duration::from_secs(90);

/// Pause the whole cluster, warp it, resume it. This is the body of the
/// daemon's `WarpClock` op (`test_daemon.rs` drives the op itself); the
/// Ubuntu cluster is where the mechanism has to hold up.
fn warp_cluster(cluster: &mut common::ubuntu_k3s::UbuntuCluster, delta: Duration) -> Duration {
    let mut vms: [&mut Vm; 3] = [
        &mut cluster.server,
        &mut cluster.agent1,
        &mut cluster.agent2,
    ];
    let latency = warp_clock_lockstep(&mut vms, delta).expect("the cluster warps");
    eprintln!(
        "MEASUREMENT warp_clock 3-node Ubuntu cluster: +{}s in {latency:?} \
         (budget {WARP_CLUSTER_3VM:?})",
        delta.as_secs()
    );
    assert!(
        latency <= WARP_CLUSTER_3VM,
        "the warp held the cluster paused for {latency:?}, over the {WARP_CLUSTER_3VM:?} \
         budget — the pause window is the part a guest can notice"
    );
    latency
}

#[test]
fn test_warp_clock_moves_a_live_cluster_in_lockstep() {
    let _ = env_logger::builder().is_test(true).try_init();

    let mut cluster = bring_up_cluster();
    let names = cluster.names();
    let kubeconfig = cluster.kubeconfig.clone();
    let whose = ["server", "agent-1", "agent-2"];

    // Agents stay connected across the warp — a pause/resume must not
    // cost the caller its vsock connection, and the trap is warping
    // with an `exec` in flight, not with a socket open.
    let mut agents = [
        connect_or_dump(&mut cluster.server, whose[0]),
        connect_or_dump(&mut cluster.agent1, whose[1]),
        connect_or_dump(&mut cluster.agent2, whose[2]),
    ];
    let mut before = [0.0; 3];
    for (i, agent) in agents.iter_mut().enumerate() {
        check_clocksource(agent, whose[i]);
        check_clockevent(agent, whose[i]);
        check_no_ntp_client(agent, whose[i]);
        before[i] = guest_ahead_of_host(agent, whose[i]);
        assert!(
            before[i].abs() <= MAX_SKEW,
            "{}: guest clock is {:.3}s off the host's before any warp",
            whose[i],
            before[i]
        );
    }

    settle_cluster(&kubeconfig, "warp");

    // --- 1. the jump itself, in lockstep ---
    let clocks_before = [
        guest_clocks(&mut agents[0], whose[0]),
        guest_clocks(&mut agents[1], whose[1]),
        guest_clocks(&mut agents[2], whose[2]),
    ];
    warp_cluster(&mut cluster, WARP);
    for (i, agent) in agents.iter_mut().enumerate() {
        let now = guest_clocks(agent, whose[i]);
        eprintln!(
            "MEASUREMENT {} clocks moved by +{}s warp: realtime {:+.3}s, \
             monotonic {:+.3}s, boottime {:+.3}s",
            whose[i],
            WARP.as_secs(),
            now[0] - clocks_before[i][0],
            now[1] - clocks_before[i][1],
            now[2] - clocks_before[i][2],
        );
    }

    let mut after = [0.0; 3];
    for (i, agent) in agents.iter_mut().enumerate() {
        after[i] = guest_ahead_of_host(agent, whose[i]);
        let jumped = after[i] - before[i];
        eprintln!(
            "{}: guest was {:+.3}s off the host, now {:+.3}s — jumped {:.3}s",
            whose[i], before[i], after[i], jumped
        );
        assert!(
            (jumped - WARP.as_secs_f64()).abs() <= MAX_SKEW,
            "{}: guest clock moved {:.3}s, wanted {}s ± {MAX_SKEW}s",
            whose[i],
            jumped,
            WARP.as_secs()
        );
    }
    let spread = after.iter().copied().fold(f64::MIN, f64::max)
        - after.iter().copied().fold(f64::MAX, f64::min);
    eprintln!(
        "MEASUREMENT lockstep spread after +{}s: {spread:.3}s",
        WARP.as_secs()
    );
    assert!(
        spread <= MAX_SKEW,
        "the nodes' clocks are {spread:.3}s apart after the warp (bound {MAX_SKEW}s) — \
         a skewed jump is what etcd does not tolerate"
    );

    // --- 2. the functional proof: a backoff fires early ---
    start_crashloop(&kubeconfig);
    let (restarts, seen_at, observed_backoff) =
        wait_for_long_backoff(&kubeconfig, MIN_OBSERVED_BACKOFF);
    let pending = pending_backoff(observed_backoff);
    let since_restart = seen_at.elapsed();
    let remaining = pending
        .checked_sub(since_restart)
        .unwrap_or_else(|| panic!("the ~{pending:?} backoff already elapsed ({since_restart:?})"));
    assert!(
        remaining >= Duration::from_secs(60),
        "only ~{remaining:?} of the ~{pending:?} backoff is left — the spec's proof needs \
         ≥ 60 s so the restart cannot be the backoff expiring on its own \
         (observed wait {observed_backoff:?}, {since_restart:?} elapsed since the restart)"
    );
    assert!(
        remaining < BACKOFF_WARP,
        "~{remaining:?} of backoff is left, which a +{}s warp would not cover — the \
         restart could not be attributed to the warp (observed wait {observed_backoff:?})",
        BACKOFF_WARP.as_secs()
    );
    eprintln!(
        "{CRASHLOOP_POD}: at restart {restarts} after a {observed_backoff:?} wait, \
         ~{pending:?} pending with ~{remaining:?} left; warping +{}s",
        BACKOFF_WARP.as_secs()
    );

    warp_cluster(&mut cluster, BACKOFF_WARP);
    let warped_at = Instant::now();
    loop {
        let now = pod_restarts(&kubeconfig, CRASHLOOP_POD);
        if now > restarts {
            eprintln!(
                "MEASUREMENT CrashLoopBackOff restart after a +{}s warp: {:?} \
                 (was ~{pending:?} away)",
                BACKOFF_WARP.as_secs(),
                warped_at.elapsed()
            );
            break;
        }
        assert!(
            warped_at.elapsed() < RESTART_AFTER_WARP,
            "{CRASHLOOP_POD} still at {now} restarts {:?} after a +{}s warp that covered \
             its ~{pending:?} backoff — the clock moved but the timers did not: {}",
            warped_at.elapsed(),
            BACKOFF_WARP.as_secs(),
            kubectl(&kubeconfig, &["describe", "pod", CRASHLOOP_POD]).unwrap_or_else(|e| e)
        );
        std::thread::sleep(Duration::from_millis(500));
    }
    delete_crashloop(&kubeconfig);

    // --- 3. the cluster is still one a caller would want ---
    //
    // Both agents go NotReady for a few seconds first, and that is the
    // warp working rather than breaking. A node's lease is 40 s and its
    // kubelet renews every 10 s, so a jump wider than 40 s lands with
    // every lease's `renewTime` further in the past than the control
    // plane now tolerates. They come back on the next renewal. A caller
    // asking for "+90 s" is asking for exactly that, and anything using
    // this as a fault injector wants the number, so measure it.
    let readiness_recovered = Instant::now();
    wait_nodes_ready(&kubeconfig, &names, CONVERGE);
    eprintln!(
        "MEASUREMENT all nodes Ready again after the +{}s warp expired their \
         40s leases: {:?}",
        BACKOFF_WARP.as_secs(),
        readiness_recovered.elapsed()
    );
    kubectl_round_trip(&kubeconfig, "warp-after");
    for (i, agent) in agents.iter_mut().enumerate() {
        // The pre-warp connection is still good: proof the warp cost
        // nobody their vsock session.
        assert_eq!(
            sh_ok(agent, "echo alive").trim(),
            "alive",
            "{}: vsock exec broke across the warps",
            whose[i]
        );
        check_clocksource(agent, whose[i]);
        check_no_splats(agent, whose[i]);
    }
}
