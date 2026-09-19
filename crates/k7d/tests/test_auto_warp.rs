//! The cluster's idle wall time, deleted without being
//! asked.
//!
//! `warp_clock` could be *told* "+90 s". This is the policy that decides it: a
//! loop that pauses every member of a cluster, establishes that the
//! whole thing is idle, works out when the next thing was going to
//! happen, and jumps to just before it — all inside one pause, because
//! resuming between the check and the warp reopens every race the check
//! closed.
//!
//! Two claims are worth a test, and they are different claims:
//!
//! 1. **`jump` mode buys real time.** A pod parked in the kubelet's
//!    300 s crash-loop backoff restarts after far less than 300 s of
//!    *wall* time while the cluster's own timestamps still say it
//!    waited the full five minutes — and no node goes `NotReady`, which
//!    is what the 30 s single-jump cap is for. We measured a +90 s
//!    warp taking every agent `NotReady` for ~9 s; a policy that did
//!    that in every idle window would be a fault injector, not a
//!    speedup.
//! 2. **`micro` mode buys time on a cluster that is never all-idle.**
//!    Fixed 50 ms quantum at 20 Hz, no idleness claimed: the pause is
//!    the atomicity and lateness is bounded by the quantum. The honest
//!    assertion is that guest time outruns wall time — *not* that work
//!    goes faster. The clock survey bounds the useful part at 1.11× in the busy
//!    phase, and a clock ratio is not a throughput ratio.
//!
//! What is deliberately *not* asserted is that the policy warps often.
//! Declining is always correct, and the predicate declines on things
//! this suite cannot arrange (a frame on a TAP, an interrupt caught
//! mid-injection, a PIT one-shot whose expiry KVM will not export). So
//! the decline histogram is printed as a MEASUREMENT on every run: when
//! a compression assertion fails, that table is the reason, and it is
//! the input to dilation rather than something to tune the predicate
//! against.

mod common;

use std::path::Path;
use std::time::{Duration, Instant};

use k7d::autowarp::{AutoWarpMode, AutoWarpStats, Cycle, DeclineReason, Driver, MAX_JUMP};
use k7d::control::{Daemon, Request, Response};
use k7d::vm::Vm;

use common::ubuntu::connect_or_dump;
use common::ubuntu_k3s::{
    bring_up_cluster, deploy_churn, kubectl, pod_restarts, settle_cluster, wait_nodes_ready,
    UbuntuCluster, CONVERGE,
};
use common::warp::{
    check_clockevent, check_clocksource, check_no_ntp_client, check_no_splats, delete_crashloop,
    guest_clocks, kubectl_round_trip, last_terminated_secs, start_crashloop, BACKOFF_SCHEDULE,
    CRASHLOOP_POD,
};

/// Guest-observed backoff that counts as "the ~5 min one" the spec's
/// claim is about. The kubelet's nominal cap is
/// `BACKOFF_SCHEDULE`'s 300 s, but the measured gap is death-to-death:
/// it carries the container's own start-and-exit time and a poll lag,
/// and the kubelet's `flowcontrol.Backoff` does not promise the nominal
/// figure to the second. So the window is *discovered* rather than
/// counted to — see [`walk_backoffs`].
const CAP_MIN: i64 = 240;

/// The spec's headline: ~300 s of guest backoff for under 150 s of wall
/// time. Half the guest time is a 2× floor on the compression, which is
/// well inside the survey's 3.59× ceiling for the backoff-wait phase.
///
/// Measured (132.3 s, 2.34×) on guests whose timers are the LAPIC
/// one-shot — the AMD nodes. There KVM's hrtimer is host-anchored, so a
/// jump to `earliest − ε` does not make that timer fire: it fires when
/// it was always going to, the guest wakes to find its clock past the
/// expiry, and every idle cycle in between has jumped the same target
/// again. That is suspend semantics, and part of the 2.34× is the guest
/// believing more time passed than the timers it slept on.
const BACKOFF_WALL_CEILING_ONE_SHOT: Duration = Duration::from_secs(150);

/// The same claim on guests whose timers are TSC deadlines — the Intel
/// node, where the host advertises `CPUID.1:ECX[24]` and Linux
/// registers `lapic-deadline`. `Vm::warp_vcpus` rewrites the deadline
/// after the offset moves, KVM fires it on the next entry, and the jump
/// deletes exactly one idle gap: the guest wakes, does its work, and
/// the next cycle finds a vCPU awake. Exact, bounded, and slower —
/// measured once at 191.8 s for a 314 s window (1.64×, 42% of cycles
/// declined `vcpu_awake` against 18% on AMD). 25% over that; a 1.3×
/// floor. Mirroring the one-shot's host-anchored expiry by shifting the
/// deadline with the offset was tried and rejected (CHALLENGES #261).
const BACKOFF_WALL_CEILING_DEADLINE: Duration = Duration::from_secs(240);

/// Wall time the whole walk to a capped backoff may take. The guest has
/// to live through the entire doubling schedule
/// (10+20+40+80+160+300 = 610 s of guest time) to produce one capped
/// window, so at 1× — a policy that never warps — this is where the
/// test gives up and prints the schedule it actually saw.
const WALK_WALL_CEILING: Duration = Duration::from_secs(900);

/// Fraction of guest time the survey measured the 3-node cluster all-idle in
/// the backoff-wait phase. The compression ceiling follows from it —
/// idle time is the only time there is to delete — so a run that beats
/// `1/(1 − ALL_IDLE_WAITING)` has not found a faster policy, it has an
/// accounting bug. The survey's own measured bound was 3.59×; this is the
/// arithmetic ceiling it sits under.
const ALL_IDLE_WAITING: f64 = 0.734;

/// How long `micro` mode runs on the churning cluster.
const MICRO_RUN: Duration = Duration::from_secs(60);

/// Wall time each `pump` call spends running policy cycles before
/// handing the thread back for a `kubectl` poll.
///
/// A `kubectl` round-trip to the in-guest API server takes the better
/// part of a second and the policy loop is not running during it, so
/// this trades measurement resolution for honesty: at 4 s the polls are
/// under a fifth of the run, and a restart is placed to within one
/// slice — 1.7% of the ~300 s window that matters.
const PUMP_SLICE: Duration = Duration::from_secs(4);

/// Poll node readiness every this many slices. Once per slice would
/// double the `kubectl` time; a node that has gone `NotReady` because a
/// jump expired its lease stays that way for seconds (measured
/// ~9 s), so it cannot hide between checks.
const READY_EVERY: u32 = 3;

/// What a stretch of policy cycles did, in host time only.
#[derive(Debug, Default)]
struct Pumped {
    /// Guest time added over the whole run.
    added: Duration,
    /// Widest single jump — the 30 s cap is on this, not on the total.
    widest: Duration,
    /// Cycles run.
    cycles: u64,
}

impl Pumped {
    fn absorb(&mut self, other: &Pumped) {
        self.added += other.added;
        self.widest = self.widest.max(other.widest);
        self.cycles += other.cycles;
    }
}

/// Run policy cycles against the cluster for `slice` of wall time.
///
/// The test drives the loop inline rather than through a thread because
/// it also has to run `kubectl`, and interleaving on one thread is the
/// simplest way to be sure no `kubectl` round-trip is in flight while
/// the cluster is paused — which is the fifth safety check, arranged
/// rather than declared.
fn pump(cluster: &mut UbuntuCluster, driver: &mut Driver, slice: Duration) -> Pumped {
    let started = Instant::now();
    let mut out = Pumped::default();
    while started.elapsed() < slice {
        let cycle = {
            let mut vms: [&mut Vm; 3] = [
                &mut cluster.server,
                &mut cluster.agent1,
                &mut cluster.agent2,
            ];
            driver.cycle(&mut vms, None)
        };
        out.cycles += 1;
        if let Some(delta) = cycle.warped() {
            out.added += delta;
            out.widest = out.widest.max(delta);
        }
        driver.pace(&cycle);
    }
    out
}

/// Print the counters the way the dilation bench will read them.
fn report(tag: &str, stats: &AutoWarpStats, pumped: &Pumped, wall: Duration) {
    let declines = if stats.declines.is_empty() {
        "none".to_string()
    } else {
        stats
            .declines
            .iter()
            .map(|(k, v)| format!("{k}={v}"))
            .collect::<Vec<_>>()
            .join(" ")
    };
    // The per-phase means are what tell a failed compression assertion
    // *why*: the pause is wall time in which no guest time passes, so
    // whichever phase dominates it is the thing bounding how often a
    // busy cluster may be probed and how much of an idle window a jump
    // can convert (CHALLENGES #183).
    let per_cycle_us = |ns: u64| {
        if stats.cycles == 0 {
            0.0
        } else {
            ns as f64 / stats.cycles as f64 / 1e3
        }
    };
    eprintln!(
        "MEASUREMENT {tag}: {} cycles, {} warps, +{:.1}s guest added over {:?} wall, \
         widest jump {:?}, {:.1}ms paused ({:.2}× guest per paused ns), \
         mean cycle {:.0}µs = pause {:.0} + decide {:.0} + warp {:.0} + resume {:.0}µs, \
         pause = freeze {:.0} + stop-vcpus {:.0} ({:.1} signals/cycle) \
         + quiesce {:.0}µs, \
         APIC bus cycle {}; declines: {declines}",
        stats.cycles,
        stats.warps,
        pumped.added.as_secs_f64(),
        wall,
        pumped.widest,
        stats.wall_ns_paused as f64 / 1e6,
        stats.guest_per_wall_paused(),
        per_cycle_us(stats.wall_ns_paused),
        per_cycle_us(stats.pause_ns),
        per_cycle_us(stats.decide_ns),
        per_cycle_us(stats.warp_ns),
        per_cycle_us(stats.resume_ns),
        per_cycle_us(stats.freeze_ns),
        per_cycle_us(stats.stop_vcpus_ns),
        if stats.cycles == 0 {
            0.0
        } else {
            stats.stop_signal_rounds as f64 / stats.cycles as f64
        },
        per_cycle_us(stats.quiesce_ns),
        stats.apic_bus_cycle_fs.map_or_else(
            || "unmeasured (no one-shot count to convert)".to_string(),
            |fs| format!("{fs}fs")
        ),
    );
    assert_eq!(
        stats.resume_failures, 0,
        "{tag}: {} member(s) failed to resume after a cycle — a policy loop that leaves a \
         VM paused has stopped a node, not accelerated it",
        stats.resume_failures
    );
    assert!(
        pumped.widest <= MAX_JUMP,
        "{tag}: a single jump was {:?}, over the {MAX_JUMP:?} cap — a jump past the 40 s \
         node lease takes every agent NotReady (measured ~9 s of it)",
        pumped.widest
    );
}

/// One inter-restart window: what the cluster believed it waited, and
/// what that belief cost in host wall time.
#[derive(Debug, Clone, Copy)]
struct Backoff {
    /// Restart count the window ended on.
    restart: u64,
    /// Death-to-death gap in the cluster's *own* timestamps, stamped by
    /// a kubelet whose clock the policy is moving.
    guest: i64,
    /// Host wall time the same window took. Both ends are measured at
    /// the poll that noticed a restart, so the poll lag cancels.
    wall: Duration,
    /// Guest time the policy added inside the window.
    added: Duration,
}

impl Backoff {
    fn ratio(&self) -> f64 {
        self.guest as f64 / self.wall.as_secs_f64()
    }
}

/// The backoff schedule as observed, for a failure message. The point
/// of printing it is that this test does not assume it: the first run of
/// We assert against the nominal 10/20/40/80/160/300 by counting
/// restarts and measured an 81 s window it believed was the 300 s cap
/// (`CHALLENGES.md` #184).
fn schedule_table(windows: &[Backoff]) -> String {
    if windows.is_empty() {
        return "no restart was observed at all".to_string();
    }
    windows
        .iter()
        .map(|w| {
            format!(
                "restart {}: {}s guest in {:.0}s wall ({:.2}×)",
                w.restart,
                w.guest,
                w.wall.as_secs_f64(),
                w.ratio()
            )
        })
        .collect::<Vec<_>>()
        .join("\n  ")
}

/// Run the policy against the crash-looping pod, recording one
/// [`Backoff`] per restart, until the cluster has waited out a window of
/// at least [`CAP_MIN`] guest seconds.
///
/// The schedule is walked rather than counted to. The kubelet's nominal
/// doubling is `BACKOFF_SCHEDULE`, but which restart lands on the cap
/// depends on whether the first failure backs off at all and on the
/// container's own start-and-exit time, and getting that wrong measures
/// a short window while claiming it is the long one — which is exactly
/// what happened the first time (`CHALLENGES.md` #184). Reading the gap
/// the cluster itself recorded, for every restart, cannot be wrong about
/// which window it is.
fn walk_backoffs(
    cluster: &mut UbuntuCluster,
    driver: &mut Driver,
    kubeconfig: &Path,
    names: &[String],
) -> (Vec<Backoff>, Pumped, u32, Duration) {
    let started = Instant::now();
    let mut total = Pumped::default();
    let mut window = Pumped::default();
    let mut windows: Vec<Backoff> = Vec::new();
    let mut ready_lapses = 0_u32;
    let mut slices = 0_u32;
    let mut restarts = pod_restarts(kubeconfig, CRASHLOOP_POD);
    let mut mark = last_terminated_secs(kubeconfig, CRASHLOOP_POD);
    let mut window_started = Instant::now();

    while started.elapsed() < WALK_WALL_CEILING {
        let slice = pump(cluster, driver, PUMP_SLICE);
        total.absorb(&slice);
        window.absorb(&slice);
        slices += 1;
        // A node going NotReady is the failure the 30 s cap exists to
        // prevent, so it is checked while the policy runs rather than
        // waited out afterwards.
        if slices % READY_EVERY == 0 && !nodes_all_ready(kubeconfig, names) {
            ready_lapses += 1;
        }

        let seen = pod_restarts(kubeconfig, CRASHLOOP_POD);
        if seen == restarts {
            continue;
        }
        restarts = seen;
        let stamp = last_terminated_secs(kubeconfig, CRASHLOOP_POD);
        if let (Some(from), Some(to)) = (mark, stamp) {
            let backoff = Backoff {
                restart: restarts,
                guest: to - from,
                wall: window_started.elapsed(),
                added: window.added,
            };
            eprintln!(
                "MEASUREMENT backoff window to restart {}: {}s of guest time in \
                 {:.1}s of wall time ({:.2}×), policy added {:.1}s over {} cycles",
                backoff.restart,
                backoff.guest,
                backoff.wall.as_secs_f64(),
                backoff.ratio(),
                backoff.added.as_secs_f64(),
                window.cycles
            );
            // Reported per window, not only at the end: the phase
            // breakdown is how a compression failure gets diagnosed,
            // and waiting for the whole walk to print it costs a
            // quarter of an hour per look (`CHALLENGES.md` #183).
            report(
                &format!("jump window to restart {}", backoff.restart),
                &driver.stats(),
                &window,
                backoff.wall,
            );
            windows.push(backoff);
        }
        mark = stamp;
        window_started = Instant::now();
        window = Pumped::default();
        if windows.last().is_some_and(|w| w.guest >= CAP_MIN) {
            break;
        }
    }
    (windows, total, ready_lapses, started.elapsed())
}

/// Every node is `Ready` right now, without waiting.
fn nodes_all_ready(kubeconfig: &Path, names: &[String]) -> bool {
    let Ok(out) = kubectl(
        kubeconfig,
        &[
            "get",
            "nodes",
            "-o",
            "jsonpath={range .items[*]}{.metadata.name}={.status.conditions[?(@.type=='Ready')].status}{'\\n'}{end}",
        ],
    ) else {
        return false;
    };
    names.iter().all(|n| out.contains(&format!("{n}=True")))
}

/// Every member's three guest clocks, in cluster order.
fn read_clocks(cluster: &mut UbuntuCluster, whose: &[&str; 3]) -> [[f64; 3]; 3] {
    let mut agents = [
        connect_or_dump(&mut cluster.server, whose[0]),
        connect_or_dump(&mut cluster.agent1, whose[1]),
        connect_or_dump(&mut cluster.agent2, whose[2]),
    ];
    [
        guest_clocks(&mut agents[0], whose[0]),
        guest_clocks(&mut agents[1], whose[1]),
        guest_clocks(&mut agents[2], whose[2]),
    ]
}

#[test]
fn test_auto_warp_jump_compresses_a_crash_loop_backoff() {
    let _ = env_logger::builder().is_test(true).try_init();

    let mut cluster = bring_up_cluster();
    let names = cluster.names();
    let kubeconfig = cluster.kubeconfig.clone();
    let whose = ["server", "agent-1", "agent-2"];

    // The preconditions the whole increment rests on, asserted before
    // any clock moves: the guest reads the clock k7d owns, arms either
    // the LAPIC one-shot or the TSC deadline (which one is the host's
    // choice, and decides the wall ceiling below), and runs no NTP
    // client to fight a 20 Hz policy loop.
    let tsc_deadline = {
        let mut agents = [
            connect_or_dump(&mut cluster.server, whose[0]),
            connect_or_dump(&mut cluster.agent1, whose[1]),
            connect_or_dump(&mut cluster.agent2, whose[2]),
        ];
        let mut per_cpu = Vec::new();
        for (i, agent) in agents.iter_mut().enumerate() {
            check_clocksource(agent, whose[i]);
            let clockevents = check_clockevent(agent, whose[i]);
            check_no_ntp_client(agent, whose[i]);
            eprintln!(
                "MEASUREMENT {} tick_broadcast device: {} \
                 (the timer the predicate declines on when KVM will not export its expiry)",
                whose[i], clockevents.broadcast
            );
            per_cpu.push(clockevents.per_cpu);
        }
        per_cpu.dedup();
        assert_eq!(
            per_cpu.len(),
            1,
            "the members of one cluster on one host arm different timers ({per_cpu:?}) — the \
             compression claim below is per timer, so it does not know which one to make"
        );
        per_cpu[0] == "lapic-deadline"
    };
    let backoff_wall_ceiling = if tsc_deadline {
        BACKOFF_WALL_CEILING_DEADLINE
    } else {
        BACKOFF_WALL_CEILING_ONE_SHOT
    };

    settle_cluster(&kubeconfig, "auto-warp");
    start_crashloop(&kubeconfig);

    let mut driver = Driver::new(AutoWarpMode::Jump);
    let before = read_clocks(&mut cluster, &whose);

    // Walk the kubelet's doubling schedule with the policy running
    // throughout, recording what the cluster believed each wait was and
    // what it cost. The policy runs during the short waits too, which is
    // the point: the 610 s of guest time it takes to *reach* a capped
    // backoff should not cost 610 s of wall time either.
    let (windows, total, ready_lapses, walk_wall) =
        walk_backoffs(&mut cluster, &mut driver, &kubeconfig, &names);
    report("jump", &driver.stats(), &total, walk_wall);
    // What the *guests* saw, independently of what the counters claim
    // to have given them. Reported for `jump` as well as `micro`
    // because the two can disagree: a counter records the delta the
    // policy asked `warp_clock` for, and only the guest can say how
    // much of it it kept.
    let after = read_clocks(&mut cluster, &whose);
    for (i, node) in after.iter().enumerate() {
        let monotonic = node[1] - before[i][1];
        eprintln!(
            "MEASUREMENT jump {} over {walk_wall:?} of wall time: monotonic \
             +{monotonic:.1}s ({:.2}×), realtime +{:.1}s, policy asked for +{:.1}s",
            whose[i],
            monotonic / walk_wall.as_secs_f64(),
            node[0] - before[i][0],
            total.added.as_secs_f64(),
        );
    }
    eprintln!(
        "MEASUREMENT observed backoff schedule (nominal {BACKOFF_SCHEDULE:?}):\n  {}",
        schedule_table(&windows)
    );

    // The window the compression claim is about is the longest one the
    // cluster believes it waited. Anything shorter is a different claim.
    let capped = windows
        .iter()
        .max_by_key(|w| w.guest)
        .copied()
        .unwrap_or_else(|| {
            panic!(
                "{CRASHLOOP_POD} never restarted in {walk_wall:?} of wall time. \
                 Counters: {:?}",
                driver.stats()
            )
        });
    assert!(
        capped.guest >= CAP_MIN,
        "the longest backoff the cluster believes it waited in {walk_wall:?} was {}s, under \
         the {CAP_MIN}s this claim is about. Either the policy is too slow to get the \
         kubelet to its cap, or the schedule is not the one assumed:\n  {}\nCounters: {:?}",
        capped.guest,
        schedule_table(&windows),
        driver.stats()
    );

    let ceiling = 1.0 / (1.0 - ALL_IDLE_WAITING);
    eprintln!(
        "MEASUREMENT jump-mode compression: {}s of guest backoff in {:?} of wall \
         time = {:.2}× (idleness ceiling {ceiling:.2}×, measured bound 3.59×; timers are \
         {}, wall ceiling {backoff_wall_ceiling:?})",
        capped.guest,
        capped.wall,
        capped.ratio(),
        if tsc_deadline {
            "TSC deadlines"
        } else {
            "LAPIC one-shots"
        }
    );
    assert!(
        capped.wall < backoff_wall_ceiling,
        "a {}s guest backoff cost {:?} of wall time, over the {backoff_wall_ceiling:?} \
         bound. Counters: {:?}",
        capped.guest,
        capped.wall,
        driver.stats()
    );
    assert!(
        capped.ratio() <= ceiling,
        "{:.2}× beats the {ceiling:.2}× that the {:.1}% all-idle fraction allows — \
         idle time is the only time there is to delete, so this is an accounting bug, not a \
         faster policy",
        capped.ratio(),
        ALL_IDLE_WAITING * 100.0
    );
    assert_eq!(
        ready_lapses, 0,
        "a node went NotReady during {} policy cycles — the 30 s single-jump cap is there \
         so an automatic policy never expires a 40 s node lease (widest jump seen: {:?})",
        total.cycles, total.widest
    );

    // --- 3. the cluster is still one a caller would want ---
    delete_crashloop(&kubeconfig);
    wait_nodes_ready(&kubeconfig, &names, CONVERGE);
    kubectl_round_trip(&kubeconfig, "auto-warp-after");
    let mut agents = [
        connect_or_dump(&mut cluster.server, whose[0]),
        connect_or_dump(&mut cluster.agent1, whose[1]),
        connect_or_dump(&mut cluster.agent2, whose[2]),
    ];
    for (i, agent) in agents.iter_mut().enumerate() {
        check_clocksource(agent, whose[i]);
        check_no_ntp_client(agent, whose[i]);
        check_no_splats(agent, whose[i]);
    }
}

#[test]
fn test_auto_warp_micro_outruns_wall_time_on_a_busy_cluster() {
    let _ = env_logger::builder().is_test(true).try_init();

    let mut cluster = bring_up_cluster();
    let names = cluster.names();
    let kubeconfig = cluster.kubeconfig.clone();
    let whose = ["server", "agent-1", "agent-2"];

    settle_cluster(&kubeconfig, "auto-warp-micro");
    // Churn is the point: `micro` mode exists for the workloads that
    // never give the whole cluster an idle window, so measuring it on an
    // idle one would measure `jump` mode's regime by accident.
    deploy_churn(&kubeconfig);

    let before = {
        let mut agents = [
            connect_or_dump(&mut cluster.server, whose[0]),
            connect_or_dump(&mut cluster.agent1, whose[1]),
            connect_or_dump(&mut cluster.agent2, whose[2]),
        ];
        for (i, agent) in agents.iter_mut().enumerate() {
            check_clocksource(agent, whose[i]);
            check_no_ntp_client(agent, whose[i]);
        }
        [
            guest_clocks(&mut agents[0], whose[0]),
            guest_clocks(&mut agents[1], whose[1]),
            guest_clocks(&mut agents[2], whose[2]),
        ]
    };

    let mut driver = Driver::new(AutoWarpMode::Micro);
    let started = Instant::now();
    let mut pumped = Pumped::default();
    while started.elapsed() < MICRO_RUN {
        let slice = pump(&mut cluster, &mut driver, PUMP_SLICE);
        pumped.absorb(&slice);
    }
    let wall = started.elapsed();
    report("micro", &driver.stats(), &pumped, wall);
    assert!(
        driver.stats().warps > 0,
        "micro mode warped nothing in {wall:?} — the whole point is that it does not wait \
         for an idle window"
    );

    let after = {
        let mut agents = [
            connect_or_dump(&mut cluster.server, whose[0]),
            connect_or_dump(&mut cluster.agent1, whose[1]),
            connect_or_dump(&mut cluster.agent2, whose[2]),
        ];
        [
            guest_clocks(&mut agents[0], whose[0]),
            guest_clocks(&mut agents[1], whose[1]),
            guest_clocks(&mut agents[2], whose[2]),
        ]
    };

    // `CLOCK_MONOTONIC` is the one that matters: it is what Go's
    // `time.Since` — and so every kubelet backoff and lease renewal —
    // measures with, and it is the one an NTP client could not undo.
    for (i, node) in after.iter().enumerate() {
        let monotonic = node[1] - before[i][1];
        let realtime = node[0] - before[i][0];
        eprintln!(
            "MEASUREMENT micro {} over {wall:?} of wall time: monotonic +{monotonic:.1}s \
             ({:.2}×), realtime +{realtime:.1}s",
            whose[i],
            monotonic / wall.as_secs_f64()
        );
        assert!(
            monotonic > wall.as_secs_f64(),
            "{}: guest monotonic clock advanced {monotonic:.1}s in {wall:?} of wall time — \
             micro mode added nothing this node could observe",
            whose[i]
        );
    }

    wait_nodes_ready(&kubeconfig, &names, CONVERGE);
    let mut agents = [
        connect_or_dump(&mut cluster.server, whose[0]),
        connect_or_dump(&mut cluster.agent1, whose[1]),
        connect_or_dump(&mut cluster.agent2, whose[2]),
    ];
    for (i, agent) in agents.iter_mut().enumerate() {
        check_clocksource(agent, whose[i]);
        check_no_splats(agent, whose[i]);
    }
    kubectl_round_trip(&kubeconfig, "micro-after");
}

/// The daemon-side op, without a cluster: `AutoWarp` refuses to start a
/// loop on a cluster it owns no VM on, `AutoWarpStatus` answers for a
/// cluster that never had one, and the hold — the explicit form of the
/// fifth safety check — cannot be double-taken or released by somebody
/// who never took it.
///
/// The loop itself is exercised against real VMs by the two tests
/// above; what is checked here is the wiring a caller (the gym)
/// actually touches, including the failure modes that would otherwise
/// be silent.
#[test]
fn test_auto_warp_op_refuses_to_guess() {
    let _ = env_logger::builder().is_test(true).try_init();
    let daemon = Daemon::new();

    let started = daemon.handle(Request::AutoWarp {
        cluster_id: "no-such-cluster".to_string(),
        mode: AutoWarpMode::Jump,
    });
    match started {
        Response::Error { message } => assert!(
            message.contains("no VM on cluster"),
            "a loop on an empty cluster must say so, not count no_members forever: {message}"
        ),
        other => panic!("auto_warp on an empty cluster should be an error, got {other:?}"),
    }

    // `off` on a cluster that never ran a loop is not an error: it is
    // how a caller collects a finished run's accounting, and a run that
    // never started has all-zero accounting.
    match daemon.handle(Request::AutoWarp {
        cluster_id: "no-such-cluster".to_string(),
        mode: AutoWarpMode::Off,
    }) {
        Response::AutoWarp { mode, stats, .. } => {
            assert_eq!(mode, AutoWarpMode::Off);
            assert_eq!(stats, AutoWarpStats::default());
        }
        other => panic!("auto_warp off should report counters, got {other:?}"),
    }

    let hold = |holder: &str, hold: bool| {
        daemon.handle(Request::AutoWarpHold {
            cluster_id: "c1".to_string(),
            holder: holder.to_string(),
            hold,
        })
    };
    match hold("gym-exec", true) {
        Response::AutoWarp { holders, .. } => assert_eq!(holders, vec!["gym-exec".to_string()]),
        other => panic!("taking a hold should report the holders, got {other:?}"),
    }
    assert!(
        matches!(hold("gym-exec", true), Response::Error { .. }),
        "a double take must fail: one release would then free a hold the other caller \
         still needs"
    );
    assert!(
        matches!(hold("nobody", false), Response::Error { .. }),
        "releasing a hold nobody took must fail — it would unblock somebody else's warp"
    );
    match hold("gym-exec", false) {
        Response::AutoWarp { holders, .. } => assert!(holders.is_empty()),
        other => panic!("releasing a hold should report the holders, got {other:?}"),
    }
    match daemon.handle(Request::AutoWarpStatus {
        cluster_id: "c1".to_string(),
    }) {
        Response::AutoWarp { mode, stats, .. } => {
            assert_eq!(mode, AutoWarpMode::Off);
            assert_eq!(stats.cycles, 0);
        }
        other => panic!("auto_warp_status should answer for any cluster, got {other:?}"),
    }
}

/// A cycle whose caller declares an action in flight must not pause the
/// cluster, let alone warp it — and it must decline for *that* reason
/// rather than for whatever else it would have noticed. Checked without
/// a VM because the decision is made before KVM is touched, and it is
/// the one safety check that cannot be read off KVM at all.
#[test]
fn test_auto_warp_declines_while_an_action_is_in_flight() {
    let _ = env_logger::builder().is_test(true).try_init();
    let mut driver = Driver::new(AutoWarpMode::Micro);

    let held = driver.cycle(&mut [], Some("gym exec on member 0"));
    match &held {
        Cycle::Declined(d) => {
            assert_eq!(d.reason, DeclineReason::ActionInFlight);
            assert!(d.detail.contains("gym exec"), "detail was {:?}", d.detail);
        }
        Cycle::Warped(_) => panic!("a cycle with an action in flight must never warp"),
    }
    assert!(
        !held.paused(),
        "a cycle that declined before the pause must not ask its caller to re-attach \
         cgroups it never disturbed"
    );

    // No hold and no members is a different fault, and counts as one:
    // a cluster the caller thinks exists but the daemon owns no VM on.
    match driver.cycle(&mut [], None) {
        Cycle::Declined(d) => assert_eq!(d.reason, DeclineReason::NoMembers),
        Cycle::Warped(_) => panic!("a cycle with no members must never warp"),
    }

    let stats = driver.stats();
    assert_eq!(stats.warps, 0);
    assert_eq!(stats.cycles, 2);
    assert_eq!(stats.guest_ns_added, 0);
    assert_eq!(stats.wall_ns_paused, 0, "neither cycle paused anything");
    assert_eq!(stats.declines.get("action_in_flight"), Some(&1));
    assert_eq!(stats.declines.get("no_members"), Some(&1));
}
