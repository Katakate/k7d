//! Auto-warp: delete a cluster's idle wall time without being asked.
//!
//! `warp_clock` gave the daemon a warp it can be *told* to do. This is the
//! policy that decides to do it: with every member of a cluster paused,
//! establish that the whole cluster is idle, work out when the next
//! thing was going to happen, and jump to just before it — all inside
//! the same pause, because resuming between the check and the warp
//! reopens every race the check just closed.
//!
//! Two measured facts shape it, and neither is negotiable:
//!
//! 1. **There is no deadline MSR to jump to.** `IA32_TSC_DEADLINE` reads
//!    zero on every vCPU of every node in every sample,
//!    because `KVM_GET_SUPPORTED_CPUID` does not report
//!    `CPUID.1:ECX[24]` on this host kernel; we confirmed it from
//!    inside the guest (`/proc/timer_list` says `lapic`, never
//!    `lapic-deadline`). The timer the guest actually arms is the LAPIC
//!    one-shot, read here through `KVM_GET_LAPIC`'s live `TMCCT`.
//! 2. **A jump wider than a node lease flaps the cluster.** Leases are
//!    40 s with 10 s kubelet renewal, and we measured a +90 s warp
//!    taking every agent `NotReady` for ~9 s. Correct for a caller who
//!    asked; not something a policy may inject into every idle window.
//!    Hence [`MAX_JUMP`].
//!
//! Everything here is host time. The guest clocks are the thing being
//! moved, so no decision may be derived from them.
//!
//! ## What a jump target is, and is not
//!
//! Hard safety comes from the pause: the clock only moves while every
//! member is stopped and every device is quiescent, exactly as on the
//! fork path. A forward jump never *loses* a timer — the host hrtimers
//! backing the guest's timers are untouched, so they fire at the same
//! host instant either way. What the target buys is **fidelity**: land
//! just before the earliest armed deadline and no timer's
//! guest-observed firing time moves by more than ε, so the cluster
//! cannot tell the deleted wall time from a scheduling hiccup. Jump
//! further and timers start firing late in guest time, bunched
//! together, which is where lease flapping and reordered reconcile
//! loops come from.
//!
//! Which is why a periodic timer is never a target. A rate generator is
//! the guest asking "tick me this often", not "wake me at T"; a forward
//! jump changes how many of its ticks land in a guest second in exactly
//! the way suspend/resume does, which is what `KVM_KVMCLOCK_CTRL` tells
//! the guest happened.

use std::collections::BTreeMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

use crate::vm::{TimerSurvey, Vm};

/// Longest single jump the policy will ever take.
///
/// Not headroom — "stay under the node lease". A k3s node lease is 40 s
/// and its kubelet renews every 10 s, so a jump past 40 s lands with
/// every lease already expired from the control plane's point of view;
/// We measured the resulting `NotReady` window at ~9 s. 30 s leaves a
/// full renewal interval of margin.
pub const MAX_JUMP: Duration = Duration::from_secs(30);

/// Gap left between the jump and the deadline it is jumping to, so the
/// timer still fires *after* the warp rather than being landed on.
pub const EPSILON: Duration = Duration::from_micros(100);

/// Shortest jump worth taking. We measured `warp_clock_lockstep` on
/// three VMs at 0.79–0.83 ms, so a jump under a millisecond deletes
/// less guest time than the warp itself costs in wall time — a loss,
/// not a gain, and the only reason this floor exists.
pub const MIN_JUMP: Duration = Duration::from_millis(1);

/// Fixed quantum of `micro` mode, and its period: 20 Hz × 50 ms, both
/// from the survey. At the measured 0.79–0.83 ms warp that is 1.7% of the
/// quantum in overhead — the busy fraction is the entire constraint,
/// not the cycle cost, so there is nothing to win by making the pause
/// cheaper or the quantum longer.
///
/// Also `jump` mode's fallback when the whole cluster is provably idle
/// and *no* source reports an armed deadline: with
/// nothing armed there is no deadline to overshoot, and inventing a
/// target from the absence of one is the thing that is never allowed.
pub const MICRO_QUANTUM: Duration = Duration::from_millis(50);

/// Wall time the *first* probe after the cluster stopped being provably
/// idle leaves it running for every unit of wall time the loop has been
/// leaving it paused — a 25% pause duty cycle at that first probe,
/// stated as the ratio so nothing has to divide.
///
/// It is a budget rather than a period because a pause is wall time in
/// which no guest time passes: probing costs the cluster exactly the
/// pauses it takes, while all a longer wait buys is a smaller bill and
/// all it costs is idle windows that open and close unseen. Deriving the
/// first probe from the measured pause keeps that price fixed however
/// expensive the pause turns out to be — which matters, because the
/// first version of this loop had a 6.4 ms pause and no idea
/// (`CHALLENGES.md` #183).
///
/// Consecutive declines double the wait up to [`PROBE_INTERVAL_MAX`], so
/// 25% is what a cluster that merely twitched pays, and a cluster that
/// is genuinely busy is left alone at the survey's cadence and ~1%.
///
/// The survey's flat 20–50 ms is not used as the cadence itself: it was the
/// sampling rate of a read-only survey that never paused anything, and
/// so had no duty cycle to respect.
pub const PROBE_RUN_PER_PAUSE: u32 = 3;

/// Floor and ceiling on the probe interval. The floor keeps a
/// suspiciously cheap pause from turning the loop into a spin; the
/// ceiling is the survey's sampling cadence, past which idle windows on a
/// 3-node cluster are being missed wholesale.
pub const PROBE_INTERVAL_MIN: Duration = Duration::from_millis(2);
/// See [`PROBE_INTERVAL_MIN`].
pub const PROBE_INTERVAL_MAX: Duration = Duration::from_millis(50);

/// Grace added to the wait for a timer this loop declined to jump over,
/// so the next cycle lands *after* the wakeup that timer causes instead
/// of inside it.
///
/// Without it the loop phase-locks itself to the guests' timers: it
/// waits exactly until the timer fires and then samples, which is the
/// one instant a vCPU is guaranteed to be awake. The first run of this
/// policy reported half its cycles declining for `vcpu_awake` on a
/// cluster the survey had measured 73.4% all-idle, and that gap was the
/// sampling bias, not the cluster (`CHALLENGES.md` #183).
pub const WAKEUP_GRACE: Duration = Duration::from_micros(500);

/// Pause cost the loop assumes before it has measured its own — the
/// survey's 0.65 ms and the primitive's 0.79–0.83 ms, rounded up. Wrong in either
/// direction costs a handful of cycles: the estimate is an EWMA over
/// every cycle, warps and declines alike.
const ASSUMED_PAUSE_COST: Duration = Duration::from_millis(1);

/// Pause window spent measuring the APIC bus cycle, once per driver.
///
/// 2 ms is ~2 million bus cycles at KVM's 1 ns, so the ratio is precise
/// to well under a part in a thousand, while staying short enough that
/// a vCPU's armed one-shot timer usually outlives it (a timer that
/// expires inside the window fails the calibration, which then simply
/// retries on the next idle cycle).
const CALIBRATION_WINDOW: Duration = Duration::from_millis(2);

/// What the policy loop is doing for one cluster.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum AutoWarpMode {
    /// No policy loop. `AutoWarp { mode: off }` stops a running one.
    Off,
    /// Probe at [`PROBE_RUN_PER_PAUSE`]; when the whole cluster is provably
    /// idle, jump to just before its earliest armed deadline.
    Jump,
    /// Warp by [`MICRO_QUANTUM`] every [`MICRO_QUANTUM`] regardless of
    /// idleness. Atomicity comes from the pause; the fidelity cost is
    /// timers firing late by at most the quantum.
    Micro,
}

impl AutoWarpMode {
    /// Name used on the wire and in log lines.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            AutoWarpMode::Off => "off",
            AutoWarpMode::Jump => "jump",
            AutoWarpMode::Micro => "micro",
        }
    }
}

/// Why a cycle did not warp. Every one of these is a *correct* outcome —
/// declining costs a sample, guessing a target costs correctness — so
/// they are counted rather than logged, and the counts are the honest
/// column of the dilation benchmark.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeclineReason {
    /// The cluster has no live member VM.
    NoMembers,
    /// A member was not running, so this loop does not own its pause
    /// state and must not pause it.
    MemberNotRunning,
    /// A daemon or gym action is in flight against a member.
    ActionInFlight,
    /// At least one vCPU was not in `HLT` (check 1).
    VcpuAwake,
    /// A vCPU had an event captured mid-injection (check 2, #78).
    MidInjection,
    /// A driver-filled virtqueue still had work outstanding (check 3, #79).
    VirtioInFlight,
    /// A frame was queued on a member's TAP (check 4).
    TapFramePending,
    /// A timer is armed whose expiry KVM does not export, so there is
    /// nothing to compute a target from.
    OpaqueTimer,
    /// The APIC bus cycle has not been measured yet, so a `TMCCT`
    /// reading is a count and not a deadline.
    Uncalibrated,
    /// The earliest deadline is inside ε, or under [`MIN_JUMP`] — the
    /// micro-jump regime, not a reason to weaken the predicate.
    TargetTooNear,
    /// A KVM ioctl failed. Loud: the detail is logged.
    KvmError,
    /// The warp itself failed and rolled back.
    WarpFailed,
}

impl DeclineReason {
    /// Every reason, in counter order.
    pub const ALL: [DeclineReason; 12] = [
        DeclineReason::NoMembers,
        DeclineReason::MemberNotRunning,
        DeclineReason::ActionInFlight,
        DeclineReason::VcpuAwake,
        DeclineReason::MidInjection,
        DeclineReason::VirtioInFlight,
        DeclineReason::TapFramePending,
        DeclineReason::OpaqueTimer,
        DeclineReason::Uncalibrated,
        DeclineReason::TargetTooNear,
        DeclineReason::KvmError,
        DeclineReason::WarpFailed,
    ];

    /// Counter key.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            DeclineReason::NoMembers => "no_members",
            DeclineReason::MemberNotRunning => "member_not_running",
            DeclineReason::ActionInFlight => "action_in_flight",
            DeclineReason::VcpuAwake => "vcpu_awake",
            DeclineReason::MidInjection => "mid_injection",
            DeclineReason::VirtioInFlight => "virtio_in_flight",
            DeclineReason::TapFramePending => "tap_frame_pending",
            DeclineReason::OpaqueTimer => "opaque_timer",
            DeclineReason::Uncalibrated => "uncalibrated",
            DeclineReason::TargetTooNear => "target_too_near",
            DeclineReason::KvmError => "kvm_error",
            DeclineReason::WarpFailed => "warp_failed",
        }
    }

    /// Whether this reason was reached before the cluster was paused.
    /// A cycle that never paused has not disturbed anyone's vCPU
    /// threads, so it needs no cgroup re-attach afterwards.
    #[must_use]
    pub fn before_pause(self) -> bool {
        matches!(
            self,
            DeclineReason::NoMembers
                | DeclineReason::MemberNotRunning
                | DeclineReason::ActionInFlight
        )
    }

    fn index(self) -> usize {
        match Self::ALL.iter().position(|r| *r == self) {
            Some(i) => i,
            // Unreachable by construction; a new variant left out of
            // ALL must not silently share another reason's counter.
            None => panic!("DeclineReason::{self:?} is missing from DeclineReason::ALL"),
        }
    }
}

/// A declined cycle: the counted reason plus what was actually seen.
#[derive(Debug, Clone)]
pub struct Decline {
    /// The counter this bumped.
    pub reason: DeclineReason,
    /// Human-readable evidence, for logs and test failure messages.
    pub detail: String,
    /// When this decline knows *when* it stops being true, how long
    /// that is. `Some` only for [`DeclineReason::TargetTooNear`], where
    /// the cluster is idle and a timer is about to fire: waiting the
    /// jittered sampling cadence there would leave 20–50 ms of provably
    /// idle wall time undeleted for the sake of a millisecond timer.
    /// Every other reason is a fact about the cluster this loop cannot
    /// predict the end of, and takes the cadence.
    pub retry_after: Option<Duration>,
}

impl Decline {
    fn new(reason: DeclineReason, detail: impl Into<String>) -> Self {
        Self {
            reason,
            detail: detail.into(),
            retry_after: None,
        }
    }

    /// Same decline, but with a known end.
    fn retry_in(mut self, after: Duration) -> Self {
        self.retry_after = Some(after);
        self
    }
}

/// What one cycle did.
#[derive(Debug, Clone)]
pub enum Cycle {
    /// The cluster's clocks moved forward by this much.
    Warped(Duration),
    /// Nothing moved, for this reason.
    Declined(Decline),
}

impl Cycle {
    /// The delta, when this cycle warped.
    #[must_use]
    pub fn warped(&self) -> Option<Duration> {
        match self {
            Cycle::Warped(d) => Some(*d),
            Cycle::Declined(_) => None,
        }
    }

    /// Whether this cycle paused and resumed the cluster. False only
    /// for the three checks that happen before the pause — the caller
    /// re-attaches CFS-capped vCPU threads to their cgroup when this is
    /// true, because a resume always brings fresh threads.
    #[must_use]
    pub fn paused(&self) -> bool {
        match self {
            Cycle::Warped(_) => true,
            Cycle::Declined(d) => !d.reason.before_pause(),
        }
    }
}

/// How one cycle's pause was spent, in host time.
///
/// Broken out because the pause is the whole cost of the policy: every
/// nanosecond of it is wall time in which no guest time passes, so it is
/// what bounds how often the loop may probe a busy cluster and how much
/// of an idle window it can convert. Which of the four phases dominates
/// decides what to fix, and guessing that from a total was wrong once
/// already (`CHALLENGES.md` #183).
#[derive(Debug, Default, Clone, Copy)]
struct Phases {
    /// `Vm::pause` over every member: signal the vCPU threads out of
    /// `KVM_RUN`, join them, wait for the virtio workers to park.
    pause: Duration,
    /// Of that, summed over the members: freezing the virtio backends,
    /// stopping the vCPUs, and waiting for the workers to park. Broken
    /// out because the total said 6.4 ms and two rounds of guessing
    /// which part that was were both wrong (`CHALLENGES.md` #183).
    freeze: Duration,
    /// See [`Phases::freeze`].
    stop_vcpus: Duration,
    /// How many times the members' vCPU threads were signalled in total.
    /// One per vCPU means every first signal worked.
    stop_signal_rounds: u64,
    /// See [`Phases::freeze`].
    quiesce: Duration,
    /// The safety predicate and the jump target — read-only ioctls.
    decide: Duration,
    /// `Vm::warp_clock` over every member.
    warp: Duration,
    /// `Vm::resume` over every member: fresh vCPU threads, workers
    /// unparked.
    resume: Duration,
}

/// Live counters for one cluster's policy loop. All host time.
#[derive(Debug)]
pub struct AutoWarpCounters {
    cycles: AtomicU64,
    warps: AtomicU64,
    guest_ns_added: AtomicU64,
    wall_ns_paused: AtomicU64,
    pause_ns: AtomicU64,
    freeze_ns: AtomicU64,
    stop_vcpus_ns: AtomicU64,
    stop_signal_rounds: AtomicU64,
    quiesce_ns: AtomicU64,
    decide_ns: AtomicU64,
    warp_ns: AtomicU64,
    resume_ns: AtomicU64,
    resume_failures: AtomicU64,
    /// Measured APIC bus cycle in femtoseconds, 0 until calibrated.
    /// Integral so a counter snapshot stays exactly comparable.
    apic_bus_cycle_fs: AtomicU64,
    declines: [AtomicU64; DeclineReason::ALL.len()],
}

impl Default for AutoWarpCounters {
    fn default() -> Self {
        Self {
            cycles: AtomicU64::new(0),
            warps: AtomicU64::new(0),
            guest_ns_added: AtomicU64::new(0),
            wall_ns_paused: AtomicU64::new(0),
            pause_ns: AtomicU64::new(0),
            freeze_ns: AtomicU64::new(0),
            stop_vcpus_ns: AtomicU64::new(0),
            stop_signal_rounds: AtomicU64::new(0),
            quiesce_ns: AtomicU64::new(0),
            decide_ns: AtomicU64::new(0),
            warp_ns: AtomicU64::new(0),
            resume_ns: AtomicU64::new(0),
            resume_failures: AtomicU64::new(0),
            apic_bus_cycle_fs: AtomicU64::new(0),
            declines: std::array::from_fn(|_| AtomicU64::new(0)),
        }
    }
}

impl AutoWarpCounters {
    fn bump(counter: &AtomicU64, by: u64) {
        counter.fetch_add(by, Ordering::Relaxed);
    }

    fn bump_dur(counter: &AtomicU64, by: Duration) {
        Self::bump(counter, u64::try_from(by.as_nanos()).unwrap_or(u64::MAX));
    }

    fn absorb_phases(&self, phases: Phases) {
        Self::bump_dur(&self.pause_ns, phases.pause);
        Self::bump_dur(&self.freeze_ns, phases.freeze);
        Self::bump_dur(&self.stop_vcpus_ns, phases.stop_vcpus);
        self.stop_signal_rounds
            .fetch_add(phases.stop_signal_rounds, Ordering::Relaxed);
        Self::bump_dur(&self.quiesce_ns, phases.quiesce);
        Self::bump_dur(&self.decide_ns, phases.decide);
        Self::bump_dur(&self.warp_ns, phases.warp);
        Self::bump_dur(&self.resume_ns, phases.resume);
    }

    /// Point-in-time copy, for the status op and the bench.
    #[must_use]
    pub fn snapshot(&self) -> AutoWarpStats {
        let mut declines = BTreeMap::new();
        for reason in DeclineReason::ALL {
            let n = self.declines[reason.index()].load(Ordering::Relaxed);
            if n > 0 {
                declines.insert(reason.as_str().to_string(), n);
            }
        }
        let fs = self.apic_bus_cycle_fs.load(Ordering::Relaxed);
        AutoWarpStats {
            cycles: self.cycles.load(Ordering::Relaxed),
            warps: self.warps.load(Ordering::Relaxed),
            guest_ns_added: self.guest_ns_added.load(Ordering::Relaxed),
            wall_ns_paused: self.wall_ns_paused.load(Ordering::Relaxed),
            pause_ns: self.pause_ns.load(Ordering::Relaxed),
            freeze_ns: self.freeze_ns.load(Ordering::Relaxed),
            stop_vcpus_ns: self.stop_vcpus_ns.load(Ordering::Relaxed),
            stop_signal_rounds: self.stop_signal_rounds.load(Ordering::Relaxed),
            quiesce_ns: self.quiesce_ns.load(Ordering::Relaxed),
            decide_ns: self.decide_ns.load(Ordering::Relaxed),
            warp_ns: self.warp_ns.load(Ordering::Relaxed),
            resume_ns: self.resume_ns.load(Ordering::Relaxed),
            resume_failures: self.resume_failures.load(Ordering::Relaxed),
            apic_bus_cycle_fs: (fs > 0).then_some(fs),
            declines,
        }
    }
}

/// Serialisable snapshot of [`AutoWarpCounters`].
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct AutoWarpStats {
    /// Cycles attempted.
    pub cycles: u64,
    /// Cycles that moved the cluster's clocks.
    pub warps: u64,
    /// Guest time added, summed over every warp.
    pub guest_ns_added: u64,
    /// Host wall time the cluster spent paused, summed over every cycle
    /// — declines included, because a decline costs the same pause.
    pub wall_ns_paused: u64,
    /// Of that, the part spent stopping the members.
    #[serde(default)]
    pub pause_ns: u64,
    /// Of the pause, summed over members: freezing the virtio backends.
    #[serde(default)]
    pub freeze_ns: u64,
    /// Of the pause, summed over members: getting the vCPUs out of
    /// `KVM_RUN`.
    #[serde(default)]
    pub stop_vcpus_ns: u64,
    /// How many signals it took in total. One per vCPU per cycle means
    /// every first signal landed.
    #[serde(default)]
    pub stop_signal_rounds: u64,
    /// Of the pause, summed over members: waiting for the virtio worker
    /// threads to park.
    #[serde(default)]
    pub quiesce_ns: u64,
    /// The part spent on the predicate and the target.
    #[serde(default)]
    pub decide_ns: u64,
    /// The part spent moving the clocks.
    #[serde(default)]
    pub warp_ns: u64,
    /// The part spent starting the members again.
    #[serde(default)]
    pub resume_ns: u64,
    /// Members that failed to resume after a cycle. Non-zero is a bug,
    /// not a tuning signal: the loop logs each one at error level.
    #[serde(default)]
    pub resume_failures: u64,
    /// Measured APIC bus cycle in femtoseconds; absent until the loop
    /// has calibrated (see `Vm::calibrate_apic_bus_cycle_ns`).
    #[serde(default)]
    pub apic_bus_cycle_fs: Option<u64>,
    /// Declines by reason; reasons that never fired are absent.
    #[serde(default)]
    pub declines: BTreeMap<String, u64>,
}

impl AutoWarpStats {
    /// Guest time added per unit of host time spent paused — how much
    /// the pauses bought, in the only two clocks not being manipulated.
    ///
    /// This is *not* the cluster's speedup: guest time also passes
    /// while the cluster runs. Speedup is `(wall + added) / wall` over
    /// the whole run, which only the caller's own wall clock knows.
    /// Nanosecond counters cross an `f64` mantissa only after 52 days
    /// of accumulated pause, which no policy loop reaches.
    #[allow(clippy::cast_precision_loss)]
    #[must_use]
    pub fn guest_per_wall_paused(&self) -> f64 {
        if self.wall_ns_paused == 0 {
            return 0.0;
        }
        self.guest_ns_added as f64 / self.wall_ns_paused as f64
    }
}

/// xorshift64*, so the cadence jitter needs no `rand` dependency.
#[derive(Debug)]
pub struct Rng(u64);

impl Default for Rng {
    fn default() -> Self {
        Self::new()
    }
}

impl Rng {
    /// Seed from the wall clock's sub-second part.
    #[must_use]
    pub fn new() -> Self {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0x2545_F491_4F6C_DD1D, |d| u64::from(d.subsec_nanos()));
        Self(nanos | 1)
    }

    /// Next value.
    pub fn next_u64(&mut self) -> u64 {
        self.0 ^= self.0 >> 12;
        self.0 ^= self.0 << 25;
        self.0 ^= self.0 >> 27;
        self.0.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }
}

/// One cluster's policy loop, minus the thread.
///
/// Split that way on purpose: the daemon runs it on a thread that holds
/// its VM registry for each cycle, and `test_auto_warp.rs` runs the
/// same cycles inline against the three `Vm`s of an Ubuntu cluster it
/// owns directly. Both get the same policy and the same counters.
#[derive(Debug)]
pub struct Driver {
    mode: AutoWarpMode,
    counters: Arc<AutoWarpCounters>,
    /// Measured length of one APIC bus cycle, in femtoseconds. `None`
    /// until a cycle found the cluster idle long enough to measure it.
    bus_cycle_fs: Option<u64>,
    /// EWMA of what one cycle's pause costs in wall time, which is what
    /// the probing cadence is derived from. See [`PROBE_RUN_PER_PAUSE`].
    pause_cost: Duration,
    /// Consecutive cycles that found the cluster doing something. Each
    /// one doubles the probe interval, so a twitch costs one short wait
    /// and a busy stretch settles at [`PROBE_INTERVAL_MAX`].
    busy_streak: u32,
    rng: Rng,
}

impl Driver {
    /// A driver for `mode`, with fresh counters.
    #[must_use]
    pub fn new(mode: AutoWarpMode) -> Self {
        Self {
            mode,
            counters: Arc::new(AutoWarpCounters::default()),
            bus_cycle_fs: None,
            pause_cost: ASSUMED_PAUSE_COST,
            busy_streak: 0,
            rng: Rng::new(),
        }
    }

    /// The counters, shared so a status op can read them while the loop
    /// runs.
    #[must_use]
    pub fn counters(&self) -> Arc<AutoWarpCounters> {
        Arc::clone(&self.counters)
    }

    /// The mode this driver was built for.
    #[must_use]
    pub fn mode(&self) -> AutoWarpMode {
        self.mode
    }

    /// Counters as of now.
    #[must_use]
    pub fn stats(&self) -> AutoWarpStats {
        self.counters.snapshot()
    }

    /// Wait for the next cycle.
    ///
    /// Three cases, and the difference between them is most of `jump`
    /// mode's compression:
    ///
    /// - A cycle that **warped** does not wait at all. The idle window
    ///   it just deleted is exactly where the next deadline now is, so
    ///   sleeping the cadence after every jump would cap the whole
    ///   mode's compression at the cadence.
    /// - A cycle that declined with a **known end** — the cluster is
    ///   idle and a timer fires within [`MIN_JUMP`] — waits only for
    ///   that timer. Handing it the probe interval instead throws away
    ///   tens of milliseconds of *provably idle* wall time to respect a
    ///   millisecond timer, which was the single biggest loss in the
    ///   first run of this policy (`CHALLENGES.md` #183).
    /// - Any other decline waits the probe interval, because it is a
    ///   fact about the cluster whose end this loop cannot predict.
    ///
    /// `micro` mode always waits its quantum — that is what 20 Hz is.
    pub fn pace(&mut self, last: &Cycle) {
        // A cycle that warped, or one that declined only because a timer
        // was about to fire, both found the cluster idle: the streak is
        // about how long it has been *busy*.
        match last {
            Cycle::Warped(_) => self.busy_streak = 0,
            Cycle::Declined(d) => {
                if d.retry_after.is_some() {
                    self.busy_streak = 0;
                } else {
                    self.busy_streak = self.busy_streak.saturating_add(1);
                }
            }
        }
        let wait = match (self.mode, last) {
            (AutoWarpMode::Micro, _) => MICRO_QUANTUM,
            (AutoWarpMode::Jump, Cycle::Warped(_)) | (AutoWarpMode::Off, _) => Duration::ZERO,
            (AutoWarpMode::Jump, Cycle::Declined(d)) => d
                .retry_after
                .map_or_else(|| self.probe_interval(), |after| after + WAKEUP_GRACE),
        };
        if wait > Duration::ZERO {
            std::thread::sleep(wait);
        }
    }

    /// How long to leave a busy cluster alone: the measured pause cost
    /// times [`PROBE_RUN_PER_PAUSE`], doubled once per consecutive busy
    /// cycle, jittered ±25% so the loop does not beat against the guests'
    /// own periodic timers, and held inside
    /// [`PROBE_INTERVAL_MIN`]..=[`PROBE_INTERVAL_MAX`].
    #[must_use]
    pub fn probe_interval(&mut self) -> Duration {
        let budgeted = (self.pause_cost * PROBE_RUN_PER_PAUSE).max(PROBE_INTERVAL_MIN);
        // Saturate the shift rather than the duration: 2^32 of anything
        // overflows, and the clamp below only needs "at least the max".
        let backed_off = budgeted
            .checked_mul(
                1u32.checked_shl(self.busy_streak.saturating_sub(1))
                    .unwrap_or(u32::MAX),
            )
            .unwrap_or(PROBE_INTERVAL_MAX);
        // 75..=125 percent, from the same xorshift the rest uses.
        let jittered =
            backed_off * u32::try_from(75 + self.rng.next_u64() % 51).unwrap_or(100) / 100;
        jittered.clamp(PROBE_INTERVAL_MIN, PROBE_INTERVAL_MAX)
    }

    /// Run one cycle over a cluster's member VMs.
    ///
    /// `in_flight` is the fifth safety check, and the only one that
    /// cannot be read off KVM: `Some(what)` when the caller knows a
    /// daemon or gym action is running against a member. It is checked
    /// before the pause because it is an in-process fact, and what
    /// makes it atomic is the caller's own lock — the daemon holds its
    /// VM registry for the whole cycle, so no daemon op can start
    /// against a member inside one, and anything driving a member from
    /// outside the daemon (a gym `exec` over vsock) declares itself
    /// here.
    ///
    /// Every other check happens with all members paused, and the warp
    /// happens in that same pause: resuming in between reopens every
    /// race the checks just closed. Members are resumed on every path,
    /// including a panic.
    pub fn cycle(&mut self, vms: &mut [&mut Vm], in_flight: Option<&str>) -> Cycle {
        AutoWarpCounters::bump(&self.counters.cycles, 1);

        if let Some(d) = Self::before_pause_checks(vms, in_flight) {
            return self.count(Cycle::Declined(d));
        }

        let started = Instant::now();
        let resume_failures = std::cell::RefCell::new(Vec::<String>::new());
        let mut guard = scopeguard::guard(vms, |vms| {
            for (i, vm) in vms.iter_mut().enumerate() {
                if let Err(e) = vm.resume() {
                    log::error!("auto-warp: member {i} did not resume after a cycle: {e}");
                    resume_failures
                        .borrow_mut()
                        .push(format!("member {i}: {e}"));
                }
            }
        });

        let mut phases = Phases::default();
        let outcome = {
            let t = Instant::now();
            let stopped = Self::pause_all(&mut guard, &mut phases);
            phases.pause = t.elapsed();
            stopped.and_then(|()| {
                let t = Instant::now();
                let decided = match self.mode {
                    // The pause is the atomicity; idleness is not claimed.
                    AutoWarpMode::Micro => Ok(MICRO_QUANTUM),
                    AutoWarpMode::Jump => self.decide_jump(&mut guard),
                    AutoWarpMode::Off => Err(Decline::new(
                        DeclineReason::NoMembers,
                        "auto-warp is off — a cycle should not have been run",
                    )),
                };
                phases.decide = t.elapsed();
                decided
            })
        };

        let cycle = match outcome {
            Ok(delta) => {
                let t = Instant::now();
                let warped = Self::warp_paused(&mut guard, delta);
                phases.warp = t.elapsed();
                warped
            }
            Err(d) => Cycle::Declined(d),
        };
        let t = Instant::now();
        drop(guard);
        phases.resume = t.elapsed();

        let cost = started.elapsed();
        AutoWarpCounters::bump(
            &self.counters.wall_ns_paused,
            u64::try_from(cost.as_nanos()).unwrap_or(u64::MAX),
        );
        self.counters.absorb_phases(phases);
        // Quarter-weight EWMA: fast enough to follow a node that got
        // busy, slow enough that one unlucky pause does not stall the
        // probing for a second.
        self.pause_cost = (self.pause_cost * 3 + cost) / 4;
        let failures = resume_failures.into_inner();
        if !failures.is_empty() {
            AutoWarpCounters::bump(
                &self.counters.resume_failures,
                failures.len().try_into().unwrap_or(u64::MAX),
            );
        }
        self.count(cycle)
    }

    /// Bump the per-outcome counters and hand the cycle back.
    fn count(&self, cycle: Cycle) -> Cycle {
        match &cycle {
            Cycle::Warped(delta) => {
                AutoWarpCounters::bump(&self.counters.warps, 1);
                AutoWarpCounters::bump(
                    &self.counters.guest_ns_added,
                    u64::try_from(delta.as_nanos()).unwrap_or(u64::MAX),
                );
            }
            Cycle::Declined(d) => {
                AutoWarpCounters::bump(&self.counters.declines[d.reason.index()], 1);
            }
        }
        cycle
    }

    /// The three things knowable without touching KVM.
    fn before_pause_checks(vms: &[&mut Vm], in_flight: Option<&str>) -> Option<Decline> {
        // The hold comes first: it is the caller's own statement about
        // state this loop cannot see, and it must hold even for a
        // cluster whose membership is in flux.
        if let Some(what) = in_flight {
            return Some(Decline::new(
                DeclineReason::ActionInFlight,
                what.to_string(),
            ));
        }
        if vms.is_empty() {
            return Some(Decline::new(
                DeclineReason::NoMembers,
                "the cluster has no live VM",
            ));
        }
        // A member somebody else paused is a member this loop does not
        // own: pausing it is idempotent, resuming it is not.
        vms.iter().position(|vm| !vm.is_running()).map(|i| {
            Decline::new(
                DeclineReason::MemberNotRunning,
                format!("member {i} is not running — another op owns its pause"),
            )
        })
    }

    fn pause_all(vms: &mut [&mut Vm], phases: &mut Phases) -> Result<(), Decline> {
        for (i, vm) in vms.iter_mut().enumerate() {
            vm.pause().map_err(|e| {
                let d = Decline::new(DeclineReason::KvmError, format!("pausing member {i}: {e}"));
                log::error!("auto-warp: {}", d.detail);
                d
            })?;
            let cost = vm.last_pause_cost();
            phases.freeze += cost.freeze;
            phases.stop_vcpus += cost.stop_vcpus;
            phases.stop_signal_rounds += u64::from(cost.stop_signal_rounds);
            phases.quiesce += cost.quiesce;
        }
        Ok(())
    }

    /// Move every member's clock by `delta`, in the pause the caller
    /// already holds. This is `warp_clock_lockstep`'s body without its
    /// pause/resume: the checks and the warp have to be one pause, and
    /// the caller's `scopeguard` owns the resume.
    fn warp_paused(vms: &mut [&mut Vm], delta: Duration) -> Cycle {
        for (i, vm) in vms.iter().enumerate() {
            if let Err(e) = vm.warp_clock(delta) {
                let d = Decline::new(
                    DeclineReason::WarpFailed,
                    format!("member {i}, +{}ms: {e}", delta.as_millis()),
                );
                log::error!("auto-warp: the warp itself failed — {}", d.detail);
                return Cycle::Declined(d);
            }
        }
        Cycle::Warped(delta)
    }

    /// The safety predicate and the jump target, over a paused cluster.
    ///
    /// Checks are ordered by cost: `KVM_GET_MP_STATE` is one ioctl per
    /// vCPU and rejects most samples on a busy cluster (the survey measured
    /// 62.3% of vCPUs awake in the busy phase), so it runs before
    /// anything that reads guest memory or the APIC page.
    fn decide_jump(&mut self, vms: &mut [&mut Vm]) -> Result<Duration, Decline> {
        Self::check_idle(vms)?;

        // `TMCCT` is a count, not a duration, until the length of an
        // APIC bus cycle is known. Measure it here, in an idle pause
        // that has already passed the predicate, and keep the answer:
        // that is one 2 ms pause per driver, not one per cycle.
        let Some(bus_cycle_fs) = self.bus_cycle_fs else {
            return Err(self.calibrate(vms[0]));
        };

        let mut survey = TimerSurvey::default();
        for (i, vm) in vms.iter().enumerate() {
            survey.absorb(vm.sample_timers(bus_cycle_fs).map_err(|e| {
                Decline::new(
                    DeclineReason::KvmError,
                    format!("surveying member {i}'s timers: {e}"),
                )
            })?);
        }
        if !survey.unmodelled.is_empty() {
            return Err(Decline::new(
                DeclineReason::OpaqueTimer,
                survey.unmodelled.join("; "),
            ));
        }
        // Nothing armed anywhere: there is no deadline to overshoot, so
        // the quantum is safe — and it is the only honest target, since
        // inventing one from the absence of a timer is what the spec
        // forbids.
        let Some(earliest) = survey.earliest() else {
            return Ok(MICRO_QUANTUM);
        };
        let target = earliest.checked_sub(EPSILON).unwrap_or(Duration::ZERO);
        if target < MIN_JUMP {
            // The cluster is idle and a timer fires within a
            // millisecond, so this decline knows when it stops being
            // true: let that timer fire and come straight back rather
            // than sleeping the sampling cadence over an idle cluster.
            return Err(Decline::new(
                DeclineReason::TargetTooNear,
                format!(
                    "the earliest of {} armed deadlines is {earliest:?}, which leaves \
                     nothing to delete once ε={EPSILON:?} and the {MIN_JUMP:?} warp cost \
                     are taken off",
                    survey.armed.len()
                ),
            )
            .retry_in(earliest));
        }
        Ok(target.min(MAX_JUMP))
    }

    /// Checks 1–4 of the predicate, over a paused cluster.
    fn check_idle(vms: &[&mut Vm]) -> Result<(), Decline> {
        // --- 1. every vCPU halted ---
        let mut awake = Vec::new();
        for (i, vm) in vms.iter().enumerate() {
            let sample = vm.sample_time_state().map_err(|e| {
                Decline::new(
                    DeclineReason::KvmError,
                    format!("sampling member {i}'s time state: {e}"),
                )
            })?;
            for (cpu, c) in sample.cpus.iter().enumerate() {
                if !c.is_halted() {
                    awake.push(format!("member {i} vCPU {cpu} mp_state {}", c.mp_state));
                }
            }
        }
        if !awake.is_empty() {
            return Err(Decline::new(
                DeclineReason::VcpuAwake,
                format!("{} vCPUs awake: {}", awake.len(), awake.join(", ")),
            ));
        }

        // --- 2. no interrupt captured mid-injection (CHALLENGES #78) ---
        let mut staged = Vec::new();
        for (i, vm) in vms.iter().enumerate() {
            let cpus = vm.vcpus_mid_injection().map_err(|e| {
                Decline::new(
                    DeclineReason::KvmError,
                    format!("reading member {i}'s vCPU events: {e}"),
                )
            })?;
            for cpu in cpus {
                staged.push(format!("member {i} vCPU {cpu}"));
            }
        }
        if !staged.is_empty() {
            return Err(Decline::new(
                DeclineReason::MidInjection,
                format!(
                    "an event injection was cancelled mid-flight on {}",
                    staged.join(", ")
                ),
            ));
        }

        // --- 3. every driver-filled virtqueue drained (CHALLENGES #79) ---
        let mut busy = Vec::new();
        for (i, vm) in vms.iter().enumerate() {
            for q in vm.virtio_queues_in_flight() {
                busy.push(format!("member {i} {q}"));
            }
        }
        if !busy.is_empty() {
            return Err(Decline::new(DeclineReason::VirtioInFlight, busy.join("; ")));
        }

        // --- 4. no frame queued on a member's TAP ---
        for (i, vm) in vms.iter().enumerate() {
            let pending = vm.tap_has_pending_frame().map_err(|e| {
                Decline::new(
                    DeclineReason::KvmError,
                    format!("polling member {i}'s TAP: {e}"),
                )
            })?;
            if pending {
                return Err(Decline::new(
                    DeclineReason::TapFramePending,
                    format!("member {i}'s TAP has a frame waiting for the guest"),
                ));
            }
        }
        Ok(())
    }

    /// Measure the APIC bus cycle and spend this cycle on it. Always
    /// returns a decline: the calibration itself holds the cluster
    /// paused for [`CALIBRATION_WINDOW`], and warping on top of that
    /// would make the one cycle that pays for the measurement also the
    /// least representative one.
    fn calibrate(&mut self, vm: &Vm) -> Decline {
        match vm.calibrate_apic_bus_cycle_fs(CALIBRATION_WINDOW) {
            Ok(fs) => {
                self.bus_cycle_fs = Some(fs);
                self.counters.apic_bus_cycle_fs.store(fs, Ordering::Relaxed);
                Decline::new(
                    DeclineReason::Uncalibrated,
                    format!("measured the APIC bus cycle at {fs}fs this cycle"),
                )
            }
            Err(e) => Decline::new(DeclineReason::Uncalibrated, e.to_string()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_decline_reason_has_its_own_counter_slot() {
        let mut seen = std::collections::BTreeSet::new();
        for reason in DeclineReason::ALL {
            assert!(
                seen.insert(reason.index()),
                "{reason:?} shares a counter slot"
            );
        }
        assert_eq!(seen.len(), DeclineReason::ALL.len());
    }

    #[test]
    fn decline_reason_names_are_unique() {
        let names: std::collections::BTreeSet<&str> =
            DeclineReason::ALL.iter().map(|r| r.as_str()).collect();
        assert_eq!(names.len(), DeclineReason::ALL.len());
    }

    #[test]
    fn a_declined_cycle_before_the_pause_needs_no_cgroup_reattach() {
        let paused = Cycle::Declined(Decline::new(DeclineReason::VcpuAwake, "x"));
        let not = Cycle::Declined(Decline::new(DeclineReason::ActionInFlight, "x"));
        assert!(paused.paused());
        assert!(!not.paused());
        assert!(Cycle::Warped(MICRO_QUANTUM).paused());
    }

    #[test]
    fn the_jump_cap_stays_under_a_node_lease() {
        // 40 s lease, 10 s kubelet renewal: a cap at or above the lease
        // is a policy that flaps every node it is enabled on.
        assert!(MAX_JUMP <= Duration::from_secs(30));
        assert!(MIN_JUMP < MICRO_QUANTUM);
        assert!(EPSILON < MIN_JUMP);
    }

    #[test]
    fn guest_per_wall_paused_is_zero_before_any_pause() {
        let stats = AutoWarpStats::default();
        assert!((stats.guest_per_wall_paused() - 0.0).abs() < f64::EPSILON);
    }

    #[test]
    fn the_probe_interval_holds_its_bounds_for_every_streak_and_pause() {
        let mut driver = Driver::new(AutoWarpMode::Jump);
        for pause_us in [1, 650, 7_000, 500_000] {
            driver.pause_cost = Duration::from_micros(pause_us);
            // Every streak, including the ones that would overflow the
            // doubling if it were not saturated.
            for streak in [0, 1, 2, 8, 31, 32, 64, u32::MAX] {
                driver.busy_streak = streak;
                for _ in 0..50 {
                    let wait = driver.probe_interval();
                    assert!(
                        (PROBE_INTERVAL_MIN..=PROBE_INTERVAL_MAX).contains(&wait),
                        "a {pause_us}µs pause on a streak of {streak} probed after \
                         {wait:?}, outside the bounds"
                    );
                }
            }
        }
    }

    #[test]
    fn a_twitch_is_probed_soon_and_a_busy_stretch_is_left_alone() {
        let mut driver = Driver::new(AutoWarpMode::Jump);
        driver.pause_cost = Duration::from_micros(500);

        // One busy cycle: come straight back, because the cluster that
        // was idle a moment ago probably is again.
        driver.busy_streak = 1;
        for _ in 0..50 {
            assert!(
                driver.probe_interval() <= Duration::from_millis(3),
                "a single busy cycle after a 0.5ms pause should be re-probed within 3ms"
            );
        }

        // Six of them: settle at the survey's cadence, which is ~1% duty.
        // pause_cost has to be large enough that even 75% jitter still
        // clamps to the max — 0.5 ms × 3 × 2^5 = 48 ms, which the
        // jitter can leave under 50 ms.
        driver.pause_cost = Duration::from_millis(1);
        driver.busy_streak = 6;
        assert_eq!(driver.probe_interval(), PROBE_INTERVAL_MAX);
    }

    #[test]
    fn pacing_tracks_the_busy_streak_rather_than_the_decline_count() {
        // `off` so `pace` sleeps for none of this: the streak is
        // bookkeeping about the cycles, not about the mode.
        let mut driver = Driver::new(AutoWarpMode::Off);
        let busy = Cycle::Declined(Decline::new(DeclineReason::VcpuAwake, "x"));
        let near = Cycle::Declined(
            Decline::new(DeclineReason::TargetTooNear, "x").retry_in(Duration::ZERO),
        );

        driver.pace(&busy);
        driver.pace(&busy);
        assert_eq!(driver.busy_streak, 2);
        // An idle cluster whose timer was merely too close is not busy.
        driver.pace(&near);
        assert_eq!(driver.busy_streak, 0);
        driver.pace(&busy);
        driver.pace(&Cycle::Warped(MICRO_QUANTUM));
        assert_eq!(driver.busy_streak, 0);
    }

    #[test]
    fn a_decline_that_knows_its_end_waits_only_that_long() {
        let mut driver = Driver::new(AutoWarpMode::Jump);
        driver.pause_cost = PROBE_INTERVAL_MAX;
        let near = Cycle::Declined(
            Decline::new(DeclineReason::TargetTooNear, "a timer fires in 400µs")
                .retry_in(Duration::from_micros(400)),
        );
        let started = Instant::now();
        driver.pace(&near);
        assert!(
            started.elapsed() < PROBE_INTERVAL_MAX,
            "an idle cluster with a timer 400µs out waited {:?} — the probe interval was \
             applied to a decline whose end was known",
            started.elapsed()
        );
    }
}
