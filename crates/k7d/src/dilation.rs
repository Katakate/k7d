//! Adaptive dilation factor : when to stop asking
//! a cluster to run 8× faster than the host can feed it, and — if the
//! caller wants it — when to ask again after the load goes away.
//!
//! the referenced work swept the factor and found the fidelity cost is a
//! curve, not a cliff: compression is exactly N through 16, while extra
//! liveness-probe failures go 0 / 0 / 0 / 3 / 19 / 32 and in-guest churn
//! rounds collapse 110 → 7 across N ∈ {1, 2, 4, 8, 12, 16}. The reading
//! that moved *with* the damage, and the only one available from the
//! host without asking the guest anything, is busy-phase **mean awake
//! vCPUs**: 2.71 → 3.41 → 4.67 → 5.20 → 5.00 → 6.00 of 6. At 6 of 6
//! there is no idle left to sell, and inc0's `n_cpus / mean_awake`
//! ceiling has fallen to 1.0×.
//!
//! So the signal is [`crate::vm::Vm::sample_time_state`] — the same
//! per-vCPU `KVM_GET_MP_STATE` reading inc0's survey used — and not
//! probe failures. Probe failures are a *consequence*: by the time the
//! kubelet has recorded them the episode has already lost fidelity, and
//! they arrive through the guest's API server, which is exactly the
//! thing dilation is starving. Awake vCPUs are measured on the host,
//! during a pause the policy is taking anyway.
//!
//! Two types, because "never raise" and "track both ways" are different
//! claims, not a flag on one claim:
//!
//! - [`DilationPolicy`] (inc8) starts at 8 and drops 8 → 4 → 2 → 1 when
//!   the cluster is saturated. **Never raises.** A factor that goes up
//!   and down turns the guest's clock rate into a function of host load,
//!   and every guest-time measurement in the episode — a probe period, a
//!   backoff ladder, a reward — becomes uncomparable with the same
//!   measurement from another episode. Dropping is already a fidelity
//!   event; the honest version of it is monotone, once per rung, and
//!   reported. There is no method that increases the factor.
//! - [`TrackingPolicy`] (inc9) uses the same ladder and the same drop
//!   threshold, and *also* raises when the cluster is quiet again. The
//!   deadband between the two thresholds is load-bearing: one threshold
//!   chatters. Whether that trade is worth it is a measurement, not a
//!   default — see the referenced work's four-policy table.
//!
//! Applying a decision is [`crate::control::Request::SetDilation`].
//! This module only decides, and it is deliberately not wired into the
//! gym: the referenced work's `dilate` mode stays create-time N=8.

use crate::vm::TimeSample;

/// The rungs, highest first. inc6's operating point is the first and its
/// knee (N=12) is deliberately not here: this ladder is what the sweep
/// licenses as *comfortable*, and a policy that can only descend should
/// not start above the point three runs per N called comfortable.
pub const LADDER: [u32; 4] = [8, 4, 2, 1];

/// Saturated: this fraction of the cluster's vCPUs awake, or more.
///
/// 0.8 of 6 is 4.8 awake, which sits between inc6's N=4 reading (4.67)
/// and its N=8 one (5.20) — i.e. between the last factor that was
/// essentially free and the first that showed a cost. It is a threshold
/// on a measured curve, not a tuned constant, and it is here rather than
/// at 1.0 because 6-of-6 awake is where there is no headroom left at
/// all, which is too late to react.
pub const SATURATED: f64 = 0.8;

/// Quiet enough to climb one rung: this fraction of the cluster's vCPUs
/// awake, or less. [`TrackingPolicy`] only.
///
/// 0.45 of 6 is 2.7 awake, which is inc6's N=1 busy-phase mean (2.71).
/// An idle cluster (no burner) sits well below it. Together with
/// [`SATURATED`] this is a deadband, not two names for one line: a
/// single threshold chatters as the cluster hovers around it.
pub const QUIET: f64 = 0.45;

/// Observations a decision rests on. One observation is one cluster-wide
/// pause, so a single staggered wakeup can put every vCPU in `RUNNING`
/// for one sample; three is the floor against spending a rung on that.
/// It is not a measured constant — inc6 recorded 2–24 samples per run
/// depending on N — which is why it is a constructor argument.
pub const WINDOW: usize = 3;

/// Why the policy last did nothing, for the caller's accounting.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict {
    /// Fewer than `window` observations since the last decision.
    Warming,
    /// The cluster has headroom at this factor.
    Headroom,
    /// Saturated, but already on the bottom rung.
    Floor,
    /// Saturated: drop to this factor.
    Drop(u32),
    /// Quiet: raise to this factor. [`DilationPolicy`] never returns this.
    Raise(u32),
    /// Quiet, but already on the top rung. [`DilationPolicy`] never
    /// returns this — an idle cluster is [`Verdict::Headroom`] there.
    Ceiling,
    /// Between [`QUIET`] and [`SATURATED`]: hold this rung.
    /// [`DilationPolicy`] never returns this.
    Hold,
}

/// The adaptive-factor policy for one episode .
///
/// One instance per episode. It is monotone by construction — there is
/// no method that raises the factor — so "never raise mid-episode" is a
/// property of the type rather than a rule a caller has to remember.
#[derive(Debug, Clone)]
pub struct DilationPolicy {
    rung: usize,
    window: usize,
    saturated: f64,
    /// Sum of awake vCPUs over the observations since the last decision.
    /// Counted exactly and divided only at the end, so the threshold is
    /// compared against the samples rather than against a running mean.
    awake: u64,
    /// Sum of total vCPUs over the same observations. Summed rather than
    /// assumed constant so a cluster that loses a member mid-episode
    /// still divides by what it actually sampled.
    cpus: u64,
    samples: usize,
    drops: u32,
}

impl Default for DilationPolicy {
    fn default() -> Self {
        Self::new(WINDOW, SATURATED)
    }
}

impl DilationPolicy {
    /// A policy starting on [`LADDER`]'s top rung, deciding on `window`
    /// observations against a `saturated` fraction of awake vCPUs.
    #[must_use]
    pub fn new(window: usize, saturated: f64) -> Self {
        Self {
            rung: 0,
            window: window.max(1),
            saturated,
            awake: 0,
            cpus: 0,
            samples: 0,
            drops: 0,
        }
    }

    /// The factor the cluster should be running at now.
    #[must_use]
    pub fn factor(&self) -> u32 {
        LADDER[self.rung]
    }

    /// How many rungs this episode has spent.
    #[must_use]
    pub fn drops(&self) -> u32 {
        self.drops
    }

    /// Mean awake vCPUs per observation in the current window, and the
    /// mean cluster width they were measured against. `None` before the
    /// first observation of the window.
    // vCPU counts over one window: a cluster would need 2^53 of them
    // before an f64 could not hold the sum exactly.
    #[allow(clippy::cast_precision_loss)]
    #[must_use]
    pub fn mean_awake(&self) -> Option<(f64, f64)> {
        if self.samples == 0 {
            return None;
        }
        let n = self.samples as f64;
        Some((self.awake as f64 / n, self.cpus as f64 / n))
    }

    /// Feed one cluster-wide observation: how many vCPUs were awake (not
    /// `HLT`) out of how many, read from a paused cluster.
    ///
    /// Returns the factor to switch to when the window says the cluster
    /// is saturated, and resets the window on a drop so the next rung is
    /// judged on its own evidence rather than the rung above's.
    // Same bound as `mean_awake`: these are vCPU counts, not nanoseconds.
    #[allow(clippy::cast_precision_loss)]
    pub fn observe(&mut self, awake: usize, n_cpus: usize) -> Verdict {
        assert!(
            n_cpus > 0,
            "a cluster with no vCPUs cannot be saturated — an empty sample is a caller bug"
        );
        self.awake += awake as u64;
        self.cpus += n_cpus as u64;
        self.samples += 1;
        if self.samples < self.window {
            return Verdict::Warming;
        }

        let saturated = self.awake as f64 / self.cpus as f64 >= self.saturated;
        // The window closes on every decision, saturated or not: a mean
        // that keeps the whole episode's history would make late samples
        // unable to move it.
        self.awake = 0;
        self.cpus = 0;
        self.samples = 0;

        if !saturated {
            return Verdict::Headroom;
        }
        if self.rung + 1 >= LADDER.len() {
            return Verdict::Floor;
        }
        self.rung += 1;
        self.drops += 1;
        Verdict::Drop(self.factor())
    }

    /// [`Self::observe`] from the samples of a paused cluster.
    pub fn observe_samples(&mut self, samples: &[TimeSample]) -> Verdict {
        let (awake, n_cpus) = awake_cpus(samples);
        self.observe(awake, n_cpus)
    }
}

/// The bidirectional policy : drop on saturation, raise
/// on quiet, hold the deadband.
///
/// One instance per episode. One rung per closed window, same ladder as
/// [`DilationPolicy`]. The raise is a property of this type, not a
/// method grafted onto the monotone one — a caller that wanted "never
/// raise" and got a raise because they constructed the wrong type would
/// be a silent fallback.
#[derive(Debug, Clone)]
pub struct TrackingPolicy {
    rung: usize,
    window: usize,
    saturated: f64,
    quiet: f64,
    awake: u64,
    cpus: u64,
    samples: usize,
    drops: u32,
    raises: u32,
}

impl Default for TrackingPolicy {
    fn default() -> Self {
        Self::new(WINDOW, SATURATED, QUIET)
    }
}

impl TrackingPolicy {
    /// A policy starting on [`LADDER`]'s top rung, deciding on `window`
    /// observations against a `saturated` fraction (drop) and a `quiet`
    /// fraction (raise).
    #[must_use]
    pub fn new(window: usize, saturated: f64, quiet: f64) -> Self {
        assert!(
            quiet < saturated,
            "quiet ({quiet}) must be below saturated ({saturated}) — a missing deadband chatters"
        );
        Self {
            rung: 0,
            window: window.max(1),
            saturated,
            quiet,
            awake: 0,
            cpus: 0,
            samples: 0,
            drops: 0,
            raises: 0,
        }
    }

    /// The factor the cluster should be running at now.
    #[must_use]
    pub fn factor(&self) -> u32 {
        LADDER[self.rung]
    }

    /// How many rungs this episode has spent going down.
    #[must_use]
    pub fn drops(&self) -> u32 {
        self.drops
    }

    /// How many rungs this episode has spent going up.
    #[must_use]
    pub fn raises(&self) -> u32 {
        self.raises
    }

    /// Mean awake vCPUs per observation in the current window, and the
    /// mean cluster width they were measured against. `None` before the
    /// first observation of the window.
    // vCPU counts over one window: a cluster would need 2^53 of them
    // before an f64 could not hold the sum exactly.
    #[allow(clippy::cast_precision_loss)]
    #[must_use]
    pub fn mean_awake(&self) -> Option<(f64, f64)> {
        if self.samples == 0 {
            return None;
        }
        let n = self.samples as f64;
        Some((self.awake as f64 / n, self.cpus as f64 / n))
    }

    /// Feed one cluster-wide observation. Drops, raises, or holds when
    /// the window closes; never more than one rung.
    // Same bound as `mean_awake`: these are vCPU counts, not nanoseconds.
    #[allow(clippy::cast_precision_loss)]
    pub fn observe(&mut self, awake: usize, n_cpus: usize) -> Verdict {
        assert!(
            n_cpus > 0,
            "a cluster with no vCPUs cannot be saturated — an empty sample is a caller bug"
        );
        self.awake += awake as u64;
        self.cpus += n_cpus as u64;
        self.samples += 1;
        if self.samples < self.window {
            return Verdict::Warming;
        }

        let load = self.awake as f64 / self.cpus as f64;
        self.awake = 0;
        self.cpus = 0;
        self.samples = 0;

        if load >= self.saturated {
            if self.rung + 1 >= LADDER.len() {
                return Verdict::Floor;
            }
            self.rung += 1;
            self.drops += 1;
            return Verdict::Drop(self.factor());
        }
        if load <= self.quiet {
            if self.rung == 0 {
                return Verdict::Ceiling;
            }
            self.rung -= 1;
            self.raises += 1;
            return Verdict::Raise(self.factor());
        }
        Verdict::Hold
    }

    /// [`Self::observe`] from the samples of a paused cluster.
    pub fn observe_samples(&mut self, samples: &[TimeSample]) -> Verdict {
        let (awake, n_cpus) = awake_cpus(samples);
        self.observe(awake, n_cpus)
    }
}

fn awake_cpus(samples: &[TimeSample]) -> (usize, usize) {
    let awake = samples
        .iter()
        .flat_map(|s| s.cpus.iter())
        .filter(|c| !c.is_halted())
        .count();
    let n_cpus: usize = samples.iter().map(|s| s.cpus.len()).sum();
    (awake, n_cpus)
}

#[cfg(test)]
mod tests {
    use super::{DilationPolicy, TrackingPolicy, Verdict, LADDER, QUIET, SATURATED, WINDOW};

    /// The ladder is what inc6's sweep licensed, in descending order.
    #[test]
    fn ladder_descends_from_the_operating_point() {
        assert_eq!(LADDER, [8, 4, 2, 1]);
        assert!(LADDER.windows(2).all(|w| w[0] > w[1]));
    }

    #[test]
    fn a_quiet_cluster_keeps_the_operating_point() {
        let mut p = DilationPolicy::default();
        for _ in 0..30 {
            let v = p.observe(1, 6);
            assert!(matches!(v, Verdict::Warming | Verdict::Headroom), "{v:?}");
        }
        assert_eq!(p.factor(), 8);
        assert_eq!(p.drops(), 0);
    }

    /// A single saturated sample must not spend a rung — one pause can
    /// catch every vCPU in a staggered wakeup.
    #[test]
    fn one_saturated_sample_is_not_a_drop() {
        let mut p = DilationPolicy::default();
        assert_eq!(p.observe(6, 6), Verdict::Warming);
        assert_eq!(p.factor(), 8);
    }

    #[test]
    fn a_saturated_cluster_walks_down_the_ladder_and_stops() {
        let mut p = DilationPolicy::default();
        let mut seen = Vec::new();
        for _ in 0..40 {
            if let Verdict::Drop(f) = p.observe(6, 6) {
                seen.push(f);
            }
        }
        assert_eq!(
            seen,
            vec![4, 2, 1],
            "the ladder is 8 → 4 → 2 → 1, once each"
        );
        assert_eq!(p.factor(), 1);
        assert_eq!(p.drops(), 3);
        // And it stays there: the floor is a verdict, not another drop.
        // Driven until the next window closes rather than a fixed number
        // of times — where the 40 above left the window is not the point.
        let closed = std::iter::from_fn(|| Some(p.observe(6, 6)))
            .take(WINDOW)
            .find(|v| *v != Verdict::Warming);
        assert_eq!(closed, Some(Verdict::Floor));
        assert_eq!(p.factor(), 1);
    }

    /// The whole point: there is no path back up. A cluster that goes
    /// idle after a drop keeps the lower factor for the rest of the
    /// episode, so guest-time measurements stay comparable.
    #[test]
    fn the_factor_never_rises() {
        let mut p = DilationPolicy::default();
        while p.factor() > 4 {
            p.observe(6, 6);
        }
        assert_eq!(p.factor(), 4);
        for _ in 0..50 {
            assert_ne!(p.observe(0, 6), Verdict::Drop(8));
        }
        assert_eq!(p.factor(), 4);
    }

    /// 0.8 of 6 is 4.8 awake: inc6's N=4 reading (4.67) has headroom,
    /// its N=8 one (5.20) does not.
    #[test]
    fn the_threshold_sits_between_inc6_n4_and_n8() {
        let mut free = DilationPolicy::default();
        // 4.67 of 6 ≈ 14 awake over 3 samples of 6.
        assert_eq!(free.observe(5, 6), Verdict::Warming);
        assert_eq!(free.observe(5, 6), Verdict::Warming);
        assert_eq!(free.observe(4, 6), Verdict::Headroom);

        let mut tight = DilationPolicy::default();
        // 5.20 of 6 ≈ 16 awake over the same three.
        assert_eq!(tight.observe(5, 6), Verdict::Warming);
        assert_eq!(tight.observe(5, 6), Verdict::Warming);
        assert_eq!(tight.observe(6, 6), Verdict::Drop(4));
        assert!((SATURATED - 0.8).abs() < f64::EPSILON);
    }

    /// A member that disappears mid-episode changes the denominator, and
    /// the mean divides by what was sampled rather than what was assumed.
    #[test]
    fn a_shrinking_cluster_divides_by_what_it_sampled() {
        let mut p = DilationPolicy::new(2, 0.8);
        p.observe(5, 6);
        let (awake, cpus) = p.mean_awake().expect("one sample");
        assert!((awake - 5.0).abs() < f64::EPSILON);
        assert!((cpus - 6.0).abs() < f64::EPSILON);
        // 5/6 then 4/4: 9 awake of 10 is saturated.
        assert_eq!(p.observe(4, 4), Verdict::Drop(4));
        assert_eq!(p.mean_awake(), None, "a decision closes the window");
    }

    /// Tracking is a second type, not a flag: the monotone policy still
    /// has no path back up after the same idle that would raise here.
    #[test]
    fn tracking_walks_back_up_after_the_load_goes_away() {
        let mut p = TrackingPolicy::default();
        let mut down = Vec::new();
        for _ in 0..40 {
            if let Verdict::Drop(f) = p.observe(6, 6) {
                down.push(f);
            }
        }
        assert_eq!(down, vec![4, 2, 1]);
        assert_eq!(p.factor(), 1);

        let mut up = Vec::new();
        for _ in 0..40 {
            if let Verdict::Raise(f) = p.observe(0, 6) {
                up.push(f);
            }
        }
        assert_eq!(up, vec![2, 4, 8], "the ladder is 1 → 2 → 4 → 8, once each");
        assert_eq!(p.factor(), 8);
        assert_eq!(p.raises(), 3);
        let closed = std::iter::from_fn(|| Some(p.observe(0, 6)))
            .take(WINDOW)
            .find(|v| *v != Verdict::Warming);
        assert_eq!(closed, Some(Verdict::Ceiling));
        assert_eq!(p.factor(), 8);
    }

    /// A single quiet sample must not raise — the same staggered-wakeup
    /// reason a single saturated sample must not drop.
    #[test]
    fn one_quiet_sample_is_not_a_raise() {
        let mut p = TrackingPolicy::default();
        while p.factor() > 4 {
            p.observe(6, 6);
        }
        assert_eq!(p.factor(), 4);
        assert_eq!(p.observe(0, 6), Verdict::Warming);
        assert_eq!(p.factor(), 4);
    }

    /// 0.45 of 6 is 2.7 awake: 8/18 is a raise, 9/18 is a hold, 15/18
    /// is a drop. The deadband is the point of the type.
    #[test]
    fn the_deadband_holds() {
        let mut raise = TrackingPolicy::default();
        while raise.factor() > 4 {
            raise.observe(6, 6);
        }
        assert_eq!(raise.observe(2, 6), Verdict::Warming);
        assert_eq!(raise.observe(3, 6), Verdict::Warming);
        assert_eq!(raise.observe(3, 6), Verdict::Raise(8));

        let mut hold = TrackingPolicy::default();
        while hold.factor() > 4 {
            hold.observe(6, 6);
        }
        assert_eq!(hold.observe(3, 6), Verdict::Warming);
        assert_eq!(hold.observe(3, 6), Verdict::Warming);
        assert_eq!(hold.observe(3, 6), Verdict::Hold);
        assert_eq!(hold.factor(), 4);

        let mut drop = TrackingPolicy::default();
        assert_eq!(drop.observe(5, 6), Verdict::Warming);
        assert_eq!(drop.observe(5, 6), Verdict::Warming);
        assert_eq!(drop.observe(5, 6), Verdict::Drop(4));
        assert!((QUIET - 0.45).abs() < f64::EPSILON);
    }

    #[test]
    fn a_quiet_cluster_at_the_operating_point_is_the_ceiling() {
        let mut p = TrackingPolicy::default();
        let mut seen = Vec::new();
        for _ in 0..9 {
            seen.push(p.observe(0, 6));
        }
        assert!(seen.iter().any(|v| *v == Verdict::Warming));
        assert!(seen.iter().any(|v| *v == Verdict::Ceiling));
        assert!(!seen
            .iter()
            .any(|v| matches!(v, Verdict::Drop(_) | Verdict::Raise(_))));
        assert_eq!(p.factor(), 8);
        assert_eq!(p.drops(), 0);
        assert_eq!(p.raises(), 0);
    }
}
