//! Adaptive dilation factor: when to stop asking
//! a cluster to run 8× faster than the host can feed it, and — if the
//! caller wants it — when to ask again after the load goes away.
//!
//! A sweep of the factor found the fidelity cost is a
//! curve, not a cliff: compression is exactly N through 16, while extra
//! liveness-probe failures go 0 / 0 / 0 / 3 / 19 / 32 and in-guest churn
//! rounds collapse 110 → 7 across N ∈ {1, 2, 4, 8, 12, 16}. The reading
//! that moved *with* the damage, and the only one available from the
//! host without asking the guest anything, is busy-phase **mean awake
//! vCPUs**: 2.71 → 3.41 → 4.67 → 5.20 → 5.00 → 6.00 of 6. At 6 of 6
//! there is no idle left to sell, and the survey's `n_cpus / mean_awake`
//! ceiling has fallen to 1.0×.
//!
//! So the signal is [`crate::vm::Vm::sample_time_state`] — the same
//! per-vCPU `KVM_GET_MP_STATE` reading that survey used — and not
//! probe failures. Probe failures are a *consequence*: by the time the
//! kubelet has recorded them the episode has already lost fidelity, and
//! they arrive through the guest's API server, which is exactly the
//! thing dilation is starving. Awake vCPUs are measured on the host,
//! during a pause the policy is taking anyway.
//!
//! Two types, because "never raise" and "track both ways" are different
//! claims, not a flag on one claim:
//!
//! - [`DilationPolicy`] starts at 8 and drops 8 → 4 → 2 → 1 when
//!   the cluster is saturated. **Never raises.** A factor that goes up
//!   and down turns the guest's clock rate into a function of host load,
//!   and every guest-time measurement in the episode — a probe period, a
//!   backoff ladder, a reward — becomes uncomparable with the same
//!   measurement from another episode. Dropping is already a fidelity
//!   event; the honest version of it is monotone, once per rung, and
//!   reported. There is no method that increases the factor.
//! - [`TrackingPolicy`] uses the same ladder and the same drop
//!   threshold, and *also* raises when the cluster is quiet again. The
//!   deadband between the two thresholds is load-bearing: one threshold
//!   chatters. Whether that trade is worth it is a measurement, not a
//!   default — see the four-policy table.
//!
//! Applying a decision is [`crate::control::Request::SetDilation`].
//! The daemon runs that path from a per-tree loop when the tree's
//! [`DilationPolicyMode`] is [`DilationPolicyMode::Down`] or
//! [`DilationPolicyMode::Track`]. [`DilationPolicyMode::Fixed`] (the
//! default) does not start a loop. The gym's `dilate` mode is still
//! create-time N=8; it does not opt a tree into the loop.
//!
//! [`PolicyConfig`] is the knob bag the loop passes to the constructors.
//! An omitted [`DilationPolicyConfig`] on the tree request is these
//! module constants. A request that sets one replaces window, saturated,
//! quiet, cadence, and the ladder for that tree; a fork that omits it
//! copies its parent's.

use std::time::Duration;

use serde::{Deserialize, Serialize};

use crate::vm::TimeSample;

/// Which way a tree's dilation loop may move the factor.
///
/// Set on `tree_create` / `tree_create_cluster` / `tree_adopt_cluster`.
/// A fork copies the source node's mode unless the fork request sets
/// one. [`Self::Fixed`] is the default and starts no loop, so a tree
/// that omits the field keeps today's create-time factor.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DilationPolicyMode {
    /// Do not sample and do not call `SetDilation`.
    #[default]
    Fixed,
    /// [`DilationPolicy`]: drop when saturated, never raise.
    Down,
    /// [`TrackingPolicy`]: drop when saturated, raise when quiet.
    Track,
}

impl DilationPolicyMode {
    /// Wire / log name.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Fixed => "fixed",
            Self::Down => "down",
            Self::Track => "track",
        }
    }
}

/// Caller knobs for one tree's dilation loop.
///
/// Omitted fields are the module constants ([`WINDOW`], [`SATURATED`],
/// [`QUIET`], one second, [`LADDER`]). `None` for the whole struct — the
/// request field was absent — is [`PolicyConfig::default`]. `fixed`
/// still validates this and still starts no thread.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default)]
pub struct DilationPolicyConfig {
    /// Observations a decision rests on. `None` is [`WINDOW`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub window: Option<usize>,
    /// Drop at this fraction of vCPUs awake. `None` is [`SATURATED`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub saturated: Option<f64>,
    /// Raise at this fraction or below. `None` is [`QUIET`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub quiet: Option<f64>,
    /// Milliseconds between samples. `None` is 1000. A fork that sets
    /// this is refused: the tree has one loop and one sleep.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cadence_ms: Option<u64>,
    /// Rungs, highest first. `None` is [`LADDER`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ladder: Option<Vec<u32>>,
}

impl DilationPolicyConfig {
    /// Resolve omitted fields onto the module constants.
    pub fn resolve(&self) -> Result<PolicyConfig, String> {
        PolicyConfig {
            window: self.window.unwrap_or(WINDOW),
            saturated: self.saturated.unwrap_or(SATURATED),
            quiet: self.quiet.unwrap_or(QUIET),
            cadence: Duration::from_millis(self.cadence_ms.unwrap_or(1_000)),
            ladder: self.ladder.clone().unwrap_or_else(|| LADDER.to_vec()),
        }
        .validated()
    }
}

/// Knobs the daemon loop passes into the existing policy types.
///
/// Built from [`DilationPolicyConfig::resolve`] or [`Self::default`].
/// The ladder is per tree: [`Self::down_policy`], [`Self::track_policy`],
/// and [`ladder_rung`] read this one, not the module constant, unless
/// the caller left it at the default.
#[derive(Debug, Clone, PartialEq)]
pub struct PolicyConfig {
    /// Observations a decision rests on. See [`WINDOW`].
    pub window: usize,
    /// Drop at this fraction of vCPUs awake. See [`SATURATED`].
    pub saturated: f64,
    /// Raise at this fraction or below. See [`QUIET`]. Ignored by
    /// [`DilationPolicy`].
    pub quiet: f64,
    /// Wall time between samples. The four-policy episode used 1s.
    /// One value per tree: a fork cannot replace it.
    pub cadence: Duration,
    /// Rungs, highest first. See [`LADDER`].
    pub ladder: Vec<u32>,
}

impl Default for PolicyConfig {
    fn default() -> Self {
        Self {
            window: WINDOW,
            saturated: SATURATED,
            quiet: QUIET,
            cadence: Duration::from_secs(1),
            ladder: LADDER.to_vec(),
        }
    }
}

impl PolicyConfig {
    /// The request field. `None` is [`Self::default`].
    pub fn from_request(config: Option<&DilationPolicyConfig>) -> Result<Self, String> {
        match config {
            None => Ok(Self::default()),
            Some(cfg) => cfg.resolve(),
        }
    }

    /// Knobs a fork should arm with.
    ///
    /// `None` copies `self`. `Some` replaces the child, except a set
    /// `cadence_ms` is an error and an omitted one keeps this tree's
    /// cadence — one loop, one sleep.
    pub fn for_fork(&self, requested: Option<&DilationPolicyConfig>) -> Result<Self, String> {
        let Some(cfg) = requested else {
            return Ok(self.clone());
        };
        if cfg.cadence_ms.is_some() {
            return Err(
                "a fork cannot set dilation cadence_ms — the tree has one loop and one sleep"
                    .into(),
            );
        }
        let mut resolved = cfg.resolve()?;
        resolved.cadence = self.cadence;
        Ok(resolved)
    }

    /// Refuse a config the constructors would either panic on or silently
    /// rewrite. `window == 0` is rejected here; [`DilationPolicy::new`]
    /// would otherwise clamp it to 1.
    fn validated(self) -> Result<Self, String> {
        if self.window == 0 {
            return Err(
                "dilation policy window must be >= 1 — a zero window spends a rung on every sample"
                    .into(),
            );
        }
        if self.cadence.is_zero() {
            return Err(
                "dilation policy cadence must be > 0 — a zero cadence spins the pause loop".into(),
            );
        }
        if !self.quiet.is_finite() || !self.saturated.is_finite() || self.quiet >= self.saturated {
            return Err(format!(
                "dilation policy quiet ({}) must be below saturated ({}) — a missing deadband chatters",
                self.quiet, self.saturated
            ));
        }
        validate_ladder(&self.ladder)?;
        Ok(self)
    }

    /// A down-only policy on this ladder's top rung.
    pub fn down_policy(&self) -> Result<DilationPolicy, String> {
        let cfg = self.clone().validated()?;
        Ok(DilationPolicy::with_ladder(
            cfg.window,
            cfg.saturated,
            cfg.ladder,
        ))
    }

    /// A tracking policy on this ladder's top rung.
    pub fn track_policy(&self) -> Result<TrackingPolicy, String> {
        let cfg = self.clone().validated()?;
        Ok(TrackingPolicy::with_ladder(
            cfg.window,
            cfg.saturated,
            cfg.quiet,
            cfg.ladder,
        ))
    }
}

/// Refuse an empty ladder, a rung outside `1..=MAX_DILATION`, a
/// duplicate, or any step that does not descend.
fn validate_ladder(ladder: &[u32]) -> Result<(), String> {
    if ladder.is_empty() {
        return Err(
            "dilation policy ladder must not be empty — the loop has to start on a rung".into(),
        );
    }
    let mut prev: Option<u32> = None;
    for &rung in ladder {
        if rung == 0 || rung > crate::vm::MAX_DILATION {
            return Err(format!(
                "dilation policy ladder rung {rung} is outside 1..={} — \
                 the carried patch refuses a factor past that",
                crate::vm::MAX_DILATION
            ));
        }
        if let Some(earlier) = prev {
            if rung >= earlier {
                return Err(format!(
                    "dilation policy ladder {ladder:?} must be strictly decreasing — \
                     a duplicate or rising rung is refused"
                ));
            }
        }
        prev = Some(rung);
    }
    Ok(())
}

/// Index of `factor` on `ladder`, if it is one of the rungs.
#[must_use]
pub fn ladder_rung(ladder: &[u32], factor: u32) -> Option<usize> {
    ladder.iter().position(|&rung| rung == factor)
}

/// `factor` is not a rung the adaptive loop can represent.
#[must_use]
pub fn ladder_factor_error(ladder: &[u32], factor: u32) -> String {
    format!(
        "dilation factor {factor} is not on the ladder {ladder:?} — \
         the adaptive loop only moves between those rungs"
    )
}

/// The rungs, highest first. The sweep's operating point is the first and its
/// knee (N=12) is deliberately not here: this ladder is what the sweep
/// licenses as *comfortable*, and a policy that can only descend should
/// not start above the point three runs per N called comfortable.
pub const LADDER: [u32; 4] = [8, 4, 2, 1];

/// Saturated: this fraction of the cluster's vCPUs awake, or more.
///
/// 0.8 of 6 is 4.8 awake, which sits between the sweep's N=4 reading (4.67)
/// and its N=8 one (5.20) — i.e. between the last factor that was
/// essentially free and the first that showed a cost. It is a threshold
/// on a measured curve, not a tuned constant, and it is here rather than
/// at 1.0 because 6-of-6 awake is where there is no headroom left at
/// all, which is too late to react.
pub const SATURATED: f64 = 0.8;

/// Quiet enough to climb one rung: this fraction of the cluster's vCPUs
/// awake, or less. [`TrackingPolicy`] only.
///
/// 0.45 of 6 is 2.7 awake, which is the sweep's N=1 busy-phase mean (2.71).
/// An idle cluster (no burner) sits well below it. Together with
/// [`SATURATED`] this is a deadband, not two names for one line: a
/// single threshold chatters as the cluster hovers around it.
pub const QUIET: f64 = 0.45;

/// Observations a decision rests on. One observation is one cluster-wide
/// pause, so a single staggered wakeup can put every vCPU in `RUNNING`
/// for one sample; three is the floor against spending a rung on that.
/// It is not a measured constant — the sweep recorded 2–24 samples per run
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

/// The adaptive-factor policy for one episode.
///
/// One instance per episode. It is monotone by construction — there is
/// no method that raises the factor — so "never raise mid-episode" is a
/// property of the type rather than a rule a caller has to remember.
#[derive(Debug, Clone)]
pub struct DilationPolicy {
    /// Rungs, highest first. The rung index walks this, not the module
    /// [`LADDER`], so a tree can run `[4, 1]`.
    ladder: Vec<u32>,
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
        Self::with_ladder(window, saturated, LADDER.to_vec())
    }

    /// [`Self::new`] on `ladder` instead of [`LADDER`]. Starts on the
    /// top rung. The caller has already refused an empty ladder.
    fn with_ladder(window: usize, saturated: f64, ladder: Vec<u32>) -> Self {
        Self {
            ladder,
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
        self.ladder[self.rung]
    }

    /// Start on the rung whose factor is `factor`, instead of the top.
    ///
    /// The daemon loop calls this with the node's live factor so a tree
    /// created at 8 stays there until a window says otherwise, and a
    /// fork that inherited 2 does not immediately try to set 8. A factor
    /// that is not on this policy's ladder is an error — the loop does
    /// not snap to a neighbour.
    pub fn align_to(&mut self, factor: u32) -> Result<(), String> {
        let Some(rung) = ladder_rung(&self.ladder, factor) else {
            return Err(ladder_factor_error(&self.ladder, factor));
        };
        self.rung = rung;
        Ok(())
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
        if self.rung + 1 >= self.ladder.len() {
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

/// The bidirectional policy: drop on saturation, raise
/// on quiet, hold the deadband.
///
/// One instance per episode. One rung per closed window, same ladder as
/// [`DilationPolicy`]. The raise is a property of this type, not a
/// method grafted onto the monotone one — a caller that wanted "never
/// raise" and got a raise because they constructed the wrong type would
/// be a silent fallback.
#[derive(Debug, Clone)]
pub struct TrackingPolicy {
    /// Rungs, highest first. The rung index walks this, not [`LADDER`].
    ladder: Vec<u32>,
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
        Self::with_ladder(window, saturated, quiet, LADDER.to_vec())
    }

    /// [`Self::new`] on `ladder` instead of [`LADDER`].
    fn with_ladder(window: usize, saturated: f64, quiet: f64, ladder: Vec<u32>) -> Self {
        assert!(
            quiet < saturated,
            "quiet ({quiet}) must be below saturated ({saturated}) — a missing deadband chatters"
        );
        Self {
            ladder,
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
        self.ladder[self.rung]
    }

    /// Start on the rung whose factor is `factor`. See
    /// [`DilationPolicy::align_to`].
    pub fn align_to(&mut self, factor: u32) -> Result<(), String> {
        let Some(rung) = ladder_rung(&self.ladder, factor) else {
            return Err(ladder_factor_error(&self.ladder, factor));
        };
        self.rung = rung;
        Ok(())
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
            if self.rung + 1 >= self.ladder.len() {
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
    use super::{
        DilationPolicy, DilationPolicyConfig, DilationPolicyMode, PolicyConfig, TrackingPolicy,
        Verdict, LADDER, QUIET, SATURATED, WINDOW,
    };

    /// The ladder is what the N sweep licensed, in descending order.
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

    /// 0.8 of 6 is 4.8 awake: the sweep's N=4 reading (4.67) has headroom,
    /// its N=8 one (5.20) does not.
    #[test]
    fn the_threshold_sits_between_n4_and_n8() {
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

    #[test]
    fn builtin_config_is_the_module_constants() {
        let cfg = PolicyConfig::default();
        assert_eq!(cfg.window, WINDOW);
        assert!((cfg.saturated - SATURATED).abs() < f64::EPSILON);
        assert!((cfg.quiet - QUIET).abs() < f64::EPSILON);
        assert_eq!(cfg.cadence, std::time::Duration::from_secs(1));
        assert_eq!(cfg.ladder, LADDER);
        let down = cfg.down_policy().expect("default config");
        let mut track = cfg.track_policy().expect("default config");
        assert_eq!(down.factor(), LADDER[0]);
        track.align_to(1).expect("1 is the bottom rung");
        assert_eq!(track.factor(), 1);
        assert!(
            track.align_to(12).is_err(),
            "12 is the sweep's knee, not a rung"
        );
        assert!(track.align_to(3).is_err());
    }

    #[test]
    fn a_missing_deadband_is_refused_before_the_constructor_asserts() {
        let cfg = PolicyConfig {
            quiet: SATURATED,
            ..PolicyConfig::default()
        };
        let err = cfg.track_policy().expect_err("quiet == saturated chatters");
        assert!(err.contains("deadband"), "{err}");
    }

    #[test]
    fn omitted_request_config_is_the_module_constants() {
        let cfg = PolicyConfig::from_request(None).expect("omitted config");
        let builtin = PolicyConfig::default();
        assert_eq!(cfg.window, builtin.window);
        assert!((cfg.saturated - builtin.saturated).abs() < f64::EPSILON);
        assert!((cfg.quiet - builtin.quiet).abs() < f64::EPSILON);
        assert_eq!(cfg.cadence, builtin.cadence);
        assert_eq!(cfg.ladder, builtin.ladder);
        assert_eq!(cfg.window, WINDOW);
        assert_eq!(cfg.ladder, LADDER);
    }

    #[test]
    fn bad_request_knobs_are_refused() {
        let refuse = |cfg: DilationPolicyConfig, needle: &str| {
            let err = cfg.resolve().expect_err(needle);
            assert!(err.contains(needle), "{err}");
        };
        refuse(
            DilationPolicyConfig {
                window: Some(0),
                ..DilationPolicyConfig::default()
            },
            "window",
        );
        refuse(
            DilationPolicyConfig {
                cadence_ms: Some(0),
                ..DilationPolicyConfig::default()
            },
            "cadence",
        );
        refuse(
            DilationPolicyConfig {
                quiet: Some(SATURATED),
                ..DilationPolicyConfig::default()
            },
            "deadband",
        );
        refuse(
            DilationPolicyConfig {
                quiet: Some(0.9),
                saturated: Some(0.4),
                ..DilationPolicyConfig::default()
            },
            "deadband",
        );
        refuse(
            DilationPolicyConfig {
                ladder: Some(vec![]),
                ..DilationPolicyConfig::default()
            },
            "empty",
        );
        refuse(
            DilationPolicyConfig {
                ladder: Some(vec![1, 4]),
                ..DilationPolicyConfig::default()
            },
            "strictly decreasing",
        );
        refuse(
            DilationPolicyConfig {
                ladder: Some(vec![4, 4, 1]),
                ..DilationPolicyConfig::default()
            },
            "strictly decreasing",
        );
        refuse(
            DilationPolicyConfig {
                ladder: Some(vec![4, 0]),
                ..DilationPolicyConfig::default()
            },
            "outside",
        );
        refuse(
            DilationPolicyConfig {
                ladder: Some(vec![65, 1]),
                ..DilationPolicyConfig::default()
            },
            "outside",
        );
    }

    #[test]
    fn window_one_drops_on_the_first_saturated_sample() {
        let cfg = DilationPolicyConfig {
            window: Some(1),
            ladder: Some(vec![4, 1]),
            ..DilationPolicyConfig::default()
        }
        .resolve()
        .expect("window 1 on [4, 1]");
        let mut policy = cfg.down_policy().expect("down policy");
        assert_eq!(policy.factor(), 4);
        assert_eq!(policy.observe(6, 6), Verdict::Drop(1));
        assert_eq!(policy.factor(), 1);
        assert_eq!(policy.observe(6, 6), Verdict::Floor);
        assert!(
            !matches!(policy.observe(0, 6), Verdict::Raise(_)),
            "down never raises"
        );
    }

    #[test]
    fn a_fork_inherits_knobs_unless_it_sets_them() {
        let parent = DilationPolicyConfig {
            window: Some(1),
            cadence_ms: Some(250),
            ladder: Some(vec![4, 1]),
            ..DilationPolicyConfig::default()
        }
        .resolve()
        .expect("parent knobs");
        let inherited = parent.for_fork(None).expect("inherit");
        assert_eq!(inherited.window, 1);
        assert_eq!(inherited.cadence, std::time::Duration::from_millis(250));
        assert_eq!(inherited.ladder, vec![4, 1]);

        let replaced = parent
            .for_fork(Some(&DilationPolicyConfig {
                window: Some(5),
                ..DilationPolicyConfig::default()
            }))
            .expect("replace");
        assert_eq!(replaced.window, 5);
        assert_eq!(replaced.ladder, LADDER.to_vec());
        assert_eq!(replaced.cadence, parent.cadence);

        let err = parent
            .for_fork(Some(&DilationPolicyConfig {
                cadence_ms: Some(250),
                ..DilationPolicyConfig::default()
            }))
            .expect_err("a fork cadence is refused");
        assert!(err.contains("cadence"), "{err}");
    }

    #[test]
    fn policy_mode_wire_names() {
        assert_eq!(DilationPolicyMode::default(), DilationPolicyMode::Fixed);
        for (mode, name) in [
            (DilationPolicyMode::Fixed, "fixed"),
            (DilationPolicyMode::Down, "down"),
            (DilationPolicyMode::Track, "track"),
        ] {
            let wire = serde_json::to_string(&mode).unwrap();
            assert_eq!(wire, format!("\"{name}\""));
            let back: DilationPolicyMode = serde_json::from_str(&wire).unwrap();
            assert_eq!(back, mode);
        }
    }
}
