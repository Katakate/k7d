//! Per-container writable-layer (ephemeral storage) usage.
//!
//! The number itself can only come from inside the guest — the host
//! sees a sparse image's allocated blocks, which never shrink when the
//! guest deletes a file and say nothing about which container wrote
//! them (`k7d::api::AgentClient::container_usage`).
//!
//! **Why this is not in the `Stats` payload.** The CRI stats path
//! accepts exactly one message from a shim: a cgroups `Metrics`
//! (hugetlb / pids / cpu / memory / blkio / rdma / network / cgroup
//! stats), and none of those has a field for filesystem usage. Putting
//! the number anywhere in there would mean lying in a field kubelet
//! reads as something else, and anything *other* than a decodable
//! `Metrics` breaks `ListContainerStats` for every pod on the node, k7
//! or not (see the comment on `task::K7Service::stats` and
//! CHALLENGES #61). So `Stats` stays a valid `Metrics`, and it is used
//! as the *clock*: each call refreshes a cached sample in the
//! background and logs the usage, warning when a container crosses the
//! high-water mark. The precise numbers stay available on demand over
//! vsock, which is the surface programs should use.
//!
//! Sampling must never make `Stats` slow or expensive: kubelet polls it
//! per container every few seconds, and a shared-scratch sample walks
//! the container's `upper` tree in the guest. Hence a TTL'd cache, a
//! single in-flight refresh per container, and a background thread —
//! the ttrpc handler never waits on the guest.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use k7d::api::{AgentClient, ContainerUsage};

/// How stale a cached sample may be before a `Stats` call refreshes it.
const SAMPLE_TTL: Duration = Duration::from_secs(15);

/// Retry interval after a failed sample. Longer than [`SAMPLE_TTL`]:
/// the common failure is a container that legitimately has no k7d
/// writable layer (no overlay), and re-dialling the guest for it on
/// every poll would be pure overhead.
const ERROR_BACKOFF: Duration = Duration::from_secs(60);

/// Give up on a refresh that cannot reach the agent this quickly. The
/// guest is either gone (teardown) or busy; either way `Stats` has
/// already returned and a stuck thread would pile up.
const AGENT_TIMEOUT: Duration = Duration::from_secs(2);

/// Percentage of capacity at which a writable layer is reported as
/// nearly full. Edge-triggered: crossing up warns, dropping back below
/// logs the recovery, and a container parked above it does not repeat
/// the warning on every poll.
const HIGH_WATER_PCT: u64 = 85;

/// A usage reading plus the bookkeeping that keeps logging quiet.
struct Sample {
    at: Instant,
    usage: ContainerUsage,
    /// Whether this reading was at or above [`HIGH_WATER_PCT`].
    over_high_water: bool,
}

#[derive(Default)]
struct Slot {
    last: Option<Sample>,
    /// A refresh thread is running (or crashed without clearing this,
    /// which the [`AGENT_TIMEOUT`]-bounded work makes a bounded lie).
    refreshing: bool,
    /// When the last attempt failed, and whether we have already said
    /// so — the reason is usually static (no overlay), so it is logged
    /// once per container rather than once per poll.
    failed_at: Option<Instant>,
    reported_failure: bool,
}

/// Percentage of `capacity` that `used` is; 0 when the capacity is
/// unknown (a `statfs` on a filesystem reporting no blocks).
///
/// Widened to `u128` for the multiply: a saturating `u64` one clamps
/// before the divide, which turns a full multi-exabyte filesystem into
/// 1%. The result is clamped rather than wrapped, so the comparison
/// against [`HIGH_WATER_PCT`] stays monotone in `used`.
fn percent(used: u64, capacity: u64) -> u64 {
    if capacity == 0 {
        return 0;
    }
    let pct = u128::from(used) * 100 / u128::from(capacity);
    u64::try_from(pct).unwrap_or(u64::MAX)
}

/// Cache of per-container writable-layer usage, shared across the
/// shim's task-service clones.
#[derive(Clone, Default)]
pub struct UsageTracker {
    slots: Arc<Mutex<HashMap<String, Slot>>>,
}

impl UsageTracker {
    /// Refresh `container_id`'s sample in the background if the cached
    /// one is stale, and return the reading currently cached (`None`
    /// until the first refresh lands).
    ///
    /// Returns immediately in every case: the guest is only ever talked
    /// to from the spawned thread.
    pub fn sample(
        &self,
        container_id: &str,
        guest_name: &str,
        guest_cid: u64,
    ) -> Option<ContainerUsage> {
        let (due, cached) = {
            let mut slots = self.slots.lock().unwrap();
            let slot = slots.entry(container_id.to_string()).or_default();
            let fresh_enough = slot
                .last
                .as_ref()
                .is_some_and(|s| s.at.elapsed() < SAMPLE_TTL);
            let backing_off = slot
                .failed_at
                .is_some_and(|at| at.elapsed() < ERROR_BACKOFF);
            let due = !slot.refreshing && !fresh_enough && !backing_off;
            if due {
                slot.refreshing = true;
            }
            (due, slot.last.as_ref().map(|s| s.usage))
        };
        if due {
            let tracker = self.clone();
            let container_id = container_id.to_string();
            let guest_name = guest_name.to_string();
            std::thread::spawn(move || {
                tracker.refresh(&container_id, &guest_name, guest_cid);
            });
        }
        cached
    }

    /// Drop a container's cache entry (its Delete).
    pub fn forget(&self, container_id: &str) {
        self.slots.lock().unwrap().remove(container_id);
    }

    fn refresh(&self, container_id: &str, guest_name: &str, guest_cid: u64) {
        let result = AgentClient::connect_vsock(guest_cid, AGENT_TIMEOUT)
            .and_then(|mut agent| agent.container_usage(guest_name));
        let mut slots = self.slots.lock().unwrap();
        let Some(slot) = slots.get_mut(container_id) else {
            // Container deleted while we were asking.
            return;
        };
        slot.refreshing = false;
        match result {
            Ok(usage) => {
                let pct = percent(usage.used_bytes, usage.capacity_bytes);
                let over = pct >= HIGH_WATER_PCT;
                let was_over = slot.last.as_ref().is_some_and(|s| s.over_high_water);
                let first = slot.last.is_none();
                slot.failed_at = None;
                slot.reported_failure = false;
                slot.last = Some(Sample {
                    at: Instant::now(),
                    usage,
                    over_high_water: over,
                });
                drop(slots);
                log_reading(container_id, &usage, pct, first, was_over, over);
            }
            Err(e) => {
                let first = !slot.reported_failure;
                slot.failed_at = Some(Instant::now());
                slot.reported_failure = true;
                drop(slots);
                if first {
                    // Not an error: a container whose rootfs is not an
                    // overlay has no writable layer of ours to measure.
                    log::info!(
                        "ephemeral storage: no usage for container {container_id} \
                         (guest {guest_name}): {e}"
                    );
                }
            }
        }
    }
}

/// The observable surface. Every reading goes to the shim's log with
/// the numbers spelled out; crossing the high-water mark warns and
/// names the annotation that raises the limit, because a container that
/// runs out of writable space otherwise only shows up as a write
/// failing inside the guest.
fn log_reading(
    container_id: &str,
    usage: &ContainerUsage,
    pct: u64,
    first: bool,
    was_over: bool,
    over: bool,
) {
    let shape = if usage.dedicated {
        "its own scratch disk"
    } else {
        "the pod's shared scratch disk"
    };
    let msg = format!(
        "ephemeral storage: container {container_id} uses {} MiB of {} MiB ({pct}%) on {shape}",
        usage.used_bytes / (1024 * 1024),
        usage.capacity_bytes / (1024 * 1024),
    );
    if over && !was_over {
        let hint = if usage.dedicated {
            "raise k7d.katakate.org/container-scratch-size for this container"
        } else {
            "raise k7d.katakate.org/scratch-size, or give this container its own limit \
             with k7d.katakate.org/container-scratch-size"
        };
        log::warn!("{msg} — past {HIGH_WATER_PCT}% of capacity; {hint}");
        crate::task::debug_log_cni(&msg);
    } else if !over && was_over {
        log::info!("{msg} — back under {HIGH_WATER_PCT}% of capacity");
        crate::task::debug_log_cni(&msg);
    } else {
        log::info!("{msg}");
        if first {
            crate::task::debug_log_cni(&msg);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn percent_is_saturating_and_zero_safe() {
        assert_eq!(percent(0, 0), 0, "unknown capacity must not divide by zero");
        assert_eq!(percent(5, 0), 0);
        assert_eq!(percent(1, 2), 50);
        assert_eq!(percent(85, 100), HIGH_WATER_PCT);
        assert_eq!(
            percent(u64::MAX, u64::MAX),
            100,
            "a full filesystem is full at any size"
        );
        assert!(
            percent(u64::MAX - 1, u64::MAX) >= HIGH_WATER_PCT,
            "an exabyte-scale filesystem must still trip the high-water mark"
        );
    }

    /// `Stats` must never block on the guest: with no VM on the CID the
    /// first call still returns instantly (with nothing cached), and the
    /// failed refresh then backs the container off instead of dialling
    /// again on every poll.
    #[test]
    fn sampling_never_blocks_and_backs_off_after_failure() {
        let tracker = UsageTracker::default();
        let start = Instant::now();
        assert!(
            tracker.sample("c1", "c1", 0xffff_fffe).is_none(),
            "nothing can be cached before the first refresh lands"
        );
        assert!(
            start.elapsed() < Duration::from_millis(500),
            "sample() waited on the agent: {:?}",
            start.elapsed()
        );

        // Let the refresh thread fail against the bogus CID.
        let deadline = Instant::now() + Duration::from_secs(30);
        loop {
            {
                let slots = tracker.slots.lock().unwrap();
                let slot = slots.get("c1").expect("slot exists");
                if !slot.refreshing && slot.failed_at.is_some() {
                    break;
                }
            }
            assert!(Instant::now() < deadline, "refresh never finished");
            std::thread::sleep(Duration::from_millis(50));
        }

        tracker.sample("c1", "c1", 0xffff_fffe);
        let slots = tracker.slots.lock().unwrap();
        assert!(
            !slots.get("c1").unwrap().refreshing,
            "a failed container must back off, not re-dial on the next poll"
        );
        drop(slots);

        tracker.forget("c1");
        assert!(tracker.slots.lock().unwrap().is_empty());
    }
}
