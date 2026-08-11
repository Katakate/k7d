//! Latency budgets enforced by integration tests.
//!
//! This is the **single source of truth** for every performance budget.
//! The table in [`LATENCY_BUDGETS.md`](../../../LATENCY_BUDGETS.md) mirrors
//! these values — update both together.
//!
//! Budgets are set at roughly 2× the typical observed value on the bare-metal
//! bare-metal node to allow for normal variance while catching regressions.

use std::time::Duration;

/// VM build: KVM fd creation + memfd + virtiofsd spawn + kernel load.
pub const VM_BUILD: Duration = Duration::from_millis(150);

/// VM boot to agent ready: vCPU start + kernel boot + init + vsock handshake.
pub const VM_BOOT_TO_AGENT: Duration = Duration::from_millis(250);

/// Agent ping round-trip (after warmup).
pub const AGENT_PING_RTT: Duration = Duration::from_millis(1);

/// Agent exec round-trip for a trivial command (after warmup).
pub const AGENT_EXEC_RTT: Duration = Duration::from_millis(2);

/// Five sequential agent exec round-trips (total, after warmup).
pub const EXEC_SEQUENTIAL_5X: Duration = Duration::from_millis(5);

/// Virtiofs host→guest file read via agent exec (after warmup).
pub const VIRTIOFS_READ: Duration = Duration::from_millis(2);

/// Virtiofs guest→host file write via agent exec (after warmup).
pub const VIRTIOFS_WRITE: Duration = Duration::from_millis(2);

/// Full snapshot of a 256 MB VM (pause + memory dump + CPU + devices + resume).
pub const SNAPSHOT_256MB: Duration = Duration::from_millis(500);

/// `CoW` restore from snapshot: mmap + KVM setup + vCPU restore + vsock.
/// Does NOT include agent reconnection time.
pub const RESTORE_COW: Duration = Duration::from_millis(10);

/// Agent reconnect after restore (vsock connect to new CID).
pub const RESTORE_AGENT_RECONNECT: Duration = Duration::from_millis(5000);

/// Fork a running VM (snapshot + reflink + restore). Includes pause/resume of source.
/// For a cold-booted source, this is dominated by memory dump (~200ms).
pub const FORK_COLD: Duration = Duration::from_millis(600);

/// Warm fork of a source that has been `prepare_fork_source`'d — uses KVM dirty
/// page tracking + memory-to-memory copy instead of a full memory dump.
///
/// This is a per-fork ceiling for a source with `<25%` dirty pages on 256 MB,
/// which is the typical RL exploration regime. See `fork_warm_budget()` for
/// a dirty-count-proportional budget used by the test suite.
pub const FORK_WARM: Duration = Duration::from_millis(50);

// The warm-fork budget model lives in `crate::tree_model` as raw `u64`
// nanoseconds (internal notes; internal notes`Duration`
// there because Aeneas models it opaquely — the `fork_warm_budget_*_rust`
// corollaries in `verif/Verif/Equiv/Transfer.lean` are proved against the
// Aeneas translation of `fork_warm_budget_ns`). This is the one place the
// `_NS` values are wrapped back into `Duration`; call sites keep using
// `crate::latency::FORK_WARM_BASE` etc. unchanged.
use crate::tree_model::{fork_warm_budget_ns, FORK_WARM_BASE_NS, FORK_WARM_PER_PAGE_NS};

/// Per-page memcpy budget (0.5 µs per 4 KiB page on DDR4 ~20 GB/s).
pub const FORK_WARM_PER_PAGE: Duration = Duration::from_nanos(FORK_WARM_PER_PAGE_NS);

/// Fixed overhead of the warm fork hot path (KVM fd + vCPU setup + vsock).
pub const FORK_WARM_BASE: Duration = Duration::from_nanos(FORK_WARM_BASE_NS);

/// Compute a per-dirty-page warm fork budget.
///
/// `Duration` wrapper over [`crate::tree_model::fork_warm_budget_ns`]
/// (`base + per_page * dirty_pages`, saturating at `u64::MAX` ns).
#[must_use]
pub fn fork_warm_budget(dirty_pages: u64) -> Duration {
    Duration::from_nanos(fork_warm_budget_ns(dirty_pages))
}

/// Fork agent reconnect (vsock connect to forked VM's new CID).
pub const FORK_AGENT_RECONNECT: Duration = Duration::from_millis(5000);

/// internal notes� warm fork of a 2-vCPU source ([`FORK_WARM`] + 25 ms).
///
/// The extra headroom covers the second vCPU's capture (LAPIC + MSRs +
/// XSAVE reads) and restore (create + full state ioctl sequence);
/// deliberately generous at first — tighten after measuring.
pub const FORK_WARM_2VCPU: Duration = Duration::from_millis(75);

/// internal notes� `CoW` restore of a 2-vCPU snapshot ([`RESTORE_COW`] + 25 ms).
pub const RESTORE_2VCPU: Duration = Duration::from_millis(35);

/// Warm cluster fork of 3 VMs.
///
/// Budget covers the on-host portion only — bridge clone + per-VM
/// `add_tap_at` + per-VM warm fork. Excludes any k8s-API plumbing that
/// would happen above this layer.
///
/// internal notes's quiet-host target is ~25–40 ms; the ceiling is 150 ms to
/// absorb bare-metal scheduler/KVM-cache jitter (same class of variance that
/// pushed the cluster-tree budgets to 750 ms). Still fails loud on real
/// regressions (hundreds of ms).
pub const FORK_CLUSTER_WARM_3VM: Duration = Duration::from_millis(150);

/// internal notes� 3-VM cluster fork via the cluster snapshot tree.
///
/// [`FORK_CLUSTER_WARM_3VM`] (50 ms — internal notes's bare primitive) plus
/// the tree's bookkeeping: `auto_evict_if_over` + `save_metadata` +
/// `cluster.json` write + per-fork bitmap re-seed. internal notes"Latency
/// expectations" projects ~75 ms; we set the ceiling at 750 ms to
/// match the run-after-other-tests variance we see for
/// [`FORK_CLUSTER_WARM_3VM`] on the loaded bare-metal node (the
/// `fork_cluster_warm` test alone runs in ~25 ms; under the full
/// integration suite it can swing up to ~500 ms when KVM sees a busy
/// L1 cache from prior tests). Tightening this back to ~75 ms is a
/// follow-up once `make remote-check` enforces a clean-bridge state
/// between tests.
pub const FORK_CLUSTER_TREE_3VM: Duration = Duration::from_millis(750);

/// internal notes� shared-pause batch of 50× 3-VM cluster-tree forks.
///
/// [`crate::fork::fork_cluster_warm_batch`] pauses the source once,
/// builds 50 bridges sequentially (host `ip`/`iptables`), then
/// materialises 150 member VMs concurrently. Bridge setup dominates;
/// the ceiling absorbs loaded-host jitter under `make remote-check`.
/// Enforced by `test_cluster_tree_fork_batch_50`.
pub const FORK_CLUSTER_TREE_BATCH_50: Duration = Duration::from_secs(20);

/// internal notes� 8× 3-VM bare `fork_cluster_warm_batch` (no tree).
///
/// Must beat 8 × [`FORK_CLUSTER_WARM_3VM`] so the shared-pause path is
/// measurably better than N independent pauses under the same ceiling.
pub const FORK_CLUSTER_WARM_BATCH_8: Duration = Duration::from_secs(2);

/// internal notes/ 14a Inc 5 — warm-fork a live 3-VM inner-k3s
/// cluster via `TreeAdoptCluster` + `TreeFork`.
///
/// Covers only the on-host `TreeFork` call (not adopt/prepare, not
/// kubectl plumbing). internal notes
/// block path (airgap RO hostPath → cached erofs on virtio-blk, zero
/// virtiofs shares), so every member forks `CoW` (`MAP_PRIVATE` of
/// `base.mem` + dirty-page memcpy) instead of full-copying 3 ×
/// ~3.2 GiB memfds — the historical 15 s budget collapses to < 1 s.
/// Inner-k3s members are dirtier than the busybox payloads behind
/// [`FORK_CLUSTER_TREE_3VM`] (k3s + etcd churn between prepare and
/// fork), hence the extra headroom over that 750 ms ceiling.
/// Enforced by `test_inner_k3s_cluster_warm_fork_no_restart`.
pub const FORK_INNER_K3S_CLUSTER_3VM: Duration = Duration::from_millis(1_000);

/// internal notes� 3-VM cluster suspend via the cluster snapshot tree.
///
/// Per-member pause + dirty bitmap capture + `delta.pack` write +
/// state-json write, plus bridge teardown and `cluster.json` write.
/// internal notes~25 ms; ceiling at 250 ms for the same
/// run-after-other-tests headroom as the fork budget.
pub const SUSPEND_CLUSTER_TREE_3VM: Duration = Duration::from_millis(750);

/// internal notes� 3-VM cluster resume via the cluster snapshot tree.
///
/// Bridge re-create + per-member `add_tap_at` + `mmap(MAP_PRIVATE)` of
/// each member's `base.mem` + per-member `apply_delta` + KVM rebuild
/// from `vm_state.json`. internal notes~40 ms; ceiling at 750 ms.
pub const RESUME_CLUSTER_TREE_3VM: Duration = Duration::from_millis(750);

/// internal notes� pool-compatible `create_vm` served from the
/// warm pool (mirrors Milestone 10's 100 ms ceiling): pop an idle
/// agent-ready VM, registry insert, sandbox-record write, and one
/// JSON-lines Unix-socket round trip. No boot, no fork — those happen
/// off the request path in the pool's filler thread.
pub const POOL_ACQUIRE: Duration = Duration::from_millis(100);

/// internal notes� single-VM tree fork through the daemon
/// control plane: [`FORK_WARM`] plus tree bookkeeping (metadata save,
/// post-fork eviction check) plus one JSON-lines Unix-socket round
/// trip. Ceiling carries the same busy-node headroom as the cluster
/// tree budgets.
pub const DAEMON_TREE_FORK: Duration = Duration::from_millis(500);

/// VM shutdown (signal vCPU thread + join).
pub const VM_SHUTDOWN: Duration = Duration::from_millis(5);

/// internal notes� per-pod kubelet-volume setup time.
///
/// Bounds the host-side work [`crate::volumes::PodVolumes::prepare`]
/// does at sandbox `Create`: enumerate the kubelet pod dir, classify
/// each volume's plugin, create the per-pod scratch tree, and bind-
/// mount one entry per volume into it. This is per-pod, runs once,
/// and happens inline in the shim's Create path so it adds directly
/// to "time-to-pod-Ready" for any `runtimeClassName: k7` workload.
///
/// internal notes's design budget is **80 ms**; on the bare-metal node a
/// typical pod with 3-4 kubelet volumes (configmap + projected
/// kube-api-access + maybe a secret or emptyDir) finishes in
/// **~25-40 ms** dominated by the per-volume `mount --bind` fork+
/// execs. We set the ceiling at **250 ms** to absorb the same kind
/// of run-after-other-tests variance the cluster-tree budgets
/// allow for — the test exercises a pod with 6 volumes (one more
/// than typical) so the budget covers some real-world overhead.
///
/// Excludes virtiofsd spawn time (that's already in
/// [`VM_BUILD`]) and excludes the per-workload hostPath /
/// etc-files binds (those run at workload Create, not sandbox
/// Create — different code path, smaller scope).
pub const POD_VOLUMES_SETUP: Duration = Duration::from_millis(250);

/// internal notes� time from shim `Create` returning to "pod is reachable
/// on its CNI-assigned pod IP from another pod on the cluster."
///
/// Adds the spec-10a in-pod-netns work over the existing
/// [`VM_BOOT_TO_AGENT`] cost: `move_link_to_netns`,
/// `create_bridge_in_netns` (with two `ip link set master` enslaves
/// and two `sysctl -w bridge-nf-call-*=0`), and `install_pod_nat`
/// (two `nsenter --net=PATH iptables -A` calls). Each shells out via
/// `nsenter`/`ip`, ~1 ms per `nsenter` fork; ceiling is 50 ms.
pub const POD_NETWORK_READY: Duration = Duration::from_millis(50);

/// internal notes, Milestone 4 — how long the host waits for a freshly
/// spawned `virtiofsd` to create its vhost-user socket before failing
/// the VM build.
///
/// A multi-share pod spawns up to three `virtiofsd` children
/// sequentially (`k7fs`, `k7fs1`, `k7fs2`), so on a busy node — e.g.
/// the 7th-9th k7 pod in a back-to-back integration run — the old
/// hard-coded 5 s was too tight even when virtiofsd was perfectly
/// healthy, surfacing as "virtiofsd socket did not appear" and a pod
/// stuck in `ContainerCreating`. 15 s absorbs that variance; spawn is
/// not on any hot path, so the larger ceiling costs nothing in the
/// common (sub-second) case.
pub const VIRTIOFSD_SOCKET_APPEAR: Duration = Duration::from_secs(15);
