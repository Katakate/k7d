//! k7d daemon control plane — Unix-socket JSON-lines API.
//!
//! The daemon owns VM lifecycle (KVM, guest memory, vhost-vsock,
//! virtiofsd) and exposes create/stop/status operations to clients
//! (the containerd shim, the `k7` Python backend, tests).
//!
//! Protocol: one JSON request object per line, one JSON response
//! object per line. A connection may carry multiple request/response
//! pairs. Errors are always an explicit `{"status":"error",...}`
//! response — never a silent success.
//!
//! Clients reach the guest agent themselves over vsock using the
//! `guest_cid` returned by `create_vm`; the daemon does not proxy the
//! agent protocol (vsock CIDs are a kernel-global namespace, so any
//! host process can connect to a running VM's agent).

use std::collections::{BTreeSet, HashMap};
use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};

use crate::cluster_tree::{ClusterPayload, ClusterSnapshotTree};
use crate::network::{ClusterNetwork, TapDevice};
use crate::pool::Pool;
use crate::tree::{NodeInfo, SnapshotTree, TreeBudget, TreeUsage};
use crate::vm::Vm;

/// Default control-socket path when neither `--socket` nor `K7D_SOCKET`
/// is given.
pub const DEFAULT_SOCKET: &str = "/run/k7d/k7d.sock";

/// Default on-disk home for daemon-owned snapshot trees (override with
/// env `K7D_TREE_ROOT`). Each tree gets `{root}/{tree_id}/`.
pub const DEFAULT_TREE_ROOT: &str = "/var/lib/k7d/trees";

/// Default on-disk home for sandbox reattach records (override with
/// env `K7D_SANDBOX_ROOT`). Each sandbox-carrying VM gets
/// `{root}/{sandbox_id}.json`.
pub const DEFAULT_SANDBOX_ROOT: &str = "/var/lib/k7d/sandboxes";

/// Tree budget applied when a `tree_create*` request omits `budget`.
/// Documented default, not a silent fallback: sized for a node running
/// a handful of 256 MiB guests.
#[must_use]
pub fn default_tree_budget() -> TreeBudget {
    TreeBudget {
        max_live_vms: 8,
        max_live_ram_bytes: 8 * 1024 * 1024 * 1024,
        max_disk_bytes: 32 * 1024 * 1024 * 1024,
        max_chain_depth: 1,
    }
}

/// Control-plane (JSON) view of [`TreeUsage`].
///
/// Lives here so `tree_model.rs` (the Lean/Aeneas surface) stays
/// untouched — that type has no serde derives.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct TreeUsageInfo {
    /// Σ of `vm_count` over all Live nodes.
    pub live_vm_count: usize,
    /// Estimated non-reclaimable RAM used by live VMs, in bytes.
    pub live_ram_bytes: u64,
    /// On-disk `memory.bin` + `delta.pack` footprint, in bytes.
    pub disk_bytes: u64,
    /// Live + suspended + evicted node count.
    pub total_nodes: usize,
    /// Count of tree nodes currently in `Live` state.
    pub live_node_count: usize,
}

impl From<TreeUsage> for TreeUsageInfo {
    fn from(u: TreeUsage) -> Self {
        Self {
            live_vm_count: u.live_vm_count,
            live_ram_bytes: u.live_ram_bytes,
            disk_bytes: u.disk_bytes,
            total_nodes: u.total_nodes,
            live_node_count: u.live_node_count,
        }
    }
}

/// One mutation pushed on a `tree_watch` connection after the initial
/// snapshot. Notes/traces stay out of `tree.json` — this is
/// machine-first (op + `node_id` + optional `latency_ns`).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TreeEvent {
    /// Tree that changed.
    pub tree_id: String,
    /// `fork` / `protect` / `unprotect` / `suspend` / `resume` /
    /// `prune` / `evict` / `drop`.
    pub op: String,
    /// Node the op targeted or produced (`None` for tree-wide ops).
    #[serde(default)]
    pub node_id: Option<String>,
    /// Wall time of a fork/rollback/batch, when the op measured one.
    #[serde(default)]
    pub latency_ns: Option<u64>,
}

/// Current state of one tree, sent as the `tree_watch` snapshot.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TreeWatchSnapshot {
    /// Tree identifier.
    pub tree_id: String,
    /// `"vm"` or `"cluster"`.
    pub kind: String,
    /// Every node's metadata (same as `tree_nodes`).
    pub nodes: Vec<NodeInfo>,
    /// Current resource usage.
    pub usage: TreeUsageInfo,
    /// Resource budget.
    pub budget: TreeBudget,
    /// Live vsock CIDs keyed by node id. Empty vec = no live payload.
    /// Not persisted in `tree.json`.
    #[serde(default)]
    pub live_guest_cids: HashMap<String, Vec<u64>>,
}

/// One subscriber on the control-socket `tree_watch` stream.
struct WatchSub {
    /// `None` = every tree.
    tree_id: Option<String>,
    tx: std::sync::mpsc::Sender<TreeEvent>,
}

/// A virtiofs share to plumb into the VM.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ShareConfig {
    /// Host directory to export.
    pub host_dir: String,
    /// Mount point inside the guest.
    pub guest_mount: String,
    /// Whether the guest mounts it read-only.
    #[serde(default)]
    pub readonly: bool,
}

/// A raw virtio-blk disk image to attach to the VM.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlockDeviceConfig {
    /// Host path of the raw image file (size must be a multiple of 512).
    pub host_path: String,
    /// Attach read-only (`VIRTIO_BLK_F_RO`); guest writes are rejected.
    #[serde(default)]
    pub readonly: bool,
    /// Mount the device inside the guest at this absolute path before
    /// containers start (`k7d.blk=`). A caller declares
    /// "this device is the container rootfs" by mounting an erofs image
    /// here and pointing the container bundle's `root.path` at it — the
    /// agent assembles overlay(erofs RO, tmpfs upper) for runc. Requires
    /// `fstype`; both set or both absent, validated loudly.
    #[serde(default)]
    pub guest_mount: Option<String>,
    /// Filesystem type for `guest_mount` (e.g. `erofs`, `ext4`).
    #[serde(default)]
    pub fstype: Option<String>,
}

/// Apply `blocks` to a [`crate::vm::VmBuilder`], validating the
/// `guest_mount`/`fstype` pairing loudly: both set ⇒
/// agent-mounted device, both absent ⇒ raw device, mixed ⇒ error.
fn apply_block_devices(
    mut builder: crate::vm::VmBuilder,
    blocks: &[BlockDeviceConfig],
) -> Result<crate::vm::VmBuilder, String> {
    for blk in blocks {
        builder = match (&blk.guest_mount, &blk.fstype) {
            (Some(gm), Some(fstype)) => {
                builder.block_device_mounted(&blk.host_path, blk.readonly, gm, fstype)
            }
            (None, None) => builder.block_device(&blk.host_path, blk.readonly),
            _ => {
                return Err(format!(
                    "block device {}: guest_mount and fstype must be set together",
                    blk.host_path
                ))
            }
        };
    }
    Ok(builder)
}

/// Network parameters for a VM.
///
/// When present, the daemon creates (or joins) the shared cluster
/// bridge `k7-br-{cluster_id}`, allocates a TAP on it, and — when
/// `pod_netns` is given — moves the TAP into the CNI pod netns with
/// the bridge + NAT plumbing. Bridges are refcounted across
/// VMs so the first pod deleted in a cluster no longer tears the
/// shared bridge down under its peers.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetConfig {
    /// Cluster identity — names the shared bridge. Single-VM pods pass
    /// their sandbox ID here (bridge lives and dies with the pod).
    pub cluster_id: String,
    /// Reuse a specific `vm_index` (fork pods keep the source VM's
    /// IP/MAC). `None` allocates the next free index.
    #[serde(default)]
    pub vm_index: Option<u32>,
    /// CNI-assigned pod netns path to attach the TAP into.
    /// The daemon reads the pod IP from `eth0` inside the netns.
    /// Attach failures fall back to host-bridge networking with a
    /// warning (matching the historical shim behaviour) and are
    /// reported via `pod_netns_attached` in the response.
    #[serde(default)]
    pub pod_netns: Option<String>,
}

/// VM creation parameters supplied by a control-plane client.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VmConfig {
    /// Guest kernel path. Falls back to env `K7D_KERNEL`.
    #[serde(default)]
    pub kernel: Option<String>,
    /// Initramfs path. Falls back to env `K7D_INITRD` only when the
    /// caller did not set a `root=` disk boot (see
    /// [`crate::config::resolve_vm_guest`]). Empty/omitted on an Ubuntu
    /// node (`block_devices` + cmdline `root=`) is *no* initrd — never
    /// the `RuntimeClass` busybox pair (CHALLENGES #72).
    #[serde(default)]
    pub initrd: Option<String>,
    /// Replacement kernel command line. `None` keeps the builder's
    /// busybox/`rdinit=/init` default. A guest with a different init
    /// contract (Ubuntu `root=/dev/vda`, `k7d.k3s=`) must set this;
    /// there is no merge.
    #[serde(default)]
    pub cmdline: Option<String>,
    /// Guest RAM in MiB.
    #[serde(default = "default_memory_mb")]
    pub memory_mb: u64,
    /// Guest vCPU count (derived from the pod's CPU limit;
    /// Honored by the VMM — the guest boots with this many
    /// CPUs, discovered via an MP table when > 1). The host-side CFS
    /// quota below still enforces the pod's CPU limit across all vCPU
    /// threads. Multi-vCPU VMs snapshot/fork/checkpoint like
    /// single-vCPU ones, and are pool-served when the pool's prefill
    /// config carries the same vCPU count.
    #[serde(default = "default_vcpus")]
    pub vcpus: u32,
    /// Host CFS quota in µs per period, applied to the
    /// VM's vCPU threads via a dedicated threaded cgroup under the
    /// daemon's own cgroup. `None` = uncapped. Requires `cpu_period`.
    #[serde(default)]
    pub cpu_quota: Option<u64>,
    /// CFS period in µs for `cpu_quota`.
    #[serde(default)]
    pub cpu_period: Option<u64>,
    /// Whether to attach a vhost-vsock device (needed for the agent).
    #[serde(default = "default_true")]
    pub vsock: bool,
    /// virtiofs shares; the first is the primary (`k7fs`).
    #[serde(default)]
    pub virtiofs: Vec<ShareConfig>,
    /// virtio-blk disk images, in device order (`/dev/vda`, `/dev/vdb`, …).
    #[serde(default)]
    pub block_devices: Vec<BlockDeviceConfig>,
    /// Absolute guest tmpfs directories the agent creates at boot
    /// (`k7d.mkdir=`) — emptyDir volume backing.
    #[serde(default)]
    pub guest_dirs: Vec<String>,
    /// Capacity in bytes of this sandbox's writable scratch
    /// disk. The daemon provisions a sparse ext4 image on the reflink
    /// loopback XFS, attaches it as the LAST read-write virtio-blk
    /// device, and the guest agent puts every container's overlay
    /// `upper`/`work` on it — so container writes land on the host
    /// instead of guest RAM.
    ///
    /// `None` means "no scratch disk": the guest agent falls back to a
    /// small, explicitly bounded tmpfs and says so loudly. Callers that
    /// run containers (the shim always does) should set this; the
    /// default lives in the shim (`k7d.katakate.org/scratch-size`) and
    /// is deliberately independent of `memory_mb`.
    #[serde(default)]
    pub scratch_size_bytes: Option<u64>,
    /// Containers that get their **own** writable image
    /// instead of a directory on the shared sandbox scratch, so that a
    /// container which fills its writable layer cannot starve its
    /// siblings. Empty (the default) reproduces exactly.
    ///
    /// Each entry costs one more virtio-blk device out of the guest's
    /// MMIO budget, which is why it is opt-in per container rather than
    /// the default for all of them.
    #[serde(default)]
    pub container_scratch: Vec<ContainerScratchConfig>,
    /// **Named persistent** disks to attach, in declaration order after
    /// `block_devices` . Unlike `scratch_size_bytes`
    /// these outlive the VM: `stop_vm` leaves the image on the reflink
    /// XFS, and only an explicit `delete_data_disk` (or the age-gated
    /// sweep of a vanished test run) removes it. Empty (the default)
    /// reproduces today's all-ephemeral behaviour exactly.
    ///
    /// Each entry costs one virtio-blk device out of the guest's MMIO
    /// budget, like a per-container scratch disk.
    #[serde(default)]
    pub data_disks: Vec<DataDiskConfig>,
    /// Optional caller-supplied sandbox identity, echoed in
    /// `list_vms` so a shim can find its VM after a restart.
    #[serde(default)]
    pub sandbox_id: Option<String>,
    /// Optional network attachment (bridge + TAP + pod netns).
    #[serde(default)]
    pub network: Option<NetConfig>,
    /// Continuous time dilation : guest time runs this
    /// many times faster than wall time, for the whole life of the VM.
    /// Absent or 1 is stock. Every member of a cluster is created from
    /// one `VmConfig`, so a cluster is dilated in lockstep by
    /// construction — the same invariant `WarpClock` keeps for offsets.
    ///
    /// A host without the carried KVM patch fails VM creation instead
    /// of running the guest at 1x.
    #[serde(default)]
    pub dilation: Option<u32>,
}

/// One **named persistent** data disk .
///
/// `id` is the identity that outlives the VM: the image is
/// `<disks>/data/<id>.img` on the reflink XFS, created sparse and
/// `mkfs.ext4`'d on first use and reused as-is on every later attach.
/// Attaching an `id` whose image exists never reformats it, and a
/// `size_bytes` that disagrees with the existing image is an error rather
/// than a silent resize.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DataDiskConfig {
    /// Persistent identity; also the image's filename component.
    pub id: String,
    /// Capacity in bytes. Must match an existing image exactly.
    pub size_bytes: u64,
    /// Absolute guest path the agent mounts it at (ext4), before
    /// containers start.
    pub guest_mount: String,
}

/// One container's own writable capacity.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ContainerScratchConfig {
    /// Kubernetes container name. The agent matches it against the
    /// bundle's `io.kubernetes.cri.container-name` annotation — the
    /// guest runc name is the containerd container id, which does not
    /// exist yet when this device is declared at sandbox create.
    pub name: String,
    /// Capacity in bytes of that container's ext4 image.
    pub size_bytes: u64,
}

/// Manual `Default` matching the serde field defaults — a derived one
/// would give `memory_mb: 0` / `vcpus: 0`, which are never valid.
impl Default for VmConfig {
    fn default() -> Self {
        Self {
            kernel: None,
            initrd: None,
            cmdline: None,
            memory_mb: default_memory_mb(),
            vcpus: default_vcpus(),
            cpu_quota: None,
            cpu_period: None,
            vsock: default_true(),
            virtiofs: Vec::new(),
            block_devices: Vec::new(),
            guest_dirs: Vec::new(),
            scratch_size_bytes: None,
            container_scratch: Vec::new(),
            data_disks: Vec::new(),
            sandbox_id: None,
            network: None,
            dilation: None,
        }
    }
}

fn default_memory_mb() -> u64 {
    256
}

fn default_vcpus() -> u32 {
    1
}

fn default_dilation_one() -> u32 {
    1
}

/// the referenced work: `0` is never a factor. `None` inherits the source.
fn validate_fork_dilation(dilation: Option<u32>) -> Result<Option<u32>, String> {
    match dilation {
        Some(0) => Err(
            "dilation 0 is not a factor — omit the field to inherit the source's, or pass 1..=64"
                .into(),
        ),
        other => Ok(other),
    }
}

fn default_true() -> bool {
    true
}

/// On-disk reattach record for one sandbox-carrying VM.
/// Written atomically to
/// `{sandbox_root}/{sandbox_id}.json` on `create_vm`, removed on
/// `stop_vm` / daemon shutdown. A freshly respawned shim resolves its
/// sandbox back to the still-running VM through `reattach_sandbox`.
/// Also persists the create-time vCPU count (and CFS cap)
/// so crash-recovery / reattach paths never silently assume 1 vCPU.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SandboxRecord {
    /// CRI sandbox identity (the record's key).
    pub sandbox_id: String,
    /// Daemon-side VM identifier.
    pub vm_id: String,
    /// Guest vsock CID clients dial the agent on.
    pub guest_cid: u64,
    /// Guest vCPU count at create time. Defaults to 1 for
    /// records written before this field existed.
    #[serde(default = "default_vcpus")]
    pub vcpus: u32,
    /// Host CFS quota in µs per period, when the pod was CPU-capped.
    #[serde(default)]
    pub cpu_quota: Option<u64>,
    /// CFS period in µs for `cpu_quota`.
    #[serde(default)]
    pub cpu_period: Option<u64>,
    /// `vm_index` on the cluster bridge, when networked.
    #[serde(default)]
    pub vm_index: Option<u32>,
    /// Cluster bridge identity, when networked.
    #[serde(default)]
    pub cluster_id: Option<String>,
    /// CNI pod netns the TAP was attached into, when it was.
    #[serde(default)]
    pub pod_netns: Option<String>,
    /// Unix timestamp of the `create_vm` that wrote this record.
    pub created_at_unix: u64,
}

/// A control-plane request.
#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case")]
pub enum Request {
    /// Liveness check.
    Ping,
    /// Create and boot a VM.
    CreateVm {
        /// VM parameters.
        config: VmConfig,
    },
    /// Query a VM's state.
    VmStatus {
        /// VM identifier from `create_vm`.
        vm_id: String,
    },
    /// Read a VM's accumulated serial console output. Debugging aid:
    /// guest kernel messages (OOM kills, panics, fd/thread exhaustion)
    /// and the agent's stderr all land on the console, which the
    /// daemon buffers in memory — this is the only way to see inside
    /// a guest whose vsock agent has stopped answering.
    DumpSerial {
        /// VM identifier from `create_vm` (daemon-registry VMs).
        #[serde(default)]
        vm_id: Option<String>,
        /// Guest vsock CID — also finds live VMs inside snapshot
        /// trees (adopted / forked cluster members carry no `vm_id`).
        #[serde(default)]
        guest_cid: Option<u64>,
    },
    /// List all VMs the daemon owns.
    ListVms,
    /// Shut down and forget a VM.
    StopVm {
        /// VM identifier from `create_vm`.
        vm_id: String,
    },
    /// Delete a **named persistent** data disk's image .
    ///
    /// The only way a data disk's data goes away: `stop_vm` deliberately
    /// retains it. Fails loudly when the image does not exist, or when
    /// a live VM still has it attached — unlinking a disk out from under
    /// a running guest is CHALLENGES #63's bug with a new name.
    DeleteDataDisk {
        /// Persistent identity given in `VmConfig.data_disks`.
        id: String,
    },
    /// Resolve a sandbox to its live VM.
    LookupSandbox {
        /// CRI sandbox identity given to `create_vm`.
        sandbox_id: String,
    },
    /// Like `lookup_sandbox`, but additionally verifies the guest
    /// agent still answers over vsock before handing the VM back to a
    /// respawned shim. A dead/unresponsive VM is torn down and its
    /// record removed; a stale on-disk record (VM died with a previous
    /// daemon) is garbage-collected. Both cases return `error`.
    ReattachSandbox {
        /// CRI sandbox identity given to `create_vm`.
        sandbox_id: String,
    },
    /// Warm-fork a daemon-owned VM into a new daemon-owned VM.
    /// The first fork of a VM prepares it as a fork
    /// source — a share-less source is swapped for a restored copy on
    /// the **same vsock CID** (the pod's shim caches
    /// the CID), echoed back as `source_guest_cid`. Live agent
    /// connections to the source still die (fresh vsock backend);
    /// clients redial the same CID.
    ForkVm {
        /// Source VM identifier from `create_vm`.
        vm_id: String,
        /// CRI sandbox identity of the FORK pod, when the
        /// fork backs a kubectl pod (`fork-source-*` annotations).
        /// The fork is then registered + persisted like a
        /// `create_vm`-born sandbox VM, so `lookup_sandbox` /
        /// `reattach_sandbox` (and `k7 pause` on the fork) work.
        #[serde(default)]
        sandbox_id: Option<String>,
        /// Child dilation factor . `None` inherits the
        /// source's (inc9). `0` is a loud error.
        #[serde(default)]
        dilation: Option<u32>,
    },
    /// Pause a VM (`k7 pause` for the k7d backend):
    /// vCPU threads are stopped and joined and device workers parked;
    /// guest memory, devices, and the vsock CID are all retained.
    /// Idempotent — pausing an already-paused VM is `Ok`.
    PauseVm {
        /// VM identifier from `create_vm`.
        vm_id: String,
    },
    /// Resume a paused VM: the vCPU run loop restarts on the same
    /// guest memory and vsock CID. A CFS-capped VM's fresh vCPU
    /// threads are re-attached to its CPU cgroup (same invariant as
    /// the fork-source prepare swap). Idempotent.
    ResumeVm {
        /// VM identifier from `create_vm`.
        vm_id: String,
    },
    /// Advance the guest-visible clock of every VM on one cluster
    /// bridge by the same delta , so the guests' backoffs,
    /// probe periods and lease TTLs behave as if `delta_ms` had passed.
    ///
    /// The whole cluster is paused for the write and resumed after it:
    /// a uniform jump is what etcd heartbeats, lease TTLs and TLS skew
    /// checks tolerate, a skewed one is not. Forward-only — the field is
    /// unsigned and `0` is a loud error, never a no-op.
    ///
    /// Caller contract: no guest action may be in flight. An agent
    /// `exec` running across the warp sees its guest's clock jump
    /// mid-syscall; the caller (gym, test) gates warps on quiescence.
    WarpClock {
        /// Cluster bridge identity given to `create_vm` as
        /// [`NetConfig::cluster_id`]. Every live VM on it is warped.
        cluster_id: String,
        /// Forward jump in milliseconds. Must be > 0.
        delta_ms: u64,
    },
    /// Change the continuous dilation factor of every VM on one cluster
    /// bridge , so a cluster that is running out of CPU
    /// can be slowed back down without being restarted.
    ///
    /// The whole cluster is paused for the write and resumed after it,
    /// and every member gets the *same* factor: an offset skew is
    /// bounded, a rate skew is not. The kernel refuses the change while
    /// any vCPU is runnable, which is why the pause is not optional.
    ///
    /// Lowering the factor is not a rewind — the guests keep every
    /// nanosecond they have already been given (CHALLENGES #191); they
    /// only stop accumulating them so fast. Raising is the same write
    /// in the other direction, not a rewind either. `DilationPolicy`
    /// never asks for a raise; `TrackingPolicy` does. The op itself
    /// does not pick.
    SetDilation {
        /// Cluster bridge identity given to `create_vm` as
        /// [`NetConfig::cluster_id`], or a `ClusterSnapshotTree` node
        /// (`{tree_id}-{node_id}`, or `tree_id` for its root —
        /// CHALLENGES #193). Every live VM on it changes rate.
        cluster_id: String,
        /// Guest nanoseconds per wall nanosecond, 1..=64. 1 is stock.
        /// Needs the carried patch in `utils/kvm-dilation` above 1.
        factor: u32,
    },
    /// Start, switch or stop the auto-warp policy loop on one cluster
    /// : instead of being told "+90 s", the daemon
    /// watches the cluster and deletes its idle wall time itself.
    ///
    /// Idempotent in the sense that matters: setting a mode replaces
    /// whatever loop was running, and `off` stops it. The reply always
    /// carries the counters, so `AutoWarp { mode: off }` is also how a
    /// caller collects a finished run's accounting.
    AutoWarp {
        /// Cluster bridge identity given to `create_vm` as
        /// [`NetConfig::cluster_id`]. Every live VM on it takes part.
        cluster_id: String,
        /// `off`, `jump` or `micro`.
        mode: crate::autowarp::AutoWarpMode,
    },
    /// Read one cluster's auto-warp counters without changing its mode.
    AutoWarpStatus {
        /// Cluster to report on.
        cluster_id: String,
    },
    /// Take or release the auto-warp hold on a cluster — the explicit
    /// form of the referenced work's fifth safety check.
    ///
    /// Daemon ops need no hold: they all run under the VM registry
    /// lock, which the policy loop takes for the whole of each cycle,
    /// so no op can be in flight inside one. A caller driving a member
    /// from *outside* the daemon — a gym `exec` straight over vsock —
    /// is invisible to that lock and must say so, or its guest sees the
    /// clock jump mid-syscall.
    AutoWarpHold {
        /// Cluster to hold.
        cluster_id: String,
        /// Who is holding, so a leaked hold names its owner. Releasing
        /// a hold nobody took is an error, not a silent no-op.
        holder: String,
        /// `true` to take, `false` to release.
        hold: bool,
    },
    /// Root a single-VM snapshot tree at a freshly booted VM.
    TreeCreate {
        /// Root VM parameters. `network` must be `None` — daemon-managed
        /// bridges are per-pod; networked trees are cluster trees.
        config: VmConfig,
        /// Resource budget; [`default_tree_budget`] when omitted.
        #[serde(default)]
        budget: Option<TreeBudget>,
        /// Caller-supplied tree identity; generated when omitted.
        #[serde(default)]
        tree_id: Option<String>,
    },
    /// Root a cluster snapshot tree: `vm_count` members on a
    /// tree-owned bridge, forked/suspended/resumed as one unit.
    TreeCreateCluster {
        /// Number of member VMs (≥ 1).
        vm_count: u32,
        /// Per-member VM parameters. `network` must be `None` — the
        /// tree creates and owns its own `ClusterNetwork`.
        config: VmConfig,
        /// Resource budget; [`default_tree_budget`] when omitted.
        #[serde(default)]
        budget: Option<TreeBudget>,
        /// Caller-supplied tree identity; generated when omitted.
        #[serde(default)]
        tree_id: Option<String>,
        /// Egress posture for the tree's bridges .
        /// Omitted = `Open` (the product default); forks inherit it.
        /// RoCEv2/Soft-RoCE note: RDMA leaving the tree is UDP/4791 —
        /// a `whitelist` policy that needs it must name port 4791.
        #[serde(default)]
        egress: Option<crate::netjail::EgressPolicy>,
    },
    /// Adopt live daemon-owned sandbox VMs + their shared
    /// [`ClusterNetwork`] as a [`ClusterSnapshotTree`] root.
    /// The VMs must already share one cluster bridge (same
    /// `cluster_id`, distinct `vm_index`s covering `0..N-1`). On
    /// success they leave the sandbox VM registry and become
    /// tree-owned; `ClusterSnapshotTree::new_cluster` then
    /// `prepare_fork_source_in`s every member. For share-less VMs that
    /// swap replaces the member's vsock CID; virtiofs-backed VMs keep
    /// running in place (CID unchanged — see
    /// `Vm::prepare_fork_source_in`). Either way the response's
    /// `TreeCreated.guest_cids` carries the current CIDs.
    /// Fails loud on any half-wired state — missing VM, mixed
    /// bridges, non-contiguous indices, bridge refcount mismatch,
    /// already tree-owned. Validation failures put the VMs back in
    /// the registry untouched; a failure *after* extraction (snapshot
    /// or agent verification) tears the VMs and bridge down — no
    /// half-adopted state survives.
    TreeAdoptCluster {
        /// Daemon VM identifiers to adopt, in any order (sorted by
        /// `vm_index` internally).
        vm_ids: Vec<String>,
        /// Resource budget; [`default_tree_budget`] when omitted.
        #[serde(default)]
        budget: Option<TreeBudget>,
        /// Caller-supplied tree identity; generated when omitted.
        #[serde(default)]
        tree_id: Option<String>,
        /// Egress posture applied to the adopted bridge .
        /// Omitted keeps the bridge's current posture (sandbox bridges
        /// are born `Open`); forks inherit whatever is set here.
        #[serde(default)]
        egress: Option<crate::netjail::EgressPolicy>,
    },
    /// Fork a new branch from a live or suspended tree node.
    TreeFork {
        /// Tree identifier from `tree_create*`.
        tree_id: String,
        /// Node to fork from.
        source_id: String,
        /// Human label for the new branch (also seeds its node id).
        label: String,
        /// Child dilation factor . `None` inherits the
        /// source's (inc9). A cluster applies one factor to every
        /// member. `0` is a loud error.
        #[serde(default)]
        dilation: Option<u32>,
    },
    /// Fork N branches from the same source in one call.
    /// Single-VM trees share one dirty-bitmap capture; cluster trees
    /// run sequential warm forks (each gets its own bridge).
    TreeForkBatch {
        /// Tree identifier.
        tree_id: String,
        /// Node to fork from.
        source_id: String,
        /// One human label per new branch (also seeds each node id).
        /// Empty is a loud error — never a silent no-op.
        labels: Vec<String>,
        /// One child factor for every branch in the batch
        /// . `None` inherits the source's.
        #[serde(default)]
        dilation: Option<u32>,
    },
    /// Snapshot a live tree node so it can be a warm-fork source.
    ///
    /// Root nodes are prepared at `tree_create*`. Children from
    /// `tree_fork*` are not. `tree_fork` / `tree_fork_batch` will call
    /// this on demand; the explicit op exists so a controller can show
    /// the checkpoint as its own (slow) step. Idempotent.
    TreePrepareForkSource {
        /// Tree identifier.
        tree_id: String,
        /// Live (or suspended — resumed first) node to checkpoint.
        node_id: String,
    },
    /// Non-destructive rollback: create a new branch from `node_id`'s
    /// state. Semantically equivalent to `tree_fork`.
    TreeRollback {
        /// Tree identifier.
        tree_id: String,
        /// Node whose state becomes the new branch's root.
        node_id: String,
        /// Human label for the new branch.
        label: String,
    },
    /// Mark a node protected from auto-eviction.
    TreeProtect {
        /// Tree identifier.
        tree_id: String,
        /// Node to protect.
        node_id: String,
    },
    /// Clear eviction protection on a node.
    TreeUnprotect {
        /// Tree identifier.
        tree_id: String,
        /// Node to unprotect.
        node_id: String,
    },
    /// Suspend a live node: delta written to disk, RAM freed.
    TreeSuspend {
        /// Tree identifier.
        tree_id: String,
        /// Node to suspend.
        node_id: String,
    },
    /// Resume a suspended node. Members get **fresh vsock CIDs** —
    /// returned in the response.
    TreeResume {
        /// Tree identifier.
        tree_id: String,
        /// Node to resume.
        node_id: String,
    },
    /// Delete a node and its whole subtree (disk included).
    TreePrune {
        /// Tree identifier.
        tree_id: String,
        /// Root of the subtree to delete.
        node_id: String,
    },
    /// Run budget-driven LRU eviction now.
    TreeAutoEvict {
        /// Tree identifier.
        tree_id: String,
    },
    /// List all nodes of a tree with their metadata.
    TreeNodes {
        /// Tree identifier.
        tree_id: String,
    },
    /// List all trees the daemon owns.
    TreeList,
    /// Subscribe this connection to tree mutations. The first response
    /// is [`Response::TreeWatching`]; further lines are
    /// [`Response::TreeEvent`] until the client hangs up. `tree_id`
    /// omitted watches every tree. After this op the connection is
    /// event-only — do not send more requests on it.
    TreeWatch {
        /// Restrict to one tree; omitted / `null` = all trees.
        #[serde(default)]
        tree_id: Option<String>,
    },
    /// Forget a tree: live payloads are torn down, on-disk state under
    /// the tree's directory is kept (re-openable later).
    TreeDrop {
        /// Tree identifier.
        tree_id: String,
    },
    /// Re-open an on-disk cluster tree left by `tree_drop` or a daemon
    /// crash . Nodes come back [`crate::tree::NodeState::Suspended`]
    /// — live KVM is not resurrected. Fails loud if `tree.json` is
    /// missing, unparseable, or the id is already in memory.
    TreeOpen {
        /// On-disk tree identity: `{tree_root_dir()}/{tree_id}/tree.json`.
        tree_id: String,
    },
    /// Report warm-pool sizing and hit/miss counters. Always
    /// answers, even with the pool disabled
    /// (`size: 0`).
    PoolStatus,
    /// Host readiness: `/dev/kvm`, `/dev/vhost-vsock`, `/dev/net/tun`,
    /// cgroup v2. Same checks as `k7d doctor`. Does not create VMs.
    Doctor,
}

/// One branch produced by [`Request::TreeForkBatch`].
#[derive(Debug, Serialize, Deserialize)]
pub struct TreeForkedBranch {
    /// The new branch's node id.
    pub node_id: String,
    /// Guest vsock CIDs of the new branch's members.
    pub guest_cids: Vec<u64>,
    /// Per-member `CoW` vs full-copy flag (see [`Response::TreeForked`]).
    #[serde(default)]
    pub fork_memory_full_copy: Vec<bool>,
    /// Wall time of the whole batch (same value on every branch).
    /// Per-branch work is not timed separately — the batch is one
    /// dirty-bitmap capture.
    #[serde(default)]
    pub latency_ns: u64,
    /// Child dilation factor after the fork .
    #[serde(default = "default_dilation_one")]
    pub dilation: u32,
}

/// Summary of one VM in a `list_vms` response.
#[derive(Debug, Serialize, Deserialize)]
pub struct VmInfo {
    /// VM identifier.
    pub vm_id: String,
    /// Guest vsock CID.
    pub guest_cid: u64,
    /// Lifecycle state (currently always `running` while present).
    pub state: String,
    /// Caller-supplied sandbox identity, if any.
    pub sandbox_id: Option<String>,
}

/// A control-plane response.
#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum Response {
    /// Reply to `ping`.
    Pong {
        /// Daemon version.
        version: String,
    },
    /// Reply to `create_vm`.
    VmCreated {
        /// New VM identifier.
        vm_id: String,
        /// Guest vsock CID clients connect to.
        guest_cid: u64,
        /// `vm_index` allocated on the cluster bridge (`None` when the
        /// VM has no network). Determines the guest IP
        /// `10.200.0.{2 + vm_index}`.
        #[serde(default)]
        vm_index: Option<u32>,
        /// Whether the TAP was successfully attached to the requested
        /// CNI pod netns. `false` means host-bridge fallback (or no
        /// netns was requested) — the client must not configure the
        /// in-netns gateway route in the guest.
        #[serde(default)]
        pod_netns_attached: bool,
        /// Whether this VM was served from the warm pool instead
        /// of cold-booted. Loud so tests can
        /// assert the fast path was taken rather than inferring it
        /// from timing.
        #[serde(default)]
        pooled: bool,
    },
    /// Reply to `vm_status`.
    VmState {
        /// VM identifier.
        vm_id: String,
        /// Lifecycle state.
        state: String,
        /// Guest vsock CID.
        guest_cid: u64,
        /// Number of virtiofs shares attached (the
        /// block-path suites assert this is 0 for normal pods and
        /// non-zero exactly when the shim fell back to virtiofs).
        #[serde(default)]
        virtiofs_shares: usize,
        /// Number of virtio-blk devices attached.
        #[serde(default)]
        block_devices: usize,
        /// Whether this VM's memory is a full memfd copy of its fork
        /// source rather than `CoW` `MAP_PRIVATE` (always `false` for
        /// cold boots; the fork-path invariant probe).
        #[serde(default)]
        fork_memory_full_copy: bool,
        /// The guest kernel this VM actually booted. Reported so
        /// "which guest is this VM running" is a question the socket
        /// answers, and so the suite can assert that nobody but the
        /// daemon chose it (CHALLENGES #72).
        #[serde(default)]
        kernel: String,
    },
    /// Reply to `list_vms`.
    VmList {
        /// One entry per VM.
        vms: Vec<VmInfo>,
    },
    /// Reply to `dump_serial`.
    SerialDump {
        /// VM identifier. Tree members use `{tree_id}/{node_id}`
        /// (they carry no daemon-registry `vm_id`).
        vm_id: String,
        /// Guest vsock CID of the VM whose console was dumped.
        #[serde(default)]
        guest_cid: u64,
        /// Everything the guest has written to its console so far
        /// (lossy UTF-8).
        console: String,
    },
    /// Reply to `lookup_sandbox` / `reattach_sandbox`.
    SandboxFound {
        /// Daemon-side VM identifier.
        vm_id: String,
        /// Guest vsock CID the agent answers on.
        guest_cid: u64,
        /// Guest vCPU count. Defaults to 1 for older peers.
        #[serde(default = "default_vcpus")]
        vcpus: u32,
        /// `vm_index` on the cluster bridge, when networked.
        #[serde(default)]
        vm_index: Option<u32>,
        /// Cluster bridge identity, when networked.
        #[serde(default)]
        cluster_id: Option<String>,
        /// Whether the VM's TAP sits inside the CNI pod netns.
        #[serde(default)]
        pod_netns_attached: bool,
    },
    /// Reply to `fork_vm`.
    VmForked {
        /// New VM identifier.
        vm_id: String,
        /// The fork's guest vsock CID.
        guest_cid: u64,
        /// The source's guest vsock CID. Preserved across the first
        /// fork's prepare swap — echoed back so
        /// clients can assert it, not because it changes.
        source_guest_cid: u64,
        /// Child dilation factor after the fork .
        #[serde(default = "default_dilation_one")]
        dilation: u32,
    },
    /// Reply to `tree_create` / `tree_create_cluster` / `tree_adopt_cluster`.
    TreeCreated {
        /// Tree identifier.
        tree_id: String,
        /// Root node id (always `"root"` today).
        root_id: String,
        /// Guest vsock CIDs of the root payload's members, ordered by
        /// `vm_index` (one entry for a single-VM tree).
        guest_cids: Vec<u64>,
    },
    /// Reply to `tree_fork` / `tree_rollback`.
    TreeForked {
        /// The new branch's node id.
        node_id: String,
        /// Guest vsock CIDs of the new branch's members.
        guest_cids: Vec<u64>,
        /// Per-member (same order as `guest_cids`): whether the fork's
        /// memory is a full memfd copy rather than `CoW` `MAP_PRIVATE`
        /// (block-path cluster forks must be all-false;
        /// only virtiofs-backed sources full-copy).
        #[serde(default)]
        fork_memory_full_copy: Vec<bool>,
        /// Host wall time of the fork/rollback (control-plane
        /// measurement; not stored in `tree.json`).
        #[serde(default)]
        latency_ns: u64,
        /// Child dilation factor after the fork .
        #[serde(default = "default_dilation_one")]
        dilation: u32,
    },
    /// Reply to `tree_fork_batch`.
    TreeForkBatch {
        /// One entry per requested label, in the same order.
        forks: Vec<TreeForkedBranch>,
        /// Host wall time of the whole batch (one dirty-bitmap
        /// capture + N forks). Same value is copied onto each
        /// [`TreeForkedBranch::latency_ns`].
        #[serde(default)]
        latency_ns: u64,
    },
    /// Reply to `tree_prepare_fork_source`.
    TreePrepared {
        /// Node that is now a warm-fork source.
        node_id: String,
        /// `true` when this call wrote a new base snapshot. `false` when
        /// the node was already prepared (idempotent no-op).
        wrote_base: bool,
        /// `true` when the keyframe was written **incrementally** —
        /// `FICLONE` of the nearest ancestor's `memory.bin` plus this
        /// node's dirty pages , costing O(divergence) instead
        /// of O(guest RAM). `false` for a root, a virtiofs payload, an
        /// idempotent no-op, or a loud fallback to the full dump because
        /// the tree root is not on a reflink filesystem.
        #[serde(default)]
        wrote_base_incremental: bool,
        /// Physical bytes the keyframe added to the filesystem — the
        /// dirty set on the incremental path, the whole guest span on
        /// the full one. The daemon reports it because nothing on the
        /// host can measure it afterwards: a reflinked file's `stat`
        /// reports its logical length and `st_blocks` counts extents it
        /// only shares (CHALLENGES #152).
        #[serde(default)]
        base_disk_bytes: u64,
        /// Host wall time of the prepare (includes snapshot + restore
        /// when `wrote_base` is true).
        latency_ns: u64,
        /// Guest vsock CIDs after prepare (CID is preserved).
        guest_cids: Vec<u64>,
    },
    /// Reply to `warp_clock`.
    Warped {
        /// Cluster whose VMs moved.
        cluster_id: String,
        /// The VMs that were warped, in `vm_index` order. All of them
        /// or none — a warp that fails on one member rolls that member
        /// back and errors.
        vm_ids: Vec<String>,
        /// The delta every guest's clock advanced by.
        delta_ms: u64,
        /// Daemon-side wall time of pause-all → warp-all → resume-all
        /// .
        latency_ns: u64,
    },
    /// Reply to `set_dilation`.
    DilationSet {
        /// Cluster whose members changed rate.
        cluster_id: String,
        /// The VMs that were switched, in `vm_index` order. All of them
        /// or none — a member that refuses the factor puts the ones
        /// already switched back before the error is returned. Members
        /// owned by a `ClusterSnapshotTree` have no registry VM id and
        /// are reported positionally as `{cluster_id}#{index}`.
        vm_ids: Vec<String>,
        /// The factor every member now runs at.
        factor: u32,
        /// Daemon-side wall time of pause-all → set-all → resume-all.
        latency_ns: u64,
    },
    /// Reply to `auto_warp`, `auto_warp_status` and `auto_warp_hold`.
    AutoWarp {
        /// Cluster the counters belong to.
        cluster_id: String,
        /// Mode now in force.
        mode: crate::autowarp::AutoWarpMode,
        /// Holders currently blocking the loop, in name order.
        holders: Vec<String>,
        /// Host-time counters of the loop (of the *last* loop, when
        /// `mode` is `off`). All zero for a cluster that never ran one.
        stats: crate::autowarp::AutoWarpStats,
    },
    /// Reply to `tree_resume`.
    TreeResumed {
        /// The resumed node id.
        node_id: String,
        /// Fresh guest vsock CIDs of the resumed members.
        guest_cids: Vec<u64>,
    },
    /// Reply to `tree_open`.
    TreeOpened {
        /// Tree identifier.
        tree_id: String,
        /// Root node id (always `"root"` today).
        root_id: String,
        /// Every node's metadata. `open()` forces previously-Live nodes
        /// to Suspended — the caller must `tree_resume` to go live.
        nodes: Vec<NodeInfo>,
    },
    /// Reply to `tree_auto_evict`.
    TreeEvicted {
        /// Node ids that were evicted (may be empty).
        evicted: Vec<String>,
    },
    /// Reply to `tree_nodes`.
    TreeNodeList {
        /// Every node's metadata.
        nodes: Vec<NodeInfo>,
        /// Current resource usage (orchestrator-side; not Lean).
        #[serde(default)]
        usage: TreeUsageInfo,
        /// Resource budget.
        #[serde(default = "default_tree_budget")]
        budget: TreeBudget,
        /// Live vsock CIDs keyed by node id. Empty vec = no live
        /// payload. Not persisted in `tree.json`.
        #[serde(default)]
        live_guest_cids: HashMap<String, Vec<u64>>,
        /// Time dilation factor of each live node (the referenced work; a
        /// cluster's members all share one). Absent for nodes with no
        /// live payload. The gym reads this to check a reused source
        /// tree runs at the factor its config promises.
        #[serde(default)]
        live_dilation: HashMap<String, u32>,
    },
    /// Reply to `tree_list`.
    TreeList {
        /// One summary per tree.
        trees: Vec<TreeSummary>,
    },
    /// First reply to `tree_watch` — current snapshot(s). Further
    /// lines on the same connection are [`Response::TreeEvent`].
    TreeWatching {
        /// One snapshot per matched tree (empty if the daemon owns
        /// none and the watch was unscoped).
        trees: Vec<TreeWatchSnapshot>,
    },
    /// Streamed tree mutation (after [`Response::TreeWatching`]).
    TreeEvent {
        /// Tree that changed.
        tree_id: String,
        /// See [`TreeEvent::op`].
        op: String,
        /// Node the op targeted or produced.
        #[serde(default)]
        node_id: Option<String>,
        /// Fork/rollback/batch wall time, when measured.
        #[serde(default)]
        latency_ns: Option<u64>,
    },
    /// Reply to `pool_status`.
    PoolStatus {
        /// Configured target of idle warm VMs (0 = pool disabled).
        size: usize,
        /// Idle agent-ready VMs currently acquirable.
        idle: usize,
        /// `create_vm` requests served from the pool.
        hits: u64,
        /// Pool-enabled `create_vm` requests not served from the pool.
        misses: u64,
    },
    /// Reply to `doctor`.
    Doctor {
        /// `/dev/kvm` is a character device.
        kvm: bool,
        /// `/dev/vhost-vsock` is a character device.
        vhost_vsock: bool,
        /// `/dev/net/tun` is a character device.
        tun: bool,
        /// Host is on the cgroup v2 unified hierarchy.
        cgroup_v2: bool,
        /// All four checks passed.
        ok: bool,
        /// One line per check (`ok`/`FAIL` + name + detail).
        details: Vec<String>,
    },
    /// Generic success (e.g. `stop_vm`).
    Ok,
    /// Any failure. Never silently swallowed.
    Error {
        /// Human-readable failure detail.
        message: String,
    },
}

/// Summary of one tree in a `tree_list` response.
#[derive(Debug, Serialize, Deserialize)]
pub struct TreeSummary {
    /// Tree identifier.
    pub tree_id: String,
    /// `"vm"` or `"cluster"`.
    pub kind: String,
    /// Total node count (live + suspended + evicted).
    pub nodes: usize,
    /// Current resource usage.
    #[serde(default)]
    pub usage: TreeUsageInfo,
    /// Resource budget.
    #[serde(default = "default_tree_budget")]
    pub budget: TreeBudget,
}

/// One VM owned by the daemon. The `vm` field is load-bearing even
/// though the control plane never reads it back yet: holding the `Vm`
/// keeps the guest alive, and dropping the entry (on `stop_vm` /
/// `shutdown_all`) runs `Vm::drop`, which tears down the vCPU thread,
/// device workers, virtiofsd children, and TAP. The fork, snapshot
/// and tree paths read it.
struct VmEntry {
    #[allow(dead_code)]
    vm: Vm,
    /// The threaded CPU cgroup capping this VM's vCPU
    /// threads at the pod's CFS quota. Held only for its `Drop`
    /// (like `vm`): declared AFTER `vm` — struct fields drop in
    /// declaration order, so the vCPU thread is joined (by
    /// `Vm::drop`) before the cgroup directory is removed.
    #[allow(dead_code)]
    cpu_cgroup: Option<crate::cgroup::VmCpuCgroup>,
    /// Create-time CFS quota (µs). Carried so `fork_vm` can re-apply
    /// the same host cap to the child's vCPU threads.
    cpu_quota: Option<u64>,
    /// Create-time CFS period (µs) paired with `cpu_quota`.
    cpu_period: Option<u64>,
    guest_cid: u64,
    sandbox_id: Option<String>,
    /// Cluster bridge this VM holds a reference on (`None` = no network).
    cluster_id: Option<String>,
    /// `vm_index` allocated on the cluster bridge.
    vm_index: Option<u32>,
    /// Pod netns the TAP was attached into, when the CNI attach
    /// succeeded. Detached (best-effort) on stop.
    pod_netns: Option<PathBuf>,
}

/// A shared cluster bridge plus the number of live VMs using it.
/// Dropping the entry runs `ClusterNetwork::drop`, which destroys the
/// bridge and its iptables rules — so removal must only happen when
/// `refcount` reaches zero.
struct BridgeEntry {
    net: ClusterNetwork,
    refcount: usize,
}

/// Result of attaching a new VM to the node network.
struct NetAttachment {
    tap: TapDevice,
    vm_index: u32,
    /// Set only when the pod-netns attach succeeded.
    pod_netns: Option<PathBuf>,
}

/// What `build_and_start` hands back for the `vm_created` response.
struct CreatedVm {
    vm_id: String,
    guest_cid: u64,
    vm_index: Option<u32>,
    pod_netns_attached: bool,
}

/// One snapshot tree owned by the daemon — single-VM or
/// cluster. Both expose the same lifecycle verbs; the enum
/// keeps one registry and one set of control-plane handlers.
enum TreePayload {
    Single(SnapshotTree),
    Cluster(ClusterSnapshotTree),
}

impl TreePayload {
    fn live_cluster_members_mut(&mut self, node_id: &str) -> Option<&mut [crate::vm::Vm]> {
        match self {
            Self::Cluster(t) => t.live_members_mut(node_id),
            Self::Single(_) => None,
        }
    }

    fn fork(
        &mut self,
        source_id: &String,
        label: &str,
        dilation: Option<u32>,
    ) -> Result<String, String> {
        match self {
            Self::Single(t) => t.fork_batch(source_id, &[label], dilation),
            Self::Cluster(t) => t.fork_batch(source_id, &[label], dilation),
        }
        .map(|ids| ids.into_iter().next().expect("single fork"))
        .map_err(|e| format!("tree fork({source_id}, {label}): {e}"))
    }

    fn fork_batch(
        &mut self,
        source_id: &String,
        labels: &[String],
        dilation: Option<u32>,
    ) -> Result<Vec<String>, String> {
        if labels.is_empty() {
            return Err("tree_fork_batch: labels must be non-empty".to_string());
        }
        let refs: Vec<&str> = labels.iter().map(String::as_str).collect();
        match self {
            Self::Single(t) => t.fork_batch(source_id, &refs, dilation),
            Self::Cluster(t) => t.fork_batch(source_id, &refs, dilation),
        }
        .map_err(|e| format!("tree fork_batch({source_id}, {labels:?}): {e}"))
    }

    fn prepare_fork_source(
        &mut self,
        node_id: &String,
    ) -> Result<crate::tree::PrepareOutcome, String> {
        match self {
            Self::Single(t) => t.prepare_fork_source(node_id),
            Self::Cluster(t) => t.prepare_fork_source(node_id),
        }
        .map_err(|e| format!("tree prepare_fork_source({node_id}): {e}"))
    }

    /// Find a live VM by guest CID (debug introspection for
    /// `dump_serial` — tree members carry no daemon `vm_id`).
    fn find_live_vm_by_cid(&self, cid: u64) -> Option<(&str, &Vm)> {
        match self {
            Self::Single(t) => t.find_live_vm_by_cid(cid),
            Self::Cluster(t) => t.find_live_vm_by_cid(cid),
        }
    }

    fn rollback(&mut self, node_id: &String, label: &str) -> Result<String, String> {
        match self {
            Self::Single(t) => t.rollback(node_id, label),
            Self::Cluster(t) => t.rollback(node_id, label),
        }
        .map_err(|e| format!("tree rollback({node_id}, {label}): {e}"))
    }

    fn protect(&mut self, node_id: &String) -> Result<(), String> {
        // Loud if the node is unknown — silent no-op would let a typo
        // leave the "winner" unprotected under budget pressure.
        let known = self.list_nodes().iter().any(|n| n.id == *node_id);
        if !known {
            return Err(format!("tree protect({node_id}): no such node"));
        }
        match self {
            Self::Single(t) => t.protect(node_id),
            Self::Cluster(t) => t.protect(node_id),
        }
        Ok(())
    }

    fn unprotect(&mut self, node_id: &String) -> Result<(), String> {
        let known = self.list_nodes().iter().any(|n| n.id == *node_id);
        if !known {
            return Err(format!("tree unprotect({node_id}): no such node"));
        }
        match self {
            Self::Single(t) => t.unprotect(node_id),
            Self::Cluster(t) => t.unprotect(node_id),
        }
        Ok(())
    }

    fn suspend(&mut self, node_id: &String) -> Result<(), String> {
        match self {
            Self::Single(t) => t.suspend(node_id),
            Self::Cluster(t) => t.suspend(node_id),
        }
        .map_err(|e| format!("tree suspend({node_id}): {e}"))
    }

    fn resume(&mut self, node_id: &String) -> Result<(), String> {
        match self {
            Self::Single(t) => t.resume(node_id),
            Self::Cluster(t) => t.resume(node_id),
        }
        .map_err(|e| format!("tree resume({node_id}): {e}"))
    }

    fn prune(&mut self, node_id: &String) -> Result<(), String> {
        match self {
            Self::Single(t) => t.prune(node_id),
            Self::Cluster(t) => t.prune(node_id),
        }
        .map_err(|e| format!("tree prune({node_id}): {e}"))
    }

    fn auto_evict(&mut self) -> Result<Vec<String>, String> {
        match self {
            Self::Single(t) => t.auto_evict(),
            Self::Cluster(t) => t.auto_evict(),
        }
        .map_err(|e| format!("tree auto_evict: {e}"))
    }

    fn list_nodes(&self) -> Vec<NodeInfo> {
        match self {
            Self::Single(t) => t.list_nodes().into_iter().cloned().collect(),
            Self::Cluster(t) => t.list_nodes().into_iter().cloned().collect(),
        }
    }

    /// Guest vsock CIDs of a node's live members, ordered by member
    /// index. Empty when the node has no live payload.
    fn node_cids(&self, node_id: &String) -> Vec<u64> {
        match self {
            Self::Single(t) => t
                .get_vm(node_id)
                .map(|vm| vec![vm.guest_cid()])
                .unwrap_or_default(),
            Self::Cluster(t) => t
                .get_payload(node_id)
                .map(|p| p.members.iter().map(Vm::guest_cid).collect())
                .unwrap_or_default(),
        }
    }

    /// Time dilation factor of a node's live payload; `None` when it has
    /// none. A cluster's members are built from one `VmConfig` and
    /// forked from one state, so the first member speaks for all.
    fn node_dilation(&self, node_id: &String) -> Option<u32> {
        match self {
            Self::Single(t) => t.get_vm(node_id).map(Vm::dilation),
            Self::Cluster(t) => t
                .get_payload(node_id)
                .and_then(|p| p.members.first().map(Vm::dilation)),
        }
    }

    /// Per-member `fork_memory_is_full_copy` of a node's live members,
    /// ordered like [`Self::node_cids`]. Empty when the node has no
    /// live payload.
    fn node_fork_full_copy(&self, node_id: &String) -> Vec<bool> {
        match self {
            Self::Single(t) => t
                .get_vm(node_id)
                .map(|vm| vec![vm.fork_memory_is_full_copy()])
                .unwrap_or_default(),
            Self::Cluster(t) => t
                .get_payload(node_id)
                .map(|p| p.members.iter().map(Vm::fork_memory_is_full_copy).collect())
                .unwrap_or_default(),
        }
    }

    fn kind(&self) -> &'static str {
        match self {
            Self::Single(_) => "vm",
            Self::Cluster(_) => "cluster",
        }
    }

    fn usage(&self) -> TreeUsage {
        match self {
            Self::Single(t) => t.usage(),
            Self::Cluster(t) => t.usage(),
        }
    }

    fn budget(&self) -> TreeBudget {
        match self {
            Self::Single(t) => t.budget(),
            Self::Cluster(t) => t.budget(),
        }
    }

    /// Live guest CIDs keyed by node id. Suspended/evicted nodes map to
    /// an empty vec — the observer must not keep a stale CID.
    fn live_guest_cids(&self) -> HashMap<String, Vec<u64>> {
        self.list_nodes()
            .into_iter()
            .map(|n| (n.id.clone(), self.node_cids(&n.id)))
            .collect()
    }

    fn node_list_response(&self) -> Response {
        let nodes = self.list_nodes();
        let live_dilation = nodes
            .iter()
            .filter_map(|n| self.node_dilation(&n.id).map(|d| (n.id.clone(), d)))
            .collect();
        Response::TreeNodeList {
            nodes,
            usage: self.usage().into(),
            budget: self.budget(),
            live_guest_cids: self.live_guest_cids(),
            live_dilation,
        }
    }

    fn watch_snapshot(&self, tree_id: String) -> TreeWatchSnapshot {
        TreeWatchSnapshot {
            tree_id,
            kind: self.kind().to_string(),
            nodes: self.list_nodes(),
            usage: self.usage().into(),
            budget: self.budget(),
            live_guest_cids: self.live_guest_cids(),
        }
    }
}

/// The daemon's VM registry and request dispatcher.
pub struct Daemon {
    /// Live VMs. `Arc` because the auto-warp policy loop (spec
    /// 34a-inc3) runs on its own thread and takes this same lock for
    /// the whole of each cycle — that lock is what makes "no daemon op
    /// is in flight against a member" true rather than hoped for.
    vms: Arc<Mutex<HashMap<String, VmEntry>>>,
    /// Shared cluster bridges keyed by `cluster_id`, refcounted across
    /// VMs (this fixes the shared-bridge teardown
    /// race where the first pod deleted destroyed its peers' bridge).
    bridges: Mutex<HashMap<String, BridgeEntry>>,
    /// Snapshot trees keyed by `tree_id`. The
    /// lock is held for the duration of each tree mutation — tree ops
    /// need `&mut` and must not interleave on the same tree.
    /// `Arc` so the auto-warp loop can see tree-owned clusters
    /// (`tree_create_cluster` / fork children are not in `vms`).
    trees: Arc<Mutex<HashMap<String, TreePayload>>>,
    /// `sandbox_id → vm_id` index for `lookup_sandbox` /
    /// `reattach_sandbox`. Mirrors the on-disk
    /// records under [`sandbox_root_dir`] so the hot path never walks
    /// the directory.
    sandboxes: Mutex<HashMap<String, String>>,
    /// Warm pool; `None` when disabled
    /// (`K7D_POOL_SIZE` unset or 0).
    pool: Option<Pool>,
    /// `tree_watch` subscribers. Dead senders are dropped on emit.
    watchers: Mutex<Vec<WatchSub>>,
    /// Auto-warp policy loops, keyed by `cluster_id` .
    auto_warps: Mutex<HashMap<String, AutoWarpLoop>>,
    /// Auto-warp holds, keyed by `cluster_id`. Read by every cycle of
    /// every loop, so it is its own lock and never nested inside
    /// `vms` — a hold must be takeable while a cycle is running.
    auto_warp_holds: Arc<Mutex<HashMap<String, BTreeSet<String>>>>,
    counter: AtomicU64,
}

/// One cluster's running auto-warp policy loop.
///
/// The counters are shared with the thread rather than owned by it, so
/// `auto_warp_status` answers while the loop runs; they outlive a
/// stopped loop so `AutoWarp { mode: off }` can report the run's
/// accounting.
struct AutoWarpLoop {
    mode: crate::autowarp::AutoWarpMode,
    stop: Arc<AtomicBool>,
    counters: Arc<crate::autowarp::AutoWarpCounters>,
    thread: Option<std::thread::JoinHandle<()>>,
}

impl AutoWarpLoop {
    /// Signal the thread and wait for the cycle in flight to finish.
    ///
    /// Joining matters: a cycle holds the VM registry lock and may have
    /// the whole cluster paused, so returning before it ends would let
    /// a `stop_vm` race a pause the loop still owns.
    fn stop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        if let Some(thread) = self.thread.take() {
            if thread.join().is_err() {
                log::error!("auto-warp: a policy loop thread panicked; its cluster may be paused");
            }
        }
        self.mode = crate::autowarp::AutoWarpMode::Off;
    }
}

/// Live tree-owned members of `cluster_id`.
///
/// Gym / `tree_create_cluster` children are `{tree_id}-{node_id}`.
/// Reset / source clusters use `cluster_id == tree_id` (the live root).
fn tree_cluster_members_mut<'a>(
    trees: &'a mut HashMap<String, TreePayload>,
    cluster_id: &str,
) -> Option<&'a mut [crate::vm::Vm]> {
    for (tid, tree) in trees.iter_mut() {
        let node_id = if cluster_id == tid.as_str() {
            "root"
        } else if let Some(rest) = cluster_id.strip_prefix(tid.as_str()) {
            match rest.strip_prefix('-') {
                Some(n) => n,
                None => continue,
            }
        } else {
            continue;
        };
        if let Some(members) = tree.live_cluster_members_mut(node_id) {
            return Some(members);
        }
    }
    None
}

impl Default for Daemon {
    fn default() -> Self {
        Self::new()
    }
}

impl Daemon {
    /// Create an empty daemon (owns no VMs yet, no pool).
    #[must_use]
    pub fn new() -> Self {
        Self::with_pool(None)
    }

    /// Create an empty daemon with a warm pool.
    /// The pool's filler thread is already running when this is called
    /// ([`Pool::start`]); the daemon takes ownership and tears it down
    /// in [`Daemon::shutdown_all`].
    #[must_use]
    pub fn with_pool(pool: Option<Pool>) -> Self {
        Self {
            vms: Arc::new(Mutex::new(HashMap::new())),
            bridges: Mutex::new(HashMap::new()),
            trees: Arc::new(Mutex::new(HashMap::new())),
            sandboxes: Mutex::new(HashMap::new()),
            pool,
            watchers: Mutex::new(Vec::new()),
            auto_warps: Mutex::new(HashMap::new()),
            auto_warp_holds: Arc::new(Mutex::new(HashMap::new())),
            counter: AtomicU64::new(0),
        }
    }

    /// Startup scan of [`sandbox_root_dir`]:
    /// every record whose `vm_id` is not in the live registry is an
    /// orphan from a previous daemon that died with its VMs — logged
    /// loudly and removed (a dead VM must not be resurrected from JSON
    /// alone; live-state daemon crash recovery is out of scope). Called
    /// once from `main` before serving; NOT from [`Daemon::new`] so
    /// in-process tests can't sweep the production records dir.
    pub fn clean_stale_sandbox_records(&self) {
        let root = sandbox_root_dir();
        let entries = match std::fs::read_dir(&root) {
            Ok(entries) => entries,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return,
            Err(e) => {
                log::error!("scan sandbox records in {}: {e}", root.display());
                return;
            }
        };
        let vms = self.vms.lock().unwrap();
        let mut index = self.sandboxes.lock().unwrap();
        for entry in entries.flatten() {
            let path = entry.path();
            if path.extension().is_none_or(|e| e != "json") {
                continue;
            }
            let record = std::fs::read_to_string(&path)
                .map_err(|e| e.to_string())
                .and_then(|s| serde_json::from_str::<SandboxRecord>(&s).map_err(|e| e.to_string()));
            match record {
                Ok(r) if vms.contains_key(&r.vm_id) => {
                    index.insert(r.sandbox_id, r.vm_id);
                }
                Ok(r) => {
                    log::error!(
                        "dropping stale sandbox record {} (vm {} died with a previous daemon)",
                        path.display(),
                        r.vm_id
                    );
                    if let Err(e) = std::fs::remove_file(&path) {
                        log::error!("remove stale record {}: {e}", path.display());
                    }
                }
                Err(e) => {
                    log::error!(
                        "unparseable sandbox record {}: {e}; removing",
                        path.display()
                    );
                    if let Err(e) = std::fs::remove_file(&path) {
                        log::error!("remove bad record {}: {e}", path.display());
                    }
                }
            }
        }
    }

    /// Startup scan of [`tree_root_dir`]: every subdirectory with a
    /// parseable `tree.json` is [`ClusterSnapshotTree::open`]'d and
    /// inserted as Suspended. Unparseable dirs are logged and left
    /// alone (the operator may be mid-write). Already-registered ids
    /// are skipped. Called from `main` after sandbox GC — **not** from
    /// [`Daemon::new`], so in-process tests do not sweep `/var/lib/k7d/trees`.
    pub fn rehydrate_trees_from_disk(&self) {
        let root = tree_root_dir();
        let entries = match std::fs::read_dir(&root) {
            Ok(entries) => entries,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return,
            Err(e) => {
                log::error!("scan trees in {}: {e}", root.display());
                return;
            }
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if !path.is_dir() {
                continue;
            }
            if !path.join("tree.json").is_file() {
                continue;
            }
            match ClusterSnapshotTree::open(path.clone()) {
                Ok(tree) => {
                    let id = tree.tree_id().to_string();
                    let n = tree.list_nodes().len();
                    let mut trees = self.trees.lock().unwrap();
                    if trees.contains_key(&id) {
                        continue;
                    }
                    log::info!(
                        "rehydrated tree {id} from {} ({n} nodes, Suspended)",
                        path.display()
                    );
                    trees.insert(id, TreePayload::Cluster(tree));
                }
                Err(e) => {
                    log::error!(
                        "unparseable tree dir {}: {e}; leaving in place",
                        path.display()
                    );
                }
            }
        }
    }

    /// Dispatch a single request to its handler.
    #[allow(clippy::too_many_lines)]
    pub fn handle(&self, req: Request) -> Response {
        match req {
            Request::Ping => Response::Pong {
                version: env!("CARGO_PKG_VERSION").to_string(),
            },
            Request::CreateVm { config } => self.create_vm(config),
            Request::VmStatus { vm_id } => self.vm_status(&vm_id),
            Request::DumpSerial { vm_id, guest_cid } => {
                self.dump_serial(vm_id.as_deref(), guest_cid)
            }
            Request::ListVms => self.list_vms(),
            Request::StopVm { vm_id } => self.stop_vm(&vm_id),
            Request::DeleteDataDisk { id } => self.delete_data_disk(&id),
            Request::LookupSandbox { sandbox_id } => self.lookup_sandbox(&sandbox_id),
            Request::ReattachSandbox { sandbox_id } => self.reattach_sandbox(&sandbox_id),
            Request::ForkVm {
                vm_id,
                sandbox_id,
                dilation,
            } => match validate_fork_dilation(dilation) {
                Ok(d) => self.fork_vm(&vm_id, sandbox_id, d),
                Err(message) => Response::Error { message },
            },
            Request::PauseVm { vm_id } => self.pause_vm(&vm_id),
            Request::ResumeVm { vm_id } => self.resume_vm(&vm_id),
            Request::WarpClock {
                cluster_id,
                delta_ms,
            } => self.warp_clock(&cluster_id, delta_ms),
            Request::SetDilation { cluster_id, factor } => self.set_dilation(&cluster_id, factor),
            Request::AutoWarp { cluster_id, mode } => self.auto_warp(&cluster_id, mode),
            Request::AutoWarpStatus { cluster_id } => self.auto_warp_status(&cluster_id),
            Request::AutoWarpHold {
                cluster_id,
                holder,
                hold,
            } => self.auto_warp_hold(&cluster_id, &holder, hold),
            Request::TreeCreate {
                config,
                budget,
                tree_id,
            } => self.tree_create(&config, budget, tree_id),
            Request::TreeCreateCluster {
                vm_count,
                config,
                budget,
                tree_id,
                egress,
            } => self.tree_create_cluster(vm_count, &config, budget, tree_id, egress),
            Request::TreeAdoptCluster {
                vm_ids,
                budget,
                tree_id,
                egress,
            } => self.tree_adopt_cluster(&vm_ids, budget, tree_id, egress),
            Request::TreeFork {
                tree_id,
                source_id,
                label,
                dilation,
            } => {
                let resp = match validate_fork_dilation(dilation) {
                    Err(message) => Response::Error { message },
                    Ok(d) => self.with_tree(&tree_id, |t| {
                        let start = Instant::now();
                        match t.fork(&source_id, &label, d) {
                            Ok(node_id) => {
                                let latency_ns =
                                    u64::try_from(start.elapsed().as_nanos()).unwrap_or(u64::MAX);
                                let guest_cids = t.node_cids(&node_id);
                                let fork_memory_full_copy = t.node_fork_full_copy(&node_id);
                                let dilation = t.node_dilation(&node_id).unwrap_or(1);
                                Response::TreeForked {
                                    node_id,
                                    guest_cids,
                                    fork_memory_full_copy,
                                    latency_ns,
                                    dilation,
                                }
                            }
                            Err(message) => Response::Error { message },
                        }
                    }),
                };
                self.emit_from_response(&tree_id, &resp);
                resp
            }
            Request::TreeForkBatch {
                tree_id,
                source_id,
                labels,
                dilation,
            } => {
                let resp = match validate_fork_dilation(dilation) {
                    Err(message) => Response::Error { message },
                    Ok(d) => self.with_tree(&tree_id, |t| {
                        let start = Instant::now();
                        match t.fork_batch(&source_id, &labels, d) {
                            Ok(node_ids) => {
                                let latency_ns =
                                    u64::try_from(start.elapsed().as_nanos()).unwrap_or(u64::MAX);
                                let forks = node_ids
                                    .into_iter()
                                    .map(|node_id| TreeForkedBranch {
                                        guest_cids: t.node_cids(&node_id),
                                        fork_memory_full_copy: t.node_fork_full_copy(&node_id),
                                        dilation: t.node_dilation(&node_id).unwrap_or(1),
                                        node_id,
                                        latency_ns,
                                    })
                                    .collect();
                                Response::TreeForkBatch { forks, latency_ns }
                            }
                            Err(message) => Response::Error { message },
                        }
                    }),
                };
                self.emit_from_response(&tree_id, &resp);
                resp
            }
            Request::TreePrepareForkSource { tree_id, node_id } => {
                let resp = self.with_tree(&tree_id, |t| {
                    let start = Instant::now();
                    match t.prepare_fork_source(&node_id) {
                        Ok(outcome) => {
                            let latency_ns =
                                u64::try_from(start.elapsed().as_nanos()).unwrap_or(u64::MAX);
                            Response::TreePrepared {
                                guest_cids: t.node_cids(&node_id),
                                latency_ns,
                                node_id: node_id.clone(),
                                wrote_base: outcome.wrote_base,
                                wrote_base_incremental: outcome.incremental,
                                base_disk_bytes: outcome.disk_bytes,
                            }
                        }
                        Err(message) => Response::Error { message },
                    }
                });
                if let Response::TreePrepared {
                    latency_ns,
                    ref node_id,
                    ..
                } = resp
                {
                    self.emit_tree_event(
                        &tree_id,
                        "prepare_fork_source",
                        Some(node_id),
                        Some(latency_ns),
                    );
                }
                resp
            }
            Request::TreeRollback {
                tree_id,
                node_id,
                label,
            } => {
                let resp = self.with_tree(&tree_id, |t| {
                    let start = Instant::now();
                    match t.rollback(&node_id, &label) {
                        Ok(node_id) => {
                            let latency_ns =
                                u64::try_from(start.elapsed().as_nanos()).unwrap_or(u64::MAX);
                            let dilation = t.node_dilation(&node_id).unwrap_or(1);
                            Response::TreeForked {
                                guest_cids: t.node_cids(&node_id),
                                fork_memory_full_copy: t.node_fork_full_copy(&node_id),
                                node_id,
                                latency_ns,
                                dilation,
                            }
                        }
                        Err(message) => Response::Error { message },
                    }
                });
                self.emit_from_response(&tree_id, &resp);
                resp
            }
            Request::TreeProtect { tree_id, node_id } => {
                let resp = self.with_tree(&tree_id, |t| match t.protect(&node_id) {
                    Ok(()) => Response::Ok,
                    Err(message) => Response::Error { message },
                });
                if matches!(resp, Response::Ok) {
                    self.emit_tree_event(&tree_id, "protect", Some(&node_id), None);
                }
                resp
            }
            Request::TreeUnprotect { tree_id, node_id } => {
                let resp = self.with_tree(&tree_id, |t| match t.unprotect(&node_id) {
                    Ok(()) => Response::Ok,
                    Err(message) => Response::Error { message },
                });
                if matches!(resp, Response::Ok) {
                    self.emit_tree_event(&tree_id, "unprotect", Some(&node_id), None);
                }
                resp
            }
            Request::TreeSuspend { tree_id, node_id } => {
                let resp = self.with_tree(&tree_id, |t| match t.suspend(&node_id) {
                    Ok(()) => Response::Ok,
                    Err(message) => Response::Error { message },
                });
                if matches!(resp, Response::Ok) {
                    self.emit_tree_event(&tree_id, "suspend", Some(&node_id), None);
                }
                resp
            }
            Request::TreeResume { tree_id, node_id } => {
                let resp = self.with_tree(&tree_id, |t| match t.resume(&node_id) {
                    Ok(()) => Response::TreeResumed {
                        guest_cids: t.node_cids(&node_id),
                        node_id: node_id.clone(),
                    },
                    Err(message) => Response::Error { message },
                });
                if matches!(resp, Response::TreeResumed { .. }) {
                    self.emit_tree_event(&tree_id, "resume", Some(&node_id), None);
                }
                resp
            }
            Request::TreePrune { tree_id, node_id } => {
                let resp = self.with_tree(&tree_id, |t| match t.prune(&node_id) {
                    Ok(()) => Response::Ok,
                    Err(message) => Response::Error { message },
                });
                if matches!(resp, Response::Ok) {
                    self.emit_tree_event(&tree_id, "prune", Some(&node_id), None);
                }
                resp
            }
            Request::TreeAutoEvict { tree_id } => {
                let resp = self.with_tree(&tree_id, |t| match t.auto_evict() {
                    Ok(evicted) => Response::TreeEvicted { evicted },
                    Err(message) => Response::Error { message },
                });
                if let Response::TreeEvicted { ref evicted } = resp {
                    for id in evicted {
                        self.emit_tree_event(&tree_id, "evict", Some(id), None);
                    }
                }
                resp
            }
            Request::TreeNodes { tree_id } => self.with_tree(&tree_id, |t| t.node_list_response()),
            Request::TreeList => self.tree_list(),
            Request::TreeWatch { tree_id } => self.watch_snapshot(tree_id.as_deref()),
            Request::TreeDrop { tree_id } => self.tree_drop(&tree_id),
            Request::TreeOpen { tree_id } => {
                let resp = self.tree_open(&tree_id);
                if matches!(resp, Response::TreeOpened { .. }) {
                    self.emit_tree_event(&tree_id, "open", None, None);
                }
                resp
            }
            Request::PoolStatus => self.pool_status(),
            Request::Doctor => {
                let report = crate::doctor::run();
                Response::Doctor {
                    kvm: report.kvm(),
                    vhost_vsock: report.vhost_vsock(),
                    tun: report.tun(),
                    cgroup_v2: report.cgroup_v2(),
                    ok: report.ok(),
                    details: report.lines(),
                }
            }
        }
    }

    fn create_vm(&self, config: VmConfig) -> Response {
        // Pool fast path. A pool-compatible
        // request is served from the warm pool when it has an idle VM;
        // a miss (incompatible or empty) cold-boots — never an error.
        if let Some(ref pool) = self.pool {
            if pool.compatible(&config) {
                if let Some(vm) = pool.acquire() {
                    let guest_cid = vm.guest_cid();
                    let vm_id = self.mint_vm_id();
                    // Pool VMs are never CPU-capped: `Pool::compatible`
                    // rejects configs carrying a `cpu_quota`.
                    return match self.register_vm(
                        vm_id,
                        vm,
                        None,
                        None,
                        None,
                        config.sandbox_id,
                        None,
                        None,
                        None,
                    ) {
                        Ok(vm_id) => {
                            log::info!("created {vm_id} from pool (guest_cid={guest_cid})");
                            Response::VmCreated {
                                vm_id,
                                guest_cid,
                                vm_index: None,
                                pod_netns_attached: false,
                                pooled: true,
                            }
                        }
                        Err(message) => Response::Error { message },
                    };
                }
            } else {
                pool.note_miss();
            }
        }
        match self.build_and_start(config) {
            Ok(created) => Response::VmCreated {
                vm_id: created.vm_id,
                guest_cid: created.guest_cid,
                vm_index: created.vm_index,
                pod_netns_attached: created.pod_netns_attached,
                pooled: false,
            },
            Err(message) => Response::Error { message },
        }
    }

    /// Reply to `pool_status`; a disabled pool answers all-zeroes
    /// rather than erroring so clients can probe unconditionally.
    fn pool_status(&self) -> Response {
        let status = self.pool.as_ref().map(Pool::status).unwrap_or_default();
        Response::PoolStatus {
            size: status.size,
            idle: status.idle,
            hits: status.hits,
            misses: status.misses,
        }
    }

    /// Join (or create) the refcounted cluster bridge for `cfg`,
    /// allocate a TAP on it, and optionally attach the TAP into the
    /// CNI pod netns. On any hard failure the bridge reference taken
    /// here is released again so a failed create never leaks a bridge.
    ///
    /// The pod-netns attach itself is best-effort (warn + host-bridge
    /// fallback), matching the historical shim behaviour: a pod
    /// without CNI plumbing still boots and is reachable via the host
    /// bridge.
    fn acquire_network(&self, cfg: &NetConfig) -> Result<NetAttachment, String> {
        let mut bridges = self.bridges.lock().unwrap();
        if !bridges.contains_key(&cfg.cluster_id) {
            let net = ClusterNetwork::create(&cfg.cluster_id)
                .map_err(|e| format!("ClusterNetwork::create({}): {e}", cfg.cluster_id))?;
            bridges.insert(cfg.cluster_id.clone(), BridgeEntry { net, refcount: 0 });
        }

        let tap_result = {
            let entry = bridges
                .get_mut(&cfg.cluster_id)
                .expect("bridge entry just ensured");
            match cfg.vm_index {
                Some(idx) => entry
                    .net
                    .add_tap_at(idx)
                    .map_err(|e| format!("add_tap_at({idx}): {e}")),
                None => entry.net.add_tap().map_err(|e| format!("add_tap: {e}")),
            }
        };
        let tap = match tap_result {
            Ok(tap) => tap,
            Err(e) => {
                // Undo the bridge creation if we were the only would-be
                // user (refcount 0 means no live VM references it).
                if bridges
                    .get(&cfg.cluster_id)
                    .is_some_and(|e| e.refcount == 0)
                {
                    bridges.remove(&cfg.cluster_id);
                }
                return Err(e);
            }
        };
        let vm_index = tap.vm_index();

        let entry = bridges
            .get_mut(&cfg.cluster_id)
            .expect("bridge entry just ensured");
        entry.refcount += 1;

        // Move the TAP into the CNI pod netns and install
        // pod_ip ↔ guest_ip NAT. Best-effort — on failure the VM
        // falls back to host-bridge networking (the TAP fd stays valid
        // across the netns move).
        let mut attached = None;
        if let Some(ref netns) = cfg.pod_netns {
            let netns_path = PathBuf::from(netns);
            match crate::netns::link_addrs_v4(&netns_path, "eth0") {
                Ok(addrs) => match addrs.into_iter().next() {
                    Some(pod_ip) => {
                        match entry.net.attach_to_pod_netns(vm_index, &netns_path, pod_ip) {
                            Ok(()) => attached = Some(netns_path),
                            Err(e) => log::warn!(
                                "attach_to_pod_netns({vm_index}, {}, {pod_ip}) failed: {e}; \
                                 falling back to host-bridge networking",
                                netns_path.display()
                            ),
                        }
                    }
                    None => log::warn!(
                        "pod netns {} eth0 has no IPv4 address; skipping CNI attach",
                        netns_path.display()
                    ),
                },
                Err(e) => log::warn!(
                    "failed to read pod IP from {} eth0: {e}; skipping CNI attach",
                    netns_path.display()
                ),
            }
        }

        Ok(NetAttachment {
            tap,
            vm_index,
            pod_netns: attached,
        })
    }

    /// Drop one reference on `cluster_id`'s bridge; destroy the bridge
    /// when the last reference goes. `vm_index`, when given, is freed
    /// on the surviving bridge so the identity slot can be reused.
    fn release_bridge_locked(
        bridges: &mut HashMap<String, BridgeEntry>,
        cluster_id: &str,
        vm_index: Option<u32>,
    ) {
        let Some(entry) = bridges.get_mut(cluster_id) else {
            log::warn!("release_bridge: no bridge entry for cluster {cluster_id}");
            return;
        };
        if let Some(idx) = vm_index {
            entry.net.remove_entry(idx);
        }
        if entry.refcount <= 1 {
            // Dropping the entry runs ClusterNetwork::drop → destroy().
            bridges.remove(cluster_id);
            log::info!("bridge for cluster {cluster_id} destroyed (last VM gone)");
        } else {
            entry.refcount -= 1;
        }
    }

    /// Build and boot the VM *without* holding the registry lock, then
    /// insert it. Keeps the lock off the multi-hundred-millisecond boot
    /// path so concurrent `list_vms` / `stop_vm` calls don't stall.
    #[allow(clippy::too_many_lines)]
    fn build_and_start(&self, config: VmConfig) -> Result<CreatedVm, String> {
        let artifacts = Self::resolve_vm_guest(&config)?;
        let kernel = artifacts.kernel;
        // Name the guest in the log. "Which kernel did this pod boot?"
        // is otherwise unanswerable after the fact, and the answer is
        // what turns a guest that misbehaves in one corner (nf_tables
        // with no address families, an agent older than the call it is
        // waiting for) into a one-line diagnosis. See CHALLENGES #72.
        log::info!(
            "guest artifacts: kernel={kernel} initrd={} cmdline={} (from {})",
            artifacts.initrd.as_deref().unwrap_or("(none)"),
            config.cmdline.as_deref().unwrap_or("(builder default)"),
            if config.kernel.is_some() {
                "the client's request"
            } else {
                "the daemon environment"
            }
        );

        // Build the (fallible) device config before acquiring the
        // network so a validation error cannot leak a bridge reference.
        // The builder honors `vcpus` (and rejects invalid
        // counts loudly at build time).
        let mut builder = Vm::builder()
            .kernel(&kernel)
            .memory_mb(config.memory_mb)
            .vcpus(config.vcpus)
            .vsock(config.vsock);
        if let Some(n) = config.dilation {
            builder = builder.dilation(n);
        }
        if let Some(ref initrd) = artifacts.initrd {
            builder = builder.initrd(initrd);
        }
        if let Some(ref cmdline) = config.cmdline {
            if cmdline.trim().is_empty() {
                return Err(
                    "config.cmdline is empty; omit the field to keep the builder default"
                        .to_string(),
                );
            }
            builder = builder.cmdline(cmdline);
        }
        for share in &config.virtiofs {
            builder = builder.virtiofs_share(&share.host_dir, &share.guest_mount, share.readonly);
        }
        builder = apply_block_devices(builder, &config.block_devices)?;
        for dir in &config.guest_dirs {
            builder = builder.guest_dir(dir);
        }

        // The VM id doubles as the scratch image's name, so mint it
        // before the disk. Both happen before `acquire_network` so a
        // provisioning failure cannot leak a bridge reference.
        let vm_id = self.mint_vm_id();

        // The sandbox's writable layer. Attached after every
        // caller-declared device, so the guest device names the caller
        // computed from `block_devices` positions still hold. The built
        // `Vm` owns the handle: teardown unlinks the image.
        if let Some(size) = config.scratch_size_bytes {
            let disk = crate::disks::ScratchDisk::create(&vm_id, size)
                .map_err(|e| format!("provision scratch disk for {vm_id}: {e}"))?;
            builder = builder.scratch_disk(disk);
        }

        // And one image per container that asked for its own
        // writable-space limit, so its ENOSPC stays its own. Last of
        // all, for the same reason.
        for (i, cs) in config.container_scratch.iter().enumerate() {
            if config.container_scratch[..i]
                .iter()
                .any(|prev| prev.name == cs.name)
            {
                // Two devices at one mount point: the second would
                // shadow the first, and one container's limit would
                // silently be an image nobody writes to.
                return Err(format!(
                    "container_scratch names container {:?} twice",
                    cs.name
                ));
            }
            let disk =
                crate::disks::ScratchDisk::create(&format!("{vm_id}-c-{}", cs.name), cs.size_bytes)
                    .map_err(|e| {
                        format!("provision scratch disk for container {}: {e}", cs.name)
                    })?;
            builder = builder.container_scratch_disk(&cs.name, disk);
        }

        // Named persistent disks. Same "declared last" rule, opposite
        // lifetime: these images are reused by the next VM that claims
        // the same id, and teardown leaves them alone.
        for (i, dd) in config.data_disks.iter().enumerate() {
            if config.data_disks[..i].iter().any(|prev| prev.id == dd.id) {
                return Err(format!("data_disks names disk {:?} twice", dd.id));
            }
            if config.data_disks[..i]
                .iter()
                .any(|prev| prev.guest_mount == dd.guest_mount)
            {
                // Two devices at one mount point: the second shadows the
                // first, and a node would be writing its replicas to an
                // image nobody reads back.
                return Err(format!(
                    "data_disks mounts two disks at {:?}",
                    dd.guest_mount
                ));
            }
            let disk = crate::disks::DataDisk::attach(&dd.id, dd.size_bytes, &dd.guest_mount)
                .map_err(|e| format!("attach data disk {}: {e}", dd.id))?;
            builder = builder.data_disk(disk);
        }

        let attachment = match config.network {
            Some(ref net_cfg) => Some(self.acquire_network(net_cfg)?),
            None => None,
        };
        let cluster_id = config.network.as_ref().map(|n| n.cluster_id.clone());

        let (vm_index, pod_netns) = match attachment {
            Some(att) => {
                builder = builder.network(att.tap);
                (Some(att.vm_index), att.pod_netns)
            }
            None => (None, None),
        };

        // From here on a failure must release the bridge reference we
        // just took, or a failed boot leaks the bridge forever.
        let vm_result = builder
            .build()
            .map_err(|e| format!("build VM: {e}"))
            .and_then(|mut vm| {
                vm.start().map_err(|e| format!("start VM: {e}"))?;
                Ok(vm)
            })
            .and_then(|vm| {
                // Cap the vCPU thread at the pod's CFS quota.
                // Fails loudly — a pod promised a CPU limit must never
                // silently run uncapped. Dropping the partially built
                // VM on failure joins the vCPU thread first, so the
                // cgroup (dropped after, declaration order) removes
                // cleanly.
                let cpu_cgroup = Self::apply_cpu_cap(&vm_id, &vm, &config)?;
                Ok((vm, cpu_cgroup))
            });
        let (vm, cpu_cgroup) = match vm_result {
            Ok(v) => v,
            Err(e) => {
                if let Some(ref cid) = cluster_id {
                    Self::release_bridge_locked(&mut self.bridges.lock().unwrap(), cid, vm_index);
                }
                return Err(e);
            }
        };
        let guest_cid = vm.guest_cid();
        let pod_netns_attached = pod_netns.is_some();

        self.register_vm(
            vm_id.clone(),
            vm,
            cpu_cgroup,
            config.cpu_quota,
            config.cpu_period,
            config.sandbox_id,
            cluster_id,
            vm_index,
            pod_netns,
        )?;
        log::info!("created {vm_id} (guest_cid={guest_cid}, vm_index={vm_index:?})");
        Ok(CreatedVm {
            vm_id,
            guest_cid,
            vm_index,
            pod_netns_attached,
        })
    }

    /// Apply the pod's CFS quota to `vm`'s vCPU thread via a
    /// dedicated threaded cgroup under the daemon's own cgroup (see
    /// [`crate::cgroup`] for why the pod slice itself can't be used).
    /// `Ok(None)` when the config carries no quota.
    fn apply_cpu_cap(
        vm_id: &str,
        vm: &Vm,
        config: &VmConfig,
    ) -> Result<Option<crate::cgroup::VmCpuCgroup>, String> {
        let Some(quota) = config.cpu_quota else {
            return Ok(None);
        };
        let period = config
            .cpu_period
            .ok_or("cpu_quota set without cpu_period")?;
        if quota == 0 || period == 0 {
            return Err(format!(
                "invalid CPU cap: quota={quota} period={period} (both must be > 0)"
            ));
        }
        // Every vCPU thread goes into the cgroup so the pod's
        // CFS quota caps the whole VM, not just the BSP.
        let tids = vm
            .vcpu_kernel_tids(Duration::from_secs(5))
            .ok_or("vCPU threads never published their kernel TIDs")?;
        let cgroup = crate::cgroup::VmCpuCgroup::create(vm_id, quota, period)
            .map_err(|e| format!("create CPU cgroup for {vm_id}: {e}"))?;
        for &tid in &tids {
            cgroup
                .add_thread(tid)
                .map_err(|e| format!("move vCPU thread {tid} into CPU cgroup: {e}"))?;
        }
        log::info!(
            "applied host CPU cap {quota}/{period}us to vCPU thread(s) {tids:?} of {vm_id} \
             (cgroup {})",
            cgroup.dir().display()
        );
        Ok(Some(cgroup))
    }

    /// Mint a process-unique VM identifier.
    fn mint_vm_id(&self) -> String {
        format!(
            "vm-{}-{}",
            std::process::id(),
            self.counter.fetch_add(1, Ordering::SeqCst)
        )
    }

    /// Insert a running VM into the registry and, for a sandbox-carrying
    /// VM, persist its reattach record. Shared by
    /// the cold-boot path and the pool fast path
    /// so pooled VMs get identical bookkeeping.
    ///
    /// A record that cannot be written fails the create loudly (a
    /// silent miss would surface much later as an inexplicable reattach
    /// failure) and the VM — bridge reference included — is torn down
    /// again.
    #[allow(clippy::too_many_arguments)]
    fn register_vm(
        &self,
        vm_id: String,
        vm: Vm,
        cpu_cgroup: Option<crate::cgroup::VmCpuCgroup>,
        cpu_quota: Option<u64>,
        cpu_period: Option<u64>,
        sandbox_id: Option<String>,
        cluster_id: Option<String>,
        vm_index: Option<u32>,
        pod_netns: Option<PathBuf>,
    ) -> Result<String, String> {
        let guest_cid = vm.guest_cid();
        let vcpus = vm.vcpu_count();
        self.vms.lock().unwrap().insert(
            vm_id.clone(),
            VmEntry {
                vm,
                cpu_cgroup,
                cpu_quota,
                cpu_period,
                guest_cid,
                sandbox_id: sandbox_id.clone(),
                cluster_id: cluster_id.clone(),
                vm_index,
                pod_netns: pod_netns.clone(),
            },
        );

        if let Some(sandbox_id) = sandbox_id {
            let record = SandboxRecord {
                sandbox_id: sandbox_id.clone(),
                vm_id: vm_id.clone(),
                guest_cid,
                vcpus,
                cpu_quota,
                cpu_period,
                vm_index,
                cluster_id,
                pod_netns: pod_netns.map(|p| p.to_string_lossy().into_owned()),
                created_at_unix: std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map(|d| d.as_secs())
                    .unwrap_or(0),
            };
            if let Err(e) = write_sandbox_record(&record) {
                if let Some(entry) = self.vms.lock().unwrap().remove(&vm_id) {
                    self.teardown_entry(&vm_id, entry);
                }
                return Err(format!("persist sandbox record for {sandbox_id}: {e}"));
            }
            self.sandboxes
                .lock()
                .unwrap()
                .insert(sandbox_id, vm_id.clone());
        }
        Ok(vm_id)
    }

    /// Warm-fork `vm_id` into a fresh daemon-owned VM (warm path).
    ///
    /// The registry lock is held for the whole operation: the source
    /// `Vm` must not be stopped or forked concurrently. The fork itself
    /// is O(dirty pages) (~ms); the one-time `prepare_fork_source` on a
    /// VM's first fork is the slow path (cold snapshot + restore). The
    /// source's vsock CID is preserved across prepare
    /// and echoed back as `source_guest_cid`.
    #[allow(clippy::too_many_lines)]
    fn fork_vm(
        &self,
        vm_id: &str,
        fork_sandbox_id: Option<String>,
        dilation: Option<u32>,
    ) -> Response {
        let fork_id = self.mint_vm_id();

        let mut vms = self.vms.lock().unwrap();
        let forked = {
            let Some(entry) = vms.get_mut(vm_id) else {
                return Response::Error {
                    message: format!("no such VM: {vm_id}"),
                };
            };
            if entry.vm.fork_source_base_path().is_none() {
                // Daemon policy: sandbox VMs that still
                // carry virtiofs shares are explicitly slow-fork — every
                // fork is a full memfd copy. The opt-in is loud
                // (`allow_slow_fork` warns) so nothing degrades silently.
                if !entry.vm.virtiofs_shares().is_empty() {
                    entry.vm.allow_slow_fork();
                }
                if let Err(e) = entry.vm.prepare_fork_source() {
                    return Response::Error {
                        message: format!("prepare_fork_source({vm_id}): {e}"),
                    };
                }
                // prepare_fork_source swapped in a restored VM with
                // fresh vCPU threads — a capped VM must land back in
                // its CPU cgroup with ALL N kernel TIDs,
                // or the quota silently stops applying.
                if let Some(cg) = &entry.cpu_cgroup {
                    let Some(tids) = entry.vm.vcpu_kernel_tids(Duration::from_secs(5)) else {
                        return Response::Error {
                            message: format!(
                                "prepare_fork_source({vm_id}): restored vCPU threads never \
                                 published kernel TIDs — cannot re-apply the CPU cap"
                            ),
                        };
                    };
                    for tid in tids {
                        if let Err(e) = cg.add_thread(tid) {
                            return Response::Error {
                                message: format!(
                                    "prepare_fork_source({vm_id}): re-attach vCPU TID {tid} \
                                     to CPU cgroup: {e}"
                                ),
                            };
                        }
                    }
                }
                entry.guest_cid = entry.vm.guest_cid();
                log::info!(
                    "{vm_id} prepared as fork source (guest_cid={} preserved)",
                    entry.guest_cid
                );
            }
            let mut fork = match entry.vm.fork_warm_batch(&[&fork_id], dilation) {
                Ok(mut forks) => forks.pop().expect("single fork"),
                Err(e) => {
                    return Response::Error {
                        message: format!("fork_warm({vm_id}): {e}"),
                    }
                }
            };
            // fork_warm hands the fork back paused; it runs from here.
            if let Err(e) = fork.start() {
                return Response::Error {
                    message: format!("start fork of {vm_id}: {e}"),
                };
            }
            (fork, entry.guest_cid, entry.cpu_quota, entry.cpu_period)
        };
        let (fork, source_guest_cid, cpu_quota, cpu_period) = forked;
        // A capped source's fork inherits the same CFS cap
        // across all N child vCPU threads — leaving the child uncapped
        // would be a silent quota escape on the kubectl fork path.
        let cpu_cgroup = match (cpu_quota, cpu_period) {
            (Some(quota), Some(period)) => {
                let cap_cfg = VmConfig {
                    cpu_quota: Some(quota),
                    cpu_period: Some(period),
                    ..VmConfig::default()
                };
                match Self::apply_cpu_cap(&fork_id, &fork, &cap_cfg) {
                    Ok(cg) => cg,
                    Err(message) => {
                        drop(fork);
                        return Response::Error { message };
                    }
                }
            }
            _ => None,
        };
        let guest_cid = fork.guest_cid();
        let vcpus = fork.vcpu_count();
        let dilation = fork.dilation();
        vms.insert(
            fork_id.clone(),
            VmEntry {
                vm: fork,
                cpu_cgroup,
                cpu_quota,
                cpu_period,
                guest_cid,
                sandbox_id: fork_sandbox_id.clone(),
                cluster_id: None,
                vm_index: None,
                pod_netns: None,
            },
        );
        // A fork that backs a kubectl pod is a first-class
        // sandbox VM — persist its reattach record and index it so
        // `lookup_sandbox` / `reattach_sandbox` (and `k7 pause` on the
        // fork) resolve it exactly like a `create_vm`-born sandbox.
        if let Some(sandbox_id) = fork_sandbox_id {
            let record = SandboxRecord {
                sandbox_id: sandbox_id.clone(),
                vm_id: fork_id.clone(),
                guest_cid,
                vcpus,
                cpu_quota,
                cpu_period,
                vm_index: None,
                cluster_id: None,
                pod_netns: None,
                created_at_unix: std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map(|d| d.as_secs())
                    .unwrap_or(0),
            };
            if let Err(e) = write_sandbox_record(&record) {
                if let Some(entry) = vms.remove(&fork_id) {
                    drop(vms);
                    self.teardown_entry(&fork_id, entry);
                }
                return Response::Error {
                    message: format!("persist sandbox record for fork {sandbox_id}: {e}"),
                };
            }
            self.sandboxes
                .lock()
                .unwrap()
                .insert(sandbox_id, fork_id.clone());
        }
        log::info!("forked {vm_id} -> {fork_id} (guest_cid={guest_cid})");
        Response::VmForked {
            vm_id: fork_id,
            guest_cid,
            source_guest_cid,
            dilation,
        }
    }

    /// Pause `vm_id` in place: vCPUs stopped, memory and
    /// vsock CID retained. The registry lock is held so the VM cannot
    /// be stopped/forked mid-pause.
    fn pause_vm(&self, vm_id: &str) -> Response {
        let mut vms = self.vms.lock().unwrap();
        let Some(entry) = vms.get_mut(vm_id) else {
            return Response::Error {
                message: format!("no such VM: {vm_id}"),
            };
        };
        match entry.vm.pause() {
            Ok(()) => {
                log::info!("paused {vm_id} (guest_cid={} retained)", entry.guest_cid);
                Response::Ok
            }
            Err(e) => Response::Error {
                message: format!("pause({vm_id}): {e}"),
            },
        }
    }

    /// Resume a paused `vm_id`. Fresh vCPU threads of a CFS-capped VM
    /// are re-attached to its CPU cgroup — same invariant as the
    /// fork-source prepare swap (/17c).
    fn resume_vm(&self, vm_id: &str) -> Response {
        let mut vms = self.vms.lock().unwrap();
        let Some(entry) = vms.get_mut(vm_id) else {
            return Response::Error {
                message: format!("no such VM: {vm_id}"),
            };
        };
        if let Err(e) = entry.vm.resume() {
            return Response::Error {
                message: format!("resume({vm_id}): {e}"),
            };
        }
        if let Err(message) = Self::reattach_cpu_cgroup(entry, "resume", vm_id) {
            return Response::Error { message };
        }
        log::info!("resumed {vm_id} (guest_cid={})", entry.guest_cid);
        Response::Ok
    }

    /// Put a resumed VM's **fresh** vCPU threads back into its CPU
    /// cgroup. Every path that stops and restarts the run loop owes the
    /// pod its CFS cap; `op` names the caller for the error message.
    fn reattach_cpu_cgroup(entry: &VmEntry, op: &str, vm_id: &str) -> Result<(), String> {
        let Some(cg) = &entry.cpu_cgroup else {
            return Ok(());
        };
        let Some(tids) = entry.vm.vcpu_kernel_tids(Duration::from_secs(5)) else {
            return Err(format!(
                "{op}({vm_id}): vCPU threads never published kernel TIDs — \
                 cannot re-apply the CPU cap"
            ));
        };
        for tid in tids {
            cg.add_thread(tid).map_err(|e| {
                format!("{op}({vm_id}): re-attach vCPU TID {tid} to CPU cgroup: {e}")
            })?;
        }
        Ok(())
    }

    /// Advance every VM on `cluster_id`'s guest clock by `delta_ms`,
    /// atomically under pause .
    ///
    /// The registry lock is held across the whole cycle, so no VM on the
    /// cluster can be stopped, forked or paused mid-warp.
    fn warp_clock(&self, cluster_id: &str, delta_ms: u64) -> Response {
        if delta_ms == 0 {
            return Response::Error {
                message: format!(
                    "warp_clock({cluster_id}): delta_ms must be > 0 — a warp is \
                     forward-only and never a silent no-op"
                ),
            };
        }
        let mut vms = self.vms.lock().unwrap();
        let mut members: Vec<(&String, &mut VmEntry)> = vms
            .iter_mut()
            .filter(|(_, e)| e.cluster_id.as_deref() == Some(cluster_id))
            .collect();
        if members.is_empty() {
            return Response::Error {
                message: format!("warp_clock: no VM on cluster {cluster_id}"),
            };
        }
        // `vm_index` order, so the reply reads like the cluster does.
        members.sort_by(|a, b| (a.1.vm_index, a.0).cmp(&(b.1.vm_index, b.0)));
        let vm_ids: Vec<String> = members.iter().map(|(id, _)| (*id).clone()).collect();

        let mut targets: Vec<&mut crate::vm::Vm> =
            members.iter_mut().map(|(_, e)| &mut e.vm).collect();
        let latency =
            match crate::vm::warp_clock_lockstep(&mut targets, Duration::from_millis(delta_ms)) {
                Ok(latency) => latency,
                Err(e) => {
                    return Response::Error {
                        message: format!("warp_clock({cluster_id}, +{delta_ms}ms): {e}"),
                    }
                }
            };
        drop(targets);

        // Resumed VMs run on fresh vCPU threads; a CFS-capped member
        // loses its cap unless they rejoin its cgroup.
        for (vm_id, entry) in &members {
            if let Err(message) = Self::reattach_cpu_cgroup(entry, "warp_clock", vm_id) {
                return Response::Error { message };
            }
        }
        log::info!(
            "warped cluster {cluster_id} by {delta_ms}ms across {} VMs in {latency:?}",
            vm_ids.len()
        );
        Response::Warped {
            cluster_id: cluster_id.to_string(),
            vm_ids,
            delta_ms,
            latency_ns: u64::try_from(latency.as_nanos()).unwrap_or(u64::MAX),
        }
    }

    /// Change the dilation factor of every VM on `cluster_id`, atomically
    /// under pause .
    ///
    /// Members come from the `CreateVm` registry *or* from the cluster
    /// tree: `tree_create_cluster` / `tree_fork_batch` own their VMs
    /// inside `ClusterSnapshotTree::live`, and a gym child that only
    /// looked at the registry would report "no VM on cluster"
    /// (CHALLENGES #193). Whichever lock the members live under is held
    /// across the whole cycle, so nothing can stop or fork them mid-set.
    fn set_dilation(&self, cluster_id: &str, factor: u32) -> Response {
        if factor == 0 || factor > crate::vm::MAX_DILATION {
            return Response::Error {
                message: format!(
                    "set_dilation({cluster_id}): factor {factor} is outside 1..={} — \
                     the hardware TSC multiplier bounds it and the kernel never clamps",
                    crate::vm::MAX_DILATION
                ),
            };
        }

        let mut vms = self.vms.lock().unwrap();
        let mut members: Vec<(&String, &mut VmEntry)> = vms
            .iter_mut()
            .filter(|(_, e)| e.cluster_id.as_deref() == Some(cluster_id))
            .collect();
        if members.is_empty() {
            drop(vms);
            let mut trees = self.trees.lock().unwrap();
            let Some(tree_members) = tree_cluster_members_mut(&mut trees, cluster_id) else {
                return Response::Error {
                    message: format!("set_dilation: no VM on cluster {cluster_id}"),
                };
            };
            // Tree-owned VMs have no registry id, so they are reported
            // positionally rather than under a name nothing can look up.
            let vm_ids: Vec<String> = (0..tree_members.len())
                .map(|i| format!("{cluster_id}#{i}"))
                .collect();
            let mut targets: Vec<&mut Vm> = tree_members.iter_mut().collect();
            return match crate::vm::set_dilation_lockstep(&mut targets, factor) {
                // Tree members have no CreateVm CFS cgroup to reattach.
                Ok(latency) => Self::dilation_set(cluster_id, vm_ids, factor, latency),
                Err(e) => Response::Error {
                    message: format!("set_dilation({cluster_id}, x{factor}): {e}"),
                },
            };
        }
        // `vm_index` order, so the reply reads like the cluster does.
        members.sort_by(|a, b| (a.1.vm_index, a.0).cmp(&(b.1.vm_index, b.0)));
        let vm_ids: Vec<String> = members.iter().map(|(id, _)| (*id).clone()).collect();

        let mut targets: Vec<&mut crate::vm::Vm> =
            members.iter_mut().map(|(_, e)| &mut e.vm).collect();
        let latency = match crate::vm::set_dilation_lockstep(&mut targets, factor) {
            Ok(latency) => latency,
            Err(e) => {
                return Response::Error {
                    message: format!("set_dilation({cluster_id}, x{factor}): {e}"),
                }
            }
        };
        drop(targets);

        // Resumed VMs run on fresh vCPU threads; a CFS-capped member
        // loses its cap unless they rejoin its cgroup.
        for (vm_id, entry) in &members {
            if let Err(message) = Self::reattach_cpu_cgroup(entry, "set_dilation", vm_id) {
                return Response::Error { message };
            }
        }
        Self::dilation_set(cluster_id, vm_ids, factor, latency)
    }

    fn dilation_set(
        cluster_id: &str,
        vm_ids: Vec<String>,
        factor: u32,
        latency: Duration,
    ) -> Response {
        log::info!(
            "set cluster {cluster_id} to dilation x{factor} across {} VMs in {latency:?}",
            vm_ids.len()
        );
        Response::DilationSet {
            cluster_id: cluster_id.to_string(),
            vm_ids,
            factor,
            latency_ns: u64::try_from(latency.as_nanos()).unwrap_or(u64::MAX),
        }
    }

    /// Start, switch or stop `cluster_id`'s auto-warp policy loop
    /// .
    ///
    /// A mode change always stops the loop in flight first, and stopping
    /// joins it: a cycle owns the registry lock and may have the whole
    /// cluster paused, so returning early would let the next op race a
    /// pause the loop still owns.
    fn auto_warp(&self, cluster_id: &str, mode: crate::autowarp::AutoWarpMode) -> Response {
        use crate::autowarp::{AutoWarpMode, Driver};

        let mut loops = self.auto_warps.lock().unwrap();
        if let Some(running) = loops.get_mut(cluster_id) {
            running.stop();
            log::info!("auto-warp: stopped the policy loop on cluster {cluster_id}");
        }
        if mode == AutoWarpMode::Off {
            // The counters of the run that just ended are the reply:
            // `off` is how a caller collects its accounting.
            let stats = loops
                .get(cluster_id)
                .map(|l| l.counters.snapshot())
                .unwrap_or_default();
            return Response::AutoWarp {
                cluster_id: cluster_id.to_string(),
                mode: AutoWarpMode::Off,
                holders: self.auto_warp_holders(cluster_id),
                stats,
            };
        }
        // A loop on a cluster with no VM would spin on `no_members`
        // counters forever and look like a working policy.
        // CreateVm members live in `vms`; gym / tree_create_cluster
        // children live in `trees` under `{tree_id}-{node_id}`.
        let in_registry = self
            .vms
            .lock()
            .unwrap()
            .values()
            .any(|e| e.cluster_id.as_deref() == Some(cluster_id));
        let in_tree = {
            let mut trees = self.trees.lock().unwrap();
            tree_cluster_members_mut(&mut trees, cluster_id).is_some()
        };
        if !in_registry && !in_tree {
            return Response::Error {
                message: format!("auto_warp: no VM on cluster {cluster_id}"),
            };
        }

        let mut driver = Driver::new(mode);
        let counters = driver.counters();
        let stop = Arc::new(AtomicBool::new(false));
        let vms = Arc::clone(&self.vms);
        let trees = Arc::clone(&self.trees);
        let holds = Arc::clone(&self.auto_warp_holds);
        let cluster = cluster_id.to_string();
        let thread = {
            let stop = Arc::clone(&stop);
            std::thread::Builder::new()
                .name(format!("k7d-autowarp-{cluster_id}"))
                .spawn(move || {
                    Self::auto_warp_loop(&vms, &trees, &holds, &cluster, &mut driver, &stop);
                })
        };
        let thread = match thread {
            Ok(t) => t,
            Err(e) => {
                return Response::Error {
                    message: format!("auto_warp({cluster_id}): spawning the policy loop: {e}"),
                }
            }
        };
        log::info!("auto-warp: {} mode on cluster {cluster_id}", mode.as_str());
        loops.insert(
            cluster_id.to_string(),
            AutoWarpLoop {
                mode,
                stop,
                counters: Arc::clone(&counters),
                thread: Some(thread),
            },
        );
        Response::AutoWarp {
            cluster_id: cluster_id.to_string(),
            mode,
            holders: self.auto_warp_holders(cluster_id),
            stats: counters.snapshot(),
        }
    }

    /// The policy loop body. One cycle per iteration, each holding the
    /// VM registry for its whole duration.
    fn auto_warp_loop(
        vms: &Mutex<HashMap<String, VmEntry>>,
        trees: &Mutex<HashMap<String, TreePayload>>,
        holds: &Mutex<HashMap<String, BTreeSet<String>>>,
        cluster_id: &str,
        driver: &mut crate::autowarp::Driver,
        stop: &AtomicBool,
    ) {
        while !stop.load(Ordering::SeqCst) {
            // Read the hold before taking the registry: a caller must be
            // able to take one while a cycle is in flight, and the cycle
            // it lands too late for is bounded by one cadence.
            let in_flight = holds
                .lock()
                .unwrap()
                .get(cluster_id)
                .filter(|h| !h.is_empty())
                .map(|h| {
                    format!(
                        "held by {} against cluster {cluster_id}",
                        h.iter().cloned().collect::<Vec<_>>().join(", ")
                    )
                });

            let cycle = {
                let mut registry = vms.lock().unwrap();
                let mut members: Vec<&mut VmEntry> = registry
                    .values_mut()
                    .filter(|e| e.cluster_id.as_deref() == Some(cluster_id))
                    .collect();
                if members.is_empty() {
                    drop(registry);
                    let mut trees = trees.lock().unwrap();
                    let Some(members) = tree_cluster_members_mut(&mut trees, cluster_id) else {
                        log::info!(
                            "auto-warp: cluster {cluster_id} has no live VM left — stopping its loop"
                        );
                        break;
                    };
                    let mut targets: Vec<&mut Vm> = members.iter_mut().collect();
                    driver.cycle(&mut targets, in_flight.as_deref())
                } else {
                    members.sort_by_key(|e| e.vm_index);
                    let mut targets: Vec<&mut Vm> = members.iter_mut().map(|e| &mut e.vm).collect();
                    let cycle = driver.cycle(&mut targets, in_flight.as_deref());
                    drop(targets);
                    // A resumed VM runs on fresh vCPU threads, and a
                    // CFS-capped member loses its cap unless they rejoin
                    // its cgroup — the same invariant `warp_clock` holds.
                    if cycle.paused() {
                        for entry in &members {
                            if let Err(message) =
                                Self::reattach_cpu_cgroup(entry, "auto_warp", cluster_id)
                            {
                                log::error!("auto-warp: {message}");
                            }
                        }
                    }
                    cycle
                }
            };
            if let crate::autowarp::Cycle::Declined(d) = &cycle {
                log::trace!("auto-warp({cluster_id}) declined: {}", d.detail);
            }
            driver.pace(&cycle);
        }
        log::info!(
            "auto-warp: cluster {cluster_id} loop exiting; {:?}",
            driver.stats()
        );
    }

    /// Read one cluster's auto-warp mode, holds and counters.
    fn auto_warp_status(&self, cluster_id: &str) -> Response {
        let loops = self.auto_warps.lock().unwrap();
        let (mode, stats) = loops.get(cluster_id).map_or_else(
            || {
                (
                    crate::autowarp::AutoWarpMode::Off,
                    crate::autowarp::AutoWarpStats::default(),
                )
            },
            |l| (l.mode, l.counters.snapshot()),
        );
        Response::AutoWarp {
            cluster_id: cluster_id.to_string(),
            mode,
            holders: self.auto_warp_holders(cluster_id),
            stats,
        }
    }

    /// Take or release the fifth safety check's hold.
    fn auto_warp_hold(&self, cluster_id: &str, holder: &str, hold: bool) -> Response {
        if holder.is_empty() {
            return Response::Error {
                message: "auto_warp_hold: an anonymous hold cannot be attributed when it \
                          leaks — name the holder"
                    .to_string(),
            };
        }
        {
            let mut holds = self.auto_warp_holds.lock().unwrap();
            let taken = holds.entry(cluster_id.to_string()).or_default();
            if hold {
                if !taken.insert(holder.to_string()) {
                    return Response::Error {
                        message: format!(
                            "auto_warp_hold: {holder} already holds cluster {cluster_id} — \
                             a double take means one release will free it too early"
                        ),
                    };
                }
            } else if !taken.remove(holder) {
                return Response::Error {
                    message: format!(
                        "auto_warp_hold: {holder} does not hold cluster {cluster_id} — \
                         releasing a hold nobody took would unblock somebody else's warp"
                    ),
                };
            }
        }
        self.auto_warp_status(cluster_id)
    }

    /// Current holders of `cluster_id`, in name order.
    fn auto_warp_holders(&self, cluster_id: &str) -> Vec<String> {
        self.auto_warp_holds
            .lock()
            .unwrap()
            .get(cluster_id)
            .map(|h| h.iter().cloned().collect())
            .unwrap_or_default()
    }

    /// Resolve kernel + optional initrd for a `CreateVm` / tree member.
    /// Ubuntu `root=` disk boots omit the initrd and must not pick up
    /// `K7D_INITRD` (CHALLENGES #72).
    fn resolve_vm_guest(config: &VmConfig) -> Result<crate::config::GuestArtifacts, String> {
        crate::config::resolve_vm_guest(
            config.kernel.as_deref(),
            config.initrd.as_deref(),
            config.cmdline.as_deref(),
            config.block_devices.len(),
        )
    }

    /// Boot one VM for a tree payload and wait for its guest agent —
    /// the tree roots a snapshot of this state, so every later fork
    /// must inherit a *ready* agent, not a half-booted guest.
    ///
    /// Returns the VM together with its **open** agent connection: the
    /// caller must keep the client alive across the tree-rooting
    /// snapshot (`prepare_fork_source_in`) so the guest's vsock state
    /// at snapshot time has an established connection for the injected
    /// `TRANSPORT_RESET` to reset — the pattern `test_tree.rs` has
    /// exercised since. Closing it just before the snapshot
    /// leaves the guest mid-close and the restored vsock device was
    /// (rarely, but observably) unresponsive.
    fn boot_tree_member(
        config: &VmConfig,
        tap: Option<TapDevice>,
    ) -> Result<(Vm, crate::api::AgentClient), String> {
        if config.scratch_size_bytes.is_some() || !config.container_scratch.is_empty() {
            // A tree payload VM is owned by the SnapshotTree, not by a
            // sandbox, and its whole point is to be forked repeatedly.
            // Rather than quietly drop the request (the failure
            // mode is exactly a writable layer that isn't where the
            // caller thinks), refuse it.
            return Err(
                "scratch_size_bytes / container_scratch are not supported for tree payload \
                 VMs — a tree node's writable layer comes from the sandbox VMs it adopts \
"
                .to_string(),
            );
        }
        if !config.data_disks.is_empty() {
            // Same refusal, sharper reason: a tree payload is forked
            // repeatedly, and every branch would want *its own* copy of a
            // disk whose whole identity is that it is shared across VMs.
            // A node that wants persistent storage gets it from the
            // sandbox VMs the tree adopts.
            return Err(
                "data_disks are not supported for tree payload VMs — a tree node is forked \
                 repeatedly and a persistent disk has one identity; attach it to the sandbox \
                 VMs the tree adopts instead"
                    .to_string(),
            );
        }
        let artifacts = Self::resolve_vm_guest(config)?;
        let mut builder = Vm::builder()
            .kernel(&artifacts.kernel)
            .memory_mb(config.memory_mb)
            .vcpus(config.vcpus)
            .vsock(config.vsock);
        if let Some(n) = config.dilation {
            builder = builder.dilation(n);
        }
        if let Some(ref initrd) = artifacts.initrd {
            builder = builder.initrd(initrd);
        }
        if let Some(ref cmdline) = config.cmdline {
            if cmdline.trim().is_empty() {
                return Err(
                    "config.cmdline is empty; omit the field to keep the builder default"
                        .to_string(),
                );
            }
            builder = builder.cmdline(cmdline);
        }
        for share in &config.virtiofs {
            builder = builder.virtiofs_share(&share.host_dir, &share.guest_mount, share.readonly);
        }
        builder = apply_block_devices(builder, &config.block_devices)?;
        for dir in &config.guest_dirs {
            builder = builder.guest_dir(dir);
        }
        if let Some(tap) = tap {
            builder = builder.network(tap);
        }
        let mut vm = builder.build().map_err(|e| format!("build VM: {e}"))?;
        vm.start().map_err(|e| format!("start VM: {e}"))?;
        let agent = vm
            .connect_agent(Duration::from_secs(90))
            .map_err(|e| format!("guest agent never became ready: {e}"))?;
        Ok((vm, agent))
    }

    /// Verify the restored/live members of `node_id` answer on their
    /// (new) CIDs before we hand those CIDs to the client. Fails loudly
    /// — returning a dead CID would surface later as an inscrutable
    /// vsock connect timeout in the caller.
    fn verify_node_agents(payload: &TreePayload, node_id: &String) -> Result<(), String> {
        match payload {
            TreePayload::Single(t) => {
                let vm = t
                    .get_vm(node_id)
                    .ok_or_else(|| format!("node {node_id} has no live VM"))?;
                vm.connect_agent(Duration::from_secs(30))
                    .map_err(|e| format!("agent on restored CID {}: {e}", vm.guest_cid()))?;
            }
            TreePayload::Cluster(t) => {
                let p = t
                    .get_payload(node_id)
                    .ok_or_else(|| format!("node {node_id} has no live payload"))?;
                for (i, vm) in p.members.iter().enumerate() {
                    vm.connect_agent(Duration::from_secs(30)).map_err(|e| {
                        format!("agent on member {i} (CID {}): {e}", vm.guest_cid())
                    })?;
                }
            }
        }
        Ok(())
    }

    /// Validate or mint a tree id and reserve nothing — the caller
    /// inserts into the registry after the (slow) tree construction and
    /// re-checks for a duplicate at that point.
    fn mint_tree_id(&self, requested: Option<String>) -> Result<String, String> {
        match requested {
            Some(id) => {
                if id.is_empty()
                    || !id
                        .chars()
                        .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
                {
                    return Err(format!(
                        "invalid tree_id {id:?}: use ASCII alphanumerics, '-', '_'"
                    ));
                }
                if self.trees.lock().unwrap().contains_key(&id) {
                    return Err(format!("tree {id} already exists"));
                }
                Ok(id)
            }
            None => Ok(format!(
                "tree-{}-{}",
                std::process::id(),
                self.counter.fetch_add(1, Ordering::SeqCst)
            )),
        }
    }

    /// Insert a freshly built tree, failing loudly on an id race (two
    /// concurrent `tree_create`s with the same explicit id).
    fn insert_tree(&self, tree_id: String, payload: TreePayload, guest_cids: Vec<u64>) -> Response {
        use std::collections::hash_map::Entry;
        match self.trees.lock().unwrap().entry(tree_id.clone()) {
            Entry::Occupied(_) => Response::Error {
                message: format!("tree {tree_id} already exists (created concurrently)"),
            },
            Entry::Vacant(slot) => {
                slot.insert(payload);
                log::info!("created tree {tree_id} (root cids {guest_cids:?})");
                Response::TreeCreated {
                    tree_id,
                    root_id: "root".to_string(),
                    guest_cids,
                }
            }
        }
    }

    /// Root a single-VM snapshot tree — boot, wait for the
    /// agent, `SnapshotTree::new` (which prepares the VM as a fork
    /// source). All outside the trees lock; only the final insert
    /// contends.
    fn tree_create(
        &self,
        config: &VmConfig,
        budget: Option<TreeBudget>,
        tree_id: Option<String>,
    ) -> Response {
        if config.network.is_some() {
            return Response::Error {
                message: "tree_create: config.network must be None (single-VM trees are \
                          unbridged; use tree_create_cluster for networked trees)"
                    .to_string(),
            };
        }
        let tree_id = match self.mint_tree_id(tree_id) {
            Ok(id) => id,
            Err(message) => return Response::Error { message },
        };
        let (vm, agent) = match Self::boot_tree_member(config, None) {
            Ok(v) => v,
            Err(message) => return Response::Error { message },
        };
        let root_dir = tree_root_dir().join(&tree_id);
        let (tree, root_id) =
            match SnapshotTree::new(vm, root_dir, budget.unwrap_or_else(default_tree_budget)) {
                Ok(v) => v,
                Err(e) => {
                    return Response::Error {
                        message: format!("SnapshotTree::new: {e}"),
                    }
                }
            };
        // The pre-snapshot connection has served its purpose (see
        // boot_tree_member) — the snapshot has been taken.
        drop(agent);
        let payload = TreePayload::Single(tree);
        if let Err(message) = Self::verify_node_agents(&payload, &root_id) {
            return Response::Error { message };
        }
        let guest_cids = payload.node_cids(&root_id);
        self.insert_tree(tree_id, payload, guest_cids)
    }

    /// Adopt live sandbox VMs + their shared bridge as a cluster
    /// snapshot-tree root. See [`Request::TreeAdoptCluster`].
    #[allow(clippy::too_many_lines)]
    fn tree_adopt_cluster(
        &self,
        vm_ids: &[String],
        budget: Option<TreeBudget>,
        tree_id: Option<String>,
        egress: Option<crate::netjail::EgressPolicy>,
    ) -> Response {
        if let Some(ref policy) = egress {
            if let Err(e) = policy.validate() {
                return Response::Error {
                    message: format!("tree_adopt_cluster: {e}"),
                };
            }
        }
        if vm_ids.is_empty() {
            return Response::Error {
                message: "tree_adopt_cluster: vm_ids must be non-empty".to_string(),
            };
        }
        // Reject duplicates up front — a repeated id would otherwise
        // succeed once and then fail the second remove with a confusing
        // "no such VM" after half the set was already extracted.
        {
            let mut seen = std::collections::HashSet::new();
            for id in vm_ids {
                if !seen.insert(id.as_str()) {
                    return Response::Error {
                        message: format!("tree_adopt_cluster: duplicate vm_id {id}"),
                    };
                }
            }
        }
        let tree_id = match self.mint_tree_id(tree_id) {
            Ok(id) => id,
            Err(message) => return Response::Error { message },
        };

        // Extract under the vms lock. On any miss, put already-extracted
        // entries back so a failed adopt never strands live VMs outside
        // both the registry and a tree.
        let mut extracted: Vec<(String, VmEntry)> = Vec::with_capacity(vm_ids.len());
        {
            let mut vms = self.vms.lock().unwrap();
            for vm_id in vm_ids {
                if let Some(entry) = vms.remove(vm_id) {
                    extracted.push((vm_id.clone(), entry));
                } else {
                    for (id, entry) in extracted {
                        vms.insert(id, entry);
                    }
                    return Response::Error {
                        message: format!("tree_adopt_cluster: no such VM: {vm_id}"),
                    };
                }
            }
        }

        let put_back = |extracted: Vec<(String, VmEntry)>| {
            let mut vms = self.vms.lock().unwrap();
            for (id, entry) in extracted {
                vms.insert(id, entry);
            }
        };

        // Every member must be networked on the same cluster bridge with
        // a distinct vm_index. No silent "unbridged" fallback.
        let Some(cluster_id) = extracted[0].1.cluster_id.clone() else {
            let vm_id = extracted[0].0.clone();
            put_back(extracted);
            return Response::Error {
                message: format!(
                    "tree_adopt_cluster: VM {vm_id} has no cluster_id \
                     (not on a shared bridge)"
                ),
            };
        };

        let mut validation_err: Option<String> = None;
        for (vm_id, entry) in &extracted {
            match (&entry.cluster_id, entry.vm_index) {
                (Some(cid), Some(_)) if cid == &cluster_id => {}
                (Some(cid), Some(_)) => {
                    validation_err = Some(format!(
                        "tree_adopt_cluster: VM {vm_id} is on cluster_id {cid}, \
                         expected {cluster_id} (VMs must share one bridge)"
                    ));
                    break;
                }
                (None, _) => {
                    validation_err = Some(format!(
                        "tree_adopt_cluster: VM {vm_id} has no cluster_id \
                         (not on a shared bridge)"
                    ));
                    break;
                }
                (_, None) => {
                    validation_err = Some(format!(
                        "tree_adopt_cluster: VM {vm_id} has no vm_index \
                         (bridge identity slot missing)"
                    ));
                    break;
                }
            }
            if entry.pod_netns.is_some() {
                validation_err = Some(format!(
                    "tree_adopt_cluster: VM {vm_id} has a CNI pod_netns attach; \
                     cluster-tree adopt requires pure cluster-mode (no per-pod NAT)"
                ));
                break;
            }
        }
        if let Some(message) = validation_err {
            put_back(extracted);
            return Response::Error { message };
        }

        // Contiguous 0..N-1 indices — ClusterPayload.members[i] is
        // vm_index i for fork_cluster_warm / add_tap_at.
        let mut indexed: Vec<(u32, String, VmEntry)> = Vec::with_capacity(extracted.len());
        let mut pending = extracted.into_iter();
        loop {
            let Some((id, entry)) = pending.next() else {
                break;
            };
            let Some(idx) = entry.vm_index else {
                let mut back = vec![(id.clone(), entry)];
                back.extend(pending);
                put_back(back);
                return Response::Error {
                    message: format!(
                        "tree_adopt_cluster: VM {id} lost its vm_index after validation"
                    ),
                };
            };
            indexed.push((idx, id, entry));
        }
        indexed.sort_by_key(|(idx, _, _)| *idx);
        for (i, (idx, vm_id, _)) in indexed.iter().enumerate() {
            let want = u32::try_from(i).unwrap_or(u32::MAX);
            if *idx != want {
                let bad_id = vm_id.clone();
                let bad_idx = *idx;
                let back: Vec<(String, VmEntry)> = indexed
                    .into_iter()
                    .map(|(_, id, entry)| (id, entry))
                    .collect();
                put_back(back);
                return Response::Error {
                    message: format!(
                        "tree_adopt_cluster: vm_index values must be contiguous 0..{}; \
                         found gap at {want} (vm {bad_id} has index {bad_idx})",
                        vm_ids.len()
                    ),
                };
            }
        }

        // Take the bridge out of the daemon map. Refcount must equal the
        // adopted set — leftover or missing refs mean a half-wired cluster.
        let bridge = {
            let mut bridges = self.bridges.lock().unwrap();
            match bridges.remove(&cluster_id) {
                Some(entry) if entry.refcount == indexed.len() => entry.net,
                Some(entry) => {
                    let rc = entry.refcount;
                    bridges.insert(cluster_id.clone(), entry);
                    let back: Vec<(String, VmEntry)> =
                        indexed.into_iter().map(|(_, id, e)| (id, e)).collect();
                    put_back(back);
                    return Response::Error {
                        message: format!(
                            "tree_adopt_cluster: bridge {cluster_id} refcount is {rc}, \
                             but adopting {} VMs (refcount must match exactly)",
                            vm_ids.len()
                        ),
                    };
                }
                None => {
                    let back: Vec<(String, VmEntry)> =
                        indexed.into_iter().map(|(_, id, e)| (id, e)).collect();
                    put_back(back);
                    return Response::Error {
                        message: format!(
                            "tree_adopt_cluster: no bridge for cluster_id {cluster_id}"
                        ),
                    };
                }
            }
        };

        // Apply the requested egress posture before anything becomes
        // irreversible : sandbox bridges are born Open, and
        // an adopt into a contained tree re-installs the jail ruleset
        // atomically. On failure everything goes back where it was.
        let mut bridge = bridge;
        if let Some(policy) = egress {
            if let Err(e) = bridge.set_egress(policy) {
                let refcount = indexed.len();
                self.bridges.lock().unwrap().insert(
                    cluster_id.clone(),
                    BridgeEntry {
                        net: bridge,
                        refcount,
                    },
                );
                let back: Vec<(String, VmEntry)> =
                    indexed.into_iter().map(|(_, id, e)| (id, e)).collect();
                put_back(back);
                return Response::Error {
                    message: format!("tree_adopt_cluster: set_egress: {e}"),
                };
            }
        }

        // Drop sandbox index + on-disk records: these VMs are no longer
        // reattachable as sandboxes (they're tree members).
        // StopVm on pod teardown then sees "no such VM", which the shim
        // already treats as best-effort.
        {
            let mut sandboxes = self.sandboxes.lock().unwrap();
            for (_, _, entry) in &indexed {
                if let Some(ref sid) = entry.sandbox_id {
                    sandboxes.remove(sid);
                    remove_sandbox_record(sid);
                }
            }
        }

        // Build the payload. The CPU cgroups are held until
        // after `new_cluster`: prepare swaps each member for a restored
        // copy whose fresh vCPU thread is not in the old cgroup, so the
        // pod's CFS cap cannot follow the VM into the tree anyway
        // (tree members are uncapped, like tree-created VMs). Dropping
        // the guards afterwards migrates any straggler thread back to
        // the parent and removes the directory — `mem::forget` would
        // leak one cgroup dir per adopted VM per adopt.
        let mut members = Vec::with_capacity(indexed.len());
        let mut cgroups = Vec::new();
        for (_idx, vm_id, entry) in indexed {
            let VmEntry {
                vm,
                cpu_cgroup,
                cpu_quota: _,
                cpu_period: _,
                guest_cid: _,
                sandbox_id: _,
                cluster_id: _,
                vm_index: _,
                pod_netns: _,
            } = entry;
            if let Some(cg) = cpu_cgroup {
                cgroups.push(cg);
            }
            log::info!("tree_adopt_cluster: adopting {vm_id} into tree {tree_id}");
            members.push(vm);
        }

        let root = ClusterPayload {
            network: bridge,
            members,
        };
        let root_dir = tree_root_dir().join(&tree_id);
        let result = ClusterSnapshotTree::new_cluster(
            root,
            root_dir,
            budget.unwrap_or_else(default_tree_budget),
        );
        // Original vCPU threads are joined by the prepare swap inside
        // `new_cluster` (success or failure) — safe to remove the
        // cgroup dirs now.
        drop(cgroups);
        let (tree, root_id) = match result {
            Ok(v) => v,
            Err(e) => {
                return Response::Error {
                    message: format!("ClusterSnapshotTree::new_cluster (adopt): {e}"),
                }
            }
        };
        let payload = TreePayload::Cluster(tree);
        if let Err(message) = Self::verify_node_agents(&payload, &root_id) {
            return Response::Error { message };
        }
        let guest_cids = payload.node_cids(&root_id);
        self.insert_tree(tree_id, payload, guest_cids)
    }

    /// Root a cluster snapshot tree: a tree-owned bridge plus
    /// `vm_count` members, each agent-ready before the root snapshot.
    fn tree_create_cluster(
        &self,
        vm_count: u32,
        config: &VmConfig,
        budget: Option<TreeBudget>,
        tree_id: Option<String>,
        egress: Option<crate::netjail::EgressPolicy>,
    ) -> Response {
        type BuiltCluster = (ClusterPayload, Vec<crate::api::AgentClient>);
        if vm_count == 0 {
            return Response::Error {
                message: "tree_create_cluster: vm_count must be >= 1".to_string(),
            };
        }
        if config.network.is_some() {
            return Response::Error {
                message: "tree_create_cluster: config.network must be None (the tree owns its \
                          own ClusterNetwork; members are bridged automatically)"
                    .to_string(),
            };
        }
        let tree_id = match self.mint_tree_id(tree_id) {
            Ok(id) => id,
            Err(message) => return Response::Error { message },
        };

        // Build the root cluster. On any member failure, dropping `net`
        // and the already-built members tears everything down (bridge,
        // TAPs, vCPUs) — no partial cluster leaks. The agent clients
        // stay open until after new_cluster's snapshots (see
        // boot_tree_member).
        let egress = egress.unwrap_or_default();
        let build = || -> Result<BuiltCluster, String> {
            let mut net = ClusterNetwork::create_with_egress(&tree_id, egress.clone())
                .map_err(|e| format!("ClusterNetwork::create({tree_id}): {e}"))?;
            let mut members = Vec::with_capacity(vm_count as usize);
            let mut agents = Vec::with_capacity(vm_count as usize);
            for i in 0..vm_count {
                let tap = net
                    .add_tap()
                    .map_err(|e| format!("add_tap (member {i}): {e}"))?;
                let (vm, agent) = Self::boot_tree_member(config, Some(tap))
                    .map_err(|e| format!("member {i}: {e}"))?;
                members.push(vm);
                agents.push(agent);
            }
            Ok((
                ClusterPayload {
                    network: net,
                    members,
                },
                agents,
            ))
        };
        let (root, agents) = match build() {
            Ok(v) => v,
            Err(message) => return Response::Error { message },
        };

        let root_dir = tree_root_dir().join(&tree_id);
        let (tree, root_id) = match ClusterSnapshotTree::new_cluster(
            root,
            root_dir,
            budget.unwrap_or_else(default_tree_budget),
        ) {
            Ok(v) => v,
            Err(e) => {
                return Response::Error {
                    message: format!("ClusterSnapshotTree::new_cluster: {e}"),
                }
            }
        };
        drop(agents);
        let payload = TreePayload::Cluster(tree);
        if let Err(message) = Self::verify_node_agents(&payload, &root_id) {
            return Response::Error { message };
        }
        let guest_cids = payload.node_cids(&root_id);
        self.insert_tree(tree_id, payload, guest_cids)
    }

    /// Run `f` against one registered tree, holding the trees lock for
    /// the duration (tree mutations must not interleave).
    fn with_tree<F: FnOnce(&mut TreePayload) -> Response>(&self, tree_id: &str, f: F) -> Response {
        let mut trees = self.trees.lock().unwrap();
        match trees.get_mut(tree_id) {
            Some(tree) => f(tree),
            None => Response::Error {
                message: format!("no such tree: {tree_id}"),
            },
        }
    }

    fn tree_list(&self) -> Response {
        let trees = self.trees.lock().unwrap();
        let mut list: Vec<TreeSummary> = trees
            .iter()
            .map(|(id, t)| TreeSummary {
                tree_id: id.clone(),
                kind: t.kind().to_string(),
                nodes: t.list_nodes().len(),
                usage: t.usage().into(),
                budget: t.budget(),
            })
            .collect();
        list.sort_by(|a, b| a.tree_id.cmp(&b.tree_id));
        Response::TreeList { trees: list }
    }

    /// Initial `tree_watch` snapshot. Unknown `tree_id` is loud.
    fn watch_snapshot(&self, tree_id: Option<&str>) -> Response {
        let trees = self.trees.lock().unwrap();
        if let Some(id) = tree_id {
            return match trees.get(id) {
                Some(t) => Response::TreeWatching {
                    trees: vec![t.watch_snapshot(id.to_string())],
                },
                None => Response::Error {
                    message: format!("no such tree: {id}"),
                },
            };
        }
        let mut snaps: Vec<TreeWatchSnapshot> = trees
            .iter()
            .map(|(id, t)| t.watch_snapshot(id.clone()))
            .collect();
        snaps.sort_by(|a, b| a.tree_id.cmp(&b.tree_id));
        Response::TreeWatching { trees: snaps }
    }

    fn watch_subscribe(&self, tree_id: Option<String>) -> std::sync::mpsc::Receiver<TreeEvent> {
        let (tx, rx) = std::sync::mpsc::channel();
        self.watchers.lock().unwrap().push(WatchSub { tree_id, tx });
        rx
    }

    fn emit_tree_event(
        &self,
        tree_id: &str,
        op: &str,
        node_id: Option<&str>,
        latency_ns: Option<u64>,
    ) {
        let ev = TreeEvent {
            tree_id: tree_id.to_string(),
            op: op.to_string(),
            node_id: node_id.map(str::to_string),
            latency_ns,
        };
        let mut subs = self.watchers.lock().unwrap();
        subs.retain(|s| {
            if s.tree_id.as_deref().is_none_or(|id| id == tree_id) {
                s.tx.send(ev.clone()).is_ok()
            } else {
                true
            }
        });
    }

    fn emit_from_response(&self, tree_id: &str, resp: &Response) {
        match resp {
            Response::TreeForked {
                node_id,
                latency_ns,
                ..
            } => self.emit_tree_event(tree_id, "fork", Some(node_id), Some(*latency_ns)),
            Response::TreeForkBatch { forks, latency_ns } => {
                for f in forks {
                    self.emit_tree_event(tree_id, "fork", Some(&f.node_id), Some(*latency_ns));
                }
            }
            _ => {}
        }
    }

    /// Re-open an on-disk cluster tree. See [`Request::TreeOpen`].
    fn tree_open(&self, tree_id: &str) -> Response {
        use std::collections::hash_map::Entry;
        {
            let trees = self.trees.lock().unwrap();
            if trees.contains_key(tree_id) {
                return Response::Error {
                    message: format!("tree {tree_id} already registered"),
                };
            }
        }
        let root = tree_root_dir().join(tree_id);
        let tree_json = root.join("tree.json");
        if !tree_json.is_file() {
            return Response::Error {
                message: format!("tree.json missing at {}", tree_json.display()),
            };
        }
        match ClusterSnapshotTree::open(root) {
            Ok(tree) => {
                let nodes: Vec<NodeInfo> = tree.list_nodes().into_iter().cloned().collect();
                let mut trees = self.trees.lock().unwrap();
                match trees.entry(tree_id.to_string()) {
                    Entry::Occupied(_) => Response::Error {
                        message: format!("tree {tree_id} already registered"),
                    },
                    Entry::Vacant(slot) => {
                        slot.insert(TreePayload::Cluster(tree));
                        log::info!("opened tree {tree_id} ({} nodes, Suspended)", nodes.len());
                        Response::TreeOpened {
                            tree_id: tree_id.to_string(),
                            root_id: "root".to_string(),
                            nodes,
                        }
                    }
                }
            }
            Err(e) => Response::Error {
                message: format!("tree_open({tree_id}): {e}"),
            },
        }
    }

    /// Forget a tree. Dropping the payload outside the lock tears down
    /// every live VM (and, for clusters, the tree-owned bridges); the
    /// on-disk `tree.json` + node dirs stay for later re-open.
    fn tree_drop(&self, tree_id: &str) -> Response {
        let removed = self.trees.lock().unwrap().remove(tree_id);
        match removed {
            Some(payload) => {
                drop(payload);
                log::info!("dropped tree {tree_id}");
                self.emit_tree_event(tree_id, "drop", None, None);
                Response::Ok
            }
            None => Response::Error {
                message: format!("no such tree: {tree_id}"),
            },
        }
    }

    /// Resolve `sandbox_id` to its live VM via the in-memory index.
    fn lookup_sandbox(&self, sandbox_id: &str) -> Response {
        let vm_id = self.sandboxes.lock().unwrap().get(sandbox_id).cloned();
        let Some(vm_id) = vm_id else {
            return Response::Error {
                message: format!("no such sandbox: {sandbox_id}"),
            };
        };
        let vms = self.vms.lock().unwrap();
        match vms.get(&vm_id) {
            Some(entry) => Response::SandboxFound {
                vm_id,
                guest_cid: entry.guest_cid,
                vcpus: entry.vm.vcpu_count(),
                vm_index: entry.vm_index,
                cluster_id: entry.cluster_id.clone(),
                pod_netns_attached: entry.pod_netns.is_some(),
            },
            // Index says the VM exists but the registry disagrees —
            // should be unreachable (both are updated under stop_vm).
            None => Response::Error {
                message: format!("sandbox {sandbox_id} maps to unknown VM {vm_id}"),
            },
        }
    }

    /// `lookup_sandbox` + liveness proof: the guest agent must answer
    /// a ping over vsock before the VM is handed to a respawned shim.
    /// A registry VM whose agent is dead is torn down (record
    /// included); a stale on-disk record with no live VM is removed.
    fn reattach_sandbox(&self, sandbox_id: &str) -> Response {
        let found = self.lookup_sandbox(sandbox_id);
        let Response::SandboxFound {
            ref vm_id,
            guest_cid,
            ..
        } = found
        else {
            // No live VM. If a record file survived a daemon restart
            // it is stale by definition — GC it loudly.
            let path = sandbox_record_path(sandbox_id);
            if path.exists() {
                log::error!(
                    "reattach_sandbox({sandbox_id}): stale record {} (VM died with a \
                     previous daemon); removing",
                    path.display()
                );
                if let Err(e) = std::fs::remove_file(&path) {
                    log::error!("remove stale record {}: {e}", path.display());
                }
                return Response::Error {
                    message: format!(
                        "sandbox {sandbox_id}: VM died with a previous daemon (stale \
                         record removed)"
                    ),
                };
            }
            return found;
        };

        // Liveness check outside any lock — the vsock connect can
        // legitimately take a moment and must not stall the control
        // plane. CIDs are kernel-global so the daemon dials the guest
        // the same way any client does.
        let ping = crate::api::AgentClient::connect_vsock(guest_cid, Duration::from_secs(10))
            .and_then(|mut agent| agent.ping().map(|_| ()));
        if let Err(e) = ping {
            log::error!(
                "reattach_sandbox({sandbox_id}): VM {vm_id} (cid {guest_cid}) is \
                 unresponsive: {e}; tearing it down"
            );
            let vm_id = vm_id.clone();
            self.stop_vm(&vm_id); // also removes the record + index entry
            return Response::Error {
                message: format!(
                    "sandbox {sandbox_id}: VM {vm_id} was unresponsive and has been \
                     torn down"
                ),
            };
        }
        found
    }

    fn vm_status(&self, vm_id: &str) -> Response {
        let vms = self.vms.lock().unwrap();
        match vms.get(vm_id) {
            Some(entry) => Response::VmState {
                vm_id: vm_id.to_string(),
                state: "running".to_string(),
                guest_cid: entry.guest_cid,
                virtiofs_shares: entry.vm.virtiofs_shares().len(),
                block_devices: entry.vm.block_devices().len(),
                fork_memory_full_copy: entry.vm.fork_memory_is_full_copy(),
                kernel: entry.vm.kernel_path().to_string_lossy().into_owned(),
            },
            None => Response::Error {
                message: format!("no such VM: {vm_id}"),
            },
        }
    }

    fn dump_serial(&self, vm_id: Option<&str>, guest_cid: Option<u64>) -> Response {
        {
            let vms = self.vms.lock().unwrap();
            if let Some(id) = vm_id {
                if let Some(entry) = vms.get(id) {
                    return Response::SerialDump {
                        vm_id: id.to_string(),
                        guest_cid: entry.vm.guest_cid(),
                        console: entry.vm.serial_output(Duration::ZERO),
                    };
                }
            }
            if let Some(cid) = guest_cid {
                if let Some((id, entry)) = vms
                    .iter()
                    .find(|(_, e)| e.guest_cid == cid || e.vm.guest_cid() == cid)
                {
                    return Response::SerialDump {
                        vm_id: id.clone(),
                        guest_cid: entry.vm.guest_cid(),
                        console: entry.vm.serial_output(Duration::ZERO),
                    };
                }
            }
        }

        let trees = self.trees.lock().unwrap();
        // Composite id `{tree_id}/{node_id}` is what we echo for tree
        // members — looking it back up must work without a CID.
        if let Some(id) = vm_id {
            if let Some((tree_id, node_id)) = id.split_once('/') {
                if let Some(tree) = trees.get(tree_id) {
                    if let Some(cid) = guest_cid {
                        if let Some((nid, vm)) = tree.find_live_vm_by_cid(cid) {
                            if nid == node_id {
                                return serial_dump_tree(tree_id, nid, vm);
                            }
                        }
                    }
                    let key = node_id.to_string();
                    if let Some(&cid) = tree.node_cids(&key).first() {
                        if let Some((nid, vm)) = tree.find_live_vm_by_cid(cid) {
                            return serial_dump_tree(tree_id, nid, vm);
                        }
                    }
                }
            }
        }
        if let Some(cid) = guest_cid {
            for (tree_id, tree) in trees.iter() {
                if let Some((node_id, vm)) = tree.find_live_vm_by_cid(cid) {
                    return serial_dump_tree(tree_id, node_id, vm);
                }
            }
        }
        Response::Error {
            message: format!("no such VM: vm_id={vm_id:?} guest_cid={guest_cid:?}"),
        }
    }

    fn list_vms(&self) -> Response {
        let vms = self.vms.lock().unwrap();
        let mut list: Vec<VmInfo> = vms
            .iter()
            .map(|(id, entry)| VmInfo {
                vm_id: id.clone(),
                guest_cid: entry.guest_cid,
                state: "running".to_string(),
                sandbox_id: entry.sandbox_id.clone(),
            })
            .collect();
        list.sort_by(|a, b| a.vm_id.cmp(&b.vm_id));
        Response::VmList { vms: list }
    }

    fn stop_vm(&self, vm_id: &str) -> Response {
        // Remove under the lock, then drop the VM outside it: `Vm::drop`
        // stops the vCPU thread and joins device workers, which can take
        // a few ms and must not block other control-plane calls.
        let entry = self.vms.lock().unwrap().remove(vm_id);
        match entry {
            Some(entry) => {
                self.teardown_entry(vm_id, entry);
                log::info!("stopped {vm_id}");
                Response::Ok
            }
            None => Response::Error {
                message: format!("no such VM: {vm_id}"),
            },
        }
    }

    /// Delete a persistent data disk's image, refusing while a VM the
    /// daemon owns still has it attached.
    ///
    /// Retention with no way to delete is a disk leak, and deletion that
    /// ignores the live attachment is CHALLENGES #63 again — the check
    /// is against the daemon's own registry, which is the only set of
    /// VMs that could have been given the disk through `create_vm`.
    fn delete_data_disk(&self, id: &str) -> Response {
        if let Err(e) = crate::disks::DataDisk::validate_id(id) {
            return Response::Error {
                message: e.to_string(),
            };
        }
        let holder = self.vms.lock().unwrap().iter().find_map(|(vm_id, entry)| {
            entry
                .vm
                .data_disks()
                .iter()
                .any(|d| d.id() == id)
                .then(|| vm_id.clone())
        });
        if let Some(vm_id) = holder {
            return Response::Error {
                message: format!(
                    "data disk {id} is attached to live VM {vm_id} — stop it before deleting \
                     the disk"
                ),
            };
        }
        match crate::disks::DataDisk::delete(id) {
            Ok(()) => Response::Ok,
            Err(e) => Response::Error {
                message: format!("delete data disk {id}: {e}"),
            },
        }
    }

    /// Tear one VM down in the right order: in-netns bridge first
    /// (best-effort — containerd usually destroys the pod netns right
    /// after), then the VM itself (vCPU, device workers, virtiofsd
    /// children, TAP link via `Vm::drop`), then the bridge reference.
    fn teardown_entry(&self, vm_id: &str, entry: VmEntry) {
        // A stopped sandbox must not be
        // reattachable — drop the index entry and the on-disk record
        // before the VM teardown.
        if let Some(ref sandbox_id) = entry.sandbox_id {
            self.sandboxes.lock().unwrap().remove(sandbox_id);
            remove_sandbox_record(sandbox_id);
        }

        if let (Some(cluster_id), Some(netns)) = (&entry.cluster_id, &entry.pod_netns) {
            let bridges = self.bridges.lock().unwrap();
            if let Some(bridge) = bridges.get(cluster_id) {
                let _ = bridge
                    .net
                    .detach_from_pod_netns(entry.vm_index.unwrap_or(0), netns);
            }
        }

        let cluster_id = entry.cluster_id.clone();
        let vm_index = entry.vm_index;
        drop(entry);

        if let Some(ref cid) = cluster_id {
            Self::release_bridge_locked(&mut self.bridges.lock().unwrap(), cid, vm_index);
        }
        log::debug!("teardown of {vm_id} complete");
    }

    /// Shut down and drop every VM the daemon owns. Called on graceful
    /// daemon shutdown so device workers, virtiofsd children, TAPs, and
    /// cluster bridges are cleaned up rather than orphaned.
    pub fn shutdown_all(&self) {
        // Stop the warm pool first: the filler
        // must not race a refill against the teardown below. The pool
        // drops its template + idle VMs; acquired VMs live in the
        // registry and are drained like any other.
        if let Some(ref pool) = self.pool {
            log::info!("shutdown: tearing down warm pool");
            pool.shutdown();
        }
        // Auto-warp loops next, and joined: a cycle in flight holds the
        // registry lock with its cluster paused, so draining VMs under
        // it would tear down a VM this daemon has stopped mid-pause.
        for (cluster_id, mut policy) in self.auto_warps.lock().unwrap().drain() {
            log::info!("shutdown: stopping the auto-warp loop on {cluster_id}");
            policy.stop();
        }
        let drained: Vec<(String, VmEntry)> = self.vms.lock().unwrap().drain().collect();
        for (vm_id, entry) in drained {
            log::info!("shutdown: dropping {vm_id}");
            self.teardown_entry(&vm_id, entry);
        }
        // Trees own their live VMs (and, for clusters, their bridges);
        // dropping each payload tears them down. On-disk tree state is
        // kept — it is re-opened later for crash recovery.
        let trees: Vec<(String, TreePayload)> = self.trees.lock().unwrap().drain().collect();
        for (tree_id, payload) in trees {
            log::info!("shutdown: dropping tree {tree_id}");
            drop(payload);
        }
        // Any bridge still alive here had leaked references (should not
        // happen); dropping the map destroys them loudly in the logs.
        let leftover: Vec<String> = self
            .bridges
            .lock()
            .unwrap()
            .drain()
            .map(|(k, _)| k)
            .collect();
        for cluster_id in leftover {
            log::warn!("shutdown: destroying leaked bridge for cluster {cluster_id}");
        }
    }

    /// Number of VMs currently owned (test/introspection helper).
    #[must_use]
    pub fn vm_count(&self) -> usize {
        self.vms.lock().unwrap().len()
    }
}

/// Resolve the control-socket path from the environment: `K7D_SOCKET`
/// if set, else [`DEFAULT_SOCKET`]. Used by both the daemon and
/// clients (shim, tests) so they always agree.
#[must_use]
pub fn socket_path_from_env() -> String {
    std::env::var("K7D_SOCKET").unwrap_or_else(|_| DEFAULT_SOCKET.to_string())
}

/// Resolve the tree storage root: `K7D_TREE_ROOT` if set, else
/// [`DEFAULT_TREE_ROOT`].
#[must_use]
pub fn tree_root_dir() -> PathBuf {
    PathBuf::from(std::env::var("K7D_TREE_ROOT").unwrap_or_else(|_| DEFAULT_TREE_ROOT.to_string()))
}

/// Resolve the sandbox-record root: `K7D_SANDBOX_ROOT` if set, else
/// [`DEFAULT_SANDBOX_ROOT`].
#[must_use]
pub fn sandbox_root_dir() -> PathBuf {
    PathBuf::from(
        std::env::var("K7D_SANDBOX_ROOT").unwrap_or_else(|_| DEFAULT_SANDBOX_ROOT.to_string()),
    )
}

/// Path of one sandbox's reattach record.
fn sandbox_record_path(sandbox_id: &str) -> PathBuf {
    sandbox_root_dir().join(format!("{sandbox_id}.json"))
}

/// Atomically persist `record` (write to `*.json.tmp`, then rename) —
/// a crash mid-write must never leave a half-written record behind.
fn write_sandbox_record(record: &SandboxRecord) -> Result<(), String> {
    let root = sandbox_root_dir();
    std::fs::create_dir_all(&root).map_err(|e| format!("create {}: {e}", root.display()))?;
    let path = sandbox_record_path(&record.sandbox_id);
    let tmp = path.with_extension("json.tmp");
    let json = serde_json::to_string_pretty(record).map_err(|e| format!("serialize: {e}"))?;
    std::fs::write(&tmp, json).map_err(|e| format!("write {}: {e}", tmp.display()))?;
    std::fs::rename(&tmp, &path)
        .map_err(|e| format!("rename {} -> {}: {e}", tmp.display(), path.display()))?;
    Ok(())
}

/// Remove one sandbox's record file. Missing file is fine (record may
/// never have been written for this VM); any other failure is logged
/// loudly — a leftover record would let a future shim reattach to a
/// dead sandbox.
fn remove_sandbox_record(sandbox_id: &str) {
    let path = sandbox_record_path(sandbox_id);
    match std::fs::remove_file(&path) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => log::error!("remove sandbox record {}: {e}", path.display()),
    }
}

fn serial_dump_tree(tree_id: &str, node_id: &str, vm: &Vm) -> Response {
    Response::SerialDump {
        vm_id: format!("{tree_id}/{node_id}"),
        guest_cid: vm.guest_cid(),
        console: vm.serial_output(Duration::ZERO),
    }
}

/// Synchronous control-plane client (one Unix connection, JSON-lines).
///
/// Used by the containerd shim and by tests. Each [`Client::call`]
/// writes one request line and reads one response line; the connection
/// carries as many pairs as the caller wants.
pub struct Client {
    stream: UnixStream,
}

impl Client {
    /// Connect to the daemon at `socket_path`.
    pub fn connect(socket_path: &str) -> std::io::Result<Self> {
        let stream = UnixStream::connect(socket_path)?;
        Ok(Self { stream })
    }

    /// Connect using [`socket_path_from_env`].
    pub fn connect_env() -> std::io::Result<Self> {
        Self::connect(&socket_path_from_env())
    }

    /// Send one request and read its response. IO or serialization
    /// failures are returned as `Err(String)`; a daemon-side failure
    /// comes back as `Ok(Response::Error { .. })`.
    pub fn call(&mut self, req: &Request) -> Result<Response, String> {
        let mut line = serde_json::to_string(req).map_err(|e| format!("serialize request: {e}"))?;
        line.push('\n');
        self.stream
            .write_all(line.as_bytes())
            .and_then(|()| self.stream.flush())
            .map_err(|e| format!("write to k7d control socket: {e}"))?;

        let mut reader = BufReader::new(&self.stream);
        let mut resp_line = String::new();
        reader
            .read_line(&mut resp_line)
            .map_err(|e| format!("read from k7d control socket: {e}"))?;
        if resp_line.is_empty() {
            return Err("k7d closed the control connection".to_string());
        }
        serde_json::from_str(resp_line.trim()).map_err(|e| format!("parse k7d response: {e}"))
    }
}

/// Serve the control plane on `socket_path` until `shutdown` is set.
///
/// Uses a non-blocking listener polled against `shutdown` so a signal
/// handler can stop the loop; each accepted connection is handled on
/// its own thread. On return the socket file is removed.
pub fn serve(
    socket_path: &str,
    daemon: &Arc<Daemon>,
    shutdown: &AtomicBool,
) -> std::io::Result<()> {
    let path = PathBuf::from(socket_path);
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    // A socket file that exists is either a live daemon's or a dead one's
    // leftover, and only a connect can tell them apart. Removing it blind
    // meant a second daemon stole the path from the first: the original kept
    // serving an unlinked listener no client could reach, and whichever
    // process exited first deleted the survivor's socket. So probe, and
    // refuse to be the second daemon rather than silently displacing it.
    if path.exists() {
        match UnixStream::connect(&path) {
            Ok(_) => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::AddrInUse,
                    format!("another k7d is already serving {socket_path}"),
                ));
            }
            // Nobody is listening: a leftover from a dead daemon. bind(2)
            // fails with EADDRINUSE on an existing path, so clear it.
            Err(_) => match std::fs::remove_file(&path) {
                Ok(()) => {}
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                Err(e) => return Err(e),
            },
        }
    }

    let listener = UnixListener::bind(&path)?;
    listener.set_nonblocking(true)?;
    log::info!("k7d listening on {socket_path}");

    let mut workers: Vec<std::thread::JoinHandle<()>> = Vec::new();
    while !shutdown.load(Ordering::SeqCst) {
        match listener.accept() {
            Ok((stream, _addr)) => {
                let daemon = Arc::clone(daemon);
                workers.push(std::thread::spawn(move || {
                    handle_connection(&stream, &daemon);
                }));
            }
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                std::thread::sleep(Duration::from_millis(50));
            }
            Err(e) => {
                log::error!("accept error: {e}");
                std::thread::sleep(Duration::from_millis(50));
            }
        }
        workers.retain(|w| !w.is_finished());
    }

    let _ = std::fs::remove_file(&path);
    log::info!("k7d control socket closed");
    Ok(())
}

/// Handle one client connection: read request lines, dispatch, write
/// response lines, until EOF. `tree_watch` takes over the connection
/// (snapshot, then events) until the client hangs up.
fn handle_connection(stream: &UnixStream, daemon: &Daemon) {
    let reader = BufReader::new(stream);
    let mut writer = stream;
    for line in reader.lines() {
        let line = match line {
            Ok(l) => l,
            Err(e) => {
                log::warn!("control read error: {e}");
                return;
            }
        };
        if line.trim().is_empty() {
            continue;
        }
        let req = match serde_json::from_str::<Request>(&line) {
            Ok(req) => req,
            Err(e) => {
                if !write_response(
                    &mut writer,
                    &Response::Error {
                        message: format!("bad request: {e}"),
                    },
                ) {
                    return;
                }
                continue;
            }
        };
        if let Request::TreeWatch { tree_id } = req {
            serve_tree_watch(&mut writer, daemon, tree_id.as_deref());
            return;
        }
        if !write_response(&mut writer, &daemon.handle(req)) {
            return;
        }
    }
}

fn write_response(writer: &mut &UnixStream, response: &Response) -> bool {
    let mut buf = match serde_json::to_string(response) {
        Ok(s) => s,
        Err(e) => {
            log::error!("serialize response: {e}");
            return false;
        }
    };
    buf.push('\n');
    if let Err(e) = writer
        .write_all(buf.as_bytes())
        .and_then(|()| writer.flush())
    {
        log::warn!("control write error: {e}");
        return false;
    }
    true
}

fn serve_tree_watch(writer: &mut &UnixStream, daemon: &Daemon, tree_id: Option<&str>) {
    let rx = daemon.watch_subscribe(tree_id.map(str::to_string));
    let snap = daemon.watch_snapshot(tree_id);
    let failed = matches!(snap, Response::Error { .. });
    if !write_response(writer, &snap) || failed {
        return;
    }
    while let Ok(ev) = rx.recv() {
        let resp = Response::TreeEvent {
            tree_id: ev.tree_id,
            op: ev.op,
            node_id: ev.node_id,
            latency_ns: ev.latency_ns,
        };
        if !write_response(writer, &resp) {
            return;
        }
    }
}
