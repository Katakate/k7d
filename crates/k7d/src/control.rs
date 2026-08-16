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

use std::collections::HashMap;
use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use serde::{Deserialize, Serialize};

use crate::cluster_tree::{ClusterPayload, ClusterSnapshotTree};
use crate::network::{ClusterNetwork, TapDevice};
use crate::pool::Pool;
use crate::tree::{NodeInfo, SnapshotTree, TreeBudget};
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
    /// Initramfs path. Falls back to env `K7D_INITRD`.
    #[serde(default)]
    pub initrd: Option<String>,
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
    /// Optional caller-supplied sandbox identity, echoed in
    /// `list_vms` so a shim can find its VM after a restart.
    #[serde(default)]
    pub sandbox_id: Option<String>,
    /// Optional network attachment (bridge + TAP + pod netns).
    #[serde(default)]
    pub network: Option<NetConfig>,
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
            sandbox_id: None,
            network: None,
        }
    }
}

fn default_memory_mb() -> u64 {
    256
}

fn default_vcpus() -> u32 {
    1
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
    },
    /// Fork a new branch from a live or suspended tree node.
    TreeFork {
        /// Tree identifier from `tree_create*`.
        tree_id: String,
        /// Node to fork from.
        source_id: String,
        /// Human label for the new branch (also seeds its node id).
        label: String,
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
    /// Forget a tree: live payloads are torn down, on-disk state under
    /// the tree's directory is kept (re-openable later).
    TreeDrop {
        /// Tree identifier.
        tree_id: String,
    },
    /// Report warm-pool sizing and hit/miss counters. Always
    /// answers, even with the pool disabled
    /// (`size: 0`).
    PoolStatus,
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
        /// VM identifier.
        vm_id: String,
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
    },
    /// Reply to `tree_fork_batch`.
    TreeForkBatch {
        /// One entry per requested label, in the same order.
        forks: Vec<TreeForkedBranch>,
    },
    /// Reply to `tree_resume`.
    TreeResumed {
        /// The resumed node id.
        node_id: String,
        /// Fresh guest vsock CIDs of the resumed members.
        guest_cids: Vec<u64>,
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
    },
    /// Reply to `tree_list`.
    TreeList {
        /// One summary per tree.
        trees: Vec<TreeSummary>,
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
    fn fork(&mut self, source_id: &String, label: &str) -> Result<String, String> {
        match self {
            Self::Single(t) => t.fork(source_id, label),
            Self::Cluster(t) => t.fork(source_id, label),
        }
        .map_err(|e| format!("tree fork({source_id}, {label}): {e}"))
    }

    fn fork_batch(&mut self, source_id: &String, labels: &[String]) -> Result<Vec<String>, String> {
        if labels.is_empty() {
            return Err("tree_fork_batch: labels must be non-empty".to_string());
        }
        let refs: Vec<&str> = labels.iter().map(String::as_str).collect();
        match self {
            Self::Single(t) => t.fork_batch(source_id, &refs),
            Self::Cluster(t) => t.fork_batch(source_id, &refs),
        }
        .map_err(|e| format!("tree fork_batch({source_id}, {labels:?}): {e}"))
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
}

/// The daemon's VM registry and request dispatcher.
pub struct Daemon {
    vms: Mutex<HashMap<String, VmEntry>>,
    /// Shared cluster bridges keyed by `cluster_id`, refcounted across
    /// VMs (this fixes the shared-bridge teardown
    /// race where the first pod deleted destroyed its peers' bridge).
    bridges: Mutex<HashMap<String, BridgeEntry>>,
    /// Snapshot trees keyed by `tree_id`. The
    /// lock is held for the duration of each tree mutation — tree ops
    /// need `&mut` and must not interleave on the same tree.
    trees: Mutex<HashMap<String, TreePayload>>,
    /// `sandbox_id → vm_id` index for `lookup_sandbox` /
    /// `reattach_sandbox`. Mirrors the on-disk
    /// records under [`sandbox_root_dir`] so the hot path never walks
    /// the directory.
    sandboxes: Mutex<HashMap<String, String>>,
    /// Warm pool; `None` when disabled
    /// (`K7D_POOL_SIZE` unset or 0).
    pool: Option<Pool>,
    counter: AtomicU64,
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
            vms: Mutex::new(HashMap::new()),
            bridges: Mutex::new(HashMap::new()),
            trees: Mutex::new(HashMap::new()),
            sandboxes: Mutex::new(HashMap::new()),
            pool,
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
            Request::LookupSandbox { sandbox_id } => self.lookup_sandbox(&sandbox_id),
            Request::ReattachSandbox { sandbox_id } => self.reattach_sandbox(&sandbox_id),
            Request::ForkVm { vm_id, sandbox_id } => self.fork_vm(&vm_id, sandbox_id),
            Request::PauseVm { vm_id } => self.pause_vm(&vm_id),
            Request::ResumeVm { vm_id } => self.resume_vm(&vm_id),
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
            } => self.tree_create_cluster(vm_count, &config, budget, tree_id),
            Request::TreeAdoptCluster {
                vm_ids,
                budget,
                tree_id,
            } => self.tree_adopt_cluster(&vm_ids, budget, tree_id),
            Request::TreeFork {
                tree_id,
                source_id,
                label,
            } => self.with_tree(&tree_id, |t| match t.fork(&source_id, &label) {
                Ok(node_id) => {
                    let guest_cids = t.node_cids(&node_id);
                    let fork_memory_full_copy = t.node_fork_full_copy(&node_id);
                    Response::TreeForked {
                        node_id,
                        guest_cids,
                        fork_memory_full_copy,
                    }
                }
                Err(message) => Response::Error { message },
            }),
            Request::TreeForkBatch {
                tree_id,
                source_id,
                labels,
            } => self.with_tree(&tree_id, |t| match t.fork_batch(&source_id, &labels) {
                Ok(node_ids) => {
                    let forks = node_ids
                        .into_iter()
                        .map(|node_id| TreeForkedBranch {
                            guest_cids: t.node_cids(&node_id),
                            fork_memory_full_copy: t.node_fork_full_copy(&node_id),
                            node_id,
                        })
                        .collect();
                    Response::TreeForkBatch { forks }
                }
                Err(message) => Response::Error { message },
            }),
            Request::TreeRollback {
                tree_id,
                node_id,
                label,
            } => self.with_tree(&tree_id, |t| match t.rollback(&node_id, &label) {
                Ok(node_id) => Response::TreeForked {
                    guest_cids: t.node_cids(&node_id),
                    fork_memory_full_copy: t.node_fork_full_copy(&node_id),
                    node_id,
                },
                Err(message) => Response::Error { message },
            }),
            Request::TreeProtect { tree_id, node_id } => {
                self.with_tree(&tree_id, |t| match t.protect(&node_id) {
                    Ok(()) => Response::Ok,
                    Err(message) => Response::Error { message },
                })
            }
            Request::TreeUnprotect { tree_id, node_id } => {
                self.with_tree(&tree_id, |t| match t.unprotect(&node_id) {
                    Ok(()) => Response::Ok,
                    Err(message) => Response::Error { message },
                })
            }
            Request::TreeSuspend { tree_id, node_id } => {
                self.with_tree(&tree_id, |t| match t.suspend(&node_id) {
                    Ok(()) => Response::Ok,
                    Err(message) => Response::Error { message },
                })
            }
            Request::TreeResume { tree_id, node_id } => {
                self.with_tree(&tree_id, |t| match t.resume(&node_id) {
                    Ok(()) => Response::TreeResumed {
                        guest_cids: t.node_cids(&node_id),
                        node_id,
                    },
                    Err(message) => Response::Error { message },
                })
            }
            Request::TreePrune { tree_id, node_id } => {
                self.with_tree(&tree_id, |t| match t.prune(&node_id) {
                    Ok(()) => Response::Ok,
                    Err(message) => Response::Error { message },
                })
            }
            Request::TreeAutoEvict { tree_id } => {
                self.with_tree(&tree_id, |t| match t.auto_evict() {
                    Ok(evicted) => Response::TreeEvicted { evicted },
                    Err(message) => Response::Error { message },
                })
            }
            Request::TreeNodes { tree_id } => {
                self.with_tree(&tree_id, |t| Response::TreeNodeList {
                    nodes: t.list_nodes(),
                })
            }
            Request::TreeList => self.tree_list(),
            Request::TreeDrop { tree_id } => self.tree_drop(&tree_id),
            Request::PoolStatus => self.pool_status(),
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
        let (kernel, initrd) = Self::resolve_guest_paths(&config)?;
        // Name the guest in the log. "Which kernel did this pod boot?"
        // is otherwise unanswerable after the fact, and the answer is
        // what turns a guest that misbehaves in one corner (nf_tables
        // with no address families, an agent older than the call it is
        // waiting for) into a one-line diagnosis. See CHALLENGES #72.
        log::info!(
            "guest artifacts: kernel={kernel} initrd={initrd} (from {})",
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
            .initrd(&initrd)
            .memory_mb(config.memory_mb)
            .vcpus(config.vcpus)
            .vsock(config.vsock);
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
    fn fork_vm(&self, vm_id: &str, fork_sandbox_id: Option<String>) -> Response {
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
            let mut fork = match entry.vm.fork_warm(&fork_id) {
                Ok(fork) => fork,
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
        if let Some(cg) = &entry.cpu_cgroup {
            let Some(tids) = entry.vm.vcpu_kernel_tids(Duration::from_secs(5)) else {
                return Response::Error {
                    message: format!(
                        "resume({vm_id}): vCPU threads never published kernel TIDs — \
                         cannot re-apply the CPU cap"
                    ),
                };
            };
            for tid in tids {
                if let Err(e) = cg.add_thread(tid) {
                    return Response::Error {
                        message: format!(
                            "resume({vm_id}): re-attach vCPU TID {tid} to CPU cgroup: {e}"
                        ),
                    };
                }
            }
        }
        log::info!("resumed {vm_id} (guest_cid={})", entry.guest_cid);
        Response::Ok
    }

    /// Resolve kernel/initrd from `config` or the environment — loudly.
    fn resolve_guest_paths(config: &VmConfig) -> Result<(String, String), String> {
        crate::config::resolve_guest_paths(config.kernel.as_deref(), config.initrd.as_deref())
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
        let (kernel, initrd) = Self::resolve_guest_paths(config)?;
        let mut builder = Vm::builder()
            .kernel(&kernel)
            .initrd(&initrd)
            .memory_mb(config.memory_mb)
            .vcpus(config.vcpus)
            .vsock(config.vsock);
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
    ) -> Response {
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
        let build = || -> Result<BuiltCluster, String> {
            let mut net = ClusterNetwork::create(&tree_id)
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
            })
            .collect();
        list.sort_by(|a, b| a.tree_id.cmp(&b.tree_id));
        Response::TreeList { trees: list }
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
            let hit = match (vm_id, guest_cid) {
                (Some(id), _) => vms.get_key_value(id),
                (None, Some(cid)) => vms.iter().find(|(_, e)| e.guest_cid == cid),
                (None, None) => None,
            };
            if let Some((id, entry)) = hit {
                return Response::SerialDump {
                    vm_id: id.clone(),
                    console: entry.vm.serial_output(Duration::ZERO),
                };
            }
        }
        if let Some(cid) = guest_cid {
            let trees = self.trees.lock().unwrap();
            for (tree_id, tree) in trees.iter() {
                if let Some((node_id, vm)) = tree.find_live_vm_by_cid(cid) {
                    return Response::SerialDump {
                        vm_id: format!("{tree_id}/{node_id}"),
                        console: vm.serial_output(Duration::ZERO),
                    };
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
    // Remove a stale socket from a previous run (bind fails on EADDRINUSE
    // otherwise). Fail loud if removal itself errors for a reason other
    // than "not there".
    match std::fs::remove_file(&path) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => return Err(e),
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
/// response lines, until EOF.
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
        let response = match serde_json::from_str::<Request>(&line) {
            Ok(req) => daemon.handle(req),
            Err(e) => Response::Error {
                message: format!("bad request: {e}"),
            },
        };
        let mut buf = match serde_json::to_string(&response) {
            Ok(s) => s,
            Err(e) => {
                log::error!("serialize response: {e}");
                return;
            }
        };
        buf.push('\n');
        if let Err(e) = writer
            .write_all(buf.as_bytes())
            .and_then(|()| writer.flush())
        {
            log::warn!("control write error: {e}");
            return;
        }
    }
}
