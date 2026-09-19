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
use std::os::fd::AsRawFd;
use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};

use crate::cluster_tree::{ClusterPayload, ClusterSnapshotTree};
use crate::guest::{native_vms_mut, AgentEndpoint, Backend, Guest, GuestError};
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

/// How long `resume_vm` gives a resumed Firecracker guest to answer a
/// vsock dial. A healthy guest answers in milliseconds
/// (`test_fc_pause_resume_exec_answers_twenty_times`: worst 30 ms);
/// containerd's exec probe gives up at 5 s.
const FC_RESUME_DIAL: Duration = Duration::from_secs(5);

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
    /// Firecracker cluster-fork pause skew (`max − min` pause Instant),
    /// when the op measured one. Absent on native lockstep forks.
    #[serde(default)]
    pub pause_skew_ns: Option<u64>,
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
    /// Last Firecracker cluster-fork pause skew on this tree, if any.
    #[serde(default)]
    pub pause_skew_ns: Option<u64>,
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

/// Fail Create when the node has disabled the virtiofs hostPath
/// fallback and the request still carries virtiofs shares.
fn deny_virtiofs_if_configured(config: &VmConfig) -> Result<(), String> {
    if config.virtiofs.is_empty() {
        return Ok(());
    }
    if crate::volumes::virtiofs_fallback_denied()? {
        return Err(crate::volumes::DENY_VIRTIOFS_FALLBACK_MSG.to_string());
    }
    Ok(())
}

/// Hand the config's host paths to the node broker for validation, at
/// the one point where a refusal is still free: the id is minted, no
/// disk is provisioned and no bridge reference is held (privilege
/// separation: path validation before any resource is acquired).
///
/// The error keeps the node broker's wording, which names the field and
/// the index, so `CreateVm` says which `hostPath` was refused.
fn register_with_broker(vm_id: &str, config: &VmConfig) -> Result<(), String> {
    crate::broker::client::register_vm(vm_id, config)
        .map_err(|e| format!("host path validation for {vm_id}: {e}"))
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
    /// When set, a failed attach fails `create_vm` (the VM and
    /// bridge slot are torn down). Omit the field (`None`) when
    /// there is no CNI — host-bridge networking is then correct
    /// and `pod_netns_attached` is `false`.
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
    /// `block_devices`. Unlike `scratch_size_bytes`
    /// these outlive the VM: `stop_vm` leaves the image on the reflink
    /// XFS, and only an explicit `delete_data_disk` (or the age-gated
    /// sweep of a vanished test run) removes it. Empty (the default)
    /// reproduces today's all-ephemeral behaviour exactly.
    ///
    /// An `id` is exclusive while a VM holding it is live: a second
    /// `create_vm` with the same id fails until `stop_vm`. Warm forks
    /// are unaffected — they reflink the image into the child and never
    /// share the parent's file.
    ///
    /// Each entry costs one virtio-blk device out of the guest's MMIO
    /// budget, like a per-container scratch disk.
    #[serde(default)]
    pub data_disks: Vec<DataDiskConfig>,
    /// When `Some`, attach a per-VM Docker graph scratch disk
    /// as the last read-write virtio-blk device, mounted at
    /// [`crate::disks::DOCKER_GRAPH_GUEST_MOUNT`], and put `k7d.docker=1`
    /// on the kernel cmdline so the agent supervises dockerd. `None`
    /// (the default) is today's behaviour.
    #[serde(default)]
    pub docker: Option<DockerConfig>,
    /// Optional caller-supplied sandbox identity, echoed in
    /// `list_vms` so a shim can find its VM after a restart.
    #[serde(default)]
    pub sandbox_id: Option<String>,
    /// Optional network attachment (bridge + TAP + pod netns).
    #[serde(default)]
    pub network: Option<NetConfig>,
    /// Continuous time dilation: guest time runs this
    /// many times faster than wall time, for the whole life of the VM.
    /// Absent or 1 is stock. Every member of a cluster is created from
    /// one `VmConfig`, so a cluster is dilated in lockstep by
    /// construction — the same invariant `WarpClock` keeps for offsets.
    ///
    /// A host without the carried KVM patch fails VM creation instead
    /// of running the guest at 1x.
    #[serde(default)]
    pub dilation: Option<u32>,
    /// VMM engine. Omitted / `"native"` is the in-process KVM VMM;
    /// `"firecracker"` is stock Firecracker under the stock jailer.
    /// A Firecracker VM has no network, no disks
    /// and no virtiofs — those fields are rejected rather than ignored.
    #[serde(default)]
    pub backend: Backend,
}

/// One **named persistent** data disk.
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

/// Per-VM Docker graph disk. Ephemeral scratch, reflinked
/// on fork, deleted with the VM — never a named [`DataDiskConfig`].
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DockerConfig {
    /// Capacity in bytes of the ext4 graph image.
    pub graph_size_bytes: u64,
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
            docker: None,
            sandbox_id: None,
            network: None,
            dilation: None,
            backend: Backend::default(),
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

/// `0` is never a factor. `None` inherits the source.
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
    /// How to reach the guest agent. A Firecracker sandbox is not
    /// reachable through `guest_cid` at all, so a shim that reattaches
    /// to one has to read this. Absent in records written before
    /// the Firecracker backend; those are native by definition.
    #[serde(default)]
    pub agent_endpoint: Option<AgentEndpoint>,
    /// VMM engine this sandbox's VM runs on.
    #[serde(default)]
    pub backend: Backend,
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
    /// Delete a **named persistent** data disk's image.
    ///
    /// The only way a data disk's data goes away: `stop_vm` deliberately
    /// retains it. Fails loudly when the image does not exist, or when
    /// a live VM still has it attached — unlinking a disk out from under
    /// a running guest is CHALLENGES #63's bug with a new name.
    DeleteDataDisk {
        /// Persistent identity given in `VmConfig.data_disks`.
        id: String,
    },
    /// Repoint a running VM's block device at another host file
    /// for the image-slot late fill.
    ///
    /// Firecracker only, and deliberately so. On the native backend the
    /// shim fills the slot's backing file in place, through the very
    /// inode the daemon's block backend opened at boot; there is no
    /// daemon call because there is nothing for the daemon to do. An
    /// out-of-process VMM has its own fd table, so the equivalent is
    /// asking it to re-open a path (`PATCH /drives`). Sending this to a
    /// native VM is an error, not a no-op — a shim that got the backend
    /// wrong must find out here and not from a guest mounting an empty
    /// device.
    UpdateDrive {
        /// VM identifier from `create_vm`.
        vm_id: String,
        /// Position of the device in `VmConfig.block_devices`, i.e. the
        /// `i` in the guest's `/dev/vd{a+i}`.
        device_index: usize,
        /// Host path of the file to serve the device from.
        host_path: String,
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
        /// Child dilation factor. `None` inherits the
        /// source's. `0` is a loud error.
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
    /// bridge by the same delta, so the guests' backoffs,
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
    /// bridge, so a cluster that is running out of CPU
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
    /// Start, switch or stop the auto-warp policy loop on one cluster:
    /// instead of being told "+90 s", the daemon
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
    /// form of the fifth safety check.
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
        /// Egress posture for the tree's bridges.
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
        /// Egress posture applied to the adopted bridge.
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
        /// Child dilation factor. `None` inherits the
        /// source's. A cluster applies one factor to every
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
        /// One child factor for every branch in the batch.
        /// `None` inherits the source's.
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
    /// crash. Nodes come back [`crate::tree::NodeState::Suspended`]
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

impl Request {
    /// Wire `op` name for the peer-cred audit log.
    fn op_name(&self) -> &'static str {
        match self {
            Self::Ping => "ping",
            Self::CreateVm { .. } => "create_vm",
            Self::VmStatus { .. } => "vm_status",
            Self::DumpSerial { .. } => "dump_serial",
            Self::ListVms => "list_vms",
            Self::StopVm { .. } => "stop_vm",
            Self::DeleteDataDisk { .. } => "delete_data_disk",
            Self::UpdateDrive { .. } => "update_drive",
            Self::LookupSandbox { .. } => "lookup_sandbox",
            Self::ReattachSandbox { .. } => "reattach_sandbox",
            Self::ForkVm { .. } => "fork_vm",
            Self::PauseVm { .. } => "pause_vm",
            Self::ResumeVm { .. } => "resume_vm",
            Self::WarpClock { .. } => "warp_clock",
            Self::SetDilation { .. } => "set_dilation",
            Self::AutoWarp { .. } => "auto_warp",
            Self::AutoWarpStatus { .. } => "auto_warp_status",
            Self::AutoWarpHold { .. } => "auto_warp_hold",
            Self::TreeCreate { .. } => "tree_create",
            Self::TreeCreateCluster { .. } => "tree_create_cluster",
            Self::TreeAdoptCluster { .. } => "tree_adopt_cluster",
            Self::TreeFork { .. } => "tree_fork",
            Self::TreeForkBatch { .. } => "tree_fork_batch",
            Self::TreePrepareForkSource { .. } => "tree_prepare_fork_source",
            Self::TreeRollback { .. } => "tree_rollback",
            Self::TreeProtect { .. } => "tree_protect",
            Self::TreeUnprotect { .. } => "tree_unprotect",
            Self::TreeSuspend { .. } => "tree_suspend",
            Self::TreeResume { .. } => "tree_resume",
            Self::TreePrune { .. } => "tree_prune",
            Self::TreeAutoEvict { .. } => "tree_auto_evict",
            Self::TreeNodes { .. } => "tree_nodes",
            Self::TreeList => "tree_list",
            Self::TreeWatch { .. } => "tree_watch",
            Self::TreeDrop { .. } => "tree_drop",
            Self::TreeOpen { .. } => "tree_open",
            Self::PoolStatus => "pool_status",
            Self::Doctor => "doctor",
        }
    }

    /// VM / tree writes that get an `info` peer-cred line.
    /// Reads log at `debug`.
    fn is_mutating(&self) -> bool {
        !matches!(
            self,
            Self::Ping
                | Self::VmStatus { .. }
                | Self::DumpSerial { .. }
                | Self::ListVms
                | Self::LookupSandbox { .. }
                | Self::AutoWarpStatus { .. }
                | Self::TreeNodes { .. }
                | Self::TreeList
                | Self::TreeWatch { .. }
                | Self::PoolStatus
                | Self::Doctor
        )
    }
}

/// One branch produced by [`Request::TreeForkBatch`].
#[derive(Debug, Serialize, Deserialize)]
pub struct TreeForkedBranch {
    /// The new branch's node id.
    pub node_id: String,
    /// Guest vsock CIDs of the new branch's members.
    pub guest_cids: Vec<u64>,
    /// How to reach each member's agent, in the same order. The only
    /// handle on a Firecracker member, whose `guest_cids` entry is
    /// absent.
    #[serde(default)]
    pub agent_endpoints: Vec<AgentEndpoint>,
    /// Per-member `CoW` vs full-copy flag (see [`Response::TreeForked`]).
    #[serde(default)]
    pub fork_memory_full_copy: Vec<bool>,
    /// Wall time of the whole batch (same value on every branch).
    /// Per-branch work is not timed separately — the batch is one
    /// dirty-bitmap capture.
    #[serde(default)]
    pub latency_ns: u64,
    /// Child dilation factor after the fork.
    #[serde(default = "default_dilation_one")]
    pub dilation: u32,
    /// Firecracker cluster-fork pause skew for this batch, when measured.
    #[serde(default)]
    pub pause_skew_ns: Option<u64>,
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
    /// VMM engine this VM runs on.
    #[serde(default)]
    pub backend: Backend,
    /// Host pid of the jailed Firecracker process, and the uid and
    /// chroot it runs under. `None` for native VMs, whose VMM is the
    /// daemon itself. `k7d doctor` prints these — for a jailed VMM
    /// they are the only handles an operator has on it.
    #[serde(default)]
    pub jail: Option<JailInfo>,
}

/// Where a Firecracker VM's VMM process lives.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct JailInfo {
    /// Host pid (pid 1 of its own pid namespace).
    pub pid: u32,
    /// Unprivileged uid == gid the jailer dropped it to.
    pub uid: u32,
    /// Host path of the directory it sees as `/`.
    pub chroot: String,
}

/// A control-plane response.
#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum Response {
    /// Reply to `ping`.
    Pong {
        /// Daemon version.
        version: String,
        /// Process-wide count of forks that took a full dump because a
        /// virtio-blk worker missed the 200 ms park deadline.
        #[serde(default)]
        fork_nonquiescent_blk: u64,
        /// Same, for virtio-net.
        #[serde(default)]
        fork_nonquiescent_net: u64,
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
        /// Whether the TAP was attached into the CNI pod netns.
        /// `true` only when `NetConfig.pod_netns` was set and attach
        /// succeeded; `false` when no netns was requested (host-bridge
        /// is then correct). A requested attach that fails is an
        /// error, not `false`.
        #[serde(default)]
        pod_netns_attached: bool,
        /// Whether this VM was served from the warm pool instead
        /// of cold-booted. Loud so tests can
        /// assert the fast path was taken rather than inferring it
        /// from timing.
        #[serde(default)]
        pooled: bool,
        /// How to reach this VM's guest agent. `Vsock { cid }` for
        /// native VMs (the same value as `guest_cid`), `FcUds { path }`
        /// for Firecracker ones, whose `guest_cid` is meaningless to
        /// the host. `None` only from a daemon without Firecracker support.
        #[serde(default)]
        agent_endpoint: Option<AgentEndpoint>,
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
        /// VMM engine this VM runs on.
        #[serde(default)]
        backend: Backend,
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
        /// How to reach the guest agent — what a reattaching shim
        /// dials. `None` only from a daemon without Firecracker support.
        #[serde(default)]
        agent_endpoint: Option<AgentEndpoint>,
        /// VMM engine this sandbox's VM runs on.
        #[serde(default)]
        backend: Backend,
    },
    /// Reply to `fork_vm`.
    VmForked {
        /// New VM identifier.
        vm_id: String,
        /// The fork's guest vsock CID. Firecracker forks are not
        /// reachable over `AF_VSOCK`; this is 0 (`VMADDR_CID_HYPERVISOR`)
        /// and the shim must use `agent_endpoint`.
        guest_cid: u64,
        /// The source's guest vsock CID. Preserved across the first
        /// fork's prepare swap — echoed back so
        /// clients can assert it, not because it changes.
        source_guest_cid: u64,
        /// Child dilation factor after the fork.
        #[serde(default = "default_dilation_one")]
        dilation: u32,
        /// How to reach the child's guest agent. Required for
        /// Firecracker (`FcUds`); native is `Vsock`.
        #[serde(default)]
        agent_endpoint: Option<AgentEndpoint>,
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
        /// Agent endpoints of the same members, same order. Empty
        /// `guest_cids` plus `FcUds` entries here is a Firecracker tree.
        #[serde(default)]
        agent_endpoints: Vec<AgentEndpoint>,
    },
    /// Reply to `tree_fork` / `tree_rollback`.
    TreeForked {
        /// The new branch's node id.
        node_id: String,
        /// Guest vsock CIDs of the new branch's members.
        guest_cids: Vec<u64>,
        /// Agent endpoints of the same members, same order.
        #[serde(default)]
        agent_endpoints: Vec<AgentEndpoint>,
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
        /// Child dilation factor after the fork.
        #[serde(default = "default_dilation_one")]
        dilation: u32,
        /// Firecracker cluster-fork pause skew (`max − min`), when this
        /// fork paused members in parallel. `None` on native lockstep.
        #[serde(default)]
        pause_skew_ns: Option<u64>,
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
        /// Firecracker cluster-fork pause skew for the batch.
        #[serde(default)]
        pause_skew_ns: Option<u64>,
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
        /// node's dirty pages, costing O(divergence) instead
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
        /// Agent endpoints after prepare, same order.
        #[serde(default)]
        agent_endpoints: Vec<AgentEndpoint>,
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
        /// (measured here, not around the socket).
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
        /// Agent endpoints of the resumed members, same order.
        #[serde(default)]
        agent_endpoints: Vec<AgentEndpoint>,
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
        /// Live agent endpoints keyed by node id, same shape.
        #[serde(default)]
        live_agent_endpoints: HashMap<String, Vec<AgentEndpoint>>,
        /// Time dilation factor of each live node (a
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
        /// Firecracker cluster-fork pause skew, when measured.
        #[serde(default)]
        pause_skew_ns: Option<u64>,
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
        /// `snapshot_type` Firecracker fork points are taken with
        /// (`diff` | `full`, from `K7D_FC_FORK_SNAPSHOT`).
        /// Reported here because a pin-around must be visible, not a
        /// silent fallback.
        #[serde(default)]
        fc_fork_mode: String,
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
/// though the control plane never reads it back yet: holding the `Guest`
/// keeps the guest alive, and dropping the entry (on `stop_vm` /
/// `shutdown_all`) runs `Guest`/`Vm::drop`, which tears down the vCPU
/// thread, device workers, virtiofsd children, and TAP. The fork,
/// snapshot and tree paths read it.
struct VmEntry {
    #[allow(dead_code)]
    vm: Guest,
    /// The threaded CPU cgroup capping this VM's vCPU
    /// threads at the pod's CFS quota. Held only for its `Drop`
    /// (like `vm`): declared AFTER `vm` — struct fields drop in
    /// declaration order, so the vCPU thread is joined (by
    /// `Guest`/`Vm::drop`) before the cgroup directory is removed.
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
    agent_endpoint: AgentEndpoint,
}

/// One snapshot tree owned by the daemon — single-VM or
/// cluster. Both expose the same lifecycle verbs; the enum
/// keeps one registry and one set of control-plane handlers.
enum TreePayload {
    Single(SnapshotTree),
    Cluster(ClusterSnapshotTree),
}

impl TreePayload {
    fn live_cluster_members_mut(&mut self, node_id: &str) -> Option<&mut [Guest]> {
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
    fn find_live_vm_by_cid(&self, cid: u64) -> Option<(&str, &Guest)> {
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

    /// Live guests of a node, ordered by member index. Empty when the
    /// node has no live payload. Works for Firecracker, whose
    /// [`Self::node_cids`] is empty.
    fn node_guests(&self, node_id: &str) -> Vec<&Guest> {
        let key = node_id.to_string();
        match self {
            Self::Single(t) => t.get_vm(&key).into_iter().collect(),
            Self::Cluster(t) => t
                .get_payload(&key)
                .map(|p| p.members.iter().collect())
                .unwrap_or_default(),
        }
    }

    /// Guest vsock CIDs of a node's live members, ordered by member
    /// index. Empty when the node has no live payload.
    fn node_cids(&self, node_id: &String) -> Vec<u64> {
        match self {
            Self::Single(t) => t
                .get_vm(node_id)
                .map(|g| g.guest_cid().into_iter().collect())
                .unwrap_or_default(),
            Self::Cluster(t) => t
                .get_payload(node_id)
                .map(|p| p.members.iter().filter_map(Guest::guest_cid).collect())
                .unwrap_or_default(),
        }
    }

    /// Agent endpoints of a node's live members, ordered like
    /// [`Self::node_cids`]. Non-empty for a live Firecracker node whose
    /// `node_cids` is empty.
    fn node_endpoints(&self, node_id: &String) -> Vec<AgentEndpoint> {
        match self {
            Self::Single(t) => t
                .get_vm(node_id)
                .map(|g| vec![g.agent_endpoint()])
                .unwrap_or_default(),
            Self::Cluster(t) => t
                .get_payload(node_id)
                .map(|p| p.members.iter().map(Guest::agent_endpoint).collect())
                .unwrap_or_default(),
        }
    }

    fn last_pause_skew_ns(&self) -> Option<u64> {
        match self {
            Self::Cluster(t) => t.last_pause_skew_ns(),
            Self::Single(_) => None,
        }
    }

    /// Time dilation factor of a node's live payload; `None` when it has
    /// none. A cluster's members are built from one `VmConfig` and
    /// forked from one state, so the first member speaks for all.
    fn node_dilation(&self, node_id: &String) -> Option<u32> {
        match self {
            Self::Single(t) => t
                .get_vm(node_id)
                .and_then(|g| g.as_native().ok().map(Vm::dilation)),
            Self::Cluster(t) => t.get_payload(node_id).and_then(|p| {
                p.members
                    .first()
                    .and_then(|g| g.as_native().ok().map(Vm::dilation))
            }),
        }
    }

    /// Per-member `fork_memory_is_full_copy` of a node's live members,
    /// ordered like [`Self::node_cids`]. Empty when the node has no
    /// live payload.
    fn node_fork_full_copy(&self, node_id: &String) -> Vec<bool> {
        match self {
            Self::Single(t) => t
                .get_vm(node_id)
                .map(|g| vec![g.fork_memory_is_full_copy()])
                .unwrap_or_default(),
            Self::Cluster(t) => t
                .get_payload(node_id)
                .map(|p| {
                    p.members
                        .iter()
                        .map(Guest::fork_memory_is_full_copy)
                        .collect()
                })
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

    /// Live agent endpoints keyed by node id ([`Self::live_guest_cids`]'s
    /// backend-agnostic twin).
    fn live_agent_endpoints(&self) -> HashMap<String, Vec<AgentEndpoint>> {
        self.list_nodes()
            .into_iter()
            .map(|n| (n.id.clone(), self.node_endpoints(&n.id)))
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
            live_agent_endpoints: self.live_agent_endpoints(),
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
            pause_skew_ns: self.last_pause_skew_ns(),
        }
    }
}

/// The daemon's VM registry and request dispatcher.
pub struct Daemon {
    /// Live VMs. `Arc` because the auto-warp policy loop runs on its
    /// own thread and takes this same lock for
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
    /// Auto-warp policy loops, keyed by `cluster_id`.
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
) -> Option<&'a mut [Guest]> {
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

/// What a tree payload VM may not carry, on either backend: it is
/// owned by the `SnapshotTree` and forked repeatedly, so everything a
/// sandbox VM gets for its own writable layer or persistent identity is
/// refused here by name.
fn deny_tree_payload_extras(config: &VmConfig) -> Result<(), String> {
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
    if config.docker.is_some() {
        return Err(
            "docker is not supported for tree payload VMs — attach it to the sandbox \
             VMs the tree adopts instead"
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
    Ok(())
}

/// Fields `create_vm` cannot honour on Firecracker.
///
/// Both of these are permanent, not increments: Firecracker has no
/// vhost-user-fs device, and time dilation is a property of k7d owning
/// the guest's kvmclock. Rejecting them is the
/// point — a pod that asked for a hostPath mount and silently got a VM
/// without one would fail much later, inside the guest, as an empty
/// directory.
fn deny_fc_unsupported(config: &VmConfig) -> Result<(), String> {
    let unsupported: &[(bool, &'static str)] = &[
        (!config.virtiofs.is_empty(), "virtiofs"),
        (config.dilation.is_some(), "dilation"),
    ];
    for (present, op) in unsupported {
        if *present {
            return Err(GuestError::Unsupported {
                backend: Backend::Firecracker,
                op,
            }
            .to_string());
        }
    }
    Ok(())
}

/// Everything a Firecracker VM's chroot has to be given, in guest
/// device order, plus the host-side handles that must outlive it.
struct FcAttachments {
    drives: Vec<crate::fc::FcDrive>,
    disks: Vec<crate::fc::FcDisk>,
    /// `vd{letter}:{mount}:{fstype}:{ro|rw}` for every drive the guest
    /// agent has to mount, built in the same loop as `drives` so the
    /// letters cannot drift from the device order.
    blk_mounts: Vec<String>,
}

/// A failed FC start, carrying the bridge slot to free.
///
/// The `vm_index` is the only thing the caller cannot recover for
/// itself: the TAP allocation happens inside the start, so a failure
/// after it has to say which slot on the bridge is now unused, or the
/// identity leaks and the next pod on that cluster gets the one after.
struct FcStartError {
    message: String,
    vm_index: Option<u32>,
}

/// What a successful [`Daemon::spawn_fc`] hands back: the live VM (which
/// owns its TAP) and its slot on the cluster bridge.
type SpawnedFc = (crate::fc::FcVm, Option<u32>);

/// `a`..`z` for a block device index, or `?` past the 26 the guest can
/// name. Log-only: the create path rejects an over-long device list.
fn device_letter(index: usize) -> char {
    u8::try_from(index)
        .ok()
        .filter(|i| *i < 26)
        .map_or('?', |i| char::from(b'a' + i))
}

/// Build the drive list for `config` in exactly the order the native
/// backend attaches devices, so `/dev/vdX` means the same thing on both
/// backends.
///
/// That order is not incidental: the shim computes a guest device name
/// from a device's index in `VmConfig.block_devices` (and the daemon
/// documents scratch / container-scratch / data / docker disks as
/// coming after them, in that sequence) at a point where it has no
/// other handle on the device. Any divergence here would surface as a
/// container mounting the wrong disk, silently.
#[allow(clippy::too_many_lines)]
fn fc_attachments(vm_id: &str, config: &VmConfig, live: &Daemon) -> Result<FcAttachments, String> {
    let mut drives = Vec::new();
    let mut disks = Vec::new();
    let mut blk_mounts = Vec::new();

    for (i, blk) in config.block_devices.iter().enumerate() {
        let host_path = PathBuf::from(&blk.host_path);
        let mount = match (&blk.guest_mount, &blk.fstype) {
            (Some(gm), Some(fstype)) => Some((gm.as_str(), fstype.as_str())),
            (None, None) => None,
            _ => {
                return Err(format!(
                    "block device {}: guest_mount and fstype must be set together",
                    blk.host_path
                ))
            }
        };
        // A writable caller-declared image is not one of k7d's own
        // disks, so it has no `ScratchDisk`/`DataDisk` handle; the
        // caller owns its lifetime, as on the native backend.
        push_drive(
            &mut drives,
            &mut blk_mounts,
            crate::fc::FcDrive {
                name: format!("blk{i}-{}", file_stem_for_jail(&host_path)),
                host_path,
                read_only: blk.readonly,
            },
            mount,
        )?;
    }

    if let Some(size) = config.scratch_size_bytes {
        let disk = crate::disks::ScratchDisk::create(vm_id, size)
            .map_err(|e| format!("provision scratch disk for {vm_id}: {e}"))?;
        push_drive(
            &mut drives,
            &mut blk_mounts,
            crate::fc::FcDrive {
                name: "scratch.ext4".to_string(),
                host_path: disk.path().to_path_buf(),
                read_only: false,
            },
            Some((crate::disks::SCRATCH_GUEST_MOUNT, "ext4")),
        )?;
        disks.push(crate::fc::FcDisk::Scratch(disk));
    }

    for (i, cs) in config.container_scratch.iter().enumerate() {
        if config.container_scratch[..i]
            .iter()
            .any(|prev| prev.name == cs.name)
        {
            return Err(format!(
                "container_scratch names container {:?} twice",
                cs.name
            ));
        }
        let disk =
            crate::disks::ScratchDisk::create(&format!("{vm_id}-c-{}", cs.name), cs.size_bytes)
                .map_err(|e| format!("provision scratch disk for container {}: {e}", cs.name))?;
        let mount = crate::disks::container_scratch_mount(&cs.name);
        push_drive(
            &mut drives,
            &mut blk_mounts,
            crate::fc::FcDrive {
                name: format!("cscratch-{i}.ext4"),
                host_path: disk.path().to_path_buf(),
                read_only: false,
            },
            Some((&mount, "ext4")),
        )?;
        disks.push(crate::fc::FcDisk::Scratch(disk));
    }

    for (i, dd) in config.data_disks.iter().enumerate() {
        if config.data_disks[..i].iter().any(|prev| prev.id == dd.id) {
            return Err(format!("data_disks names disk {:?} twice", dd.id));
        }
        if config.data_disks[..i]
            .iter()
            .any(|prev| prev.guest_mount == dd.guest_mount)
        {
            return Err(format!(
                "data_disks mounts two disks at {:?}",
                dd.guest_mount
            ));
        }
        if let Some(holder) = live.live_data_disk_holder(&dd.id) {
            return Err(format!(
                "data disk {:?} is attached to live VM {holder} — stop it or use another id",
                dd.id
            ));
        }
        let disk = crate::disks::DataDisk::attach(&dd.id, dd.size_bytes, &dd.guest_mount)
            .map_err(|e| format!("attach data disk {}: {e}", dd.id))?;
        push_drive(
            &mut drives,
            &mut blk_mounts,
            crate::fc::FcDrive {
                name: format!("data-{i}.ext4"),
                host_path: disk.path().to_path_buf(),
                read_only: false,
            },
            Some((disk.guest_mount(), "ext4")),
        )?;
        disks.push(crate::fc::FcDisk::Data(disk));
    }

    if let Some(ref docker) = config.docker {
        let disk =
            crate::disks::ScratchDisk::create(&format!("{vm_id}-docker"), docker.graph_size_bytes)
                .map_err(|e| format!("provision docker graph disk for {vm_id}: {e}"))?;
        push_drive(
            &mut drives,
            &mut blk_mounts,
            crate::fc::FcDrive {
                name: "docker.ext4".to_string(),
                host_path: disk.path().to_path_buf(),
                read_only: false,
            },
            Some((crate::disks::DOCKER_GRAPH_GUEST_MOUNT, "ext4")),
        )?;
        disks.push(crate::fc::FcDisk::Scratch(disk));
    }

    Ok(FcAttachments {
        drives,
        disks,
        blk_mounts,
    })
}

/// Append one drive, and — when the guest agent has to mount it — the
/// `k7d.blk=` entry naming the `/dev/vdX` this position gives it.
///
/// Both in one call because the guest device letter *is* the drive's
/// index: building the mount list anywhere else would be a second
/// ordering to keep in step with the first, and the failure mode of
/// them drifting is a container quietly mounting the wrong disk. The
/// validation mirrors the native builder's so a spec the native backend
/// rejects does not boot on Firecracker.
fn push_drive(
    drives: &mut Vec<crate::fc::FcDrive>,
    blk_mounts: &mut Vec<String>,
    drive: crate::fc::FcDrive,
    mount: Option<(&str, &str)>,
) -> Result<(), String> {
    let index = drives.len();
    if let Some((guest_mount, fstype)) = mount {
        if index >= 26 || guest_mount.contains([':', ',']) || fstype.contains([':', ',']) {
            return Err(format!(
                "invalid block mount spec for device {index} (max 26 mounted devices; \
                 mount/fstype must not contain ':' or ','): {guest_mount:?} {fstype:?}"
            ));
        }
        blk_mounts.push(format!(
            "vd{}:{guest_mount}:{fstype}:{}",
            device_letter(index),
            if drive.read_only { "ro" } else { "rw" }
        ));
    }
    drives.push(drive);
    Ok(())
}

/// The boot args a Firecracker guest needs on top of the caller's
/// cmdline: the same `k7d.blk=` / `k7d.mkdir=` / `k7d.docker=1` tokens
/// [`crate::vm::VmBuilder::build`] appends while it attaches devices.
///
/// The native backend can append them there because it builds the
/// cmdline and the devices together. Firecracker takes `boot_args` as
/// one opaque string before any drive is declared, so the equivalent
/// has to be assembled here — and it is the *only* thing that tells the
/// agent a device exists. `virtio_mmio.device=` is absent on purpose:
/// Firecracker emits its own, and `k7d.virtiofs=` cannot appear because
/// this backend refuses virtiofs outright.
fn fc_cmdline(base: &str, blk_mounts: &[String], config: &VmConfig) -> Result<String, String> {
    let mut cmdline = base.to_string();
    if !blk_mounts.is_empty() {
        cmdline.push_str(&format!(" k7d.blk={}", blk_mounts.join(",")));
    }
    for dir in &config.guest_dirs {
        if !dir.starts_with('/') || dir.contains([',', ' ']) {
            return Err(format!(
                "invalid guest dir {dir:?}: must be absolute and contain no ',' or space"
            ));
        }
    }
    if !config.guest_dirs.is_empty() {
        cmdline.push_str(&format!(" k7d.mkdir={}", config.guest_dirs.join(",")));
    }
    if config.docker.is_some() {
        cmdline.push_str(" k7d.docker=1");
    }
    Ok(cmdline)
}

/// A file name safe to use inside a jail: the source's stem, stripped
/// of anything that is not `[A-Za-z0-9._-]`.
///
/// The name is cosmetic (the drive is addressed by `drive_id`), but it
/// is the only thing an operator staring at `/proc/<pid>/fd` has to go
/// on, so it keeps enough of the host name to be recognisable.
fn file_stem_for_jail(path: &Path) -> String {
    let raw = path
        .file_name()
        .map_or_else(|| "img".to_string(), |n| n.to_string_lossy().into_owned());
    let cleaned: String = raw
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '.' || c == '_' || c == '-' {
                c
            } else {
                '-'
            }
        })
        .collect();
    cleaned
        .chars()
        .rev()
        .take(48)
        .collect::<Vec<_>>()
        .into_iter()
        .rev()
        .collect()
}

/// CID stored in the registry and the sandbox record.
///
/// Native guests are reachable at a host-global `AF_VSOCK` CID.
/// Firecracker guests are not reachable over `AF_VSOCK` at all, so
/// theirs is `0` — `VMADDR_CID_HYPERVISOR`, which is never a guest —
/// and the response's `agent_endpoint` is what a client must use.
const NO_HOST_CID: u64 = 0;

fn registry_cid(g: &Guest) -> u64 {
    g.guest_cid().unwrap_or(NO_HOST_CID)
}

fn native(g: &Guest) -> Result<&Vm, String> {
    g.as_native().map_err(|e| e.to_string())
}

fn native_mut(g: &mut Guest) -> Result<&mut Vm, String> {
    g.as_native_mut().map_err(|e| e.to_string())
}

/// Refuse a native-only cluster verb, naming the verb.
///
/// The `as_native_mut` these handlers reach for further down does
/// refuse, but it says "native VMM access is not supported" — true, and
/// useless to the caller, who asked for `warp_clock` and gets told
/// about an accessor it has never heard of. The op has to be named,
/// so the check happens here, before the collect.
fn deny_non_native_members<'a, I>(vms: I, op: &'static str) -> Option<String>
where
    I: IntoIterator<Item = (&'a str, &'a Guest)>,
{
    let (vm_id, backend) = vms
        .into_iter()
        .map(|(id, g)| (id, g.backend()))
        .find(|(_, b)| *b != Backend::Native)?;
    Some(format!(
        "{}: VM {vm_id} runs on it",
        GuestError::Unsupported { backend, op }
    ))
}

/// Daemon-unique suffix for a Firecracker tree root's jailer id.
fn fc_tree_root_seq() -> u64 {
    static NEXT: AtomicU64 = AtomicU64::new(0);
    NEXT.fetch_add(1, Ordering::SeqCst)
}

fn guest_cid_u64(g: &Guest) -> Result<u64, String> {
    g.guest_cid()
        .ok_or_else(|| format!("{:?} guest has no vsock CID", g.backend()))
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

    /// Take over the Firecracker sandboxes the node broker kept back
    /// from a VM broker that died (`K7D_VM_BROKER_RESTART`).
    ///
    /// A no-op in every process but a **successor** VM broker: the
    /// first generation has nothing to inherit, and an un-split daemon
    /// has no node broker. Called from `main` **before**
    /// [`Self::clean_stale_sandbox_records`], which would otherwise
    /// delete the reattach records these VMs are matched against —
    /// they are the one piece of the previous VM broker's state that
    /// outlived it on disk, and a jail with no record is a jail nobody
    /// can ever name again, so it is killed here rather than kept.
    ///
    /// Trees, the warm pool, native VMs and fork children were released
    /// by the node broker before this process existed
    /// (`broker::node::survives`); what `fc.list` answers is already
    /// the set that qualifies, and each entry is re-checked against its
    /// record anyway.
    pub fn readopt_fc_sandboxes(&self) {
        use crate::broker::client;
        let epoch = client::restart_epoch();
        if !client::is_split() || epoch == 0 {
            return;
        }
        let held = match client::fc_list() {
            Ok(held) => held,
            Err(e) => {
                log::error!("VM broker generation {epoch}: fc.list: {e} — nothing re-adopted");
                return;
            }
        };
        log::info!(
            "VM broker generation {epoch}: the node broker holds {} Firecracker jail(s) from the \
             previous generation",
            held.len()
        );
        let mut adopted = 0usize;
        for jail in held {
            let vm_id = jail.record.vm_id.clone();
            match self.readopt_one(jail) {
                Ok(sandbox_id) => {
                    adopted += 1;
                    log::warn!(
                        "survived: {vm_id} (sandbox {sandbox_id}) re-adopted from VM broker \
                         generation {}",
                        epoch - 1
                    );
                }
                Err(e) => {
                    log::error!("cannot re-adopt {vm_id}: {e}; killing it");
                    Self::discard_jail(&vm_id);
                }
            }
        }
        log::info!("VM broker generation {epoch}: {adopted} Firecracker sandbox(es) re-adopted");
    }

    /// `fc.kill` a held jail this process will not adopt, and drop its
    /// registration. Idempotent on both counts.
    fn discard_jail(vm_id: &str) {
        if let Err(e) = crate::broker::client::ok(&crate::broker::Verb::FcKill {
            vm_id: vm_id.to_string(),
        }) {
            log::error!("fc.kill({vm_id}) on a jail that was not re-adopted: {e}");
        }
        crate::broker::client::release_vm(vm_id);
    }

    /// One jail of [`Self::readopt_fc_sandboxes`]: match it to its
    /// reattach record, rebuild the bridge mirror and the TAP slot when
    /// it is networked, rebuild the `FcVm`, re-hold its disks, and
    /// register it under the **same** `vm_id` and sandbox — without
    /// rewriting the record, whose `created_at_unix` is the pod's, not
    /// this process's. Returns the sandbox id.
    fn readopt_one(&self, held: crate::broker::client::HeldJail) -> Result<String, String> {
        let record = &held.record;
        let vm_id = record.vm_id.clone();
        let sandbox_id = record
            .sandbox_id
            .clone()
            .ok_or_else(|| "no sandbox id — nothing can name it again".to_string())?;
        let path = sandbox_record_path(&sandbox_id);
        let saved: SandboxRecord = std::fs::read_to_string(&path)
            .map_err(|e| {
                format!(
                    "no reattach record at {} ({e}) — the previous VM broker died before it \
                     wrote one",
                    path.display()
                )
            })
            .and_then(|s| {
                serde_json::from_str(&s).map_err(|e| format!("record {}: {e}", path.display()))
            })?;
        if saved.vm_id != vm_id {
            return Err(format!(
                "record {} names vm {}, the jail is {vm_id}",
                path.display(),
                saved.vm_id
            ));
        }
        if saved.backend != Backend::Firecracker {
            return Err(format!(
                "record {} says backend {:?}",
                path.display(),
                saved.backend
            ));
        }
        if self.vms.lock().unwrap().contains_key(&vm_id) {
            return Err(format!("{vm_id} is already registered in this process"));
        }

        // The bridge mirror and the TAP slot first, so a failure below
        // releases them the way a failed boot does.
        let networked = match (record.tap, &saved.cluster_id, saved.vm_index) {
            (true, Some(cluster_id), Some(vm_index)) => Some((cluster_id.clone(), vm_index)),
            (false, None, _) => None,
            (tap, cluster, index) => {
                return Err(format!(
                    "the jail {} a TAP but the record says cluster {cluster:?}, vm_index {index:?}",
                    if tap { "has" } else { "has not" }
                ))
            }
        };
        let tap = match &networked {
            Some((cluster_id, vm_index)) => Some(self.readopt_tap(cluster_id, *vm_index)?),
            None => None,
        };
        let release_net = |why: String| -> String {
            if let Some((cluster_id, vm_index)) = &networked {
                Self::release_bridge_locked(
                    &mut self.bridges.lock().unwrap(),
                    cluster_id,
                    Some(*vm_index),
                );
            }
            why
        };

        let mut fc = match crate::fc::FcVm::readopt(held, tap) {
            Ok(fc) => fc,
            Err(e) => return Err(release_net(e.to_string())),
        };
        let disks = match Self::readopt_disks(&fc) {
            Ok(disks) => disks,
            // Dropping `fc` here is the `fc.kill`.
            Err(e) => return Err(release_net(e)),
        };
        fc.adopt_disks(disks);

        let guest: Guest = fc.into();
        self.vms.lock().unwrap().insert(
            vm_id.clone(),
            VmEntry {
                vm: guest,
                // As at create: the jailer's cgroup caps this VM, and
                // no vCPU thread of this process exists to cap.
                cpu_cgroup: None,
                cpu_quota: saved.cpu_quota,
                cpu_period: saved.cpu_period,
                guest_cid: NO_HOST_CID,
                sandbox_id: Some(sandbox_id.clone()),
                cluster_id: saved.cluster_id.clone(),
                vm_index: saved.vm_index,
                pod_netns: saved.pod_netns.as_ref().map(PathBuf::from),
            },
        );
        self.sandboxes
            .lock()
            .unwrap()
            .insert(sandbox_id.clone(), vm_id);
        Ok(sandbox_id)
    }

    /// The bridge mirror (created if this is the first re-adopted VM on
    /// it — `net.tree_create` is idempotent on the node broker, which
    /// still holds the bridge) and the TAP slot of a re-adopted VM.
    fn readopt_tap(&self, cluster_id: &str, vm_index: u32) -> Result<TapDevice, String> {
        let mut bridges = self.bridges.lock().unwrap();
        if !bridges.contains_key(cluster_id) {
            let net = ClusterNetwork::create(cluster_id)
                .map_err(|e| format!("ClusterNetwork::create({cluster_id}): {e}"))?;
            bridges.insert(cluster_id.to_string(), BridgeEntry { net, refcount: 0 });
        }
        let entry = bridges
            .get_mut(cluster_id)
            .expect("bridge entry just ensured");
        match entry.net.adopt_tap(vm_index) {
            Ok(tap) => {
                entry.refcount += 1;
                Ok(tap)
            }
            Err(e) => {
                if entry.refcount == 0 {
                    bridges.remove(cluster_id);
                }
                Err(format!("adopt_tap({vm_index}): {e}"))
            }
        }
    }

    /// Re-hold the k7d-owned writable disks of a re-adopted VM, so a
    /// scratch image is still unlinked when the VM goes and a data disk
    /// is still refused to a second VM while this one has it. Which is
    /// which is decided the way [`fc_attachments`] decided it: by where
    /// the backing file lives. A caller-declared writable block device
    /// and a restored VM's jail-side clone have no handle, as at create.
    fn readopt_disks(fc: &crate::fc::FcVm) -> Result<Vec<crate::fc::FcDisk>, String> {
        // `k7d.blk=vdX:<mount>:<fstype>:<rw|ro>,…`: the guest mount of
        // each device, by position, which a `DataDisk` has to be
        // re-attached with.
        let mounts: HashMap<usize, String> = fc
            .cmdline()
            .split_whitespace()
            .find_map(|tok| tok.strip_prefix("k7d.blk="))
            .into_iter()
            .flat_map(|list| list.split(','))
            .filter_map(|spec| {
                let mut parts = spec.split(':');
                let dev = parts.next()?.strip_prefix("vd")?;
                let letter = dev.chars().next().filter(|_| dev.len() == 1)?;
                let index = usize::from(u8::try_from(letter).ok()?.checked_sub(b'a')?);
                Some((index, parts.next()?.to_string()))
            })
            .collect();
        let scratch_dir = Path::new(crate::disks::DISKS_DIR);
        let data_dir = crate::disks::data_disks_dir();
        let mut disks = Vec::new();
        for (index, drive) in fc.writable_drives() {
            let host = drive.host_path.as_path();
            let is_scratch = host.parent() == Some(scratch_dir)
                && host
                    .file_name()
                    .and_then(|n| n.to_str())
                    .is_some_and(|n| n.starts_with("scratch-"));
            if is_scratch {
                let disk = crate::disks::ScratchDisk::adopt(host)
                    .map_err(|e| format!("re-hold scratch {}: {e}", host.display()))?;
                disks.push(crate::fc::FcDisk::Scratch(disk));
            } else if host.parent() == Some(data_dir.as_path()) {
                let id = host
                    .file_stem()
                    .and_then(|s| s.to_str())
                    .ok_or_else(|| format!("data disk {} has no usable name", host.display()))?;
                let mount = mounts.get(&index).ok_or_else(|| {
                    format!(
                        "data disk {id} at drive {index} has no k7d.blk= mount in the boot args"
                    )
                })?;
                let size = std::fs::metadata(host)
                    .map_err(|e| format!("stat data disk {}: {e}", host.display()))?
                    .len();
                let disk = crate::disks::DataDisk::attach(id, size, mount)
                    .map_err(|e| format!("re-attach data disk {id}: {e}"))?;
                disks.push(crate::fc::FcDisk::Data(disk));
            }
        }
        Ok(disks)
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
            Request::Ping => {
                let c = crate::virtio_mmio::fork_nonquiescent_counts();
                Response::Pong {
                    version: env!("CARGO_PKG_VERSION").to_string(),
                    fork_nonquiescent_blk: c.virtio_blk,
                    fork_nonquiescent_net: c.virtio_net,
                }
            }
            Request::CreateVm { config } => self.create_vm(config),
            Request::VmStatus { vm_id } => self.vm_status(&vm_id),
            Request::DumpSerial { vm_id, guest_cid } => {
                self.dump_serial(vm_id.as_deref(), guest_cid)
            }
            Request::ListVms => self.list_vms(),
            Request::StopVm { vm_id } => self.stop_vm(&vm_id),
            Request::DeleteDataDisk { id } => self.delete_data_disk(&id),
            Request::UpdateDrive {
                vm_id,
                device_index,
                host_path,
            } => self.update_drive(&vm_id, device_index, Path::new(&host_path)),
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
                                let agent_endpoints = t.node_endpoints(&node_id);
                                let fork_memory_full_copy = t.node_fork_full_copy(&node_id);
                                let dilation = t.node_dilation(&node_id).unwrap_or(1);
                                let pause_skew_ns = t.last_pause_skew_ns();
                                Response::TreeForked {
                                    node_id,
                                    guest_cids,
                                    agent_endpoints,
                                    fork_memory_full_copy,
                                    latency_ns,
                                    dilation,
                                    pause_skew_ns,
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
                                let pause_skew_ns = t.last_pause_skew_ns();
                                let forks = node_ids
                                    .into_iter()
                                    .map(|node_id| TreeForkedBranch {
                                        guest_cids: t.node_cids(&node_id),
                                        agent_endpoints: t.node_endpoints(&node_id),
                                        fork_memory_full_copy: t.node_fork_full_copy(&node_id),
                                        dilation: t.node_dilation(&node_id).unwrap_or(1),
                                        node_id,
                                        latency_ns,
                                        pause_skew_ns,
                                    })
                                    .collect();
                                Response::TreeForkBatch {
                                    forks,
                                    latency_ns,
                                    pause_skew_ns,
                                }
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
                                agent_endpoints: t.node_endpoints(&node_id),
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
                                agent_endpoints: t.node_endpoints(&node_id),
                                fork_memory_full_copy: t.node_fork_full_copy(&node_id),
                                node_id,
                                latency_ns,
                                dilation,
                                pause_skew_ns: t.last_pause_skew_ns(),
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
                        agent_endpoints: t.node_endpoints(&node_id),
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
                    fc_fork_mode: crate::fc::snapshot::fork_mode()
                        .map_or_else(|e| format!("invalid ({e})"), |m| m.env_name().to_string()),
                    details: report.lines(),
                }
            }
        }
    }

    fn create_vm(&self, config: VmConfig) -> Response {
        // Pool first for either backend. A miss
        // (incompatible, empty, or no matching engine) cold-boots —
        // never an error.
        if let Some(ref pool) = self.pool {
            if pool.compatible(&config) {
                if let Some(vm) = pool.acquire(config.backend) {
                    let guest_cid = registry_cid(&vm);
                    let vm_id = self.mint_vm_id();
                    let agent_endpoint = vm.agent_endpoint();
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
                                agent_endpoint: Some(agent_endpoint),
                            }
                        }
                        Err(message) => Response::Error { message },
                    };
                }
            } else {
                pool.note_miss();
            }
        }
        if config.backend == Backend::Firecracker {
            return match self.build_and_start_fc(config) {
                Ok(created) => Response::VmCreated {
                    vm_id: created.vm_id,
                    guest_cid: created.guest_cid,
                    vm_index: created.vm_index,
                    pod_netns_attached: created.pod_netns_attached,
                    pooled: false,
                    agent_endpoint: Some(created.agent_endpoint),
                },
                Err(message) => Response::Error { message },
            };
        }
        if let Err(message) = deny_virtiofs_if_configured(&config) {
            return Response::Error { message };
        }
        match self.build_and_start(config) {
            Ok(created) => Response::VmCreated {
                vm_id: created.vm_id,
                guest_cid: created.guest_cid,
                vm_index: created.vm_index,
                pod_netns_attached: created.pod_netns_attached,
                pooled: false,
                agent_endpoint: Some(created.agent_endpoint),
            },
            Err(message) => Response::Error { message },
        }
    }

    /// Boot `config` on stock Firecracker under the stock jailer.
    ///
    /// The warm pool is tried in [`Self::create_vm`] before this path;
    /// a miss lands here. Everything else a `runtimeClassName: k7` pod
    /// needs is here — erofs and image-slot drives, scratch /
    /// container-scratch / data / docker disks, and a TAP on the
    /// cluster bridge.
    #[allow(clippy::too_many_lines)]
    fn build_and_start_fc(&self, config: VmConfig) -> Result<CreatedVm, String> {
        deny_fc_unsupported(&config)?;
        let artifacts = Self::resolve_vm_guest(&config)?;
        let vm_id = self.mint_vm_id();
        register_with_broker(&vm_id, &config)?;
        let base_cmdline = config
            .cmdline
            .clone()
            .unwrap_or_else(|| crate::vm::DEFAULT_GUEST_CMDLINE.to_string());
        if base_cmdline.trim().is_empty() {
            return Err(
                "config.cmdline is empty; omit the field to keep the builder default".to_string(),
            );
        }
        log::info!(
            "guest artifacts: kernel={} initrd={} backend=firecracker (from {})",
            artifacts.kernel,
            artifacts.initrd.as_deref().unwrap_or("(none)"),
            if config.kernel.is_some() {
                "the client's request"
            } else {
                "the daemon environment"
            }
        );

        // Disks first, network second: a disk that cannot be
        // provisioned must not leave a bridge reference behind, and the
        // native path orders it the same way for the same reason.
        let attachments = fc_attachments(&vm_id, &config, self)?;
        // The guest agent learns what to mount and what to create from
        // the cmdline, not from the VMM. On the native backend the
        // `VmBuilder` appends these while it attaches the devices;
        // Firecracker takes the boot args as one string, so the same
        // tokens are appended here — without them the agent boots with
        // no rootfs, no scratch and no `/run/k7d/tools/runc`, and the
        // first container start fails with a bare ENOENT on runc.
        let cmdline = fc_cmdline(&base_cmdline, &attachments.blk_mounts, &config)?;
        log::info!("firecracker {vm_id} boot_args: {cmdline}");
        let attachment = match config.network {
            Some(ref net_cfg) => Some(self.acquire_network(net_cfg, true)?),
            None => None,
        };
        let cluster_id = config.network.as_ref().map(|n| n.cluster_id.clone());

        // From here on every failure must release the bridge reference.
        let started = Self::spawn_fc(
            &vm_id,
            &config,
            &artifacts,
            cmdline,
            attachments,
            attachment,
        );
        let (fc, vm_index) = match started {
            Ok(v) => v,
            Err(e) => {
                if let Some(ref cid) = cluster_id {
                    Self::release_bridge_locked(&mut self.bridges.lock().unwrap(), cid, e.vm_index);
                }
                return Err(e.message);
            }
        };
        let pid = fc.pid();

        // Only now: Firecracker resolves the TAP by name in its own
        // netns, so the device had to still be in the root one when it
        // opened it. It holds the fd across the move, exactly as the
        // native backend's VMM does.
        let pod_netns = match (&config.network, vm_index) {
            (Some(net_cfg), Some(idx)) => {
                match self.attach_pod_netns(&net_cfg.cluster_id, idx, net_cfg.pod_netns.as_deref())
                {
                    Ok(path) => path,
                    Err(e) => {
                        drop(fc);
                        if let Some(ref cid) = cluster_id {
                            Self::release_bridge_locked(
                                &mut self.bridges.lock().unwrap(),
                                cid,
                                vm_index,
                            );
                        }
                        return Err(e);
                    }
                }
            }
            _ => None,
        };

        let guest: Guest = fc.into();
        let agent_endpoint = guest.agent_endpoint();
        let pod_netns_attached = pod_netns.is_some();
        let registered = self.register_vm(
            vm_id.clone(),
            guest,
            // The jailer's `--cgroup cpu.max=` already caps this VM;
            // `VmCpuCgroup` caps threads of the *daemon*, which owns no
            // vCPU on this backend.
            None,
            config.cpu_quota,
            config.cpu_period,
            config.sandbox_id,
            cluster_id.clone(),
            vm_index,
            pod_netns,
        );
        if let Err(e) = registered {
            if let Some(ref cid) = cluster_id {
                Self::release_bridge_locked(&mut self.bridges.lock().unwrap(), cid, vm_index);
            }
            return Err(e);
        }
        log::info!("created {vm_id} on firecracker (pid={pid}, vm_index={vm_index:?})");
        Ok(CreatedVm {
            vm_id,
            guest_cid: NO_HOST_CID,
            vm_index,
            pod_netns_attached,
            agent_endpoint,
        })
    }

    /// Stage, spawn, configure and boot the jailed VMM. Split out of
    /// [`Self::build_and_start_fc`] so the bridge-release path above is
    /// one `match` instead of a release call per failure.
    fn spawn_fc(
        vm_id: &str,
        config: &VmConfig,
        artifacts: &crate::config::GuestArtifacts,
        cmdline: String,
        attachments: FcAttachments,
        attachment: Option<NetAttachment>,
    ) -> Result<SpawnedFc, FcStartError> {
        let (net, vm_index, tap) = match attachment {
            Some(att) => {
                let net = crate::fc::FcNet {
                    host_dev_name: att.tap.name().to_string(),
                    guest_mac: att.tap.mac(),
                };
                (Some(net), Some(att.vm_index), Some(att.tap))
            }
            None => (None, None, None),
        };
        let fail = |message: String| FcStartError { message, vm_index };

        let fc_config = crate::fc::FcConfig {
            vm_id: vm_id.to_string(),
            memory_mb: config.memory_mb,
            vcpus: config.vcpus,
            kernel: PathBuf::from(&artifacts.kernel),
            initrd: artifacts.initrd.as_ref().map(PathBuf::from),
            cmdline,
            cpu_quota_us: config.cpu_quota,
            cpu_period_us: config.cpu_period,
            drives: attachments.drives,
            net,
            // k7 fork (`ForkVm`) snapshots this VM; Diff
            // needs dirty-page tracking. Tree roots already set this.
            track_dirty_pages: true,
        };
        // `create` takes the TAP: it gives the device to the VM's uid
        // and releases k7d's descriptor before Firecracker opens it, so
        // a failure from here on drops the device with the VM.
        let mut fc = crate::fc::FcVm::create(&fc_config, tap).map_err(|e| fail(e.to_string()))?;
        fc.adopt_disks(attachments.disks);
        fc.start()
            .map_err(|e| fail(format!("start Firecracker VM: {e}")))?;
        Ok((fc, vm_index))
    }

    /// `PATCH /drives` on a live Firecracker VM.
    fn update_drive(&self, vm_id: &str, device_index: usize, host_path: &Path) -> Response {
        let mut vms = self.vms.lock().unwrap();
        let Some(entry) = vms.get_mut(vm_id) else {
            return Response::Error {
                message: format!("no such VM: {vm_id}"),
            };
        };
        match entry.vm.update_drive(device_index, host_path) {
            Ok(()) => {
                log::info!(
                    "update_drive: {vm_id} /dev/vd{} -> {}",
                    device_letter(device_index),
                    host_path.display()
                );
                Response::Ok
            }
            Err(e) => Response::Error {
                message: format!("update_drive({vm_id}, {device_index}): {e}"),
            },
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
    /// A requested pod-netns attach (`cfg.pod_netns = Some`) that
    /// cannot complete is a hard error — the TAP and bridge slot are
    /// released with the `Err`. `pod_netns: None` means no CNI and
    /// host-bridge is the intended network.
    ///
    /// `defer_pod_netns` holds that attach back for the caller to run
    /// later ([`Self::attach_pod_netns`]). The Firecracker backend
    /// needs it: its VMM opens the TAP **by name**, and `TUNSETIFF`
    /// resolves that name in the *caller's* netns, so a TAP already
    /// moved into the pod's namespace is invisible to it — the ioctl
    /// then tries to create a new device and fails `EPERM` in the jail.
    /// The native backend has the fd from creation and does not care.
    fn acquire_network(
        &self,
        cfg: &NetConfig,
        defer_pod_netns: bool,
    ) -> Result<NetAttachment, String> {
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

        {
            let entry = bridges
                .get_mut(&cfg.cluster_id)
                .expect("bridge entry just ensured");
            entry.refcount += 1;
        }

        // Move the TAP into the CNI pod netns and install
        // pod_ip ↔ guest_ip NAT. A requested attach that fails
        // releases the TAP and the bridge reference taken above.
        let attached = if defer_pod_netns {
            None
        } else {
            let attach = {
                let entry = bridges
                    .get_mut(&cfg.cluster_id)
                    .expect("bridge entry just ensured");
                Self::attach_pod_netns_locked(&mut entry.net, vm_index, cfg.pod_netns.as_deref())
            };
            match attach {
                Ok(path) => path,
                Err(e) => {
                    drop(tap);
                    Self::release_bridge_locked(&mut bridges, &cfg.cluster_id, Some(vm_index));
                    return Err(e);
                }
            }
        };

        Ok(NetAttachment {
            tap,
            vm_index,
            pod_netns: attached,
        })
    }

    /// Run the CNI attach `acquire_network` deferred: move the TAP into
    /// the pod netns and install the `pod_ip` ↔ `guest_ip` NAT.
    ///
    /// `pod_netns: None` → `Ok(None)` (no CNI). A requested path that
    /// cannot attach is `Err`.
    fn attach_pod_netns(
        &self,
        cluster_id: &str,
        vm_index: u32,
        pod_netns: Option<&str>,
    ) -> Result<Option<PathBuf>, String> {
        let Some(path) = pod_netns else {
            return Ok(None);
        };
        let mut bridges = self.bridges.lock().unwrap();
        let entry = bridges
            .get_mut(cluster_id)
            .ok_or_else(|| format!("CNI attach failed: no bridge for cluster {cluster_id}"))?;
        Self::attach_pod_netns_locked(&mut entry.net, vm_index, Some(path))
    }

    /// Attach the TAP for `vm_index` into `pod_netns`.
    ///
    /// `pod_netns: None` → `Ok(None)` (host-bridge is correct). Any of
    /// missing eth0 IPv4, `link_addrs_v4` error, or `attach_to_pod_netns`
    /// error is `Err` naming the cause — never a silent host-bridge.
    fn attach_pod_netns_locked(
        net: &mut ClusterNetwork,
        vm_index: u32,
        pod_netns: Option<&str>,
    ) -> Result<Option<PathBuf>, String> {
        let Some(pod_netns) = pod_netns else {
            return Ok(None);
        };
        let netns_path = PathBuf::from(pod_netns);
        let addrs = crate::broker::client::pod_ip(&netns_path).map_err(|e| {
            format!(
                "CNI attach failed: failed to read pod IP from {} eth0: {e}",
                netns_path.display()
            )
        })?;
        let Some(pod_ip) = addrs.into_iter().next() else {
            return Err(format!(
                "CNI attach failed: pod netns {} eth0 has no IPv4 address",
                netns_path.display()
            ));
        };
        match net.attach_to_pod_netns(vm_index, &netns_path, pod_ip) {
            Ok(()) => Ok(Some(netns_path)),
            Err(e) => Err(format!(
                "CNI attach failed: attach_to_pod_netns({vm_index}, {}, {pod_ip}): {e}",
                netns_path.display()
            )),
        }
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
        register_with_broker(&vm_id, &config)?;

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
            if let Some(holder) = self.live_data_disk_holder(&dd.id) {
                return Err(format!(
                    "data disk {:?} is attached to live VM {holder} — stop it or use another id",
                    dd.id
                ));
            }
            let disk = crate::disks::DataDisk::attach(&dd.id, dd.size_bytes, &dd.guest_mount)
                .map_err(|e| format!("attach data disk {}: {e}", dd.id))?;
            builder = builder.data_disk(disk);
        }

        // Docker graph disk last of all, so every caller-computed
        // `/dev/vdX` from `block_devices` / scratch / data disks still
        // holds. The agent mounts it at `/var/lib/docker` via `k7d.blk=`.
        if let Some(ref docker) = config.docker {
            let disk = crate::disks::ScratchDisk::create(
                &format!("{vm_id}-docker"),
                docker.graph_size_bytes,
            )
            .map_err(|e| format!("provision docker graph disk for {vm_id}: {e}"))?;
            builder = builder.docker_disk(disk);
        }

        let attachment = match config.network {
            Some(ref net_cfg) => Some(self.acquire_network(net_cfg, false)?),
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
        let agent_endpoint = AgentEndpoint::Vsock { cid: guest_cid };

        self.register_vm(
            vm_id.clone(),
            Guest::from(vm),
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
            agent_endpoint,
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
        vm: Guest,
        cpu_cgroup: Option<crate::cgroup::VmCpuCgroup>,
        cpu_quota: Option<u64>,
        cpu_period: Option<u64>,
        sandbox_id: Option<String>,
        cluster_id: Option<String>,
        vm_index: Option<u32>,
        pod_netns: Option<PathBuf>,
    ) -> Result<String, String> {
        let guest_cid = registry_cid(&vm);
        let vcpus = vm.vcpu_count();
        let backend = vm.backend();
        let agent_endpoint = vm.agent_endpoint();
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
                agent_endpoint: Some(agent_endpoint),
                backend,
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
    fn fork_vm(
        &self,
        vm_id: &str,
        fork_sandbox_id: Option<String>,
        dilation: Option<u32>,
    ) -> Response {
        let backend = {
            let vms = self.vms.lock().unwrap();
            match vms.get(vm_id) {
                Some(entry) => entry.vm.backend(),
                None => {
                    return Response::Error {
                        message: format!("no such VM: {vm_id}"),
                    };
                }
            }
        };
        match backend {
            Backend::Firecracker => self.fork_vm_fc(vm_id, fork_sandbox_id, dilation),
            Backend::Native => self.fork_vm_native(vm_id, fork_sandbox_id, dilation),
        }
    }

    #[allow(clippy::too_many_lines)]
    fn fork_vm_native(
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
            {
                let native = match native_mut(&mut entry.vm) {
                    Ok(v) => v,
                    Err(message) => return Response::Error { message },
                };
                if native.fork_source_base_path().is_none() {
                    // Daemon policy: sandbox VMs that still
                    // carry virtiofs shares are explicitly slow-fork — every
                    // fork is a full memfd copy. The opt-in is loud
                    // (`allow_slow_fork` warns) so nothing degrades silently.
                    if !native.virtiofs_shares().is_empty() {
                        native.allow_slow_fork();
                    }
                    if let Err(e) = native.prepare_fork_source() {
                        return Response::Error {
                            message: format!("prepare_fork_source({vm_id}): {e}"),
                        };
                    }
                    // prepare_fork_source swapped in a restored VM with
                    // fresh vCPU threads — a capped VM must land back in
                    // its CPU cgroup with ALL N kernel TIDs,
                    // or the quota silently stops applying.
                    if let Some(cg) = &entry.cpu_cgroup {
                        let Some(tids) = native.vcpu_kernel_tids(Duration::from_secs(5)) else {
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
                    entry.guest_cid = native.guest_cid();
                    log::info!(
                        "{vm_id} prepared as fork source (guest_cid={} preserved)",
                        entry.guest_cid
                    );
                }
            }
            let mut fork = match entry.vm.fork_batch(&[&fork_id], dilation) {
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
                match native(&fork).and_then(|n| Self::apply_cpu_cap(&fork_id, n, &cap_cfg)) {
                    Ok(cg) => cg,
                    Err(message) => {
                        drop(fork);
                        return Response::Error { message };
                    }
                }
            }
            _ => None,
        };
        let guest_cid = match guest_cid_u64(&fork) {
            Ok(c) => c,
            Err(message) => {
                drop(fork);
                return Response::Error { message };
            }
        };
        let vcpus = fork.vcpu_count();
        let dilation = match native(&fork) {
            Ok(n) => n.dilation(),
            Err(message) => {
                drop(fork);
                return Response::Error { message };
            }
        };
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
                agent_endpoint: Some(AgentEndpoint::Vsock { cid: guest_cid }),
                backend: Backend::Native,
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
            agent_endpoint: Some(AgentEndpoint::Vsock { cid: guest_cid }),
        }
    }

    /// Firecracker `fork_vm`: snapshot point + `LoadSnapshot` child,
    /// with a new TAP on the source's cluster bridge when the source
    /// is networked. Children are already running (`resume_vm: true`).
    #[allow(clippy::too_many_lines)]
    fn fork_vm_fc(
        &self,
        vm_id: &str,
        fork_sandbox_id: Option<String>,
        dilation: Option<u32>,
    ) -> Response {
        if dilation.is_some() {
            return Response::Error {
                message: GuestError::Unsupported {
                    backend: Backend::Firecracker,
                    op: "fork_vm with dilation",
                }
                .to_string(),
            };
        }
        let fork_id = self.mint_vm_id();
        let (cluster_id, cpu_quota, cpu_period, source_guest_cid) = {
            let vms = self.vms.lock().unwrap();
            let Some(entry) = vms.get(vm_id) else {
                return Response::Error {
                    message: format!("no such VM: {vm_id}"),
                };
            };
            (
                entry.cluster_id.clone(),
                entry.cpu_quota,
                entry.cpu_period,
                entry.guest_cid,
            )
        };

        let attachment = match cluster_id.as_deref() {
            Some(cid) => match self.acquire_network(
                &NetConfig {
                    cluster_id: cid.to_string(),
                    vm_index: None,
                    pod_netns: None,
                },
                true,
            ) {
                Ok(a) => Some(a),
                Err(message) => return Response::Error { message },
            },
            None => None,
        };
        let child_vm_index = attachment.as_ref().map(|a| a.vm_index);
        let tap = attachment.map(|a| a.tap);

        let release_tap = |tap: Option<crate::network::TapDevice>| {
            drop(tap);
            if let Some(cid) = cluster_id.as_deref() {
                Self::release_bridge_locked(&mut self.bridges.lock().unwrap(), cid, child_vm_index);
            }
        };

        let child = {
            let mut vms = self.vms.lock().unwrap();
            let Some(entry) = vms.get_mut(vm_id) else {
                release_tap(tap);
                return Response::Error {
                    message: format!("no such VM: {vm_id}"),
                };
            };
            let fc = match entry.vm.as_fc_mut() {
                Ok(fc) => fc,
                Err(e) => {
                    release_tap(tap);
                    return Response::Error {
                        message: e.to_string(),
                    };
                }
            };
            if let Err(e) = fc.prepare_fork_source() {
                release_tap(tap);
                return Response::Error {
                    message: format!("prepare_fork_source({vm_id}): {e}"),
                };
            }
            match fc.spawn_child(tap) {
                Ok(child) => child,
                Err(e) => {
                    if let Some(cid) = cluster_id.as_deref() {
                        Self::release_bridge_locked(
                            &mut self.bridges.lock().unwrap(),
                            cid,
                            child_vm_index,
                        );
                    }
                    return Response::Error {
                        message: format!("fork_vm({vm_id}): {e}"),
                    };
                }
            }
        };

        let guest = Guest::from(child);
        let agent_endpoint = guest.agent_endpoint();
        let guest_cid = registry_cid(&guest);
        let vcpus = guest.vcpu_count();
        {
            let mut vms = self.vms.lock().unwrap();
            vms.insert(
                fork_id.clone(),
                VmEntry {
                    vm: guest,
                    cpu_cgroup: None,
                    cpu_quota,
                    cpu_period,
                    guest_cid,
                    sandbox_id: fork_sandbox_id.clone(),
                    cluster_id: cluster_id.clone(),
                    vm_index: child_vm_index,
                    pod_netns: None,
                },
            );
        }
        if let Some(sandbox_id) = fork_sandbox_id {
            let record = SandboxRecord {
                sandbox_id: sandbox_id.clone(),
                vm_id: fork_id.clone(),
                guest_cid,
                vcpus,
                cpu_quota,
                cpu_period,
                vm_index: child_vm_index,
                cluster_id: cluster_id.clone(),
                pod_netns: None,
                agent_endpoint: Some(agent_endpoint.clone()),
                backend: Backend::Firecracker,
                created_at_unix: std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map(|d| d.as_secs())
                    .unwrap_or(0),
            };
            if let Err(e) = write_sandbox_record(&record) {
                let mut vms = self.vms.lock().unwrap();
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
        log::info!("forked {vm_id} -> {fork_id} (firecracker, guest_cid={guest_cid})");
        Response::VmForked {
            vm_id: fork_id,
            guest_cid,
            source_guest_cid,
            dilation: 1,
            agent_endpoint: Some(agent_endpoint),
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
    /// fork-source prepare swap.
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
        // Firecracker v1.16.0/v1.16.1 armed the vsock TRANSPORT_RESET
        // RX gate on a bare `Resumed` with no reset for the guest to
        // ack, so every host→guest connection after a resume hung
        // (upstream #6100; guest/fc/pins.env is ≥ v1.16.2). A dial here
        // turns any recurrence into this error instead of a `kubectl
        // exec` that never returns.
        if entry.vm.backend() == Backend::Firecracker {
            if let Err(e) = entry.vm.connect_agent(FC_RESUME_DIAL) {
                return Response::Error {
                    message: format!(
                        "resume({vm_id}): guest unreachable over vsock after Resumed \
                         (Firecracker < v1.16.2 gates RX after a bare resume): {e}"
                    ),
                };
            }
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
    /// atomically under pause.
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

        if let Some(message) = deny_non_native_members(
            members.iter().map(|(id, e)| (id.as_str(), &e.vm)),
            "warp_clock",
        ) {
            return Response::Error { message };
        }
        let mut targets: Vec<&mut crate::vm::Vm> = match members
            .iter_mut()
            .map(|(_, e)| e.vm.as_native_mut())
            .collect()
        {
            Ok(t) => t,
            Err(e) => {
                return Response::Error {
                    message: e.to_string(),
                }
            }
        };
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
    /// under pause.
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
            let mut natives = match native_vms_mut(tree_members) {
                Ok(v) => v,
                Err(e) => {
                    return Response::Error {
                        message: e.to_string(),
                    }
                }
            };
            return match crate::vm::set_dilation_lockstep(&mut natives, factor) {
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

        if let Some(message) = deny_non_native_members(
            members.iter().map(|(id, e)| (id.as_str(), &e.vm)),
            "set_dilation",
        ) {
            return Response::Error { message };
        }
        let mut targets: Vec<&mut crate::vm::Vm> = match members
            .iter_mut()
            .map(|(_, e)| e.vm.as_native_mut())
            .collect()
        {
            Ok(t) => t,
            Err(e) => {
                return Response::Error {
                    message: e.to_string(),
                }
            }
        };
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

    /// Start, switch or stop `cluster_id`'s auto-warp policy loop.
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
        // Refuse here rather than inside the loop: a loop that discovers
        // the backend on its first cycle logs an error nobody is reading
        // and leaves the caller believing auto-warp is on.
        if let Some(message) = deny_non_native_members(
            self.vms
                .lock()
                .unwrap()
                .iter()
                .filter(|(_, e)| e.cluster_id.as_deref() == Some(cluster_id))
                .map(|(id, e)| (id.as_str(), &e.vm)),
            "auto_warp",
        ) {
            return Response::Error { message };
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
                    let mut natives = match native_vms_mut(members) {
                        Ok(v) => v,
                        Err(e) => {
                            log::error!("auto-warp: {e}");
                            break;
                        }
                    };
                    driver.cycle(&mut natives, in_flight.as_deref())
                } else {
                    members.sort_by_key(|e| e.vm_index);
                    let mut targets: Vec<&mut Vm> =
                        match members.iter_mut().map(|e| e.vm.as_native_mut()).collect() {
                            Ok(t) => t,
                            Err(e) => {
                                log::error!("auto-warp: {e}");
                                break;
                            }
                        };
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
        deny_virtiofs_if_configured(config)?;
        deny_tree_payload_extras(config)?;
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

    /// Firecracker twin of [`Self::boot_tree_member`]:
    /// boot `config` on stock Firecracker with `track_dirty_pages` on,
    /// so the root's Diff points are exactly the pages written since
    /// the previous one, and wait for the agent.
    ///
    /// The open agent connection is returned for the same reason as
    /// the native path's, with the opposite effect: Firecracker resets
    /// it at the root's first snapshot point, and holding it across
    /// that point is what proves the reconnect path before any client
    /// depends on it.
    fn boot_fc_tree_member(
        config: &VmConfig,
        tap: Option<TapDevice>,
    ) -> Result<(Guest, crate::api::AgentClient), String> {
        deny_fc_unsupported(config)?;
        deny_tree_payload_extras(config)?;
        let artifacts = Self::resolve_vm_guest(config)?;
        let base_cmdline = config
            .cmdline
            .clone()
            .unwrap_or_else(|| crate::vm::DEFAULT_GUEST_CMDLINE.to_string());
        if base_cmdline.trim().is_empty() {
            return Err(
                "config.cmdline is empty; omit the field to keep the builder default".to_string(),
            );
        }
        let vm_id = format!("fct-{}-{}", std::process::id(), fc_tree_root_seq());
        // A tree payload has no scratch / data / docker disks (refused
        // above), so this is the caller's `block_devices`, in guest
        // device order, and nothing else.
        let mut drives = Vec::new();
        let mut blk_mounts = Vec::new();
        for (i, blk) in config.block_devices.iter().enumerate() {
            let host_path = PathBuf::from(&blk.host_path);
            let mount = match (&blk.guest_mount, &blk.fstype) {
                (Some(gm), Some(fstype)) => Some((gm.as_str(), fstype.as_str())),
                (None, None) => None,
                _ => {
                    return Err(format!(
                        "block device {}: guest_mount and fstype must be set together",
                        blk.host_path
                    ))
                }
            };
            push_drive(
                &mut drives,
                &mut blk_mounts,
                crate::fc::FcDrive {
                    name: format!("blk{i}-{}", file_stem_for_jail(&host_path)),
                    host_path,
                    read_only: blk.readonly,
                },
                mount,
            )?;
        }
        let cmdline = fc_cmdline(&base_cmdline, &blk_mounts, config)?;
        log::info!("firecracker tree root {vm_id} boot_args: {cmdline}");
        let net = tap.as_ref().map(|t| crate::fc::FcNet {
            host_dev_name: t.name().to_string(),
            guest_mac: t.mac(),
        });
        let fc_config = crate::fc::FcConfig {
            vm_id,
            memory_mb: config.memory_mb,
            vcpus: config.vcpus,
            kernel: PathBuf::from(&artifacts.kernel),
            initrd: artifacts.initrd.as_ref().map(PathBuf::from),
            cmdline,
            cpu_quota_us: config.cpu_quota,
            cpu_period_us: config.cpu_period,
            drives,
            net,
            track_dirty_pages: true,
        };
        let mut fc = crate::fc::FcVm::create(&fc_config, tap).map_err(|e| e.to_string())?;
        fc.start()
            .map_err(|e| format!("start Firecracker tree root: {e}"))?;
        let agent = fc
            .connect_agent(Duration::from_secs(90))
            .map_err(|e| format!("guest agent never became ready: {e}"))?;
        Ok((Guest::from(fc), agent))
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
                let endpoint = vm.agent_endpoint();
                vm.connect_agent(Duration::from_secs(30))
                    .map_err(|e| format!("agent on restored {endpoint:?}: {e}"))?;
            }
            TreePayload::Cluster(t) => {
                let p = t
                    .get_payload(node_id)
                    .ok_or_else(|| format!("node {node_id} has no live payload"))?;
                for (i, vm) in p.members.iter().enumerate() {
                    let endpoint = vm.agent_endpoint();
                    vm.connect_agent(Duration::from_secs(30))
                        .map_err(|e| format!("agent on member {i} ({endpoint:?}): {e}"))?;
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
        let agent_endpoints = payload.node_endpoints(&"root".to_string());
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
                    agent_endpoints,
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
        let booted = match config.backend {
            Backend::Native => {
                Self::boot_tree_member(config, None).map(|(vm, agent)| (Guest::from(vm), agent))
            }
            Backend::Firecracker => Self::boot_fc_tree_member(config, None),
        };
        let (root, agent) = match booted {
            Ok(v) => v,
            Err(message) => return Response::Error { message },
        };
        let root_dir = tree_root_dir().join(&tree_id);
        let (tree, root_id) = match SnapshotTree::new_guest(
            root,
            root_dir,
            budget.unwrap_or_else(default_tree_budget),
        ) {
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
        // irreversible: sandbox bridges are born Open, and
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
                let (vm, agent) = match config.backend {
                    Backend::Native => Self::boot_tree_member(config, Some(tap))
                        .map(|(vm, agent)| (Guest::from(vm), agent)),
                    Backend::Firecracker => Self::boot_fc_tree_member(config, Some(tap)),
                }
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
            pause_skew_ns: None,
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
                pause_skew_ns,
                ..
            } => self.emit_fork_event(tree_id, node_id, *latency_ns, *pause_skew_ns),
            Response::TreeForkBatch {
                forks,
                latency_ns,
                pause_skew_ns,
            } => {
                for f in forks {
                    self.emit_fork_event(tree_id, &f.node_id, *latency_ns, *pause_skew_ns);
                }
            }
            _ => {}
        }
    }

    fn emit_fork_event(
        &self,
        tree_id: &str,
        node_id: &str,
        latency_ns: u64,
        pause_skew_ns: Option<u64>,
    ) {
        let ev = TreeEvent {
            tree_id: tree_id.to_string(),
            op: "fork".to_string(),
            node_id: Some(node_id.to_string()),
            latency_ns: Some(latency_ns),
            pause_skew_ns,
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
                agent_endpoint: Some(entry.vm.agent_endpoint()),
                backend: entry.vm.backend(),
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
            ref agent_endpoint,
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

        if agent_endpoint.is_none() {
            return Response::Error {
                message: format!("sandbox {sandbox_id}: VM has no agent endpoint"),
            };
        }
        // Liveness check outside any lock — the connect can
        // legitimately take a moment and must not stall the control
        // plane. Dialled the way *this process* can, not over the
        // endpoint it published for the shim: under the split the two
        // differ for a Firecracker VM, and the published one is a path
        // uid `k7d` cannot walk (`Guest::own_agent_endpoint`).
        let own = self
            .vms
            .lock()
            .unwrap()
            .get(vm_id)
            .map(|entry| entry.vm.own_agent_endpoint());
        let Some(endpoint) = own else {
            return Response::Error {
                message: format!("sandbox {sandbox_id}: VM {vm_id} went away"),
            };
        };
        let ping = crate::api::AgentClient::connect_endpoint(&endpoint, Duration::from_secs(10))
            .and_then(|mut agent| agent.ping().map(|_| ()));
        if let Err(e) = ping {
            log::error!(
                "reattach_sandbox({sandbox_id}): VM {vm_id} ({endpoint:?}) is \
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
            // A Firecracker VM has no in-process VMM to interrogate, so
            // the native-only fields answer for the engine rather than
            // failing the whole call: `fork_memory_full_copy` is a
            // property of k7d's `MAP_PRIVATE` fork (Firecracker has its
            // own), and the kernel path is one the jailed process was
            // handed rather than one this process opened.
            Some(entry) => match &entry.vm {
                Guest::Native(native) => Response::VmState {
                    vm_id: vm_id.to_string(),
                    state: "running".to_string(),
                    guest_cid: entry.guest_cid,
                    virtiofs_shares: entry.vm.virtiofs_shares().len(),
                    block_devices: native.block_devices().len(),
                    fork_memory_full_copy: native.fork_memory_is_full_copy(),
                    kernel: native.kernel_path().to_string_lossy().into_owned(),
                    backend: Backend::Native,
                },
                Guest::Firecracker(fc) => Response::VmState {
                    vm_id: vm_id.to_string(),
                    state: if fc.paused() { "paused" } else { "running" }.to_string(),
                    guest_cid: entry.guest_cid,
                    virtiofs_shares: 0,
                    block_devices: fc.drive_count(),
                    fork_memory_full_copy: false,
                    kernel: String::new(),
                    backend: Backend::Firecracker,
                },
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
                    return serial_dump_guest(id.to_string(), &entry.vm);
                }
            }
            // `registry_cid` is 0 for every Firecracker VM
            // (`NO_HOST_CID`); a dump by CID 0 must not match them.
            if let Some(cid) = guest_cid.filter(|&c| c != NO_HOST_CID) {
                if let Some((id, entry)) = vms
                    .iter()
                    .find(|(_, e)| e.guest_cid == cid || e.vm.guest_cid() == Some(cid))
                {
                    return serial_dump_guest(id.clone(), &entry.vm);
                }
            }
        }

        let trees = self.trees.lock().unwrap();
        // Composite id `{tree_id}/{node_id}` is what we echo for tree
        // members — looking it back up must work without a CID, including
        // Firecracker nodes whose `node_cids` is empty.
        if let Some(id) = vm_id {
            if let Some((tree_id, node_id)) = id.split_once('/') {
                if let Some(tree) = trees.get(tree_id) {
                    if let Some(guest) = dump_node_guest(tree, node_id, guest_cid) {
                        return serial_dump_tree(tree_id, node_id, guest);
                    }
                }
            }
        }
        if let Some(cid) = guest_cid.filter(|&c| c != NO_HOST_CID) {
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
                backend: entry.vm.backend(),
                jail: match &entry.vm {
                    Guest::Native(_) => None,
                    Guest::Firecracker(fc) => Some(JailInfo {
                        pid: fc.pid(),
                        uid: fc.uid(),
                        chroot: fc.chroot_root().to_string_lossy().into_owned(),
                    }),
                },
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

    /// Live VM (if any) whose attached data disks include `id`.
    fn live_data_disk_holder(&self, id: &str) -> Option<String> {
        self.vms.lock().unwrap().iter().find_map(|(vm_id, entry)| {
            entry
                .vm
                .data_disks()
                .iter()
                .any(|d| d.id() == id)
                .then(|| vm_id.clone())
        })
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
        if let Some(vm_id) = self.live_data_disk_holder(id) {
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
        // Last, so the node broker's pinned descriptors and its record of
        // what to undo outlive everything above that might still name
        // them. A no-op unless `K7D_PRIVSEP` is on.
        crate::broker::client::release_vm(vm_id);
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

fn serial_dump_guest(vm_id: String, guest: &Guest) -> Response {
    match guest.serial_output(Duration::ZERO) {
        Ok(console) => Response::SerialDump {
            vm_id,
            guest_cid: guest.guest_cid().unwrap_or(NO_HOST_CID),
            console,
        },
        Err(e) => Response::Error {
            message: format!("dump_serial({vm_id}): {e}"),
        },
    }
}

/// Pick a live guest of `node_id` to dump. Cluster nodes dump member 0
/// unless `guest_cid` names a native member. Firecracker members have
/// no CID — they are found by node id, not invented one.
fn dump_node_guest<'a>(
    tree: &'a TreePayload,
    node_id: &str,
    guest_cid: Option<u64>,
) -> Option<&'a Guest> {
    let guests = tree.node_guests(node_id);
    let first = guests.first().copied()?;
    if let Some(cid) = guest_cid.filter(|&c| c != NO_HOST_CID) {
        if let Some(g) = guests.iter().copied().find(|g| g.guest_cid() == Some(cid)) {
            return Some(g);
        }
    }
    Some(first)
}

fn serial_dump_tree(tree_id: &str, node_id: &str, guest: &Guest) -> Response {
    serial_dump_guest(format!("{tree_id}/{node_id}"), guest)
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
        if !parent.as_os_str().is_empty() {
            std::fs::DirBuilder::new()
                .recursive(true)
                .mode(0o750)
                .create(parent)?;
            // Mode on create applies only to newly created components;
            // tighten an existing dedicated parent (never a shared tmp).
            tighten_socket_parent(parent)?;
        }
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
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o660))?;
    listener.set_nonblocking(true)?;
    let allowed_uids = parse_allowed_uids()
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidInput, e))?;
    log::info!("k7d listening on {socket_path}");

    let mut workers: Vec<std::thread::JoinHandle<()>> = Vec::new();
    while !shutdown.load(Ordering::SeqCst) {
        match listener.accept() {
            Ok((stream, _addr)) => {
                let daemon = Arc::clone(daemon);
                let allowed = allowed_uids.clone();
                workers.push(std::thread::spawn(move || {
                    handle_connection(&stream, &daemon, allowed.as_deref());
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
fn handle_connection(stream: &UnixStream, daemon: &Daemon, allowed_uids: Option<&[u32]>) {
    let cred = match peer_cred(stream) {
        Ok(c) => c,
        Err(e) => {
            log::error!("SO_PEERCRED failed: {e}");
            return;
        }
    };
    if let Some(allow) = allowed_uids {
        if !allow.contains(&cred.uid) {
            log::error!(
                "control socket: rejected uid={} gid={} pid={} (K7D_ALLOWED_UIDS)",
                cred.uid,
                cred.gid,
                cred.pid
            );
            return;
        }
    }
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
        let peer = format!(
            "control {} uid={} gid={} pid={}",
            req.op_name(),
            cred.uid,
            cred.gid,
            cred.pid
        );
        if req.is_mutating() {
            log::info!("{peer}");
        } else {
            log::debug!("{peer}");
        }
        if let Request::TreeWatch { tree_id } = req {
            serve_tree_watch(&mut writer, daemon, tree_id.as_deref());
            return;
        }
        if !write_response(&mut writer, &daemon.handle(req)) {
            return;
        }
    }
}

/// `SO_PEERCRED` of an accepted Unix client. Linux-only.
fn peer_cred(stream: &UnixStream) -> std::io::Result<libc::ucred> {
    let mut cred = libc::ucred {
        pid: 0,
        uid: 0,
        gid: 0,
    };
    let mut len = std::mem::size_of::<libc::ucred>() as libc::socklen_t;
    // SAFETY: `stream` is a live Unix socket; `cred` / `len` match
    // SO_PEERCRED's `struct ucred`.
    let rc = unsafe {
        libc::getsockopt(
            stream.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_PEERCRED,
            (&raw mut cred).cast::<libc::c_void>(),
            &mut len,
        )
    };
    if rc != 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(cred)
}

/// Optional `K7D_ALLOWED_UIDS=0,1000` allowlist. Unset / empty = any
/// uid that can connect (mode bits). A malformed token fails loudly.
fn parse_allowed_uids() -> Result<Option<Vec<u32>>, String> {
    match std::env::var("K7D_ALLOWED_UIDS") {
        Err(std::env::VarError::NotPresent) => Ok(None),
        Ok(s) if s.trim().is_empty() => Ok(None),
        Ok(s) => {
            let mut uids = Vec::new();
            for part in s.split(',') {
                let part = part.trim();
                if part.is_empty() {
                    continue;
                }
                let uid: u32 = part
                    .parse()
                    .map_err(|_| format!("K7D_ALLOWED_UIDS: {part:?} is not a uid"))?;
                uids.push(uid);
            }
            if uids.is_empty() {
                Ok(None)
            } else {
                Ok(Some(uids))
            }
        }
        Err(e) => Err(format!("K7D_ALLOWED_UIDS: {e}")),
    }
}

/// Set the control-socket parent to `0750`, skipping a world-writable
/// sticky dir (`/tmp`) so a test socket of the form `/tmp/foo.sock`
/// cannot steal the host temp root.
fn tighten_socket_parent(parent: &Path) -> std::io::Result<()> {
    let meta = std::fs::metadata(parent)?;
    let mode = meta.permissions().mode();
    if mode & 0o1002 == 0o1002 {
        log::warn!(
            "not tightening {}: world-writable sticky (shared tmp); put k7d.sock in a dedicated directory",
            parent.display()
        );
        return Ok(());
    }
    std::fs::set_permissions(parent, std::fs::Permissions::from_mode(0o750))
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
            pause_skew_ns: ev.pause_skew_ns,
        };
        if !write_response(writer, &resp) {
            return;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn vm_config_missing_backend_deserialises_to_native() {
        let cfg: VmConfig = serde_json::from_str(r#"{"memory_mb":256}"#).unwrap();
        assert_eq!(cfg.backend, Backend::Native);
    }

    #[test]
    fn create_vm_firecracker_rejects_devices_it_cannot_honour() {
        // Every one of these must be named in the error rather than
        // dropped: a pod that asked for a disk and got a VM without one
        // fails later, in the guest, as a missing mount.
        for (cfg, want) in [
            (
                VmConfig {
                    virtiofs: vec![ShareConfig {
                        host_dir: "/tmp".to_string(),
                        guest_mount: "/mnt".to_string(),
                        readonly: true,
                    }],
                    ..VmConfig::default()
                },
                "virtiofs",
            ),
            (
                VmConfig {
                    dilation: Some(4),
                    ..VmConfig::default()
                },
                "dilation",
            ),
        ] {
            let err = deny_fc_unsupported(&cfg).expect_err("must be refused");
            assert_eq!(
                err,
                format!("{want} is not supported on backend Firecracker")
            );
        }
        deny_fc_unsupported(&VmConfig::default()).expect("a plain FC VM is fine");

        // Disks are drives on this backend — they must
        // no longer be refused.
        deny_fc_unsupported(&VmConfig {
            scratch_size_bytes: Some(1 << 20),
            data_disks: vec![DataDiskConfig {
                id: "d0".to_string(),
                size_bytes: 1 << 20,
                guest_mount: "/mnt/d0".to_string(),
            }],
            ..VmConfig::default()
        })
        .expect("scratch and data disks are Firecracker drives");
    }
}
