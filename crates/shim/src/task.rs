//! Task service implementation: the containerd shim v2 `TaskService`.
//!
//! Handles Create, Start, Kill, Delete, Exec, Wait, State, Stats,
//! Connect, Shutdown, `CloseIO`, `ResizePty`, Pause, Resume, Pids.
//!
//! Architecture: one shim process per pod. The VM itself is owned by
//! the k7d daemon — the shim asks the daemon to
//! create/stop it over the Unix control socket and communicates with
//! the guest agent directly over vsock (CIDs are kernel-global).

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use async_trait::async_trait;
use containerd_shim::asynchronous::publisher::RemotePublisher;
use containerd_shim::protos::events::task::{
    TaskCreate, TaskDelete, TaskExecAdded, TaskExit, TaskStart,
};
use containerd_shim::protos::protobuf::well_known_types::timestamp::Timestamp;
use containerd_shim::protos::protobuf::{MessageDyn, MessageField};
use containerd_shim::protos::shim_async::Task;
use containerd_shim::protos::ttrpc::context::Context;
use containerd_shim::protos::ttrpc::r#async::TtrpcContext;
use containerd_shim::protos::types::task::Status;
use containerd_shim::{self as shim, api, TtrpcResult};

use crate::io_bridge::{self, OutputBridge};
use crate::sandbox::{ContainerState, ImageSlot, ProcessState, RootfsDevice, SandboxState};

const CRI_CONTAINER_TYPE: &str = "io.kubernetes.cri.container-type";
const CRI_SANDBOX_ID: &str = "io.kubernetes.cri.sandbox-id";
/// Kubernetes container name, stamped on a WORKLOAD container's OCI
/// spec (never on the sandbox's). matches it against the names
/// in [`ANN_CONTAINER_SCRATCH_SIZE`]; the guest agent reads the same
/// key off the bundle, because the guest runc name is the containerd
/// container id, which does not exist yet when the sandbox declares a
/// container's writable image.
const CRI_CONTAINER_NAME: &str = "io.kubernetes.cri.container-name";

// Pod-level resources containerd's CRI stamps onto the
// SANDBOX OCI spec for VM runtimes (workload containers' configs only
// arrive later, so sandbox-create is the one place VM sizing can
// happen). Values are decimal strings: memory limit in bytes, CFS
// quota/period in µs. Unset/zero means "no limit" (BestEffort).
const CRI_SANDBOX_MEMORY: &str = "io.kubernetes.cri.sandbox-memory";
const CRI_SANDBOX_CPU_QUOTA: &str = "io.kubernetes.cri.sandbox-cpu-quota";
const CRI_SANDBOX_CPU_PERIOD: &str = "io.kubernetes.cri.sandbox-cpu-period";

// k7d cluster-fork annotations.
const ANN_CLUSTER_ID: &str = "k7d.katakate.org/cluster-id";
const ANN_FORK_SOURCE_CLUSTER: &str = "k7d.katakate.org/fork-source-cluster";
const ANN_FORK_SOURCE_VM: &str = "k7d.katakate.org/fork-source-vm";
const ANN_FORK_VM_INDEX: &str = "k7d.katakate.org/fork-vm-index";

// Cluster-tree annotations.
//
// `tree-id` is opt-in: when set, the cluster lives under a named
// `ClusterSnapshotTree` whose lifecycle (suspend / resume / evict) the
// k7d daemon owns — the shim merely records the tree-id so the
// daemon-side wiring (currently the responsibility of a future
// shim ↔ k7d Unix-socket call) can
// route to the right tree. When `tree-id` is absent the shim's
// behaviour is unchanged.
const ANN_TREE_ID: &str = "k7d.katakate.org/tree-id";
/// When both `tree-id` and `tree-source-node-id` are set, the new
/// cluster is a fork of the source node within the named tree.
const ANN_TREE_SOURCE_NODE_ID: &str = "k7d.katakate.org/tree-source-node-id";

// Operator-facing cluster-tree fork annotations.
//
// These DRIVE the k7d daemon (unlike the record-only pair
// above). Trigger: the **sandbox `Create`** of a pod carrying them —
// Create is the one CRI hop where containerd reliably forwards pod
// annotations into the OCI spec (`pod_annotations` in the k7 runtime
// config), and a dedicated trigger pod gives kubectl a first-class
// success signal: the pod only reaches Running when adopt/fork
// succeeded, and a failed adopt/fork fails Create loudly (visible in
// `kubectl describe pod` events). Contract (fail loud, no silent
// defaults):
// - `tree-adopt-cluster: <cluster-id>` — adopt the live VMs sharing
//   that `k7d.katakate.org/cluster-id` as the root of tree `tree-id`
//   (`TreeAdoptCluster`). Requires `tree-id`. The trigger pod itself
//   must NOT be a member of that cluster.
// - `tree-fork-from: <node-id>` + `tree-fork-label: <label>` — fork
//   tree `tree-id` from that node (`TreeFork`). Both or neither;
//   require `tree-id`. Runs after the adopt when combined.
// - `tree-budget: <json TreeBudget>` — optional adopt budget override
//   (the daemon default is sized for 256 MiB busybox guests). Only
//   meaningful with `tree-adopt-cluster`; rejected otherwise.
const ANN_TREE_ADOPT_CLUSTER: &str = "k7d.katakate.org/tree-adopt-cluster";
/// Source node id for the annotation-driven `TreeFork` (usually `root`).
const ANN_TREE_FORK_FROM: &str = "k7d.katakate.org/tree-fork-from";
/// Branch label for the annotation-driven `TreeFork`.
const ANN_TREE_FORK_LABEL: &str = "k7d.katakate.org/tree-fork-label";
/// JSON-serialized [`k7d::tree::TreeBudget`] for the adopt.
const ANN_TREE_BUDGET: &str = "k7d.katakate.org/tree-budget";

// Spare image-slot virtio-blk devices. virtio-mmio
// has no hotplug, and the VM boots at the FIRST workload Create; a
// later workload with a distinct image attaches through one of these
// boot-time-declared spares: the host fills the slot's sparse backing
// file (FICLONE reflink / `copy_file_range`) and the agent
// `BLKFLSBUF`s + mounts the device.
/// Pod annotation: number of spare image slots to declare at boot.
const ANN_IMAGE_SLOTS: &str = "k7d.katakate.org/image-slots";
/// Pod annotation: capacity in bytes of each slot's backing file.
const ANN_IMAGE_SLOT_SIZE: &str = "k7d.katakate.org/image-slot-size";

/// Pod annotation sizing the sandbox's writable scratch
/// disk, the host-backed ext4 image every container's overlay
/// `upper`/`work` lives on. Accepts a plain byte count or a k8s-style
/// quantity suffix (`512Mi`, `16Gi`, `2G`). Unset ⇒
/// [`k7d::disks::DEFAULT_SCRATCH_SIZE`] (8 GiB), which is deliberately
/// a constant and NOT a function of the pod's memory limit — decoupling
/// writable space from guest RAM is the point of the annotation.
const ANN_SCRATCH_SIZE: &str = "k7d.katakate.org/scratch-size";

/// Pod annotation giving named containers their **own**
/// writable image instead of a directory on the shared sandbox
/// scratch, so one container filling its writable layer cannot starve
/// its siblings. Value is a comma-separated `name=size` list over
/// Kubernetes container names, e.g. `builder=2Gi,logger=256Mi`; sizes
/// take the same suffixes as [`ANN_SCRATCH_SIZE`]. Containers not
/// listed keep sharing the sandbox scratch exactly as in.
///
/// Why an annotation and not the pod spec: containerd's CRI carries no
/// ephemeral-storage number at all — not on the sandbox, not on the
/// container, and not in `linux.resources` (verified against live k3s
/// bundles). The
/// kubelet's own `ephemeral-storage` limits only exist on the pod
/// object in the API server, which the shim deliberately does not talk
/// to. Do not go looking for the number again, and do not substitute
/// anything memory-shaped for it.
///
/// Why a whole device per container rather than an ext4 project quota
/// on the shared image: the guest kernel has no quota support at all
/// (`guest/kernel/config-minimal` has `CONFIG_EXT4_FS=y` and no
/// `CONFIG_QUOTA`/`CONFIG_QUOTA_TREE`/`CONFIG_QFMT_V2`), and no loop
/// device either, so every in-guest quota mechanism costs a guest
/// kernel rebuild that the nodes of an existing cluster would not
/// have. A virtio-blk image costs one MMIO slot out of
/// [`MMIO_DEVICE_BUDGET`] instead, which is why it is opt-in per
/// container. The third option — measure but do not enforce — is what
/// unlisted containers still get, and it is reported as such
/// (`dedicated: false`) rather than dressed up as a limit.
const ANN_CONTAINER_SCRATCH_SIZE: &str = "k7d.katakate.org/container-scratch-size";
/// Default spare image-slot count (each costs one MMIO slot + IOAPIC pin).
const DEFAULT_IMAGE_SLOTS: u32 = 4;
/// Default slot capacity: 2 GiB, sparse (blocks allocate on fill).
const DEFAULT_IMAGE_SLOT_SIZE: u64 = 2 * 1024 * 1024 * 1024;
/// Guest mount prefix for assigned image slots (`/run/k7d/slot-<n>`).
const GUEST_IMAGE_SLOT_PREFIX: &str = "/run/k7d/slot";
/// virtio-mmio device budget: IOAPIC has 24 pins, devices take IRQ
/// `5 + idx` (COM1=4, COM2=3), so at most 19 devices fit. The VMM
/// re-checks the final total at build; checking here (at slot
/// declaration) is what lets the error name the annotation.
const MMIO_DEVICE_BUDGET: usize = 19;

// Block-path guest layout. All under /run/k7d/
// (guest tmpfs; the initramfs root) or /mnt/ (kept for the explicit
// virtiofs fallback), matching the strip-pass carve-out in
// `fix_oci_config`.
/// Guest mount point of the cached "tools" erofs image (static runc).
const GUEST_TOOLS_MOUNT: &str = "/run/k7d/tools";
/// Guest mount prefix for container-rootfs erofs devices
/// (`/run/k7d/rootfs-<n>`, one per distinct container image).
const GUEST_ROOTFS_PREFIX: &str = "/run/k7d/rootfs";
/// Guest tmpfs base the shim writes fixed OCI bundles into (vsock
/// `write_file`; replaces the virtiofs `/mnt/state/containers/`).
const GUEST_BUNDLES_BASE: &str = "/run/k7d/bundles";
/// Guest tmpfs base for pushed etc-files
/// (`/etc/{resolv.conf,hosts,hostname}` sources).
const GUEST_ETC_BASE: &str = "/run/k7d/etc";
/// Guest mount base for k7d-provisioned RWO disk volumes (raw ext4
/// images on the reflink loopback XFS).
const GUEST_DISKS_BASE: &str = "/run/k7d/disks";
/// In-VM roots of the explicit virtiofs fallback shares (hostPath /
/// unsupported PVC plugins). Distinct from the legacy
/// `/mnt/pod-volumes-{ro,rw}` because `/mnt/pod-volumes-ro` is taken
/// by the packed block-volumes erofs image.
const FALLBACK_MOUNT_RO: &str = "/mnt/hostpath-ro";
const FALLBACK_MOUNT_RW: &str = "/mnt/hostpath-rw";
/// Guest mount prefix for RO-hostPath erofs devices:
/// `readOnly: true` hostPath mounts are packed into cached erofs
/// images on virtio-blk instead of forcing the virtiofs fallback.
const GUEST_HOSTPATH_PREFIX: &str = "/run/k7d/hostpath";
/// Default size of a k7d-provisioned RWO disk volume image: 1 GiB,
/// sparse (real blocks allocate as the guest writes). The OCI spec
/// carries no PVC capacity, so static provisioning uses this fixed
/// size; a real CSI driver (out of scope) would size
/// from the claim.
const K7D_DISK_DEFAULT_SIZE: u64 = 1024 * 1024 * 1024;

/// Annotations consumed by the shim from the OCI bundle's `config.json`.
#[derive(Debug, Default, Clone)]
#[allow(dead_code)]
pub struct ShimAnnotations {
    /// CRI container type: `sandbox` or `container`.
    pub container_type: String,
    /// CRI sandbox ID (set for non-sandbox containers).
    pub sandbox_id: Option<String>,
    /// `k7d.katakate.org/cluster-id` — bridge identity for this VM.
    pub cluster_id: Option<String>,
    /// `k7d.katakate.org/fork-source-cluster` — set on fork pods.
    pub fork_source_cluster: Option<String>,
    /// `k7d.katakate.org/fork-source-vm` — set on fork pods.
    pub fork_source_vm: Option<String>,
    /// `k7d.katakate.org/fork-vm-index` — preserves source VM's IP/MAC.
    pub fork_vm_index: Option<u32>,
    /// `k7d.katakate.org/tree-id` — the named cluster
    /// snapshot tree this cluster belongs to. `None` means the cluster
    /// is not tree-managed (legacy behaviour).
    pub tree_id: Option<String>,
    /// `k7d.katakate.org/tree-source-node-id` — the source
    /// node within the named tree to fork from. Only meaningful when
    /// `tree_id` is also set.
    pub tree_source_node_id: Option<String>,
    /// `k7d.katakate.org/tree-adopt-cluster` — adopt
    /// the live VMs on this `cluster-id` as the root of tree `tree_id`.
    pub tree_adopt_cluster: Option<String>,
    /// `k7d.katakate.org/tree-fork-from` — tree node
    /// to fork from (paired with `tree_fork_label`).
    pub tree_fork_from: Option<String>,
    /// `k7d.katakate.org/tree-fork-label` — label of
    /// the new branch (paired with `tree_fork_from`).
    pub tree_fork_label: Option<String>,
    /// `k7d.katakate.org/tree-budget` — raw JSON
    /// `TreeBudget` for the adopt; parsed (fail-loud) when used.
    pub tree_budget: Option<String>,
    /// `io.kubernetes.cri.sandbox-memory` — pod memory
    /// limit in bytes. `None`/0 for `BestEffort` pods.
    pub sandbox_memory_bytes: Option<u64>,
    /// `io.kubernetes.cri.sandbox-cpu-quota` — pod CFS
    /// quota in µs. `None`/≤0 means no CPU limit.
    pub sandbox_cpu_quota: Option<i64>,
    /// `io.kubernetes.cri.sandbox-cpu-period` — CFS period
    /// in µs for the quota above.
    pub sandbox_cpu_period: Option<u64>,
    /// `k7d.katakate.org/image-slots` — spare
    /// image-slot device count. Raw string; validated loudly at
    /// sandbox Create ([`declare_image_slots`]).
    pub image_slots: Option<String>,
    /// `k7d.katakate.org/image-slot-size` — slot
    /// backing-file capacity in bytes. Raw string; validated loudly
    /// at sandbox Create.
    pub image_slot_size: Option<String>,
    /// `k7d.katakate.org/scratch-size` — capacity of the
    /// sandbox's writable scratch disk. Raw string; parsed loudly at
    /// sandbox Create ([`scratch_size_from_annotations`]).
    pub scratch_size: Option<String>,
    /// `k7d.katakate.org/container-scratch-size` — raw
    /// `name=size,...` list of containers that get their own writable
    /// image; parsed loudly at sandbox Create
    /// ([`container_scratch_from_annotations`]).
    pub container_scratch_size: Option<String>,
}

impl ShimAnnotations {
    fn lookup<'a>(annotations: &'a serde_json::Value, key: &str) -> Option<&'a str> {
        annotations.get(key).and_then(serde_json::Value::as_str)
    }
}

/// The k7 shim service.
pub struct K7Service {
    state: Arc<Mutex<SandboxState>>,
    bridges: Arc<Mutex<HashMap<String, OutputBridge>>>,
    /// Live/pending PTY exec sessions keyed by exec id
    /// (`ResizePty`/`CloseIO` route through here).
    pty_sessions: crate::exec::PtySessions,
    /// Arc so per-container exit watcher threads can
    /// publish `TaskExit` events without a second containerd connection.
    publisher: Option<Arc<RemotePublisher>>,
    namespace: String,
    /// Sandbox/task id containerd spawned this shim with (`-id` flag).
    /// The binary `delete` subcommand (containerd's
    /// cleanup-after-dead-shim path) uses it to find and stop the dead
    /// predecessor's VM in the k7d daemon.
    id: String,
    /// Per-container writable-layer usage, sampled off the
    /// guest on `Stats` and logged (see [`crate::usage`]).
    usage: crate::usage::UsageTracker,
    exit: Arc<tokio::sync::Notify>,
}

/// Debugging: append a timestamped line to /tmp/k7-shim.log.
/// containerd hands the shim /dev/null for stderr, so this is the only
/// way to see Create/Delete decisions on a live cluster.
pub(crate) fn debug_log_cni(msg: &str) {
    use std::io::Write as _;
    if let Ok(mut f) = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open("/tmp/k7-shim.log")
    {
        let _ = writeln!(
            f,
            "[{}] [k7-shim] {msg}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0)
        );
    }
}

/// Detect a `hostNetwork: true` pod by the absence of the
/// `network` namespace AND a non-empty namespaces list (kubelet
/// produces a fully-populated `linux.namespaces` array for normal
/// pods and omits the `network` entry for `hostNetwork: true`).
fn spec_has_host_network(bundle: &str) -> bool {
    let spec_path = Path::new(bundle).join("config.json");
    let Ok(data) = std::fs::read_to_string(&spec_path) else {
        return false;
    };
    let Ok(spec) = serde_json::from_str::<serde_json::Value>(&data) else {
        return false;
    };
    let Some(namespaces) = spec.pointer("/linux/namespaces").and_then(|v| v.as_array()) else {
        return false;
    };
    if namespaces.is_empty() {
        return false;
    }
    let has_network = namespaces
        .iter()
        .any(|ns| ns.get("type").and_then(|t| t.as_str()).unwrap_or_default() == "network");
    !has_network
}

/// Extract the CNI-assigned pod netns path from the OCI
/// spec, or `None` if no `network` namespace is present (which kubelet
/// produces for `hostNetwork: true` pods — those are explicitly
/// rejected in `Create`).
fn pod_netns_from_spec(bundle: &str) -> Option<PathBuf> {
    let spec_path = Path::new(bundle).join("config.json");
    let data = std::fs::read_to_string(&spec_path).ok()?;
    let spec: serde_json::Value = serde_json::from_str(&data).ok()?;
    let namespaces = spec.pointer("/linux/namespaces")?.as_array()?;
    for ns in namespaces {
        let ns_type = ns.get("type")?.as_str().unwrap_or_default();
        if ns_type == "network" {
            let path = ns.get("path")?.as_str()?;
            if path.is_empty() {
                return None;
            }
            return Some(PathBuf::from(path));
        }
    }
    None
}

/// Pull the kubelet-set pod UID annotation out of the
/// OCI spec. Used by sandbox `Create` to derive the kubelet
/// volumes directory `/var/lib/kubelet/pods/<pod-uid>/` that
/// [`k7d::volumes::PodVolumes::prepare`] enumerates.
///
/// We probe both the modern containerd-CRI annotation
/// (`io.kubernetes.cri.sandbox-uid` — what containerd 1.x+ sets on
/// sandbox containers) and the legacy/dockershim annotation
/// (`io.kubernetes.pod.uid`) so the shim works across older and
/// newer CRI plugins.
///
/// Returns `None` for any sandbox CRI didn't tag with either
/// annotation — direct `Vm`-API callers, `ctr run` sandboxes, or
/// any future CRI implementation that ever stops setting them.
/// The volumes plumbing degrades gracefully to an empty rewrite
/// map in that case.
fn pod_uid_from_spec(bundle: &str) -> Option<String> {
    let spec_path = Path::new(bundle).join("config.json");
    let data = std::fs::read_to_string(&spec_path).ok()?;
    let spec: serde_json::Value = serde_json::from_str(&data).ok()?;
    let ann = spec.get("annotations").and_then(|a| a.as_object())?;
    for key in &["io.kubernetes.cri.sandbox-uid", "io.kubernetes.pod.uid"] {
        if let Some(v) = ann.get(*key).and_then(|v| v.as_str()) {
            if !v.is_empty() {
                return Some(v.to_string());
            }
        }
    }
    None
}

fn annotations_from_spec(bundle: &str) -> ShimAnnotations {
    let spec_path = Path::new(bundle).join("config.json");
    let Ok(spec_data) = std::fs::read_to_string(&spec_path) else {
        return ShimAnnotations {
            container_type: "container".to_string(),
            ..Default::default()
        };
    };
    let Ok(spec) = serde_json::from_str::<serde_json::Value>(&spec_data) else {
        return ShimAnnotations {
            container_type: "container".to_string(),
            ..Default::default()
        };
    };

    let annotations = spec
        .pointer("/annotations")
        .or_else(|| spec.pointer("/process/annotations"));

    let Some(annotations) = annotations else {
        return ShimAnnotations {
            container_type: "container".to_string(),
            ..Default::default()
        };
    };

    ShimAnnotations {
        container_type: ShimAnnotations::lookup(annotations, CRI_CONTAINER_TYPE)
            .unwrap_or("container")
            .to_string(),
        sandbox_id: ShimAnnotations::lookup(annotations, CRI_SANDBOX_ID).map(str::to_string),
        cluster_id: ShimAnnotations::lookup(annotations, ANN_CLUSTER_ID).map(str::to_string),
        fork_source_cluster: ShimAnnotations::lookup(annotations, ANN_FORK_SOURCE_CLUSTER)
            .map(str::to_string),
        fork_source_vm: ShimAnnotations::lookup(annotations, ANN_FORK_SOURCE_VM)
            .map(str::to_string),
        fork_vm_index: ShimAnnotations::lookup(annotations, ANN_FORK_VM_INDEX)
            .and_then(|s| s.parse::<u32>().ok()),
        tree_id: ShimAnnotations::lookup(annotations, ANN_TREE_ID).map(str::to_string),
        tree_source_node_id: ShimAnnotations::lookup(annotations, ANN_TREE_SOURCE_NODE_ID)
            .map(str::to_string),
        tree_adopt_cluster: ShimAnnotations::lookup(annotations, ANN_TREE_ADOPT_CLUSTER)
            .map(str::to_string),
        tree_fork_from: ShimAnnotations::lookup(annotations, ANN_TREE_FORK_FROM)
            .map(str::to_string),
        tree_fork_label: ShimAnnotations::lookup(annotations, ANN_TREE_FORK_LABEL)
            .map(str::to_string),
        tree_budget: ShimAnnotations::lookup(annotations, ANN_TREE_BUDGET).map(str::to_string),
        sandbox_memory_bytes: ShimAnnotations::lookup(annotations, CRI_SANDBOX_MEMORY)
            .and_then(|s| s.parse::<u64>().ok()),
        sandbox_cpu_quota: ShimAnnotations::lookup(annotations, CRI_SANDBOX_CPU_QUOTA)
            .and_then(|s| s.parse::<i64>().ok()),
        sandbox_cpu_period: ShimAnnotations::lookup(annotations, CRI_SANDBOX_CPU_PERIOD)
            .and_then(|s| s.parse::<u64>().ok()),
        image_slots: ShimAnnotations::lookup(annotations, ANN_IMAGE_SLOTS).map(str::to_string),
        image_slot_size: ShimAnnotations::lookup(annotations, ANN_IMAGE_SLOT_SIZE)
            .map(str::to_string),
        scratch_size: ShimAnnotations::lookup(annotations, ANN_SCRATCH_SIZE).map(str::to_string),
        container_scratch_size: ShimAnnotations::lookup(annotations, ANN_CONTAINER_SCRATCH_SIZE)
            .map(str::to_string),
    }
}

/// Parse a k8s-style storage quantity into bytes: a decimal integer
/// with an optional binary (`Ki`/`Mi`/`Gi`/`Ti`) or decimal
/// (`k`/`M`/`G`/`T`) suffix. Bare digits are bytes.
fn parse_size_quantity(raw: &str) -> Result<u64, String> {
    let s = raw.trim();
    let split = s.find(|c: char| !c.is_ascii_digit()).unwrap_or(s.len());
    let (digits, suffix) = s.split_at(split);
    if digits.is_empty() {
        return Err(format!("{raw:?} must start with a decimal digit"));
    }
    let value: u64 = digits
        .parse()
        .map_err(|e| format!("{raw:?}: {e} (value too large for a byte count)"))?;
    let unit: u64 = match suffix {
        "" | "B" => 1,
        "Ki" => 1024,
        "Mi" => 1024 * 1024,
        "Gi" => 1024 * 1024 * 1024,
        "Ti" => 1024 * 1024 * 1024 * 1024,
        "k" | "K" => 1000,
        "M" => 1_000_000,
        "G" => 1_000_000_000,
        "T" => 1_000_000_000_000,
        other => {
            return Err(format!(
                "unknown size suffix {other:?} in {raw:?} — use bytes, Ki/Mi/Gi/Ti or k/M/G/T"
            ))
        }
    };
    value
        .checked_mul(unit)
        .ok_or_else(|| format!("{raw:?} overflows a 64-bit byte count"))
}

/// Capacity of the sandbox's writable scratch disk, from the
/// `k7d.katakate.org/scratch-size` annotation, defaulting to
/// [`k7d::disks::DEFAULT_SCRATCH_SIZE`].
///
/// Note what this function does NOT read: `ann.sandbox_memory_bytes`.
/// Deriving scratch capacity from the pod's memory limit is the exact
/// coupling removes.
fn scratch_size_from_annotations(ann: &ShimAnnotations) -> Result<u64, String> {
    let Some(raw) = ann.scratch_size.as_deref() else {
        return Ok(k7d::disks::DEFAULT_SCRATCH_SIZE);
    };
    let bytes = parse_size_quantity(raw).map_err(|e| format!("invalid {ANN_SCRATCH_SIZE}: {e}"))?;
    if bytes < k7d::disks::MIN_SCRATCH_SIZE {
        return Err(format!(
            "{ANN_SCRATCH_SIZE}={raw:?} is {bytes} bytes, below the \
             {}-byte minimum for a usable ext4 scratch filesystem",
            k7d::disks::MIN_SCRATCH_SIZE
        ));
    }
    Ok(bytes)
}

/// Containers that get their own writable image, from the
/// `k7d.katakate.org/container-scratch-size` annotation.
///
/// Every failure is loud: a pod that asked for a per-container limit
/// and silently did not get one would go on sharing the sandbox
/// scratch, which is precisely the behaviour the annotation exists to
/// change.
fn container_scratch_from_annotations(
    ann: &ShimAnnotations,
) -> Result<Vec<k7d::control::ContainerScratchConfig>, String> {
    let Some(raw) = ann.container_scratch_size.as_deref() else {
        return Ok(Vec::new());
    };
    let mut out: Vec<k7d::control::ContainerScratchConfig> = Vec::new();
    for entry in raw.split(',').map(str::trim).filter(|e| !e.is_empty()) {
        let (name, size) = entry.split_once('=').ok_or_else(|| {
            format!(
                "invalid {ANN_CONTAINER_SCRATCH_SIZE} entry {entry:?} — expected \
                 <container-name>=<size>, e.g. builder=2Gi"
            )
        })?;
        let name = name.trim();
        k7d::disks::ScratchDisk::validate_key(name)
            .map_err(|e| format!("invalid {ANN_CONTAINER_SCRATCH_SIZE} container name: {e}"))?;
        if out.iter().any(|c| c.name == name) {
            return Err(format!(
                "{ANN_CONTAINER_SCRATCH_SIZE} names container {name:?} twice"
            ));
        }
        let size_bytes = parse_size_quantity(size.trim())
            .map_err(|e| format!("invalid {ANN_CONTAINER_SCRATCH_SIZE} size for {name:?}: {e}"))?;
        if size_bytes < k7d::disks::MIN_SCRATCH_SIZE {
            return Err(format!(
                "{ANN_CONTAINER_SCRATCH_SIZE} gives {name:?} {size_bytes} bytes, below the \
                 {}-byte minimum for a usable ext4 filesystem",
                k7d::disks::MIN_SCRATCH_SIZE
            ));
        }
        out.push(k7d::control::ContainerScratchConfig {
            name: name.to_string(),
            size_bytes,
        });
    }
    if out.is_empty() {
        return Err(format!(
            "{ANN_CONTAINER_SCRATCH_SIZE}={raw:?} names no containers"
        ));
    }
    Ok(out)
}

// Pod resources → VM sizing.

/// Fixed VM overhead added on top of the pod's memory limit: guest
/// kernel text/data, page tables, and agent runtime that exist inside
/// the VM but that a container on runc would not pay for.
const VM_MEMORY_OVERHEAD_MB: u64 = 64;
/// Smallest guest that reliably boots the kernel + agent.
const VM_MEMORY_FLOOR_MB: u64 = 128;
/// `BestEffort` default (today's fixed sizing, unchanged).
const DEFAULT_VM_MEMORY_MB: u64 = 256;

/// VM sizing derived from the sandbox resource annotations.
#[derive(Debug, PartialEq, Eq)]
struct VmSizing {
    memory_mb: u64,
    vcpus: u32,
    cpu_quota: Option<u64>,
    cpu_period: Option<u64>,
}

/// Translate pod-level resources into VM sizing:
/// `memory_mb = limit/1Mi + 64 MB overhead` (floor 128 MB),
/// `vcpus = ceil(quota/period)` (floor 1), and the raw quota/period
/// passed through for the daemon's host-side CFS cap. Unset
/// annotations (`BestEffort`) keep today's defaults: 256 MB, 1 vCPU,
/// uncapped.
fn vm_sizing_from_annotations(ann: &ShimAnnotations) -> VmSizing {
    let memory_mb = match ann.sandbox_memory_bytes {
        Some(bytes) if bytes > 0 => {
            (bytes / (1024 * 1024) + VM_MEMORY_OVERHEAD_MB).max(VM_MEMORY_FLOOR_MB)
        }
        _ => DEFAULT_VM_MEMORY_MB,
    };
    match (ann.sandbox_cpu_quota, ann.sandbox_cpu_period) {
        (Some(quota), Some(period)) if quota > 0 && period > 0 => {
            let quota = quota as u64;
            let vcpus = u32::try_from(quota.div_ceil(period))
                .unwrap_or(u32::MAX)
                .max(1);
            VmSizing {
                memory_mb,
                vcpus,
                cpu_quota: Some(quota),
                cpu_period: Some(period),
            }
        }
        _ => VmSizing {
            memory_mb,
            vcpus: 1,
            cpu_quota: None,
            cpu_period: None,
        },
    }
}

/// Ask the k7d daemon to stop `vm_id`.
///
/// Best-effort by design: this runs on the Delete/Shutdown path where
/// failing loudly would wedge containerd's pod teardown. A daemon that
/// is unreachable (crashed, restarting) took the VM down with it, and
/// "no such VM" simply means an earlier call already stopped it. Both
/// are logged so operators can see them.
fn stop_daemon_vm(vm_id: &str) {
    let result = k7d::control::Client::connect_env()
        .map_err(|e| format!("connect: {e}"))
        .and_then(|mut c| {
            c.call(&k7d::control::Request::StopVm {
                vm_id: vm_id.to_string(),
            })
        });
    match result {
        Ok(k7d::control::Response::Ok) => {
            debug_log_cni(&format!("stop_daemon_vm: {vm_id} stopped"));
        }
        Ok(other) => {
            debug_log_cni(&format!("stop_daemon_vm: {vm_id}: {other:?}"));
            log::warn!("k7d stop_vm({vm_id}): {other:?}");
        }
        Err(e) => {
            debug_log_cni(&format!("stop_daemon_vm: {vm_id}: {e}"));
            log::warn!("k7d stop_vm({vm_id}): {e}");
        }
    }
}

/// Ask the k7d daemon whether `sandbox_id` maps to a live VM; returns
/// its `vm_id`. Best-effort (used on cleanup paths where a missing
/// daemon simply means the VM died with it) — failures are logged.
fn lookup_daemon_sandbox(sandbox_id: &str) -> Option<String> {
    let result = k7d::control::Client::connect_env()
        .map_err(|e| format!("connect: {e}"))
        .and_then(|mut c| {
            c.call(&k7d::control::Request::LookupSandbox {
                sandbox_id: sandbox_id.to_string(),
            })
        });
    match result {
        Ok(k7d::control::Response::SandboxFound { vm_id, .. }) => Some(vm_id),
        Ok(_) => None,
        Err(e) => {
            debug_log_cni(&format!("lookup_daemon_sandbox({sandbox_id}): {e}"));
            None
        }
    }
}

/// Resolve the live daemon VMs whose sandboxes sit on
/// `cluster_id`, sorted by `vm_index`. Returns `(vm_id, guest_cid)`
/// pairs — the CIDs feed the post-adopt invariant check in
/// [`run_tree_annotation_ops`]. Fails loud when the cluster has no
/// live members (nothing to adopt) or on any daemon transport error.
fn discover_cluster_vms(
    daemon: &mut k7d::control::Client,
    cluster_id: &str,
) -> Result<Vec<(String, u64)>, String> {
    let k7d::control::Response::VmList { vms } = daemon.call(&k7d::control::Request::ListVms)?
    else {
        return Err("unexpected list_vms response".to_string());
    };
    let mut found: Vec<(u32, String, u64)> = Vec::new();
    for vm in vms {
        let Some(sandbox_id) = vm.sandbox_id else {
            continue;
        };
        match daemon.call(&k7d::control::Request::LookupSandbox { sandbox_id })? {
            k7d::control::Response::SandboxFound {
                vm_id,
                guest_cid,
                vm_index: Some(idx),
                cluster_id: Some(ref cid),
                ..
            } if cid == cluster_id => found.push((idx, vm_id, guest_cid)),
            _ => {}
        }
    }
    if found.is_empty() {
        return Err(format!(
            "tree-adopt-cluster: no live sandbox VMs on cluster-id {cluster_id}"
        ));
    }
    found.sort_by_key(|(idx, _, _)| *idx);
    Ok(found.into_iter().map(|(_, id, cid)| (id, cid)).collect())
}

/// Annotation-driven cluster-tree adopt + fork (the
/// operator-facing drive path over the tree primitives). Runs during
/// sandbox `Create` of the trigger pod, before its own VM is created —
/// a failed adopt/fork therefore fails Create with nothing to unwind.
///
/// The annotation contract is validated fail-loud (see the
/// `ANN_TREE_ADOPT_CLUSTER` block comment); no combination is silently
/// ignored. After the adopt, the response's `guest_cids` are compared
/// against the pre-adopt CIDs: the member pods' own shims cache their
/// CID at Create and have no refresh channel (the daemon drops the
/// sandbox records at adopt), so a changed CID would break every later
/// exec against those pods. `prepare_fork_source_in` preserves the
/// CID on both routes — virtiofs-backed sources stay running in
/// place, share-less sources are restored **onto the same CID**
/// (CHALLENGES.md #39) — so a mismatch here is a
/// broken daemon invariant and fails the Create loudly instead of
/// leaving half the cluster unreachable.
fn run_tree_annotation_ops(ann: &ShimAnnotations) -> Result<(), String> {
    let has_fork = ann.tree_fork_from.is_some() || ann.tree_fork_label.is_some();
    if ann.tree_adopt_cluster.is_none() && !has_fork {
        if ann.tree_budget.is_some() {
            return Err(format!(
                "{ANN_TREE_BUDGET} requires {ANN_TREE_ADOPT_CLUSTER}"
            ));
        }
        return Ok(());
    }
    let Some(ref tree_id) = ann.tree_id else {
        return Err(format!(
            "{ANN_TREE_ADOPT_CLUSTER} / {ANN_TREE_FORK_FROM} require {ANN_TREE_ID}"
        ));
    };
    let fork = match (&ann.tree_fork_from, &ann.tree_fork_label) {
        (Some(from), Some(label)) => Some((from.clone(), label.clone())),
        (None, None) => None,
        _ => {
            return Err(format!(
                "{ANN_TREE_FORK_FROM} and {ANN_TREE_FORK_LABEL} must be set together"
            ));
        }
    };
    if ann.tree_budget.is_some() && ann.tree_adopt_cluster.is_none() {
        return Err(format!(
            "{ANN_TREE_BUDGET} requires {ANN_TREE_ADOPT_CLUSTER}"
        ));
    }
    if ann.tree_adopt_cluster.is_some() && ann.tree_adopt_cluster == ann.cluster_id {
        return Err(format!(
            "the trigger pod cannot be a member of the cluster it adopts \
             ({ANN_CLUSTER_ID} == {ANN_TREE_ADOPT_CLUSTER})"
        ));
    }

    let mut daemon = k7d::control::Client::connect_env().map_err(|e| {
        format!(
            "connect to k7d daemon at {}: {e}",
            k7d::control::socket_path_from_env()
        )
    })?;

    if let Some(ref cluster_id) = ann.tree_adopt_cluster {
        let budget = match ann.tree_budget {
            Some(ref raw) => Some(
                serde_json::from_str::<k7d::tree::TreeBudget>(raw)
                    .map_err(|e| format!("parse {ANN_TREE_BUDGET} {raw:?}: {e}"))?,
            ),
            None => None,
        };
        annotation_adopt_cluster(&mut daemon, cluster_id, tree_id, budget)?;
    }

    if let Some((source_id, label)) = fork {
        annotation_fork_tree(&mut daemon, tree_id, source_id, label)?;
    }
    Ok(())
}

/// [`run_tree_annotation_ops`] adopt step: discover the cluster's live
/// VMs, `TreeAdoptCluster` them, and verify no member vsock CID
/// changed (see the caller's doc comment for why a change is fatal).
fn annotation_adopt_cluster(
    daemon: &mut k7d::control::Client,
    cluster_id: &str,
    tree_id: &str,
    budget: Option<k7d::tree::TreeBudget>,
) -> Result<(), String> {
    let members = discover_cluster_vms(daemon, cluster_id)?;
    let vm_ids: Vec<String> = members.iter().map(|(id, _)| id.clone()).collect();
    let pre_adopt_cids: Vec<u64> = members.iter().map(|(_, cid)| *cid).collect();
    debug_log_cni(&format!(
        "tree annotations: adopting cluster {cluster_id} (vm_ids={vm_ids:?}) \
         into tree {tree_id}"
    ));
    match daemon.call(&k7d::control::Request::TreeAdoptCluster {
        vm_ids,
        budget,
        tree_id: Some(tree_id.to_string()),
    })? {
        k7d::control::Response::TreeCreated { ref guest_cids, .. } => {
            if *guest_cids != pre_adopt_cids {
                return Err(format!(
                    "tree_adopt_cluster changed member vsock CIDs \
                     ({pre_adopt_cids:?} -> {guest_cids:?}); the member pods' shims \
                     cache their CID and cannot be refreshed — exec against them \
                     would dial dead CIDs"
                ));
            }
            debug_log_cni(&format!(
                "tree annotations: adopted tree {tree_id} (cids {guest_cids:?} unchanged)"
            ));
            Ok(())
        }
        k7d::control::Response::Error { message } => Err(format!("tree_adopt_cluster: {message}")),
        other => Err(format!("unexpected tree_adopt_cluster response: {other:?}")),
    }
}

/// [`run_tree_annotation_ops`] fork step: `TreeFork` the named tree.
fn annotation_fork_tree(
    daemon: &mut k7d::control::Client,
    tree_id: &str,
    source_id: String,
    label: String,
) -> Result<(), String> {
    debug_log_cni(&format!(
        "tree annotations: forking tree {tree_id} from {source_id} (label {label})"
    ));
    match daemon.call(&k7d::control::Request::TreeFork {
        tree_id: tree_id.to_string(),
        source_id,
        label,
    })? {
        k7d::control::Response::TreeForked {
            node_id,
            guest_cids,
            fork_memory_full_copy,
        } => {
            debug_log_cni(&format!(
                "tree annotations: forked node {node_id} (cids {guest_cids:?}, \
                 full_copy {fork_memory_full_copy:?})"
            ));
            Ok(())
        }
        k7d::control::Response::Error { message } => Err(format!("tree_fork: {message}")),
        other => Err(format!("unexpected tree_fork response: {other:?}")),
    }
}

/// Whether the pod carries either single-VM fork-source
/// annotation. Both-or-neither is validated by
/// [`sandbox_create_fork_adopt`] — this only routes the Create.
fn has_fork_source(ann: &ShimAnnotations) -> bool {
    ann.fork_source_vm.is_some() || ann.fork_source_cluster.is_some()
}

/// Sandbox Create of a fork pod. Resolves the source
/// sandbox through the daemon (`LookupSandbox`), validates the
/// annotated cluster identity against the source VM's actual cluster,
/// warm-forks it (`ForkVm`), and adopts the returned VM as this
/// sandbox's — no cold boot, no `pending_vm`. Fail-loud on every
/// half-specified or mismatched input, naming the annotation keys.
fn sandbox_create_fork_adopt(
    state: &mut SandboxState,
    sandbox_id: &str,
    ann: &ShimAnnotations,
) -> Result<(), String> {
    let (src_sandbox, src_cluster) = match (&ann.fork_source_vm, &ann.fork_source_cluster) {
        (Some(v), Some(c)) => (v.clone(), c.clone()),
        _ => {
            return Err(format!(
                "{ANN_FORK_SOURCE_VM} and {ANN_FORK_SOURCE_CLUSTER} must be set together"
            ));
        }
    };

    let mut daemon = k7d::control::Client::connect_env().map_err(|e| {
        format!(
            "connect to k7d daemon at {}: {e}",
            k7d::control::socket_path_from_env()
        )
    })?;

    let (src_vm_id, src_cluster_actual) =
        match daemon.call(&k7d::control::Request::LookupSandbox {
            sandbox_id: src_sandbox.clone(),
        })? {
            k7d::control::Response::SandboxFound {
                vm_id, cluster_id, ..
            } => (vm_id, cluster_id),
            k7d::control::Response::Error { message } => {
                return Err(format!("{ANN_FORK_SOURCE_VM}={src_sandbox:?}: {message}"));
            }
            other => return Err(format!("unexpected lookup_sandbox response: {other:?}")),
        };
    if let Some(ref actual) = src_cluster_actual {
        if *actual != src_cluster {
            return Err(format!(
                "{ANN_FORK_SOURCE_CLUSTER}={src_cluster:?} does not match the source \
                 VM's cluster {actual:?}"
            ));
        }
    }

    let (fork_vm_id, fork_cid) = match daemon.call(&k7d::control::Request::ForkVm {
        vm_id: src_vm_id.clone(),
        sandbox_id: Some(sandbox_id.to_string()),
    })? {
        k7d::control::Response::VmForked {
            vm_id, guest_cid, ..
        } => (vm_id, guest_cid),
        k7d::control::Response::Error { message } => {
            return Err(format!("fork_vm({src_vm_id}): {message}"));
        }
        other => return Err(format!("unexpected fork_vm response: {other:?}")),
    };

    let state_dir = std::env::temp_dir().join(format!("k7d-shim-{sandbox_id}"));
    let _ = std::fs::create_dir_all(&state_dir);

    log::info!(
        "sandbox {sandbox_id}: adopted warm fork {fork_vm_id} (cid {fork_cid}) of \
         source sandbox {src_sandbox} (vm {src_vm_id})"
    );
    debug_log_cni(&format!(
        "Create: sandbox={sandbox_id} fork-adopted vm={fork_vm_id} cid={fork_cid} \
         source_sandbox={src_sandbox} source_vm={src_vm_id}"
    ));

    state.vm_id = Some(fork_vm_id);
    state.guest_cid = Some(fork_cid);
    state.sandbox_id = Some(sandbox_id.to_string());
    state.state_dir = Some(state_dir);
    state.fork_of = Some(src_sandbox);
    state.pending_vm = None;
    // The fork VM rides the source's (daemon-owned) bridge and keeps
    // the inherited guest network identity; this pod's own CNI netns
    // is left untouched (kubectl exec/logs go over vsock, not the pod
    // IP).
    state.cluster_id = None;
    state.cluster_mode = false;
    state.vm_index = None;
    Ok(())
}

/// Workload Create in a fork pod — adopt the container the
/// forked guest inherited from the source instead of pushing a fresh
/// bundle. Exactly one unclaimed guest container must exist: fork
/// adoption is defined for single-workload pods only (multi-container
/// pods have no reliable containerd-id → guest-name correspondence).
fn adopt_forked_workload(state: &mut SandboxState, container_id: &str) -> Result<(), String> {
    if state.agent.is_none() {
        state.connect_agent()?;
    }
    let claimed: Vec<String> = state.guest_names.values().cloned().collect();
    let agent = state.agent_mut()?;
    let listed = agent
        .container_list()
        .map_err(|e| format!("container_list in forked guest: {e}"))?;
    let available: Vec<String> = listed
        .containers
        .into_iter()
        .filter(|n| !claimed.contains(n))
        .collect();
    match available.as_slice() {
        [one] => {
            log::info!("fork workload {container_id}: adopting guest container {one}");
            state
                .guest_names
                .insert(container_id.to_string(), one.clone());
            Ok(())
        }
        [] => Err("forked guest reports no unclaimed running container to adopt".to_string()),
        many => Err(format!(
            "forked guest has {} unclaimed containers ({many:?}); fork of \
             multi-container pods is not supported",
            many.len()
        )),
    }
}

/// Unmount container rootfs overlays a dead shim left under its state
/// dir and remove the dir. Best-effort — this runs on containerd's
/// cleanup-after-dead-shim path where wedging teardown is worse than
/// leaking a mount.
fn cleanup_state_dir(sandbox_id: &str) {
    let dir = std::env::temp_dir().join(format!("k7d-shim-{sandbox_id}"));
    if !dir.exists() {
        return;
    }
    if let Ok(entries) = std::fs::read_dir(dir.join("containers")) {
        for entry in entries.flatten() {
            let rootfs = entry.path().join("rootfs");
            if rootfs.exists() {
                let _ = std::process::Command::new("umount")
                    .arg("-l")
                    .arg(&rootfs)
                    .status();
            }
        }
    }
    let _ = std::fs::remove_dir_all(&dir);
}

/// Rebuild a freshly spawned shim's
/// `SandboxState` from the k7d daemon (the source of truth for VM
/// identity) and dial the guest agent. Fails loudly — the caller
/// surfaces the error so kubelet recreates the pod instead of
/// operating on a silently empty shim.
///
/// The container table is intentionally NOT rebuilt here: containerd
/// re-issues Create/Start for workload containers as it drives the
/// recovered sandbox.
fn reattach_sandbox_state(
    state: &Arc<Mutex<SandboxState>>,
    sandbox_id: &str,
) -> Result<(), String> {
    let mut daemon = k7d::control::Client::connect_env().map_err(|e| {
        format!(
            "connect to k7d daemon at {}: {e}",
            k7d::control::socket_path_from_env()
        )
    })?;
    let resp = daemon.call(&k7d::control::Request::ReattachSandbox {
        sandbox_id: sandbox_id.to_string(),
    })?;
    match resp {
        k7d::control::Response::SandboxFound {
            vm_id,
            guest_cid,
            vm_index,
            cluster_id,
            pod_netns_attached,
            ..
        } => {
            debug_log_cni(&format!(
                "reattach: sandbox {sandbox_id} -> vm {vm_id} (cid {guest_cid})"
            ));
            {
                let mut st = state.lock().unwrap();
                st.vm_id = Some(vm_id);
                st.guest_cid = Some(guest_cid);
                st.sandbox_id = Some(sandbox_id.to_string());
                st.cluster_id = cluster_id;
                st.vm_index = vm_index;
                // The guest's eth0/route/ARP were configured by the
                // original Start; pod_netns only gates that one-time
                // setup, so it stays None here (`pod_netns_attached`
                // is bookkeeping only for a reattached shim).
                let _ = pod_netns_attached;
                let state_dir = std::env::temp_dir().join(format!("k7d-shim-{sandbox_id}"));
                // Reload the persisted block-path
                // snapshot (mount rewrites, attached rootfs erofs
                // devices, pushed etc-files) so workload Creates
                // replayed at this fresh shim still resolve.
                st.load_block_state(&state_dir)?;
                st.state_dir = Some(state_dir);
                st.connect_agent()?;
            }
            Ok(())
        }
        k7d::control::Response::Error { message } => Err(message),
        other => Err(format!("unexpected reattach_sandbox response: {other:?}")),
    }
}

#[allow(clippy::cast_possible_wrap)]
fn now_timestamp() -> MessageField<Timestamp> {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default();
    MessageField::some(Timestamp {
        seconds: now.as_secs() as i64,
        nanos: now.subsec_nanos() as i32,
        ..Default::default()
    })
}

#[async_trait]
impl shim::asynchronous::Shim for K7Service {
    type T = Self;

    async fn new(_runtime_id: &str, args: &shim::Flags, _config: &mut shim::Config) -> Self {
        Self {
            state: Arc::new(Mutex::new(SandboxState::new())),
            bridges: Arc::new(Mutex::new(HashMap::new())),
            pty_sessions: crate::exec::new_sessions(),
            publisher: None,
            namespace: args.namespace.clone(),
            id: args.id.clone(),
            usage: crate::usage::UsageTracker::default(),
            exit: Arc::new(tokio::sync::Notify::new()),
        }
    }

    async fn start_shim(&mut self, opts: shim::StartOpts) -> shim::Result<String> {
        // containerd 2.x writes its own (non-Any-wrapped) bootstrap protobuf
        // to the start command's stdin. The containerd-shim crate's spawn()
        // helper later re-reads stdin and tries to parse it as Any<runc
        // Options> for shim-cgroup placement, failing loudly with
        // Protobuf(WireError(IncorrectTag)). Drain stdin first so that parse
        // sees EOF and is skipped (we don't use shim_cgroup placement).
        {
            use std::io::Read as _;
            let mut sink = Vec::new();
            let _ = std::io::stdin().read_to_end(&mut sink);
        }
        // Group per POD, like the upstream runc shim: the socket address
        // is derived from (namespace, grouping), so the grouping key is
        // the sandbox id — its own id for a sandbox bundle, the
        // `io.kubernetes.cri.sandbox-id` annotation for workload
        // containers (routing them to their pod's existing shim).
        //
        // The empty grouping this used before collapsed EVERY k7 pod in
        // the namespace onto one socket: with two pods running
        // concurrently, containerd routed the second pod's sandbox
        // Create at the first pod's shim process, whose singleton
        // `SandboxState` (vm_id / guest_cid / sandbox_id) was silently
        // overwritten — execs then dialed the wrong VM's agent and hung,
        // and sandbox teardowns stopped sibling VMs (earlier tests
        // only ever ran one kubectl pod at a time).
        let grouping = annotations_from_spec(".")
            .sandbox_id
            .unwrap_or_else(|| opts.id.clone());
        let address = shim::asynchronous::spawn(opts, &grouping, Vec::new()).await?;
        Ok(address)
    }

    async fn delete_shim(&mut self) -> shim::Result<api::DeleteResponse> {
        // Containerd runs the binary `delete`
        // subcommand to clean up after a shim it can no longer reach
        // (cleanup-after-dead-shim) — the path taken when a shim is
        // SIGKILLed. The dead shim's VM is still running inside the
        // k7d daemon; stop it here so kubelet's recreated sandbox
        // doesn't compete with (and leak) the orphan forever.
        debug_log_cni(&format!("delete_shim: id={}", self.id));
        if !self.id.is_empty() {
            if let Some(vm_id) = lookup_daemon_sandbox(&self.id) {
                debug_log_cni(&format!(
                    "delete_shim: stopping orphaned VM {vm_id} of dead sandbox {}",
                    self.id
                ));
                stop_daemon_vm(&vm_id);
            }
            cleanup_state_dir(&self.id);
        }
        Ok(api::DeleteResponse::new())
    }

    async fn wait(&mut self) {
        self.exit.notified().await;
    }

    async fn create_task_service(&self, publisher: RemotePublisher) -> Self::T {
        Self {
            state: Arc::clone(&self.state),
            bridges: Arc::clone(&self.bridges),
            pty_sessions: Arc::clone(&self.pty_sessions),
            publisher: Some(Arc::new(publisher)),
            namespace: self.namespace.clone(),
            id: self.id.clone(),
            usage: self.usage.clone(),
            exit: Arc::clone(&self.exit),
        }
    }
}

impl K7Service {
    async fn publish_event(&self, topic: &str, event: Box<dyn MessageDyn>) {
        if let Some(ref p) = self.publisher {
            let _ = p
                .publish(Context::default(), topic, &self.namespace, event)
                .await;
        }
    }

    /// Watch a workload container for its NATURAL exit.
    ///
    /// A dedicated thread dials the guest agent over its own fresh
    /// vsock connection (never the shared `state.agent` — a blocked
    /// watcher must not starve Kill/Delete/Exec) and polls
    /// `container_wait_poll` until the init process exits. First
    /// writer wins on `exit_code`: if `Kill` already stamped one, the
    /// watcher backs off entirely (no bridge stop, no event). On an
    /// observed exit it lets the output bridge flush one more poll
    /// cycle, closes the containerd FIFOs, and publishes `TaskExit` so
    /// the kubelet sees Terminated with the real exit code —
    /// `restartPolicy` and init-container sequencing depend on this.
    fn spawn_exit_watcher(
        &self,
        container_id: String,
        guest_name: String,
        guest_cid: u64,
        exit_code: Arc<Mutex<Option<i32>>>,
        pid: u32,
    ) {
        let bridges = Arc::clone(&self.bridges);
        let publisher = self.publisher.clone();
        let namespace = self.namespace.clone();
        let handle = tokio::runtime::Handle::current();
        std::thread::spawn(move || {
            let Some(code) = watch_container_exit(guest_cid, &guest_name, &exit_code) else {
                return;
            };
            {
                let mut ec = exit_code.lock().unwrap();
                if ec.is_some() {
                    return; // Kill won the race — nothing left to report
                }
                *ec = Some(code);
            }
            debug_log_cni(&format!(
                "exit watcher: container {container_id} exited naturally with code {code}"
            ));
            // One more output-bridge poll cycle so the tail of the logs
            // reaches the FIFOs before they close.
            std::thread::sleep(Duration::from_millis(500));
            bridges.lock().unwrap().remove(&container_id);
            if let Some(p) = publisher {
                let mut event = TaskExit::new();
                event.container_id.clone_from(&container_id);
                event.id = container_id;
                event.pid = pid;
                event.exit_status = code as u32;
                event.exited_at = now_timestamp();
                let _ = handle.block_on(p.publish(
                    Context::default(),
                    "/tasks/exit",
                    &namespace,
                    Box::new(event),
                ));
            }
        });
    }
}

/// Poll the guest agent for a workload container's exit.
/// Returns the exit code, or `None` when watching should stop
/// silently: Kill/Delete already stamped an exit code, the container
/// is gone from the agent (stopped/torn down), or the VM's vsock died
/// (sandbox teardown is normal shutdown, not an error). Never panics —
/// the shim must not be taken down by its watchers.
fn watch_container_exit(guest_cid: u64, name: &str, exit_code: &Mutex<Option<i32>>) -> Option<i32> {
    use k7d::api::{AgentClient, AgentError};
    let mut agent: Option<AgentClient> = None;
    let mut connect_failures = 0u32;
    loop {
        if exit_code.lock().unwrap().is_some() {
            return None;
        }
        let Some(ref mut a) = agent else {
            if let Ok(a) = AgentClient::connect_vsock(guest_cid, Duration::from_secs(2)) {
                agent = Some(a);
                connect_failures = 0;
            } else {
                connect_failures += 1;
                if connect_failures >= 10 {
                    return None; // VM gone — normal teardown
                }
                std::thread::sleep(Duration::from_millis(500));
            }
            continue;
        };
        match a.container_wait_poll(name) {
            Ok(Some(code)) => return Some(code),
            Ok(None) => std::thread::sleep(Duration::from_millis(250)),
            Err(AgentError::Remote(e)) => {
                // The agent no longer tracks the container (stop /
                // teardown) or cannot observe its init — logged for
                // diagnosability, then quiet exit.
                debug_log_cni(&format!("exit watcher: {name}: agent said: {e}"));
                return None;
            }
            // Transport hiccup: retry on a fresh connection.
            Err(_) => agent = None,
        }
    }
}

#[async_trait]
impl Task for K7Service {
    async fn state(
        &self,
        _ctx: &TtrpcContext,
        req: api::StateRequest,
    ) -> TtrpcResult<api::StateResponse> {
        let state = self.state.lock().unwrap();
        let mut resp = api::StateResponse::new();
        resp.id.clone_from(&req.id);

        if let Some(c) = state.containers.get(&req.id) {
            if req.exec_id.is_empty() {
                resp.pid = c.init.pid;
                resp.bundle.clone_from(&c.init.bundle);
                let exit_code = c.init.exit_code.lock().unwrap();
                if let Some(code) = *exit_code {
                    resp.status = Status::STOPPED.into();
                    resp.exit_status = code as u32;
                    resp.exited_at = now_timestamp();
                } else {
                    resp.status = Status::RUNNING.into();
                }
            } else if let Some(exec) = c.execs.get(&req.exec_id) {
                resp.pid = exec.pid;
                resp.exec_id = req.exec_id;
                let exit_code = exec.exit_code.lock().unwrap();
                if let Some(code) = *exit_code {
                    resp.status = Status::STOPPED.into();
                    resp.exit_status = code as u32;
                    resp.exited_at = now_timestamp();
                } else {
                    resp.status = Status::RUNNING.into();
                }
            } else {
                resp.status = Status::UNKNOWN.into();
            }
        } else {
            resp.status = Status::UNKNOWN.into();
        }

        Ok(resp)
    }

    #[allow(clippy::too_many_lines)]
    async fn create(
        &self,
        _ctx: &TtrpcContext,
        req: api::CreateTaskRequest,
    ) -> TtrpcResult<api::CreateTaskResponse> {
        log::info!("Create: id={} bundle={}", req.id, req.bundle);

        let ann = annotations_from_spec(&req.bundle);
        let container_type = ann.container_type.clone();
        log::info!(
            "container_type={container_type} cluster_id={:?} fork_source={:?} vm_index={:?} \
             tree_id={:?} tree_source_node_id={:?} for {}",
            ann.cluster_id,
            ann.fork_source_cluster,
            ann.fork_vm_index,
            ann.tree_id,
            ann.tree_source_node_id,
            req.id
        );

        let pid = {
            let mut state = self.state.lock().unwrap();

            if container_type == "sandbox" && has_fork_source(&ann) {
                // A pod carrying `k7d.katakate.org/
                // fork-source-{cluster,vm}` boots as a WARM FORK of the
                // named live sandbox VM instead of cold-booting. The
                // daemon does the fork; this sandbox adopts the
                // returned VM (and later, at workload Create, the
                // container already running inside it). Fail-loud:
                // unknown source / half-specified annotations fail
                // Create with an error naming the annotation keys.
                sandbox_create_fork_adopt(&mut state, &req.id, &ann).map_err(|e| {
                    debug_log_cni(&format!("Create: fork adopt for {} failed: {e}", req.id));
                    containerd_shim::Error::Other(format!("k7d fork-source annotations: {e}"))
                })?;
            } else if container_type == "sandbox" {
                // Annotation-driven cluster-tree adopt +
                // fork runs FIRST, before this trigger pod's own VM is
                // created — a failed adopt/fork fails Create with
                // nothing to unwind, and the pod only reaches Running
                // when the fork landed.
                run_tree_annotation_ops(&ann).map_err(|e| {
                    debug_log_cni(&format!("Create: tree annotation ops failed: {e}"));
                    containerd_shim::Error::Other(format!("k7d tree annotations: {e}"))
                })?;

                let state_dir = std::env::temp_dir().join(format!("k7d-shim-{}", req.id));
                let _ = std::fs::create_dir_all(&state_dir);

                // (block path): kubelet volumes ride
                // on virtio-blk / guest tmpfs instead of virtiofs.
                // RO classes (configmap/secret/downwardAPI/projected)
                // pack into one erofs image; emptyDir becomes a
                // guest tmpfs dir (`k7d.mkdir=`). Pod UID comes from
                // the CRI annotation kubelet sets on the sandbox;
                // non-kubelet callers get an empty translation.
                let cache_dir = std::path::Path::new(k7d::erofs::DEFAULT_CACHE_DIR);
                let pod_uid = pod_uid_from_spec(&req.bundle);
                let block_volumes = k7d::volumes_blk::BlockVolumes::prepare(
                    pod_uid.as_deref().unwrap_or(""),
                    cache_dir,
                )
                .map_err(|e| {
                    containerd_shim::Error::Other(format!("BlockVolumes::prepare: {e}"))
                })?;
                debug_log_cni(&format!(
                    "Create: pod_uid={pod_uid:?} block_volumes rewrites={} ro_image={:?} \
                     emptydirs={}",
                    block_volumes.rewrites.len(),
                    block_volumes.ro_image,
                    block_volumes.emptydir_guest_dirs.len()
                ));

                // The static runc rides into the guest on a cached
                // "tools" erofs image (RO virtio-blk) mounted at
                // /run/k7d/tools — the block-path replacement for
                // the old /mnt/state/bin/runc virtiofs placement.
                let tools_image = prepare_tools_image(cache_dir).map_err(|e| {
                    containerd_shim::Error::Other(format!("prepare tools erofs image: {e}"))
                })?;

                // Resolve the cluster identity: if this pod opted into a
                // cluster, its VM joins the shared `k7-br-{cluster_id}`
                // bridge (created and refcounted by the k7d daemon).
                // Otherwise fall back to the legacy single-VM behavior
                // where `cluster_id == sandbox_id`.
                let cluster_id = ann.cluster_id.clone().unwrap_or_else(|| req.id.clone());

                // If kubelet handed us a CNI-assigned pod
                // netns, the daemon will move the VM's TAP into it,
                // bridge it to `eth0` (the CNI veth), and install
                // pod_ip ↔ guest_ip NAT. Pods on hostNetwork: true
                // come through with no `network` namespace entry —
                // we refuse them upfront with a clear error.
                let pod_netns = pod_netns_from_spec(&req.bundle);
                debug_log_cni(&format!(
                    "Create: sandbox={} bundle={} pod_netns={:?}",
                    req.id, req.bundle, pod_netns
                ));
                if pod_netns.is_none() && spec_has_host_network(&req.bundle) {
                    debug_log_cni(&format!(
                        "Create: refusing hostNetwork=true sandbox {}",
                        req.id
                    ));
                    return Err(containerd_shim::Error::Other(
                        "hostNetwork=true pods are not supported by runtimeClassName=k7 \
                         (the VM has its own network stack and cannot share the host netns)"
                            .into(),
                    )
                    .into());
                }
                // Preservation: if the pod carries a
                // `k7d.katakate.org/cluster-id` annotation it is opting
                // into the shared-bridge cluster-mode (zero-restart
                // cluster fork), where every pod in the cluster shares
                // one host-side `k7-br-{cluster_id}` and the VMs talk
                // to each other at L2 with stable 10.200.0.X guest IPs.
                // The CNI per-pod-netns plumbing moves the TAP out of
                // that shared bridge into the pod's private netns,
                // which silently breaks 9d's L2 sharing — pods in the
                // same "cluster" can no longer reach each other on
                // their guest IPs, and warm-fork loses its network
                // identity invariant. Skip CNI integration entirely
                // for these pods and preserve the legacy
                // host-bridge behaviour. Non-cluster pods (the
                // overwhelmingly common case for runtimeClassName=k7)
                // get the full CNI flow below.
                //
                // NOTE: For this gate to fire on a kubectl-deployed
                // pod, the containerd runtime config for k7 needs
                // `pod_annotations = ["k7d.katakate.org/*"]` so the
                // CRI plugin forwards pod-level annotations into the
                // OCI spec's `annotations` map (where
                // `ShimAnnotations::lookup` reads them). Today the
                // k7 runtime config template (see AGENTS.md) does
                // NOT set `pod_annotations`, so `ann.cluster_id` is
                // always None for kubectl-deployed pods. The gate is
                // here as the correct preventative measure for when
                // that config gets added — without it, the day
                // annotation forwarding lands, every kubectl-
                // deployed cluster-mode pod silently breaks. Direct
                // `Vm`-API-based cluster-mode tests (test_cluster_*)
                // never go through this path, so they're unaffected
                // either way.
                let cluster_mode_pod = ann.cluster_id.is_some();
                if cluster_mode_pod {
                    debug_log_cni(&format!(
                        "Create: cluster-mode pod (cluster-id={:?}); \
                         skipping CNI integration to preserve \
                         shared-bridge L2",
                        ann.cluster_id
                    ));
                }
                let cni_netns = if cluster_mode_pod {
                    None
                } else {
                    pod_netns.clone()
                };

                // The k7d daemon owns the VM —
                // KVM, guest memory, vsock, and the whole network
                // attachment (cluster bridge + TAP + pod-netns NAT).
                //
                // The VM is NOT created here. Its
                // rootfs is an erofs image on virtio-blk, and
                // virtio-blk devices are boot-time declarations (no
                // hotplug) — but the container image is only known at
                // the first workload Create. So sandbox Create only
                // ASSEMBLES the `VmConfig` (zero virtiofs shares;
                // tools + packed-RO-volume erofs devices; emptyDir
                // guest dirs) and parks it in `pending_vm`; the first
                // workload Create appends the rootfs device (plus any
                // k7d disk images / explicit virtiofs fallback
                // shares) and submits `create_vm`.
                // Size the VM from the pod's CPU/memory
                // limits (BestEffort pods keep today's 256 MB / 1
                // vCPU defaults) and pass the CFS quota through so
                // the daemon caps the vCPU threads host-side.
                let sizing = vm_sizing_from_annotations(&ann);
                log::info!(
                    "sandbox {}: VM sizing memory_mb={} vcpus={} cpu_quota={:?} cpu_period={:?} \
                     (sandbox-memory={:?} sandbox-cpu-quota={:?} sandbox-cpu-period={:?})",
                    req.id,
                    sizing.memory_mb,
                    sizing.vcpus,
                    sizing.cpu_quota,
                    sizing.cpu_period,
                    ann.sandbox_memory_bytes,
                    ann.sandbox_cpu_quota,
                    ann.sandbox_cpu_period,
                );
                debug_log_cni(&format!(
                    "Create: sandbox={} sizing memory_mb={} vcpus={} cpu_quota={:?} \
                     cpu_period={:?}",
                    req.id, sizing.memory_mb, sizing.vcpus, sizing.cpu_quota, sizing.cpu_period
                ));

                // Which guest a VM boots is the daemon's answer alone —
                // it is the process whose environment an operator sets
                // (`K7D_KERNEL` / `K7D_INITRD` in k7d.service), and it
                // fails loudly when they are unset. The shim used to
                // resolve the pair itself and send it, which *overrode*
                // that; and since containerd spawns a shim with no
                // environment of its own, the shim's answer came from
                // the workspace path baked into the binary at compile
                // time. On a node that both builds and runs k7d that
                // path exists and holds whatever guest was last built
                // there — rsync deliberately never updates it — so pods
                // booted a kernel nobody deployed. See CHALLENGES #72.
                let mut block_devices = vec![k7d::control::BlockDeviceConfig {
                    host_path: tools_image.to_string_lossy().into_owned(),
                    readonly: true,
                    guest_mount: Some(GUEST_TOOLS_MOUNT.to_string()),
                    fstype: Some("erofs".to_string()),
                }];
                if let Some(ref img) = block_volumes.ro_image {
                    block_devices.push(k7d::control::BlockDeviceConfig {
                        host_path: img.to_string_lossy().into_owned(),
                        readonly: true,
                        guest_mount: Some(k7d::volumes_blk::VM_VOLUMES_RO_MOUNT.to_string()),
                        fstype: Some("erofs".to_string()),
                    });
                }
                // Every container in this pod writes to a
                // host-backed scratch disk, not to guest RAM. Sized
                // from the annotation (default 8 GiB), never from
                // `sizing.memory_mb`. A malformed annotation fails
                // Create loudly — silently falling back to the
                // RAM-sized tmpfs is the bug this replaces.
                let scratch_size_bytes = scratch_size_from_annotations(&ann).map_err(|e| {
                    debug_log_cni(&format!("Create: scratch size for {} failed: {e}", req.id));
                    containerd_shim::Error::Other(e)
                })?;
                // Containers that asked for a writable-space
                // limit of their own. Same fail-loud rule.
                let container_scratch = container_scratch_from_annotations(&ann).map_err(|e| {
                    debug_log_cni(&format!(
                        "Create: container scratch for {} failed: {e}",
                        req.id
                    ));
                    containerd_shim::Error::Other(e)
                })?;
                let mut config = k7d::control::VmConfig {
                    kernel: None,
                    initrd: None,
                    memory_mb: sizing.memory_mb,
                    vcpus: sizing.vcpus,
                    cpu_quota: sizing.cpu_quota,
                    cpu_period: sizing.cpu_period,
                    vsock: true,
                    virtiofs: Vec::new(),
                    block_devices,
                    guest_dirs: block_volumes.emptydir_guest_dirs.clone(),
                    scratch_size_bytes: Some(scratch_size_bytes),
                    container_scratch,
                    sandbox_id: Some(req.id.clone()),
                    network: Some(k7d::control::NetConfig {
                        cluster_id: cluster_id.clone(),
                        vm_index: ann.fork_vm_index,
                        pod_netns: cni_netns.as_ref().map(|p| p.to_string_lossy().into_owned()),
                    }),
                };
                // Declare the spare image-slot devices
                // while the VmConfig is still parked — they must be in
                // the boot-time declaration for a post-boot distinct
                // image to have somewhere to attach.
                let image_slots =
                    declare_image_slots(&mut config, &ann, &state_dir).map_err(|e| {
                        debug_log_cni(&format!("Create: image slots for {} failed: {e}", req.id));
                        containerd_shim::Error::Other(format!("image slots for {}: {e}", req.id))
                    })?;

                debug_log_cni(&format!(
                    "Create: sandbox={} VM deferred to first workload Create \
                     (block_devices={}, image_slots={}, guest_dirs={}, scratch={} MiB, \
                     zero virtiofs)",
                    req.id,
                    config.block_devices.len(),
                    image_slots.len(),
                    config.guest_dirs.len(),
                    scratch_size_bytes / (1024 * 1024)
                ));

                state.image_slots = image_slots;
                state.container_scratch = config
                    .container_scratch
                    .iter()
                    .map(|cs| (cs.name.clone(), cs.size_bytes))
                    .collect();
                state.pending_vm = Some(config);
                state.rewrites = block_volumes.rewrites;
                // Only record the pod netns when the daemon actually
                // attaches the TAP into it (first workload Create).
                state.pod_netns = None;
                state.state_dir = Some(state_dir);
                state.sandbox_id = Some(req.id.clone());
                state.cluster_id = Some(cluster_id);
                state.cluster_mode = cluster_mode_pod;
                state.vm_index = ann.fork_vm_index;
                state.pod_volumes = None;
                state
                    .fork_source_cluster
                    .clone_from(&ann.fork_source_cluster);
                // Opt-in cluster-tree association. The actual
                // tree-side fork / suspend / resume is the k7d daemon's
                // job — the shim merely records the annotations so the
                // future shim ↔ k7d Unix-socket call can route to the
                // right tree. When `tree_id` is None the cluster is not
                // tree-managed (legacy behaviour, unchanged).
                state.tree_id.clone_from(&ann.tree_id);
                state
                    .tree_source_node_id
                    .clone_from(&ann.tree_source_node_id);
                if let Some(ref tid) = ann.tree_id {
                    log::info!(
                        "sandbox {} opted into cluster tree '{tid}' (source_node_id={:?})",
                        req.id,
                        ann.tree_source_node_id,
                    );
                }
            } else if state.fork_of.is_some() {
                // Workload Create in a fork pod — the
                // container is ALREADY RUNNING inside the forked
                // guest (inherited from the source, warm memory and
                // all). Adopt it: map this containerd id to the
                // guest's runc container name so Start/Exec/Kill/
                // Delete route to the inherited container instead of
                // pushing a fresh bundle.
                adopt_forked_workload(&mut state, &req.id).map_err(|e| {
                    debug_log_cni(&format!(
                        "Create: fork workload adopt {} failed: {e}",
                        req.id
                    ));
                    containerd_shim::Error::Other(format!("fork workload adopt {}: {e}", req.id))
                })?;
            } else if state.state_dir.is_some() {
                // The block-path workload Create —
                // resolve the container's rootfs into a cached erofs
                // image, boot the VM on the first workload (the
                // pending config from sandbox Create plus the rootfs
                // device, k7d disk images, and any explicit virtiofs
                // fallback shares), push runc-independent state over
                // vsock, and write the fixed OCI bundle into guest
                // tmpfs. Fail-loud throughout: a pod must never
                // reach Running without its rootfs or volumes.
                workload_create_block(&mut state, &req).map_err(|e| {
                    debug_log_cni(&format!("Create: workload {} failed: {e}", req.id));
                    containerd_shim::Error::Other(format!("workload create {}: {e}", req.id))
                })?;
            }

            let pid = state.alloc_pid();
            state.containers.insert(
                req.id.clone(),
                ContainerState {
                    init: ProcessState {
                        pid,
                        exit_code: Arc::new(Mutex::new(None)),
                        bundle: req.bundle.clone(),
                        stdout: req.stdout.clone(),
                        stderr: req.stderr.clone(),
                        stdin: req.stdin.clone(),
                        args: Vec::new(),
                        terminal: false,
                        term: String::new(),
                    },
                    execs: HashMap::new(),
                },
            );
            pid
        }; // state lock released here

        let mut event = TaskCreate::new();
        event.container_id = req.id;
        event.bundle = req.bundle;
        event.pid = pid;
        self.publish_event("/tasks/create", Box::new(event)).await;

        let mut resp = api::CreateTaskResponse::new();
        resp.pid = pid;
        Ok(resp)
    }

    #[allow(clippy::too_many_lines)]
    async fn start(
        &self,
        _ctx: &TtrpcContext,
        req: api::StartRequest,
    ) -> TtrpcResult<api::StartResponse> {
        log::info!("Start: id={} exec_id={}", req.id, req.exec_id);

        // (guest_cid, exit_code, guest container name)
        // of a workload whose natural exit must be watched — set inside
        // the lock, spawned after it is released. Sandboxes keep their
        // synthetic exit behaviour (there is no runc container for the
        // pause task). The guest name differs from the containerd id
        // only for fork-adopted containers.
        let mut exit_watch: Option<(u64, Arc<Mutex<Option<i32>>>, String)> = None;

        let pid = {
            let mut state = self.state.lock().unwrap();

            if !req.exec_id.is_empty() {
                let guest_cid = state.guest_cid.unwrap_or(k7d::vsock::DEFAULT_GUEST_CID);
                let container = state.containers.get(&req.id).ok_or_else(|| {
                    containerd_shim::Error::NotFoundError(format!("container {} not found", req.id))
                })?;
                let exec = container.execs.get(&req.exec_id).ok_or_else(|| {
                    containerd_shim::Error::NotFoundError(format!("exec {} not found", req.exec_id))
                })?;
                let pid = exec.pid;
                // PTY execs bridge containerd's attach FIFOs
                // to the agent's PTY session, starting here (the
                // non-PTY bridge was already spawned in `Exec`).
                if exec.terminal {
                    let params = crate::exec::PtyBridgeParams {
                        guest_cid,
                        container: state.guest_name(&req.id),
                        exec_id: req.exec_id.clone(),
                        args: exec.args.clone(),
                        term: exec.term.clone(),
                        stdin_path: exec.stdin.clone(),
                        stdout_path: exec.stdout.clone(),
                        exit_code: Arc::clone(&exec.exit_code),
                    };
                    let sessions = Arc::clone(&self.pty_sessions);
                    std::thread::spawn(move || {
                        crate::exec::run_pty_exec_bridge(&sessions, &params);
                    });
                }
                return Ok({
                    let mut resp = api::StartResponse::new();
                    resp.pid = pid;
                    resp
                });
            }

            let is_sandbox = state.sandbox_id.as_ref().is_some_and(|sid| *sid == req.id);

            if is_sandbox {
                if state.pending_vm.is_some() {
                    // The VM boots at the FIRST
                    // workload Create (the earliest moment the
                    // container's rootfs erofs image is known), so
                    // sandbox Start has nothing to dial yet.
                    debug_log_cni(&format!(
                        "Start: sandbox {} VM deferred to first workload Create (block path)",
                        req.id
                    ));
                } else {
                    // Reattached / legacy sandboxes whose VM already
                    // exists: dial the agent (retries absorb any
                    // remaining boot time) and configure the guest
                    // network exactly as before. Fork-adopted VMs
                    // inherit the source guest's fully
                    // configured eth0 — reconfiguring it here would
                    // clobber the inherited identity.
                    state
                        .connect_agent()
                        .map_err(|e| containerd_shim::Error::Other(e.to_string()))?;
                    if state.fork_of.is_none() {
                        configure_guest_network(&mut state);
                    }
                }
            } else {
                // Fork-adopted workloads are already running
                // inside the forked guest — starting them again would
                // fail in runc. Bridges and the exit watcher poll the
                // MAPPED guest container name.
                let guest_name = state.guest_name(&req.id);
                let adopted = state.fork_of.is_some();
                if !adopted {
                    let guest_bundle = format!("{GUEST_BUNDLES_BASE}/{}", req.id);
                    let agent = state.agent_mut().map_err(containerd_shim::Error::Other)?;
                    agent.container_start(&req.id, &guest_bundle).map_err(|e| {
                        containerd_shim::Error::Other(format!("container start failed: {e}"))
                    })?;
                }

                if let Some(container) = state.containers.get(&req.id) {
                    // Read the VM's actual CID instead of
                    // hardcoding `3`. Falls back to
                    // `DEFAULT_GUEST_CID` only for sandboxes
                    // somehow restored from before this field
                    // existed — should never happen in practice
                    // because Create writes it unconditionally.
                    let guest_cid = state.guest_cid.unwrap_or(k7d::vsock::DEFAULT_GUEST_CID);
                    if !container.init.stdout.is_empty() || !container.init.stderr.is_empty() {
                        let bridge = io_bridge::start_output_bridge(
                            guest_name.clone(),
                            guest_cid,
                            container.init.stdout.clone(),
                            container.init.stderr.clone(),
                        );
                        let mut bridges = self.bridges.lock().unwrap();
                        bridges.insert(req.id.clone(), bridge);
                    }
                    exit_watch =
                        Some((guest_cid, Arc::clone(&container.init.exit_code), guest_name));
                }
            }

            state.containers.get(&req.id).map_or(1, |c| c.init.pid)
        }; // state lock released here

        if let Some((guest_cid, exit_code, guest_name)) = exit_watch {
            self.spawn_exit_watcher(req.id.clone(), guest_name, guest_cid, exit_code, pid);
        }

        let mut event = TaskStart::new();
        event.container_id = req.id;
        event.pid = pid;
        self.publish_event("/tasks/start", Box::new(event)).await;

        let mut resp = api::StartResponse::new();
        resp.pid = pid;
        Ok(resp)
    }

    async fn kill(&self, _ctx: &TtrpcContext, req: api::KillRequest) -> TtrpcResult<api::Empty> {
        log::info!(
            "Kill: id={} exec_id={} signal={}",
            req.id,
            req.exec_id,
            req.signal
        );

        let state = self.state.lock().unwrap();
        let is_sandbox = state.sandbox_id.as_ref().is_some_and(|sid| *sid == req.id);

        if !req.exec_id.is_empty() {
            // A live PTY session must also be hung up guest-
            // side, or the exec process would outlive its bookkeeping.
            if let Some(crate::exec::PtySessionState::Active(w)) =
                self.pty_sessions.lock().unwrap().get(&req.exec_id)
            {
                let _ = w.send_eof();
            }
            if let Some(container) = state.containers.get(&req.id) {
                if let Some(exec) = container.execs.get(&req.exec_id) {
                    let mut ec = exec.exit_code.lock().unwrap();
                    if ec.is_none() {
                        *ec = Some(137);
                    }
                }
            }
            return Ok(api::Empty::new());
        }

        if is_sandbox {
            for container in state.containers.values() {
                let mut ec = container.init.exit_code.lock().unwrap();
                if ec.is_none() {
                    *ec = Some(0);
                }
            }
            // Containerd's exit handling (client task.Delete) blocks in
            // io.Wait() until the shim closes the write end of the
            // container stdio FIFOs. Bridges hold those FIFOs open, so
            // they must die with the task — waiting for the Delete RPC
            // deadlocks: containerd only sends Delete *after* io.Wait().
            self.bridges.lock().unwrap().clear();
        } else {
            let guest_name = state.guest_name(&req.id);
            // Dial a FRESH agent connection instead of trusting the cached
            // one: after this pod's VM was prepared as a fork source
            // (share swap), the cached connection is silently dead and a
            // signal through it blocks until the 30s request deadline WHILE
            // HOLDING THE STATE LOCK — containerd's own Kill deadline is
            // shorter, so kubelet retries forever and the pod can never
            // terminate. A fresh dial reaches the swapped VM on the same
            // CID in milliseconds (the same pattern the exec bridges use).
            if let Some(cid) = state.guest_cid {
                #[allow(clippy::cast_possible_wrap)]
                let signal = req.signal as i32;
                if let Ok(mut agent) =
                    k7d::api::AgentClient::connect_vsock(cid, Duration::from_secs(2))
                {
                    let _ = agent.container_signal(&guest_name, signal);
                }
            }
            if let Some(container) = state.containers.get(&req.id) {
                if req.signal == 9 || req.signal == 15 {
                    let mut ec = container.init.exit_code.lock().unwrap();
                    if ec.is_none() {
                        *ec = Some(if req.signal == 9 { 137 } else { 0 });
                    }
                    // Close the stdio FIFOs now that the task is dead —
                    // see the sandbox branch above for why this cannot
                    // wait for the Delete RPC.
                    self.bridges.lock().unwrap().remove(&req.id);
                }
            }
        }

        Ok(api::Empty::new())
    }

    async fn delete(
        &self,
        _ctx: &TtrpcContext,
        req: api::DeleteRequest,
    ) -> TtrpcResult<api::DeleteResponse> {
        log::info!("Delete: id={} exec_id={}", req.id, req.exec_id);

        let (pid, exit_code, known) = {
            let mut state = self.state.lock().unwrap();

            if !req.exec_id.is_empty() {
                // Drop any leftover PTY session entry.
                self.pty_sessions.lock().unwrap().remove(&req.exec_id);
                let (pid, exit_code) = if let Some(container) = state.containers.get_mut(&req.id) {
                    if let Some(exec) = container.execs.remove(&req.exec_id) {
                        let ec = exec.exit_code.lock().unwrap().unwrap_or(0);
                        (exec.pid, ec)
                    } else {
                        (0, 0)
                    }
                } else {
                    (0, 0)
                };

                let mut resp = api::DeleteResponse::new();
                resp.pid = pid;
                resp.exit_status = exit_code as u32;
                resp.exited_at = now_timestamp();
                return Ok(resp);
            }

            let is_sandbox = state.sandbox_id.as_ref().is_some_and(|sid| *sid == req.id);

            {
                let mut bridges = self.bridges.lock().unwrap();
                bridges.remove(&req.id);
            }
            // This container's writable layer is going away
            // with it; keep no sample for it.
            self.usage.forget(&req.id);

            let known = state.containers.contains_key(&req.id) || is_sandbox;

            let (pid, exit_code) = if let Some(container) = state.containers.get(&req.id) {
                let ec = container.init.exit_code.lock().unwrap().unwrap_or(0);
                (container.init.pid, ec)
            } else {
                (0, 0)
            };

            if !is_sandbox && known {
                let guest_name = state.guest_name(&req.id);
                // Fresh dial, not the cached agent — see Kill above (a
                // fork-prepared source's cached connection is dead and
                // would block teardown while holding the state lock).
                if let Some(cid) = state.guest_cid {
                    if let Ok(mut agent) =
                        k7d::api::AgentClient::connect_vsock(cid, Duration::from_secs(2))
                    {
                        let _ = agent.container_stop(&guest_name);
                    }
                }
                if let Some(ref state_dir) = state.state_dir {
                    let rootfs = state_dir.join("containers").join(&req.id).join("rootfs");
                    if rootfs.exists() {
                        let _ = std::process::Command::new("umount").arg(&rootfs).status();
                    }
                }
                release_container_rootfs(&mut state, &req.id)
                    .map_err(containerd_shim::Error::Other)?;
            }

            state.containers.remove(&req.id);

            if is_sandbox {
                // The daemon owns the VM, the
                // TAP, the in-pod-netns bridge, and the (refcounted)
                // cluster bridge — one `stop_vm` tears all of it down
                // in the right order. Best-effort: if the daemon is
                // already gone the VM died with it.
                if let Some(vm_id) = state.vm_id.take() {
                    stop_daemon_vm(&vm_id);
                }
                state.pod_netns = None;
                state.agent = None;
                // A sandbox deleted before its first
                // workload Create never booted a VM — drop the parked
                // config.
                state.pending_vm = None;

                // Tear down the per-pod kubelet volume
                // bind-mount tree AFTER the VM is gone (so the
                // virtiofsd children have released their file
                // handles into the binds) and BEFORE the state_dir
                // cleanup. `cleanup()` is best-effort — kubelet
                // GCs `/var/lib/kubelet/pods/<uid>/` shortly after
                // pod delete, so a stray bind eventually goes away
                // even if our umount fails.
                if let Some(pv) = state.pod_volumes.take() {
                    pv.cleanup();
                }

                if let Some(ref dir) = state.state_dir {
                    let _ = std::fs::remove_dir_all(dir);
                }
                state.state_dir = None;

                let mut bridges = self.bridges.lock().unwrap();
                bridges.clear();
            }

            (pid, exit_code, known)
        }; // state lock released here

        // An id this shim has never seen can be
        // a dead predecessor's sandbox routed here through the shared
        // shim socket. If the daemon still holds a VM for it, that VM
        // is an orphan — stop it and sweep the dead shim's state dir.
        if !known {
            if let Some(vm_id) = lookup_daemon_sandbox(&req.id) {
                debug_log_cni(&format!(
                    "Delete: foreign sandbox {} still had VM {vm_id}; stopping orphan",
                    req.id
                ));
                stop_daemon_vm(&vm_id);
                cleanup_state_dir(&req.id);
            }
        }

        let mut event = TaskDelete::new();
        event.container_id = req.id;
        event.pid = pid;
        event.exit_status = exit_code as u32;
        event.exited_at = now_timestamp();
        self.publish_event("/tasks/delete", Box::new(event)).await;

        let mut resp = api::DeleteResponse::new();
        resp.pid = pid;
        resp.exit_status = exit_code as u32;
        resp.exited_at = now_timestamp();
        Ok(resp)
    }

    async fn exec(
        &self,
        _ctx: &TtrpcContext,
        req: api::ExecProcessRequest,
    ) -> TtrpcResult<api::Empty> {
        log::info!(
            "Exec: id={} exec_id={} terminal={}",
            req.id,
            req.exec_id,
            req.terminal
        );

        let (args, spec_terminal, term) = parse_exec_process_spec(req.spec.as_ref());
        // Containerd sets `terminal` on the request AND in
        // the OCI process spec — honor either.
        let terminal = req.terminal || spec_terminal;

        let exit_code = Arc::new(Mutex::new(None));

        let (guest_cid, guest_name) = {
            let mut state = self.state.lock().unwrap();
            let pid = state.alloc_pid();

            if let Some(container) = state.containers.get_mut(&req.id) {
                container.execs.insert(
                    req.exec_id.clone(),
                    ProcessState {
                        pid,
                        exit_code: Arc::clone(&exit_code),
                        bundle: String::new(),
                        stdout: req.stdout.clone(),
                        stderr: req.stderr.clone(),
                        stdin: req.stdin.clone(),
                        args: args.clone(),
                        terminal,
                        term: term.clone(),
                    },
                );
            } else {
                return Err(containerd_shim::Error::NotFoundError(format!(
                    "container {} not found",
                    req.id
                ))
                .into());
            }
            // Capture the VM's actual CID while we hold the lock so
            // the spawned exec bridge thread doesn't need to re-lock.
            // Falls back to `DEFAULT_GUEST_CID` only for
            // SandboxStates somehow created before this field
            // existed. The guest container name differs from `req.id`
            // only for fork-adopted containers.
            (
                state.guest_cid.unwrap_or(k7d::vsock::DEFAULT_GUEST_CID),
                state.guest_name(&req.id),
            )
        }; // state lock released here

        // PTY execs start their bridge at `Start(exec_id)`
        // (containerd's attach is set up by then). Non-PTY execs keep
        // the historical behavior: bridge spawned right here.
        if !args.is_empty() && !terminal {
            let container_name = guest_name;
            let exit_code_clone = Arc::clone(&exit_code);
            let stdout_path = req.stdout.clone();
            let stderr_path = req.stderr.clone();
            std::thread::spawn(move || {
                run_exec_bridge(
                    guest_cid,
                    &container_name,
                    &args,
                    &exit_code_clone,
                    &stdout_path,
                    &stderr_path,
                );
            });
        }

        let mut event = TaskExecAdded::new();
        event.container_id = req.id;
        event.exec_id = req.exec_id;
        self.publish_event("/tasks/exec-added", Box::new(event))
            .await;

        Ok(api::Empty::new())
    }

    async fn wait(
        &self,
        _ctx: &TtrpcContext,
        req: api::WaitRequest,
    ) -> TtrpcResult<api::WaitResponse> {
        log::info!("Wait: id={} exec_id={}", req.id, req.exec_id);

        let exit_code_arc = {
            let state = self.state.lock().unwrap();
            if let Some(container) = state.containers.get(&req.id) {
                if req.exec_id.is_empty() {
                    Arc::clone(&container.init.exit_code)
                } else if let Some(exec) = container.execs.get(&req.exec_id) {
                    Arc::clone(&exec.exit_code)
                } else {
                    return Err(containerd_shim::Error::NotFoundError(format!(
                        "exec {} not found",
                        req.exec_id
                    ))
                    .into());
                }
            } else {
                return Err(containerd_shim::Error::NotFoundError(format!(
                    "container {} not found",
                    req.id
                ))
                .into());
            }
        }; // state lock released here

        loop {
            {
                let ec = exit_code_arc.lock().unwrap();
                if let Some(code) = *ec {
                    let mut resp = api::WaitResponse::new();
                    resp.exit_status = code as u32;
                    resp.exited_at = now_timestamp();
                    return Ok(resp);
                }
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    }

    async fn stats(
        &self,
        _ctx: &TtrpcContext,
        req: api::StatsRequest,
    ) -> TtrpcResult<api::StatsResponse> {
        // Use the poll as a clock for per-container writable
        // usage (logged; see `crate::usage` for why the number cannot
        // ride in the payload below) — never as a reason to change the
        // payload's shape. Returns without waiting on the guest.
        {
            let (guest_cid, guest_name, is_workload) = {
                let state = self.state.lock().unwrap();
                (
                    state.guest_cid,
                    state.guest_name(&req.id),
                    state.containers.contains_key(&req.id)
                        && state.sandbox_id.as_deref() != Some(req.id.as_str()),
                )
            };
            if let (true, Some(cid)) = (is_workload, guest_cid) {
                self.usage.sample(&req.id, &guest_name, cid);
            }
        }

        // An empty response (no `stats` Any) poisons the CRI plugin's
        // ListContainerStats for the WHOLE node: containerd fails the
        // aggregate call with `failed to decode container metrics: type
        // with url : not found`, kubelet's summary API loses container
        // stats, and metrics-server serves nothing (which even blocks
        // namespace deletion via the stale aggregated-API discovery).
        // Return a valid empty cgroups Metrics payload instead — the VM's
        // real resource accounting lives host-side in the k7d daemon's
        // per-VM cgroup. The guest's per-container writable-layer usage
        // deliberately does NOT go in here: `Metrics` has no filesystem
        // field, so every candidate would mean writing storage bytes
        // into a counter kubelet reads as cpu/memory/blkio.
        let metrics = containerd_shim_protos::cgroups::metrics::Metrics::new();
        let any = containerd_shim::util::convert_to_any(Box::new(metrics))
            .map_err(|e| containerd_shim::Error::Other(format!("stats Any: {e}")))?;
        let mut resp = api::StatsResponse::new();
        resp.set_stats(any);
        Ok(resp)
    }

    async fn connect(
        &self,
        _ctx: &TtrpcContext,
        req: api::ConnectRequest,
    ) -> TtrpcResult<api::ConnectResponse> {
        log::info!("Connect: id={}", req.id);

        // A shim that receives Connect without
        // ever having run Create is a fresh process containerd pointed
        // at an existing sandbox (e.g. reconnect after a containerd
        // restart raced a shim respawn). Rebuild the sandbox state
        // from the k7d daemon instead of answering with an empty shim.
        // "No such sandbox" is returned as NotFound — loudly — so
        // kubelet recreates the pod.
        //
        // A sandbox whose VM is DEFERRED to the first
        // workload Create legitimately has `vm_id == None` right after
        // its own Create — the daemon knows nothing about it yet, so a
        // reattach would fail "no such sandbox" and containerd would
        // tear the fresh sandbox down in a loop. Only reattach ids
        // this shim has truly never seen.
        let needs_reattach = {
            let state = self.state.lock().unwrap();
            state.vm_id.is_none()
                && state.pending_vm.is_none()
                && state.sandbox_id.as_deref() != Some(req.id.as_str())
                && !state.containers.contains_key(&req.id)
                && !req.id.is_empty()
        };
        if needs_reattach {
            reattach_sandbox_state(&self.state, &req.id).map_err(|e| {
                debug_log_cni(&format!("Connect: reattach {} failed: {e}", req.id));
                containerd_shim::Error::NotFoundError(format!(
                    "sandbox {}: reattach failed: {e}",
                    req.id
                ))
            })?;
            debug_log_cni(&format!("Connect: reattached sandbox {}", req.id));
        }

        let mut resp = api::ConnectResponse::new();
        resp.shim_pid = std::process::id();
        resp.version = "0.1.0".to_string();
        Ok(resp)
    }

    async fn shutdown(
        &self,
        _ctx: &TtrpcContext,
        req: api::ShutdownRequest,
    ) -> TtrpcResult<api::Empty> {
        log::info!("Shutdown requested: id={}", req.id);

        // Shims now group per pod (sandbox-id
        // grouping in start_shim), but a crashed predecessor of the
        // SAME pod leaves its socket path behind, so containerd can
        // still route the dead shim's Shutdown at a freshly spawned
        // shim serving a *different* sandbox. Tearing down our own VM
        // for a foreign id would take a healthy pod with it — stop the
        // predecessor's orphaned VM instead and stay alive.
        let foreign = {
            let state = self.state.lock().unwrap();
            !req.id.is_empty()
                && state
                    .sandbox_id
                    .as_ref()
                    .is_some_and(|sid| *sid != req.id && !state.containers.contains_key(&req.id))
        };
        if foreign {
            debug_log_cni(&format!(
                "Shutdown: foreign id {} (ours: {:?}); stopping its daemon VM only",
                req.id,
                self.state.lock().unwrap().sandbox_id
            ));
            if let Some(vm_id) = lookup_daemon_sandbox(&req.id) {
                stop_daemon_vm(&vm_id);
            }
            cleanup_state_dir(&req.id);
            return Ok(api::Empty::new());
        }

        {
            let mut state = self.state.lock().unwrap();
            // Parallel to the sandbox Delete cleanup: ask the daemon
            // to stop the VM (no-op when Delete already did).
            if let Some(vm_id) = state.vm_id.take() {
                stop_daemon_vm(&vm_id);
            }
            state.agent = None;
            state.pending_vm = None;

            // Parallel to the sandbox Delete cleanup, also
            // tear down per-pod kubelet volume binds on Shutdown.
            if let Some(pv) = state.pod_volumes.take() {
                pv.cleanup();
            }

            if let Some(ref dir) = state.state_dir {
                let _ = std::fs::remove_dir_all(dir);
            }
        }

        {
            let mut bridges = self.bridges.lock().unwrap();
            bridges.clear();
        }

        self.exit.notify_one();

        Ok(api::Empty::new())
    }

    async fn close_io(
        &self,
        _ctx: &TtrpcContext,
        req: api::CloseIORequest,
    ) -> TtrpcResult<api::Empty> {
        log::info!(
            "CloseIO: id={} exec_id={} stdin={}",
            req.id,
            req.exec_id,
            req.stdin
        );
        // Closing stdin of a TTY exec means the client
        // detached — hang the guest-side session up (SIGHUP).
        if !req.exec_id.is_empty() && req.stdin {
            if let Some(crate::exec::PtySessionState::Active(w)) =
                self.pty_sessions.lock().unwrap().get(&req.exec_id)
            {
                let _ = w.send_eof();
            }
        }
        Ok(api::Empty::new())
    }

    async fn resize_pty(
        &self,
        _ctx: &TtrpcContext,
        req: api::ResizePtyRequest,
    ) -> TtrpcResult<api::Empty> {
        log::info!(
            "ResizePty: id={} exec_id={} {}x{}",
            req.id,
            req.exec_id,
            req.width,
            req.height
        );
        // Only PTY exec processes have a window to resize.
        if req.exec_id.is_empty() {
            return Ok(api::Empty::new());
        }
        let rows = u16::try_from(req.height).unwrap_or(u16::MAX);
        let cols = u16::try_from(req.width).unwrap_or(u16::MAX);
        let mut sessions = self.pty_sessions.lock().unwrap();
        match sessions.get(&req.exec_id) {
            Some(crate::exec::PtySessionState::Active(w)) => {
                if let Err(e) = w.send_winch(rows, cols) {
                    log::warn!("ResizePty {}: {e}", req.exec_id);
                }
            }
            // Bridge not connected yet (containerd sends the initial
            // size racing Start) — remember it for the handshake.
            _ => {
                sessions.insert(
                    req.exec_id.clone(),
                    crate::exec::PtySessionState::Pending { rows, cols },
                );
            }
        }
        Ok(api::Empty::new())
    }

    async fn pause(&self, _ctx: &TtrpcContext, _req: api::PauseRequest) -> TtrpcResult<api::Empty> {
        Ok(api::Empty::new())
    }

    async fn resume(
        &self,
        _ctx: &TtrpcContext,
        _req: api::ResumeRequest,
    ) -> TtrpcResult<api::Empty> {
        Ok(api::Empty::new())
    }

    async fn pids(
        &self,
        _ctx: &TtrpcContext,
        _req: api::PidsRequest,
    ) -> TtrpcResult<api::PidsResponse> {
        Ok(api::PidsResponse::new())
    }

    async fn checkpoint(
        &self,
        _ctx: &TtrpcContext,
        _req: api::CheckpointTaskRequest,
    ) -> TtrpcResult<api::Empty> {
        Ok(api::Empty::new())
    }

    async fn update(
        &self,
        _ctx: &TtrpcContext,
        _req: api::UpdateTaskRequest,
    ) -> TtrpcResult<api::Empty> {
        Ok(api::Empty::new())
    }
}

/// Parse the OCI Process spec containerd attaches to `Exec` requests.
/// Returns `(args, terminal, term)` where `term` falls back to `xterm`
/// when the env carries no `TERM=` entry.
fn parse_exec_process_spec(
    spec: Option<&containerd_shim::protos::protobuf::well_known_types::any::Any>,
) -> (Vec<String>, bool, String) {
    let Some(process) = spec
        .and_then(|any| std::str::from_utf8(&any.value).ok())
        .and_then(|s| serde_json::from_str::<serde_json::Value>(s).ok())
    else {
        return (Vec::new(), false, "xterm".to_string());
    };
    let args = process
        .get("args")
        .and_then(|a| a.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|v| v.as_str().map(String::from))
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    let terminal = process
        .get("terminal")
        .and_then(serde_json::Value::as_bool)
        .unwrap_or(false);
    let term = process
        .get("env")
        .and_then(|e| e.as_array())
        .and_then(|arr| {
            arr.iter()
                .filter_map(|v| v.as_str())
                .find_map(|kv| kv.strip_prefix("TERM="))
        })
        .unwrap_or("xterm")
        .to_string();
    (args, terminal, term)
}

fn run_exec_bridge(
    guest_cid: u64,
    container_name: &str,
    args: &[String],
    exit_code: &Arc<Mutex<Option<i32>>>,
    stdout_path: &str,
    stderr_path: &str,
) {
    let mut agent = match k7d::api::AgentClient::connect_vsock(guest_cid, Duration::from_secs(10)) {
        Ok(a) => a,
        Err(e) => {
            log::error!("exec bridge: agent connect failed: {e}");
            let mut ec = exit_code.lock().unwrap();
            *ec = Some(-1);
            return;
        }
    };

    let args_refs: Vec<&str> = args.iter().map(String::as_str).collect();
    match agent.container_exec(container_name, &args_refs) {
        Ok(result) => {
            if !stdout_path.is_empty() {
                if let Ok(mut f) = std::fs::OpenOptions::new().write(true).open(stdout_path) {
                    let _ = std::io::Write::write_all(&mut f, result.stdout.as_bytes());
                }
            }
            if !stderr_path.is_empty() {
                if let Ok(mut f) = std::fs::OpenOptions::new().write(true).open(stderr_path) {
                    let _ = std::io::Write::write_all(&mut f, result.stderr.as_bytes());
                }
            }
            let mut ec = exit_code.lock().unwrap();
            *ec = Some(result.exit_code);
        }
        Err(e) => {
            log::error!("exec bridge: container_exec failed: {e}");
            let mut ec = exit_code.lock().unwrap();
            *ec = Some(-1);
        }
    }
}

/// Mount the container rootfs on the host using the mount
/// specifications from containerd (overlayfs lowerdir/upperdir/
/// workdir) so it can be packed into an erofs image. Fail-loud: a
/// rootfs that cannot be materialized must fail the workload Create.
fn mount_rootfs(
    mounts: &[containerd_shim::protos::types::mount::Mount],
    target: &Path,
) -> Result<(), String> {
    let mut last_err = "no rootfs mounts provided".to_string();
    for m in mounts {
        let fs_type = &m.type_;
        let source = if m.source.is_empty() {
            "none"
        } else {
            &m.source
        };
        let options = m.options.join(",");

        log::info!(
            "mounting rootfs: type={fs_type} source={source} target={} options={options}",
            target.display()
        );

        let status = std::process::Command::new("mount")
            .args(["-t", fs_type, "-o", &options, source])
            .arg(target)
            .status();

        match status {
            Ok(s) if s.success() => return Ok(()),
            Ok(s) => {
                last_err = format!(
                    "mount -t {fs_type} {source} -> {}: exit {s}",
                    target.display()
                );
            }
            Err(e) => last_err = format!("mount -t {fs_type} {source}: {e}"),
        }
    }
    Err(last_err)
}

/// Fix an already-parsed OCI config.json for our minimal guest
/// kernel and return the serialized result:
/// - Point `root.path` at the agent-mounted erofs rootfs device
///   (`guest_root`) — the agent assembles overlay(erofs, tmpfs) and
///   patches its own copy of the bundle
/// - Strip namespace types the kernel doesn't support (keep pid,
///   mount, cgroup — this restores the cgroup namespace for
///   Kata-like per-container cgroup2 views)
/// - Strip mount types the kernel doesn't support (mqueue, hugetlbfs)
/// - Translate `cgroup`/`cgroup2` mounts to the OCI `cgroup` type so
///   guest runc mounts the guest's cgroup2 hierarchy (the
///   guest is cgroup2-only; stripping these left
///   `/sys/fs/cgroup` empty and forced nested daemons like dockerd to
///   `mount -t cgroup2` themselves)
/// - Rewrite kubelet-volume mount sources to their in-VM
///   paths via the [`k7d::volumes::MountRewriteMap`]
/// - Strip remaining bind mounts whose source is outside the
///   container rootfs and wasn't covered by the rewrite map
/// - Strip seccomp, apparmor, `maskedPaths`, `readonlyPaths`,
///   `cgroupsPath` (runc creates a fresh guest path)
/// - Preserve CRI `linux.resources` (memory/cpu/…) so guest runc
///   enforces per-container cgroup limits; always
///   force a devices allow-all (CHALLENGES #36)
///
/// Fail-loud: the caller reads and parses
/// `config.json` once and propagates any read/parse error before
/// reaching here, so this function never falls back to copying a
/// raw, unfixed config (which would leave host-only bind mounts and
/// namespace paths the guest can't satisfy). A serialization
/// failure is returned as an `io::Error` so Create fails.
fn fix_oci_config(
    mut spec: serde_json::Value,
    rewrites: &k7d::volumes::MountRewriteMap,
    guest_root: Option<&str>,
) -> std::io::Result<String> {
    // The container rootfs lives on an erofs
    // virtio-blk device mounted in the guest — rewrite `root.path`
    // to it. The agent detects the read-only erofs lower and builds
    // the tmpfs-upper overlay before handing the bundle to runc.
    if let Some(guest_root) = guest_root {
        match spec.get_mut("root").and_then(|r| r.as_object_mut()) {
            Some(root) => {
                root.insert(
                    "path".to_string(),
                    serde_json::Value::String(guest_root.to_string()),
                );
            }
            None => {
                spec["root"] = serde_json::json!({ "path": guest_root, "readonly": false });
            }
        }
    }
    // Apply the per-pod rewrite map FIRST (before the
    // strip pass below), so a kubelet-set mount whose host source
    // we know how to translate ends up with an in-VM source string
    // and survives the bind-mount strip downstream. Untranslated
    // bind mounts (hostPath, /etc/resolv.conf, etc.) are still
    // dropped by the strip pass — chunk 2b extends the rewrite map
    // to cover those cases too.
    if !rewrites.is_empty() {
        let summary = rewrites.rewrite_oci_mounts(&mut spec);
        if !summary.rewritten.is_empty() || !summary.stripped.is_empty() {
            log::info!(
                "OCI rewrite: translated {} mount source(s), {} bind mount(s) without a \
                 rewrite will fall through to the strip pass below",
                summary.rewritten.len(),
                summary.stripped.len(),
            );
        }
    }

    // Containerd's OCI config includes namespace entries with `path` fields
    // like "/proc/{sandbox_pid}/ns/ipc" — these reference host namespace files
    // that don't exist inside the guest VM. Strip the `path` so runc creates
    // fresh namespaces instead of trying to join non-existent host ones.
    // Also remove the network namespace entirely — the guest VM has its own
    // network stack, and runc can't create a useful netns inside the VM.
    if let Some(namespaces) = spec
        .pointer_mut("/linux/namespaces")
        .and_then(|v| v.as_array_mut())
    {
        // The cgroup namespace is KEPT: with cgroupns, the
        // translated cgroup2 mount below shows each container its own
        // private subtree — exactly what Kata/stock k8s containers
        // see. Nested daemons (dockerd, k3s) handle cgroup2's
        // no-internal-process constraint themselves via the standard
        // dind-style evacuation (moby hack/dind), so 18b's guest-root
        // shortcut (dropping cgroupns) is unnecessary and
        // over-permissive.
        namespaces.retain(|ns| {
            let ns_type = ns.get("type").and_then(|t| t.as_str()).unwrap_or_default();
            ns_type != "network"
        });
        for ns in namespaces.iter_mut() {
            if let Some(obj) = ns.as_object_mut() {
                obj.remove("path");
            }
        }
    }

    let unsupported_mount_types = ["mqueue", "hugetlbfs"];
    let virtual_fs_types = ["proc", "tmpfs", "sysfs", "devpts", "devtmpfs"];
    if let Some(mounts) = spec.get_mut("mounts").and_then(|v| v.as_array_mut()) {
        // Translate cgroup/cgroup2 mounts to the OCI `cgroup`
        // type instead of stripping them. The guest mounts cgroup2 at
        // /sys/fs/cgroup (init.sh), so guest runc's
        // cgroup-mount special case mounts the unified hierarchy at the
        // requested destination, honoring the CRI-set options (ro for
        // regular containers, rw for privileged ones). The cgroup
        // namespace is kept, so the mount shows each
        // container its own private namespaced subtree.
        for m in mounts.iter_mut() {
            let mount_type = m.get("type").and_then(|t| t.as_str()).unwrap_or_default();
            if mount_type == "cgroup" || mount_type == "cgroup2" {
                if let Some(obj) = m.as_object_mut() {
                    obj.insert("type".into(), serde_json::Value::String("cgroup".into()));
                    obj.insert("source".into(), serde_json::Value::String("cgroup".into()));
                }
            }
        }
        mounts.retain(|m| {
            let mount_type = m.get("type").and_then(|t| t.as_str()).unwrap_or_default();
            if unsupported_mount_types.contains(&mount_type) {
                return false;
            }
            if mount_type == "cgroup" {
                return true;
            }
            // Keep virtual filesystem mounts (proc, tmpfs, sysfs, devpts)
            if virtual_fs_types.contains(&mount_type) {
                return true;
            }
            // Strip bind mounts whose source is a HOST path (kubelet's
            // etc-hosts, hostname, resolv.conf, service account
            // tokens, hostPath volumes). Those host paths don't
            // exist inside the guest VM. The container rootfs is
            // already on virtiofs.
            //
            // CARVE-OUT: keep bind mounts whose source
            // has already been rewritten by the rewrite map above to
            // an in-VM path — anything under `/mnt/` (virtiofs-era
            // volume shares and the packed block-volume erofs image)
            // or `/run/k7d/` (block-path mounts: emptyDir guest
            // tmpfs, pushed etc-files, erofs rootfs/tools devices,
            // k7d ext4 disk volumes). runc inside the VM can and
            // should bind-mount from them into the container's
            // rootfs as kubelet asked. Without this carve-out the
            // strip pass would drop every kubelet volume right
            // after the rewrite pass put it in the right place.
            let src = m.get("source").and_then(|s| s.as_str()).unwrap_or_default();
            let is_in_vm_source = src.starts_with("/mnt/") || src.starts_with("/run/k7d/");
            let is_bind = mount_type.is_empty()
                || mount_type == "bind"
                || m.get("options")
                    .and_then(|o| o.as_array())
                    .is_some_and(|arr| {
                        arr.iter()
                            .any(|v| v.as_str().is_some_and(|s| s == "bind" || s == "rbind"))
                    });
            !is_bind || is_in_vm_source
        });
    }

    if let Some(linux) = spec.get_mut("linux").and_then(|v| v.as_object_mut()) {
        linux.remove("seccomp");
        linux.remove("maskedPaths");
        linux.remove("readonlyPaths");
        linux.remove("cgroupsPath");
        let resources = sanitize_guest_resources(linux.remove("resources"))?;
        linux.insert("resources".to_string(), resources);
    }

    // Remove apparmor profile
    if let Some(process) = spec.get_mut("process").and_then(|v| v.as_object_mut()) {
        process.remove("apparmorProfile");
    }

    serde_json::to_string_pretty(&spec)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))
}

/// Keep CRI memory/cpu (and other) resource fields so
/// guest runc enforces per-container cgroup limits; force devices
/// allow-all (CHALLENGES #36); drop swap fields/unified keys the
/// no-swap guest kernel cannot honour (CHALLENGES #54).
fn sanitize_guest_resources(
    resources: Option<serde_json::Value>,
) -> std::io::Result<serde_json::Value> {
    let mut resources = match resources {
        Some(serde_json::Value::Object(map)) => map,
        Some(other) => {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("linux.resources must be an object, got {other}"),
            ));
        }
        None => serde_json::Map::new(),
    };
    // Structured OCI `memory.swap` maps to memory.swap.max — absent
    // when CONFIG_SWAP=n.
    if let Some(serde_json::Value::Object(mem)) = resources.get_mut("memory") {
        mem.remove("swap");
    }
    let drop_unified = match resources.get_mut("unified") {
        Some(serde_json::Value::Object(unified)) => {
            for key in [
                "memory.swap.max",
                "memory.swap.high",
                "memory.zswap.max",
                "memory.zswap.writeback",
                // oom.group=1 kills every task in the container cgroup
                // on soft OOM (including an over-limit kubectl exec).
                // Without exit observation the shim never
                // publishes that death, so kubelet cannot restart and
                // the container stays Stopped. Default (process-level)
                // OOM still enforces memory.max; the main-process
                // hog test covers whole-container OOMKilled.
                "memory.oom.group",
            ] {
                unified.remove(key);
            }
            unified.is_empty()
        }
        _ => false,
    };
    if drop_unified {
        resources.remove("unified");
    }
    resources.insert(
        "devices".to_string(),
        serde_json::json!([{ "allow": true, "access": "rwm" }]),
    );
    Ok(serde_json::Value::Object(resources))
}

/// Locate the static runc binary on the host for the guest tools
/// image (replaces the virtiofs
/// `/mnt/state/bin/runc` placement).
fn find_runc_binary() -> Option<PathBuf> {
    let candidates = [
        std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .and_then(|p| p.parent())
            .map(|p| p.join("guest/rootfs/runc.amd64"))
            .unwrap_or_default(),
        std::path::PathBuf::from("/root/k7d/guest/rootfs/runc.amd64"),
        // Release install location (k7 Ansible playbook).
        std::path::PathBuf::from("/opt/k7d/runc.amd64"),
        std::path::PathBuf::from("/usr/bin/runc"),
        std::path::PathBuf::from("/usr/sbin/runc"),
    ];
    candidates.into_iter().find(|c| c.exists())
}

/// Build (or cache-hit) the "tools" erofs image carrying the static
/// runc, attached to every pod VM as a read-only virtio-blk device
/// mounted at [`GUEST_TOOLS_MOUNT`]. Content-walk keyed, so a runc
/// upgrade on the host produces a new image while running pods keep
/// theirs. Fail-loud: a pod without runc cannot start containers.
fn prepare_tools_image(cache_dir: &Path) -> Result<PathBuf, String> {
    let runc = find_runc_binary().ok_or(
        "runc binary not found on host (looked for guest/rootfs/runc.amd64, \
         /usr/bin/runc, /usr/sbin/runc) — container start would fail",
    )?;
    let staging = std::env::temp_dir().join(format!(
        "k7d-tools-stage-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_nanos())
    ));
    std::fs::create_dir_all(&staging).map_err(|e| format!("create {}: {e}", staging.display()))?;
    let result = (|| {
        let dst = staging.join("runc");
        std::fs::copy(&runc, &dst).map_err(|e| format!("copy {} -> tools: {e}", runc.display()))?;
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&dst, std::fs::Permissions::from_mode(0o755))
                .map_err(|e| format!("chmod tools runc: {e}"))?;
        }
        k7d::erofs::cached_erofs_image(cache_dir, &staging, None)
            .map_err(|e| format!("tools erofs image: {e}"))
    })();
    let _ = std::fs::remove_dir_all(&staging);
    result
}

/// Configure the guest's eth0 / default route once its VM is up.
///
/// If the daemon moved this VM's TAP into a pod netns and
/// put a 10.200.0.1 gateway on the in-netns bridge, configure the
/// guest's eth0 with the matching `10.200.0.{2 + vm_index}` address
/// and a default route via that gateway (plus a pinned gateway ARP
/// entry — see the inline comment). Cluster-mode
/// pods (TAP on the shared host bridge) get the same eth0 identity
/// without the ARP pin.
///
/// Best-effort: log on failure and continue. `test_shim` (today)
/// doesn't need pod-IP-routed traffic to its pods so this can fail
/// without breaking the suite.
fn configure_guest_network(state: &mut SandboxState) {
    if state.pod_netns.is_some() {
        let guest_ip = format!("10.200.0.{}", 2 + state.vm_index.unwrap_or(0));
        if let Ok(agent) = state.agent_mut() {
            debug_log_cni(&format!(
                "Create: configuring guest eth0={guest_ip} gateway=10.200.0.1"
            ));
            if let Err(e) = agent.exec(&[
                "ifconfig",
                "eth0",
                &guest_ip,
                "netmask",
                "255.255.255.0",
                "up",
            ]) {
                debug_log_cni(&format!("Create: guest ifconfig eth0 failed: {e}"));
            } else if let Err(e) =
                agent.exec(&["ip", "route", "add", "default", "via", "10.200.0.1"])
            {
                debug_log_cni(&format!("Create: guest add default route failed: {e}"));
            } else if let Err(e) = agent.exec(&[
                "ip",
                "neigh",
                "replace",
                "10.200.0.1",
                "lladdr",
                "aa:bb:00:00:00:01",
                "dev",
                "eth0",
                "nud",
                "permanent",
            ]) {
                // Pin the gateway MAC. Without this the guest ARPs
                // for 10.200.0.1, the bridge floods the request, and
                // a stray pod on flannel's cni0 may reply first with
                // a wrong MAC — bridges then L2-forward the guest's
                // reply traffic out `eth0` instead of letting it
                // L3-route + SNAT. The bridge MAC is pinned in
                // create_bridge_in_netns; keep these in sync.
                debug_log_cni(&format!(
                    "Create: guest add static ARP for gateway failed: {e}"
                ));
            } else {
                debug_log_cni("Create: guest eth0 + default route + gateway ARP configured");
            }
        }
    } else if state.cluster_mode {
        // Cluster-mode pods skip the CNI attach (their TAP stays on
        // the shared host bridge), so nothing else gives the guest
        // its stable IP. 10.200.0.1 lives on the host bridge, which
        // also masquerades 10.200.0.0/24 egress. No static ARP pin
        // is needed: the gateway IP is the host bridge device
        // itself, so ARP resolves unambiguously.
        let guest_ip = format!("10.200.0.{}", 2 + state.vm_index.unwrap_or(0));
        if let Ok(agent) = state.agent_mut() {
            debug_log_cni(&format!(
                "Start: cluster-mode guest eth0={guest_ip} gateway=10.200.0.1"
            ));
            if let Err(e) = agent.exec(&[
                "ifconfig",
                "eth0",
                &guest_ip,
                "netmask",
                "255.255.255.0",
                "up",
            ]) {
                debug_log_cni(&format!(
                    "Start: cluster-mode guest ifconfig eth0 failed: {e}"
                ));
            } else if let Err(e) =
                agent.exec(&["ip", "route", "add", "default", "via", "10.200.0.1"])
            {
                debug_log_cni(&format!(
                    "Start: cluster-mode guest default route failed: {e}"
                ));
            } else {
                debug_log_cni("Start: cluster-mode guest eth0 + default route set");
            }
        }
    }
}

/// Release a deleted container's claim on its rootfs
/// erofs key. The guest erofs mounts (boot rootfs devices and image
/// slots) are NEVER unmounted at container Delete — a live sibling
/// may still run from the same mount (same-image init + main), and an
/// assigned slot is immutable until VM teardown (fork backing-file
/// sharing). The agent only tears down the exited container's private
/// overlay (tmpfs upper), never the shared erofs lower. The refcount
/// makes that invariant checkable: fail loud if a still-referenced
/// key lost its device entry — Delete would be yanking a live
/// container's rootfs.
fn release_container_rootfs(state: &mut SandboxState, container_id: &str) -> Result<(), String> {
    let Some((key, remaining)) = state.release_rootfs_key(container_id) else {
        return Ok(()); // no rootfs recorded (pause task / failed Create)
    };
    let mount_live = state.rootfs_devices.iter().any(|d| d.key == key);
    if remaining > 0 && !mount_live {
        return Err(format!(
            "Delete {container_id}: rootfs erofs key {key} is still used by {remaining} \
             live container(s) but its guest mount is gone (refcount \
             invariant violated)"
        ));
    }
    debug_log_cni(&format!(
        "Delete {container_id}: released rootfs key {key} ({remaining} live user(s) \
         remain; guest erofs mount retained until VM teardown)"
    ));
    if let Err(e) = state.persist_block_state() {
        log::warn!("Delete {container_id}: persist block state: {e}");
    }
    Ok(())
}

/// The block-path workload `Create`.
///
/// 1. Resolve the container's rootfs into a cached erofs image and
///    attach it as a read-only virtio-blk device (dedup per image).
/// 2. Translate whitelisted etc-files to guest-tmpfs pushes, k7d
///    disk-volume binds to raw ext4 virtio-blk devices, and any
///    remaining hostPath / unsupported-PVC binds to the **explicit
///    virtiofs fallback** (slow-fork, loudly logged).
/// 3. Boot the VM on the first workload (the `pending_vm` config
///    from sandbox Create plus everything gathered above), connect
///    the agent, and configure the guest network.
/// 4. Push the etc-files and the fixed OCI bundle over vsock into
///    guest tmpfs (`/run/k7d/bundles/<id>/config.json`).
///
/// Fail-loud throughout: a pod must never reach Running without its
/// rootfs or volumes.
fn workload_create_block(
    state: &mut SandboxState,
    req: &api::CreateTaskRequest,
) -> Result<(), String> {
    let sandbox_id = state
        .sandbox_id
        .clone()
        .ok_or("workload Create before sandbox Create (no sandbox_id)")?;

    // Read + parse the workload's OCI config ONCE (fail-loud): an
    // unreadable/unparseable config.json must
    // NOT let the pod reach Running without its mounts.
    let src_config = Path::new(&req.bundle).join("config.json");
    let spec_data = std::fs::read_to_string(&src_config)
        .map_err(|e| format!("read {}: {e}", src_config.display()))?;
    let spec_val: serde_json::Value = serde_json::from_str(&spec_data)
        .map_err(|e| format!("parse {}: {e}", src_config.display()))?;

    log_container_scratch_placement(state, &req.id, &spec_val);

    let cache_dir = Path::new(k7d::erofs::DEFAULT_CACHE_DIR);
    let guest_root = prepare_rootfs_device(state, req, cache_dir)?;
    let etc_to_push = collect_etc_files(state, &spec_val);
    prepare_k7d_disks(state, &spec_val)?;
    prepare_ro_hostpath_images(state, &spec_val, cache_dir)?;
    prepare_hostpath_fallback(state, &sandbox_id, &spec_val)?;

    // First workload: submit the accumulated VmConfig to the daemon
    // and bring the guest up.
    if state.pending_vm.is_some() {
        boot_pending_vm(state)?;
    }
    if state.agent.is_none() {
        state.connect_agent()?;
    }

    push_etc_files(state, &etc_to_push)?;

    // Fix the OCI config for the guest (root.path -> erofs overlay,
    // volume sources -> in-VM paths, host-only mounts stripped) and
    // push the bundle over vsock into guest tmpfs.
    let rewrites = state.mount_rewrite_map();
    let fixed = fix_oci_config(spec_val, &rewrites, Some(&guest_root))
        .map_err(|e| format!("fix OCI config for {}: {e}", req.id))?;
    // Host-side copy for debugging (best-effort — the guest copy is
    // the one runc consumes).
    if let Some(ref dir) = state.state_dir {
        let container_dir = dir.join("containers").join(&req.id);
        let _ = std::fs::create_dir_all(&container_dir);
        let _ = std::fs::write(container_dir.join("config.json"), &fixed);
    }
    let guest_config = format!("{GUEST_BUNDLES_BASE}/{}/config.json", req.id);
    state
        .agent_mut()?
        .write_file(&guest_config, fixed.as_bytes())
        .map_err(|e| format!("push bundle {guest_config}: {e}"))?;
    debug_log_cni(&format!(
        "Create: workload {} bundle pushed to {guest_config} (root.path={guest_root})",
        req.id
    ));

    state.persist_block_state()?;
    Ok(())
}

/// Say in the log which writable layer this container got.
///
/// The agent does the actual matching (it reads the container's
/// `io.kubernetes.cri.container-name` off the bundle and looks for a
/// mount of that name), so the shim cannot fail a mismatch: a name in
/// [`ANN_CONTAINER_SCRATCH_SIZE`] that belongs to no container in the
/// pod provisions an image nobody mounts, and the container the author
/// meant goes on sharing the pod scratch. Printing both the container's
/// name and the declared set makes that visible on the spot instead of
/// as an unexplained `ENOSPC` later.
fn log_container_scratch_placement(
    state: &SandboxState,
    container_id: &str,
    spec: &serde_json::Value,
) {
    if state.container_scratch.is_empty() {
        return;
    }
    let k8s_name = spec
        .pointer("/annotations")
        .and_then(|a| a.get(CRI_CONTAINER_NAME))
        .and_then(serde_json::Value::as_str)
        .unwrap_or_default();
    match state.container_scratch.get(k8s_name) {
        Some(size) => debug_log_cni(&format!(
            "Create: workload {container_id} ({k8s_name}) gets its own {} MiB writable image \
             ({ANN_CONTAINER_SCRATCH_SIZE})",
            size / (1024 * 1024)
        )),
        None => debug_log_cni(&format!(
            "Create: workload {container_id} ({k8s_name}) shares the pod scratch disk — \
             {ANN_CONTAINER_SCRATCH_SIZE} names {:?}, which does not include it",
            state.container_scratch.keys().collect::<Vec<_>>()
        )),
    }
}

/// Resolve the workload's container rootfs into a cached erofs image
/// and ensure it is attached to the pod VM as a read-only virtio-blk
/// device. Returns the guest mount point for the OCI `root.path`.
///
/// Image identity: the containerd overlayfs `lowerdir` chain when
/// present (stable per image on a node; the per-container upperdir
/// is empty at Create and deliberately excluded), else a SHA-256
/// content walk. Cache hits on the lowerdir key skip mounting the
/// snapshot entirely.
fn prepare_rootfs_device(
    state: &mut SandboxState,
    req: &api::CreateTaskRequest,
    cache_dir: &Path,
) -> Result<String, String> {
    let overlay_lower = req.rootfs.iter().find_map(|m| {
        if m.type_ == "overlay" {
            m.options.iter().find_map(|o| o.strip_prefix("lowerdir="))
        } else {
            None
        }
    });

    let image = if let Some(lower) = overlay_lower {
        let key = k7d::erofs::snapshot_cache_key(lower);
        let cached = cache_dir.join(format!("{key}.erofs"));
        if cached.exists() {
            log::info!(
                "rootfs erofs cache hit for {}: {}",
                req.id,
                cached.display()
            );
            cached
        } else {
            pack_mounted_rootfs(state, req, cache_dir, Some(&key))?
        }
    } else if !req.rootfs.is_empty() {
        // Non-overlay snapshotters (bind of a merged dir): the
        // source path is unique per container, so identity must be
        // a content walk.
        pack_mounted_rootfs(state, req, cache_dir, None)?
    } else {
        // Direct-bundle callers (no containerd mounts): pack the
        // bundle's rootfs dir, content-walk keyed.
        let dir = Path::new(&req.bundle).join("rootfs");
        if !dir.is_dir() {
            return Err(format!(
                "no rootfs mounts and no {} — cannot resolve the container image",
                dir.display()
            ));
        }
        k7d::erofs::cached_erofs_image(cache_dir, &dir, None)
            .map_err(|e| format!("pack bundle rootfs: {e}"))?
    };

    let key = image
        .file_stem()
        .and_then(|s| s.to_str())
        .ok_or_else(|| format!("erofs image {} has no file stem", image.display()))?
        .to_string();

    if let Some(dev) = state.rootfs_devices.iter().find(|d| d.key == key) {
        let guest_mount = dev.guest_mount.clone();
        // A second container of the SAME image (e.g.
        // a main container after a same-image init) shares the mount —
        // record its claim so Delete of the other container knows the
        // mount is still live.
        state
            .container_rootfs_keys
            .insert(req.id.clone(), key.clone());
        return Ok(guest_mount);
    }
    if state.pending_vm.is_none() {
        // virtio-blk devices are boot-time declarations (userspace
        // MMIO, no hotplug), and the VM booted at the FIRST workload
        // Create. A later workload with a DISTINCT image attaches
        // through one of the spare image slots declared at sandbox
        // Create: fill the slot's backing file with
        // the erofs image, then have the agent mount it.
        let guest_mount = assign_image_slot(state, &key, &image, "erofs")?;
        state.rootfs_devices.push(RootfsDevice {
            key: key.clone(),
            guest_mount: guest_mount.clone(),
        });
        state.container_rootfs_keys.insert(req.id.clone(), key);
        return Ok(guest_mount);
    }
    let guest_mount = format!("{GUEST_ROOTFS_PREFIX}-{}", state.rootfs_devices.len());
    let cfg = state
        .pending_vm
        .as_mut()
        .ok_or("pending_vm vanished (checked above)")?;
    cfg.block_devices.push(k7d::control::BlockDeviceConfig {
        host_path: image.to_string_lossy().into_owned(),
        readonly: true,
        guest_mount: Some(guest_mount.clone()),
        fstype: Some("erofs".to_string()),
    });
    state.rootfs_devices.push(RootfsDevice {
        key: key.clone(),
        guest_mount: guest_mount.clone(),
    });
    state.container_rootfs_keys.insert(req.id.clone(), key);
    Ok(guest_mount)
}

/// Declare `N` spare "image slot" virtio-blk devices
/// on the parked [`k7d::control::VmConfig`] — RO, backed by per-pod
/// sparse files of fixed capacity, with **no** `guest_mount` (empty
/// slots must not appear in `k7d.blk=`; the agent would automount
/// garbage). The blk backend reads capacity from backing-file size at
/// boot, hence the up-front ftruncate. Count/size come from the
/// `k7d.katakate.org/image-slots` / `image-slot-size` pod annotations
/// (defaults 4 / 2 GiB); invalid values fail loud.
fn declare_image_slots(
    config: &mut k7d::control::VmConfig,
    ann: &ShimAnnotations,
    state_dir: &Path,
) -> Result<Vec<ImageSlot>, String> {
    let count = match ann.image_slots.as_deref() {
        Some(raw) => raw
            .parse::<u32>()
            .map_err(|e| format!("invalid {ANN_IMAGE_SLOTS} {raw:?}: {e}"))?,
        None => DEFAULT_IMAGE_SLOTS,
    };
    let size = match ann.image_slot_size.as_deref() {
        Some(raw) => raw
            .parse::<u64>()
            .map_err(|e| format!("invalid {ANN_IMAGE_SLOT_SIZE} {raw:?}: {e}"))?,
        None => DEFAULT_IMAGE_SLOT_SIZE,
    };
    if size == 0 || size % 512 != 0 {
        return Err(format!(
            "{ANN_IMAGE_SLOT_SIZE} must be a positive multiple of the 512-byte \
             sector size, got {size}"
        ));
    }
    // Pin-budget check at declaration time so the error can name the
    // annotation. The first workload Create appends more devices
    // (rootfs, k7d disks, RO hostPath images); the VMM re-checks the
    // final total at build.
    let declared = usize::from(config.vsock)
        + config.virtiofs.len()
        + config.block_devices.len()
        + usize::from(config.network.is_some())
        // The daemon appends the sandbox scratch device
        // and every per-container one after the devices declared here,
        // so they spend pins too.
        + usize::from(config.scratch_size_bytes.is_some())
        + config.container_scratch.len();
    if declared + count as usize > MMIO_DEVICE_BUDGET {
        return Err(format!(
            "{ANN_IMAGE_SLOTS}={count} exceeds the MMIO/IOAPIC pin budget: {declared} \
             devices already declared, at most {MMIO_DEVICE_BUDGET} total"
        ));
    }
    let dir = state_dir.join("image-slots");
    std::fs::create_dir_all(&dir).map_err(|e| format!("create {}: {e}", dir.display()))?;
    let mut slots = Vec::with_capacity(count as usize);
    for i in 0..count {
        let device_index = config.block_devices.len();
        if device_index >= 26 {
            return Err(format!(
                "image slot {i} would be block device #{device_index} — the guest \
                 device namespace is vda..vdz (26)"
            ));
        }
        let backing = dir.join(format!("slot-{i}.img"));
        let f = std::fs::OpenOptions::new()
            .create(true)
            .truncate(false)
            .write(true)
            .open(&backing)
            .map_err(|e| format!("create slot backing {}: {e}", backing.display()))?;
        f.set_len(size)
            .map_err(|e| format!("ftruncate slot backing {}: {e}", backing.display()))?;
        config.block_devices.push(k7d::control::BlockDeviceConfig {
            host_path: backing.to_string_lossy().into_owned(),
            readonly: true,
            guest_mount: None,
            fstype: None,
        });
        slots.push(ImageSlot {
            device_index,
            backing: backing.to_string_lossy().into_owned(),
            key: None,
            guest_mount: None,
        });
    }
    Ok(slots)
}

/// Attach `image` to the RUNNING VM through a spare
/// image slot. The fill goes through the slot backing file's **same
/// inode** (open + FICLONE / `copy_file_range`, never rename — the blk
/// backend holds an fd from boot), then ftruncates back to slot
/// capacity so backend `pread`s past the image tail don't hit EOF.
/// The agent then `BLKFLSBUF`s + mounts the device. A slot's content
/// is immutable once assigned (RO erofs; a new image takes a new
/// slot), which keeps forked clones sharing backing files. Fail-loud
/// on exhaustion and oversized images, naming the annotation knobs.
fn assign_image_slot(
    state: &mut SandboxState,
    key: &str,
    image: &Path,
    fstype: &str,
) -> Result<String, String> {
    // Same image already riding a slot (e.g. a rootfs and a RO
    // hostPath resolving to the same erofs key): reuse the mount.
    if let Some(slot) = state
        .image_slots
        .iter()
        .find(|s| s.key.as_deref() == Some(key))
    {
        return slot
            .guest_mount
            .clone()
            .ok_or_else(|| format!("image slot for key {key} has no guest mount"));
    }
    let Some(pos) = state.image_slots.iter().position(|s| s.key.is_none()) else {
        let assigned: Vec<_> = state
            .image_slots
            .iter()
            .filter_map(|s| s.key.as_deref())
            .collect();
        return Err(format!(
            "no free image slot for erofs key {key} — all {} slots are assigned \
             ({assigned:?}). virtio-blk devices are boot-time declarations (no \
             hotplug); raise the {ANN_IMAGE_SLOTS} pod annotation (default \
             {DEFAULT_IMAGE_SLOTS}) to attach more distinct post-boot images.",
            state.image_slots.len()
        ));
    };
    let (device_index, backing) = {
        let slot = &state.image_slots[pos];
        (slot.device_index, PathBuf::from(&slot.backing))
    };
    let image_len = std::fs::metadata(image)
        .map_err(|e| format!("stat image {}: {e}", image.display()))?
        .len();
    let capacity = std::fs::metadata(&backing)
        .map_err(|e| format!("stat slot backing {}: {e}", backing.display()))?
        .len();
    if image_len > capacity {
        return Err(format!(
            "image {} ({image_len} bytes, erofs key {key}) exceeds the image-slot \
             capacity ({capacity} bytes) — raise the {ANN_IMAGE_SLOT_SIZE} pod \
             annotation",
            image.display()
        ));
    }
    clone_or_copy_into(image, &backing)?;
    // Restore the declared capacity: FICLONE / copy leave the file at
    // image size, but the guest saw a `capacity`-sized disk at boot.
    std::fs::OpenOptions::new()
        .write(true)
        .open(&backing)
        .and_then(|f| f.set_len(capacity))
        .map_err(|e| format!("ftruncate {} back to {capacity}: {e}", backing.display()))?;

    let letter = u8::try_from(device_index)
        .ok()
        .filter(|i| *i < 26)
        .map(|i| char::from(b'a' + i))
        .ok_or_else(|| format!("image slot device index {device_index} out of vda..vdz"))?;
    let device = format!("vd{letter}");
    let guest_mount = format!("{GUEST_IMAGE_SLOT_PREFIX}-{pos}");
    if state.agent.is_none() {
        state.connect_agent()?;
    }
    state
        .agent_mut()?
        .mount_blk(&device, fstype, &guest_mount, true)
        .map_err(|e| format!("agent mount_blk {device} ({fstype}) at {guest_mount}: {e}"))?;

    let slot = &mut state.image_slots[pos];
    slot.key = Some(key.to_string());
    slot.guest_mount = Some(guest_mount.clone());
    log::info!(
        "image slot {pos} (dev {device}): {} -> {guest_mount} ({fstype} ro)",
        image.display()
    );
    state.persist_block_state()?;
    Ok(guest_mount)
}

/// Fill `dst`'s content from `src` **via the same inode**: FICLONE
/// (O(1) reflink on XFS/btrfs), then `copy_file_range`, then a plain
/// read/write copy (kernels ≥ 5.19 return `EXDEV` for cross-
/// filesystem `copy_file_range`, and the erofs cache and the slot
/// backing file usually live on different filesystems). Never a
/// rename — the blk backend's boot-time fd must observe the new bytes.
fn clone_or_copy_into(src: &Path, dst: &Path) -> Result<(), String> {
    use std::io::Seek;
    use std::os::fd::AsRawFd;
    let mut src_file =
        std::fs::File::open(src).map_err(|e| format!("open {}: {e}", src.display()))?;
    let mut dst_file = std::fs::OpenOptions::new()
        .write(true)
        .open(dst)
        .map_err(|e| format!("open {}: {e}", dst.display()))?;
    // SAFETY: both fds are valid for the duration of the call; FICLONE
    // takes the source fd as its integer argument.
    let rc = unsafe { libc::ioctl(dst_file.as_raw_fd(), libc::FICLONE, src_file.as_raw_fd()) };
    if rc == 0 {
        return Ok(());
    }
    log::debug!(
        "FICLONE {} -> {}: {}; falling back to copy_file_range",
        src.display(),
        dst.display(),
        std::io::Error::last_os_error()
    );
    let len = src_file
        .metadata()
        .map_err(|e| format!("stat {}: {e}", src.display()))?
        .len();
    let mut off_in: libc::loff_t = 0;
    let mut off_out: libc::loff_t = 0;
    while (off_in as u64) < len {
        let remaining = (len - off_in as u64) as usize;
        // SAFETY: fds are valid; the offset pointers outlive the call
        // and are advanced by the kernel.
        let n = unsafe {
            libc::copy_file_range(
                src_file.as_raw_fd(),
                &raw mut off_in,
                dst_file.as_raw_fd(),
                &raw mut off_out,
                remaining,
                0,
            )
        };
        if n < 0 {
            let err = std::io::Error::last_os_error();
            if off_in == 0
                && matches!(
                    err.raw_os_error(),
                    Some(libc::EXDEV | libc::EINVAL | libc::ENOSYS | libc::EOPNOTSUPP)
                )
            {
                // Cross-filesystem / unsupported: plain read/write copy.
                log::debug!(
                    "copy_file_range {} -> {}: {err}; falling back to read/write copy",
                    src.display(),
                    dst.display()
                );
                dst_file
                    .rewind()
                    .map_err(|e| format!("rewind {}: {e}", dst.display()))?;
                std::io::copy(&mut src_file, &mut dst_file)
                    .map_err(|e| format!("copy {} -> {}: {e}", src.display(), dst.display()))?;
                return Ok(());
            }
            return Err(format!(
                "copy_file_range {} -> {} at offset {off_in}: {err}",
                src.display(),
                dst.display()
            ));
        }
        if n == 0 {
            return Err(format!(
                "copy_file_range {} -> {}: premature EOF at offset {off_in} of {len}",
                src.display(),
                dst.display()
            ));
        }
    }
    Ok(())
}

/// Mount the containerd-provided rootfs (overlayfs) at a scratch
/// point under the sandbox state dir, pack it into a cached erofs
/// image, and unmount. The mount exists only for the pack — the
/// guest never sees it.
fn pack_mounted_rootfs(
    state: &SandboxState,
    req: &api::CreateTaskRequest,
    cache_dir: &Path,
    digest: Option<&str>,
) -> Result<PathBuf, String> {
    let state_dir = state
        .state_dir
        .as_ref()
        .ok_or("no state_dir for rootfs packing")?;
    let target = state_dir.join("containers").join(&req.id).join("rootfs");
    std::fs::create_dir_all(&target).map_err(|e| format!("create {}: {e}", target.display()))?;
    mount_rootfs(&req.rootfs, &target)?;
    let result = k7d::erofs::cached_erofs_image(cache_dir, &target, digest)
        .map_err(|e| format!("pack rootfs erofs: {e}"));
    let umount = std::process::Command::new("umount").arg(&target).status();
    if let Ok(s) = umount {
        if !s.success() {
            log::warn!("umount {} after erofs pack: exit {s}", target.display());
        }
    }
    result
}

/// Whitelisted etc-files (`/etc/{resolv.conf,hosts,hostname}`): the
/// kubelet/CRI-generated host sources are read here and pushed into
/// guest tmpfs over vsock after the VM is up (the block-path
/// replacement for the virtiofs etc-file binds). Returns the
/// `(host, guest)` pairs to push; the rewrite-map entries are added
/// immediately so `fix_oci_config` translates the mounts.
fn collect_etc_files(state: &mut SandboxState, spec: &serde_json::Value) -> Vec<(String, String)> {
    let mut to_push = Vec::new();
    let Some(mounts) = spec.get("mounts").and_then(|m| m.as_array()) else {
        return to_push;
    };
    for mount in mounts {
        let dst = mount
            .get("destination")
            .and_then(|d| d.as_str())
            .unwrap_or_default();
        if !k7d::volumes::ETC_FILE_WHITELIST.contains(&dst) {
            continue;
        }
        let src = mount
            .get("source")
            .and_then(|s| s.as_str())
            .unwrap_or_default();
        if src.is_empty() || !Path::new(src).is_file() {
            continue;
        }
        let leaf = dst.rsplit('/').next().unwrap_or("etc-file");
        // Deterministic per host source, so workloads of the same
        // pod (and shim restarts) agree on the guest path.
        let hash = k7d::erofs::snapshot_cache_key(src);
        let guest = format!("{GUEST_ETC_BASE}/{}-{leaf}", &hash[5..17]);
        state
            .rewrites
            .insert(PathBuf::from(src), PathBuf::from(&guest), true);
        to_push.push((src.to_string(), guest));
    }
    to_push
}

/// Push collected etc-files into guest tmpfs (idempotent across the
/// pod's workloads via [`SandboxState::etc_pushed`]). Fail-loud: a
/// pod without its `/etc/resolv.conf` has broken DNS in ways that
/// are painful to diagnose later.
fn push_etc_files(state: &mut SandboxState, to_push: &[(String, String)]) -> Result<(), String> {
    for (host, guest) in to_push {
        if state.etc_pushed.get(host) == Some(guest) {
            continue;
        }
        let data =
            std::fs::read(host).map_err(|e| format!("read etc-file {host} for push: {e}"))?;
        state
            .agent_mut()?
            .write_file(guest, &data)
            .map_err(|e| format!("push etc-file {host} -> {guest}: {e}"))?;
        state.etc_pushed.insert(host.clone(), guest.clone());
        debug_log_cni(&format!("Create: pushed etc-file {host} -> {guest}"));
    }
    Ok(())
}

/// k7d-provisioned RWO disk volumes (static
/// provisioning): a bind mount whose source is a direct child of
/// `/var/lib/k7d/disks/` opts into a raw ext4 image on the reflink
/// loopback XFS, attached read-write as a virtio-blk device. The
/// image (`<name>.img`, [`K7D_DISK_DEFAULT_SIZE`], sparse) outlives
/// the pod — a restart reattaches it with data intact.
fn prepare_k7d_disks(state: &mut SandboxState, spec: &serde_json::Value) -> Result<(), String> {
    let Some(mounts) = spec.get("mounts").and_then(|m| m.as_array()) else {
        return Ok(());
    };
    let disks_prefix = format!("{}/", k7d::disks::DISKS_DIR);
    for mount in mounts {
        let src = mount
            .get("source")
            .and_then(|s| s.as_str())
            .unwrap_or_default();
        let Some(name) = src.strip_prefix(&disks_prefix) else {
            continue;
        };
        if name.is_empty() || name.contains('/') {
            return Err(format!(
                "k7d disk volume source {src} must be a direct child of {}",
                k7d::disks::DISKS_DIR
            ));
        }
        if state.rewrites.translate(Path::new(src)).is_some() {
            continue; // already wired by an earlier workload
        }
        let image = k7d::disks::ensure_ext4_volume(
            Path::new(k7d::disks::DISKS_DIR),
            &format!("{name}.img"),
            K7D_DISK_DEFAULT_SIZE,
        )
        .map_err(|e| format!("k7d disk volume {name}: {e}"))?;
        let guest = format!("{GUEST_DISKS_BASE}/{name}");
        let Some(cfg) = state.pending_vm.as_mut() else {
            return Err(format!(
                "k7d disk volume {src} appeared after the VM booted — virtio-blk \
                 devices are boot-time declarations (no hotplug) and the spare \
                 image slots are RO-only; mount the volume in the \
                 pod's first container"
            ));
        };
        cfg.block_devices.push(k7d::control::BlockDeviceConfig {
            host_path: image.to_string_lossy().into_owned(),
            readonly: false,
            guest_mount: Some(guest.clone()),
            fstype: Some("ext4".to_string()),
        });
        state
            .rewrites
            .insert(PathBuf::from(src), PathBuf::from(&guest), false);
        log::info!("k7d disk volume {name}: {src} -> {guest} (rw ext4)");
    }
    Ok(())
}

/// Route `readOnly: true` hostPath mounts onto the
/// block path — pack the host dir (or a staging dir holding the host
/// file) into a cached erofs image (`cached_erofs_image`, content-walk
/// key) and attach it as one more RO virtio-blk device, rewriting the
/// mount like the packed kubelet-volume image. The pod then carries
/// zero virtiofs shares for RO hostPaths and stays on the `CoW`
/// fast-fork path (this is what puts the inner-k3s airgap dir — the
/// last virtiofs share on cluster pods — onto the block path).
///
/// Gate: only `ro` mounts whose source is a regular file or directory
/// qualify. RW hostPath and special files (sockets, devices) fall
/// through untouched to the virtiofs fallback, which preserves live
/// host-dir semantics. The trade the gate encodes: an erofs image is
/// a **snapshot at pod create** — later host-side writes are not
/// visible in-guest (virtiofs was live). RO consumers that need
/// liveness must use RW hostPath (explicitly slow-fork).
fn prepare_ro_hostpath_images(
    state: &mut SandboxState,
    spec: &serde_json::Value,
    cache_dir: &Path,
) -> Result<(), String> {
    // Never mix routes: once the pod is on the virtiofs fallback,
    // its shares are live and later RO binds appear in-guest for
    // free — adding erofs devices post-boot is impossible anyway
    // (boot-time declarations).
    if state.pod_volumes.is_some() {
        return Ok(());
    }
    let mounts = k7d::volumes::hostpath_mounts_for_workload(spec, &state.rewrites)
        .map_err(|e| format!("enumerate hostPath mounts: {e}"))?;
    for m in mounts {
        if !m.readonly {
            continue;
        }
        let src = m.source;
        let meta = std::fs::metadata(&src).map_err(|e| format!("stat {}: {e}", src.display()))?;
        let is_file = meta.is_file();
        if !is_file && !meta.is_dir() {
            // Sockets / devices / FIFOs cannot ride an erofs image —
            // leave them for the virtiofs fallback.
            continue;
        }

        // Files are packed via a staging dir holding a copy (mkfs.erofs
        // takes a directory); the mount rewrite then points at the file
        // inside the image's guest mount.
        let (pack_dir, file_name) = if is_file {
            let state_dir = state
                .state_dir
                .as_ref()
                .ok_or("no state_dir for RO hostPath file staging")?;
            let name = src
                .file_name()
                .and_then(|n| n.to_str())
                .ok_or_else(|| format!("RO hostPath file {} has no UTF-8 name", src.display()))?
                .to_string();
            let staging = state_dir
                .join("hostpath-pack")
                .join(k7d::erofs::snapshot_cache_key(&src.to_string_lossy()));
            std::fs::create_dir_all(&staging)
                .map_err(|e| format!("create {}: {e}", staging.display()))?;
            std::fs::copy(&src, staging.join(&name))
                .map_err(|e| format!("stage {} for erofs pack: {e}", src.display()))?;
            (staging, Some(name))
        } else {
            (src.clone(), None)
        };

        let image = k7d::erofs::cached_erofs_image(cache_dir, &pack_dir, None)
            .map_err(|e| format!("pack RO hostPath {} as erofs: {e}", src.display()))?;
        let key = image
            .file_stem()
            .and_then(|s| s.to_str())
            .ok_or_else(|| format!("erofs image {} has no file stem", image.display()))?
            .to_string();

        let guest_mount = if let Some(dev) = state.hostpath_devices.iter().find(|d| d.key == key) {
            dev.guest_mount.clone()
        } else if state.pending_vm.is_none() {
            // RO hostPath declared after the VM booted
            // rides a spare image slot — the same mechanism as a
            // post-boot distinct container image.
            let guest_mount = assign_image_slot(state, &key, &image, "erofs")?;
            state.hostpath_devices.push(RootfsDevice {
                key,
                guest_mount: guest_mount.clone(),
            });
            guest_mount
        } else {
            let guest_mount = format!("{GUEST_HOSTPATH_PREFIX}-{}", state.hostpath_devices.len());
            let cfg = state
                .pending_vm
                .as_mut()
                .ok_or("pending_vm vanished (checked above)")?;
            cfg.block_devices.push(k7d::control::BlockDeviceConfig {
                host_path: image.to_string_lossy().into_owned(),
                readonly: true,
                guest_mount: Some(guest_mount.clone()),
                fstype: Some("erofs".to_string()),
            });
            state.hostpath_devices.push(RootfsDevice {
                key,
                guest_mount: guest_mount.clone(),
            });
            guest_mount
        };

        let in_vm = match file_name {
            Some(ref name) => format!("{guest_mount}/{name}"),
            None => guest_mount.clone(),
        };
        state
            .rewrites
            .insert(src.clone(), PathBuf::from(&in_vm), true);
        log::info!(
            "RO hostPath on block path: {} -> {in_vm} (erofs image {})",
            src.display(),
            image.display()
        );
        debug_log_cni(&format!(
            "Create: RO hostPath {} -> {in_vm} (erofs on virtio-blk)",
            src.display()
        ));
    }
    Ok(())
}

/// The **explicit virtiofs fallback**: hostPath
/// volumes and PVC plugins the block path does not support stay on
/// virtiofs — the pod is thereby marked slow-fork by the daemon
/// (virtiofs shares force a full-copy fork, `allow_slow_fork()`)
/// and the shim logs which volume forced it. Everything the block
/// path already handles (kubelet RO volumes, emptyDir, etc-files,
/// k7d disks, RO hostPath erofs images —) is
/// pre-seeded into the probe's rewrite map so only genuinely
/// unsupported binds (RW hostPath, special files) trigger the
/// fallback.
fn prepare_hostpath_fallback(
    state: &mut SandboxState,
    sandbox_id: &str,
    spec: &serde_json::Value,
) -> Result<(), String> {
    if let Some(ref mut pv) = state.pod_volumes {
        // Shares already attached at boot: the share roots are live
        // virtiofs directories, so new binds under them appear in
        // the guest immediately.
        pv.rewrites.merge(&state.rewrites);
        let before = pv.rewrites.len();
        pv.add_hostpath_mounts_for_workload(spec)
            .map_err(|e| format!("virtiofs-fallback hostPath wiring: {e}"))?;
        if pv.rewrites.len() > before {
            log::warn!(
                "virtiofs fallback: workload added {} hostPath bind(s) to the \
                 already-attached fallback shares",
                pv.rewrites.len() - before
            );
        }
        return Ok(());
    }

    // Probe: would this workload leave any bind the block path can't
    // serve? Seed with everything already handled so only leftovers
    // count.
    let mut pv = k7d::volumes::PodVolumes::prepare(None, sandbox_id)
        .map_err(|e| format!("virtiofs-fallback scratch tree: {e}"))?
        .with_vm_mounts(FALLBACK_MOUNT_RO, FALLBACK_MOUNT_RW);
    pv.rewrites.merge(&state.rewrites);
    let baseline = pv.rewrites.len();
    pv.add_hostpath_mounts_for_workload(spec)
        .map_err(|e| format!("virtiofs-fallback hostPath wiring: {e}"))?;
    if pv.rewrites.len() == baseline {
        // No fallback needed — drop the scratch tree again.
        pv.cleanup();
        return Ok(());
    }

    let Some(cfg) = state.pending_vm.as_mut() else {
        return Err(
            "hostPath volume(s) appeared after the VM booted share-less — virtiofs \
             shares are boot-time declarations; mount the hostPath in the pod's \
             first container"
                .to_string(),
        );
    };
    let added = pv.rewrites.len() - baseline;
    log::warn!(
        "virtiofs FALLBACK for sandbox {sandbox_id}: {added} hostPath / unsupported-PVC \
         bind(s) cannot ride the block path — attaching {FALLBACK_MOUNT_RO} + \
         {FALLBACK_MOUNT_RW} virtiofs shares; this pod will SLOW-FORK (full memory \
         copy) because virtiofs sessions cannot be CoW-forked"
    );
    debug_log_cni(&format!(
        "Create: virtiofs fallback for {sandbox_id} ({added} hostPath bind(s)) — slow-fork"
    ));
    cfg.virtiofs.push(k7d::control::ShareConfig {
        host_dir: pv.host_volumes_ro.to_string_lossy().into_owned(),
        guest_mount: FALLBACK_MOUNT_RO.to_string(),
        readonly: true,
    });
    cfg.virtiofs.push(k7d::control::ShareConfig {
        host_dir: pv.host_volumes_rw.to_string_lossy().into_owned(),
        guest_mount: FALLBACK_MOUNT_RW.to_string(),
        readonly: false,
    });
    state.pod_volumes = Some(pv);
    Ok(())
}

/// Submit the sandbox's parked `VmConfig` to the k7d daemon (which
/// owns KVM, guest memory, vsock, and the network
/// attachment), record the returned identity, dial the agent, and
/// configure the guest network. `pending_vm` is consumed only on
/// success so a kubelet retry of a failed Create replays cleanly.
fn boot_pending_vm(state: &mut SandboxState) -> Result<(), String> {
    let config = state
        .pending_vm
        .clone()
        .ok_or("boot_pending_vm without a pending VmConfig")?;
    let pod_netns = config
        .network
        .as_ref()
        .and_then(|n| n.pod_netns.clone())
        .map(PathBuf::from);
    debug_log_cni(&format!(
        "Create: booting deferred VM (virtiofs={}, block_devices={}, guest_dirs={})",
        config.virtiofs.len(),
        config.block_devices.len(),
        config.guest_dirs.len()
    ));

    let mut daemon = k7d::control::Client::connect_env().map_err(|e| {
        format!(
            "connect to k7d daemon at {}: {e} — is the k7d daemon running?",
            k7d::control::socket_path_from_env()
        )
    })?;
    let created = daemon.call(&k7d::control::Request::CreateVm { config })?;
    let (vm_id, guest_cid, vm_index, pod_netns_attached) = match created {
        k7d::control::Response::VmCreated {
            vm_id,
            guest_cid,
            vm_index,
            pod_netns_attached,
            pooled: _,
        } => (vm_id, guest_cid, vm_index, pod_netns_attached),
        k7d::control::Response::Error { message } => {
            return Err(format!("k7d create_vm: {message}"));
        }
        other => {
            return Err(format!("unexpected k7d create_vm response: {other:?}"));
        }
    };
    debug_log_cni(&format!(
        "Create: daemon vm_id={vm_id} guest_cid={guest_cid} vm_index={vm_index:?} \
         pod_netns_attached={pod_netns_attached}"
    ));
    state.vm_id = Some(vm_id);
    state.guest_cid = Some(guest_cid);
    state.vm_index = vm_index;
    state.pod_netns = if pod_netns_attached { pod_netns } else { None };
    state.pending_vm = None;

    state.connect_agent()?;
    configure_guest_network(state);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn slot_ann(slots: Option<&str>, size: Option<&str>) -> ShimAnnotations {
        ShimAnnotations {
            image_slots: slots.map(str::to_string),
            image_slot_size: size.map(str::to_string),
            ..Default::default()
        }
    }

    #[test]
    fn image_slots_defaults() {
        let dir = std::env::temp_dir().join(format!("k7d-slot-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let mut config = k7d::control::VmConfig::default();
        let slots = declare_image_slots(&mut config, &slot_ann(None, None), &dir).unwrap();
        assert_eq!(slots.len(), DEFAULT_IMAGE_SLOTS as usize);
        assert_eq!(config.block_devices.len(), DEFAULT_IMAGE_SLOTS as usize);
        for (i, slot) in slots.iter().enumerate() {
            assert_eq!(slot.device_index, i);
            assert!(slot.key.is_none() && slot.guest_mount.is_none());
            let blk = &config.block_devices[i];
            assert!(blk.readonly && blk.guest_mount.is_none() && blk.fstype.is_none());
            let len = std::fs::metadata(&slot.backing).unwrap().len();
            assert_eq!(len, DEFAULT_IMAGE_SLOT_SIZE);
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn image_slots_annotations_and_validation() {
        let dir = std::env::temp_dir().join(format!("k7d-slot-test2-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let mut config = k7d::control::VmConfig::default();
        let slots =
            declare_image_slots(&mut config, &slot_ann(Some("2"), Some("1024")), &dir).unwrap();
        assert_eq!(slots.len(), 2);
        assert_eq!(std::fs::metadata(&slots[0].backing).unwrap().len(), 1024);

        // Not a multiple of 512 — loud, naming the annotation.
        let err = declare_image_slots(&mut config, &slot_ann(None, Some("1000")), &dir)
            .expect_err("size must be validated");
        assert!(err.contains(ANN_IMAGE_SLOT_SIZE), "{err}");

        // Unparseable count — loud.
        let err = declare_image_slots(&mut config, &slot_ann(Some("many"), None), &dir)
            .expect_err("count must be validated");
        assert!(err.contains(ANN_IMAGE_SLOTS), "{err}");

        // Pin budget exceeded — loud, naming the annotation.
        let err = declare_image_slots(&mut config, &slot_ann(Some("40"), None), &dir)
            .expect_err("pin budget must be enforced");
        assert!(err.contains(ANN_IMAGE_SLOTS), "{err}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    fn cscratch_ann(raw: Option<&str>) -> ShimAnnotations {
        ShimAnnotations {
            container_scratch_size: raw.map(str::to_string),
            ..Default::default()
        }
    }

    /// The per-container annotation parses to exactly what it
    /// says, and 19b behaviour is what its absence means.
    #[test]
    fn container_scratch_annotation_parses() {
        assert!(
            container_scratch_from_annotations(&cscratch_ann(None))
                .unwrap()
                .is_empty(),
            "no annotation must reproduce: everyone shares the pod scratch"
        );
        let parsed =
            container_scratch_from_annotations(&cscratch_ann(Some(" builder=2Gi , logger=32Mi ")))
                .expect("valid list");
        assert_eq!(
            parsed,
            vec![
                k7d::control::ContainerScratchConfig {
                    name: "builder".into(),
                    size_bytes: 2 * 1024 * 1024 * 1024,
                },
                k7d::control::ContainerScratchConfig {
                    name: "logger".into(),
                    size_bytes: 32 * 1024 * 1024,
                },
            ]
        );
    }

    /// Every rejection names the annotation: a pod that asked for a
    /// limit must never reach Running sharing the pod scratch instead.
    #[test]
    fn container_scratch_annotation_rejections_are_loud() {
        for bad in [
            "builder",            // no size
            "builder=",           // empty size
            "=2Gi",               // no name
            "bui/lder=2Gi",       // not a filename component
            "..=2Gi",             // path escape
            "builder=2Zi",        // unknown suffix
            "builder=1Mi",        // below the ext4 floor
            "a=32Mi,a=64Mi",      // same container twice
            ",",                  // names nobody
            "builder=2Gi,logger", // one good entry does not excuse a bad one
        ] {
            let err = container_scratch_from_annotations(&cscratch_ann(Some(bad)))
                .expect_err("annotation value must be rejected");
            assert!(
                err.contains(ANN_CONTAINER_SCRATCH_SIZE),
                "error for {bad:?} must name the annotation, got: {err}"
            );
        }
    }

    /// Each per-container image is one more virtio-blk device, so it
    /// spends an MMIO pin the image-slot budget check has to see.
    #[test]
    fn container_scratch_counts_against_the_pin_budget() {
        let dir = std::env::temp_dir().join(format!("k7d-cscratch-budget-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let mut config = k7d::control::VmConfig {
            vsock: true,
            scratch_size_bytes: Some(k7d::disks::DEFAULT_SCRATCH_SIZE),
            container_scratch: (0..MMIO_DEVICE_BUDGET - 4)
                .map(|i| k7d::control::ContainerScratchConfig {
                    name: format!("c{i}"),
                    size_bytes: k7d::disks::MIN_SCRATCH_SIZE,
                })
                .collect(),
            ..Default::default()
        };
        let err = declare_image_slots(&mut config, &slot_ann(Some("4"), None), &dir)
            .expect_err("per-container images must count against the budget");
        assert!(err.contains(ANN_IMAGE_SLOTS), "{err}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn image_slot_exhaustion_is_loud() {
        // No free slot: the error must name the annotation knob.
        let mut state = SandboxState::new();
        let err = assign_image_slot(&mut state, "somekey", Path::new("/nonexistent"), "erofs")
            .expect_err("no slots declared");
        assert!(err.contains(ANN_IMAGE_SLOTS), "{err}");
    }

    #[test]
    fn clone_or_copy_fills_same_inode() {
        let dir = std::env::temp_dir().join(format!("k7d-clone-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let src = dir.join("src.img");
        let dst = dir.join("dst.img");
        std::fs::write(&src, vec![0xa5u8; 8192]).unwrap();
        std::fs::File::create(&dst).unwrap().set_len(16384).unwrap();
        // Hold an fd across the fill, like the blk backend does.
        use std::io::Read;
        let mut boot_fd = std::fs::File::open(&dst).unwrap();
        clone_or_copy_into(&src, &dst).unwrap();
        std::fs::OpenOptions::new()
            .write(true)
            .open(&dst)
            .unwrap()
            .set_len(16384)
            .unwrap();
        let mut buf = vec![0u8; 8192];
        boot_fd.read_exact(&mut buf).unwrap();
        assert_eq!(buf, vec![0xa5u8; 8192], "boot-time fd must see the fill");
        assert_eq!(std::fs::metadata(&dst).unwrap().len(), 16384);
        let _ = std::fs::remove_dir_all(&dir);
    }

    fn ann(memory: Option<u64>, quota: Option<i64>, period: Option<u64>) -> ShimAnnotations {
        ShimAnnotations {
            sandbox_memory_bytes: memory,
            sandbox_cpu_quota: quota,
            sandbox_cpu_period: period,
            ..Default::default()
        }
    }

    #[test]
    fn fix_oci_config_preserves_memory_and_cpu_resources() {
        // CRI linux.resources must reach guest runc.
        let spec = serde_json::json!({
            "root": { "path": "/var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snap" },
            "linux": {
                "resources": {
                    "memory": { "limit": 33554432, "reservation": 16777216 },
                    "cpu": { "shares": 1024, "quota": 50000, "period": 100000 },
                    "unified": {
                        "memory.swap.max": "0",
                        "memory.oom.group": "1"
                    },
                    "devices": [{ "allow": false, "access": "rwm" }]
                },
                "cgroupsPath": "/kubepods/pod123/ctr456",
                "seccomp": { "defaultAction": "SCMP_ACT_ERRNO" }
            },
            "mounts": []
        });
        let empty = k7d::volumes::MountRewriteMap::default();
        let fixed: serde_json::Value =
            serde_json::from_str(&fix_oci_config(spec, &empty, Some("/run/k7d/rootfs-0")).unwrap())
                .unwrap();
        assert_eq!(fixed["linux"]["resources"]["memory"]["limit"], 33_554_432);
        assert_eq!(
            fixed["linux"]["resources"]["memory"]["reservation"],
            16_777_216
        );
        assert_eq!(fixed["linux"]["resources"]["cpu"]["quota"], 50_000);
        assert_eq!(fixed["linux"]["resources"]["cpu"]["period"], 100_000);
        assert_eq!(fixed["linux"]["resources"]["cpu"]["shares"], 1024);
        // Host device deny-all must be replaced with guest allow-all.
        assert_eq!(
            fixed["linux"]["resources"]["devices"],
            serde_json::json!([{ "allow": true, "access": "rwm" }])
        );
        // Swap + oom.group unified keys dropped for the guest; with
        // nothing left, the unified object itself is removed.
        assert!(fixed["linux"]["resources"].get("unified").is_none());
        assert!(fixed["linux"].get("cgroupsPath").is_none());
        assert!(fixed["linux"].get("seccomp").is_none());
    }

    #[test]
    fn fix_oci_config_strips_structured_memory_swap() {
        let spec = serde_json::json!({
            "root": { "path": "/x" },
            "linux": {
                "resources": {
                    "memory": { "limit": 268435456, "swap": 268435456 }
                }
            },
            "mounts": []
        });
        let empty = k7d::volumes::MountRewriteMap::default();
        let fixed: serde_json::Value =
            serde_json::from_str(&fix_oci_config(spec, &empty, None).unwrap()).unwrap();
        assert_eq!(fixed["linux"]["resources"]["memory"]["limit"], 268_435_456);
        assert!(fixed["linux"]["resources"]["memory"].get("swap").is_none());
    }

    #[test]
    fn fix_oci_config_translates_cgroup_mounts_and_strips_mqueue() {
        // Cgroup/cgroup2 mounts are translated to the OCI
        // `cgroup` type (guest runc mounts the cgroup2 hierarchy),
        // preserving destination and CRI-set options; mqueue is still
        // stripped.
        let spec = serde_json::json!({
            "root": { "path": "/x" },
            "linux": {
                "namespaces": [
                    { "type": "pid" },
                    { "type": "mount" },
                    { "type": "cgroup" },
                    { "type": "network" }
                ]
            },
            "mounts": [
                {
                    "destination": "/sys/fs/cgroup",
                    "type": "cgroup",
                    "source": "cgroup",
                    "options": ["nosuid", "noexec", "nodev", "relatime", "ro"]
                },
                {
                    "destination": "/custom/cgroup2",
                    "type": "cgroup2",
                    "source": "cgroup2",
                    "options": ["rw"]
                },
                {
                    "destination": "/dev/mqueue",
                    "type": "mqueue",
                    "source": "mqueue",
                    "options": ["nosuid"]
                }
            ]
        });
        let empty = k7d::volumes::MountRewriteMap::default();
        let fixed: serde_json::Value =
            serde_json::from_str(&fix_oci_config(spec, &empty, None).unwrap()).unwrap();
        let mounts = fixed["mounts"].as_array().unwrap();
        assert_eq!(mounts.len(), 2, "cgroup mounts kept, mqueue stripped");
        assert_eq!(mounts[0]["destination"], "/sys/fs/cgroup");
        assert_eq!(mounts[0]["type"], "cgroup");
        assert_eq!(
            mounts[0]["options"],
            serde_json::json!(["nosuid", "noexec", "nodev", "relatime", "ro"])
        );
        assert_eq!(mounts[1]["destination"], "/custom/cgroup2");
        assert_eq!(mounts[1]["type"], "cgroup", "cgroup2 normalized to cgroup");
        assert_eq!(mounts[1]["source"], "cgroup");
        // The cgroup namespace is kept so the mount shows a
        // private namespaced subtree; network is stripped as before.
        let ns_types: Vec<&str> = fixed["linux"]["namespaces"]
            .as_array()
            .unwrap()
            .iter()
            .map(|ns| ns["type"].as_str().unwrap())
            .collect();
        assert_eq!(ns_types, vec!["pid", "mount", "cgroup"]);
    }

    #[test]
    fn fix_oci_config_resources_absent_still_gets_devices_allow() {
        let spec = serde_json::json!({
            "root": { "path": "/x" },
            "linux": {},
            "mounts": []
        });
        let empty = k7d::volumes::MountRewriteMap::default();
        let fixed: serde_json::Value =
            serde_json::from_str(&fix_oci_config(spec, &empty, None).unwrap()).unwrap();
        assert_eq!(
            fixed["linux"]["resources"]["devices"],
            serde_json::json!([{ "allow": true, "access": "rwm" }])
        );
        assert!(fixed["linux"]["resources"].get("memory").is_none());
    }

    #[test]
    fn sizing_besteffort_gets_defaults() {
        let s = vm_sizing_from_annotations(&ann(None, None, None));
        assert_eq!(
            s,
            VmSizing {
                memory_mb: 256,
                vcpus: 1,
                cpu_quota: None,
                cpu_period: None
            }
        );
        // containerd emits "0" for unset limits on some versions.
        let s = vm_sizing_from_annotations(&ann(Some(0), Some(0), Some(100_000)));
        assert_eq!(s.memory_mb, 256);
        assert_eq!(s.vcpus, 1);
        assert_eq!(s.cpu_quota, None);
    }

    #[test]
    fn sizing_memory_limit_adds_overhead() {
        // 256 Mi limit -> 256 + 64 MB VM.
        let s = vm_sizing_from_annotations(&ann(Some(256 * 1024 * 1024), None, None));
        assert_eq!(s.memory_mb, 320);
        // Tiny limit floors at 128 MB.
        let s = vm_sizing_from_annotations(&ann(Some(16 * 1024 * 1024), None, None));
        assert_eq!(s.memory_mb, 128);
    }

    #[test]
    fn sizing_cpu_limit_derives_vcpus_and_quota() {
        // cpu: 500m -> quota 50000/100000 -> 1 vCPU, capped.
        let s = vm_sizing_from_annotations(&ann(None, Some(50_000), Some(100_000)));
        assert_eq!(s.vcpus, 1);
        assert_eq!(s.cpu_quota, Some(50_000));
        assert_eq!(s.cpu_period, Some(100_000));
        // cpu: 2 -> 2 vCPUs (ceil).
        let s = vm_sizing_from_annotations(&ann(None, Some(200_000), Some(100_000)));
        assert_eq!(s.vcpus, 2);
        // cpu: 1.5 -> ceil -> 2 vCPUs.
        let s = vm_sizing_from_annotations(&ann(None, Some(150_000), Some(100_000)));
        assert_eq!(s.vcpus, 2);
        // Negative quota (containerd's "unlimited") -> uncapped.
        let s = vm_sizing_from_annotations(&ann(None, Some(-1), Some(100_000)));
        assert_eq!(s.vcpus, 1);
        assert_eq!(s.cpu_quota, None);
    }
}
