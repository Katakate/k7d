//! Per-sandbox state: daemon VM handle, agent connection, container
//! tracking.
//!
//! One sandbox = one pod = one VM. Multiple containers (pause + workload)
//! share the same VM and agent connection.
//!
//! The VM itself (KVM fds, guest memory,
//! virtiofsd children, TAP/bridge) lives in the **k7d daemon**; the
//! shim only holds the daemon's `vm_id` and talks to the guest agent
//! directly over vsock (CIDs are kernel-global).

use std::collections::{BTreeMap, HashMap};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use k7d::api::AgentClient;
use k7d::guest::AgentEndpoint;
use k7d::volumes::{MountRewriteMap, PodVolumes};

/// One erofs container-rootfs image attached to the VM as a
/// read-only virtio-blk device. `key` is the image
/// cache file name (digest- or content-keyed) so a second container
/// using the same image reuses the device instead of demanding a
/// hotplug the VMM doesn't have.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct RootfsDevice {
    /// erofs image cache key (the image file name under the cache dir).
    pub key: String,
    /// Guest mount point of the erofs device (`/run/k7d/rootfs-<n>`).
    pub guest_mount: String,
}

/// One spare "image slot" virtio-blk device declared at boot: a
/// fixed-capacity sparse RO backing file whose content
/// the host fills (FICLONE reflink / `copy_file_range`) at a
/// post-boot workload Create — the no-hotplug answer to
/// multi-container pods with distinct images. Empty slots carry no
/// `guest_mount`, so the agent never automounts them at boot; the
/// shim mounts an assigned slot via the agent's `mount_blk` request.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ImageSlot {
    /// Index of this slot in the VM's `block_devices` declaration
    /// order — determines the guest device name (`vd{a+index}`).
    pub device_index: usize,
    /// Host path of the sparse backing file (fixed capacity, set with
    /// ftruncate at declaration — the blk backend reads capacity from
    /// file size at boot).
    pub backing: String,
    /// erofs cache key of the assigned image; `None` = free.
    pub key: Option<String>,
    /// Guest mount point once assigned and mounted.
    pub guest_mount: Option<String>,
}

/// The subset of block-path sandbox state that must survive a shim
/// restart. Persisted as JSON in the sandbox state
/// dir; `reattach_sandbox_state` loads it back so a workload Create
/// issued at a freshly respawned shim still resolves rootfs devices
/// and mount rewrites.
#[derive(Debug, Default, serde::Serialize, serde::Deserialize)]
pub struct BlockStateSnapshot {
    /// Union host→in-VM mount rewrite map.
    pub rewrites: MountRewriteMap,
    /// Attached rootfs erofs devices, in device order.
    pub rootfs_devices: Vec<RootfsDevice>,
    /// Attached RO-hostPath erofs devices, in device order.
    #[serde(default)]
    pub hostpath_devices: Vec<RootfsDevice>,
    /// Spare image-slot devices and their assignments.
    #[serde(default)]
    pub image_slots: Vec<ImageSlot>,
    /// Container id → rootfs erofs key claims.
    #[serde(default)]
    pub container_rootfs_keys: BTreeMap<String, String>,
    /// Host etc-file source → guest tmpfs path already pushed.
    pub etc_pushed: BTreeMap<String, String>,
    /// Kubernetes container names that were given their own writable
    /// image, with the capacity each was given.
    #[serde(default)]
    pub container_scratch: BTreeMap<String, u64>,
}

/// File name of the persisted [`BlockStateSnapshot`] in the state dir.
pub const BLOCK_STATE_FILE: &str = "block-state.json";

/// Per-process state tracked by the shim.
pub struct ProcessState {
    /// Synthetic PID returned to containerd.
    pub pid: u32,
    /// Exit code once the process has exited.
    pub exit_code: Arc<Mutex<Option<i32>>>,
    /// Bundle path on the host.
    pub bundle: String,
    /// Stdout FIFO path from containerd.
    pub stdout: String,
    /// Stderr FIFO path from containerd.
    pub stderr: String,
    /// Stdin FIFO path from containerd.
    pub stdin: String,
    /// Exec argv parsed from the OCI process spec (exec processes
    /// only; empty for init processes). Captured at `Exec`,
    /// consumed at `Start`.
    pub args: Vec<String>,
    /// Containerd requested a TTY for this process.
    pub terminal: bool,
    /// `$TERM` from the OCI process spec env (PTY execs).
    pub term: String,
    /// Created and not yet started, so `State` answers CREATED. Only
    /// CRI-O bundles set it: CRI-O refuses `Start` unless `State` says
    /// created, and containerd's restart reconcile has only ever seen
    /// RUNNING from this shim.
    pub created: bool,
}

/// Per-container state.
pub struct ContainerState {
    /// Init process state.
    pub init: ProcessState,
    /// Exec processes keyed by `exec_id`.
    pub execs: HashMap<String, ProcessState>,
}

/// Shared sandbox state across all task service calls.
pub struct SandboxState {
    /// Daemon-side VM identifier (set on sandbox Create by the
    /// `create_vm` control-plane call; consumed by Delete/Shutdown to
    /// `stop_vm`). The VM object itself lives in the k7d daemon.
    pub vm_id: Option<String>,
    /// Agent client for communicating with the guest (set after VM starts).
    pub agent: Option<AgentClient>,
    /// Containers keyed by container ID.
    pub containers: HashMap<String, ContainerState>,
    /// The sandbox container ID (container-type=sandbox).
    pub sandbox_id: Option<String>,
    /// Cluster identity for this sandbox (from `k7d.katakate.org/cluster-id`).
    /// `None` means a single-VM sandbox with a one-off bridge.
    pub cluster_id: Option<String>,
    /// True when the pod carried an explicit `k7d.katakate.org/cluster-id`
    /// annotation (shared-bridge cluster mode). Such pods skip the
    /// CNI attach, so the Start path must configure the guest's
    /// eth0 with its stable `10.200.0.{2 + vm_index}` identity directly on
    /// the shared host bridge.
    pub cluster_mode: bool,
    /// `vm_index` allocated on the bridge (preserved across forks).
    pub vm_index: Option<u32>,
    /// Source cluster ID when this sandbox is the result of a cluster fork.
    pub fork_source_cluster: Option<String>,
    /// Cluster snapshot tree this sandbox belongs to (from
    /// `k7d.katakate.org/tree-id`). `None` means the sandbox is not
    /// managed by any cluster snapshot tree — the legacy
    /// behaviour. The actual tree-side fork / suspend / resume
    /// operations happen in the k7d daemon (a future PR will wire the
    /// shim's `tree_id` and `tree_source_node_id` through the daemon
    /// Unix-socket API to drive
    /// `ClusterSnapshotTree::{new_cluster, fork, suspend, resume}`).
    pub tree_id: Option<String>,
    /// Source node within the named tree when this sandbox is
    /// a tree-fork. Only meaningful when `tree_id` is also set.
    pub tree_source_node_id: Option<String>,
    /// CNI-assigned pod netns path (from
    /// `linux.namespaces[type=network].path` in the sandbox OCI
    /// bundle). Set only when the k7d daemon reported a successful
    /// pod-netns attach in its `create_vm` response — the Start path
    /// keys the guest's gateway-route configuration off it. Teardown
    /// of the in-netns bridge is the daemon's job (`stop_vm`).
    pub pod_netns: Option<PathBuf>,
    /// Host directory shared into the VM via virtiofs.
    pub state_dir: Option<PathBuf>,
    /// Per-pod kubelet volumes — bind-mount tree on the
    /// host, virtiofs shares plumbed into the VM, and the
    /// host→in-VM rewrite map applied to each workload container's
    /// OCI `config.json` before runc consumes it.
    ///
    /// Set at sandbox Create (after [`PodVolumes::prepare`]),
    /// consulted by `copy_and_fix_oci_config` for each workload
    /// Create, dropped on sandbox Delete (which runs the bind-mount
    /// teardown). `None` when [`PodVolumes::prepare`] hasn't been
    /// called (e.g. legacy single-VM tests that don't drive the
    /// shim) — consumers treat that the same as an empty rewrite
    /// map.
    pub pod_volumes: Option<PodVolumes>,
    /// (block path): the `VmConfig` assembled at
    /// sandbox Create but NOT yet submitted to the daemon. The VM
    /// boots at the FIRST workload Create instead — that is the
    /// earliest moment the container's rootfs erofs image (a
    /// boot-time virtio-blk declaration) is known. `None` once the
    /// VM exists (or for legacy/reattached sandboxes).
    pub pending_vm: Option<k7d::control::VmConfig>,
    /// Union host→in-VM mount rewrite map: block kubelet volumes
    /// (erofs image / guest tmpfs), etc-files pushed over vsock,
    /// k7d disk images, and any virtiofs-fallback binds.
    pub rewrites: MountRewriteMap,
    /// Rootfs erofs devices attached to the VM, in device order.
    pub rootfs_devices: Vec<RootfsDevice>,
    /// RO-hostPath erofs devices attached to the VM, in device order
    /// (`readOnly: true` hostPath mounts are packed
    /// into cached erofs images instead of forcing the virtiofs
    /// fallback — the pod stays on the `CoW` fast-fork path). Keyed
    /// like [`Self::rootfs_devices`] so a second mount of the same
    /// source reuses the device.
    pub hostpath_devices: Vec<RootfsDevice>,
    /// Spare image-slot virtio-blk devices declared at sandbox Create
    /// and their post-boot image assignments.
    pub image_slots: Vec<ImageSlot>,
    /// Container id → rootfs erofs key — the
    /// guest-mount refcount. Containers of the same image share ONE
    /// erofs device + guest mount (dedupe by key), so `Delete` of an
    /// exited container (e.g. an init container whose image the main
    /// container also uses) must not tear down a mount a live sibling
    /// still runs from. Recorded at workload Create
    /// (`prepare_rootfs_device`), released at container Delete.
    pub container_rootfs_keys: BTreeMap<String, String>,
    /// Host etc-file source → guest tmpfs path already pushed over
    /// vsock (dedupe across workloads of the same pod).
    pub etc_pushed: BTreeMap<String, String>,
    /// Kubernetes container name → capacity of the writable
    /// image declared for it by
    /// `k7d.katakate.org/container-scratch-size`. Recorded at sandbox
    /// Create purely so each workload Create can say in the log which
    /// side of the line it landed on — a name matching no container in
    /// the pod (a typo) otherwise leaves that container silently
    /// sharing the pod scratch.
    pub container_scratch: BTreeMap<String, u64>,
    /// Pod asked for dockerd as an agent service.
    pub docker: bool,
    /// VMM engine this pod's VM runs on, from
    /// `k7d.katakate.org/backend`. Kept next to
    /// `pending_vm` because it outlives it: the workload path checks it
    /// long after the config has been submitted, and a Firecracker pod
    /// has no virtiofs to fall back to.
    pub backend: k7d::guest::Backend,
    /// How this sandbox's guest agent is reached.
    ///
    /// Returned by the daemon's `create_vm` / `lookup_sandbox` and read
    /// by the Start stdout-bridge, the exit watcher and the Exec ttrpc
    /// handler. `Vsock { cid }` for native VMs — one CID per VM
    /// (`vsock::allocate_cid`), because a hardcoded 3 limited the node
    /// to a single `runtimeClassName: k7` pod and collided with the
    /// production `k7-api` pod. `FcUds { path }` for a
    /// `backend: firecracker` pod, whose guest is not on the host's
    /// vsock namespace at all.
    ///
    /// `None` until `Create` runs. Consumers fail loudly rather than
    /// guessing: a bridge dialled at the wrong endpoint would silently
    /// stream another pod's logs.
    pub agent_endpoint: Option<AgentEndpoint>,
    /// Source CRI sandbox id when this pod's VM was
    /// warm-forked from a live sandbox VM (`k7d.katakate.org/
    /// fork-source-{cluster,vm}` annotations) instead of cold-booted.
    /// Fork pods ADOPT the workload container already running inside
    /// the forked guest (see [`Self::guest_names`]) — they never push
    /// a bundle or `container_start`.
    pub fork_of: Option<String>,
    /// Containerd container id → guest runc container name.
    /// Only populated for fork-adopted containers (the inherited guest
    /// container keeps the SOURCE pod's containerd id); identity for
    /// everything else — resolve through [`Self::guest_name`].
    pub guest_names: HashMap<String, String>,
    /// Next synthetic PID to hand out.
    next_pid: u32,
}

impl SandboxState {
    pub fn new() -> Self {
        Self {
            vm_id: None,
            agent: None,
            containers: HashMap::new(),
            sandbox_id: None,
            cluster_id: None,
            cluster_mode: false,
            vm_index: None,
            fork_source_cluster: None,
            tree_id: None,
            tree_source_node_id: None,
            pod_netns: None,
            state_dir: None,
            pod_volumes: None,
            pending_vm: None,
            rewrites: MountRewriteMap::default(),
            rootfs_devices: Vec::new(),
            hostpath_devices: Vec::new(),
            image_slots: Vec::new(),
            container_rootfs_keys: BTreeMap::new(),
            etc_pushed: BTreeMap::new(),
            container_scratch: BTreeMap::new(),
            docker: false,
            backend: k7d::guest::Backend::Native,
            agent_endpoint: None,
            fork_of: None,
            guest_names: HashMap::new(),
            next_pid: 100,
        }
    }

    /// Resolve a containerd container id to the guest runc container
    /// name: the mapped source-container name for
    /// fork-adopted containers, the id itself for everything else.
    #[must_use]
    pub fn guest_name(&self, container_id: &str) -> String {
        self.guest_names
            .get(container_id)
            .cloned()
            .unwrap_or_else(|| container_id.to_string())
    }

    /// Persist the block-path snapshot (rewrites, rootfs devices,
    /// pushed etc-files) into the state dir so a respawned shim can
    /// reload it. Fail-loud: a workload Create that
    /// cannot be replayed after a shim crash would otherwise fail
    /// with a confusing "image not attached" error.
    pub fn persist_block_state(&self) -> Result<(), String> {
        let Some(ref dir) = self.state_dir else {
            return Ok(());
        };
        let snap = BlockStateSnapshot {
            rewrites: self.rewrites.clone(),
            rootfs_devices: self.rootfs_devices.clone(),
            hostpath_devices: self.hostpath_devices.clone(),
            image_slots: self.image_slots.clone(),
            container_rootfs_keys: self.container_rootfs_keys.clone(),
            etc_pushed: self.etc_pushed.clone(),
            container_scratch: self.container_scratch.clone(),
        };
        let json = serde_json::to_string_pretty(&snap)
            .map_err(|e| format!("serialize block state: {e}"))?;
        let path = dir.join(BLOCK_STATE_FILE);
        std::fs::write(&path, json).map_err(|e| format!("write {}: {e}", path.display()))
    }

    /// Load a previously persisted block-path snapshot, if present.
    /// Missing file is fine (sandbox predates the first workload
    /// Create); a corrupt file fails loud.
    pub fn load_block_state(&mut self, dir: &Path) -> Result<(), String> {
        let path = dir.join(BLOCK_STATE_FILE);
        if !path.exists() {
            return Ok(());
        }
        let data =
            std::fs::read_to_string(&path).map_err(|e| format!("read {}: {e}", path.display()))?;
        let snap: BlockStateSnapshot =
            serde_json::from_str(&data).map_err(|e| format!("parse {}: {e}", path.display()))?;
        self.rewrites = snap.rewrites;
        self.rootfs_devices = snap.rootfs_devices;
        self.hostpath_devices = snap.hostpath_devices;
        self.image_slots = snap.image_slots;
        self.container_rootfs_keys = snap.container_rootfs_keys;
        self.etc_pushed = snap.etc_pushed;
        self.container_scratch = snap.container_scratch;
        Ok(())
    }

    /// Number of live containers whose rootfs rides
    /// the erofs mount for `key`.
    #[must_use]
    pub fn rootfs_key_users(&self, key: &str) -> usize {
        self.container_rootfs_keys
            .values()
            .filter(|k| k.as_str() == key)
            .count()
    }

    /// Drop `container_id`'s claim on its rootfs
    /// erofs key (container Delete). Returns the released key and the
    /// number of OTHER live containers still riding the same mount —
    /// `None` when the container had no recorded rootfs (the sandbox
    /// pause task, or a workload whose Create failed before the
    /// rootfs resolved).
    pub fn release_rootfs_key(&mut self, container_id: &str) -> Option<(String, usize)> {
        let key = self.container_rootfs_keys.remove(container_id)?;
        let remaining = self.rootfs_key_users(&key);
        Some((key, remaining))
    }

    /// Allocate a synthetic PID for containerd.
    pub fn alloc_pid(&mut self) -> u32 {
        let pid = self.next_pid;
        self.next_pid += 1;
        pid
    }

    /// Connect to the guest agent (retries until timeout).
    ///
    /// The VM was booted by the k7d daemon during `Create`, which
    /// returned the endpoint to dial: a kernel-global vsock CID for a
    /// native guest, the jail's vsock UDS for a Firecracker one.
    /// Either way the connect retries until the agent starts listening
    /// or the deadline passes, which also absorbs the boot time.
    pub fn connect_agent(&mut self) -> Result<(), String> {
        let endpoint = self.endpoint()?;
        let agent = AgentClient::connect_endpoint(&endpoint, Duration::from_secs(30))
            .map_err(|e| format!("agent connect failed: {e}"))?;
        self.agent = Some(agent);
        Ok(())
    }

    /// The agent endpoint recorded at Create, or a loud error.
    pub fn endpoint(&self) -> Result<AgentEndpoint, String> {
        self.agent_endpoint
            .clone()
            .ok_or_else(|| "VM not created (no agent endpoint)".to_string())
    }

    /// Get a mutable reference to the agent client.
    pub fn agent_mut(&mut self) -> Result<&mut AgentClient, String> {
        self.agent
            .as_mut()
            .ok_or_else(|| "agent not connected".to_string())
    }

    /// Snapshot the per-pod rewrite map so the workload `Create`
    /// path can apply it without holding the `SandboxState` lock
    /// across IO. The union lives in
    /// [`Self::rewrites`]; any virtiofs-fallback binds
    /// ([`Self::pod_volumes`]) are merged in on top.
    #[must_use]
    pub fn mount_rewrite_map(&self) -> MountRewriteMap {
        let mut map = self.rewrites.clone();
        if let Some(ref pv) = self.pod_volumes {
            map.merge(&pv.rewrites);
        }
        map
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The rootfs erofs-key refcount — a same-image
    /// init + main pair shares one key; deleting the init leaves one
    /// live user, so the mount must be reported as still referenced.
    #[test]
    fn rootfs_key_refcount_release() {
        let mut state = SandboxState::new();
        state
            .container_rootfs_keys
            .insert("init".into(), "img-a".into());
        state
            .container_rootfs_keys
            .insert("main".into(), "img-a".into());
        state
            .container_rootfs_keys
            .insert("side".into(), "img-b".into());

        assert_eq!(state.rootfs_key_users("img-a"), 2);
        assert_eq!(state.rootfs_key_users("img-b"), 1);

        // Init delete: the shared key stays referenced by main.
        assert_eq!(state.release_rootfs_key("init"), Some(("img-a".into(), 1)));
        // Double release / unknown container (the sandbox pause task):
        // no claim recorded.
        assert_eq!(state.release_rootfs_key("init"), None);
        assert_eq!(state.release_rootfs_key("pause"), None);

        assert_eq!(state.release_rootfs_key("main"), Some(("img-a".into(), 0)));
        assert_eq!(state.release_rootfs_key("side"), Some(("img-b".into(), 0)));
        assert_eq!(state.rootfs_key_users("img-a"), 0);
    }

    /// The refcount map must survive a shim restart via the
    /// block-state snapshot (kubelet can Delete an exited init
    /// container through a respawned shim).
    #[test]
    fn rootfs_keys_persist_roundtrip() {
        let dir = std::env::temp_dir().join(format!("k7d-sbx-persist-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();

        let mut state = SandboxState::new();
        state.state_dir = Some(dir.clone());
        state
            .container_rootfs_keys
            .insert("init".into(), "img-a".into());
        state
            .container_rootfs_keys
            .insert("main".into(), "img-a".into());
        state.persist_block_state().unwrap();

        let mut restored = SandboxState::new();
        restored.load_block_state(&dir).unwrap();
        assert_eq!(restored.rootfs_key_users("img-a"), 2);
        assert_eq!(
            restored.release_rootfs_key("init"),
            Some(("img-a".into(), 1))
        );

        let _ = std::fs::remove_dir_all(&dir);
    }
}
