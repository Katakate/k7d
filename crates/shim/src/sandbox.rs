//! Per-sandbox state: daemon VM handle, agent connection, container
//! tracking.
//!
//! One sandbox = one pod = one VM. Multiple containers (pause + workload)
//! share the same VM and agent connection.
//!
//! internal notes: the VM itself (KVM fds, guest memory,
//! virtiofsd children, TAP/bridge) lives in the **k7d daemon**; the
//! shim only holds the daemon's `vm_id` and talks to the guest agent
//! directly over vsock (CIDs are kernel-global).

use std::collections::{BTreeMap, HashMap};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use k7d::api::AgentClient;
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

/// One spare "image slot" virtio-blk device declared at boot (spec
/// 16a Inc 1): a fixed-capacity sparse RO backing file whose content
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
    /// Attached RO-hostPath erofs devices, in device order (internal notes
    /// Inc 5).
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
    /// only; empty for init processes). internal notes: captured at `Exec`,
    /// consumed at `Start`.
    pub args: Vec<String>,
    /// internal notes: containerd requested a TTY for this process.
    pub terminal: bool,
    /// internal notes: `$TERM` from the OCI process spec env (PTY execs).
    pub term: String,
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
    /// annotation. Such pods skip the
    /// spec-10a CNI attach, so the Start path must configure the guest's
    /// eth0 with its stable `10.200.0.{2 + vm_index}` identity directly on
    /// the shared host bridge.
    pub cluster_mode: bool,
    /// `vm_index` allocated on the bridge (preserved across forks).
    pub vm_index: Option<u32>,
    /// Source cluster ID when this sandbox is the result of a cluster fork.
    pub fork_source_cluster: Option<String>,
    /// internal notes: cluster snapshot tree this sandbox belongs to (from
    /// `k7d.katakate.org/tree-id`). `None` means the sandbox is not
    /// managed by any cluster snapshot tree — the legacy spec-9d
    /// behaviour. The actual tree-side fork / suspend / resume
    /// operations happen in the k7d daemon (a future PR will wire the
    /// shim's `tree_id` and `tree_source_node_id` through the daemon
    /// Unix-socket API to drive
    /// `ClusterSnapshotTree::{new_cluster, fork, suspend, resume}`).
    pub tree_id: Option<String>,
    /// internal notes: source node within the named tree when this sandbox is
    /// a tree-fork. Only meaningful when `tree_id` is also set.
    pub tree_source_node_id: Option<String>,
    /// internal notes: CNI-assigned pod netns path (from
    /// `linux.namespaces[type=network].path` in the sandbox OCI
    /// bundle). Set only when the k7d daemon reported a successful
    /// pod-netns attach in its `create_vm` response — the Start path
    /// keys the guest's gateway-route configuration off it. Teardown
    /// of the in-netns bridge is the daemon's job (`stop_vm`).
    pub pod_netns: Option<PathBuf>,
    /// Host directory shared into the VM via virtiofs.
    pub state_dir: Option<PathBuf>,
    /// internal notes: per-pod kubelet volumes — bind-mount tree on the
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
    /// internal notes(block path): the `VmConfig` assembled at
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
    /// (internal notes: `readOnly: true` hostPath mounts are packed
    /// into cached erofs images instead of forcing the virtiofs
    /// fallback — the pod stays on the `CoW` fast-fork path). Keyed
    /// like [`Self::rootfs_devices`] so a second mount of the same
    /// source reuses the device.
    pub hostpath_devices: Vec<RootfsDevice>,
    /// Spare image-slot virtio-blk devices declared at sandbox Create
    /// and their post-boot image assignments.
    pub image_slots: Vec<ImageSlot>,
    /// internal notes: container id → rootfs erofs key — the
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
    /// Vsock CID this sandbox's VM was created with.
    ///
    /// Captured from `vm.guest_cid()` in Create and read by the Start
    /// stdout-bridge and the Exec ttrpc handler so they connect to the
    /// right VM via `AgentClient::connect_vsock(cid, ...)`.
    ///
    /// Historically the shim hardcoded `3` for these bridges, which
    /// (a) limited the node to one `runtimeClassName: k7` pod at a
    /// time (the second pod hit `vhost SET_GUEST_CID: Address already
    /// in use` and never started) and (b) prevented the production
    /// `k7-api` pod (which uses CID 3) from coexisting with any
    /// other k7 pod or running test on the same node.
    /// `Vm::builder()` now defaults to a unique CID per VM via
    /// `crate::vsock::allocate_cid`; this field carries that value
    /// to the bridges.
    ///
    /// `None` until `Create` runs; defensive consumers
    /// `.unwrap_or(crate::vsock::DEFAULT_GUEST_CID)` to keep behaving
    /// like the legacy code in the unlikely case the field is
    /// missing.
    pub guest_cid: Option<u64>,
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
            guest_cid: None,
            next_pid: 100,
        }
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
        Ok(())
    }

    /// internal notes: number of live containers whose rootfs rides
    /// the erofs mount for `key`.
    #[must_use]
    pub fn rootfs_key_users(&self, key: &str) -> usize {
        self.container_rootfs_keys
            .values()
            .filter(|k| k.as_str() == key)
            .count()
    }

    /// internal notes: drop `container_id`'s claim on its rootfs
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

    /// Connect to the guest agent over vsock (retries until timeout).
    ///
    /// The VM was booted by the k7d daemon during `Create`; vsock CIDs
    /// are kernel-global so this process can dial the guest directly
    /// with the CID the daemon returned. `connect_vsock` retries until
    /// the guest agent starts listening or the deadline passes, which
    /// also absorbs the boot time.
    pub fn connect_agent(&mut self) -> Result<(), String> {
        let guest_cid = self.guest_cid.ok_or("VM not created (no guest_cid)")?;
        let agent = AgentClient::connect_vsock(guest_cid, Duration::from_secs(30))
            .map_err(|e| format!("agent connect failed: {e}"))?;
        self.agent = Some(agent);
        Ok(())
    }

    /// Get a mutable reference to the agent client.
    pub fn agent_mut(&mut self) -> Result<&mut AgentClient, String> {
        self.agent
            .as_mut()
            .ok_or_else(|| "agent not connected".to_string())
    }

    /// Snapshot the per-pod rewrite map so the workload `Create`
    /// path can apply it without holding the `SandboxState` lock
    /// across IO. internal notes: the union lives in
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

    /// internal notes: the rootfs erofs-key refcount — a same-image
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
