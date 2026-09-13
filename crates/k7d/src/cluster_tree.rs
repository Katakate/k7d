//! Cluster snapshot tree — generalisation of the single-VM
//! [`crate::tree::SnapshotTree`] to whole clusters of N warm-forkable VMs
//! sharing a per-cluster bridge.
//!
//! Where the single-VM tree's nodes are `Vm`s, this tree's nodes are
//! [`ClusterPayload`]s — an N-VM cluster + its [`ClusterNetwork`]. Every
//! fork / suspend / resume / evict / prune operation runs atomically on
//! the whole cluster: `fork_cluster_warm` is the per-fork hot
//! path, and the bookkeeping layer (LRU eviction, RAM/disk budgets, DAG
//! invariants) reuses the exact same pure helpers in
//! [`crate::tree_model`] as the single-VM tree.
//!
//! This file is a parallel hierarchy: we ship the runtime-side cluster
//! tree today; the cleanup that fuses both trees behind a single
//! `SnapshotTree<P: Payload = VmPayload>` generic is left as a follow-up
//! refactor that does not gate cluster-tree functionality.
//!
//! ## On-disk layout
//!
//! ```text
//! {tree_root}/
//! ├── tree.json                        # DAG + budget + per-node {kind, vm_count}
//! └── nodes/
//!     ├── {node_id}/
//!     │   ├── kind                     # literal "cluster"
//!     │   ├── cluster.json             # bridge topology (subnet + per-VM tuple)
//!     │   └── members/
//!     │       ├── 0/                   # full snapshot (checkpoints) or delta only
//!     │       │   ├── memory.bin       # checkpoint nodes only
//!     │       │   ├── delta.pack
//!     │       │   ├── vm_state.json
//!     │       │   ├── cpu.json / devices.json / irqchip.json / metadata.json
//!     │       ├── 1/ …
//!     │       └── 2/ …
//! ```
//!
//! `cluster.json` records the per-VM `(vm_index, guest_ip, guest_mac)`
//! tuples so [`ClusterSnapshotTree::resume`] can reconstruct the bridge
//! with `ClusterNetwork::create + add_tap_at(idx)` per member, restoring
//! every guest's L2/L3 identity verbatim.
//!
//! The bridge name itself is **not** persisted — it's recreated as
//! `{tree_id}-{node_id}` on resume. Bridge names are ephemeral host
//! state, not part of the cluster's identity from the guest's point of
//! view (the guests only see `guest_ip` / `guest_mac`).

use std::collections::{HashMap, VecDeque};
use std::fs;
use std::io::Write;
use std::net::Ipv4Addr;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant, SystemTime};

use serde::{Deserialize, Serialize};

use crate::guest::{
    native_vms_mut, pause_fc_parallel, pause_skew_ns, resume_fc_parallel, Backend, Guest,
};
use crate::network::ClusterNetwork;
use crate::snapshot;
use crate::tree::{
    apply_delta, reap_dir_contents, write_delta, AppliedDelta, NodeId, NodeInfo, PrepareOutcome,
    TreeError,
};
use crate::tree_model::{self, NodeState, PayloadKind, TreeBudget, TreeUsage};
use crate::vm::Vm;

/// One cluster — N VMs sharing a per-cluster bridge. The unit of
/// fork / suspend / resume / evict in a [`ClusterSnapshotTree`].
///
/// `members` are stable-ordered: `members[i]` corresponds to
/// `network.entry(i as u32)`. The index is the `vm_index` used by
/// [`ClusterNetwork::add_tap_at`] both at allocation time and across
/// fork/resume.
pub struct ClusterPayload {
    /// Per-cluster bridge + TAP entries.
    pub network: ClusterNetwork,
    /// Cluster members in stable order. The index in this `Vec` is the
    /// `vm_index` used for `add_tap_at` and recorded in `cluster.json`.
    pub members: Vec<Guest>,
}

impl ClusterPayload {
    /// Number of underlying VMs in this cluster.
    #[must_use]
    pub fn vm_count(&self) -> u32 {
        // Cap at u32 — we don't expect clusters of >4B VMs.
        u32::try_from(self.members.len()).unwrap_or(u32::MAX)
    }

    /// Σ of per-member non-reclaimable RAM in bytes (lower bound, from
    /// dirty bitmaps).
    #[must_use]
    pub fn est_ram_bytes(&self) -> u64 {
        self.members.iter().map(Guest::est_private_bytes).sum()
    }
}

fn cluster_backend(members: &[Guest]) -> Result<Backend, TreeError> {
    let backend = members
        .first()
        .map(Guest::backend)
        .ok_or_else(|| TreeError::InvalidDelta("empty cluster".into()))?;
    if members.iter().any(|g| g.backend() != backend) {
        return Err(TreeError::InvalidDelta(
            "ClusterSnapshotTree::new_cluster: mixed-backend cluster \
             (every member must be native or every member firecracker)"
                .into(),
        ));
    }
    Ok(backend)
}

/// On-disk topology record for one cluster node — written into
/// `nodes/{id}/cluster.json` so resume can rebuild the bridge with the
/// recorded per-VM identity tuples.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClusterTopology {
    /// Schema version — bumped on incompatible changes.
    pub cluster_version: u32,
    /// Subnet base (currently always `[10, 200, 0, 0]`, kept for forward
    /// compatibility with a future configurable subnet).
    pub subnet_base: [u8; 4],
    /// Per-member topology entries in `vm_index` order.
    pub members: Vec<ClusterTopologyMember>,
    /// The tree's egress posture. Serde-defaulted so
    /// legacy `cluster.json` files load as `Open`, which is exactly
    /// the behaviour they were written under.
    #[serde(default)]
    pub egress: crate::netjail::EgressPolicy,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClusterTopologyMember {
    pub vm_index: u32,
    pub guest_ip: Ipv4Addr,
    /// Serialised as a colon-separated MAC string (`aa:bb:00:00:00:02`).
    #[serde(with = "mac_serde")]
    pub guest_mac: [u8; 6],
}

mod mac_serde {
    use serde::{de::Error, Deserialize, Deserializer, Serializer};

    #[allow(clippy::trivially_copy_pass_by_ref)] // signature is dictated by serde
    pub fn serialize<S: Serializer>(mac: &[u8; 6], s: S) -> Result<S::Ok, S::Error> {
        let str_repr = format!(
            "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
            mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]
        );
        s.serialize_str(&str_repr)
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<[u8; 6], D::Error> {
        let s = String::deserialize(d)?;
        let parts: Vec<&str> = s.split(':').collect();
        if parts.len() != 6 {
            return Err(D::Error::custom(format!(
                "MAC must have 6 octets; got {}",
                parts.len()
            )));
        }
        let mut out = [0u8; 6];
        for (i, p) in parts.iter().enumerate() {
            out[i] = u8::from_str_radix(p, 16).map_err(D::Error::custom)?;
        }
        Ok(out)
    }
}

/// Persistent tree document written atomically to `tree.json`.
///
/// This is the same shape as the single-VM tree's `TreeDoc`; the
/// per-node `kind: "cluster"` and `vm_count: N` fields (already on
/// `NodeInfo` from phase 1) tell a reader which on-disk layout
/// each node uses.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct ClusterTreeDoc {
    tree_id: String,
    created_at_unix: u64,
    budget: TreeBudget,
    nodes: HashMap<NodeId, NodeInfo>,
}

/// Snapshot tree of clusters.
///
/// Sibling of [`crate::tree::SnapshotTree`] — same DAG model, same
/// budget / LRU eviction policy, same persistence layer; the difference
/// is the per-node payload is a [`ClusterPayload`] (N VMs + a bridge)
/// instead of a single `Vm`.
pub struct ClusterSnapshotTree {
    tree_id: String,
    root_dir: PathBuf,
    budget: TreeBudget,
    nodes: HashMap<NodeId, NodeInfo>,
    /// Live cluster payloads owned by the tree, keyed by node id.
    live: HashMap<NodeId, ClusterPayload>,
    created_at_unix: u64,
    next_id: u64,
    /// Orchestrator `String → u64` id map into the pure model.
    /// Minted monotonically at node creation (children after parents);
    /// rebuilt parents-first by [`Self::open`].
    pure_ids: HashMap<NodeId, u64>,
    next_pure_id: u64,
    /// For each live node: the node whose per-member `memory.bin` files
    /// its VMs are `MAP_PRIVATE` mappings of, and the generation of that
    /// keyframe. See [`crate::tree::SnapshotTree`]'s field of the same
    /// name — an incremental keyframe is only sound against
    /// the exact generation the payload was materialized from.
    cow_base: HashMap<NodeId, (NodeId, u64)>,
    /// Whether this tree's storage can `FICLONE`. Probed
    /// once at construction — the disk budget projects a keyframe's cost
    /// before writing it, so it has to know which regime it is in. See
    /// `SnapshotTree`'s field of the same name.
    reflink_root: bool,
    /// This tree's cgroup jail. `None` only when
    /// `K7D_TREE_CGROUP=off`. Declared after `live` so a node's VMs
    /// (and their threads) are gone before the cgroup is removed.
    jail: Option<crate::cgroup::TreeCgroup>,
    /// Last cluster-fork pause skew (`max − min` pause-completion
    /// timestamps). Native lockstep forks leave this `None`.
    last_pause_skew_ns: Option<u64>,
}

impl ClusterSnapshotTree {
    /// Registry id — last component of the on-disk root, echoed in `tree.json`.
    #[must_use]
    pub fn tree_id(&self) -> &str {
        &self.tree_id
    }

    /// Live members of `node_id`, if that cluster is in RAM.
    ///
    /// Auto-warp looks tree children up by
    /// `{tree_id}-{node_id}` because `tree_create_cluster` never
    /// inserts members into the daemon's `CreateVm` registry.
    pub fn live_members_mut(&mut self, node_id: &str) -> Option<&mut [Guest]> {
        self.live.get_mut(node_id).map(|p| p.members.as_mut_slice())
    }

    /// Last Firecracker cluster-fork pause skew, if one was measured.
    #[must_use]
    pub fn last_pause_skew_ns(&self) -> Option<u64> {
        self.last_pause_skew_ns
    }

    /// Put every VM of a live cluster node into the tree's cgroup jail.
    fn jail_payload(&self, node_id: &NodeId) -> Result<(), TreeError> {
        let Some(jail) = &self.jail else {
            return Ok(());
        };
        let payload = self
            .live
            .get(node_id)
            .ok_or_else(|| TreeError::NodeNotFound(node_id.clone()))?;
        for vm in &payload.members {
            if matches!(vm, Guest::Firecracker(_)) {
                continue;
            }
            jail.add_vm(vm.as_native()?)?;
        }
        Ok(())
    }

    /// Create a new cluster snapshot tree rooted at a running cluster.
    ///
    /// Each member is `Vm::prepare_fork_source_in`'d against
    /// `nodes/root/members/{i}/`, the bridge topology is written to
    /// `nodes/root/cluster.json`, and the root node enters `Live` state
    /// with `kind = Cluster, vm_count = N`.
    pub fn new_cluster(
        root: ClusterPayload,
        root_dir: PathBuf,
        budget: TreeBudget,
    ) -> Result<(Self, NodeId), TreeError> {
        let vm_count = root.vm_count();
        if vm_count == 0 {
            return Err(TreeError::InvalidDelta(
                "ClusterSnapshotTree::new_cluster: empty cluster".into(),
            ));
        }
        let backend = cluster_backend(&root.members)?;

        fs::create_dir_all(root_dir.join("nodes"))?;
        let root_dir_for_probe = root_dir.clone();
        // Fork / resume bridges are named from `{tree_id}-{node_id}`.
        // Clients (gym `k7_bridge_name`) recompute that from the *registry*
        // tree_id (`tree_root_dir()/{tree_id}`). Inventing `ctree-{pid}`
        // here made `--interface` bind to a link that was never created
        // (curl 45). The last path component *is* that registry id.
        let tree_id = root_dir
            .file_name()
            .and_then(|s| s.to_str())
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .ok_or_else(|| {
                TreeError::InvalidDelta(
                    "ClusterSnapshotTree::new_cluster: root_dir must end in a \
                     non-empty tree_id component (fork bridges are named from it)"
                        .into(),
                )
            })?
            .to_string();
        let now = now_unix();

        let root_id: NodeId = "root".to_string();
        let root_node_dir = root_dir.join("nodes").join(&root_id);
        fs::create_dir_all(&root_node_dir)?;
        fs::write(root_node_dir.join("kind"), b"cluster")?;

        let mut root = root;

        // Prepare every member as a warm-fork source.
        let mut root_span = 0u64;
        for (i, vm) in root.members.iter_mut().enumerate() {
            let member_dir = root_node_dir.join("members").join(i.to_string());
            fs::create_dir_all(&member_dir)?;
            match vm {
                Guest::Firecracker(fc) => {
                    let report = fc
                        .prepare_fork_source()
                        .map_err(|e| TreeError::Firecracker(e.to_string()))?;
                    root_span = root_span.saturating_add(report.diff_bytes);
                }
                Guest::Native(_) => {
                    if !vm.virtiofs_shares().is_empty() {
                        vm.as_native_mut()?.allow_slow_fork();
                    }
                    vm.as_native_mut()?.prepare_fork_source_in(&member_dir)?;
                }
            }
        }
        if backend == Backend::Native {
            root_span = 0;
            for vm in &root.members {
                root_span = root_span.saturating_add(vm.as_native()?.mem_span());
            }
        }

        // Write cluster.json describing the bridge topology.
        let topology = topology_from_network(&root.network);
        write_cluster_topology(&root_node_dir.join("cluster.json"), &topology)?;

        let info = NodeInfo {
            id: root_id.clone(),
            parent: None,
            children: Vec::new(),
            state: NodeState::Live,
            dirty_page_count: 0,
            has_base_snapshot: true,
            label: "root".to_string(),
            created_at_unix: now,
            last_active_at_unix: now,
            protected: false,
            kind: PayloadKind::Cluster,
            vm_count,
            parked_disk_dirs: Vec::new(),
            base_identity: 1,
            base_disk_bytes: Some(root_span),
        };

        let mut nodes = HashMap::new();
        nodes.insert(root_id.clone(), info);
        let mut live = HashMap::new();
        live.insert(root_id.clone(), root);

        let mut pure_ids = HashMap::new();
        pure_ids.insert(root_id.clone(), 0);

        let jail = crate::cgroup::TreeCgroup::create(&tree_id, budget)?;
        let tree = Self {
            tree_id,
            root_dir,
            budget,
            nodes,
            live,
            created_at_unix: now,
            next_id: 0,
            pure_ids,
            next_pure_id: 1,
            cow_base: HashMap::new(),
            reflink_root: crate::tree::probe_reflink_root(&root_dir_for_probe),
            jail,
            last_pause_skew_ns: None,
        };
        tree.jail_payload(&root_id)?;
        tree.save_metadata()?;
        Ok((tree, root_id))
    }

    /// Find a live member VM by guest CID (debug introspection:
    /// `dump_serial` reads the guest console of cluster members, which
    /// carry no daemon `vm_id`). Returns the owning node id alongside
    /// the VM.
    #[must_use]
    pub fn find_live_vm_by_cid(&self, cid: u64) -> Option<(&str, &Guest)> {
        for (node_id, payload) in &self.live {
            if let Some(vm) = payload
                .members
                .iter()
                .find(|vm| vm.guest_cid() == Some(cid))
            {
                return Some((node_id.as_str(), vm));
            }
        }
        None
    }

    /// Make `source_id` legal for `fork_warm` without writing a keyframe.
    ///
    /// A live child already maps its nearest checkpoint's `memory.bin`
    /// plus an accumulated dirty bitmap. Point `fork_source_base_path`
    /// at that file and let `fork_warm` memcpy dirty pages in-process.
    /// Write a new keyframe only when no ancestor file exists, or when
    /// any member has virtiofs shares (FUSE DMA is invisible to the
    /// dirty log).
    fn is_fc(&self, node_id: &NodeId) -> bool {
        self.live.get(node_id).is_some_and(|p| {
            !p.members.is_empty()
                && p.members
                    .iter()
                    .all(|g| g.backend() == Backend::Firecracker)
        })
    }

    fn ensure_forkable(&mut self, source_id: &NodeId) -> Result<(), TreeError> {
        if self.is_fc(source_id) {
            return Ok(());
        }
        let (already, virtiofs) = {
            let source = self
                .live
                .get(source_id)
                .ok_or_else(|| TreeError::NodeNotFound(source_id.clone()))?;
            (
                source.members.iter().all(|vm| {
                    vm.as_native()
                        .is_ok_and(|n| n.fork_source_base_path().is_some())
                }),
                source
                    .members
                    .iter()
                    .any(|vm| !vm.virtiofs_shares().is_empty()),
            )
        };
        if already {
            return Ok(());
        }
        if !virtiofs {
            if let Ok(ckpt) = self.nearest_checkpoint(source_id) {
                if ckpt != *source_id {
                    let dir = self.node_dir(&ckpt);
                    let source = self
                        .live
                        .get_mut(source_id)
                        .ok_or_else(|| TreeError::NodeNotFound(source_id.clone()))?;
                    for (i, vm) in source.members.iter_mut().enumerate() {
                        if vm.as_native()?.fork_source_base_path().is_some() {
                            continue;
                        }
                        let mem = dir.join("members").join(i.to_string()).join("memory.bin");
                        if !mem.is_file() {
                            return Err(TreeError::InvalidDelta(format!(
                                "ensure_forkable({source_id}): ancestor '{ckpt}' member {i} \
                                 has no memory.bin at {}",
                                mem.display()
                            )));
                        }
                        let dirty = vm.as_native()?.accumulated_dirty_pages().unwrap_or(0);
                        log::info!(
                            "cluster_tree: inherit {ckpt}/members/{i}/memory.bin on {source_id} \
                             ({dirty} dirty pages, no new keyframe)"
                        );
                        vm.as_native_mut()?.set_fork_source_base_path(mem);
                    }
                    return Ok(());
                }
            }
        }
        self.prepare_fork_source(source_id)?;
        Ok(())
    }

    /// Snapshot a live cluster so later forks from it take the warm path
    /// against *this* node's per-member `memory.bin` (dirty set reset).
    ///
    /// Root members are prepared at [`Self::new_cluster`]. In-tree
    /// children inherit an ancestor path at fork and are not
    /// checkpoints until this runs. Idempotent on `has_base_snapshot` —
    /// an inherited `fork_source_base_path` is not a keyframe this node
    /// owns (CHALLENGES.md #59, #182).
    ///
    /// A child whose members still map their source's keyframes takes
    /// the **incremental** path per member — this is the GRPO
    /// path, where a generation's keyframe would otherwise cost
    /// `N × guest RAM`.
    pub fn prepare_fork_source(&mut self, node_id: &NodeId) -> Result<PrepareOutcome, TreeError> {
        self.ensure_live(node_id)?;
        // Firecracker: a point is a file children load, so re-take whenever
        // the guest has dirtied anything — not idempotent on
        // `has_base_snapshot` the way the native path is.
        if self.is_fc(node_id) {
            return self.prepare_fork_source_fc(node_id);
        }
        if self.nodes.get(node_id).is_some_and(|n| n.has_base_snapshot) {
            return Ok(PrepareOutcome::already_prepared());
        }
        let node_dir = self.node_dir(node_id);
        let ancestor_dir = self.cow_base_keyframe_dir(node_id);
        // Make disk headroom for the per-member keyframes BEFORE writing
        // them — `usage()` only sees the files after the
        // fact, so without this the writes silently blow `max_disk_bytes`
        // until the next auto_evict. On the incremental path the
        // projection is the members' dirty estimate, not their spans.
        {
            let source = self
                .live
                .get(node_id)
                .ok_or_else(|| TreeError::NodeNotFound(node_id.clone()))?;
            let projected: u64 = {
                let mut total = 0u64;
                for vm in &source.members {
                    let native = vm.as_native()?;
                    total = total.saturating_add(if ancestor_dir.is_some() {
                        native.accumulated_dirty_pages().unwrap_or(0) * 4096
                    } else {
                        native.mem_span()
                    });
                }
                total
            };
            if projected > 0 {
                self.evict_disk_for_incoming(projected)?;
            }
        }
        let source = self
            .live
            .get_mut(node_id)
            .ok_or_else(|| TreeError::NodeNotFound(node_id.clone()))?;
        log::info!("cluster_tree: prepare_fork_source({node_id})");
        // A cluster's keyframe is incremental only if *every* member's
        // was: one member falling back to a full dump makes the node's
        // recorded disk cost a mixture, and the wire flag must not claim
        // more than happened.
        let mut incremental = ancestor_dir.is_some();
        let mut disk_bytes: u64 = 0;
        for (i, vm) in source.members.iter_mut().enumerate() {
            let member_dir = node_dir.join("members").join(i.to_string());
            fs::create_dir_all(&member_dir)?;
            if !vm.virtiofs_shares().is_empty() {
                vm.as_native_mut()?.allow_slow_fork();
            }
            let ancestor_mem = ancestor_dir
                .as_ref()
                .map(|d| d.join("members").join(i.to_string()).join("memory.bin"))
                .filter(|p| p.is_file());
            let native = vm.as_native_mut()?;
            let prepared = if let Some(ancestor) = &ancestor_mem {
                native.prepare_fork_source_incremental_in(&member_dir, ancestor)?
            } else {
                let span = native.mem_span();
                crate::vm::PreparedBase::full(native.prepare_fork_source_in(&member_dir)?, span)
            };
            incremental &= prepared.incremental;
            disk_bytes = disk_bytes.saturating_add(prepared.disk_bytes);
        }
        let identity = self.mint_base_identity();
        if let Some(info) = self.nodes.get_mut(node_id) {
            info.has_base_snapshot = true;
            info.base_identity = identity;
            info.base_disk_bytes = Some(disk_bytes);
            touch(info);
        }
        self.save_metadata()?;
        Ok(PrepareOutcome {
            wrote_base: true,
            incremental,
            disk_bytes,
        })
    }

    fn prepare_fork_source_fc(&mut self, node_id: &NodeId) -> Result<PrepareOutcome, TreeError> {
        let source = self
            .live
            .get_mut(node_id)
            .ok_or_else(|| TreeError::NodeNotFound(node_id.clone()))?;
        log::info!("cluster_tree: prepare_fork_source({node_id}) firecracker");
        let mut incremental = true;
        let mut disk_bytes: u64 = 0;
        for vm in &mut source.members {
            let report = vm.as_fc_mut()?.prepare_fork_source()?;
            incremental &= report.incremental;
            disk_bytes = disk_bytes.saturating_add(report.diff_bytes);
        }
        let identity = self.mint_base_identity();
        if let Some(info) = self.nodes.get_mut(node_id) {
            info.has_base_snapshot = true;
            info.base_identity = identity;
            info.base_disk_bytes = Some(disk_bytes);
            touch(info);
        }
        self.save_metadata()?;
        Ok(PrepareOutcome {
            wrote_base: true,
            incremental,
            disk_bytes,
        })
    }

    /// The node directory whose per-member `memory.bin` files this
    /// node's live payload maps, if that generation is still current.
    /// See `SnapshotTree::cow_base_keyframe`.
    fn cow_base_keyframe_dir(&self, node_id: &NodeId) -> Option<PathBuf> {
        if !self.reflink_root {
            return None;
        }
        let (ancestor, identity) = self.cow_base.get(node_id)?;
        if self.nodes.get(ancestor)?.base_identity != *identity {
            log::warn!(
                "cluster_tree: node '{node_id}' was forked off '{ancestor}' generation \
                 {identity}, which has since re-prepared — writing full keyframes"
            );
            return None;
        }
        Some(self.node_dir(ancestor))
    }

    /// Record that `node_id`'s payload maps `ancestor`'s keyframes.
    fn record_cow_base(&mut self, node_id: &NodeId, ancestor: &NodeId) {
        let Some(identity) = self.nodes.get(ancestor).map(|n| n.base_identity) else {
            return;
        };
        self.cow_base
            .insert(node_id.clone(), (ancestor.clone(), identity));
    }

    /// The next unused base-generation number for this tree. Never 0.
    fn mint_base_identity(&self) -> u64 {
        self.nodes
            .values()
            .map(|n| n.base_identity)
            .max()
            .unwrap_or(0)
            + 1
    }

    /// Fork a new cluster branch from any live or suspended node.
    ///
    /// Implements:
    ///   1. pre-fork eviction (RAM tier; cluster nodes count as `vm_count` each)
    ///   2. `fork_cluster_warm` — atomic per-cluster pause +
    ///      bitmap+state capture, then per-VM warm fork onto a fresh bridge
    ///      cloned via `ClusterNetwork::fork_from + add_tap_at(i)`
    ///   3. post-fork eviction (the new cluster is exempted)
    pub fn fork(&mut self, source_id: &NodeId, label: &str) -> Result<NodeId, TreeError> {
        let ids = self.fork_batch(source_id, &[label], None)?;
        Ok(ids.into_iter().next().expect("single fork"))
    }

    /// Non-destructive rollback: create a new branch from `node_id`'s
    /// state (RL verb). Equivalent to [`Self::fork`].
    pub fn rollback(&mut self, node_id: &NodeId, label: &str) -> Result<NodeId, TreeError> {
        self.fork(node_id, label)
    }

    /// Fork N cluster branches from the same source.
    ///
    /// Uses [`crate::fork::fork_cluster_warm_batch`]: one shared pause +
    /// dirty-bitmap capture across the whole batch, then N bridges and
    /// `N × M` member materialisations in parallel (host-net setup stays
    /// sequential). Loud on the first failure — no half-batch is inserted
    /// into the tree (the source is always handed back).
    #[allow(clippy::too_many_lines)]
    pub fn fork_batch(
        &mut self,
        source_id: &NodeId,
        labels: &[&str],
        dilation: Option<u32>,
    ) -> Result<Vec<NodeId>, TreeError> {
        if labels.is_empty() {
            return Err(TreeError::InvalidDelta(
                "ClusterSnapshotTree::fork_batch: labels must be non-empty".into(),
            ));
        }
        self.ensure_live(source_id)?;
        // Make headroom for the incoming forks (CHALLENGES
        // #115): each label clones the whole cluster, so `labels.len() ×
        // vm_count(source)` new live VMs are about to exist. Suspend LRU
        // non-protected nodes until they fit, exempting the source; fail
        // loud (`BudgetExhausted`) instead of hanging the control socket.
        let source_vm_count = self
            .nodes
            .get(source_id)
            .ok_or_else(|| TreeError::NodeNotFound(source_id.clone()))?
            .vm_count
            .max(1) as usize;
        let incoming = labels.len().saturating_mul(source_vm_count);
        let t0 = Instant::now();
        self.evict_for_incoming(source_id, incoming)?;
        self.ensure_live(source_id)?;
        if self.is_fc(source_id) {
            return self.fork_batch_fc(source_id, labels, dilation, t0);
        }
        // In-tree forks inherit the ancestor keyframe + dirty bitmap.
        // Do not write a new memory.bin (that restore-swap is the 23s
        // mid-tree tax). Prepare only when there is no ancestor file.
        self.ensure_forkable(source_id)?;
        let t_prep = t0.elapsed();

        let new_ids: Vec<NodeId> = labels.iter().map(|label| self.mint_id(label)).collect();
        for id in &new_ids {
            self.mint_pure_id(id);
        }
        let bridge_labels: Vec<String> = new_ids
            .iter()
            .map(|id| format!("{}-{id}", self.tree_id))
            .collect();

        // Take temporary ownership of the source so we can mutably borrow
        // its members for the shared-pause batch. Handed back on every path.
        let mut source = self
            .live
            .remove(source_id)
            .ok_or_else(|| TreeError::NodeNotFound(source_id.clone()))?;

        let n = source.members.len();
        let member_id_owned: Vec<Vec<String>> = labels
            .iter()
            .map(|label| (0..n).map(|i| format!("{label}-{i}")).collect())
            .collect();
        let member_id_refs: Vec<Vec<&str>> = member_id_owned
            .iter()
            .map(|v| v.iter().map(String::as_str).collect())
            .collect();
        let requests: Vec<crate::fork::ClusterForkRequest<'_>> = bridge_labels
            .iter()
            .enumerate()
            .map(|(i, bl)| crate::fork::ClusterForkRequest {
                fork_cluster_id: bl.as_str(),
                fork_ids: &member_id_refs[i],
                fork_pod_ips: &[],
                fork_pod_netns: &[],
                dilation,
            })
            .collect();

        let natives = native_vms_mut(&mut source.members)?;
        let mut sources_view: Vec<(&mut Vm, u32)> = natives
            .into_iter()
            .enumerate()
            .map(|(i, v)| (v, u32::try_from(i).unwrap_or(u32::MAX)))
            .collect();

        let t1 = Instant::now();
        let result =
            crate::fork::fork_cluster_warm_batch(&source.network, &mut sources_view, &requests);
        let t_warm = t1.elapsed();
        drop(sources_view);

        let forked = match result {
            Ok(v) => v,
            Err(e) => {
                self.live.insert(source_id.clone(), source);
                return Err(TreeError::Fork(e));
            }
        };

        // Snapshot source bitmaps AFTER the batch (updated in place during
        // pause/capture) so each child seeds deltas covering pre-fork dirty
        // pages — mirrors single-VM `tree.rs::fork_batch`.
        let mut source_bitmaps = Vec::with_capacity(source.members.len());
        let mut source_bases = Vec::with_capacity(source.members.len());
        for vm in &source.members {
            let native = vm.as_native()?;
            source_bitmaps.push(native.accumulated_dirty_bitmap().unwrap_or_default());
            source_bases.push(
                native
                    .fork_source_base_path()
                    .map(std::path::Path::to_path_buf),
            );
        }
        let cow_ancestor = self.nearest_checkpoint(source_id)?;
        // Hand the source back before starting forks so a later `start`
        // failure cannot strand the live map without the root cluster.
        self.live.insert(source_id.clone(), source);

        let now = now_unix();
        let t2 = Instant::now();
        for (((fork_net, fork_vms), new_id), label) in
            forked.into_iter().zip(new_ids.iter()).zip(labels.iter())
        {
            let mut fork_payload = ClusterPayload {
                network: fork_net,
                members: fork_vms.into_iter().map(Guest::from).collect(),
            };
            // Dirty log *before* start: enable_dirty_tracking pauses a
            // running VM and wait_quiescent can sit on virtio-blk/net
            // for up to 200 ms each (CHALLENGES #162). The child is still
            // stopped here, so the ioctl is just a slot re-register.
            for (i, vm) in fork_payload.members.iter_mut().enumerate() {
                {
                    let native = vm.as_native_mut()?;
                    native.enable_dirty_tracking()?;
                    if let Some(seed) = source_bitmaps.get(i) {
                        native.seed_accumulated_dirty(seed)?;
                    }
                    if let Some(Some(base)) = source_bases.get(i) {
                        native.set_fork_source_base_path(base.clone());
                    }
                }
                vm.start()?;
            }

            let new_node_dir = self.node_dir(new_id);
            fs::create_dir_all(&new_node_dir)?;
            fs::write(new_node_dir.join("kind"), b"cluster")?;
            let topology = topology_from_network(&fork_payload.network);
            write_cluster_topology(&new_node_dir.join("cluster.json"), &topology)?;

            let info = NodeInfo {
                id: new_id.clone(),
                parent: Some(source_id.clone()),
                children: Vec::new(),
                state: NodeState::Live,
                dirty_page_count: 0,
                has_base_snapshot: false,
                label: (*label).to_string(),
                created_at_unix: now,
                last_active_at_unix: now,
                protected: false,
                kind: PayloadKind::Cluster,
                vm_count: fork_payload.vm_count(),
                parked_disk_dirs: Vec::new(),
                base_identity: 0,
                base_disk_bytes: None,
            };
            self.nodes.insert(new_id.clone(), info);
            self.live.insert(new_id.clone(), fork_payload);
            self.record_cow_base(new_id, &cow_ancestor);
            self.jail_payload(new_id)?;
            if let Some(src_info) = self.nodes.get_mut(source_id) {
                src_info.children.push(new_id.clone());
                touch(src_info);
            }
        }
        let t_start_jail = t2.elapsed();

        let t3 = Instant::now();
        self.save_metadata()?;
        let t_save = t3.elapsed();

        // Resume applies one pack onto the nearest checkpoint. Children
        // must inherit (or prepare) a memory.bin path so the next fork
        // does not write a keyframe.
        #[cfg(debug_assertions)]
        for id in &new_ids {
            debug_assert!(
                self.nearest_checkpoint(id).is_ok(),
                "fork_batch child {id} has no checkpoint ancestor"
            );
            debug_assert!(
                self.live.get(id).is_some_and(|p| {
                    p.members.iter().all(|vm| {
                        vm.as_native()
                            .is_ok_and(|n| n.fork_source_base_path().is_some())
                    })
                }),
                "fork_batch child {id} is not forkable"
            );
        }

        let t4 = Instant::now();
        self.evict_post_fork(source_id, &new_ids)?;
        log::info!(
            "cluster_tree fork_batch: prepare={t_prep:?} warm={t_warm:?} \
             start_jail={t_start_jail:?} save={t_save:?} evict={:?}",
            t4.elapsed()
        );
        Ok(new_ids)
    }

    /// Firecracker cluster fork: parallel pause with per-member
    /// timestamps, Diff/apply/restore-point/disk-reflink per member,
    /// parallel resume, children on `{tree_id}-{node_id}` via
    /// `network_overrides`. `pause_skew_ns` is max−min pause Instant.
    #[allow(clippy::too_many_lines)]
    fn fork_batch_fc(
        &mut self,
        source_id: &NodeId,
        labels: &[&str],
        dilation: Option<u32>,
        t0: Instant,
    ) -> Result<Vec<NodeId>, TreeError> {
        if dilation.is_some() {
            return Err(TreeError::Firecracker(
                "time dilation is not supported on Firecracker nodes".into(),
            ));
        }
        let mut source = self.live.remove(source_id).ok_or_else(|| {
            TreeError::InvalidDelta(format!("fork_batch_fc: source {source_id} vanished"))
        })?;
        let timestamps = match pause_fc_parallel(&mut source.members) {
            Ok(ts) => ts,
            Err(e) => {
                let _ = resume_fc_parallel(&mut source.members);
                self.live.insert(source_id.clone(), source);
                return Err(e.into());
            }
        };
        let pause_skew_ns = pause_skew_ns(&timestamps);
        self.last_pause_skew_ns = Some(pause_skew_ns);
        for member in &mut source.members {
            if let Err(e) = member.as_fc_mut()?.prepare_fork_source() {
                let _ = resume_fc_parallel(&mut source.members);
                self.live.insert(source_id.clone(), source);
                return Err(e.into());
            }
        }
        if let Err(e) = resume_fc_parallel(&mut source.members) {
            self.live.insert(source_id.clone(), source);
            return Err(e.into());
        }
        self.live.insert(source_id.clone(), source);

        let new_ids: Vec<NodeId> = labels.iter().map(|label| self.mint_id(label)).collect();
        for id in &new_ids {
            self.mint_pure_id(id);
        }

        let mut children: Vec<(NodeId, ClusterPayload)> = Vec::new();
        for new_id in &new_ids {
            match self.materialize_fc_child(source_id, new_id) {
                Ok(payload) => children.push((new_id.clone(), payload)),
                Err(e) => {
                    drop(children);
                    return Err(e);
                }
            }
        }

        let now = now_unix();
        let source_disk = self
            .nodes
            .get(source_id)
            .and_then(|n| n.base_disk_bytes)
            .unwrap_or(0);
        for ((new_id, payload), label) in children.into_iter().zip(labels.iter()) {
            let new_node_dir = self.node_dir(&new_id);
            fs::create_dir_all(&new_node_dir)?;
            fs::write(new_node_dir.join("kind"), b"cluster")?;
            let topology = topology_from_network(&payload.network);
            write_cluster_topology(&new_node_dir.join("cluster.json"), &topology)?;
            let info = NodeInfo {
                id: new_id.clone(),
                parent: Some(source_id.clone()),
                children: Vec::new(),
                state: NodeState::Live,
                dirty_page_count: 0,
                has_base_snapshot: true,
                label: (*label).to_string(),
                created_at_unix: now,
                last_active_at_unix: now,
                protected: false,
                kind: PayloadKind::Cluster,
                vm_count: payload.vm_count(),
                parked_disk_dirs: Vec::new(),
                base_identity: 0,
                base_disk_bytes: Some(source_disk),
            };
            self.nodes.insert(new_id.clone(), info);
            self.live.insert(new_id.clone(), payload);
            self.jail_payload(&new_id)?;
            if let Some(src_info) = self.nodes.get_mut(source_id) {
                src_info.children.push(new_id.clone());
                touch(src_info);
            }
        }
        self.save_metadata()?;
        self.evict_post_fork(source_id, &new_ids)?;
        log::info!(
            "cluster_tree fork_batch_fc: pause_skew_ns={pause_skew_ns} elapsed={:?}",
            t0.elapsed()
        );
        Ok(new_ids)
    }

    fn materialize_fc_child(
        &self,
        source_id: &NodeId,
        new_id: &NodeId,
    ) -> Result<ClusterPayload, TreeError> {
        let source = self.live.get(source_id).ok_or_else(|| {
            TreeError::InvalidDelta(format!("materialize_fc_child: source {source_id} gone"))
        })?;
        let bridge = format!("{}-{new_id}", self.tree_id);
        let mut fork_net = ClusterNetwork::fork_from(&source.network, &bridge).map_err(|e| {
            TreeError::Fork(crate::fork::ForkError::Reflink(format!(
                "ClusterNetwork::fork_from({bridge}): {e}"
            )))
        })?;
        let mut members = Vec::with_capacity(source.members.len());
        for (i, src) in source.members.iter().enumerate() {
            let idx = u32::try_from(i).unwrap_or(u32::MAX);
            let tap = fork_net.add_tap_at(idx).map_err(|e| {
                TreeError::Fork(crate::fork::ForkError::Reflink(format!(
                    "add_tap_at({idx}) on {bridge}: {e}"
                )))
            })?;
            let child = src.as_fc()?.spawn_child(Some(tap))?;
            members.push(Guest::from(child));
        }
        Ok(ClusterPayload {
            network: fork_net,
            members,
        })
    }

    /// Suspend a live cluster: per-member delta + state captured, bridge
    /// torn down, RAM freed.
    ///
    /// Fails loud for virtiofs-backed members: virtiofsd writes FUSE
    /// completions through its own mapping, invisible to KVM dirty
    /// tracking, so `delta.pack` would silently miss device DMA and the
    /// resumed guest would corrupt (limitation).
    pub fn suspend(&mut self, node_id: &NodeId) -> Result<(), TreeError> {
        if self.is_fc(node_id) {
            return self.suspend_fc(node_id);
        }
        if let Some(p) = self.live.get(node_id) {
            if p.members.iter().any(|vm| !vm.virtiofs_shares().is_empty()) {
                return Err(TreeError::InvalidDelta(format!(
                    "suspend({node_id}): virtiofs-backed members cannot be suspended — \
                     virtiofsd DMA bypasses KVM dirty tracking, so the delta would be \
                     incomplete"
                )));
            }
        }
        let mut payload = self
            .live
            .remove(node_id)
            .ok_or_else(|| TreeError::NodeNotFound(node_id.clone()))?;

        let node_dir = self.node_dir(node_id);
        fs::create_dir_all(&node_dir)?;
        fs::write(node_dir.join("kind"), b"cluster")?;

        // Pause every member, capture dirty + state, write delta + state.
        let mut total_dirty: u32 = 0;
        // Name the keyframe generation these packs diff against, so a
        // resume onto a base that has since re-prepared fails loud
        // (CHALLENGES #144).
        let base_identity = self
            .nearest_checkpoint(node_id)
            .ok()
            .and_then(|base| self.nodes.get(&base).map(|n| n.base_identity))
            .unwrap_or(0);
        for (i, vm) in payload.members.iter_mut().enumerate() {
            let member_dir = node_dir.join("members").join(i.to_string());
            fs::create_dir_all(&member_dir)?;

            vm.pause()?;
            let native = vm.as_native_mut()?;
            let bitmap = native.get_and_accumulate_dirty()?.to_vec();
            let state = snapshot::capture_vm_state(native)?;
            let src_mem = native.mem_host_addr();
            // Deltas index pages of the guest physical span, not of RAM.
            let mem_size = native.mem_span();

            let dirty_pages = write_delta(
                &member_dir.join("delta.pack"),
                &bitmap,
                src_mem,
                mem_size,
                base_identity,
            )?;
            let state_json = serde_json::to_string(&state)?;
            atomic_write(&member_dir.join("vm_state.json"), state_json.as_bytes())?;
            total_dirty = total_dirty.saturating_add(dirty_pages);
        }

        // Write cluster.json so resume can rebuild the bridge.
        let topology = topology_from_network(&payload.network);
        write_cluster_topology(&node_dir.join("cluster.json"), &topology)?;

        // Forked members' RW disk images live in directories the Vm
        // owns (removed on Drop) — but they ARE this node's disk state,
        // and each member's `vm_state.json` records their paths for
        // resume's reflink. Park ownership on the node record before
        // dropping the payload (CHALLENGES.md #130).
        let mut parked = Vec::new();
        for vm in &mut payload.members {
            if let Some(dir) = vm.as_native_mut()?.take_fork_state_dir() {
                parked.push(dir);
            }
        }

        // Drop the payload — Vm::Drop closes KVM fds + munmaps memory;
        // ClusterNetwork::Drop tears down the bridge + iptables rules.
        drop(payload);
        // No mappings, no CoW base — resume re-records one.
        self.cow_base.remove(node_id);

        if let Some(info) = self.nodes.get_mut(node_id) {
            info.state = NodeState::Suspended;
            info.dirty_page_count = total_dirty;
            info.parked_disk_dirs = parked;
            touch(info);
        }
        self.save_metadata()?;
        log::info!(
            "cluster_tree: suspended '{node_id}' ({total_dirty} dirty pages across members)"
        );
        Ok(())
    }

    /// Firecracker suspend: parallel pause, Full snapshot into each
    /// `members/{i}/`, then drop the payload (processes, chroots, bridge).
    /// Resume re-stages from the exported files.
    fn suspend_fc(&mut self, node_id: &NodeId) -> Result<(), TreeError> {
        let mut payload = self
            .live
            .remove(node_id)
            .ok_or_else(|| TreeError::NodeNotFound(node_id.clone()))?;
        if let Err(e) = pause_fc_parallel(&mut payload.members) {
            let _ = resume_fc_parallel(&mut payload.members);
            self.live.insert(node_id.clone(), payload);
            return Err(e.into());
        }
        let node_dir = self.node_dir(node_id);
        fs::create_dir_all(&node_dir)?;
        fs::write(node_dir.join("kind"), b"cluster")?;
        let mut exported = 0u64;
        for (i, vm) in payload.members.iter_mut().enumerate() {
            let member_dir = node_dir.join("members").join(i.to_string());
            if let Err(e) = vm.snapshot(&member_dir) {
                let _ = resume_fc_parallel(&mut payload.members);
                self.live.insert(node_id.clone(), payload);
                return Err(e.into());
            }
            exported = exported.saturating_add(crate::fc::exported_snapshot_bytes(&member_dir));
        }
        let topology = topology_from_network(&payload.network);
        write_cluster_topology(&node_dir.join("cluster.json"), &topology)?;
        drop(payload);
        self.cow_base.remove(node_id);
        if let Some(info) = self.nodes.get_mut(node_id) {
            info.state = NodeState::Suspended;
            info.dirty_page_count = 0;
            info.parked_disk_dirs = Vec::new();
            info.base_disk_bytes = Some(exported);
            touch(info);
        }
        self.save_metadata()?;
        log::info!("cluster_tree: suspended Firecracker '{node_id}' ({exported} bytes exported)");
        Ok(())
    }

    /// Resume a suspended cluster: bridge re-created with the recorded
    /// per-VM identity tuples, every member restored from
    /// `members/{i}/delta.pack` + the nearest checkpoint ancestor's
    /// `members/{i}/memory.bin`.
    pub fn resume(&mut self, node_id: &NodeId) -> Result<(), TreeError> {
        let info = self
            .nodes
            .get(node_id)
            .ok_or_else(|| TreeError::NodeNotFound(node_id.clone()))?;
        if info.state != NodeState::Suspended {
            return Err(TreeError::BadState(
                node_id.clone(),
                info.state,
                "resume (must be Suspended)",
            ));
        }
        let vm_count_for_node = info.vm_count;
        let node_dir = self.node_dir(node_id);
        if node_dir
            .join("members")
            .join("0")
            .join(crate::fc::SUSPEND_META)
            .is_file()
        {
            return self.resume_fc(node_id, vm_count_for_node);
        }

        // One delta.pack per member onto the nearest checkpoint. In-tree
        // inherit means unprepared hops are not extra packs.
        if self.nearest_checkpoint(node_id).is_err() {
            let chain = self.restore_chain_depth(node_id).unwrap_or(usize::MAX);
            return Err(TreeError::ChainTooDeep {
                node: node_id.clone(),
                depth: chain,
                max: 0,
            });
        }

        // Reserve headroom for the cluster we're about to bring back to Live.
        self.evict_for_incoming_no_exempt(vm_count_for_node as usize)?;

        // Read cluster.json to learn the bridge topology.
        let node_dir = self.node_dir(node_id);
        let topology = read_cluster_topology(&node_dir.join("cluster.json"))?;

        // Recreate the bridge with the recorded subnet + per-VM identity
        // and the persisted egress posture (a contained tree
        // must not resume Open).
        let bridge_label = format!("{}-{}", self.tree_id, node_id);
        let mut net = ClusterNetwork::create_with_egress(&bridge_label, topology.egress.clone())
            .map_err(|e| {
                TreeError::Fork(crate::fork::ForkError::Reflink(format!(
                    "ClusterNetwork::create resume: {e}"
                )))
            })?;

        // Find the nearest checkpoint ancestor for each member.
        let base_node = self.nearest_checkpoint(node_id)?;
        let base_dir = self.node_dir(&base_node);
        let base_identity = self
            .nodes
            .get(&base_node)
            .map_or(0, |info| info.base_identity);

        let n = topology.members.len();
        let mut members: Vec<Guest> = Vec::with_capacity(n);
        for (i, member_topo) in topology.members.iter().enumerate() {
            let _tap = net.add_tap_at(member_topo.vm_index).map_err(|e| {
                TreeError::Fork(crate::fork::ForkError::Reflink(format!(
                    "add_tap_at({}) on resume: {e}",
                    member_topo.vm_index
                )))
            })?;

            let member_dir = node_dir.join("members").join(i.to_string());
            let base_member_dir = base_dir.join("members").join(i.to_string());
            let base_mem_path = base_member_dir.join("memory.bin");

            let state = snapshot::load_vm_state(&member_dir)?;

            let mem_span = crate::mem_layout::MemLayout::from_ram(state.memory_size).span();
            let fork_mem_addr = crate::fork::mmap_base_mem_private(&base_mem_path, mem_span)?;

            let applied = if base_node == *node_id {
                AppliedDelta::empty(mem_span)
            } else {
                apply_delta(
                    &member_dir.join("delta.pack"),
                    fork_mem_addr,
                    mem_span,
                    base_identity,
                )?
            };

            let mut vm = crate::fork::build_vm_from_state_and_mem(
                &state,
                fork_mem_addr,
                &format!("resume:{node_id}/{i}"),
            )?;
            vm.start()?;
            vm.enable_dirty_tracking()?;
            // The pack's pages are this member's divergence from its
            // base; a fresh bitmap would forget them and the next
            // suspend would write an incomplete pack (CHALLENGES #143).
            vm.seed_accumulated_dirty(&applied.bitmap)?;
            // Always a MAP_PRIVATE of the nearest checkpoint file.
            // Inherited children keep has_base_snapshot=false so an
            // explicit prepare still writes (CHALLENGES #144).
            vm.set_fork_source_base_path(base_mem_path.clone());
            members.push(Guest::from(vm));
        }

        let payload = ClusterPayload {
            network: net,
            members,
        };
        self.live.insert(node_id.clone(), payload);
        self.record_cow_base(node_id, &base_node);
        self.jail_payload(node_id)?;
        if let Some(info) = self.nodes.get_mut(node_id) {
            info.state = NodeState::Live;
            // The resumed members reflinked their own copies of the RW
            // images out of the parked directories (see `suspend`); the
            // parked originals are now dead weight — remove them.
            for dir in std::mem::take(&mut info.parked_disk_dirs) {
                fs::remove_dir_all(&dir)?;
            }
            touch(info);
        }
        self.save_metadata()?;
        log::info!("cluster_tree: resumed '{node_id}'");
        Ok(())
    }

    fn resume_fc(&mut self, node_id: &NodeId, vm_count: u32) -> Result<(), TreeError> {
        self.evict_for_incoming_no_exempt(vm_count as usize)?;
        let node_dir = self.node_dir(node_id);
        let topology = read_cluster_topology(&node_dir.join("cluster.json"))?;
        let bridge_label = format!("{}-{node_id}", self.tree_id);
        let mut net = ClusterNetwork::create_with_egress(&bridge_label, topology.egress.clone())
            .map_err(|e| {
                TreeError::Fork(crate::fork::ForkError::Reflink(format!(
                    "ClusterNetwork::create resume fc: {e}"
                )))
            })?;
        let mut members = Vec::with_capacity(topology.members.len());
        for (i, member_topo) in topology.members.iter().enumerate() {
            let tap = net.add_tap_at(member_topo.vm_index).map_err(|e| {
                TreeError::Fork(crate::fork::ForkError::Reflink(format!(
                    "add_tap_at({}) on fc resume: {e}",
                    member_topo.vm_index
                )))
            })?;
            let member_dir = node_dir.join("members").join(i.to_string());
            let fc = crate::fc::FcVm::load_exported(&member_dir, Some(tap))
                .map_err(|e| TreeError::Firecracker(e.to_string()))?;
            members.push(Guest::from(fc));
        }
        self.live.insert(
            node_id.clone(),
            ClusterPayload {
                network: net,
                members,
            },
        );
        self.jail_payload(node_id)?;
        if let Some(info) = self.nodes.get_mut(node_id) {
            info.state = NodeState::Live;
            touch(info);
        }
        self.save_metadata()?;
        log::info!("cluster_tree: resumed Firecracker '{node_id}'");
        Ok(())
    }

    /// Permanently delete a node and all its descendants.
    pub fn prune(&mut self, node_id: &NodeId) -> Result<(), TreeError> {
        let mut queue = VecDeque::new();
        queue.push_back(node_id.clone());
        let mut subtree: Vec<NodeId> = Vec::new();
        while let Some(id) = queue.pop_front() {
            if !self.nodes.contains_key(&id) {
                continue;
            }
            subtree.push(id.clone());
            if let Some(info) = self.nodes.get(&id) {
                for c in &info.children {
                    queue.push_back(c.clone());
                }
            }
        }
        for id in subtree.into_iter().rev() {
            if let Some(payload) = self.live.remove(&id) {
                drop(payload);
            }
            self.pure_ids.remove(&id);
            self.cow_base.remove(&id);
            let _ = fs::remove_dir_all(self.node_dir(&id));
            if let Some(info) = self.nodes.remove(&id) {
                // Suspended nodes park their RW disk-clone dirs on the
                // record (see `suspend`); pruning must reap those too.
                for dir in &info.parked_disk_dirs {
                    let _ = fs::remove_dir_all(dir);
                }
                if let Some(parent_id) = info.parent {
                    if let Some(parent) = self.nodes.get_mut(&parent_id) {
                        parent.children.retain(|c| c != &id);
                    }
                }
            }
        }
        self.save_metadata()?;
        log::info!("cluster_tree: pruned '{node_id}'");
        Ok(())
    }

    /// Resource budget this tree was created with (or last `set_budget`).
    #[must_use]
    pub fn budget(&self) -> TreeBudget {
        self.budget
    }

    /// Update the resource budget.
    pub fn set_budget(&mut self, budget: TreeBudget) {
        self.budget = budget;
        let _ = self.save_metadata();
    }

    /// Get current resource usage.
    ///
    /// `live_vm_count` is the Σ of `vm_count` over Live nodes (so an
    /// N-VM cluster counts as N for `max_live_vms`); `live_node_count`
    /// is the count of Live nodes regardless of payload size.
    #[must_use]
    pub fn usage(&self) -> TreeUsage {
        let mut live_ram_bytes: u64 = 0;
        for payload in self.live.values() {
            live_ram_bytes = live_ram_bytes.saturating_add(payload.est_ram_bytes());
        }
        let mut disk_bytes: u64 = 0;
        for info in self.nodes.values() {
            let dir = self.node_dir(&info.id);
            let n = info.vm_count.max(1);
            // `base_disk_bytes` is the Σ over members of what the
            // keyframes physically cost — for reflinked members that is
            // far below their logical length, and `st_blocks` would
            // still report the shared extents.
            match info.base_disk_bytes {
                Some(recorded) => disk_bytes = disk_bytes.saturating_add(recorded),
                None => {
                    for i in 0..n {
                        let mem = dir.join("members").join(i.to_string()).join("memory.bin");
                        if let Ok(md) = fs::metadata(mem) {
                            disk_bytes = disk_bytes.saturating_add(md.len());
                        }
                    }
                }
            }
            for i in 0..n {
                let member = dir.join("members").join(i.to_string());
                if let Ok(md) = fs::metadata(member.join("delta.pack")) {
                    disk_bytes = disk_bytes.saturating_add(md.len());
                }
            }
            // cluster.json (negligible but counted).
            if let Ok(md) = fs::metadata(dir.join("cluster.json")) {
                disk_bytes = disk_bytes.saturating_add(md.len());
            }
        }
        let live_node_count = self.live.len();
        let live_vm_count: usize = self
            .live
            .keys()
            .filter_map(|id| self.nodes.get(id))
            .map(|n| n.vm_count as usize)
            .sum();
        TreeUsage {
            live_vm_count,
            live_ram_bytes,
            disk_bytes,
            total_nodes: self.nodes.len(),
            live_node_count,
        }
    }

    /// Tier-1 RAM eviction loop: make room for `incoming` new live VMs,
    /// exempting `source_id`.
    fn evict_for_incoming(&mut self, source_id: &NodeId, incoming: usize) -> Result<(), TreeError> {
        self.evict_for_incoming_inner(Some(source_id.as_str()), incoming)
    }

    fn evict_for_incoming_no_exempt(&mut self, incoming: usize) -> Result<(), TreeError> {
        self.evict_for_incoming_inner(None, incoming)
    }

    fn evict_for_incoming_inner(
        &mut self,
        exempt: Option<&str>,
        incoming: usize,
    ) -> Result<(), TreeError> {
        loop {
            let usage = self.usage();
            let projected_count = usage.live_vm_count.saturating_add(incoming);
            let over_count = projected_count > self.budget.max_live_vms;
            let over_ram = usage.live_ram_bytes > self.budget.ram_soft_limit();
            if !over_count && !over_ram {
                break;
            }
            let model = self.build_model()?;
            let mut exempt_pure: Vec<u64> = Vec::new();
            if let Some(ex) = exempt {
                exempt_pure.push(self.lookup_pure_id(&ex.to_string())?);
            }
            let victim = tree_model::lru_live_victim(&model, &exempt_pure);
            let Some(victim) = victim else {
                return Err(TreeError::BudgetExhausted {
                    reason: format!(
                        "cluster tree RAM budget: live_vm_count={}/{} ram={}B/{}B; \
                         all other live cluster nodes protected/exempt",
                        usage.live_vm_count,
                        self.budget.max_live_vms,
                        usage.live_ram_bytes,
                        self.budget.ram_soft_limit(),
                    ),
                });
            };
            let victim = self.node_id_for_pure(victim)?;
            self.suspend(&victim)?;
        }
        self.auto_evict_disk()?;
        Ok(())
    }

    fn evict_post_fork(&mut self, source_id: &NodeId, exempt: &[NodeId]) -> Result<(), TreeError> {
        loop {
            let usage = self.usage();
            let over_count = usage.live_vm_count > self.budget.max_live_vms;
            let over_ram = usage.live_ram_bytes > self.budget.ram_soft_limit();
            if !over_count && !over_ram {
                break;
            }
            let model = self.build_model()?;
            let mut exempt_pure: Vec<u64> = vec![self.lookup_pure_id(source_id)?];
            for ex in exempt {
                exempt_pure.push(self.lookup_pure_id(ex)?);
            }
            let victim = tree_model::lru_live_victim(&model, &exempt_pure);
            let Some(victim) = victim else {
                log::warn!(
                    "cluster_tree: post-fork eviction left {} live VMs (over budget {}); \
                     other live nodes protected/exempt",
                    usage.live_vm_count,
                    self.budget.max_live_vms,
                );
                break;
            };
            let victim = self.node_id_for_pure(victim)?;
            self.suspend(&victim)?;
        }
        Ok(())
    }

    /// Evict LRU suspended leaf subtrees until `incoming` more bytes of
    /// snapshot data fit `max_disk_bytes`. Fails loud (`BudgetExhausted`)
    /// when nothing is evictable — the caller must not write the file.
    fn evict_disk_for_incoming(&mut self, incoming: u64) -> Result<(), TreeError> {
        loop {
            let usage = self.usage();
            // Inline mirror of the verified predicate
            // `tree_model::over_disk_incoming` (the model view carries no
            // fs-derived `disk_bytes`, so the comparison runs on the
            // impure `usage()` — same convention as `over_count`).
            if usage.disk_bytes.saturating_add(incoming) <= self.budget.max_disk_bytes {
                return Ok(());
            }
            let model = self.build_model()?;
            let Some(victim) = tree_model::lru_evictable_leaf_subtree(&model) else {
                return Err(TreeError::BudgetExhausted {
                    reason: format!(
                        "cluster tree disk budget: need {incoming}B headroom for new base \
                         snapshots; {}B/{}B used, no evictable subtrees",
                        usage.disk_bytes, self.budget.max_disk_bytes,
                    ),
                });
            };
            let victim = self.node_id_for_pure(victim)?;
            self.evict_subtree(&victim)?;
        }
    }

    fn auto_evict_disk(&mut self) -> Result<Vec<NodeId>, TreeError> {
        let mut affected: Vec<NodeId> = Vec::new();
        loop {
            let usage = self.usage();
            if usage.disk_bytes <= self.budget.max_disk_bytes {
                break;
            }
            let model = self.build_model()?;
            let Some(victim) = tree_model::lru_evictable_leaf_subtree(&model) else {
                return Err(TreeError::BudgetExhausted {
                    reason: format!(
                        "cluster tree disk budget: {}B/{}B, no evictable subtrees",
                        usage.disk_bytes, self.budget.max_disk_bytes,
                    ),
                });
            };
            let victim = self.node_id_for_pure(victim)?;
            self.evict_subtree(&victim)?;
            affected.push(victim);
        }
        Ok(affected)
    }

    /// Enforce both RAM and disk budgets. Returns affected node ids.
    pub fn auto_evict(&mut self) -> Result<Vec<NodeId>, TreeError> {
        let mut affected: Vec<NodeId> = Vec::new();
        loop {
            let usage = self.usage();
            let over_count = usage.live_vm_count > self.budget.max_live_vms;
            let over_ram = usage.live_ram_bytes > self.budget.ram_soft_limit();
            if !over_count && !over_ram {
                break;
            }
            let model = self.build_model()?;
            let victim = tree_model::lru_live_victim(&model, &[]);
            let Some(victim) = victim else {
                return Err(TreeError::BudgetExhausted {
                    reason: format!(
                        "cluster tree RAM budget: live_vm_count={}/{} ram={}B/{}B, all live nodes protected",
                        usage.live_vm_count,
                        self.budget.max_live_vms,
                        usage.live_ram_bytes,
                        self.budget.ram_soft_limit(),
                    ),
                });
            };
            let victim = self.node_id_for_pure(victim)?;
            self.suspend(&victim)?;
            affected.push(victim);
        }
        affected.extend(self.auto_evict_disk()?);
        Ok(affected)
    }

    fn evict_subtree(&mut self, node_id: &NodeId) -> Result<(), TreeError> {
        let mut queue = VecDeque::new();
        queue.push_back(node_id.clone());
        let mut evicted: Vec<NodeId> = Vec::new();
        while let Some(id) = queue.pop_front() {
            if let Some(info) = self.nodes.get(&id) {
                for c in &info.children {
                    queue.push_back(c.clone());
                }
            }
            let dir = self.node_dir(&id);
            let n = self.nodes.get(&id).map_or(0, |n| n.vm_count);
            for i in 0..n {
                let member = dir.join("members").join(i.to_string());
                for f in [
                    "memory.bin",
                    "delta.pack",
                    "cpu.json",
                    "devices.json",
                    "irqchip.json",
                    "metadata.json",
                    "vm_state.json",
                ] {
                    let _ = fs::remove_file(member.join(f));
                }
                // Leftovers prune would have dropped with remove_dir_all of
                // the member dir: FC `vmstate` / `fc.json` / `disk-*`.
                reap_dir_contents(&member);
            }
            let _ = fs::remove_file(dir.join("cluster.json"));
            reap_dir_contents(&dir);
            if let Some(info) = self.nodes.get_mut(&id) {
                info.state = NodeState::Evicted;
                info.has_base_snapshot = false;
                // The keyframes are gone, so they cost nothing and name
                // no generation any pack may still claim.
                info.base_disk_bytes = None;
                info.base_identity = 0;
                // Suspend parks RW disk-clone dirs on the record (see
                // `suspend`); eviction must reap them the way prune does
                // or usage() reports the space free while XFS still holds
                // the clones (bug-candidates #52 / CHALLENGES #130).
                for parked in std::mem::take(&mut info.parked_disk_dirs) {
                    let _ = fs::remove_dir_all(&parked);
                }
                touch(info);
            }
            evicted.push(id);
        }
        self.save_metadata()?;
        log::info!(
            "cluster_tree: evicted subtree rooted at '{node_id}' ({} nodes)",
            evicted.len()
        );
        Ok(())
    }

    /// Get info about a single node.
    #[must_use]
    pub fn get_node(&self, node_id: &NodeId) -> Option<&NodeInfo> {
        self.nodes.get(node_id)
    }

    /// List all nodes in the tree.
    #[must_use]
    pub fn list_nodes(&self) -> Vec<&NodeInfo> {
        self.nodes.values().collect()
    }

    /// Shared reference to the live cluster payload for a node.
    #[must_use]
    pub fn get_payload(&self, node_id: &NodeId) -> Option<&ClusterPayload> {
        self.live.get(node_id)
    }

    /// Mutable reference to the live cluster payload for a node.
    pub fn get_payload_mut(&mut self, node_id: &NodeId) -> Option<&mut ClusterPayload> {
        if let Some(info) = self.nodes.get_mut(node_id) {
            touch(info);
        }
        self.live.get_mut(node_id)
    }

    /// Frontier (leaf nodes still live or suspended).
    #[must_use]
    pub fn frontier(&self) -> Vec<NodeId> {
        self.nodes
            .values()
            .filter(|n| {
                !matches!(n.state, NodeState::Evicted)
                    && n.children.iter().all(|c| {
                        self.nodes
                            .get(c)
                            .is_none_or(|cn| cn.state == NodeState::Evicted)
                    })
            })
            .map(|n| n.id.clone())
            .collect()
    }

    /// Path from a node to the root.
    #[must_use]
    pub fn path_to_root(&self, node_id: &NodeId) -> Vec<NodeId> {
        let mut path = Vec::new();
        let mut cur = Some(node_id.clone());
        while let Some(id) = cur {
            path.push(id.clone());
            cur = self.nodes.get(&id).and_then(|n| n.parent.clone());
        }
        path
    }

    /// Protect a node from auto-eviction.
    pub fn protect(&mut self, node_id: &NodeId) {
        if let Some(info) = self.nodes.get_mut(node_id) {
            info.protected = true;
            let _ = self.save_metadata();
        }
    }

    /// Remove eviction protection.
    pub fn unprotect(&mut self, node_id: &NodeId) {
        if let Some(info) = self.nodes.get_mut(node_id) {
            info.protected = false;
            let _ = self.save_metadata();
        }
    }

    /// Re-open a tree from disk. Restores `nodes` and `budget` from
    /// `tree.json`; live payloads are NOT restored — every node loaded
    /// back is in `Suspended` state until explicitly resumed.
    pub fn open(root_dir: PathBuf) -> Result<Self, TreeError> {
        let bytes = fs::read(root_dir.join("tree.json"))?;
        let mut doc: ClusterTreeDoc = serde_json::from_slice(&bytes)?;
        // Verify every node is a cluster payload — refuse to load a
        // single-VM tree.json as a cluster tree.
        for n in doc.nodes.values() {
            if n.kind != PayloadKind::Cluster {
                return Err(TreeError::BadState(
                    n.id.clone(),
                    n.state,
                    "open ClusterSnapshotTree: node has kind != Cluster",
                ));
            }
        }
        // Force every node we can't resurrect back to Suspended (the
        // payload is gone; whoever opens the tree must explicitly
        // `resume()` the nodes they want live).
        for info in doc.nodes.values_mut() {
            if info.state == NodeState::Live {
                info.state = NodeState::Suspended;
            }
        }
        // Mint future ids past the highest id we've seen.
        let next_id = doc
            .nodes
            .keys()
            .filter_map(|k| k.rsplit('-').next())
            .filter_map(|n| n.parse::<u64>().ok())
            .max()
            .map_or(0, |m| m + 1);
        // Rebuild the pure-id map parents-first so pure ids satisfy the
        // parent < child invariant the verified helpers' well-formedness
        // assumes (the map is not persisted in tree.json).
        let (pure_ids, next_pure_id) = rebuild_pure_ids(&doc.nodes);
        let jail = crate::cgroup::TreeCgroup::create(&doc.tree_id, doc.budget)?;
        let root_dir_for_probe = root_dir.clone();
        Ok(Self {
            tree_id: doc.tree_id,
            root_dir,
            budget: doc.budget,
            nodes: doc.nodes,
            live: HashMap::new(),
            created_at_unix: doc.created_at_unix,
            next_id,
            pure_ids,
            next_pure_id,
            // Nothing is live yet, so nothing maps a keyframe; `resume`
            // records the CoW base of each node it materializes.
            cow_base: HashMap::new(),
            reflink_root: crate::tree::probe_reflink_root(&root_dir_for_probe),
            jail,
            last_pause_skew_ns: None,
        })
    }

    // --- internals ---

    fn ensure_live(&mut self, node_id: &NodeId) -> Result<(), TreeError> {
        let state = self
            .nodes
            .get(node_id)
            .ok_or_else(|| TreeError::NodeNotFound(node_id.clone()))?
            .state;
        match state {
            NodeState::Live => Ok(()),
            NodeState::Suspended => {
                self.resume(node_id)?;
                Ok(())
            }
            NodeState::Evicted => Err(TreeError::BadState(
                node_id.clone(),
                state,
                "fork (Evicted nodes cannot be re-materialized)",
            )),
        }
    }

    /// Unprepared hops between `node_id` (inclusive) and its nearest
    /// `has_base_snapshot` ancestor. Resume applies **one** pack per
    /// member onto that ancestor; hop-count is not a
    /// correctness cap. 0 for a checkpoint. Not tree-graph depth.
    ///
    /// The walk itself is the verified pure function
    /// [`tree_model::restore_chain_depth`]; this wrapper only
    /// builds the model view and maps `None` (no checkpoint ancestor —
    /// corrupt tree metadata) to a loud error.
    fn restore_chain_depth(&mut self, node_id: &NodeId) -> Result<usize, TreeError> {
        let model = self.build_model()?;
        let pure = self.lookup_pure_id(node_id)?;
        tree_model::restore_chain_depth(&model, pure).ok_or_else(|| {
            TreeError::InvalidDelta(format!(
                "node {node_id} has no checkpoint ancestor \
                 (no has_base_snapshot on its root path)"
            ))
        })
    }

    fn nearest_checkpoint(&self, node_id: &NodeId) -> Result<NodeId, TreeError> {
        let mut cur: Option<NodeId> = Some(node_id.clone());
        while let Some(id) = cur.as_ref() {
            if let Some(info) = self.nodes.get(id) {
                if info.has_base_snapshot {
                    return Ok(id.clone());
                }
                let parent = info.parent.clone();
                cur = parent;
            } else {
                break;
            }
        }
        Err(TreeError::NodeNotFound(format!(
            "no checkpoint ancestor of '{node_id}'"
        )))
    }

    fn mint_id(&mut self, label: &str) -> NodeId {
        let n = self.next_id;
        self.next_id += 1;
        let safe: String = label
            .chars()
            .map(|c| {
                if c.is_ascii_alphanumeric() || c == '-' || c == '_' {
                    c
                } else {
                    '-'
                }
            })
            .collect();
        format!("{safe}-{n:04}")
    }

    fn node_dir(&self, id: &NodeId) -> PathBuf {
        self.root_dir.join("nodes").join(id)
    }

    /// Mint (or return) the pure-model id for a node — the
    /// orchestrator `String → u64` map. Minting is monotonic, so children
    /// (created after their parents) always get larger pure ids.
    fn mint_pure_id(&mut self, id: &NodeId) -> u64 {
        if let Some(v) = self.pure_ids.get(id) {
            return *v;
        }
        let v = self.next_pure_id;
        self.next_pure_id += 1;
        self.pure_ids.insert(id.clone(), v);
        v
    }

    /// Pure-model id for a node; errors loudly if the map has no entry
    /// (an invariant violation — ids are minted at node creation).
    fn lookup_pure_id(&self, id: &NodeId) -> Result<u64, TreeError> {
        self.pure_ids
            .get(id)
            .copied()
            .ok_or_else(|| TreeError::NodeNotFound(format!("pure id for '{id}'")))
    }

    /// Reverse lookup: the `String` node id for a pure-model id.
    fn node_id_for_pure(&self, pure: u64) -> Result<NodeId, TreeError> {
        for (k, v) in &self.pure_ids {
            if *v == pure {
                return Ok(k.clone());
            }
        }
        Err(TreeError::NodeNotFound(format!("pure id {pure}")))
    }

    /// Derive the pure [`tree_model::TreeModel`] view of this tree for
    /// the verified eviction helpers. Mirrors
    /// `SnapshotTree::build_model`; `est_ram_bytes` is the Σ over live
    /// cluster members, `disk_bytes` stays 0 (the victim pickers never
    /// read it — the disk-budget check is `fs`-based in the orchestrator).
    fn build_model(&mut self) -> Result<tree_model::TreeModel, TreeError> {
        let ids: Vec<NodeId> = self.nodes.keys().cloned().collect();
        for id in &ids {
            self.mint_pure_id(id);
        }
        let mut nodes = Vec::with_capacity(self.nodes.len());
        for info in self.nodes.values() {
            let mut children = Vec::with_capacity(info.children.len());
            for c in &info.children {
                children.push(self.lookup_pure_id(c)?);
            }
            let parent = match &info.parent {
                Some(p) => Some(self.lookup_pure_id(p)?),
                None => None,
            };
            let est_ram_bytes = self
                .live
                .get(&info.id)
                .map_or(0, ClusterPayload::est_ram_bytes);
            nodes.push(tree_model::NodeInfo {
                id: self.lookup_pure_id(&info.id)?,
                parent,
                children,
                state: info.state,
                kind: info.kind,
                vm_count: info.vm_count,
                dirty_pages: info.dirty_page_count,
                has_base_snapshot: info.has_base_snapshot,
                last_active: info.last_active_at_unix,
                protected: info.protected,
                est_ram_bytes,
                disk_bytes: 0,
            });
        }
        Ok(tree_model::TreeModel {
            nodes,
            budget: self.budget,
        })
    }

    fn save_metadata(&self) -> Result<(), TreeError> {
        let doc = ClusterTreeDoc {
            tree_id: self.tree_id.clone(),
            created_at_unix: self.created_at_unix,
            budget: self.budget,
            nodes: self.nodes.clone(),
        };
        let json = serde_json::to_vec_pretty(&doc)?;
        atomic_write(&self.root_dir.join("tree.json"), &json)?;
        Ok(())
    }
}

impl Drop for ClusterSnapshotTree {
    fn drop(&mut self) {
        // Drop live payloads explicitly first (frees RAM, closes KVM
        // fds, tears down bridges); the root_dir is left on disk by
        // default (callers prune() to delete).
        self.live.clear();
    }
}

/// Stamp `last_active_at_unix` on a node from the wall clock.
fn touch(info: &mut NodeInfo) {
    info.set_last_active(now_unix());
}

fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap_or(Duration::from_secs(0))
        .as_secs()
}

/// Rebuild the `String → u64` pure-id map for a tree loaded from disk,
/// assigning ids parents-first (every child's pure id is strictly greater
/// than its parent's — the `parentLt` well-formedness invariant of the
/// verified helpers). Nodes whose parent chain is broken (malformed doc)
/// are assigned ids last, in sorted order, so the map is still total.
fn rebuild_pure_ids(nodes: &HashMap<NodeId, NodeInfo>) -> (HashMap<NodeId, u64>, u64) {
    let mut pure_ids: HashMap<NodeId, u64> = HashMap::new();
    let mut next: u64 = 0;
    let mut keys: Vec<&NodeId> = nodes.keys().collect();
    keys.sort();
    loop {
        let mut assigned = false;
        for k in &keys {
            if pure_ids.contains_key(*k) {
                continue;
            }
            let parent_assigned = nodes[*k]
                .parent
                .as_ref()
                .is_none_or(|p| pure_ids.contains_key(p));
            if parent_assigned {
                pure_ids.insert((*k).clone(), next);
                next += 1;
                assigned = true;
            }
        }
        if !assigned {
            break;
        }
    }
    // Leftovers (dangling parents): assign arbitrarily but deterministically.
    for k in &keys {
        if !pure_ids.contains_key(*k) {
            pure_ids.insert((*k).clone(), next);
            next += 1;
        }
    }
    (pure_ids, next)
}

fn topology_from_network(net: &ClusterNetwork) -> ClusterTopology {
    let mut entries: Vec<&crate::network::VmNetworkEntry> = net.entries().collect();
    entries.sort_by_key(|e| e.vm_index);
    let members: Vec<ClusterTopologyMember> = entries
        .into_iter()
        .map(|e| ClusterTopologyMember {
            vm_index: e.vm_index,
            guest_ip: e.guest_ip,
            guest_mac: e.guest_mac,
        })
        .collect();
    ClusterTopology {
        cluster_version: 1,
        subnet_base: net.subnet_base().octets(),
        members,
        egress: net.egress().clone(),
    }
}

fn write_cluster_topology(path: &Path, topology: &ClusterTopology) -> Result<(), TreeError> {
    let json = serde_json::to_vec_pretty(topology)?;
    atomic_write(path, &json)
        .map_err(|e| TreeError::Io(std::io::Error::new(std::io::ErrorKind::Other, e)))?;
    Ok(())
}

fn read_cluster_topology(path: &Path) -> Result<ClusterTopology, TreeError> {
    let bytes = fs::read(path)?;
    let topo: ClusterTopology = serde_json::from_slice(&bytes)?;
    Ok(topo)
}

/// Atomic write: write to `path.tmp` + rename.
///
/// No `fsync`. These files are tiny JSON (`tree.json`, `cluster.json`,
/// `vm_state.json`). `sync_all` on a dirty XFS journal after a long
/// `make check` waits for *other* writeback and has been measured at
/// ~1 s per call — enough to miss `FORK_INNER_K3S_CLUSTER_3VM` after
/// a CoW-green warm fork (CHALLENGES #162). Rename is still atomic for
/// readers. A daemon crash drops the live VMs anyway; the next open
/// rebuilds from whatever `tree.json` last landed.
fn atomic_write(path: &Path, data: &[u8]) -> std::io::Result<()> {
    let tmp = path.with_extension("tmp");
    {
        let mut f = fs::File::create(&tmp)?;
        f.write_all(data)?;
    }
    fs::rename(&tmp, path)?;
    Ok(())
}
