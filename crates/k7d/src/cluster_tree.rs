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
use std::time::{Duration, SystemTime};

use serde::{Deserialize, Serialize};

use crate::network::ClusterNetwork;
use crate::snapshot::{self, VmState};
use crate::tree::{apply_delta, write_delta, NodeId, NodeInfo, TreeError};
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
    pub members: Vec<Vm>,
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
        self.members
            .iter()
            .map(|vm| {
                vm.accumulated_dirty_pages()
                    .unwrap_or(0)
                    .saturating_mul(4096)
            })
            .sum()
    }
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
}

impl ClusterSnapshotTree {
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

        fs::create_dir_all(root_dir.join("nodes"))?;
        let tree_id = format!("ctree-{}", std::process::id());
        let now = now_unix();

        let root_id: NodeId = "root".to_string();
        let root_node_dir = root_dir.join("nodes").join(&root_id);
        fs::create_dir_all(&root_node_dir)?;
        fs::write(root_node_dir.join("kind"), b"cluster")?;

        let mut root = root;

        // Prepare every member as a warm-fork source. After this, each
        // member has its own base.mem + cpu.json under members/{i}/.
        for (i, vm) in root.members.iter_mut().enumerate() {
            let member_dir = root_node_dir.join("members").join(i.to_string());
            fs::create_dir_all(&member_dir)?;
            // Cluster adoption knowingly accepts full-memfd
            // forks for virtiofs-backed members — the explicit slow-fork
            // opt-in requires (loud warn per member).
            if !vm.virtiofs_shares().is_empty() {
                vm.allow_slow_fork();
            }
            vm.prepare_fork_source_in(&member_dir)?;
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
        };

        let mut nodes = HashMap::new();
        nodes.insert(root_id.clone(), info);
        let mut live = HashMap::new();
        live.insert(root_id.clone(), root);

        let mut pure_ids = HashMap::new();
        pure_ids.insert(root_id.clone(), 0);

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
        };
        tree.save_metadata()?;
        Ok((tree, root_id))
    }

    /// Find a live member VM by guest CID (debug introspection:
    /// `dump_serial` reads the guest console of cluster members, which
    /// carry no daemon `vm_id`). Returns the owning node id alongside
    /// the VM.
    #[must_use]
    pub fn find_live_vm_by_cid(&self, cid: u64) -> Option<(&str, &Vm)> {
        for (node_id, payload) in &self.live {
            if let Some(vm) = payload.members.iter().find(|vm| vm.guest_cid() == cid) {
                return Some((node_id.as_str(), vm));
            }
        }
        None
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
        let ids = self.fork_batch(source_id, &[label])?;
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
    ) -> Result<Vec<NodeId>, TreeError> {
        if labels.is_empty() {
            return Err(TreeError::InvalidDelta(
                "ClusterSnapshotTree::fork_batch: labels must be non-empty".into(),
            ));
        }
        self.ensure_live(source_id)?;
        self.auto_evict_if_over(source_id)?;
        self.ensure_live(source_id)?;

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
            })
            .collect();

        let mut sources_view: Vec<(&mut Vm, u32)> = source
            .members
            .iter_mut()
            .enumerate()
            .map(|(i, v)| (v, u32::try_from(i).unwrap_or(u32::MAX)))
            .collect();

        let result =
            crate::fork::fork_cluster_warm_batch(&source.network, &mut sources_view, &requests);
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
        let source_bitmaps: Vec<Vec<u64>> = source
            .members
            .iter()
            .map(|vm| vm.accumulated_dirty_bitmap().unwrap_or_default())
            .collect();
        // Hand the source back before starting forks so a later `start`
        // failure cannot strand the live map without the root cluster.
        self.live.insert(source_id.clone(), source);

        let now = now_unix();
        for (((fork_net, fork_vms), new_id), label) in
            forked.into_iter().zip(new_ids.iter()).zip(labels.iter())
        {
            let mut fork_payload = ClusterPayload {
                network: fork_net,
                members: fork_vms,
            };
            for (i, vm) in fork_payload.members.iter_mut().enumerate() {
                vm.start()?;
                vm.enable_dirty_tracking()?;
                if let Some(seed) = source_bitmaps.get(i) {
                    vm.seed_accumulated_dirty(seed)?;
                }
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
            };
            self.nodes.insert(new_id.clone(), info);
            self.live.insert(new_id.clone(), fork_payload);
            if let Some(src_info) = self.nodes.get_mut(source_id) {
                src_info.children.push(new_id.clone());
                touch(src_info);
            }
        }

        self.save_metadata()?;
        self.evict_post_fork(source_id, &new_ids)?;
        Ok(new_ids)
    }

    /// Suspend a live cluster: per-member delta + state captured, bridge
    /// torn down, RAM freed.
    ///
    /// Fails loud for virtiofs-backed members: virtiofsd writes FUSE
    /// completions through its own mapping, invisible to KVM dirty
    /// tracking, so `delta.pack` would silently miss device DMA and the
    /// resumed guest would corrupt (limitation).
    pub fn suspend(&mut self, node_id: &NodeId) -> Result<(), TreeError> {
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
        let parent_short = cluster_node_parent(&self.nodes, node_id).unwrap_or_default();
        for (i, vm) in payload.members.iter_mut().enumerate() {
            let member_dir = node_dir.join("members").join(i.to_string());
            fs::create_dir_all(&member_dir)?;

            vm.pause()?;
            let bitmap = vm.get_and_accumulate_dirty()?.to_vec();
            let state = snapshot::capture_vm_state(vm)?;
            let src_mem = vm.mem_host_addr();
            // Deltas index pages of the guest physical span, not of RAM (19a).
            let mem_size = vm.mem_span();

            let dirty_pages = write_delta(
                &member_dir.join("delta.pack"),
                &bitmap,
                src_mem,
                mem_size,
                parent_short.clone(),
            )?;
            let state_json = serde_json::to_string(&state)?;
            atomic_write(&member_dir.join("vm_state.json"), state_json.as_bytes())?;
            total_dirty = total_dirty.saturating_add(dirty_pages);
        }

        // Write cluster.json so resume can rebuild the bridge.
        let topology = topology_from_network(&payload.network);
        write_cluster_topology(&node_dir.join("cluster.json"), &topology)?;

        // Drop the payload — Vm::Drop closes KVM fds + munmaps memory;
        // ClusterNetwork::Drop tears down the bridge + iptables rules.
        drop(payload);

        if let Some(info) = self.nodes.get_mut(node_id) {
            info.state = NodeState::Suspended;
            info.dirty_page_count = total_dirty;
            touch(info);
        }
        self.save_metadata()?;
        log::info!(
            "cluster_tree: suspended '{node_id}' ({total_dirty} dirty pages across members)"
        );
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

        // Reserve headroom for the cluster we're about to bring back to Live.
        self.evict_for_incoming_no_exempt(vm_count_for_node as usize)?;

        // Read cluster.json to learn the bridge topology.
        let node_dir = self.node_dir(node_id);
        let topology = read_cluster_topology(&node_dir.join("cluster.json"))?;

        // Recreate the bridge with the recorded subnet + per-VM identity.
        let bridge_label = format!("{}-{}", self.tree_id, node_id);
        let mut net = ClusterNetwork::create(&bridge_label).map_err(|e| {
            TreeError::Fork(crate::fork::ForkError::Reflink(format!(
                "ClusterNetwork::create resume: {e}"
            )))
        })?;

        // Find the nearest checkpoint ancestor for each member.
        let base_node = self.nearest_checkpoint(node_id)?;
        let base_dir = self.node_dir(&base_node);

        let n = topology.members.len();
        let mut members: Vec<Vm> = Vec::with_capacity(n);
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

            let state_json = fs::read_to_string(member_dir.join("vm_state.json"))?;
            let state: VmState = serde_json::from_str(&state_json)?;

            let mem_span = crate::mem_layout::MemLayout::from_ram(state.memory_size).span();
            let fork_mem_addr = crate::fork::mmap_base_mem_private(&base_mem_path, mem_span)?;

            if base_node != *node_id {
                apply_delta(&member_dir.join("delta.pack"), fork_mem_addr, mem_span)?;
            }

            let mut vm = crate::fork::build_vm_from_state_and_mem(
                &state,
                fork_mem_addr,
                &format!("resume:{node_id}/{i}"),
            )?;
            vm.start()?;
            vm.enable_dirty_tracking()?;
            members.push(vm);
        }

        let payload = ClusterPayload {
            network: net,
            members,
        };
        self.live.insert(node_id.clone(), payload);
        if let Some(info) = self.nodes.get_mut(node_id) {
            info.state = NodeState::Live;
            touch(info);
        }
        self.save_metadata()?;
        log::info!("cluster_tree: resumed '{node_id}'");
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
            let _ = fs::remove_dir_all(self.node_dir(&id));
            if let Some(info) = self.nodes.remove(&id) {
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
            for i in 0..n {
                let member = dir.join("members").join(i.to_string());
                for file in ["memory.bin", "delta.pack"] {
                    if let Ok(md) = fs::metadata(member.join(file)) {
                        disk_bytes = disk_bytes.saturating_add(md.len());
                    }
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

    /// Tier-1 RAM eviction loop, exempting `source_id`.
    fn auto_evict_if_over(&mut self, source_id: &NodeId) -> Result<(), TreeError> {
        self.evict_for_incoming_inner(Some(source_id.as_str()), 0)
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
            }
            let _ = fs::remove_file(dir.join("cluster.json"));
            if let Some(info) = self.nodes.get_mut(&id) {
                info.state = NodeState::Evicted;
                info.has_base_snapshot = false;
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

fn cluster_node_parent(nodes: &HashMap<NodeId, NodeInfo>, id: &NodeId) -> Option<String> {
    nodes
        .get(id)
        .and_then(|n| n.parent.clone())
        .map(|p| p.chars().take(16).collect())
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

fn atomic_write(path: &Path, data: &[u8]) -> std::io::Result<()> {
    let tmp = path.with_extension("tmp");
    {
        let mut f = fs::File::create(&tmp)?;
        f.write_all(data)?;
        f.sync_all()?;
    }
    fs::rename(&tmp, path)?;
    Ok(())
}
