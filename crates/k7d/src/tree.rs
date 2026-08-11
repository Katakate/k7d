//! Snapshot tree for tree-shaped VM exploration.
//!
//! A `SnapshotTree` is a DAG of VM states (Live / Suspended / Evicted) with
//! resource budgets and LRU-based auto-eviction. It is designed as
//! infrastructure for an external AI agent managing RL branch exploration —
//! k7d tracks the VM lifecycle; the AI agent tracks its own rewards, actions,
//! and observations keyed by `node_id`.
//!
//! ## On-disk layout
//!
//! ```text
//! {tree_root}/
//! ├── tree.json                      # DAG structure, node metadata
//! └── nodes/
//!     ├── {node_id}/
//!     │   ├── memory.bin             # full snapshot (only for checkpoint nodes)
//!     │   ├── delta.pack             # packed dirty pages relative to parent's memory.bin
//!     │   ├── vm_state.json          # serialized VmState (CPU + IRQ chip + devices)
//!     │   ├── cpu.json               # snapshot CpuState (written by snapshot_vm; checkpoint only)
//!     │   ├── devices.json           # MMIO device states (checkpoint only)
//!     │   ├── irqchip.json           # IRQ chip state (checkpoint only)
//!     │   └── metadata.json          # VM metadata (checkpoint only)
//! ```
//!
//! Suspended non-checkpoint nodes only have `vm_state.json` + `delta.pack`.
//! Checkpoint nodes also carry the full cold-snapshot file set because they
//! are produced by `Vm::prepare_fork_source_in`.
//!
//! ## Delta format (`delta.pack`)
//!
//! ```text
//! Header (28 bytes):
//!   magic:        [u8; 4]   = b"K7DL"
//!   version:      u32       = 1
//!   page_count:   u32
//!   mem_size:     u64
//!   reserved:     u64
//!
//! Entries (page_count times, each 4 + 4096 = 4100 bytes):
//!   page_index: u32         # byte offset = page_index * 4096
//!   data:       [u8; 4096]  # page contents
//! ```

use std::collections::{HashMap, VecDeque};
use std::fs;
use std::io::{BufWriter, Read, Write};
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};

use serde::{Deserialize, Serialize};

use crate::snapshot::{self, VmState};
use crate::tree_model::{
    self, k7dl_encode_entry, k7dl_header_bytes, k7dl_parse_entry, k7dl_parse_header, DeltaError,
    K7DL_ENTRY_SIZE, K7DL_HEADER_SIZE,
};
use crate::vm::{Vm, VmError};

// Re-export the pure model types so external callers (tests, other crates)
// keep using `k7d::tree::{NodeState, TreeBudget, TreeUsage, ...}` after the
// refactor with no source-level changes. `NodeId` / `NodeInfo` are the
// orchestrator-side (String-keyed, serde) types defined below — since spec
// 9g's pure-model rewrite, `tree_model::NodeInfo` is the `u64`-keyed pure
// twin used by the verified eviction helpers.
pub use crate::tree_model::{NodeState, PayloadKind, TreeBudget, TreeUsage};

/// Unique identifier for a tree node (filesystem-safe string).
pub type NodeId = String;

/// Orchestrator-side metadata about a tree node, as persisted in
/// `tree.json` and returned over the control socket.
///
/// This is the `String`-keyed twin of the pure [`tree_model::NodeInfo`]:
/// the orchestrator maintains a `String → u64` id map and derives the pure
/// model from these records at every eviction decision point (see
/// [`SnapshotTree::build_model`]). The `kind` and `vm_count` fields were
/// added in internal notes� older `tree.json` files (no `kind`/`vm_count`) load
/// as a single-VM payload via the `serde(default)` attributes.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NodeInfo {
    pub id: NodeId,
    pub parent: Option<NodeId>,
    pub children: Vec<NodeId>,
    pub state: NodeState,
    /// Number of dirty pages this node's delta captures (0 for root/checkpoints).
    /// For a cluster payload this is the Σ over members.
    pub dirty_page_count: u32,
    /// Whether this node has its own `base.mem` (checkpoint / fork-point).
    /// For a cluster payload, every member's `members/{i}/memory.bin`
    /// exists if and only if `has_base_snapshot` is true.
    pub has_base_snapshot: bool,
    pub label: String,
    /// Wall-clock creation time (`UNIX_EPOCH` offset, seconds).
    pub created_at_unix: u64,
    /// Wall-clock time of most recent activity (`UNIX_EPOCH` offset, seconds).
    pub last_active_at_unix: u64,
    /// Whether this node is excluded from auto-eviction.
    pub protected: bool,
    /// internal notes: payload kind (Vm or Cluster). Defaults to Vm so pre-9g
    /// `tree.json` files load unchanged.
    #[serde(default)]
    pub kind: PayloadKind,
    /// internal notes: number of *underlying* VMs this payload represents.
    /// 1 for a single-VM payload; N for a cluster of N members.
    /// Defaults to 1 so pre-9g `tree.json` files load unchanged.
    #[serde(default = "default_vm_count")]
    pub vm_count: u32,
}

fn default_vm_count() -> u32 {
    1
}

impl NodeInfo {
    /// Update `last_active_at_unix` to the orchestrator-supplied `now`.
    pub fn set_last_active(&mut self, now: u64) {
        self.last_active_at_unix = now;
    }
}

/// Errors from tree operations.
#[derive(Debug, thiserror::Error)]
pub enum TreeError {
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),
    #[error("VM error: {0}")]
    Vm(#[from] VmError),
    #[error("snapshot error: {0}")]
    Snapshot(#[from] snapshot::SnapshotError),
    #[error("fork error: {0}")]
    Fork(#[from] crate::fork::ForkError),
    #[error("restore error: {0}")]
    Restore(#[from] crate::fork::RestoreError),
    #[error("node not found: {0}")]
    NodeNotFound(String),
    #[error("node {0} is in state {1:?}, cannot {2}")]
    BadState(NodeId, NodeState, &'static str),
    #[error("budget exhausted ({reason}); all candidate nodes are protected")]
    BudgetExhausted { reason: String },
    #[error("invalid delta file: {0}")]
    InvalidDelta(String),
}

impl From<DeltaError> for TreeError {
    fn from(e: DeltaError) -> Self {
        TreeError::InvalidDelta(e.to_string())
    }
}

/// Stamp `last_active_at_unix` on a node from the wall clock.
///
/// Wraps the pure [`NodeInfo::set_last_active`] with a `SystemTime` read so
/// the time-source impurity stays in `tree.rs` (out of the Aeneas surface).
fn touch(info: &mut NodeInfo) {
    info.set_last_active(now_unix());
}

/// Persistent tree document written atomically to `tree.json`.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct TreeDoc {
    tree_id: String,
    created_at_unix: u64,
    budget: TreeBudget,
    nodes: HashMap<NodeId, NodeInfo>,
}

/// Snapshot tree: a DAG of VM states with budget-driven LRU auto-eviction.
pub struct SnapshotTree {
    tree_id: String,
    root_dir: PathBuf,
    budget: TreeBudget,
    nodes: HashMap<NodeId, NodeInfo>,
    /// Live VMs owned by the tree, keyed by node id.
    live_vms: HashMap<NodeId, Vm>,
    created_at_unix: u64,
    next_id: u64,
    /// internal notes: orchestrator `String → u64` id map into the pure model.
    /// Ids are minted monotonically at node creation, so a child's pure id
    /// is always greater than its parent's (the `parentLt` invariant the
    /// Lean proofs' `well_formed` relies on). Not persisted — rebuilt from
    /// scratch when a tree is reconstructed.
    pure_ids: HashMap<NodeId, u64>,
    next_pure_id: u64,
}

impl SnapshotTree {
    /// Create a new tree rooted at a running VM.
    ///
    /// The root VM is prepared as a fork source (cold snapshot + restore +
    /// dirty tracking). The returned root `NodeId` is a checkpoint (owns a
    /// `base.mem`) and starts in state `Live`.
    pub fn new(
        mut root_vm: Vm,
        root_dir: PathBuf,
        budget: TreeBudget,
    ) -> Result<(Self, NodeId), TreeError> {
        fs::create_dir_all(root_dir.join("nodes"))?;
        let tree_id = format!("tree-{}", std::process::id());
        let now = now_unix();

        // Give the root node a predictable id and its own directory.
        let root_id: NodeId = "root".to_string();
        let root_node_dir = root_dir.join("nodes").join(&root_id);
        fs::create_dir_all(&root_node_dir)?;

        // Prepare the VM as a fork source into the node's directory. This
        // writes base.mem, cpu.json, devices.json, metadata.json, irqchip.json
        // into `root_node_dir` and restores the VM from them.
        //
        // Tree roots with virtiofs shares knowingly take the slow
        // (full-memfd) fork path — the explicit opt-in internal notes
        // requires (loud warn inside `allow_slow_fork`).
        if !root_vm.virtiofs_shares().is_empty() {
            root_vm.allow_slow_fork();
        }
        root_vm.prepare_fork_source_in(&root_node_dir)?;

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
            kind: PayloadKind::Vm,
            vm_count: 1,
        };

        let mut nodes = HashMap::new();
        nodes.insert(root_id.clone(), info);

        let mut live_vms = HashMap::new();
        live_vms.insert(root_id.clone(), root_vm);

        let mut pure_ids = HashMap::new();
        pure_ids.insert(root_id.clone(), 0);

        let tree = Self {
            tree_id,
            root_dir,
            budget,
            nodes,
            live_vms,
            created_at_unix: now,
            next_id: 0,
            pure_ids,
            next_pure_id: 1,
        };
        tree.save_metadata()?;
        Ok((tree, root_id))
    }

    fn mint_id(&mut self, label: &str) -> NodeId {
        let n = self.next_id;
        self.next_id += 1;
        // Keep ids filesystem-safe: strip anything that's not alnum/dash.
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

    /// Mint (or return) the pure-model id for a node — the internal notes
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

    /// Derive the pure [`tree_model::TreeModel`] view of this tree (spec
    /// 9g). The verified eviction helpers (`tree_model::lru_live_victim`,
    /// `tree_model::lru_evictable_leaf_subtree`,
    /// `tree_model::implicitly_protected`) run on this view; the winning
    /// pure id is mapped back via [`Self::node_id_for_pure`].
    ///
    /// `est_ram_bytes` carries the same live-VM estimate the orchestrator's
    /// [`Self::usage`] uses; `disk_bytes` is left 0 because the victim
    /// pickers never read it (the disk-budget check stays `fs`-based in the
    /// orchestrator loop).
    fn build_model(&mut self) -> Result<tree_model::TreeModel, TreeError> {
        // Mint any missing pure ids first (normally a no-op).
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
            let est_ram_bytes = self.live_vms.get(&info.id).map_or(0, estimate_vm_ram);
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

    /// Find a live VM by guest CID (debug introspection: `dump_serial`
    /// reads the guest console of tree members, which carry no daemon
    /// `vm_id`). Returns the owning node id alongside the VM.
    #[must_use]
    pub fn find_live_vm_by_cid(&self, cid: u64) -> Option<(&str, &Vm)> {
        self.live_vms
            .iter()
            .find(|(_, vm)| vm.guest_cid() == cid)
            .map(|(id, vm)| (id.as_str(), vm))
    }

    /// Fork a new branch from any live or suspended node.
    pub fn fork(&mut self, source_id: &NodeId, label: &str) -> Result<NodeId, TreeError> {
        let ids = self.fork_batch(source_id, &[label])?;
        Ok(ids.into_iter().next().expect("single fork"))
    }

    /// Fork N branches from the same source (batch optimization).
    pub fn fork_batch(
        &mut self,
        source_id: &NodeId,
        labels: &[&str],
    ) -> Result<Vec<NodeId>, TreeError> {
        self.ensure_live(source_id)?;
        // Proactively reclaim RAM if we're ALREADY over budget. The fork will
        // add `labels.len()` more live VMs, but per internal notes
        // when a budget is _exceeded_ — we allow the fork to temporarily push
        // us over; the next auto_evict call (or the post-fork eviction below)
        // cleans up.
        self.auto_evict_if_over(source_id)?;
        // auto_evict_if_over may have suspended/resumed things; re-verify.
        self.ensure_live(source_id)?;

        let source_vm = self
            .live_vms
            .get_mut(source_id)
            .ok_or_else(|| TreeError::NodeNotFound(source_id.clone()))?;
        let forks = source_vm.fork_warm_batch(labels)?;
        // Snapshot the source's accumulated dirty bitmap AFTER fork_warm_batch
        // returns (it was updated in place during the fork). The children
        // must seed their own bitmaps with this, otherwise their delta on
        // suspend won't cover pages the source had dirtied before the fork
        // (which were memcpy'd into the child's CoW mapping at fork time).
        let source_bitmap_at_fork = source_vm.accumulated_dirty_bitmap().unwrap_or_default();

        let mut new_ids = Vec::with_capacity(forks.len());
        let now = now_unix();
        for (fork_vm, label) in forks.into_iter().zip(labels.iter()) {
            let new_id = self.mint_id(label);
            self.mint_pure_id(&new_id);
            fs::create_dir_all(self.node_dir(&new_id))?;

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
                kind: PayloadKind::Vm,
                vm_count: 1,
            };

            // Start the fork's vCPU; the tree owns it from here.
            let mut fork_vm = fork_vm;
            fork_vm.start()?;
            fork_vm.enable_dirty_tracking()?;
            // Seed the fork's accumulated bitmap with the source's bitmap
            // at fork time — see comment above on the source.
            fork_vm.seed_accumulated_dirty(&source_bitmap_at_fork)?;

            self.nodes.insert(new_id.clone(), info);
            self.live_vms.insert(new_id.clone(), fork_vm);
            if let Some(src) = self.nodes.get_mut(source_id) {
                src.children.push(new_id.clone());
                touch(src);
            }
            new_ids.push(new_id);
        }
        self.save_metadata()?;

        // Post-fork eviction: now that the fresh forks are Live, we may be
        // over the RAM budget. Suspend LRU non-protected live VMs (excluding
        // the source and the brand-new forks so the caller can immediately
        // interact with their VMs; eviction picks older siblings instead).
        let new_live: Vec<NodeId> = new_ids.clone();
        self.evict_post_fork(source_id, &new_live)?;

        Ok(new_ids)
    }

    /// Suspend LRU non-protected live VMs until the RAM budget is satisfied,
    /// excluding `source_id` and all `exempt` ids. Called after a fork adds
    /// new Live VMs; the new forks aren't auto-suspended immediately.
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
                // Nothing else to evict; the fresh forks remain live and we
                // tolerate exceeding the budget until the next auto_evict
                // call with broader eligibility (caller can retry or prune).
                log::warn!(
                    "tree: post-fork eviction left {} live VMs (over budget {}); \
                     all other live nodes are protected/exempt",
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

    /// Non-destructive rollback: create a new branch from `node_id`'s state.
    /// Equivalent to `fork` semantically (the original node is untouched).
    pub fn rollback(&mut self, node_id: &NodeId, label: &str) -> Result<NodeId, TreeError> {
        self.fork(node_id, label)
    }

    /// Suspend a live VM: save dirty delta + CPU state to disk, free RAM.
    ///
    /// Fails loud for virtiofs-backed VMs: virtiofsd writes FUSE
    /// completions through its own mapping, invisible to KVM dirty
    /// tracking, so `delta.pack` would silently miss device DMA and the
    /// resumed guest would corrupt.
    pub fn suspend(&mut self, node_id: &NodeId) -> Result<(), TreeError> {
        if let Some(vm) = self.live_vms.get(node_id) {
            if !vm.virtiofs_shares().is_empty() {
                return Err(TreeError::InvalidDelta(format!(
                    "suspend({node_id}): virtiofs-backed VMs cannot be suspended — \
                     virtiofsd DMA bypasses KVM dirty tracking, so the delta would be \
                     incomplete"
                )));
            }
        }
        let mut vm = self
            .live_vms
            .remove(node_id)
            .ok_or_else(|| TreeError::NodeNotFound(node_id.clone()))?;

        let node_dir = self.node_dir(node_id);
        fs::create_dir_all(&node_dir)?;

        // Pause, capture dirty bitmap + state.
        vm.pause()?;
        let bitmap = vm.get_and_accumulate_dirty()?.to_vec();
        let state = snapshot::capture_vm_state(&vm)?;
        let src_mem = vm.mem_host_addr();
        let mem_size = vm.memory_size();

        // Write delta + vm_state.json. Then drop the VM (munmap memory, close fds).
        let dirty_pages = write_delta(
            &node_dir.join("delta.pack"),
            &bitmap,
            src_mem,
            mem_size,
            node_parent(&self.nodes, node_id).unwrap_or_default(),
        )?;
        let state_json = serde_json::to_string(&state)?;
        atomic_write(&node_dir.join("vm_state.json"), state_json.as_bytes())?;

        drop(vm);

        if let Some(info) = self.nodes.get_mut(node_id) {
            info.state = NodeState::Suspended;
            info.dirty_page_count = dirty_pages;
            touch(info);
        }
        self.save_metadata()?;
        log::info!("tree: suspended node '{node_id}' ({dirty_pages} dirty pages)");
        Ok(())
    }

    /// Resume a suspended VM: restore from parent's `base.mem` + this node's delta.
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

        // Reserve headroom for the VM we're about to bring back to Live.
        self.evict_for_incoming_no_exempt(1)?;

        // Find the nearest ancestor with a memory.bin (checkpoint).
        let base_node = self.nearest_checkpoint(node_id)?;
        let base_path = self.node_dir(&base_node).join("memory.bin");

        // Load state + delta, materialize the VM.
        let node_dir = self.node_dir(node_id);
        let state_json = fs::read_to_string(node_dir.join("vm_state.json"))?;
        let state: VmState = serde_json::from_str(&state_json)?;

        let fork_mem_addr = crate::fork::mmap_base_mem_private(&base_path, state.memory_size)?;

        // Apply this node's delta on top of base.mem. (If the node is the same
        // as base_node — i.e. a checkpoint that also has a delta — we skip.)
        if base_node != *node_id {
            apply_delta(
                &node_dir.join("delta.pack"),
                fork_mem_addr,
                state.memory_size,
            )?;
        }

        let mut vm = crate::fork::build_vm_from_state_and_mem(
            &state,
            fork_mem_addr,
            &format!("resume:{node_id}"),
        )?;
        vm.start()?;
        vm.enable_dirty_tracking()?;

        self.live_vms.insert(node_id.clone(), vm);
        if let Some(info) = self.nodes.get_mut(node_id) {
            info.state = NodeState::Live;
            touch(info);
        }
        self.save_metadata()?;
        log::info!("tree: resumed node '{node_id}'");
        Ok(())
    }

    /// Permanently delete a node and all its descendants.
    /// Frees all RAM and disk resources; ignores protection.
    pub fn prune(&mut self, node_id: &NodeId) -> Result<(), TreeError> {
        // Collect subtree via BFS.
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

        // Delete children first, then root.
        for id in subtree.into_iter().rev() {
            if let Some(vm) = self.live_vms.remove(&id) {
                drop(vm);
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
        log::info!("tree: pruned '{node_id}' and its subtree");
        Ok(())
    }

    /// Update the resource budget.
    pub fn set_budget(&mut self, budget: TreeBudget) {
        self.budget = budget;
        let _ = self.save_metadata();
    }

    /// Get current resource usage.
    ///
    /// internal notes: `live_vm_count` is the Σ of `vm_count` across all Live
    /// nodes, so an N-VM cluster node counts as N. For a single-VM tree
    /// it equals the number of live nodes; the new `live_node_count`
    /// field reports that explicitly.
    #[must_use]
    pub fn usage(&self) -> TreeUsage {
        let mut live_ram_bytes: u64 = 0;
        for vm in self.live_vms.values() {
            live_ram_bytes = live_ram_bytes.saturating_add(estimate_vm_ram(vm));
        }
        let mut disk_bytes: u64 = 0;
        for info in self.nodes.values() {
            let dir = self.node_dir(&info.id);
            for file in ["memory.bin", "delta.pack"] {
                if let Ok(md) = fs::metadata(dir.join(file)) {
                    disk_bytes = disk_bytes.saturating_add(md.len());
                }
            }
        }
        let live_node_count = self.live_vms.len();
        // For VmPayload-backed trees this is identical to the previous
        // semantics (every live node has vm_count == 1); for cluster
        // trees it sums the underlying VM counts so internal notes's
        // "max_live_vms == 50 means 50 underlying VMs" holds.
        let live_vm_count: usize = self
            .live_vms
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

    /// Suspend the LRU non-protected live VM(s) until we're no longer over
    /// the RAM budget. A source id can be exempted (used by `fork_batch` so
    /// the source isn't suspended out from under the caller).
    fn auto_evict_if_over(&mut self, source_id: &NodeId) -> Result<(), TreeError> {
        self.evict_for_incoming_inner(Some(source_id.as_str()), 0)
    }

    /// Suspend the LRU non-protected live VM(s) until at least `incoming`
    /// new live VMs can be created (no source to exempt; used by `resume`).
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
                        "need headroom for {incoming} new live VM(s); \
                         live={}/{} ram={}B/{}B; all other live nodes protected",
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
        // Disk-tier eviction still applies once RAM is under control.
        self.auto_evict_disk()?;
        Ok(())
    }

    /// Run only the disk-tier eviction (Tier 2). Extracted so `evict_for_incoming`
    /// can invoke it separately from RAM-tier.
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
                        "disk budget: {}B/{}B, no evictable subtrees",
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

    /// Enforce budget by suspending/evicting the lowest-priority nodes.
    ///
    /// Tier 1 (RAM): if `max_live_vms` or `ram_soft_limit` exceeded, suspend
    /// the least-recently-active non-protected live VM. Repeat until under.
    ///
    /// Tier 2 (disk): if `max_disk_bytes` exceeded, evict the LRU suspended
    /// leaf subtree (no live/suspended descendants, no ancestor-protected).
    ///
    /// Returns the ids of nodes that were suspended or evicted.
    pub fn auto_evict(&mut self) -> Result<Vec<NodeId>, TreeError> {
        let mut affected: Vec<NodeId> = Vec::new();

        // --- Tier 1: RAM ---
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
                        "RAM budget: live={}/{} ram={}B/{}B, all live nodes protected",
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

        // --- Tier 2: disk ---
        affected.extend(self.auto_evict_disk()?);

        Ok(affected)
    }

    /// Evict a subtree: delete files, mark nodes Evicted (keep metadata).
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
            for f in [
                "memory.bin",
                "delta.pack",
                "cpu.json",
                "devices.json",
                "irqchip.json",
                "metadata.json",
                "vm_state.json",
            ] {
                let _ = fs::remove_file(dir.join(f));
            }
            // Keep metadata.json so `tree.json` reflects that the node existed.
            if let Some(info) = self.nodes.get_mut(&id) {
                info.state = NodeState::Evicted;
                info.has_base_snapshot = false;
                touch(info);
            }
            evicted.push(id);
        }
        self.save_metadata()?;
        log::info!(
            "tree: evicted subtree rooted at '{node_id}' ({} nodes)",
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

    /// Get a shared reference to the live VM for a node.
    #[must_use]
    pub fn get_vm(&self, node_id: &NodeId) -> Option<&Vm> {
        self.live_vms.get(node_id)
    }

    /// Get a mutable reference to the live VM for a node.
    pub fn get_vm_mut(&mut self, node_id: &NodeId) -> Option<&mut Vm> {
        if let Some(info) = self.nodes.get_mut(node_id) {
            touch(info);
        }
        self.live_vms.get_mut(node_id)
    }

    /// Get all leaf nodes (exploration tips) that are still live or suspended.
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

    /// Get path from a node to the root.
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

    /// Find the nearest ancestor (inclusive) that has a `base.mem`.
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

    fn save_metadata(&self) -> Result<(), TreeError> {
        let doc = TreeDoc {
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

impl Drop for SnapshotTree {
    fn drop(&mut self) {
        // Drop all live VMs explicitly first (frees RAM + closes KVM fds),
        // then the root_dir is left on disk by default (callers prune() to
        // delete). This avoids surprising filesystem mutations on scope exit.
        self.live_vms.clear();
    }
}

fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap_or(Duration::from_secs(0))
        .as_secs()
}

fn node_parent(nodes: &HashMap<NodeId, NodeInfo>, id: &NodeId) -> Option<String> {
    nodes
        .get(id)
        .and_then(|n| n.parent.clone())
        .map(|p| p.chars().take(16).collect())
}

/// Rough estimate of non-reclaimable RAM for a live VM: 4 KiB × popcount of
/// the accumulated dirty bitmap. This is a lower bound — pages dirtied before
/// dirty tracking was enabled aren't counted, but `prepare_fork_source_in`
/// enables tracking immediately, so the lower bound is tight in practice.
fn estimate_vm_ram(vm: &Vm) -> u64 {
    vm.accumulated_dirty_pages().unwrap_or(0) * 4096
}

// --- K7DL delta format ---
//
// The on-disk format (magic, version, header layout, entry layout) lives in
// [`tree_model`]. This file owns only the I/O and `unsafe` page-copy halves;
// the byte layout of headers and entries goes through
// `k7dl_header_bytes` / `k7dl_parse_header` / `k7dl_encode_entry` /
// `k7dl_parse_entry`.

/// Write a packed K7DL delta from a live VM's memory.
///
/// For each bit set in `dirty_bitmap`, copy the 4 KiB page from `src_addr` into
/// the delta file. Returns the number of pages written.
pub fn write_delta(
    path: &Path,
    dirty_bitmap: &[u64],
    src_addr: u64,
    mem_size: u64,
    _base_node_id: String,
) -> Result<u32, TreeError> {
    let page_size: u64 = 4096;
    let total_pages = mem_size / page_size;

    // First pass: count dirty pages (so the header contains the exact count).
    let page_count: u32 = dirty_bitmap
        .iter()
        .enumerate()
        .map(|(word_idx, &w)| {
            let mut count = 0u32;
            for bit in 0..64u64 {
                if w & (1u64 << bit) == 0 {
                    continue;
                }
                let page_idx = (word_idx as u64) * 64 + bit;
                if page_idx >= total_pages {
                    break;
                }
                count += 1;
            }
            count
        })
        .sum();

    let tmp = path.with_extension("pack.tmp");
    {
        let f = fs::File::create(&tmp)?;
        let mut w = BufWriter::new(f);

        let header = k7dl_header_bytes(page_count, mem_size);
        w.write_all(&header)?;

        for (word_idx, &word) in dirty_bitmap.iter().enumerate() {
            if word == 0 {
                continue;
            }
            for bit in 0..64u64 {
                if word & (1u64 << bit) == 0 {
                    continue;
                }
                let page_idx = ((word_idx as u64) * 64 + bit) as u32;
                if (page_idx as u64) >= total_pages {
                    break;
                }
                let offset = u64::from(page_idx) * page_size;
                // Copy the 4 KiB page out of the VM's paused mmap into a
                // stack buffer, then push it through the pure encoder. The
                // `unsafe` block is the *only* place this function reads
                // VM-owned memory.
                let mut page = [0u8; 4096];
                // SAFETY: offset+4096 <= mem_size; src_addr points to a valid
                // mmap region of at least mem_size bytes (VM is paused).
                unsafe {
                    std::ptr::copy_nonoverlapping(
                        (src_addr + offset) as *const u8,
                        page.as_mut_ptr(),
                        4096,
                    );
                }
                let entry = k7dl_encode_entry(page_idx, &page);
                w.write_all(&entry)?;
            }
        }
        w.flush()?;
    }
    fs::rename(&tmp, path)?;
    Ok(page_count)
}

/// Apply a packed K7DL delta into a `MAP_PRIVATE` memory region.
///
/// Writes each page from the delta file into `target_addr + page_idx * 4096`.
/// Returns the number of pages applied.
pub fn apply_delta(path: &Path, target_addr: u64, mem_size: u64) -> Result<u32, TreeError> {
    let mut f = fs::File::open(path)?;
    let mut header = [0u8; K7DL_HEADER_SIZE];
    f.read_exact(&mut header)?;

    let (page_count, delta_mem_size) = k7dl_parse_header(&header)?;
    if delta_mem_size != mem_size {
        return Err(DeltaError::MemSizeMismatch {
            got: delta_mem_size,
            expected: mem_size,
        }
        .into());
    }

    let mut buf = [0u8; K7DL_ENTRY_SIZE];
    for _ in 0..page_count {
        f.read_exact(&mut buf)?;
        let (page_idx, page) = k7dl_parse_entry(&buf);
        let offset = u64::from(page_idx) * 4096;
        if offset + 4096 > mem_size {
            return Err(DeltaError::PageOutOfBounds { page_idx, mem_size }.into());
        }
        // SAFETY: target_addr+offset+4096 <= target_addr+mem_size, and the
        // caller guarantees the mapping lives for the duration of this call.
        unsafe {
            std::ptr::copy_nonoverlapping(page.as_ptr(), (target_addr + offset) as *mut u8, 4096);
        }
    }
    Ok(page_count)
}

/// Atomic write: write to `path.tmp` + fsync + rename.
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
