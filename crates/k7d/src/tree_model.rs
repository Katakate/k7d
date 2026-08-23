//! Pure model + pure helpers for the snapshot tree (Step 1
//! `Vec<NodeInfo>` storage shape).
//!
//! This module is the **Aeneas translation target** for. Everything
//! here is:
//!
//! - Safe Rust (`#![forbid(unsafe_code)]`).
//! - Free of platform / KVM / filesystem dependencies (no `use std::fs`, no
//!   `use crate::vm`, no `use crate::snapshot`, no `use crate::fork`, no
//!   `std::time::SystemTime`).
//! - Deterministic on its inputs.
//! - Free of `HashMap` / `HashSet` / iterator combinators / closures —
//!   Aeneas's Lean backend has no models for those, which is why the
//!   earlier helpers were `#[cfg(not(feature = "verif"))]`-gated. The
//!   rewrite to `Vec<NodeInfo>` keyed by `u64` (this file) is what
//!   made the whole surface translatable; everything below is ungated.
//!
//! The orchestrators ([`crate::tree::SnapshotTree`],
//! [`crate::cluster_tree::ClusterSnapshotTree`]) keep their own
//! `String`-keyed node records (filesystem ids stay `String`-shaped, and
//! `tree.json` stays byte-compatible), maintain a `String → u64` id map,
//! and derive a [`TreeModel`] view at every eviction decision point. The
//! pure helpers below make the decision; the orchestrator maps the winning
//! `u64` back to its `String` id.
//!
//! ## What lives here
//!
//! - The plain-data types: [`NodeState`], [`PayloadKind`], [`TreeBudget`],
//!   [`NodeInfo`] (pure, `u64`-keyed), [`TreeModel`], [`TreeUsage`].
//! - Pure DAG operations: [`add_child`], [`touch`], [`set_state`],
//!   [`set_protected`].
//! - Pure budget / usage predicates: [`usage`], [`over_ram`],
//!   [`over_count`], [`over_disk`], [`over_disk_incoming`],
//!   [`TreeBudget::ram_soft_limit`].
//! - Pure eviction policy: [`ancestor_ids`], [`restore_chain_depth`],
//!   [`implicitly_protected`],
//!   [`lru_live_victim`], [`subtree_isolated`],
//!   [`lru_evictable_leaf_subtree`], [`auto_evict_ram`].
//! - The pure half of the K7DL delta codec: [`k7dl_header_bytes`],
//!   [`k7dl_parse_header`], [`k7dl_encode_entry`], [`k7dl_parse_entry`].
//! - The latency-budget model [`fork_warm_budget_ns`] (Group F).
//!
//! ## What does NOT live here (kept in `tree.rs` / `cluster_tree.rs`)
//!
//! - The orchestrator `NodeInfo` (`String` ids, `label`, serde) and
//!   `SnapshotTree` itself (owns `Vm`s, mutates the filesystem).
//! - `write_delta` / `apply_delta` (use `unsafe` page-copy and touch the
//!   filesystem; they call into the pure halves above).
//! - Any function that needs `SystemTime` (the orchestrator passes a
//!   pre-computed `now: u64` in).
//!
//! ## Verified properties (see `verif/Verif/`)
//!
//! The Lean theorems for Groups A–D are proven against transparent
//! mirrors of the functions in this file, and each
//! mirror is machine-checked equivalent to the Aeneas translation of this
//! file (`verif/Verif/Equiv/`). The theorems to cite are the `_rust`
//! corollaries in `verif/Verif/Equiv/Transfer.lean`: they speak about the
//! generated code directly, and each also proves the function never panics
//! on the stated inputs. The mirrors live in `verif/Verif/TreeShape.lean`,
//! `TreeBudget.lean`, `TreeEviction.lean`, `K7dlCodec.lean`,
//! `Latency.lean` — **change a function here, update its mirror;
//! `make remote-verif` re-checks the equivalence**. Groups E (K7DL
//! codec) and F (latency budget) are machine-checked too.

#![forbid(unsafe_code)]

#[cfg(not(feature = "verif"))]
use serde::{Deserialize, Serialize};

/// Lifecycle state of a node.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(not(feature = "verif"), derive(Serialize, Deserialize))]
#[cfg_attr(not(feature = "verif"), serde(rename_all = "lowercase"))]
pub enum NodeState {
    /// VM is resident in RAM (running or paused-but-alive).
    Live,
    /// VM state is on disk (`delta.pack` + `cpu.json`); RAM is freed.
    Suspended,
    /// All resources deleted; only metadata remains in `tree.json`.
    Evicted,
}

/// What lives at a snapshot-tree node: a single VM, or a whole cluster of
/// warm-forkable VMs sharing a per-cluster bridge.
///
/// Defaults to [`PayloadKind::Vm`] so `tree.json` files written by earlier
/// k7d still load — the absent `kind` field deserialises to `Vm` and the
/// rest of the on-disk layout is unchanged for VM payloads.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[cfg_attr(not(feature = "verif"), derive(Serialize, Deserialize))]
#[cfg_attr(not(feature = "verif"), serde(rename_all = "lowercase"))]
pub enum PayloadKind {
    /// Single-VM payload — today's `Vm`-backed tree (back-compat default).
    #[default]
    Vm,
    /// Cluster payload — `N` VMs sharing a per-cluster `ClusterNetwork`
    /// (`ClusterPayload`).
    Cluster,
}

/// Resource budget for a snapshot tree.
#[derive(Debug, Clone, Copy)]
#[cfg_attr(not(feature = "verif"), derive(Serialize, Deserialize))]
pub struct TreeBudget {
    /// Max concurrent live VMs.
    pub max_live_vms: usize,
    /// Max non-reclaimable RAM across live VMs, in bytes.
    pub max_live_ram_bytes: u64,
    /// Max disk usage for `base.mem` + `delta.pack` across all nodes, in bytes.
    pub max_disk_bytes: u64,
    /// Max *restore-chain* depth (non-checkpoint hops to the nearest
    /// `has_base_snapshot` ancestor) before consolidation. Recommended: 1.
    /// Not tree-graph / search depth — a graph of root→child→grandchild
    /// is legal while this stays 1. The quantity capped is
    /// [`restore_chain_depth`]; the orchestrators enforce it on `resume`
    /// .
    pub max_chain_depth: usize,
}

impl TreeBudget {
    /// Proactive suspend threshold: 85% of the RAM budget.
    /// Kept well below OOM territory and kernel reclaim stalls.
    ///
    /// Uses integer math (×85/100) to avoid precision loss on RAM budgets
    /// above ~9 PiB (where `u64 → f64` would lose least-significant bits).
    /// The saturating multiply is spelled out with an explicit guard
    /// (`x*85 > u64::MAX ⟺ x > u64::MAX/85`) instead of `saturating_mul`
    /// because Aeneas has no model for `saturating_mul` — it would land in
    /// the generated Lean as a bodyless axiom, sinking the
    /// equivalence proof (`saturating_add` has a model; `_mul` does not).
    ///
    /// Verified: `ram_soft_limit_below_max_rust` in
    /// `verif/Verif/Equiv/Transfer.lean` proves (on the Aeneas translation
    /// of this function) the result never exceeds `max_live_ram_bytes`.
    #[must_use]
    pub fn ram_soft_limit(self) -> u64 {
        let prod = if self.max_live_ram_bytes > u64::MAX / 85 {
            u64::MAX
        } else {
            self.max_live_ram_bytes * 85
        };
        prod / 100
    }
}

/// Pure metadata about a tree node (shape: `u64`-keyed).
///
/// The orchestrator keeps the `String`-shaped twin (`crate::tree::NodeInfo`,
/// which also carries `label` / `created_at_unix` and the serde derives for
/// `tree.json`) and maps between the two via its `String → u64` id map.
///
/// `Clone` is hand-written (not derived) so the `parent: Option<u64>` field
/// is a plain copy: the derive would call `Option::clone`, which Aeneas has
/// no model for and would turn into a bodyless axiom threading through every
/// rebuild loop (`add_child`, `touch`, …), sinking the
/// equivalence proofs.
#[derive(Debug)]
pub struct NodeInfo {
    /// Pure node id. Minted monotonically by the orchestrator, so a child's
    /// id is always strictly greater than its parent's (the Lean proofs'
    /// `parentLt` well-formedness invariant).
    pub id: u64,
    pub parent: Option<u64>,
    pub children: Vec<u64>,
    pub state: NodeState,
    /// Payload kind (Vm or Cluster).
    pub kind: PayloadKind,
    /// Number of *underlying* VMs this payload represents (1 for Vm, N for
    /// an N-member cluster). Budgeted against [`TreeBudget::max_live_vms`].
    pub vm_count: u32,
    /// Number of dirty pages this node's delta captures (0 for
    /// root/checkpoints). For a cluster payload this is the Σ over members.
    pub dirty_pages: u32,
    /// Whether this node has its own `base.mem` (checkpoint / fork-point).
    pub has_base_snapshot: bool,
    /// Wall-clock time of most recent activity (`UNIX_EPOCH` offset,
    /// seconds), passed in pre-computed by the orchestrator.
    pub last_active: u64,
    /// Whether this node is excluded from auto-eviction.
    pub protected: bool,
    /// Estimated non-reclaimable RAM, in bytes (orchestrator passes the
    /// `Vm`-derived value in; 0 for non-live nodes).
    pub est_ram_bytes: u64,
    /// On-disk footprint, in bytes (orchestrator passes the
    /// `fs::metadata`-derived value in when it needs [`over_disk`]).
    pub disk_bytes: u64,
}

impl Clone for NodeInfo {
    /// Field-by-field copy; only `children` needs a real clone. See the
    /// struct-level note for why this is not `#[derive(Clone)]`.
    fn clone(&self) -> Self {
        NodeInfo {
            id: self.id,
            parent: self.parent,
            children: self.children.clone(),
            state: self.state,
            kind: self.kind,
            vm_count: self.vm_count,
            dirty_pages: self.dirty_pages,
            has_base_snapshot: self.has_base_snapshot,
            last_active: self.last_active,
            protected: self.protected,
            est_ram_bytes: self.est_ram_bytes,
            disk_bytes: self.disk_bytes,
        }
    }
}

/// Pure snapshot-tree model: `Vec` storage + budget (shape).
///
/// The `Vec` (instead of the earlier `HashMap`) is what makes the eviction
/// helpers translatable by Aeneas — see the module docs.
#[derive(Debug, Clone)]
pub struct TreeModel {
    pub nodes: Vec<NodeInfo>,
    pub budget: TreeBudget,
}

/// Current resource usage of the tree.
///
/// `live_vm_count` reports the **Σ of underlying VMs** across all live
/// nodes — for a single-VM tree this equals `live_node_count`; for a
/// cluster tree of N-VM clusters it is N × `live_node_count`. This is
/// the field budgeted against [`TreeBudget::max_live_vms`] and matches
/// the rule "an N-VM cluster node counts as N for `max_live_vms`."
///
/// `live_node_count` is the count of tree nodes in `Live` state,
/// regardless of payload size — added in for callers that want
/// "how many tree nodes are Live."
#[derive(Debug, Clone, Copy, Default)]
pub struct TreeUsage {
    /// Σ of `vm_count` over all Live nodes.
    pub live_vm_count: usize,
    /// Estimated non-reclaimable RAM used by live VMs, in bytes.
    /// Derived from per-VM accumulated dirty bitmaps. For a cluster
    /// payload this is the Σ over members.
    pub live_ram_bytes: u64,
    /// Sum of `base.mem` + `delta.pack` (+ per-member files for
    /// cluster payloads + `cluster.json`) sizes, in bytes.
    pub disk_bytes: u64,
    pub total_nodes: usize,
    /// Count of tree nodes currently in `Live` state.
    pub live_node_count: usize,
}

// --- Pure lookups ---

/// Index of the node with `id` in `t.nodes`, if present. Linear scan —
/// trees are small (tens to low hundreds of nodes) and the `Vec` shape is
/// what Aeneas can translate.
#[must_use]
pub fn find_index(t: &TreeModel, id: u64) -> Option<usize> {
    let mut i = 0;
    while i < t.nodes.len() {
        if t.nodes[i].id == id {
            return Some(i);
        }
        i += 1;
    }
    None
}

/// Whether `ids` contains `id`.
#[must_use]
pub fn contains_id(ids: &[u64], id: u64) -> bool {
    let mut i = 0;
    while i < ids.len() {
        if ids[i] == id {
            return true;
        }
        i += 1;
    }
    false
}

/// Largest node id in the tree (0 for an empty tree). Used to size the
/// fuel bound of [`ancestor_ids`].
#[must_use]
pub fn max_id(t: &TreeModel) -> u64 {
    let mut m: u64 = 0;
    let mut i = 0;
    while i < t.nodes.len() {
        if t.nodes[i].id > m {
            m = t.nodes[i].id;
        }
        i += 1;
    }
    m
}

// --- Pure DAG operations ---
//
// All deterministic; all return a new `TreeModel`. Nonexistent-target
// updates return the input unchanged (the orchestrator validates ids
// before calling; the total-function shape keeps the Lean model simple).

/// Add a `Live` child of `parent` with the fresh id `new_id`; stamps both
/// the parent and the child with `last_active = now`.
///
/// Returns the input unchanged when `parent` is absent or `new_id` is
/// already taken.
///
/// Verified: `add_child_preserves_well_formed_rust` in
/// `verif/Verif/Equiv/Transfer.lean` (Group A, on the Aeneas
/// translation of this function).
#[must_use]
pub fn add_child(t: &TreeModel, parent: u64, new_id: u64, now: u64) -> TreeModel {
    if find_index(t, parent).is_none() || find_index(t, new_id).is_some() {
        return t.clone();
    }
    let mut nodes: Vec<NodeInfo> = Vec::new();
    let mut i = 0;
    while i < t.nodes.len() {
        let mut n = t.nodes[i].clone();
        if n.id == parent {
            n.children.push(new_id);
            n.last_active = now;
        }
        nodes.push(n);
        i += 1;
    }
    nodes.push(NodeInfo {
        id: new_id,
        parent: Some(parent),
        children: Vec::new(),
        state: NodeState::Live,
        kind: PayloadKind::Vm,
        vm_count: 1,
        dirty_pages: 0,
        has_base_snapshot: false,
        last_active: now,
        protected: false,
        est_ram_bytes: 0,
        disk_bytes: 0,
    });
    TreeModel {
        nodes,
        budget: t.budget,
    }
}

/// Stamp `last_active = now` on the node with `id`.
#[must_use]
pub fn touch(t: &TreeModel, id: u64, now: u64) -> TreeModel {
    let mut nodes: Vec<NodeInfo> = Vec::new();
    let mut i = 0;
    while i < t.nodes.len() {
        let mut n = t.nodes[i].clone();
        if n.id == id {
            n.last_active = now;
        }
        nodes.push(n);
        i += 1;
    }
    TreeModel {
        nodes,
        budget: t.budget,
    }
}

/// Set the state of the node with `id` to `s`.
#[must_use]
pub fn set_state(t: &TreeModel, id: u64, s: NodeState) -> TreeModel {
    let mut nodes: Vec<NodeInfo> = Vec::new();
    let mut i = 0;
    while i < t.nodes.len() {
        let mut n = t.nodes[i].clone();
        if n.id == id {
            n.state = s;
        }
        nodes.push(n);
        i += 1;
    }
    TreeModel {
        nodes,
        budget: t.budget,
    }
}

/// Set the protection flag of the node with `id` to `p`.
#[must_use]
pub fn set_protected(t: &TreeModel, id: u64, p: bool) -> TreeModel {
    let mut nodes: Vec<NodeInfo> = Vec::new();
    let mut i = 0;
    while i < t.nodes.len() {
        let mut n = t.nodes[i].clone();
        if n.id == id {
            n.protected = p;
        }
        nodes.push(n);
        i += 1;
    }
    TreeModel {
        nodes,
        budget: t.budget,
    }
}

// --- Pure budget accounting ---

/// Current resource usage of the model.
///
/// Verified: `usage_ram_is_sum_of_live_rust` /
/// `usage_count_is_count_of_live_rust` in `verif/Verif/Equiv/Transfer.lean`
/// (Group B, on the Aeneas translation of this function).
#[must_use]
pub fn usage(t: &TreeModel) -> TreeUsage {
    let mut live_vm_count: usize = 0;
    let mut live_ram_bytes: u64 = 0;
    let mut disk_bytes: u64 = 0;
    let mut live_node_count: usize = 0;
    let mut i = 0;
    while i < t.nodes.len() {
        // Copy the scalar fields out instead of holding a `&NodeInfo`
        // borrow across the branch — Aeneas's symbolic execution cannot
        // join the borrow-carrying environments otherwise.
        let state = t.nodes[i].state;
        let vm_count = t.nodes[i].vm_count;
        let est_ram_bytes = t.nodes[i].est_ram_bytes;
        let node_disk_bytes = t.nodes[i].disk_bytes;
        if state == NodeState::Live {
            live_vm_count = live_vm_count.saturating_add(vm_count as usize);
            live_ram_bytes = live_ram_bytes.saturating_add(est_ram_bytes);
            live_node_count += 1;
        }
        disk_bytes = disk_bytes.saturating_add(node_disk_bytes);
        i += 1;
    }
    TreeUsage {
        live_vm_count,
        live_ram_bytes,
        disk_bytes,
        total_nodes: t.nodes.len(),
        live_node_count,
    }
}

/// Whether live RAM exceeds the proactive soft limit
/// ([`TreeBudget::ram_soft_limit`]).
#[must_use]
pub fn over_ram(t: &TreeModel) -> bool {
    usage(t).live_ram_bytes > t.budget.ram_soft_limit()
}

/// Whether the live VM count, plus `incoming` VMs about to be created,
/// exceeds `max_live_vms`.
#[must_use]
pub fn over_count(t: &TreeModel, incoming: u32) -> bool {
    usage(t).live_vm_count.saturating_add(incoming as usize) > t.budget.max_live_vms
}

/// Whether the on-disk footprint exceeds `max_disk_bytes`.
#[must_use]
pub fn over_disk(t: &TreeModel) -> bool {
    usage(t).disk_bytes > t.budget.max_disk_bytes
}

/// Whether the on-disk footprint plus `incoming` bytes about to be
/// written (a projected new base snapshot — the referenced work) exceeds
/// `max_disk_bytes`. `over_disk_incoming(t, 0)` coincides with
/// [`over_disk`].
///
/// Verified: `over_disk_incoming_zero_rust` in
/// `verif/Verif/Equiv/Transfer.lean` (on the Aeneas translation of
/// this function).
#[must_use]
pub fn over_disk_incoming(t: &TreeModel, incoming: u64) -> bool {
    usage(t).disk_bytes.saturating_add(incoming) > t.budget.max_disk_bytes
}

// --- Pure eviction policy ---

/// Ancestor chain of `id`, inclusive (`[id, parent, grandparent, …, root]`).
///
/// The walk is fuel-bounded by `max_id(t) + 2` so it terminates even on a
/// malformed (cyclic) input. On a well-formed tree — parent ids strictly
/// smaller than child ids, the invariant the orchestrator's monotonic id
/// minting guarantees — any chain from `id` has at most `id + 1` elements,
/// so the fuel never truncates a real chain
/// (`ancestor_ids_fuel_never_truncates_rust` in
/// `verif/Verif/Equiv/Transfer.lean`).
#[must_use]
pub fn ancestor_ids(t: &TreeModel, id: u64) -> Vec<u64> {
    let mut out: Vec<u64> = Vec::new();
    let mut cur: Option<u64> = Some(id);
    let mut fuel = max_id(t).saturating_add(2);
    while fuel > 0 {
        match cur {
            None => break,
            Some(c) => {
                out.push(c);
                cur = match find_index(t, c) {
                    Some(i) => t.nodes[i].parent,
                    None => None,
                };
            }
        }
        fuel -= 1;
    }
    out
}

/// Restore-chain depth of `id` : the number of
/// non-checkpoint nodes from `id` (inclusive) up to — but not counting —
/// its nearest `has_base_snapshot` ancestor, i.e. how many `delta.pack`s
/// a resume would have to apply on top of that ancestor's `memory.bin`.
/// `Some(0)` for a checkpoint node. `None` when the walk finds no
/// checkpoint: a missing node, a root path with no base snapshot, or
/// fuel exhaustion on a malformed (cyclic) input. The fuel bound is
/// `max_id(t) + 2`, same as [`ancestor_ids`]; on a well-formed tree it
/// never truncates a real chain.
///
/// This is the quantity [`TreeBudget::max_chain_depth`] caps. It is NOT
/// tree-graph depth: `root → child → grandchild` is graph depth 2 while
/// this stays ≤ 1 as long as every fork source was prepared
/// (`prepare_fork_source` sets `has_base_snapshot`).
///
/// Verified: `restore_chain_depth_checkpoint_rust` /
/// `restore_chain_depth_hop_rust` in `verif/Verif/Equiv/Transfer.lean`
/// (on the Aeneas translation of this function).
#[must_use]
pub fn restore_chain_depth(t: &TreeModel, id: u64) -> Option<usize> {
    let mut depth: usize = 0;
    let mut cur: Option<u64> = Some(id);
    let mut fuel = max_id(t).saturating_add(2);
    while fuel > 0 {
        match cur {
            None => return None,
            Some(c) => match find_index(t, c) {
                None => return None,
                Some(i) => {
                    // Scalar copies — no `&NodeInfo` borrow across the
                    // branch (Aeneas context join; see `usage`).
                    let has_base = t.nodes[i].has_base_snapshot;
                    let parent = t.nodes[i].parent;
                    if has_base {
                        return Some(depth);
                    }
                    depth = depth.saturating_add(1);
                    cur = parent;
                }
            },
        }
        fuel -= 1;
    }
    None
}

/// The ids that should NOT be auto-evicted: every explicitly-protected
/// node and all its ancestors (so an LRU pick that would invalidate a
/// protected node's parent chain is rejected before eviction).
///
/// Verified: `implicitly_protected_includes_ancestors_rust` in
/// `verif/Verif/Equiv/Transfer.lean` (Group C, on the Aeneas
/// translation of this function).
#[must_use]
pub fn implicitly_protected(t: &TreeModel) -> Vec<u64> {
    let mut out: Vec<u64> = Vec::new();
    let mut i = 0;
    while i < t.nodes.len() {
        if t.nodes[i].protected {
            let chain = ancestor_ids(t, t.nodes[i].id);
            let mut j = 0;
            while j < chain.len() {
                if !contains_id(&out, chain[j]) {
                    out.push(chain[j]);
                }
                j += 1;
            }
        }
        i += 1;
    }
    out
}

/// Pick the LRU live, non-protected, non-exempt node.
///
/// Returns the id with the smallest `last_active` (first such node in
/// `t.nodes` order on ties). Returns `None` when no candidate satisfies
/// all three filters (caller treats this as a "budget exhausted under
/// protection" condition).
///
/// Verified: `lru_victim_is_minimum_rust` in
/// `verif/Verif/Equiv/Transfer.lean` (Group C, on the Aeneas
/// translation of this function).
// `manual_map`: the closure `Option::map` wants is not Aeneas-translatable;
// the explicit `match` is what the Lean mirror mirrors.
#[allow(clippy::manual_map)]
#[must_use]
pub fn lru_live_victim(t: &TreeModel, exempt: &[u64]) -> Option<u64> {
    let prot = implicitly_protected(t);
    let mut best: Option<(u64, u64)> = None; // (last_active, id)
    let mut i = 0;
    while i < t.nodes.len() {
        // Scalar copies + eager conjuncts: short-circuit `&&` over calls
        // that borrow `prot` trips Aeneas's context join, and holding a
        // `&NodeInfo` across the branch does too.
        let id = t.nodes[i].id;
        let state = t.nodes[i].state;
        let last_active = t.nodes[i].last_active;
        let is_live = state == NodeState::Live;
        let in_exempt = contains_id(exempt, id);
        let in_prot = contains_id(&prot, id);
        if is_live && !in_exempt && !in_prot {
            let replace = match best {
                None => true,
                Some((best_active, _)) => last_active < best_active,
            };
            if replace {
                best = Some((last_active, id));
            }
        }
        i += 1;
    }
    match best {
        None => None,
        Some((_, id)) => Some(id),
    }
}

/// Whether every strict descendant of `root` is `Evicted` — i.e. deleting
/// `root`'s subtree from disk cannot invalidate any Live or Suspended node.
///
/// A node `d` is a strict descendant of `root` iff `d != root` and `root`
/// appears on `d`'s ancestor chain.
#[must_use]
pub fn subtree_isolated(t: &TreeModel, root: u64) -> bool {
    let mut i = 0;
    while i < t.nodes.len() {
        let d = &t.nodes[i];
        if d.id != root
            && d.state != NodeState::Evicted
            && contains_id(&ancestor_ids(t, d.id), root)
        {
            return false;
        }
        i += 1;
    }
    true
}

/// Find the LRU suspended node whose strict descendants are all `Evicted`
/// and that is not (implicitly) protected.
///
/// Used by the disk-tier (Tier 2) evictor: only fully-detached suspended
/// leaf subtrees are safe to delete from disk. Note that a protected node
/// anywhere in `root`'s subtree makes `root` itself implicitly protected
/// (ancestors of protected nodes are protected), so the
/// `implicitly_protected` check subsumes the earlier "no protected node in
/// the subtree" scan.
///
/// Verified: `leaf_subtree_has_no_live_descendants_rust` in
/// `verif/Verif/Equiv/Transfer.lean` (Group C, on the Aeneas
/// translation of this function).
// `manual_map`: see `lru_live_victim`.
#[allow(clippy::manual_map)]
#[must_use]
pub fn lru_evictable_leaf_subtree(t: &TreeModel) -> Option<u64> {
    let prot = implicitly_protected(t);
    let mut best: Option<(u64, u64)> = None; // (last_active, id)
    let mut i = 0;
    while i < t.nodes.len() {
        // Scalar copies + eager conjuncts — see `lru_live_victim`.
        let id = t.nodes[i].id;
        let state = t.nodes[i].state;
        let last_active = t.nodes[i].last_active;
        let is_suspended = state == NodeState::Suspended;
        let in_prot = contains_id(&prot, id);
        let isolated = subtree_isolated(t, id);
        if is_suspended && !in_prot && isolated {
            let replace = match best {
                None => true,
                Some((best_active, _)) => last_active < best_active,
            };
            if replace {
                best = Some((last_active, id));
            }
        }
        i += 1;
    }
    match best {
        None => None,
        Some((_, id)) => Some(id),
    }
}

/// Pure equivalent of the orchestrators' Tier-1 RAM eviction loop: keep
/// suspending the [`lru_live_victim`] until neither [`over_ram`] nor
/// [`over_count`] holds, or no eligible victim remains.
///
/// The loop is fuel-bounded by the node count: each iteration suspends one
/// Live node, so at most `nodes.len()` iterations can ever run — the fuel
/// never cuts the loop short
/// (`auto_evict_ram_terminates_rust` + `auto_evict_ram_post_rust` in
/// `verif/Verif/Equiv/Transfer.lean` Group D, on the Aeneas
/// translation of this function).
#[must_use]
pub fn auto_evict_ram(t: &TreeModel, exempt: &[u64]) -> TreeModel {
    let mut cur = t.clone();
    let mut fuel = t.nodes.len();
    while fuel > 0 {
        if !over_ram(&cur) && !over_count(&cur, 0) {
            break;
        }
        match lru_live_victim(&cur, exempt) {
            None => break,
            Some(v) => {
                cur = set_state(&cur, v, NodeState::Suspended);
            }
        }
        fuel -= 1;
    }
    cur
}

// --- Latency budget (Group F target) ---
//
// Pulled in from `crate::latency` (Group F) so that Aeneas sees the
// warm-fork budget as part of the verified subset. This block is raw
// `u64` nanoseconds rather than `Duration`: Aeneas models
// `std::time::Duration` opaquely (bodyless axioms), which blocked the Group F
// mirror ↔ Aeneas equivalence proof. `latency.rs` wraps these back into
// `Duration` (`fork_warm_budget`, `FORK_WARM_BASE`, `FORK_WARM_PER_PAGE`),
// so callers outside `latency.rs` are unchanged.

/// Per-page memcpy budget in nanoseconds (0.5 µs per 4 KiB page on DDR4
/// ~20 GB/s).
pub const FORK_WARM_PER_PAGE_NS: u64 = 500;

/// Fixed overhead of the warm fork hot path (KVM fd + vCPU setup + vsock),
/// in nanoseconds (2 ms).
pub const FORK_WARM_BASE_NS: u64 = 2_000_000;

/// Compute a per-dirty-page warm fork budget in nanoseconds.
///
/// Model: `base + per_page * dirty_pages`, saturating at `u64::MAX`. A brand
/// new source (0 dirty pages) has ~2 ms budget; 10% dirty on 256 MB (6 554
/// pages) ≈ 5 ms; 100% ≈ 35 ms.
///
/// The saturating multiply is spelled out with an explicit guard
/// (`per_page * d > u64::MAX ⟺ d > u64::MAX / per_page`) instead of
/// `saturating_mul` because Aeneas has no model for `saturating_mul` — same
/// idiom as [`TreeBudget::ram_soft_limit`] (CHALLENGES.md #24).
///
/// Verified: `fork_warm_budget_base_rust` and
/// `fork_warm_budget_monotone_rust` in `verif/Verif/Equiv/Transfer.lean`
/// prove, on the Aeneas translation of this function, that zero dirty pages
/// yield exactly [`FORK_WARM_BASE_NS`] and that the budget is monotone in
/// `dirty_pages` (and that it never panics).
#[must_use]
pub fn fork_warm_budget_ns(dirty_pages: u64) -> u64 {
    let scaled = if dirty_pages > u64::MAX / FORK_WARM_PER_PAGE_NS {
        u64::MAX
    } else {
        FORK_WARM_PER_PAGE_NS * dirty_pages
    };
    FORK_WARM_BASE_NS.saturating_add(scaled)
}

// --- K7DL delta codec — pure halves ---
//
// `tree::write_delta` / `tree::apply_delta` keep the I/O + page-copy
// `unsafe` blocks; they call into the four functions below for the bytes
// that actually go to/from the wire.

/// Magic prefix on every K7DL delta header.
pub const K7DL_MAGIC: &[u8; 4] = b"K7DL";

/// On-disk format version of a K7DL delta.
pub const K7DL_VERSION: u32 = 1;

/// Size in bytes of the K7DL header: `magic(4)` + `version(4)` +
/// `page_count(4)` + `mem_size(8)` + `reserved(8)`.
pub const K7DL_HEADER_SIZE: usize = 4 + 4 + 4 + 8 + 8;

/// Size in bytes of a single K7DL entry: `page_index(4)` + `page(4096)`.
pub const K7DL_ENTRY_SIZE: usize = 4 + 4096;

/// Errors from the pure K7DL codec.
///
/// Under the default build the variants carry a `thiserror`-derived
/// `Display`/`Error` impl. Under `--features verif` (the Charon translation
/// build) the proc-macro derive is dropped — Aeneas handles plain enums far
/// better than the trait-object soup that `thiserror` expands to.
#[derive(Debug)]
#[cfg_attr(not(feature = "verif"), derive(thiserror::Error))]
pub enum DeltaError {
    /// The first four bytes are not `K7DL`.
    #[cfg_attr(
        not(feature = "verif"),
        error("invalid magic: expected {expected:?}, got {got:?}", expected = K7DL_MAGIC)
    )]
    BadMagic { got: [u8; 4] },
    /// The version field doesn't match [`K7DL_VERSION`].
    #[cfg_attr(
        not(feature = "verif"),
        error("unsupported version {got}, expected {expected}", expected = K7DL_VERSION)
    )]
    UnsupportedVersion { got: u32 },
    /// The header's `mem_size` disagrees with the orchestrator's expected size.
    #[cfg_attr(
        not(feature = "verif"),
        error("delta mem_size {got} != expected {expected}")
    )]
    MemSizeMismatch { got: u64, expected: u64 },
    /// A page index in the entry stream falls outside the target memory range.
    #[cfg_attr(
        not(feature = "verif"),
        error("page_idx {page_idx} out of bounds for mem_size {mem_size}")
    )]
    PageOutOfBounds { page_idx: u32, mem_size: u64 },
}

impl DeltaError {
    /// Manual `Display`-equivalent string. Mirrors what `thiserror` generates
    /// under the default build, but is also available under `--features verif`
    /// where the proc-macro is gated out for Charon's benefit.
    #[must_use]
    pub fn message(&self) -> String {
        match self {
            DeltaError::BadMagic { got } => {
                format!("invalid magic: expected {K7DL_MAGIC:?}, got {got:?}")
            }
            DeltaError::UnsupportedVersion { got } => {
                format!("unsupported version {got}, expected {K7DL_VERSION}")
            }
            DeltaError::MemSizeMismatch { got, expected } => {
                format!("delta mem_size {got} != expected {expected}")
            }
            DeltaError::PageOutOfBounds { page_idx, mem_size } => {
                format!("page_idx {page_idx} out of bounds for mem_size {mem_size}")
            }
        }
    }
}

/// Encode a K7DL header to its 28-byte little-endian wire form.
///
/// The reserved field is always zero. This is the inverse of
/// [`k7dl_parse_header`].
///
/// Verified: `k7dl_header_roundtrip_rust` in
/// `verif/Verif/Equiv/Transfer.lean` (Group E, on the Aeneas
/// translation of this function) — encode-then-parse is the identity
/// and neither half panics.
#[must_use]
pub fn k7dl_header_bytes(page_count: u32, mem_size: u64) -> [u8; K7DL_HEADER_SIZE] {
    let mut out = [0u8; K7DL_HEADER_SIZE];
    out[0..4].copy_from_slice(K7DL_MAGIC);
    out[4..8].copy_from_slice(&K7DL_VERSION.to_le_bytes());
    out[8..12].copy_from_slice(&page_count.to_le_bytes());
    out[12..20].copy_from_slice(&mem_size.to_le_bytes());
    // out[20..28] is the reserved u64; already zero.
    out
}

/// Decode a 28-byte K7DL header. Returns `(page_count, mem_size)` on success.
///
/// Verified: `k7dl_parse_header_equiv` in `verif/Verif/Equiv/K7dl.lean`
/// (Group E) — the Aeneas translation of this function computes
/// the `K7dlCodec.parseHeader` mirror, `DeltaError` variants included;
/// `k7dl_header_roundtrip_rust` in `verif/Verif/Equiv/Transfer.lean`
/// derives the round-trip with [`k7dl_header_bytes`].
pub fn k7dl_parse_header(b: &[u8; K7DL_HEADER_SIZE]) -> Result<(u32, u64), DeltaError> {
    // Byte-wise magic compare: `&b[0..4] != K7DL_MAGIC` would go through
    // `core::array::equality`'s Slice-vs-Array `PartialEq`, which Aeneas
    // leaves as a bodyless axiom — sinking the Group E
    // equivalence proof (CHALLENGES.md #24 standing rule).
    if b[0] != K7DL_MAGIC[0]
        || b[1] != K7DL_MAGIC[1]
        || b[2] != K7DL_MAGIC[2]
        || b[3] != K7DL_MAGIC[3]
    {
        return Err(DeltaError::BadMagic {
            got: [b[0], b[1], b[2], b[3]],
        });
    }
    let version = u32::from_le_bytes([b[4], b[5], b[6], b[7]]);
    if version != K7DL_VERSION {
        return Err(DeltaError::UnsupportedVersion { got: version });
    }
    let page_count = u32::from_le_bytes([b[8], b[9], b[10], b[11]]);
    let mem_size = u64::from_le_bytes([b[12], b[13], b[14], b[15], b[16], b[17], b[18], b[19]]);
    Ok((page_count, mem_size))
}

/// Encode a single K7DL entry: 4-byte little-endian page index followed by
/// the 4096-byte page. Inverse of [`k7dl_parse_entry`].
///
/// Verified: `k7dl_entry_roundtrip_rust` in
/// `verif/Verif/Equiv/Transfer.lean` (Group E, on the Aeneas
/// translation of this function) — encode-then-parse returns the exact
/// `(page_idx, page)` pair and neither half panics.
#[must_use]
pub fn k7dl_encode_entry(page_idx: u32, page: &[u8; 4096]) -> [u8; K7DL_ENTRY_SIZE] {
    let mut out = [0u8; K7DL_ENTRY_SIZE];
    out[0..4].copy_from_slice(&page_idx.to_le_bytes());
    out[4..].copy_from_slice(page);
    out
}

/// Decode a single K7DL entry. Returns `(page_idx, page)`.
///
/// Verified: `k7dl_parse_entry_equiv` in `verif/Verif/Equiv/K7dl.lean`
/// (Group E) — the Aeneas translation of this function computes
/// the `K7dlCodec.parseEntry` mirror; `k7dl_entry_roundtrip_rust` in
/// `verif/Verif/Equiv/Transfer.lean` derives the round-trip with
/// [`k7dl_encode_entry`].
#[must_use]
pub fn k7dl_parse_entry(b: &[u8; K7DL_ENTRY_SIZE]) -> (u32, [u8; 4096]) {
    let page_idx = u32::from_le_bytes([b[0], b[1], b[2], b[3]]);
    let mut page = [0u8; 4096];
    page.copy_from_slice(&b[4..]);
    (page_idx, page)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn k7dl_header_roundtrip_smoke() {
        let bytes = k7dl_header_bytes(7, 256 * 1024 * 1024);
        let (pc, ms) = k7dl_parse_header(&bytes).unwrap();
        assert_eq!(pc, 7);
        assert_eq!(ms, 256 * 1024 * 1024);
    }

    #[test]
    fn k7dl_header_bad_magic_rejected() {
        let mut bytes = k7dl_header_bytes(0, 0);
        bytes[0] = b'X';
        match k7dl_parse_header(&bytes) {
            Err(DeltaError::BadMagic { .. }) => {}
            other => panic!("expected BadMagic, got {other:?}"),
        }
    }

    #[test]
    fn k7dl_header_bad_version_rejected() {
        let mut bytes = k7dl_header_bytes(0, 0);
        bytes[4..8].copy_from_slice(&999u32.to_le_bytes());
        match k7dl_parse_header(&bytes) {
            Err(DeltaError::UnsupportedVersion { got: 999 }) => {}
            other => panic!("expected UnsupportedVersion(999), got {other:?}"),
        }
    }

    #[test]
    fn k7dl_entry_roundtrip_smoke() {
        let mut page = [0u8; 4096];
        for (i, b) in page.iter_mut().enumerate() {
            *b = (i & 0xff) as u8;
        }
        let bytes = k7dl_encode_entry(42, &page);
        let (idx, decoded) = k7dl_parse_entry(&bytes);
        assert_eq!(idx, 42);
        assert_eq!(decoded, page);
    }

    fn test_budget() -> TreeBudget {
        TreeBudget {
            max_live_vms: 2,
            max_live_ram_bytes: 1000,
            max_disk_bytes: 10_000,
            max_chain_depth: 1,
        }
    }

    fn node(id: u64, parent: Option<u64>, state: NodeState, last_active: u64) -> NodeInfo {
        NodeInfo {
            id,
            parent,
            children: Vec::new(),
            state,
            kind: PayloadKind::Vm,
            vm_count: 1,
            dirty_pages: 0,
            has_base_snapshot: false,
            last_active,
            protected: false,
            est_ram_bytes: 0,
            disk_bytes: 0,
        }
    }

    /// Chain 0 → 1 → 2 plus a sibling 3 of node 1, with children lists
    /// wired consistently.
    fn test_tree() -> TreeModel {
        let mut root = node(0, None, NodeState::Live, 10);
        root.children = vec![1, 3];
        let mut mid = node(1, Some(0), NodeState::Live, 20);
        mid.children = vec![2];
        let leaf = node(2, Some(1), NodeState::Live, 30);
        let sib = node(3, Some(0), NodeState::Live, 40);
        TreeModel {
            nodes: vec![root, mid, leaf, sib],
            budget: test_budget(),
        }
    }

    #[test]
    fn ram_soft_limit_is_85pct() {
        let b = test_budget();
        assert_eq!(b.ram_soft_limit(), 850);
    }

    #[test]
    fn ram_soft_limit_no_overflow_at_max() {
        let b = TreeBudget {
            max_live_vms: 0,
            max_live_ram_bytes: u64::MAX,
            max_disk_bytes: 0,
            max_chain_depth: 0,
        };
        // saturating_mul prevents overflow; result is u64::MAX/100*85.
        assert!(b.ram_soft_limit() < u64::MAX);
    }

    #[test]
    fn add_child_links_both_directions() {
        let t = test_tree();
        let t2 = add_child(&t, 2, 4, 99);
        let parent = &t2.nodes[find_index(&t2, 2).unwrap()];
        assert!(parent.children.contains(&4));
        assert_eq!(parent.last_active, 99);
        let child = &t2.nodes[find_index(&t2, 4).unwrap()];
        assert_eq!(child.parent, Some(2));
        assert_eq!(child.state, NodeState::Live);
    }

    #[test]
    fn add_child_missing_parent_is_noop() {
        let t = test_tree();
        let t2 = add_child(&t, 77, 4, 99);
        assert_eq!(t2.nodes.len(), t.nodes.len());
    }

    #[test]
    fn ancestor_ids_walks_to_root() {
        let t = test_tree();
        assert_eq!(ancestor_ids(&t, 2), vec![2, 1, 0]);
        assert_eq!(ancestor_ids(&t, 0), vec![0]);
    }

    #[test]
    fn restore_chain_depth_is_not_graph_depth() {
        // Root is a checkpoint; node 1 is a prepared fork source. Graph
        // depth of node 2 is 2, but its restore chain is 1 hop to its
        // prepared parent — the the referenced work distinction.
        let mut t = test_tree(); // chain 0 → 1 → 2, sibling 3
        t.nodes[0].has_base_snapshot = true;
        t.nodes[1].has_base_snapshot = true;
        assert_eq!(restore_chain_depth(&t, 2), Some(1));
        assert_eq!(restore_chain_depth(&t, 1), Some(0)); // checkpoint itself
        assert_eq!(restore_chain_depth(&t, 3), Some(1)); // 1 hop to root
    }

    #[test]
    fn restore_chain_depth_no_checkpoint_is_none() {
        let t = test_tree(); // no has_base_snapshot anywhere
        assert_eq!(restore_chain_depth(&t, 2), None);
        assert_eq!(restore_chain_depth(&t, 77), None); // missing node
    }

    #[test]
    fn over_disk_incoming_projects_headroom() {
        let mut t = test_tree(); // max_disk_bytes: 10_000
        t.nodes[0].disk_bytes = 9_000;
        assert!(!over_disk(&t));
        assert!(!over_disk_incoming(&t, 1_000));
        assert!(over_disk_incoming(&t, 1_001));
        assert!(over_disk_incoming(&t, u64::MAX)); // saturating, no overflow
    }

    #[test]
    fn implicitly_protected_covers_ancestors() {
        let mut t = test_tree();
        t.nodes[2].protected = true; // node id 2, chain 2 → 1 → 0
        let prot = implicitly_protected(&t);
        assert!(contains_id(&prot, 2));
        assert!(contains_id(&prot, 1));
        assert!(contains_id(&prot, 0));
        assert!(!contains_id(&prot, 3));
    }

    #[test]
    fn lru_live_victim_picks_least_recent_eligible() {
        let t = test_tree();
        // Node 0 has the smallest last_active (10).
        assert_eq!(lru_live_victim(&t, &[]), Some(0));
        // Exempting 0: node 1 (20) is next.
        assert_eq!(lru_live_victim(&t, &[0]), Some(1));
    }

    #[test]
    fn lru_live_victim_respects_protection() {
        let mut t = test_tree();
        t.nodes[2].protected = true; // protects 2 and ancestors 1, 0
        assert_eq!(lru_live_victim(&t, &[]), Some(3));
        assert_eq!(lru_live_victim(&t, &[3]), None);
    }

    #[test]
    fn leaf_subtree_requires_evicted_descendants() {
        let mut t = test_tree();
        // Suspend node 1; its descendant 2 is still Live → not evictable.
        t.nodes[1].state = NodeState::Suspended;
        assert_eq!(lru_evictable_leaf_subtree(&t), None);
        // Evict descendant 2 → node 1's subtree is now isolated.
        t.nodes[2].state = NodeState::Evicted;
        assert_eq!(lru_evictable_leaf_subtree(&t), Some(1));
    }

    #[test]
    fn leaf_subtree_skips_protected() {
        let mut t = test_tree();
        t.nodes[1].state = NodeState::Suspended;
        t.nodes[2].state = NodeState::Evicted;
        t.nodes[1].protected = true;
        assert_eq!(lru_evictable_leaf_subtree(&t), None);
    }

    #[test]
    fn usage_sums_live_nodes() {
        let mut t = test_tree();
        t.nodes[0].est_ram_bytes = 100;
        t.nodes[1].est_ram_bytes = 200;
        t.nodes[2].state = NodeState::Suspended;
        t.nodes[2].est_ram_bytes = 999; // not live → not counted
        t.nodes[3].disk_bytes = 50;
        let u = usage(&t);
        assert_eq!(u.live_ram_bytes, 300);
        assert_eq!(u.live_vm_count, 3);
        assert_eq!(u.live_node_count, 3);
        assert_eq!(u.disk_bytes, 50);
        assert_eq!(u.total_nodes, 4);
    }

    #[test]
    fn auto_evict_ram_reaches_budget() {
        let t = test_tree(); // 4 live VMs, max_live_vms = 2
        let t2 = auto_evict_ram(&t, &[]);
        let u = usage(&t2);
        assert_eq!(u.live_vm_count, 2);
        assert!(!over_count(&t2, 0));
        // LRU order: 0 (10) then 1 (20) get suspended.
        assert_eq!(t2.nodes[0].state, NodeState::Suspended);
        assert_eq!(t2.nodes[1].state, NodeState::Suspended);
        assert_eq!(t2.nodes[2].state, NodeState::Live);
        assert_eq!(t2.nodes[3].state, NodeState::Live);
    }

    #[test]
    fn auto_evict_ram_stops_when_all_protected() {
        let mut t = test_tree();
        let mut i = 0;
        while i < t.nodes.len() {
            t.nodes[i].protected = true;
            i += 1;
        }
        let t2 = auto_evict_ram(&t, &[]);
        // Nothing evictable; still over budget but every node protected.
        assert_eq!(usage(&t2).live_vm_count, 4);
    }
}
