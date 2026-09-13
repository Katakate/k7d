//! Snapshot tree for tree-shaped VM exploration (part 2).
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

use crate::guest::Guest;
use crate::snapshot::{self, VmState};
use crate::tree_model::{
    self, k7dl_base_identity, k7dl_encode_entry, k7dl_header_bytes, k7dl_parse_entry,
    k7dl_parse_header, k7dl_set_base_identity, DeltaError, K7DL_ENTRY_SIZE, K7DL_HEADER_SIZE,
};
use crate::vm::{Vm, VmError};

// Re-export the pure model types so external callers (tests, other crates)
// keep using `k7d::tree::{NodeState, TreeBudget, TreeUsage, ...}` after the
// refactor with no source-level changes. `NodeId` / `NodeInfo` are the
// orchestrator-side (String-keyed, serde) types defined below — since the
// pure-model rewrite, `tree_model::NodeInfo` is the `u64`-keyed pure
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
/// added in — older `tree.json` files (no `kind`/`vm_count`) load
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
    /// Whether this node **owns** a `memory.bin` (checkpoint). Distinct
    /// from `Vm::fork_source_base_path`: an in-tree child can `fork_warm`
    /// against an ancestor file without owning a keyframe.
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
    /// Payload kind (Vm or Cluster). Defaults to Vm so legacy
    /// `tree.json` files load unchanged.
    #[serde(default)]
    pub kind: PayloadKind,
    /// Number of *underlying* VMs this payload represents.
    /// 1 for a single-VM payload; N for a cluster of N members.
    /// Defaults to 1 so legacy `tree.json` files load unchanged.
    #[serde(default = "default_vm_count")]
    pub vm_count: u32,
    /// While this node is **Suspended**: the `.k7d-blk-fork-*`
    /// directories holding the reflinked RW disk images its member
    /// VM(s) were running on (one entry per member that had one).
    /// Suspend takes them out of the `Vm` before Drop — they ARE the
    /// node's disk state; resume reflinks fresh copies from them and
    /// then removes them; prune of a suspended node removes them
    /// (CHALLENGES.md #130); eviction does too (bug-candidates #52).
    /// Empty for live, Evicted, and legacy files.
    #[serde(default)]
    pub parked_disk_dirs: Vec<PathBuf>,
    /// Generation of this node's `memory.bin`, minted afresh every time
    /// a keyframe is written here. A `delta.pack` records the identity
    /// of the base it was diffed against, and `resume` refuses to apply
    /// one whose identity is not this (CHALLENGES #144). 0 means
    /// "unknown": legacy `tree.json` files and v1 packs.
    #[serde(default)]
    pub base_identity: u64,
    /// Physical bytes this node's `memory.bin` cost the filesystem.
    ///
    /// An incremental keyframe is a reflink clone of its
    /// ancestor plus the dirty pages, so its *logical* length is the
    /// full guest-physical span while it physically adds only the dirt.
    /// `st_blocks` does not help — XFS counts a shared extent in every
    /// file that references it — so the daemon records the true cost at
    /// write time and [`SnapshotTree::usage`] sums that. `None` is a
    /// legacy `tree.json` with no record; those fall back to the file's
    /// logical length, which is what they cost.
    #[serde(default)]
    pub base_disk_bytes: Option<u64>,
}

fn default_vm_count() -> u32 {
    1
}

/// What a `prepare_fork_source` call actually did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PrepareOutcome {
    /// `true` when this call wrote a new keyframe; `false` when the node
    /// was already a fork source (idempotent no-op).
    pub wrote_base: bool,
    /// `true` when the keyframe was written incrementally — `FICLONE` of
    /// the nearest ancestor's `memory.bin` plus the dirty pages —
    /// rather than as a full O(guest RAM) dump.
    pub incremental: bool,
    /// Physical bytes the keyframe added to the filesystem: the dirty
    /// set on the incremental path, the whole guest span on the full
    /// one, 0 for an idempotent no-op. Reported rather than measured
    /// because a reflinked file's `stat` and `du` both lie about it
    /// (CHALLENGES #152).
    pub disk_bytes: u64,
}

impl PrepareOutcome {
    /// The idempotent no-op: nothing was written.
    #[must_use]
    pub fn already_prepared() -> Self {
        Self {
            wrote_base: false,
            incremental: false,
            disk_bytes: 0,
        }
    }
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
    /// The tree's cgroup jail could not be built or
    /// could not take one of the tree's VMs. Loud on purpose: a tree
    /// silently running outside its jail is the failure this increment
    /// exists to prevent.
    #[error("tree jail: {0}")]
    Jail(String),
    /// A Firecracker-backend failure surfaced through a shared `Guest`
    /// verb. Its own variant rather than folded into
    /// `InvalidDelta` so the message blames the VMM it came from
    /// instead of a delta file the caller never wrote.
    #[error("firecracker: {0}")]
    Firecracker(String),
    #[error(
        "node {node} has no checkpoint ancestor to resume from \
         (restore-chain depth {depth}, limit {max}); resume maps exactly one \
         `memory.bin` and applies this node's delta.pack — unprepared hops \
         in between are not extra packs"
    )]
    ChainTooDeep {
        node: NodeId,
        depth: usize,
        max: usize,
    },
}

impl From<DeltaError> for TreeError {
    fn from(e: DeltaError) -> Self {
        TreeError::InvalidDelta(e.to_string())
    }
}

impl From<crate::cgroup::CgroupError> for TreeError {
    fn from(e: crate::cgroup::CgroupError) -> Self {
        TreeError::Jail(e.to_string())
    }
}

impl From<crate::guest::GuestError> for TreeError {
    fn from(e: crate::guest::GuestError) -> Self {
        match e {
            crate::guest::GuestError::Vm(inner) => Self::Vm(inner),
            crate::guest::GuestError::Fork(inner) => Self::Fork(inner),
            crate::guest::GuestError::Snapshot(inner) => Self::Snapshot(inner),
            crate::guest::GuestError::Unsupported { backend, op } => {
                Self::InvalidDelta(format!("{op} is not supported on backend {backend:?}"))
            }
            crate::guest::GuestError::Fc(inner) => Self::Firecracker(inner.to_string()),
        }
    }
}

impl From<crate::fc::FcError> for TreeError {
    fn from(e: crate::fc::FcError) -> Self {
        Self::Firecracker(e.to_string())
    }
}

fn fc_err(e: &crate::fc::FcError) -> TreeError {
    TreeError::Firecracker(e.to_string())
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
    /// Live guests owned by the tree, keyed by node id.
    live_vms: HashMap<NodeId, Guest>,
    created_at_unix: u64,
    next_id: u64,
    /// Orchestrator `String → u64` id map into the pure model.
    /// Ids are minted monotonically at node creation, so a child's pure id
    /// is always greater than its parent's (the `parentLt` invariant the
    /// Lean proofs' `well_formed` relies on). Not persisted — rebuilt from
    /// scratch when a tree is reconstructed.
    pure_ids: HashMap<NodeId, u64>,
    next_pure_id: u64,
    /// For each live node: the node whose `memory.bin` its VM is a
    /// `MAP_PRIVATE` mapping of, and the generation of that keyframe.
    ///
    /// This is what makes an incremental keyframe sound —
    /// "the pages that differ from the ancestor base" is only the VM's
    /// accumulated dirty set if the VM really was materialized from that
    /// exact generation. Runtime-only: a suspended node has no mapping,
    /// and a rebuilt tree re-records at resume.
    cow_base: HashMap<NodeId, (NodeId, u64)>,
    /// Whether this tree's storage can `FICLONE`.
    ///
    /// Probed once at construction rather than discovered per keyframe,
    /// because the disk budget has to *project* a keyframe's cost before
    /// writing it: projecting the O(divergence) cost on a filesystem
    /// that is about to force a full dump would let the write blow
    /// `max_disk_bytes`. The per-write `EXDEV`/`EOPNOTSUPP` fallback
    /// stays as the backstop.
    reflink_root: bool,
    /// This tree's cgroup jail. `None` only when
    /// `K7D_TREE_CGROUP=off`. Declared after `live_vms` so the VMs (and
    /// their threads) are gone before the cgroup is removed.
    jail: Option<crate::cgroup::TreeCgroup>,
}

impl SnapshotTree {
    /// Put a live node's VM into the tree's cgroup jail. A no-op when
    /// the jail is off; a hard error when the node is not live, since
    /// every caller has just inserted it.
    fn jail_vm(&self, node_id: &NodeId) -> Result<(), TreeError> {
        let Some(jail) = &self.jail else {
            return Ok(());
        };
        let vm = self
            .live_vms
            .get(node_id)
            .ok_or_else(|| TreeError::NodeNotFound(node_id.clone()))?;
        if let Guest::Firecracker(fc) = vm {
            // The jailer already put this VMM in its own cgroup with
            // the pod's `cpu.max` and a `memory.max`; the tree jail
            // holds *daemon threads*, and this VM has none.
            log::info!(
                "tree: node '{node_id}' runs on Firecracker (pid {}) — capped by the \
                 jailer's cgroup {}, not the tree jail",
                fc.pid(),
                fc.cgroup_dir().display()
            );
            return Ok(());
        }
        jail.add_vm(vm.as_native()?)?;
        Ok(())
    }

    /// Whether `node_id`'s live guest is a Firecracker VM.
    fn is_fc(&self, node_id: &NodeId) -> bool {
        matches!(self.live_vms.get(node_id), Some(Guest::Firecracker(_)))
    }

    /// Create a new tree rooted at a running native VM.
    ///
    /// The root VM is prepared as a fork source (cold snapshot + restore +
    /// dirty tracking). The returned root `NodeId` is a checkpoint (owns a
    /// `base.mem`) and starts in state `Live`.
    pub fn new(
        root_vm: Vm,
        root_dir: PathBuf,
        budget: TreeBudget,
    ) -> Result<(Self, NodeId), TreeError> {
        Self::new_guest(Guest::from(root_vm), root_dir, budget)
    }

    /// Create a new tree rooted at a running guest of either backend.
    /// A tree is single-backend: every node forked
    /// from this root runs on the root's VMM.
    ///
    /// Native roots take the cold snapshot + restore into the node
    /// directory; Firecracker roots take a snapshot point in their
    /// chroot ([`crate::fc::FcVm::prepare_fork_source`]). Either way
    /// the root is a checkpoint and starts `Live`.
    pub fn new_guest(
        mut root: Guest,
        root_dir: PathBuf,
        budget: TreeBudget,
    ) -> Result<(Self, NodeId), TreeError> {
        fs::create_dir_all(root_dir.join("nodes"))?;
        let root_dir_for_probe = root_dir.clone();
        let tree_id = format!("tree-{}", std::process::id());
        let now = now_unix();

        // Give the root node a predictable id and its own directory.
        let root_id: NodeId = "root".to_string();
        let root_node_dir = root_dir.join("nodes").join(&root_id);
        fs::create_dir_all(&root_node_dir)?;

        let root_span = match &mut root {
            Guest::Native(root_vm) => {
                // Prepare the VM as a fork source into the node's
                // directory. This writes base.mem, cpu.json,
                // devices.json, metadata.json, irqchip.json into
                // `root_node_dir` and restores the VM from them.
                //
                // Tree roots with virtiofs shares knowingly take the
                // slow (full-memfd) fork path — the explicit opt-in
                // requires (loud warn inside `allow_slow_fork`).
                if !root_vm.virtiofs_shares().is_empty() {
                    root_vm.allow_slow_fork();
                }
                root_vm.prepare_fork_source_in(&root_node_dir)?;
                root_vm.mem_span()
            }
            Guest::Firecracker(fc) => {
                let report = fc.prepare_fork_source().map_err(|e| fc_err(&e))?;
                log::info!(
                    "tree: Firecracker root point {} ({} bytes)",
                    report.restore_mem.display(),
                    report.diff_bytes
                );
                report.diff_bytes
            }
        };

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
            parked_disk_dirs: Vec::new(),
            // The root's keyframe is a full dump, so it physically
            // costs its whole span. Generation 1 is the first identity
            // this tree mints (0 is reserved for "unknown").
            base_identity: 1,
            base_disk_bytes: Some(root_span),
        };

        let mut nodes = HashMap::new();
        nodes.insert(root_id.clone(), info);

        let mut live_vms = HashMap::new();
        live_vms.insert(root_id.clone(), root);

        let mut pure_ids = HashMap::new();
        pure_ids.insert(root_id.clone(), 0);

        let jail = crate::cgroup::TreeCgroup::create(&tree_id, budget)?;
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
            // The root's VM maps its own freshly written keyframe, so a
            // re-prepare of the root would have nothing above it to
            // clone — leave it unrecorded and let it take the full dump.
            cow_base: HashMap::new(),
            reflink_root: probe_reflink_root(&root_dir_for_probe),
            jail,
        };
        tree.jail_vm(&root_id)?;
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

    /// Derive the pure [`tree_model::TreeModel`] view of this tree.
    /// The verified eviction helpers (`tree_model::lru_live_victim`,
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
            let est_ram_bytes = self
                .live_vms
                .get(&info.id)
                .map_or(0, Guest::est_private_bytes);
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
    pub fn find_live_vm_by_cid(&self, cid: u64) -> Option<(&str, &Guest)> {
        self.live_vms
            .iter()
            .find(|(_, vm)| vm.guest_cid() == Some(cid))
            .map(|(id, vm)| (id.as_str(), vm))
    }

    /// The keyframe this node's live VM is a `MAP_PRIVATE` mapping of,
    /// if it is still the file the tree recorded at fork/resume time.
    ///
    /// An incremental keyframe is only correct when the VM's memory
    /// really is that file plus the VM's accumulated dirty set, so the
    /// answer comes from what the tree *did* (`cow_base`), not from the
    /// topology: an ancestor that has re-prepared since holds a new
    /// generation at the same path, and cloning it would produce a
    /// keyframe that is neither the ancestor nor this node. Such a node
    /// falls back to the full dump.
    fn cow_base_keyframe(&self, node_id: &NodeId) -> Option<PathBuf> {
        if !self.reflink_root {
            return None;
        }
        let (ancestor, identity) = self.cow_base.get(node_id)?;
        if self.nodes.get(ancestor)?.base_identity != *identity {
            log::warn!(
                "tree: node '{node_id}' was forked off '{ancestor}' generation \
                 {identity}, which has since re-prepared — writing a full keyframe"
            );
            return None;
        }
        let mem = self.node_dir(ancestor).join("memory.bin");
        mem.is_file().then_some(mem)
    }

    /// Record that `node_id`'s VM maps `ancestor`'s current keyframe.
    fn record_cow_base(&mut self, node_id: &NodeId, ancestor: &NodeId) {
        let Some(identity) = self.nodes.get(ancestor).map(|n| n.base_identity) else {
            return;
        };
        self.cow_base
            .insert(node_id.clone(), (ancestor.clone(), identity));
    }

    /// The next unused base-generation number for this tree.
    ///
    /// Derived from the records rather than a counter so it survives a
    /// `tree.json` round-trip without another persisted field. Never 0 —
    /// that value means "unknown" to [`tree_model::k7dl_base_identity_ok`].
    fn mint_base_identity(&self) -> u64 {
        self.nodes
            .values()
            .map(|n| n.base_identity)
            .max()
            .unwrap_or(0)
            + 1
    }

    /// Make `source_id` legal for `fork_warm` without writing a keyframe.
    ///
    /// A live child already maps its nearest checkpoint's `memory.bin`
    /// plus an accumulated dirty bitmap. Point `fork_source_base_path`
    /// at that file and let `fork_warm` memcpy dirty pages in-process.
    /// Write a new keyframe only when no ancestor file exists, or when
    /// the VM has virtiofs shares (FUSE DMA is invisible to the dirty
    /// log — inherit would fork a stale file).
    fn ensure_forkable(&mut self, source_id: &NodeId) -> Result<(), TreeError> {
        let (already, virtiofs) = {
            let vm = self
                .live_vms
                .get(source_id)
                .ok_or_else(|| TreeError::NodeNotFound(source_id.clone()))?;
            (
                vm.as_native()?.fork_source_base_path().is_some(),
                !vm.virtiofs_shares().is_empty(),
            )
        };
        if already {
            return Ok(());
        }
        // Virtiofs FUSE DMA is invisible to the dirty log — inherit
        // would fork a stale file. Write a keyframe instead.
        if !virtiofs {
            if let Ok(ckpt) = self.nearest_checkpoint(source_id) {
                if ckpt != *source_id {
                    if let Some(mem) = {
                        let p = self.node_dir(&ckpt).join("memory.bin");
                        p.is_file().then_some(p)
                    } {
                        let vm = self
                            .live_vms
                            .get_mut(source_id)
                            .ok_or_else(|| TreeError::NodeNotFound(source_id.clone()))?;
                        let dirty = vm.as_native()?.accumulated_dirty_pages().unwrap_or(0);
                        log::info!(
                            "tree: inherit {ckpt}/memory.bin on {source_id} \
                             ({dirty} dirty pages, no new keyframe)"
                        );
                        vm.as_native_mut()?.set_fork_source_base_path(mem);
                        return Ok(());
                    }
                }
            }
        }
        self.prepare_fork_source(source_id)?;
        Ok(())
    }

    /// Snapshot a live node so later forks from it take the warm path
    /// against *this* node's `memory.bin` (dirty set reset).
    ///
    /// Root is prepared at [`Self::new`]. In-tree children inherit an
    /// ancestor path at fork and are not checkpoints until
    /// this runs. Idempotent on `has_base_snapshot` — an inherited
    /// `fork_source_base_path` is not a keyframe this node owns, so a
    /// later explicit prepare still writes (CHALLENGES.md #59, #182).
    ///
    /// A child with a checkpoint ancestor takes the **incremental**
    /// path: `FICLONE` that ancestor's `memory.bin` and overwrite only
    /// the pages this node has dirtied since it was forked off it,
    /// so a fork point down the tree costs O(divergence). Root, virtiofs
    /// VMs, and any node whose ancestor keyframe is on a different (or
    /// non-reflink) filesystem fall back to the full dump — loudly.
    pub fn prepare_fork_source(&mut self, node_id: &NodeId) -> Result<PrepareOutcome, TreeError> {
        self.ensure_live(node_id)?;
        if self.is_fc(node_id) {
            return self.prepare_fork_source_fc(node_id);
        }
        if self.nodes.get(node_id).is_some_and(|n| n.has_base_snapshot) {
            return Ok(PrepareOutcome::already_prepared());
        }
        let dir = self.node_dir(node_id);
        let ancestor_mem = self.cow_base_keyframe(node_id);
        // Make disk headroom BEFORE writing — `usage()`
        // only sees the keyframe after the fact, so without this the
        // write silently blows `max_disk_bytes` until the next
        // auto_evict. On the incremental path the projection is the
        // dirty estimate, not the whole span: projecting a full dump
        // there would evict nodes to make room for disk we will not use.
        {
            let vm = self
                .live_vms
                .get(node_id)
                .ok_or_else(|| TreeError::NodeNotFound(node_id.clone()))?;
            let projected = if ancestor_mem.is_some() {
                vm.est_private_bytes()
            } else {
                vm.as_native()?.mem_span()
            };
            self.evict_disk_for_incoming(projected)?;
        }
        let vm = self
            .live_vms
            .get_mut(node_id)
            .ok_or_else(|| TreeError::NodeNotFound(node_id.clone()))?;
        if !vm.virtiofs_shares().is_empty() {
            vm.as_native_mut()?.allow_slow_fork();
        }
        log::info!("tree: prepare_fork_source({node_id})");
        let prepared = if let Some(ancestor) = &ancestor_mem {
            vm.as_native_mut()?
                .prepare_fork_source_incremental_in(&dir, ancestor)?
        } else {
            let native = vm.as_native_mut()?;
            let span = native.mem_span();
            crate::vm::PreparedBase::full(native.prepare_fork_source_in(&dir)?, span)
        };
        let identity = self.mint_base_identity();
        if let Some(info) = self.nodes.get_mut(node_id) {
            info.has_base_snapshot = true;
            info.base_identity = identity;
            info.base_disk_bytes = Some(prepared.disk_bytes);
            touch(info);
        }
        self.save_metadata()?;
        Ok(PrepareOutcome {
            wrote_base: true,
            incremental: prepared.incremental,
            disk_bytes: prepared.disk_bytes,
        })
    }

    /// Firecracker half of [`Self::prepare_fork_source`]: a snapshot
    /// point in the VM's chroot. Not idempotent on
    /// `has_base_snapshot` the way the native path is — an FC fork
    /// always loads a *file*, so the point has to be re-taken whenever
    /// the guest has dirtied anything; the VM reports `wrote: false`
    /// itself when it has not.
    fn prepare_fork_source_fc(&mut self, node_id: &NodeId) -> Result<PrepareOutcome, TreeError> {
        let projected = self
            .live_vms
            .get(node_id)
            .map_or(0, Guest::est_private_bytes);
        self.evict_disk_for_incoming(projected)?;
        let Some(Guest::Firecracker(fc)) = self.live_vms.get_mut(node_id) else {
            return Err(TreeError::NodeNotFound(node_id.clone()));
        };
        log::info!("tree: prepare_fork_source({node_id}) on Firecracker");
        let report = fc.prepare_fork_source().map_err(|e| fc_err(&e))?;
        if report.wrote {
            let identity = self.mint_base_identity();
            if let Some(info) = self.nodes.get_mut(node_id) {
                info.has_base_snapshot = true;
                info.base_identity = identity;
                info.base_disk_bytes = Some(report.diff_bytes);
                touch(info);
            }
            self.save_metadata()?;
        }
        Ok(PrepareOutcome {
            wrote_base: report.wrote,
            incremental: report.incremental,
            disk_bytes: report.diff_bytes,
        })
    }

    /// Firecracker half of [`Self::fork_batch`] and [`Self::rollback`]:
    /// take a point (unless `from_point` says to reuse the current one)
    /// and load one child per label from it. The same `NodeInfo`
    /// bookkeeping as the native path; none of its dirty-bitmap or
    /// `cow_base` state, which describes `MAP_PRIVATE` mappings this
    /// backend does not have.
    fn fork_batch_fc(
        &mut self,
        source_id: &NodeId,
        labels: &[&str],
        dilation: Option<u32>,
        from_point: bool,
    ) -> Result<Vec<NodeId>, TreeError> {
        if dilation.is_some() {
            return Err(TreeError::Firecracker(
                "time dilation is not supported on Firecracker nodes".to_string(),
            ));
        }
        let children = {
            let Some(Guest::Firecracker(fc)) = self.live_vms.get_mut(source_id) else {
                return Err(TreeError::NodeNotFound(source_id.clone()));
            };
            if from_point {
                let mut out = Vec::with_capacity(labels.len());
                for _ in labels {
                    out.push(fc.rollback_child().map_err(|e| fc_err(&e))?);
                }
                out
            } else {
                fc.fork_batch(labels.len()).map_err(|e| fc_err(&e))?.1
            }
        };
        // The point the children loaded is the source's checkpoint. A
        // fresh point is a new generation; a rollback reuses the old one.
        let point_bytes = match self.live_vms.get(source_id) {
            Some(Guest::Firecracker(fc)) => fc.point_diff_bytes(),
            _ => 0,
        };
        let identity = self.mint_base_identity();
        if let Some(info) = self.nodes.get_mut(source_id) {
            if !from_point || !info.has_base_snapshot {
                info.base_identity = identity;
            }
            info.has_base_snapshot = true;
            info.base_disk_bytes = Some(point_bytes);
        }

        let mut new_ids = Vec::with_capacity(children.len());
        let now = now_unix();
        for (child, label) in children.into_iter().zip(labels.iter()) {
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
                parked_disk_dirs: Vec::new(),
                base_identity: 0,
                base_disk_bytes: None,
            };
            self.nodes.insert(new_id.clone(), info);
            self.live_vms.insert(new_id.clone(), Guest::from(child));
            self.jail_vm(&new_id)?;
            if let Some(src) = self.nodes.get_mut(source_id) {
                src.children.push(new_id.clone());
                touch(src);
            }
            new_ids.push(new_id);
        }
        self.save_metadata()?;
        self.evict_post_fork(source_id, &new_ids)?;
        Ok(new_ids)
    }

    /// Fork a new branch from any live or suspended node.
    pub fn fork(&mut self, source_id: &NodeId, label: &str) -> Result<NodeId, TreeError> {
        let ids = self.fork_batch(source_id, &[label], None)?;
        Ok(ids.into_iter().next().expect("single fork"))
    }

    /// Fork N branches from the same source (batch optimization).
    pub fn fork_batch(
        &mut self,
        source_id: &NodeId,
        labels: &[&str],
        dilation: Option<u32>,
    ) -> Result<Vec<NodeId>, TreeError> {
        self.ensure_live(source_id)?;
        // Make headroom for the `labels.len()` incoming live VMs
        // (CHALLENGES #115): suspend LRU non-protected live VMs
        // until `live_vm_count + incoming` fits `max_live_vms`, exempting
        // the source. Fails loud (`BudgetExhausted`) if everything else is
        // protected — never hangs the caller.
        self.evict_for_incoming(source_id, labels.len())?;
        // evict_for_incoming may have suspended things; re-verify.
        self.ensure_live(source_id)?;
        if self.is_fc(source_id) {
            return self.fork_batch_fc(source_id, labels, dilation, false);
        }
        // In-tree forks inherit the ancestor keyframe + dirty bitmap.
        // Do not write a new memory.bin / restore-swap on the source.
        self.ensure_forkable(source_id)?;

        let (forks, source_bitmap_at_fork, source_base) = {
            let source_vm = self
                .live_vms
                .get_mut(source_id)
                .ok_or_else(|| TreeError::NodeNotFound(source_id.clone()))?;
            let forks = source_vm.fork_batch(labels, dilation)?;
            // Snapshot the source's accumulated dirty bitmap AFTER
            // fork_warm_batch returns (updated in place). Children seed
            // this so their suspend delta covers pre-fork dirty pages
            // memcpy'd into the CoW mapping.
            let bitmap = source_vm
                .as_native()?
                .accumulated_dirty_bitmap()
                .unwrap_or_default();
            let base = source_vm
                .as_native()?
                .fork_source_base_path()
                .map(std::path::Path::to_path_buf);
            (forks, bitmap, base)
        };
        let cow_ancestor = self.nearest_checkpoint(source_id)?;

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
                parked_disk_dirs: Vec::new(),
                base_identity: 0,
                base_disk_bytes: None,
            };

            // Start the fork's vCPU; the tree owns it from here.
            let mut fork_vm = fork_vm;
            fork_vm.start()?;
            fork_vm.as_native_mut()?.enable_dirty_tracking()?;
            // Seed the fork's accumulated bitmap with the source's bitmap
            // at fork time — see comment above on the source.
            fork_vm
                .as_native_mut()?
                .seed_accumulated_dirty(&source_bitmap_at_fork)?;
            if let Some(base) = &source_base {
                fork_vm
                    .as_native_mut()?
                    .set_fork_source_base_path(base.clone());
            }

            self.nodes.insert(new_id.clone(), info);
            self.live_vms.insert(new_id.clone(), fork_vm);
            // Child maps the checkpoint's memory.bin, not a new keyframe.
            self.record_cow_base(&new_id, &cow_ancestor);
            self.jail_vm(&new_id)?;
            if let Some(src) = self.nodes.get_mut(source_id) {
                src.children.push(new_id.clone());
                touch(src);
            }
            new_ids.push(new_id);
        }
        self.save_metadata()?;

        // Resume applies one delta.pack onto the nearest checkpoint, so
        // unprepared hops in between are not extra packs. The child must
        // be forkable (inherited or prepared path) and have a checkpoint.
        #[cfg(debug_assertions)]
        for id in &new_ids {
            debug_assert!(
                self.nearest_checkpoint(id).is_ok(),
                "fork_batch child {id} has no checkpoint ancestor"
            );
            debug_assert!(
                self.live_vms.get(id).is_some_and(|vm| vm
                    .as_native()
                    .is_ok_and(|n| n.fork_source_base_path().is_some())),
                "fork_batch child {id} is not forkable"
            );
        }

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

    /// Non-destructive rollback: create a new branch from `node_id`'s
    /// **restore point**. The original node is untouched.
    ///
    /// Native: equivalent to `fork` (a warm fork always captures the
    /// current state, and the native node's state *is* its keyframe
    /// plus dirty pages). Firecracker: a child of the node's latest
    /// snapshot point without taking a new one, so a source that has
    /// diverged since `prepare_fork_source` yields a child equal to the
    /// point, not to the source.
    pub fn rollback(&mut self, node_id: &NodeId, label: &str) -> Result<NodeId, TreeError> {
        self.ensure_live(node_id)?;
        if self.is_fc(node_id) {
            self.evict_for_incoming(node_id, 1)?;
            self.ensure_live(node_id)?;
            let ids = self.fork_batch_fc(node_id, &[label], None, true)?;
            return Ok(ids.into_iter().next().expect("single rollback"));
        }
        self.fork(node_id, label)
    }

    /// Suspend a live VM: save dirty delta + CPU state to disk, free RAM.
    ///
    /// Firecracker: pause → Full snapshot into the node dir → drop the
    /// process. Native: `delta.pack` + `vm_state.json`.
    ///
    /// Fails loud for virtiofs-backed VMs: virtiofsd writes FUSE
    /// completions through its own mapping, invisible to KVM dirty
    /// tracking, so `delta.pack` would silently miss device DMA and the
    /// resumed guest would corrupt (limitation).
    pub fn suspend(&mut self, node_id: &NodeId) -> Result<(), TreeError> {
        if self.is_fc(node_id) {
            return self.suspend_fc(node_id);
        }
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
        let native = vm.as_native_mut()?;
        let bitmap = native.get_and_accumulate_dirty()?.to_vec();
        let state = snapshot::capture_vm_state(native)?;
        let src_mem = native.mem_host_addr();
        // Deltas index pages of the guest physical span, not of RAM.
        let mem_size = native.mem_span();

        // Name the keyframe this pack is a diff against, so a resume
        // onto a base that has since re-prepared fails loud instead of
        // scattering the pack's pages over a stranger's memory
        // (CHALLENGES #144). A checkpoint's own pack sits on its own
        // `memory.bin`.
        let base_identity = self
            .nearest_checkpoint(node_id)
            .ok()
            .and_then(|base| self.nodes.get(&base).map(|n| n.base_identity))
            .unwrap_or(0);

        // Write delta + vm_state.json. Then drop the VM (munmap memory, close fds).
        let dirty_pages = write_delta(
            &node_dir.join("delta.pack"),
            &bitmap,
            src_mem,
            mem_size,
            base_identity,
        )?;
        let state_json = serde_json::to_string(&state)?;
        atomic_write(&node_dir.join("vm_state.json"), state_json.as_bytes())?;

        // A forked VM's RW disk images live in a directory the Vm owns
        // (removed on Drop) — but they ARE this node's disk state, and
        // `vm_state.json` above records their paths for resume's
        // reflink. Park ownership on the node record before dropping
        // the Vm (CHALLENGES.md #130).
        let parked = vm.as_native_mut()?.take_fork_state_dir();
        drop(vm);
        // No mapping, no CoW base — resume re-records one.
        self.cow_base.remove(node_id);

        if let Some(info) = self.nodes.get_mut(node_id) {
            info.state = NodeState::Suspended;
            info.dirty_page_count = dirty_pages;
            info.parked_disk_dirs = parked.into_iter().collect();
            touch(info);
        }
        self.save_metadata()?;
        log::info!("tree: suspended node '{node_id}' ({dirty_pages} dirty pages)");
        Ok(())
    }

    fn suspend_fc(&mut self, node_id: &NodeId) -> Result<(), TreeError> {
        let mut vm = self
            .live_vms
            .remove(node_id)
            .ok_or_else(|| TreeError::NodeNotFound(node_id.clone()))?;
        let node_dir = self.node_dir(node_id);
        fs::create_dir_all(&node_dir)?;
        if let Err(e) = vm.snapshot(&node_dir) {
            self.live_vms.insert(node_id.clone(), vm);
            return Err(e.into());
        }
        let exported = crate::fc::exported_snapshot_bytes(&node_dir);
        drop(vm);
        self.cow_base.remove(node_id);
        if let Some(info) = self.nodes.get_mut(node_id) {
            info.state = NodeState::Suspended;
            info.dirty_page_count = 0;
            info.parked_disk_dirs = Vec::new();
            info.base_disk_bytes = Some(exported);
            touch(info);
        }
        self.save_metadata()?;
        log::info!("tree: suspended Firecracker '{node_id}' ({exported} bytes exported)");
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
        if self
            .node_dir(node_id)
            .join(crate::fc::SUSPEND_META)
            .is_file()
        {
            return self.resume_fc(node_id);
        }

        // Resume applies exactly one delta.pack onto the nearest
        // checkpoint's memory.bin. Unprepared hops on the parent path
        // are not extra packs (in-tree inherit). Fail loud only when
        // there is no checkpoint file to map.
        if self.nearest_checkpoint(node_id).is_err() {
            let chain = self.restore_chain_depth(node_id).unwrap_or(usize::MAX);
            return Err(TreeError::ChainTooDeep {
                node: node_id.clone(),
                depth: chain,
                max: 0,
            });
        }

        // Reserve headroom for the VM we're about to bring back to Live.
        self.evict_for_incoming_no_exempt(1)?;

        // Find the nearest ancestor with a memory.bin (checkpoint).
        let base_node = self.nearest_checkpoint(node_id)?;
        let base_path = self.node_dir(&base_node).join("memory.bin");
        let base_identity = self
            .nodes
            .get(&base_node)
            .map_or(0, |info| info.base_identity);

        // Load state + delta, materialize the VM.
        let node_dir = self.node_dir(node_id);
        let state_json = fs::read_to_string(node_dir.join("vm_state.json"))?;
        let state: VmState = serde_json::from_str(&state_json)?;

        let mem_span = crate::mem_layout::MemLayout::from_ram(state.memory_size).span();
        let fork_mem_addr = crate::fork::mmap_base_mem_private(&base_path, mem_span)?;

        // Apply this node's delta on top of base.mem. (If the node is the same
        // as base_node — i.e. a checkpoint that also has a delta — we skip.)
        let applied = if base_node == *node_id {
            AppliedDelta::empty(mem_span)
        } else {
            apply_delta(
                &node_dir.join("delta.pack"),
                fork_mem_addr,
                mem_span,
                base_identity,
            )?
        };

        let mut vm = crate::fork::build_vm_from_state_and_mem(
            &state,
            fork_mem_addr,
            &format!("resume:{node_id}"),
        )?;
        vm.start()?;
        vm.enable_dirty_tracking()?;
        // The pack's pages are exactly this VM's divergence from
        // `base_path`. Dirty tracking restarts empty, so without this
        // re-seed the *next* suspend writes a pack that covers only what
        // the guest touched after resume, and the pages restored here
        // silently revert to the base — a suspend→resume→suspend cycle
        // would lose them (CHALLENGES #143). Same reason a fork child
        // seeds from its source's bitmap.
        vm.seed_accumulated_dirty(&applied.bitmap)?;
        // The mapping is always `MAP_PRIVATE` of the nearest
        // checkpoint's `memory.bin` (own file if this node is the
        // checkpoint). Set the path so the next fork inherits instead
        // of writing a keyframe. A checkpoint keeps `has_base_snapshot`
        // so a later prepare is still a no-op (CHALLENGES #144).
        vm.set_fork_source_base_path(base_path.clone());

        self.live_vms.insert(node_id.clone(), Guest::from(vm));
        self.record_cow_base(node_id, &base_node);
        self.jail_vm(node_id)?;
        if let Some(info) = self.nodes.get_mut(node_id) {
            info.state = NodeState::Live;
            // The resumed VM reflinked its own copies of the RW images
            // out of the parked directory (suspend, above); the parked
            // originals are now dead weight — remove them.
            for dir in std::mem::take(&mut info.parked_disk_dirs) {
                fs::remove_dir_all(&dir)?;
            }
            touch(info);
        }
        self.save_metadata()?;
        log::info!("tree: resumed node '{node_id}'");
        Ok(())
    }

    fn resume_fc(&mut self, node_id: &NodeId) -> Result<(), TreeError> {
        self.evict_for_incoming_no_exempt(1)?;
        let node_dir = self.node_dir(node_id);
        let fc = crate::fc::FcVm::load_exported(&node_dir, None)?;
        self.live_vms.insert(node_id.clone(), Guest::from(fc));
        self.jail_vm(node_id)?;
        if let Some(info) = self.nodes.get_mut(node_id) {
            info.state = NodeState::Live;
            for dir in std::mem::take(&mut info.parked_disk_dirs) {
                fs::remove_dir_all(&dir)?;
            }
            touch(info);
        }
        self.save_metadata()?;
        log::info!("tree: resumed Firecracker '{node_id}'");
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
        log::info!("tree: pruned '{node_id}' and its subtree");
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
    /// `live_vm_count` is the Σ of `vm_count` across all Live
    /// nodes, so an N-VM cluster node counts as N. For a single-VM tree
    /// it equals the number of live nodes; the new `live_node_count`
    /// field reports that explicitly.
    #[must_use]
    pub fn usage(&self) -> TreeUsage {
        let mut live_ram_bytes: u64 = 0;
        for vm in self.live_vms.values() {
            live_ram_bytes = live_ram_bytes.saturating_add(vm.est_private_bytes());
        }
        let mut disk_bytes: u64 = 0;
        for info in self.nodes.values() {
            let dir = self.node_dir(&info.id);
            // A Firecracker node's point lives in its chroot, not in
            // the node directory, and costs its Diff's data extents.
            let keyframe = match self.live_vms.get(&info.id) {
                Some(Guest::Firecracker(fc)) => fc.point_diff_bytes(),
                _ => keyframe_disk_bytes(&dir.join("memory.bin"), info.base_disk_bytes),
            };
            disk_bytes = disk_bytes.saturating_add(keyframe);
            if let Ok(md) = fs::metadata(dir.join("delta.pack")) {
                disk_bytes = disk_bytes.saturating_add(md.len());
            }
        }
        let live_node_count = self.live_vms.len();
        // For VmPayload-backed trees this is identical to the previous
        // semantics (every live node has vm_count == 1); for cluster
        // trees it sums the underlying VM counts so the rule
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

    /// Suspend the LRU non-protected live VM(s) until `incoming` new live
    /// VMs fit the budget, exempting `source_id` (used by `fork_batch` so
    /// the source isn't suspended out from under the caller).
    fn evict_for_incoming(&mut self, source_id: &NodeId, incoming: usize) -> Result<(), TreeError> {
        self.evict_for_incoming_inner(Some(source_id.as_str()), incoming)
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
                        "disk budget: need {incoming}B headroom for a new base snapshot; \
                         {}B/{}B used, no evictable subtrees",
                        usage.disk_bytes, self.budget.max_disk_bytes,
                    ),
                });
            };
            let victim = self.node_id_for_pure(victim)?;
            self.evict_subtree(&victim)?;
        }
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
            // Leftovers prune would have dropped with remove_dir_all of
            // the node dir: FC `vmstate` / `fc.json` / `disk-*`. Keep the
            // directory so the Evicted record still has a home; do not
            // name those files (bug-candidates #13).
            reap_dir_contents(&dir);
            // Keep the node in tree.json so the Evicted record remains.
            if let Some(info) = self.nodes.get_mut(&id) {
                info.state = NodeState::Evicted;
                info.has_base_snapshot = false;
                // The keyframe is gone, so it costs nothing and names no
                // generation any pack may still claim.
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
    pub fn get_vm(&self, node_id: &NodeId) -> Option<&Guest> {
        self.live_vms.get(node_id)
    }

    /// Get a mutable reference to the live guest for a node.
    pub fn get_vm_mut(&mut self, node_id: &NodeId) -> Option<&mut Guest> {
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

    /// Unprepared hops between `node_id` (inclusive) and its nearest
    /// `has_base_snapshot` ancestor. Resume applies **one** `delta.pack`
    /// onto that ancestor; this hop-count is not a
    /// correctness cap. 0 for a checkpoint node. Not tree-graph depth.
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

/// Can this tree's storage `FICLONE`? Probed once per tree.
///
/// A `false` here is not an error — the tree works, every keyframe just
/// costs a full guest-RAM dump — but it is the difference between a
/// GRPO generation costing its divergence and costing `N × guest RAM`,
/// so say it once, loudly, at the top.
pub(crate) fn probe_reflink_root(root_dir: &Path) -> bool {
    match crate::disks::assert_reflink_capable(root_dir) {
        Ok(()) => {
            log::info!(
                "tree: {} is reflink-capable — keyframes down the tree are incremental",
                root_dir.display()
            );
            true
        }
        Err(e) => {
            log::warn!(
                "tree: {} cannot FICLONE ({e}) — every keyframe costs a FULL guest-RAM \
                 dump instead of O(divergence). Put the tree root on the reflink XFS \
                 (`disks::ensure_reflink_tree_root`).",
                root_dir.display()
            );
            false
        }
    }
}

/// Best-effort drop of leftover files in `dir` — the ones
/// [`SnapshotTree::prune`] would have removed with `remove_dir_all`.
/// Eviction keeps the directory so an Evicted node still has a home
/// under `nodes/{id}/`. Missing dir is not a failure. This is how FC
/// exports (`vmstate`, `fc.json`, `disk-*`) get reaped without a second
/// named file list (bug-candidates #13).
pub(crate) fn reap_dir_contents(dir: &Path) {
    let Ok(rd) = fs::read_dir(dir) else {
        return;
    };
    for e in rd.flatten() {
        let p = e.path();
        let _ = if p.is_dir() {
            fs::remove_dir_all(&p)
        } else {
            fs::remove_file(&p)
        };
    }
}

/// Physical disk a node's `memory.bin` costs.
///
/// `recorded` is the daemon's write-time measurement —
/// the only honest number for an incremental keyframe, whose logical
/// length is the full guest-physical span and whose `st_blocks` counts
/// extents it merely shares with its ancestor. A node written before
/// that record existed, or by the full-dump path, costs its length.
fn keyframe_disk_bytes(mem_path: &Path, recorded: Option<u64>) -> u64 {
    match fs::metadata(mem_path) {
        Ok(md) => recorded.unwrap_or(md.len()),
        // No keyframe on disk costs nothing, whatever the record says.
        Err(_) => 0,
    }
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
///
/// `base_identity` names the generation of the `memory.bin` this pack is
/// a diff against; [`apply_delta`] refuses to apply it onto any other
/// (CHALLENGES #144). 0 means "unknown" and applies anywhere.
pub fn write_delta(
    path: &Path,
    dirty_bitmap: &[u64],
    src_addr: u64,
    mem_size: u64,
    base_identity: u64,
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

        let header = k7dl_set_base_identity(k7dl_header_bytes(page_count, mem_size), base_identity);
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

/// What [`apply_delta`] restored.
#[derive(Debug, Clone)]
pub struct AppliedDelta {
    /// Number of pages written into the mapping.
    pub page_count: u32,
    /// Span-indexed bitmap of exactly those pages — the resumed VM's
    /// divergence from the base it was mapped from, which its fresh
    /// dirty bitmap must be seeded with (CHALLENGES #143).
    pub bitmap: Vec<u64>,
}

impl AppliedDelta {
    /// The no-pack case: a checkpoint resumes straight off its own
    /// `memory.bin` and diverges from it by nothing.
    #[must_use]
    pub fn empty(mem_size: u64) -> Self {
        Self {
            page_count: 0,
            bitmap: vec![0u64; bitmap_words(mem_size)],
        }
    }
}

/// Words in a span-indexed dirty bitmap for `mem_size` bytes of
/// guest-physical address space. Matches `Vm::enable_dirty_tracking`.
fn bitmap_words(mem_size: u64) -> usize {
    (mem_size.div_ceil(4096) as usize).div_ceil(64)
}

/// Apply a packed K7DL delta into a `MAP_PRIVATE` memory region.
///
/// Writes each page from the delta file into `target_addr + page_idx * 4096`.
///
/// `expected_base_identity` is the generation of the `memory.bin`
/// `target_addr` maps. A pack minted against a *different* known
/// generation is rejected: its page indices are meaningful only against
/// the base it was diffed from, so applying it elsewhere would scatter
/// one VM's pages through another's memory and resume a plausible-looking
/// corrupt guest (CHALLENGES #144). A pack or a base with identity 0 is
/// legacy and loads with a warning rather than failing.
pub fn apply_delta(
    path: &Path,
    target_addr: u64,
    mem_size: u64,
    expected_base_identity: u64,
) -> Result<AppliedDelta, TreeError> {
    let mut f = fs::File::open(path)?;
    let mut header = [0u8; K7DL_HEADER_SIZE];
    f.read_exact(&mut header)?;

    let (page_count, delta_mem_size) = k7dl_parse_header(&header)?;
    let pack_identity = k7dl_base_identity(&header);
    if delta_mem_size != mem_size {
        return Err(DeltaError::MemSizeMismatch {
            got: delta_mem_size,
            expected: mem_size,
        }
        .into());
    }
    if !tree_model::k7dl_base_identity_ok(pack_identity, expected_base_identity) {
        return Err(TreeError::InvalidDelta(format!(
            "{}: pack was written against base generation {pack_identity}, but the \
             memory.bin it is being applied to is generation {expected_base_identity} — \
             the base re-prepared under this suspended node, so its page indices no \
             longer mean what they did (CHALLENGES #144)",
            path.display(),
        )));
    }
    if pack_identity == 0 || expected_base_identity == 0 {
        log::warn!(
            "{}: applying a delta with no base identity (pack {pack_identity}, base \
             {expected_base_identity}) — legacy metadata, the base-skew check is off \
             for this resume",
            path.display(),
        );
    }

    let mut bitmap = vec![0u64; bitmap_words(mem_size)];
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
        bitmap[page_idx as usize / 64] |= 1u64 << (u64::from(page_idx) % 64);
    }
    Ok(AppliedDelta { page_count, bitmap })
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
