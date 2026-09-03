-- The payoff. Every Group A–D
-- theorem (plus the Group F latency-budget and
-- Group E codec theorems), restated on the **Aeneas-generated**
-- definitions as a corollary of `mirror theorem + equivalence`. These
-- `_rust` corollaries are the ones `crates/k7d/src/tree_model.rs` doc
-- comments cite: each says the Rust function returns `ok` (never panics
-- on the stated inputs) *and* its result satisfies the mirror property.
--
-- Side conditions (`hanc`/`hcap`/`hlen`/`hchild`) mark the only honest
-- Rust abort points — `Vec::push` capacity — inherited from the
-- equivalence theorems; on any realistic tree they hold trivially.

import Verif.Equiv.Evict
import Verif.Equiv.Chain
import Verif.Equiv.Latency
import Verif.Equiv.K7dl

namespace Verif.Equiv

open Aeneas Aeneas.Std Result
open Aeneas.Std.WP
open k7d

-- Group E corollaries instantiate `spec_imp_exists` at
-- `Array U8 28#usize`/`4096#usize`/`4100#usize`; elaboration recurses
-- once per numeral unit (see the note in `Equiv/K7dl.lean`).
set_option maxRecDepth 1000000

-- ## Group A — tree shape invariants

/-- Group A on the Rust code: `add_child` never panics (given `Vec`
capacity headroom) and preserves well-formedness, under the
orchestrator's monotonic-minting contract `parent < new_id`. -/
theorem add_child_preserves_well_formed_rust (t : tree_model.TreeModel)
    (parent new_id now : Std.U64)
    (hlen : t.nodes.val.length < Usize.max)
    (hchild : ∀ n ∈ t.nodes.val, n.children.val.length < Usize.max)
    (hwf : Tree.WellFormed (absTree t)) (hmint : parent.val < new_id.val) :
    ∃ t', tree_model.add_child t parent new_id now = ok t'
      ∧ Tree.WellFormed (absTree t') := by
  obtain ⟨t', hp, hpost⟩ := spec_imp_exists
    (add_child_equiv t parent new_id now hlen hchild)
  refine ⟨t', hp, ?_⟩
  rw [hpost]
  exact Tree.add_child_preserves_well_formed (absTree t) parent.val
    new_id.val now.val hwf hmint

/-- Group A on the Rust model: no parent-pointer cycles — from any id
the chain reaches a root. (A property of the abstracted state; no Rust
function to run.) -/
theorem parent_chain_terminates_rust (t : tree_model.TreeModel)
    (hwf : Tree.WellFormed (absTree t)) (id : Nat) :
    ∃ root, Tree.Reaches (absTree t) id root
      ∧ Tree.parentOf (absTree t) root = none :=
  Tree.parent_chain_terminates (absTree t) hwf id

/-- Group A on the Rust code: `set_state` never panics and preserves
well-formedness (it only flips `state` fields). -/
theorem set_state_preserves_well_formed_rust (t : tree_model.TreeModel)
    (id : Std.U64) (s : tree_model.NodeState)
    (hwf : Tree.WellFormed (absTree t)) :
    ∃ t', tree_model.set_state t id s = ok t'
      ∧ Tree.WellFormed (absTree t') := by
  obtain ⟨t', hp, hpost⟩ := spec_imp_exists (set_state_equiv t id s)
  refine ⟨t', hp, ?_⟩
  rw [hpost]
  exact Tree.setState_preserves_well_formed (absTree t) id.val (absState s) hwf

-- ## Group B — budget accounting

/-- Group B on the Rust code (saturation-exact form):
`usage().live_ram_bytes` is the saturating sum of `est_ram_bytes` over
Live nodes. -/
theorem usage_ram_is_sat_sum_of_live_rust (t : tree_model.TreeModel) :
    ∃ u, tree_model.usage t = ok u
      ∧ u.live_ram_bytes.val
          = Tree.satSum Tree.U64_MAX
              ((Tree.liveNodes (absTree t).nodes).map
                Tree.NodeInfo.estRamBytes) 0 := by
  obtain ⟨u, hp, hpost⟩ := spec_imp_exists (usage_equiv t)
  refine ⟨u, hp, ?_⟩
  show (absUsage u).liveRamBytes = _
  rw [hpost]
  exact Tree.usage_ram_is_sat_sum_of_live (absTree t)

/-- Group B on the Rust code: below `u64::MAX`, `usage().live_ram_bytes`
= Σ `est_ram_bytes` over Live nodes. -/
theorem usage_ram_is_sum_of_live_rust (t : tree_model.TreeModel)
    (h : ((Tree.liveNodes (absTree t).nodes).map
        Tree.NodeInfo.estRamBytes).sum ≤ Tree.U64_MAX) :
    ∃ u, tree_model.usage t = ok u
      ∧ u.live_ram_bytes.val
          = ((Tree.liveNodes (absTree t).nodes).map
              Tree.NodeInfo.estRamBytes).sum := by
  obtain ⟨u, hp, hpost⟩ := spec_imp_exists (usage_equiv t)
  refine ⟨u, hp, ?_⟩
  show (absUsage u).liveRamBytes = _
  rw [hpost]
  exact Tree.usage_ram_is_sum_of_live (absTree t) h

/-- Group B on the Rust code (saturation-exact form):
`usage().live_vm_count` is the saturating sum of `vm_count` over Live
nodes. -/
theorem usage_vm_count_is_sat_sum_of_live_rust (t : tree_model.TreeModel) :
    ∃ u, tree_model.usage t = ok u
      ∧ u.live_vm_count.val
          = Tree.satSum Tree.USIZE_MAX
              ((Tree.liveNodes (absTree t).nodes).map
                Tree.NodeInfo.vmCount) 0 := by
  obtain ⟨u, hp, hpost⟩ := spec_imp_exists (usage_equiv t)
  refine ⟨u, hp, ?_⟩
  show (absUsage u).liveVmCount = _
  rw [hpost]
  exact Tree.usage_vm_count_is_sat_sum_of_live (absTree t)

/-- Group B on the Rust code: below `usize::MAX`, `usage().live_vm_count`
= Σ `vm_count` over Live nodes. -/
theorem usage_vm_count_is_sum_of_live_rust (t : tree_model.TreeModel)
    (h : ((Tree.liveNodes (absTree t).nodes).map
        Tree.NodeInfo.vmCount).sum ≤ Tree.USIZE_MAX) :
    ∃ u, tree_model.usage t = ok u
      ∧ u.live_vm_count.val
          = ((Tree.liveNodes (absTree t).nodes).map
              Tree.NodeInfo.vmCount).sum := by
  obtain ⟨u, hp, hpost⟩ := spec_imp_exists (usage_equiv t)
  refine ⟨u, hp, ?_⟩
  show (absUsage u).liveVmCount = _
  rw [hpost]
  exact Tree.usage_vm_count_is_sum_of_live (absTree t) h

/-- Group B on the Rust code: `usage().live_node_count` counts the Live
nodes exactly (plain `+= 1`, no saturation, no side condition). -/
theorem usage_count_is_count_of_live_rust (t : tree_model.TreeModel) :
    ∃ u, tree_model.usage t = ok u
      ∧ u.live_node_count.val
          = (Tree.liveNodes (absTree t).nodes).length := by
  obtain ⟨u, hp, hpost⟩ := spec_imp_exists (usage_equiv t)
  refine ⟨u, hp, ?_⟩
  show (absUsage u).liveNodeCount = _
  rw [hpost]
  exact Tree.usage_count_is_count_of_live (absTree t)

/-- Group B on the Rust code: `TreeBudget::ram_soft_limit` never panics
and never exceeds the hard RAM budget. -/
theorem ram_soft_limit_below_max_rust (b : tree_model.TreeBudget) :
    ∃ r, tree_model.TreeBudget.ram_soft_limit b = ok r
      ∧ r.val ≤ b.max_live_ram_bytes.val := by
  obtain ⟨r, hp, hpost⟩ := spec_imp_exists (ram_soft_limit_equiv b)
  refine ⟨r, hp, ?_⟩
  rw [hpost]
  exact Tree.ram_soft_limit_below_max (absBudget b)

/-- Group B on the Rust code : with zero incoming bytes
the disk-headroom check decides exactly `over_disk`. -/
theorem over_disk_incoming_zero_rust (t : tree_model.TreeModel) :
    ∃ b, tree_model.over_disk_incoming t 0#u64 = ok b
      ∧ (b = true ↔ Tree.overDisk (absTree t)) := by
  obtain ⟨b, hpb, hpost⟩ := spec_imp_exists (over_disk_incoming_equiv t 0#u64)
  refine ⟨b, hpb, ?_⟩
  rw [hpost]
  simp [Tree.over_disk_incoming_zero]

/-- Group B on the Rust code : the disk-headroom check is
monotone in the projected write — if `i` bytes do not fit, neither does
any `j ≥ i`. -/
theorem over_disk_incoming_mono_rust (t : tree_model.TreeModel)
    (i j : Std.U64) (hij : i.val ≤ j.val) :
    ∃ bi bj, tree_model.over_disk_incoming t i = ok bi
      ∧ tree_model.over_disk_incoming t j = ok bj
      ∧ (bi = true → bj = true) := by
  obtain ⟨bi, hpi, hposti⟩ := spec_imp_exists (over_disk_incoming_equiv t i)
  obtain ⟨bj, hpj, hpostj⟩ := spec_imp_exists (over_disk_incoming_equiv t j)
  refine ⟨bi, bj, hpi, hpj, ?_⟩
  rw [hposti, hpostj]
  intro h
  simp only [decide_eq_true_eq] at h ⊢
  exact Tree.over_disk_incoming_mono (absTree t) i.val j.val hij h

-- ## Group C — eviction policy

/-- Group C on the Rust code: the fuel `max_id().saturating_add(2)`
never truncates a real chain — `ancestor_ids` computes the same chain
any larger fuel would (`hid` marks where the `u64` fuel saturates,
`hcap` the `Vec::push` capacity abort). -/
theorem ancestor_ids_fuel_never_truncates_rust (t : tree_model.TreeModel)
    (hwf : Tree.WellFormed (absTree t))
    (n : tree_model.NodeInfo) (hn : n ∈ t.nodes.val)
    (f : Nat) (hf : n.id.val < f) (hid : n.id.val + 2 ≤ Tree.U64_MAX)
    (hcap : (Tree.ancestorIds (absTree t) n.id.val).length ≤ Usize.max) :
    ∃ v, tree_model.ancestor_ids t n.id = ok v
      ∧ Tree.ancestorWalk (absTree t) f (some n.id.val) = absIds v := by
  obtain ⟨v, hp, hpost⟩ := spec_imp_exists (ancestor_ids_equiv t n.id hcap)
  refine ⟨v, hp, ?_⟩
  rw [hpost]
  exact Tree.ancestor_ids_fuel_never_truncates (absTree t) hwf (absNode n)
    (by rw [absTree_nodes]; exact List.mem_map_of_mem hn) f hf hid

/-- Group C on the Rust code: protection is ancestor-closed — the
`implicitly_protected` output contains every ancestor of every
explicitly protected node. -/
theorem implicitly_protected_includes_ancestors_rust
    (t : tree_model.TreeModel)
    (hanc : ∀ n ∈ t.nodes.val,
      (Tree.ancestorIds (absTree t) n.id.val).length ≤ Usize.max)
    (hcap : (Tree.implicitlyProtected (absTree t)).length ≤ Usize.max)
    (n : tree_model.NodeInfo) (hn : n ∈ t.nodes.val)
    (hprot : n.«protected» = true) :
    ∃ v, tree_model.implicitly_protected t = ok v
      ∧ ∀ a ∈ Tree.ancestorIds (absTree t) n.id.val, a ∈ absIds v := by
  obtain ⟨v, hp, hpost⟩ := spec_imp_exists
    (implicitly_protected_equiv t hanc hcap)
  refine ⟨v, hp, ?_⟩
  rw [hpost]
  exact Tree.implicitly_protected_includes_ancestors (absTree t) (absNode n)
    (by rw [absTree_nodes]; exact List.mem_map_of_mem hn)
    (by simpa [absNode_prot] using hprot)

/-- Group C on the Rust code: LRU correctness — `lru_live_victim`
returns the eligible node with the smallest `last_active`, and `None`
only when no node is eligible. -/
theorem lru_victim_is_minimum_rust (t : tree_model.TreeModel)
    (exempt : Slice Std.U64)
    (hanc : ∀ n ∈ t.nodes.val,
      (Tree.ancestorIds (absTree t) n.id.val).length ≤ Usize.max)
    (hcap : (Tree.implicitlyProtected (absTree t)).length ≤ Usize.max) :
    ∃ o, tree_model.lru_live_victim t exempt = ok o
      ∧ match o.map (·.val) with
        | none => ∀ n ∈ (absTree t).nodes,
            ¬ Tree.eligibleLive (absTree t) (absSlice exempt) n
        | some vid => ∃ n ∈ (absTree t).nodes,
            Tree.eligibleLive (absTree t) (absSlice exempt) n ∧ n.id = vid ∧
              ∀ m ∈ (absTree t).nodes,
                Tree.eligibleLive (absTree t) (absSlice exempt) m →
                  n.lastActive ≤ m.lastActive := by
  obtain ⟨o, hp, hpost⟩ := spec_imp_exists
    (lru_live_victim_equiv t exempt hanc hcap)
  refine ⟨o, hp, ?_⟩
  rw [hpost]
  exact Tree.lru_victim_is_minimum (absTree t) (absSlice exempt)

/-- Group C on the Rust code: the disk-tier evictor never picks a
subtree root with a Live or Suspended strict descendant. -/
theorem leaf_subtree_has_no_live_descendants_rust (t : tree_model.TreeModel)
    (hanc : ∀ n ∈ t.nodes.val,
      (Tree.ancestorIds (absTree t) n.id.val).length ≤ Usize.max)
    (hcap : (Tree.implicitlyProtected (absTree t)).length ≤ Usize.max) :
    ∃ o, tree_model.lru_evictable_leaf_subtree t = ok o
      ∧ match o.map (·.val) with
        | none => True
        | some root => ∀ d ∈ (absTree t).nodes,
            root ∈ Tree.ancestorIds (absTree t) d.id → d.id ≠ root →
              d.state ≠ .live ∧ d.state ≠ .suspended := by
  obtain ⟨o, hp, hpost⟩ := spec_imp_exists
    (lru_evictable_leaf_subtree_equiv t hanc hcap)
  refine ⟨o, hp, ?_⟩
  rw [hpost]
  exact Tree.leaf_subtree_has_no_live_descendants (absTree t)

/-- Group C on the Rust code : `restore_chain_depth`
never panics, and a checkpoint node's restore chain is 0 — resume reads
its own `memory.bin`, no deltas. -/
theorem restore_chain_depth_checkpoint_rust (t : tree_model.TreeModel)
    (id : Std.U64) (n : Tree.NodeInfo)
    (hl : Tree.lookup (absTree t) id.val = some n)
    (hb : n.hasBase = true) :
    ∃ o, tree_model.restore_chain_depth t id = ok o
      ∧ o.map (·.val) = some 0 := by
  obtain ⟨o, hp, hpost⟩ := spec_imp_exists (restore_chain_depth_equiv t id)
  refine ⟨o, hp, ?_⟩
  rw [hpost]
  exact Tree.restore_chain_depth_checkpoint (absTree t) id.val n hl hb

/-- Group C on the Rust code (the referenced work, the load-bearing
distinction): a non-checkpoint node whose parent is a checkpoint has
restore chain exactly 1, however deep it sits in the tree graph —
`root → child → grandchild` is graph depth 2 but restore depth 1 once
the child was prepared. -/
theorem restore_chain_depth_hop_rust (t : tree_model.TreeModel)
    (id : Std.U64) (p : Nat) (n m : Tree.NodeInfo)
    (hl : Tree.lookup (absTree t) id.val = some n)
    (hb : n.hasBase = false) (hp' : n.parent = some p)
    (hlp : Tree.lookup (absTree t) p = some m) (hbp : m.hasBase = true) :
    ∃ o, tree_model.restore_chain_depth t id = ok o
      ∧ o.map (·.val) = some 1 := by
  obtain ⟨o, hp, hpost⟩ := spec_imp_exists (restore_chain_depth_equiv t id)
  refine ⟨o, hp, ?_⟩
  rw [hpost]
  exact Tree.restore_chain_depth_hop (absTree t) id.val p n m hl hb hp' hlp hbp

-- ## Group D — the Tier-1 RAM eviction loop

/-- Group D on the Rust code, termination: `auto_evict_ram`'s
`nodes.len()` fuel computes the loop's true fixed point — the mirror
loop at any fuel at or above the live-node count yields the identical
result. -/
theorem auto_evict_ram_terminates_rust (t : tree_model.TreeModel)
    (exempt : Slice Std.U64)
    (hanc : ∀ id, (Tree.ancestorIds (absTree t) id).length ≤ Usize.max)
    (hcap : (Tree.implicitlyProtected (absTree t)).length ≤ Usize.max) :
    ∃ r, tree_model.auto_evict_ram t exempt = ok r
      ∧ ∀ f, Tree.liveCount (absTree t) ≤ f →
          Tree.autoEvictLoop (absSlice exempt) f (absTree t) = absTree r := by
  obtain ⟨r, hp, hpost⟩ := spec_imp_exists
    (auto_evict_ram_equiv t exempt hanc hcap)
  refine ⟨r, hp, fun f hf => ?_⟩
  rw [hpost]
  exact Tree.auto_evict_ram_terminates (absTree t) (absSlice exempt) f hf

/-- Group D on the Rust code, post-condition: on exit, `auto_evict_ram`
is either under both the RAM and count budgets, or every remaining Live
node is exempt or implicitly protected. -/
theorem auto_evict_ram_post_rust (t : tree_model.TreeModel)
    (exempt : Slice Std.U64)
    (hanc : ∀ id, (Tree.ancestorIds (absTree t) id).length ≤ Usize.max)
    (hcap : (Tree.implicitlyProtected (absTree t)).length ≤ Usize.max) :
    ∃ r, tree_model.auto_evict_ram t exempt = ok r
      ∧ ((¬ Tree.overRam (absTree r) ∧ ¬ Tree.overCount (absTree r) 0)
          ∨ (∀ n ∈ (absTree r).nodes, n.state = .live →
              n.id ∈ absSlice exempt
                ∨ n.id ∈ Tree.implicitlyProtected (absTree r))) := by
  obtain ⟨r, hp, hpost⟩ := spec_imp_exists
    (auto_evict_ram_equiv t exempt hanc hcap)
  refine ⟨r, hp, ?_⟩
  rw [hpost]
  exact Tree.auto_evict_ram_post (absTree t) (absSlice exempt)

/-- Group D on the Rust code: the eviction loop preserves the Group A
shape invariants (it only flips `state` fields). -/
theorem auto_evict_ram_preserves_well_formed_rust (t : tree_model.TreeModel)
    (exempt : Slice Std.U64)
    (hanc : ∀ id, (Tree.ancestorIds (absTree t) id).length ≤ Usize.max)
    (hcap : (Tree.implicitlyProtected (absTree t)).length ≤ Usize.max)
    (hwf : Tree.WellFormed (absTree t)) :
    ∃ r, tree_model.auto_evict_ram t exempt = ok r
      ∧ Tree.WellFormed (absTree r) := by
  obtain ⟨r, hp, hpost⟩ := spec_imp_exists
    (auto_evict_ram_equiv t exempt hanc hcap)
  refine ⟨r, hp, ?_⟩
  rw [hpost]
  exact Tree.auto_evict_ram_preserves_well_formed (absTree t)
    (absSlice exempt) hwf

-- ## Group F — latency budget

/-- Group F on the Rust code: `fork_warm_budget_ns` never panics, and
zero dirty pages yield exactly the base budget. -/
theorem fork_warm_budget_base_rust (d : Std.U64) (h : d.val = 0) :
    ∃ r, tree_model.fork_warm_budget_ns d = ok r
      ∧ r.val = Latency.forkWarmBaseNs := by
  obtain ⟨r, hp, hpost⟩ := spec_imp_exists (fork_warm_budget_ns_equiv d)
  refine ⟨r, hp, ?_⟩
  rw [hpost]
  exact Latency.fork_warm_budget_base d.val h

/-- Group F on the Rust code: the warm-fork budget is monotone in the
dirty page count (saturation included). -/
theorem fork_warm_budget_monotone_rust (a b : Std.U64) (h : a.val ≤ b.val) :
    ∃ ra rb, tree_model.fork_warm_budget_ns a = ok ra
      ∧ tree_model.fork_warm_budget_ns b = ok rb
      ∧ ra.val ≤ rb.val := by
  obtain ⟨ra, hpa, hposta⟩ := spec_imp_exists (fork_warm_budget_ns_equiv a)
  obtain ⟨rb, hpb, hpostb⟩ := spec_imp_exists (fork_warm_budget_ns_equiv b)
  refine ⟨ra, rb, hpa, hpb, ?_⟩
  rw [hposta, hpostb]
  exact Latency.fork_warm_budget_monotone a.val b.val h

-- ## Group E — K7DL codec round-trips

/-- Group E on the Rust code: `k7dl_parse_header ∘ k7dl_header_bytes`
is the identity — neither half panics, and parsing returns
`Ok((page_count, mem_size))` exactly. -/
theorem k7dl_header_roundtrip_rust (pc : Std.U32) (ms : Std.U64) :
    ∃ hdr, tree_model.k7dl_header_bytes pc ms = ok hdr
      ∧ tree_model.k7dl_parse_header hdr
          = ok (core.result.Result.Ok (pc, ms)) := by
  obtain ⟨hdr, hh, habs⟩ := spec_imp_exists (k7dl_header_bytes_equiv pc ms)
  obtain ⟨r, hp, hpost⟩ := spec_imp_exists (k7dl_parse_header_equiv hdr)
  have hround : K7dlCodec.parseHeader (absBytes hdr)
      = .ok (pc.bv, ms.bv) := by
    rw [habs]; exact K7dlCodec.k7dl_header_roundtrip pc.bv ms.bv
  refine ⟨hdr, hh, ?_⟩
  rw [hp]
  rcases r with ⟨pc', ms'⟩ | e
  · simp only [headerPost] at hpost
    rw [hround] at hpost
    simp only [Except.ok.injEq, Prod.mk.injEq] at hpost
    obtain ⟨h1, h2⟩ := hpost
    rw [(uscalar_eq_iff_bv pc' pc).mpr h1.symm,
      (uscalar_eq_iff_bv ms' ms).mpr h2.symm]
  · rcases e with got | v | ⟨a, b⟩ | ⟨a, b⟩ <;>
      simp [headerPost, hround] at hpost

/-- Group E on the Rust code : the base identity round-trips
through the header's trailing u64, and stamping it leaves what
`k7dl_parse_header` reads untouched. The second half is the one that
matters — a stamp that shifted `page_count` or `mem_size` would make a
resumed node write its pages at indices the writer never meant. -/
theorem k7dl_base_identity_roundtrip_rust (pc : Std.U32) (ms bi : Std.U64) :
    ∃ hdr stamped, tree_model.k7dl_header_bytes pc ms = ok hdr
      ∧ tree_model.k7dl_set_base_identity hdr bi = ok stamped
      ∧ tree_model.k7dl_base_identity stamped = ok bi
      ∧ tree_model.k7dl_parse_header stamped
          = ok (core.result.Result.Ok (pc, ms)) := by
  obtain ⟨hdr, hh, habs⟩ := spec_imp_exists (k7dl_header_bytes_equiv pc ms)
  obtain ⟨stamped, hst, hstabs⟩ :=
    spec_imp_exists (k7dl_set_base_identity_equiv hdr bi)
  obtain ⟨out, hout, houtpost⟩ := spec_imp_exists (k7dl_base_identity_equiv stamped)
  obtain ⟨r, hp, hpost⟩ := spec_imp_exists (k7dl_parse_header_equiv stamped)
  have hstampedAbs : absBytes stamped
      = K7dlCodec.setBaseIdentity (K7dlCodec.headerBytes pc.bv ms.bv) bi.bv := by
    rw [hstabs, habs]
  refine ⟨hdr, stamped, hh, hst, ?_, ?_⟩
  · rw [hout]
    refine congrArg _ ((uscalar_eq_iff_bv out bi).mpr (houtpost.trans ?_))
    rw [hstampedAbs]
    exact K7dlCodec.k7dl_base_identity_roundtrip pc.bv ms.bv bi.bv
  · have hround : K7dlCodec.parseHeader (absBytes stamped) = .ok (pc.bv, ms.bv) := by
      rw [hstampedAbs, K7dlCodec.k7dl_set_base_identity_preserves_header]
      exact K7dlCodec.k7dl_header_roundtrip pc.bv ms.bv
    rw [hp]
    rcases r with ⟨pc', ms'⟩ | e
    · simp only [headerPost] at hpost
      rw [hround] at hpost
      simp only [Except.ok.injEq, Prod.mk.injEq] at hpost
      obtain ⟨h1, h2⟩ := hpost
      rw [(uscalar_eq_iff_bv pc' pc).mpr h1.symm,
        (uscalar_eq_iff_bv ms' ms).mpr h2.symm]
    · rcases e with got | v | ⟨a, b⟩ | ⟨a, b⟩ <;>
        simp [headerPost, hround] at hpost

/-- Group E on the Rust code : the
base-identity guard never panics, accepts a pack applied onto the
generation it names, refuses two known generations that disagree, and
still loads a pre-30b pack (identity 0 on either side). -/
theorem k7dl_base_identity_ok_rust (pack base : Std.U64) :
    ∃ r, tree_model.k7dl_base_identity_ok pack base = ok r
      ∧ (pack.bv = base.bv → r = true)
      ∧ ((pack.bv = 0#64 ∨ base.bv = 0#64) → r = true)
      ∧ (pack.bv ≠ 0#64 → base.bv ≠ 0#64 → pack.bv ≠ base.bv → r = false) := by
  obtain ⟨r, hp, hpost⟩ := spec_imp_exists (k7dl_base_identity_ok_equiv pack base)
  refine ⟨r, hp, fun h => ?_, fun h => ?_, fun hp0 hb0 hne => ?_⟩
  · rw [hpost, h]; exact K7dlCodec.baseIdentityOk_self base.bv
  · rw [hpost]; exact K7dlCodec.baseIdentityOk_unknown pack.bv base.bv h
  · rw [hpost]
    exact K7dlCodec.baseIdentityOk_rejects_known_mismatch pack.bv base.bv hp0 hb0 hne

/-- Group E on the Rust code: `k7dl_parse_entry ∘ k7dl_encode_entry`
is the identity — neither half panics, and parsing returns the exact
`(page_idx, page)` pair (page bytes included, via `absBytes`
injectivity). -/
theorem k7dl_entry_roundtrip_rust (idx : Std.U32)
    (page : Array Std.U8 4096#usize) :
    ∃ e, tree_model.k7dl_encode_entry idx page = ok e
      ∧ tree_model.k7dl_parse_entry e = ok (idx, page) := by
  obtain ⟨e, he, habs⟩ := spec_imp_exists (k7dl_encode_entry_equiv idx page)
  obtain ⟨r, hp, hpost⟩ := spec_imp_exists (k7dl_parse_entry_equiv e)
  have hround : K7dlCodec.parseEntry (absBytes e)
      = (idx.bv, absBytes page) := by
    rw [habs]; exact K7dlCodec.k7dl_entry_roundtrip idx.bv (absBytes page)
  refine ⟨e, he, ?_⟩
  rw [hp]
  rw [hround] at hpost
  simp only [Prod.mk.injEq] at hpost
  obtain ⟨h1, h2⟩ := hpost
  rcases r with ⟨ridx, rpage⟩
  simp only at h1 h2
  rw [(uscalar_eq_iff_bv ridx idx).mpr h1, absBytes_inj h2]

end Verif.Equiv
