-- Group A — Tree shape invariants.
--
-- We prove, for the pure snapshot-tree model in `crate::tree_model`:
--   * `add_child_preserves_well_formed` — `add_child` keeps the tree
--     well-formed (unique ids, parent/child links consistent, parent id
--     strictly below child id).
--   * `parent_chain_terminates` — from any id, following `parent`
--     pointers reaches a root (a node whose walk stops) in finitely
--     many steps. The engine is the `parentLt` invariant: the
--     orchestrator mints pure ids monotonically, so every parent id is
--     strictly smaller than its child's, and the chain is a strictly
--     decreasing `Nat` sequence.
--
-- Aeneas translates the Rust source into heavily-monadic Lean threading
-- `alloc.vec.Vec` bounds obligations through every access — see
-- `tree_model.add_child` in the generated `K7d.lean`. Per the pattern
-- established by Groups E/F (see the file-level note in
-- `Verif/K7dlCodec.lean` for the full rationale), we prove against a
-- transparent Lean mirror instead:
--
--   1. `NodeInfo` / `TreeModel` / `lookup` / `addChild` below mirror
--      `tree_model.rs` field-for-field and branch-for-branch (ids and
--      times as `Nat` — the Rust `u64` ops used here are comparisons
--      and list pushes only, no wrapping arithmetic). Fields the
--      verified functions never read (`kind`, `dirty_pages`,
--      `max_chain_depth`) are dropped from the mirror
--      (`has_base_snapshot` used to be dropped too, until
--      `restore_chain_depth` started reading it — the referenced work).
--      Change the Rust, update the mirror.
--   2. The theorems are proven on the mirror.
--
-- Equivalence with the Rust source is machine-checked:
-- `Verif/Equiv/` proves each mirror equal to the Aeneas translation, and
-- `Verif/Equiv/Transfer.lean` restates the theorems above on the
-- generated definitions (`…_rust`). The unit tests in
-- `crates/k7d/src/tree_model.rs::tests` cover the same surface from the
-- Rust side.

import Verif.TreeModel

namespace Verif.Tree

/-- Mirror of `tree_model::NodeState`. -/
inductive NodeState where
  | live
  | suspended
  | evicted
  deriving DecidableEq

/-- Mirror of `tree_model::NodeInfo` (the fields the verified functions
read; `prot` mirrors the Rust `protected`, a reserved word in Lean). -/
structure NodeInfo where
  id : Nat
  parent : Option Nat
  children : List Nat
  state : NodeState
  vmCount : Nat
  hasBase : Bool
  lastActive : Nat
  prot : Bool
  estRamBytes : Nat
  diskBytes : Nat

/-- Mirror of `tree_model::TreeBudget`. -/
structure TreeBudget where
  maxLiveVms : Nat
  maxLiveRamBytes : Nat
  maxDiskBytes : Nat

/-- Mirror of `tree_model::TreeModel`. -/
structure TreeModel where
  nodes : List NodeInfo
  budget : TreeBudget

/-- Mirror of `tree_model::find_index`, returning the node instead of its
index (the callers only ever use the index to read the node). -/
def lookup (t : TreeModel) (id : Nat) : Option NodeInfo :=
  t.nodes.find? (fun n => n.id == id)

/-- The parent pointer read the Rust `ancestor_ids` walk performs at each
step: `None` both for a missing node and for a root. -/
def parentOf (t : TreeModel) (id : Nat) : Option Nat :=
  match lookup t id with
  | none => none
  | some n => n.parent

/-- The per-node update `add_child`'s copy loop applies: the parent gains
the new child id and a fresh `last_active` stamp; everyone else is
copied verbatim. -/
def bumpParent (parent newId now : Nat) (n : NodeInfo) : NodeInfo :=
  if n.id = parent then
    { n with children := n.children ++ [newId], lastActive := now }
  else n

/-- The freshly-created `Live` child `add_child` appends. -/
def newChild (parent newId now : Nat) : NodeInfo :=
  { id := newId, parent := some parent, children := [], state := .live,
    vmCount := 1, hasBase := false, lastActive := now, prot := false,
    estRamBytes := 0, diskBytes := 0 }

/-- Mirror of `tree_model::add_child`. -/
def addChild (t : TreeModel) (parent newId now : Nat) : TreeModel :=
  if lookup t parent = none ∨ (lookup t newId).isSome then t
  else
    { t with
      nodes := t.nodes.map (bumpParent parent newId now)
        ++ [newChild parent newId now] }

/-- Well-formedness of the pure model (Group A):

* `idsNodup` — node ids are unique.
* `parentLt` — every parent id is strictly below its child's id (the
  orchestrator's monotonic id minting; what makes parent chains
  strictly decreasing).
* `parentMem` — every parent pointer targets a node in the tree.
* `childLink` — every child-list entry is a node in the tree whose
  parent pointer points back. -/
structure WellFormed (t : TreeModel) : Prop where
  idsNodup : (t.nodes.map NodeInfo.id).Nodup
  parentLt : ∀ n ∈ t.nodes, ∀ p, n.parent = some p → p < n.id
  parentMem : ∀ n ∈ t.nodes, ∀ p, n.parent = some p → ∃ m ∈ t.nodes, m.id = p
  childLink : ∀ n ∈ t.nodes, ∀ c ∈ n.children,
    ∃ m ∈ t.nodes, m.id = c ∧ m.parent = some n.id

@[simp] theorem bumpParent_id (parent newId now : Nat) (n : NodeInfo) :
    (bumpParent parent newId now n).id = n.id := by
  unfold bumpParent; split <;> rfl

@[simp] theorem bumpParent_parent (parent newId now : Nat) (n : NodeInfo) :
    (bumpParent parent newId now n).parent = n.parent := by
  unfold bumpParent; split <;> rfl

/-- `bumpParent` either keeps the children list or appends `newId`. -/
theorem bumpParent_children (parent newId now : Nat) (n : NodeInfo) :
    (bumpParent parent newId now n).children = n.children ∨
    ((bumpParent parent newId now n).children = n.children ++ [newId]
      ∧ n.id = parent) := by
  unfold bumpParent; split
  · exact Or.inr ⟨rfl, by assumption⟩
  · exact Or.inl rfl

/-- Appending a fresh element keeps a list duplicate-free. -/
theorem nodup_append_singleton {α : Type} {l : List α} {a : α}
    (h : l.Nodup) (ha : a ∉ l) : (l ++ [a]).Nodup := by
  induction l with
  | nil => simp
  | cons x xs ih =>
    simp only [List.cons_append, List.nodup_cons] at h ⊢
    simp only [List.mem_cons, not_or] at ha
    refine ⟨?_, ih h.2 ha.2⟩
    intro hx
    rcases List.mem_append.mp hx with h1 | h2
    · exact h.1 h1
    · exact ha.1 ((List.mem_singleton.mp h2).symm)

/-- `lookup t id = none` means no node carries `id`. -/
theorem lookup_none_iff (t : TreeModel) (id : Nat) :
    lookup t id = none ↔ ∀ n ∈ t.nodes, n.id ≠ id := by
  simp [lookup, List.find?_eq_none]

/-- A successful `lookup` returns a member node with the queried id. -/
theorem lookup_some (t : TreeModel) (id : Nat) (n : NodeInfo)
    (h : lookup t id = some n) : n ∈ t.nodes ∧ n.id = id := by
  refine ⟨List.mem_of_find?_eq_some h, ?_⟩
  have := List.find?_some h
  simpa using this

/-- Group A: `add_child` preserves well-formedness.

The Rust function's own guard supplies parent-existence and
new-id-freshness (it returns the input unchanged otherwise); the only
extra hypothesis is the orchestrator's monotonic minting contract
`parent < newId`, which `parentLt` needs for the new edge. -/
theorem add_child_preserves_well_formed
    (t : TreeModel) (parent newId now : Nat)
    (hwf : WellFormed t) (hmint : parent < newId) :
    WellFormed (addChild t parent newId now) := by
  unfold addChild
  split
  · exact hwf
  · rename_i hguard
    rw [not_or] at hguard
    obtain ⟨hparent, hfresh⟩ := hguard
    -- The guard's two facts in usable form.
    obtain ⟨pn, hpn⟩ : ∃ pn, lookup t parent = some pn := by
      cases hl : lookup t parent with
      | none => exact absurd hl hparent
      | some pn => exact ⟨pn, rfl⟩
    obtain ⟨hpmem, hpid⟩ := lookup_some t parent pn hpn
    have hfresh'' : lookup t newId = none := by
      cases hl : lookup t newId with
      | none => rfl
      | some x => rw [hl] at hfresh; exact absurd rfl hfresh
    have hfresh' : ∀ n ∈ t.nodes, n.id ≠ newId :=
      (lookup_none_iff t newId).mp hfresh''
    set f := bumpParent parent newId now with hf
    set nc := newChild parent newId now with hnc
    -- Membership in the new node list.
    have hmem : ∀ n', n' ∈ t.nodes.map f ++ [nc] ↔
        (∃ n ∈ t.nodes, f n = n') ∨ n' = nc := by
      intro n'; simp [List.mem_append, List.mem_map]
    constructor
    · -- idsNodup
      have hmap : (t.nodes.map f).map NodeInfo.id = t.nodes.map NodeInfo.id := by
        rw [List.map_map]
        exact List.map_congr_left (fun n _ => bumpParent_id parent newId now n)
      rw [List.map_append, hmap]
      show ((t.nodes.map NodeInfo.id) ++ [newId]).Nodup
      refine nodup_append_singleton hwf.idsNodup ?_
      intro hmem
      obtain ⟨n, hn, hna⟩ := List.mem_map.mp hmem
      exact hfresh' n hn hna
    · -- parentLt
      intro n' hn' p hp
      rcases (hmem n').mp hn' with ⟨n, hn, rfl⟩ | rfl
      · rw [bumpParent_parent] at hp
        rw [bumpParent_id]
        exact hwf.parentLt n hn p hp
      · have hpp : parent = p := by simpa [hnc, newChild] using hp
        have hncid : nc.id = newId := by simp [hnc, newChild]
        rw [hncid, ← hpp]
        exact hmint
    · -- parentMem
      intro n' hn' p hp
      rcases (hmem n').mp hn' with ⟨n, hn, rfl⟩ | rfl
      · rw [bumpParent_parent] at hp
        obtain ⟨m, hm, hmid⟩ := hwf.parentMem n hn p hp
        exact ⟨f m, (hmem (f m)).mpr (Or.inl ⟨m, hm, rfl⟩),
          by rw [bumpParent_id]; exact hmid⟩
      · have hpp : parent = p := by simpa [hnc, newChild] using hp
        exact ⟨f pn, (hmem (f pn)).mpr (Or.inl ⟨pn, hpmem, rfl⟩),
          by simp only [hf, bumpParent_id]; rw [hpid, hpp]⟩
    · -- childLink
      intro n' hn' c hc
      rcases (hmem n').mp hn' with ⟨n, hn, rfl⟩ | rfl
      · -- Old (possibly bumped) node: split on whether `c` is an old
        -- child or the appended `newId`.
        have hcase : c ∈ n.children ∨ (c = newId ∧ n.id = parent) := by
          rcases bumpParent_children parent newId now n with h | ⟨h, hid⟩
          · exact Or.inl (h ▸ hc)
          · rw [h, List.mem_append, List.mem_singleton] at hc
            rcases hc with hc | hc
            · exact Or.inl hc
            · exact Or.inr ⟨hc, hid⟩
        rcases hcase with hcold | ⟨rfl, hid⟩
        · obtain ⟨m, hm, hmid, hmp⟩ := hwf.childLink n hn c hcold
          exact ⟨f m, (hmem (f m)).mpr (Or.inl ⟨m, hm, rfl⟩),
            by rw [bumpParent_id]; exact hmid,
            by rw [bumpParent_parent, bumpParent_id]; exact hmp⟩
        · exact ⟨nc, (hmem nc).mpr (Or.inr rfl), rfl,
            by simp only [hnc, newChild, hf, bumpParent_id]; rw [hid]⟩
      · -- The new child has no children.
        simp [hnc, newChild] at hc

/-- `a` reaches `b` by following parent pointers zero or more times. -/
inductive Reaches (t : TreeModel) : Nat → Nat → Prop where
  | refl (id : Nat) : Reaches t id id
  | step {a b c : Nat} : parentOf t a = some b → Reaches t b c → Reaches t a c

/-- Group A: no cycles — from any id the parent chain terminates at a
root (a node where the walk stops: `parent = None`, or an id absent
from the tree). Strong induction on the id itself: `parentLt` makes the
chain a strictly decreasing `Nat` sequence. -/
theorem parent_chain_terminates (t : TreeModel) (hwf : WellFormed t) (id : Nat) :
    ∃ root, Reaches t id root ∧ parentOf t root = none := by
  induction id using Nat.strong_induction_on with
  | _ id ih =>
    cases hpo : parentOf t id with
    | none => exact ⟨id, .refl id, hpo⟩
    | some p =>
      have hplt : p < id := by
        unfold parentOf at hpo
        cases hl : lookup t id with
        | none => rw [hl] at hpo; exact absurd hpo (by simp)
        | some n =>
          rw [hl] at hpo
          obtain ⟨hmem, hid⟩ := lookup_some t id n hl
          exact hid ▸ hwf.parentLt n hmem p hpo
      obtain ⟨root, hr, hnone⟩ := ih p hplt
      exact ⟨root, .step hpo hr, hnone⟩

end Verif.Tree
