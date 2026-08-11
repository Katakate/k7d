-- internal notes"What to build / 1" — the abstraction layer between the
-- Aeneas-generated translation of `crates/k7d/src/tree_model.rs`
-- (`Verif/K7d.lean`, imported through `Verif/TreeModel.lean`) and the
-- hand-written mirrors in `Verif/{TreeShape,TreeBudget,TreeEviction}.lean`.
--
-- Everything the equivalence proofs need to say about *generated names*
-- that is not itself an equivalence theorem lives here: the abstraction
-- functions (`absNode`, `absTree`, `absIds`, …), the spec lemmas for the
-- generated trait methods (`NodeState` equality via `read_discriminant`,
-- the structural `Clone` impls), and the scalar bridges
-- (`saturating_add` ↔ `Verif.Tree.satAdd`, `UScalar.max` ↔
-- `U64_MAX`/`USIZE_MAX`). If a regeneration renames a generated
-- identifier, the fix is localized to `Verif/Equiv/` (this file first).
--
-- Generated names may appear **only** in `Verif/Equiv/` and
-- `Verif/TreeModel.lean` — never in the mirror files.

import Verif.TreeModel
import Verif.TreeEviction

namespace Verif.Equiv

open Aeneas Aeneas.Std Result
open Aeneas.Std.WP
open k7d

-- ## Abstraction functions

/-- Abstraction: generated `NodeState` → mirror `NodeState`. -/
def absState : tree_model.NodeState → Tree.NodeState
  | .Live => .live
  | .Suspended => .suspended
  | .Evicted => .evicted

/-- Abstraction: generated `NodeInfo` → mirror `NodeInfo` (drops `kind`,
`dirty_pages`, `has_base_snapshot` — the verified functions never read
them; scalars via `.val`). -/
def absNode (n : tree_model.NodeInfo) : Tree.NodeInfo :=
  { id := n.id.val
    parent := n.parent.map (·.val)
    children := n.children.val.map (·.val)
    state := absState n.state
    vmCount := n.vm_count.val
    lastActive := n.last_active.val
    prot := n.«protected»
    estRamBytes := n.est_ram_bytes.val
    diskBytes := n.disk_bytes.val }

/-- Abstraction: generated `TreeBudget` → mirror `TreeBudget` (drops
`max_chain_depth`, which none of the verified functions read). -/
def absBudget (b : tree_model.TreeBudget) : Tree.TreeBudget :=
  { maxLiveVms := b.max_live_vms.val
    maxLiveRamBytes := b.max_live_ram_bytes.val
    maxDiskBytes := b.max_disk_bytes.val }

/-- Abstraction: generated `TreeModel` → mirror `TreeModel`. -/
def absTree (t : tree_model.TreeModel) : Tree.TreeModel :=
  { nodes := t.nodes.val.map absNode, budget := absBudget t.budget }

/-- Abstraction: generated `TreeUsage` → mirror `TreeUsage`. -/
def absUsage (u : tree_model.TreeUsage) : Tree.TreeUsage :=
  { liveVmCount := u.live_vm_count.val
    liveRamBytes := u.live_ram_bytes.val
    diskBytes := u.disk_bytes.val
    totalNodes := u.total_nodes.val
    liveNodeCount := u.live_node_count.val }

/-- Abstraction: id vector → id list. -/
def absIds (v : alloc.vec.Vec Std.U64) : List Nat := v.val.map (·.val)

/-- Abstraction: id slice → id list. -/
def absSlice (s : Slice Std.U64) : List Nat := s.val.map (·.val)

/-- Abstraction: fixed-size byte array → `BitVec 8` list (the
`K7dlCodec` mirror's `Byte` representation) — internal notes/
def absBytes {n : Std.Usize} (a : Array Std.U8 n) : List (BitVec 8) :=
  a.val.map Std.U8.bv

-- ## Field / projection simp lemmas

@[simp] theorem absNode_id (n : tree_model.NodeInfo) :
    (absNode n).id = n.id.val := rfl

@[simp] theorem absNode_parent (n : tree_model.NodeInfo) :
    (absNode n).parent = n.parent.map (·.val) := rfl

@[simp] theorem absNode_state (n : tree_model.NodeInfo) :
    (absNode n).state = absState n.state := rfl

@[simp] theorem absNode_vmCount (n : tree_model.NodeInfo) :
    (absNode n).vmCount = n.vm_count.val := rfl

@[simp] theorem absNode_lastActive (n : tree_model.NodeInfo) :
    (absNode n).lastActive = n.last_active.val := rfl

@[simp] theorem absNode_prot (n : tree_model.NodeInfo) :
    (absNode n).prot = n.«protected» := rfl

@[simp] theorem absNode_estRamBytes (n : tree_model.NodeInfo) :
    (absNode n).estRamBytes = n.est_ram_bytes.val := rfl

@[simp] theorem absNode_diskBytes (n : tree_model.NodeInfo) :
    (absNode n).diskBytes = n.disk_bytes.val := rfl

@[simp] theorem absTree_nodes (t : tree_model.TreeModel) :
    (absTree t).nodes = t.nodes.val.map absNode := rfl

@[simp] theorem absTree_budget (t : tree_model.TreeModel) :
    (absTree t).budget = absBudget t.budget := rfl

/-- `absState` is injective — the mirror `NodeState` is a faithful copy. -/
@[simp] theorem absState_inj (a b : tree_model.NodeState) :
    (absState a = absState b) ↔ a = b := by
  cases a <;> cases b <;> simp [absState]

-- ## Scalar bridges

-- (Deliberately not `@[simp]`: rewriting `Usize.max` away would break
-- `scalar_tac`, which reasons in terms of the Aeneas constants.)
theorem u64_max_eq : U64.max = Tree.U64_MAX := by
  simp [U64.max, U64.numBits, Tree.U64_MAX]

theorem usize_max_eq : Usize.max = Tree.USIZE_MAX := by
  simp [Usize.max, Usize.numBits, Tree.USIZE_MAX]

/-- `u64::MAX` (the generated constant) matches the mirror ceiling. -/
theorem core_u64_max_val : (core.num.U64.MAX).val = Tree.U64_MAX := by
  simp [core.num.U64.MAX, U64.rMax, Tree.U64_MAX]

/-- Rust `saturating_add` computes the mirror `satAdd` on values. -/
theorem saturating_add_val {ty : UScalarTy} (x y : UScalar ty) :
    (UScalar.saturating_add x y).val
      = Tree.satAdd (UScalar.max ty) x.val y.val := by
  have hmax : UScalar.max ty = 2 ^ ty.numBits - 1 := by simp [UScalar.max]
  have hpos : 0 < 2 ^ ty.numBits := Nat.two_pow_pos _
  have hlt : Min.min (UScalar.max ty) (x.val + y.val) < 2 ^ ty.numBits := by
    omega
  simp only [UScalar.saturating_add, UScalar.val, Tree.satAdd]
  simp [BitVec.toNat_ofNat, Nat.mod_eq_of_lt hlt, Nat.min_comm]

@[simp] theorem u64_saturating_add_val (x y : Std.U64) :
    (core.num.U64.saturating_add x y).val
      = Tree.satAdd Tree.U64_MAX x.val y.val := by
  have := saturating_add_val x y
  rw [← u64_max_eq]
  simpa [core.num.U64.saturating_add] using this

@[simp] theorem usize_saturating_add_val (x y : Std.Usize) :
    (core.num.Usize.saturating_add x y).val
      = Tree.satAdd Tree.USIZE_MAX x.val y.val := by
  have := saturating_add_val x y
  have hm : UScalar.max .Usize = Usize.max := by
    simp [UScalar.max, Usize.max, UScalarTy.numBits, Usize.numBits]
  rw [hm] at this
  rw [← usize_max_eq]
  simpa [core.num.Usize.saturating_add] using this

/-- A fresh `Vec` is the empty list. -/
@[simp] theorem vec_new_val (α : Type) : (alloc.vec.Vec.new α).val = [] := rfl

-- ## Generated trait-method specs

/-- The derived `PartialEq` on the generated `NodeState` (a
`read_discriminant` comparison) decides mirror-state equality. -/
@[simp] theorem nodeState_eq_spec (a b : tree_model.NodeState) :
    tree_model.NodeState.Insts.CoreCmpPartialEqNodeState.eq a b
      = ok (decide (absState a = absState b)) := by
  cases a <;> cases b <;>
    simp [tree_model.NodeState.Insts.CoreCmpPartialEqNodeState.eq,
      tree_model.NodeState.read_discriminant, absState]

/-- The manual `Clone for NodeInfo` (element-wise `u64` copy of
`children`) is the identity. -/
@[simp] theorem nodeInfo_clone_eq (n : tree_model.NodeInfo) :
    tree_model.NodeInfo.Insts.CoreCloneClone.clone n = ok n := by
  have h := spec_imp_exists
    (Slice.clone_spec (clone := core.clone.CloneU64.clone)
      (s := n.children) (by intro x _; simp))
  obtain ⟨v, hv, rfl⟩ := h
  unfold tree_model.NodeInfo.Insts.CoreCloneClone.clone
  simp only [alloc.vec.CloneVec.clone, hv]
  rfl

/-- The derived `Clone for TreeModel` is the identity. -/
@[simp] theorem treeModel_clone_eq (t : tree_model.TreeModel) :
    tree_model.TreeModel.Insts.CoreCloneClone.clone t = ok t := by
  have h := spec_imp_exists
    (Slice.clone_spec
      (clone := tree_model.NodeInfo.Insts.CoreCloneClone.clone)
      (s := t.nodes) (by intro x _; simp))
  obtain ⟨v, hv, rfl⟩ := h
  unfold tree_model.TreeModel.Insts.CoreCloneClone.clone
  simp only [alloc.vec.CloneVec.clone, hv]
  rfl

-- ## List helpers (mirror-side, no generated names)

/-- First-match characterization of `List.find?`. -/
theorem find?_eq_some_of_first {α} {l : List α} {p : α → Bool} {i : Nat}
    (hi : i < l.length) (hp : p (l[i]'hi))
    (hprefix : ∀ j (hj : j < i), ¬ p (l[j]'(by omega))) :
    l.find? p = some (l[i]'hi) := by
  induction l generalizing i with
  | nil => simp at hi
  | cons x xs ih =>
    cases i with
    | zero =>
      simp only [List.getElem_cons_zero] at hp
      simp [hp]
    | succ i =>
      have hx : ¬ p x := by
        have := hprefix 0 (by omega)
        simpa using this
      rw [List.find?_cons_of_neg hx]
      have := ih (i := i) (by simpa using hi) (by simpa using hp)
        (fun j hj => by simpa using hprefix (j+1) (by omega))
      simpa using this

end Verif.Equiv
