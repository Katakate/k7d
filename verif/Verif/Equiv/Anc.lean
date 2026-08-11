-- internal notes"What to build / 3.4" — equivalence for the fuel-bounded
-- ancestor walk `ancestor_ids`. The loop recurses on the fuel scalar
-- (not the node index), and each iteration pushes one id, so the honest
-- side condition is `|out| + |remaining walk| ≤ usize::MAX` — the
-- `Vec::push` capacity abort is the only way the Rust can fail. The
-- mirror side of each step is one `ancestorWalk` unfolding plus the
-- `find_index ≡ lookup` equivalence from `Scans.lean` (which is exactly
-- how the Rust reads the parent pointer).

import Verif.Equiv.Acct

namespace Verif.Equiv

open Aeneas Aeneas.Std Result
open Aeneas.Std.WP
open k7d

/-- The walk from a missing cursor is empty at every fuel. -/
theorem walk_none (t : Tree.TreeModel) (f : Nat) :
    Tree.ancestorWalk t f none = [] := by
  cases f <;> rfl

theorem ancestor_ids_loop_equiv (t : tree_model.TreeModel)
    (out : alloc.vec.Vec Std.U64) (cur : Option Std.U64) (fuel : Std.U64)
    (hcap : out.val.length
        + (Tree.ancestorWalk (absTree t) fuel.val (cur.map (·.val))).length
      ≤ Usize.max) :
    tree_model.ancestor_ids_loop t out cur fuel
      ⦃ r => absIds r = absIds out
          ++ Tree.ancestorWalk (absTree t) fuel.val (cur.map (·.val)) ⦄ := by
  unfold tree_model.ancestor_ids_loop
  split
  · rename_i hpos
    obtain ⟨f, hf⟩ : ∃ f, fuel.val = f + 1 := ⟨fuel.val - 1, by scalar_tac⟩
    cases cur with
    | none =>
      simp only [spec_ok, Option.map_none, walk_none]
      simp
    | some c =>
      simp only [Option.map_some] at hcap ⊢
      have hwalk : Tree.ancestorWalk (absTree t) fuel.val (some c.val)
          = c.val :: Tree.ancestorWalk (absTree t) f
              (Tree.parentOf (absTree t) c.val) := by
        rw [hf]
        rfl
      rw [hwalk] at hcap ⊢
      have hlt : out.val.length < Usize.max := by
        simp only [List.length_cons] at hcap
        omega
      step as ⟨out1, hout1⟩
      obtain ⟨o, ho, hoPost⟩ := spec_imp_exists (find_index_equiv t c)
      rw [ho]
      simp only [bind_tc_ok]
      cases o with
      | none =>
        have hpar : Tree.parentOf (absTree t) c.val = none := by
          unfold Tree.parentOf
          rw [hoPost]
        step as ⟨fuel1, hfuel1⟩
        have hf1 : fuel1.val = f := by scalar_tac
        obtain ⟨r, hp, hpost⟩ := spec_imp_exists
          (ancestor_ids_loop_equiv t out1 none fuel1
            (by
              rw [hf1]
              simp only [Option.map_none, walk_none, List.length_nil,
                hout1, List.length_append, List.length_cons] at hcap ⊢
              omega))
        rw [hp]
        simp only [spec_ok]
        rw [hpost, hf1]
        simp only [Option.map_none, walk_none, List.append_nil, hpar]
        simp [absIds, hout1]
      | some k =>
        obtain ⟨hk, hlook⟩ := hoPost
        step as ⟨ni, hni⟩
        have hpar : Tree.parentOf (absTree t) c.val
            = ni.parent.map (·.val) := by
          unfold Tree.parentOf
          rw [hlook, hni]
          simp [absNode_parent]
        step as ⟨fuel1, hfuel1⟩
        have hf1 : fuel1.val = f := by scalar_tac
        obtain ⟨r, hp, hpost⟩ := spec_imp_exists
          (ancestor_ids_loop_equiv t out1 ni.parent fuel1
            (by
              rw [hf1, ← hpar]
              simp only [hout1, List.length_append, List.length_cons,
                List.length_nil] at hcap ⊢
              omega))
        rw [hp]
        simp only [spec_ok]
        rw [hpost, hf1, hpar]
        simp [absIds, hout1]
  · rename_i hz
    have h0 : fuel.val = 0 := by scalar_tac
    simp only [spec_ok]
    rw [h0]
    simp [Tree.ancestorWalk]
termination_by fuel.val
decreasing_by all_goals scalar_decr_tac

/-- Equivalence: `tree_model::ancestor_ids` computes the mirror
`Tree.ancestorIds` (and never panics). The side condition marks the
genuine Rust abort point (the per-step `Vec::push`): the chain the walk
would produce must fit in a `Vec`. On any well-formed tree it holds
trivially (parent ids strictly decrease, so the chain is finite and
short); it can only bind on a malformed tree whose parent pointers form
a cycle *and* whose fuel exceeds `usize::MAX`. -/
theorem ancestor_ids_equiv (t : tree_model.TreeModel) (id : Std.U64)
    (hcap : (Tree.ancestorIds (absTree t) id.val).length ≤ Usize.max) :
    tree_model.ancestor_ids t id
      ⦃ r => absIds r = Tree.ancestorIds (absTree t) id.val ⦄ := by
  unfold tree_model.ancestor_ids
  obtain ⟨i, hi, hiPost⟩ := spec_imp_exists (max_id_equiv t)
  rw [hi]
  simp only [bind_tc_ok]
  step as ⟨fuel, hfuel⟩
  have hfv : fuel.val = Tree.satAdd Tree.U64_MAX (Tree.maxId (absTree t)) 2 := by
    rw [hfuel, hiPost]
  unfold Tree.ancestorIds at hcap ⊢
  obtain ⟨r, hp, hpost⟩ := spec_imp_exists
    (ancestor_ids_loop_equiv t (alloc.vec.Vec.new Std.U64) (some id) fuel
      (by
        rw [hfv]
        simpa [absIds] using hcap))
  rw [hp]
  simp only [spec_ok]
  rw [hpost, hfv]
  simp [absIds]

end Verif.Equiv
