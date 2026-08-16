-- Equivalence for the leaf scans:
-- `find_index`, `contains_id`, `max_id`. Each is a single `while i < len`
-- loop; the proofs are loop-invariant inductions on the generated
-- `…_loop` functions (structural recursion on `len - i`, closed by
-- `scalar_decr_tac`), and set the recipe every later group reuses.
--
-- Every theorem has the total-correctness shape `f args ⦃ r => r ≃ mirror ⦄`
-- (`⦃ ⦄` maps `fail`/`div` to `False`), so each equivalence also proves
-- the Rust helper never panics on the stated inputs.

import Verif.Equiv.Abs

namespace Verif.Equiv

open Aeneas Aeneas.Std Result
open Aeneas.Std.WP
open k7d

-- ## find_index ≡ Tree.lookup

/-- What `find_index` returns, phrased through the mirror: `none` exactly
when `Tree.lookup` misses, and `some k` exactly when `Tree.lookup` finds
the abstraction of `t.nodes[k]`. -/
def findIndexPost (t : tree_model.TreeModel) (id : Std.U64)
    (r : Option Std.Usize) : Prop :=
  match r with
  | none => Tree.lookup (absTree t) id.val = none
  | some k => ∃ h : k.val < t.nodes.val.length,
      Tree.lookup (absTree t) id.val = some (absNode (t.nodes.val[k.val]'h))

theorem find_index_loop_equiv (t : tree_model.TreeModel) (id : Std.U64)
    (i : Std.Usize) (hi : i.val ≤ t.nodes.val.length)
    (hprefix : ∀ j, (h : j < t.nodes.val.length) → j < i.val →
      (t.nodes.val[j]'h).id.val ≠ id.val) :
    tree_model.find_index_loop t id i ⦃ r => findIndexPost t id r ⦄ := by
  unfold tree_model.find_index_loop
  simp only
  split
  · rename_i hlt
    have hilen : i.val < t.nodes.val.length := by scalar_tac
    step as ⟨ni, hni⟩
    split
    · rename_i heq
      subst hni
      simp only [spec_ok, findIndexPost]
      refine ⟨hilen, ?_⟩
      unfold Tree.lookup
      rw [absTree_nodes]
      have := find?_eq_some_of_first (l := t.nodes.val.map absNode)
        (p := fun n => n.id == id.val) (i := i.val)
        (by simpa using hilen)
        (by simp only [List.getElem_map, absNode_id]; simp [heq])
        (fun j hj => by
          simp only [List.getElem_map, absNode_id]
          simpa using hprefix j (by omega) hj)
      simpa only [List.getElem_map] using this
    · rename_i hne
      subst hni
      step as ⟨i2, hi2⟩
      apply find_index_loop_equiv t id i2 (by scalar_tac)
      intro j hjlen hji2
      by_cases hji : j < i.val
      · exact hprefix j hjlen hji
      · have hj : j = i.val := by scalar_tac
        subst hj
        intro hcon
        apply hne
        scalar_tac
  · rename_i hge
    simp only [spec_ok, findIndexPost]
    unfold Tree.lookup
    rw [absTree_nodes]
    rw [List.find?_eq_none]
    intro n hn
    obtain ⟨m, hm, rfl⟩ := List.mem_map.mp hn
    obtain ⟨j, hj, rfl⟩ := List.getElem_of_mem hm
    simp only [absNode_id]
    have hlen : t.nodes.val.length ≤ i.val := by scalar_tac
    simpa using hprefix j hj (by omega)
termination_by t.nodes.val.length - i.val
decreasing_by scalar_decr_tac

/-- Equivalence: `tree_model::find_index` computes the mirror
`Tree.lookup` (and never panics). -/
theorem find_index_equiv (t : tree_model.TreeModel) (id : Std.U64) :
    tree_model.find_index t id ⦃ r => findIndexPost t id r ⦄ := by
  unfold tree_model.find_index
  apply find_index_loop_equiv t id 0#usize (by simp) (by intro j _ h; simp at h)

-- ## contains_id ≡ list membership

theorem contains_id_loop_equiv (ids : Slice Std.U64) (id : Std.U64)
    (i : Std.Usize)
    (hprefix : ∀ j, (h : j < ids.val.length) → j < i.val →
      (ids.val[j]'h).val ≠ id.val) :
    tree_model.contains_id_loop ids id i
      ⦃ b => b = decide (id.val ∈ absSlice ids) ⦄ := by
  unfold tree_model.contains_id_loop
  simp only
  split
  · rename_i hlt
    have hilen : i.val < ids.val.length := by scalar_tac
    step as ⟨x, hx⟩
    split
    · rename_i heq
      subst hx
      simp only [spec_ok]
      symm
      simp only [decide_eq_true_iff, absSlice]
      exact List.mem_map.mpr
        ⟨ids.val[i.val]'hilen, List.getElem_mem _, by rw [heq]⟩
    · rename_i hne
      subst hx
      step as ⟨i2, hi2⟩
      apply contains_id_loop_equiv ids id i2
      intro j hjlen hji2
      by_cases hji : j < i.val
      · exact hprefix j hjlen hji
      · have hj : j = i.val := by scalar_tac
        subst hj
        intro hcon
        apply hne
        scalar_tac
  · rename_i hge
    simp only [spec_ok]
    have hlen : ids.val.length ≤ i.val := by scalar_tac
    symm
    simp only [decide_eq_false_iff_not]
    intro hmem
    obtain ⟨x, hx, hxv⟩ := List.mem_map.mp hmem
    obtain ⟨j, hj, rfl⟩ := List.getElem_of_mem hx
    exact hprefix j hj (by omega) hxv
termination_by ids.val.length - i.val
decreasing_by scalar_decr_tac

/-- Equivalence: `tree_model::contains_id` decides mirror list
membership (and never panics). -/
theorem contains_id_equiv (ids : Slice Std.U64) (id : Std.U64) :
    tree_model.contains_id ids id
      ⦃ b => b = decide (id.val ∈ absSlice ids) ⦄ := by
  unfold tree_model.contains_id
  apply contains_id_loop_equiv ids id 0#usize (by intro j _ h; simp at h)

-- ## max_id ≡ Tree.maxId

theorem max_id_loop_equiv (t : tree_model.TreeModel) (m : Std.U64)
    (i : Std.Usize) :
    tree_model.max_id_loop t m i
      ⦃ r => r.val
        = (t.nodes.val.drop i.val).foldl (fun a n => max a n.id.val) m.val ⦄ := by
  unfold tree_model.max_id_loop
  simp only
  split
  · rename_i hlt
    have hilen : i.val < t.nodes.val.length := by scalar_tac
    have hdrop : t.nodes.val.drop i.val
        = (t.nodes.val[i.val]'hilen) :: t.nodes.val.drop (i.val + 1) :=
      List.drop_eq_getElem_cons hilen
    step as ⟨ni, hni⟩
    split
    · rename_i hgt
      subst hni
      simp only [bind_tc_ok]
      step as ⟨i2, hi2⟩
      obtain ⟨r, hr, hpost⟩ :=
        spec_imp_exists (max_id_loop_equiv t (t.nodes.val[i.val]'hilen).id i2)
      rw [hr]
      simp only [spec_ok]
      rw [hpost, hi2, hdrop, List.foldl_cons]
      congr 1
      scalar_tac
    · rename_i hle
      subst hni
      simp only [bind_tc_ok]
      step as ⟨i2, hi2⟩
      obtain ⟨r, hr, hpost⟩ := spec_imp_exists (max_id_loop_equiv t m i2)
      rw [hr]
      simp only [spec_ok]
      rw [hpost, hi2, hdrop, List.foldl_cons]
      congr 1
      scalar_tac
  · rename_i hge
    have hlen : t.nodes.val.length ≤ i.val := by scalar_tac
    simp only [spec_ok]
    rw [List.drop_eq_nil_of_le hlen]
    simp
termination_by t.nodes.val.length - i.val
decreasing_by all_goals scalar_decr_tac

/-- Equivalence: `tree_model::max_id` computes the mirror `Tree.maxId`
(and never panics). -/
theorem max_id_equiv (t : tree_model.TreeModel) :
    tree_model.max_id t ⦃ r => r.val = Tree.maxId (absTree t) ⦄ := by
  unfold tree_model.max_id
  obtain ⟨r, hr, hpost⟩ := spec_imp_exists (max_id_loop_equiv t 0#u64 0#usize)
  rw [hr]
  simp only [spec_ok]
  rw [hpost]
  unfold Tree.maxId
  rw [absTree_nodes, List.foldl_map]
  simp

end Verif.Equiv
