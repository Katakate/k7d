-- Equivalence for the restore-chain walk
-- `restore_chain_depth`. Same fuel-recursion skeleton as
-- `Anc.lean`'s `ancestor_ids`, but simpler: the loop carries a scalar
-- depth counter instead of pushing into a `Vec`, so there is no
-- capacity side condition — the theorem is unconditional. The
-- `usize::saturating_add` on the depth is bridged saturation-exactly
-- by `usize_saturating_add_val` (mirror side: `satAdd USIZE_MAX`).

import Verif.Equiv.Acct

namespace Verif.Equiv

open Aeneas Aeneas.Std Result
open Aeneas.Std.WP
open k7d

theorem restore_chain_depth_loop_equiv (t : tree_model.TreeModel)
    (depth : Std.Usize) (cur : Option Std.U64) (fuel : Std.U64) :
    tree_model.restore_chain_depth_loop t depth cur fuel
      ⦃ r => r.map (·.val)
          = Tree.restoreChainWalk (absTree t) fuel.val depth.val
              (cur.map (·.val)) ⦄ := by
  unfold tree_model.restore_chain_depth_loop
  split
  · rename_i hpos
    obtain ⟨f, hf⟩ : ∃ f, fuel.val = f + 1 := ⟨fuel.val - 1, by scalar_tac⟩
    rcases cur with _ | c
    · simp only [spec_ok, Option.map_none]
      rw [hf]
      rfl
    · simp only [Option.map_some]
      have hwalk : Tree.restoreChainWalk (absTree t) fuel.val depth.val
          (some c.val)
          = match Tree.lookup (absTree t) c.val with
            | none => none
            | some n =>
              if n.hasBase then some depth.val
              else Tree.restoreChainWalk (absTree t) f
                (Tree.satAdd Tree.USIZE_MAX depth.val 1) n.parent := by
        rw [hf]
        rfl
      obtain ⟨o, ho, hoPost⟩ := spec_imp_exists (find_index_equiv t c)
      rw [ho]
      simp only [bind_tc_ok]
      cases o with
      | none =>
        simp only [findIndexPost] at hoPost
        simp only [spec_ok, hwalk, hoPost, Option.map_none]
      | some k =>
        obtain ⟨hk, hlook⟩ := hoPost
        step as ⟨ni, hni⟩
        rw [hwalk, hlook, ← hni]
        by_cases hbase : ni.has_base_snapshot
        · simp [hbase, absNode_hasBase]
        · simp only [hbase, Bool.false_eq_true, if_false, absNode_hasBase]
          step as ⟨depth1, hdepth1⟩
          step as ⟨fuel1, hfuel1⟩
          have hf1 : fuel1.val = f := by scalar_tac
          have hd1 : depth1.val
              = Tree.satAdd Tree.USIZE_MAX depth.val 1 := by
            rw [hdepth1]
          obtain ⟨r, hp, hpost⟩ := spec_imp_exists
            (restore_chain_depth_loop_equiv t depth1 ni.parent fuel1)
          rw [hp]
          simp only [spec_ok]
          rw [hpost, hf1, hd1]
          simp [absNode_parent]
  · rename_i hz
    have h0 : fuel.val = 0 := by scalar_tac
    simp only [spec_ok]
    rw [h0]
    rfl
termination_by fuel.val
decreasing_by all_goals scalar_decr_tac

/-- Equivalence: `tree_model::restore_chain_depth` computes the mirror
`Tree.restoreChainDepth` (and never panics — unconditionally: the loop
allocates nothing and every arithmetic step saturates). -/
theorem restore_chain_depth_equiv (t : tree_model.TreeModel)
    (id : Std.U64) :
    tree_model.restore_chain_depth t id
      ⦃ r => r.map (·.val) = Tree.restoreChainDepth (absTree t) id.val ⦄ := by
  unfold tree_model.restore_chain_depth
  obtain ⟨i, hi, hiPost⟩ := spec_imp_exists (max_id_equiv t)
  rw [hi]
  simp only [bind_tc_ok]
  step as ⟨fuel, hfuel⟩
  have hfv : fuel.val = Tree.satAdd Tree.U64_MAX (Tree.maxId (absTree t)) 2 := by
    rw [hfuel, hiPost]
  obtain ⟨r, hp, hpost⟩ := spec_imp_exists
    (restore_chain_depth_loop_equiv t 0#usize (some id) fuel)
  rw [hp]
  simp only [spec_ok]
  rw [hpost, hfv]
  rfl

end Verif.Equiv
