-- internal notes"What to build / 3.3" — equivalence for the accounting
-- group: `usage`, `ram_soft_limit`, `over_ram`, `over_count`,
-- `over_disk`. The `usage` loop threads four accumulators; the invariant
-- says the mirror `usageAux` on the *remaining* suffix, seeded with the
-- current accumulator values, equals the final accumulator values. All
-- saturating arithmetic is unconditional (mirrors are saturation-exact);
-- the only side condition threaded through the induction is the
-- `live_node_count + 1` no-overflow bound, discharged from
-- `live_node_count ≤ i < t.nodes.len() ≤ usize::MAX`.

import Verif.Equiv.Rebuild

namespace Verif.Equiv

open Aeneas Aeneas.Std Result
open Aeneas.Std.WP
open k7d

-- ## `step` lemmas for the `lift`ed pure scalar ops
--
-- Aeneas purifies `saturating_add` and `as`-casts (they cannot fail), so
-- the generated code wraps them in `lift`. `step` resolves such calls
-- through `@[step]` theorems on the lifted pattern; the library does not
-- ship them for these two, so we provide them here, phrased directly in
-- mirror vocabulary (`Tree.satAdd`).

@[step] theorem lift_cast_u32_usize_spec (x : Std.U32) :
    lift (UScalar.cast .Usize x) ⦃ y => y.val = x.val ⦄ := by
  simp [lift, spec_ok]

@[step] theorem lift_usize_saturating_add_spec (x y : Std.Usize) :
    lift (core.num.Usize.saturating_add x y)
      ⦃ z => z.val = Tree.satAdd Tree.USIZE_MAX x.val y.val ⦄ := by
  simp [lift, spec_ok]

@[step] theorem lift_u64_saturating_add_spec (x y : Std.U64) :
    lift (core.num.U64.saturating_add x y)
      ⦃ z => z.val = Tree.satAdd Tree.U64_MAX x.val y.val ⦄ := by
  simp [lift, spec_ok]

-- ## ram_soft_limit ≡ Tree.ramSoftLimit

/-- Equivalence: `TreeBudget::ram_soft_limit` computes the mirror
`Tree.ramSoftLimit` (and never panics) — including the explicit
saturation guard the Rust uses in place of `saturating_mul`. -/
theorem ram_soft_limit_equiv (b : tree_model.TreeBudget) :
    tree_model.TreeBudget.ram_soft_limit b
      ⦃ r => r.val = Tree.ramSoftLimit (absBudget b) ⦄ := by
  unfold tree_model.TreeBudget.ram_soft_limit
  step as ⟨i, hi⟩
  have hrm : U64.rMax = Tree.U64_MAX := by simp [U64.rMax, Tree.U64_MAX]
  rw [hrm] at hi
  split
  · rename_i hgt
    have hgt' : i.val < b.max_live_ram_bytes.val := by scalar_tac
    step as ⟨r, hr⟩
    rw [hrm] at hr
    simp only [Tree.ramSoftLimit, Tree.satMul, absBudget]
    simp only [Tree.U64_MAX] at *
    omega
  · rename_i hle
    have hle' : b.max_live_ram_bytes.val ≤ i.val := by scalar_tac
    step as ⟨prod, hprod⟩
    · rw [u64_max_eq]
      simp only [Tree.U64_MAX] at *
      scalar_tac
    · step as ⟨r, hr⟩
      simp only [Tree.ramSoftLimit, Tree.satMul, absBudget]
      simp only [Tree.U64_MAX] at *
      scalar_tac

-- ## usage ≡ Tree.usage

theorem usage_loop_equiv (t : tree_model.TreeModel) (tn : Nat)
    (lvc : Std.Usize) (lrb db : Std.U64) (lnc i : Std.Usize)
    (hlnc : lnc.val + (t.nodes.val.length - i.val) ≤ Usize.max) :
    tree_model.usage_loop t lvc lrb db lnc i
      ⦃ v lvc' lrb' db' lnc' =>
          v = t.nodes ∧
          Tree.usageAux ((t.nodes.val.drop i.val).map absNode)
              ⟨lvc.val, lrb.val, db.val, tn, lnc.val⟩
            = ⟨lvc'.val, lrb'.val, db'.val, tn, lnc'.val⟩ ⦄ := by
  unfold tree_model.usage_loop
  simp only
  split
  · rename_i hlt
    have hilen : i.val < t.nodes.val.length := by scalar_tac
    have hdrop : t.nodes.val.drop i.val
        = (t.nodes.val[i.val]'hilen) :: t.nodes.val.drop (i.val + 1) :=
      List.drop_eq_getElem_cons hilen
    step as ⟨ni, hni⟩
    simp only [nodeState_eq_spec, bind_tc_ok]
    split
    · rename_i hb
      subst hni
      have hlive : absState (t.nodes.val[i.val]'hilen).state
          = Tree.NodeState.live := by
        simpa [absState] using hb
      step as ⟨vmc, hvmc⟩
      step as ⟨lvc2, hlvc2⟩
      step as ⟨lrb2, hlrb2⟩
      step as ⟨lnc2, hlnc2⟩
      step as ⟨db2, hdb2⟩
      step as ⟨i2, hi2⟩
      obtain ⟨⟨v, lvcF, lrbF, dbF, lncF⟩, hp, hpost⟩ := spec_imp_exists
        (usage_loop_equiv t tn lvc2 lrb2 db2 lnc2 i2 (by scalar_tac))
      simp only [WP.uncurry'_pair] at hpost
      rw [hp]
      simp only [spec_ok, WP.uncurry'_pair]
      refine ⟨hpost.1, ?_⟩
      rw [hdrop, List.map_cons]
      simp only [Tree.usageAux, absNode_state, absNode_vmCount,
        absNode_estRamBytes, absNode_diskBytes, hlive, reduceIte]
      rw [← hpost.2, hi2]
      congr 1
      simp only [Tree.TreeUsage.mk.injEq]
      exact ⟨by rw [hlvc2, hvmc], by rw [hlrb2], by rw [hdb2], trivial,
        by rw [hlnc2]⟩
    · rename_i hb
      subst hni
      have hdead : ¬ absState (t.nodes.val[i.val]'hilen).state
          = Tree.NodeState.live := by
        simpa [absState] using hb
      step as ⟨db2, hdb2⟩
      step as ⟨i2, hi2⟩
      obtain ⟨⟨v, lvcF, lrbF, dbF, lncF⟩, hp, hpost⟩ := spec_imp_exists
        (usage_loop_equiv t tn lvc lrb db2 lnc i2 (by scalar_tac))
      simp only [WP.uncurry'_pair] at hpost
      rw [hp]
      simp only [spec_ok, WP.uncurry'_pair]
      refine ⟨hpost.1, ?_⟩
      rw [hdrop, List.map_cons]
      simp only [Tree.usageAux, absNode_state, absNode_diskBytes,
        if_neg hdead]
      rw [← hpost.2, hi2]
      congr 1
      simp only [Tree.TreeUsage.mk.injEq]
      exact ⟨trivial, trivial, by rw [hdb2], trivial, trivial⟩
  · rename_i hge
    have hlen : t.nodes.val.length ≤ i.val := by scalar_tac
    simp only [spec_ok, WP.uncurry'_pair]
    rw [List.drop_eq_nil_of_le hlen]
    simp [Tree.usageAux]
termination_by t.nodes.val.length - i.val
decreasing_by all_goals scalar_decr_tac

/-- Equivalence: `tree_model::usage` computes the mirror `Tree.usage`
(and never panics). -/
theorem usage_equiv (t : tree_model.TreeModel) :
    tree_model.usage t ⦃ u => absUsage u = Tree.usage (absTree t) ⦄ := by
  unfold tree_model.usage
  obtain ⟨⟨v, lvc, lrb, db, lnc⟩, hp, hpost⟩ := spec_imp_exists
    (usage_loop_equiv t 0 0#usize 0#u64 0#u64 0#usize 0#usize
      (by have := t.nodes.property; simp; scalar_tac))
  simp only [WP.uncurry'_pair] at hpost
  obtain ⟨hv, hfields⟩ := hpost
  subst hv
  rw [hp]
  show WP.spec (ok (tree_model.TreeUsage.mk lvc lrb db
    (alloc.vec.Vec.len t.nodes) lnc)) _
  simp only [spec_ok]
  have h0 : (0#usize).val = 0 := by simp
  have h0' : (0#u64).val = 0 := by simp
  simp only [h0, h0', List.drop_zero] at hfields
  unfold Tree.usage
  simp only [absUsage, absTree_nodes]
  rw [hfields]
  simp

-- ## over_ram / over_count / over_disk ≡ mirror predicates

/-- Equivalence: `tree_model::over_ram` decides the mirror `Tree.overRam`
(and never panics). -/
theorem over_ram_equiv (t : tree_model.TreeModel) :
    tree_model.over_ram t ⦃ b => b = decide (Tree.overRam (absTree t)) ⦄ := by
  unfold tree_model.over_ram
  obtain ⟨u, hu, huPost⟩ := spec_imp_exists (usage_equiv t)
  rw [hu]
  simp only [bind_tc_ok]
  obtain ⟨r, hr, hrPost⟩ := spec_imp_exists (ram_soft_limit_equiv t.budget)
  rw [hr]
  simp only [bind_tc_ok, spec_ok]
  have h1 : u.live_ram_bytes.val = (Tree.usage (absTree t)).liveRamBytes := by
    rw [← huPost]; rfl
  have h2 : (absTree t).budget = absBudget t.budget := rfl
  simp only [Tree.overRam, ← h1, h2, ← hrPost, decide_eq_decide]
  scalar_tac

/-- Equivalence: `tree_model::over_count` decides the mirror
`Tree.overCount` (and never panics). -/
theorem over_count_equiv (t : tree_model.TreeModel) (incoming : Std.U32) :
    tree_model.over_count t incoming
      ⦃ b => b = decide (Tree.overCount (absTree t) incoming.val) ⦄ := by
  unfold tree_model.over_count
  obtain ⟨u, hu, huPost⟩ := spec_imp_exists (usage_equiv t)
  rw [hu]
  simp only [bind_tc_ok]
  step as ⟨inc, hinc⟩
  step as ⟨sum, hsum⟩
  have h1 : u.live_vm_count.val = (Tree.usage (absTree t)).liveVmCount := by
    rw [← huPost]; rfl
  have h2 : (absTree t).budget.maxLiveVms = t.budget.max_live_vms.val := rfl
  simp only [Tree.overCount, h2, decide_eq_decide, ← h1, ← hinc]
  scalar_tac

/-- Equivalence: `tree_model::over_disk` decides the mirror
`Tree.overDisk` (and never panics). -/
theorem over_disk_equiv (t : tree_model.TreeModel) :
    tree_model.over_disk t ⦃ b => b = decide (Tree.overDisk (absTree t)) ⦄ := by
  unfold tree_model.over_disk
  obtain ⟨u, hu, huPost⟩ := spec_imp_exists (usage_equiv t)
  rw [hu]
  simp only [bind_tc_ok, spec_ok]
  have h1 : u.disk_bytes.val = (Tree.usage (absTree t)).diskBytes := by
    rw [← huPost]; rfl
  have h2 : (absTree t).budget.maxDiskBytes = t.budget.max_disk_bytes.val := rfl
  simp only [Tree.overDisk, h2, ← h1, decide_eq_decide]
  scalar_tac

end Verif.Equiv
