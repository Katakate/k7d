-- Equivalence for the protection
-- and LRU-selection group: `implicitly_protected` (the nested loop — the
-- hardest single proof here), `subtree_isolated`,
-- `lru_live_victim`, and `lru_evictable_leaf_subtree`.
--
-- Side conditions: everything that walks ancestor chains inherits the
-- `Vec::push` capacity conditions of `ancestor_ids` (`hanc`: every
-- node's chain fits in a `Vec`), and `implicitly_protected` adds its own
-- (`hcap`: the final dedup'd protection list fits). Both are honest Rust
-- abort points; on a well-formed tree of any realistic size they hold
-- trivially.

import Verif.Equiv.Anc

namespace Verif.Tree

/-- `insertNew` only appends: the accumulator never shrinks. -/
theorem le_length_insertNew (out chain : List Nat) :
    out.length ≤ (insertNew out chain).length := by
  induction chain generalizing out with
  | nil => exact Nat.le_refl _
  | cons c rest ih =>
    show out.length ≤ (insertNew (if c ∈ out then out else out ++ [c]) rest).length
    refine Nat.le_trans ?_ (ih _)
    split
    · exact Nat.le_refl _
    · simp

/-- `implicitlyProtectedAux` only appends. -/
theorem le_length_ipAux (t : TreeModel) (l : List NodeInfo) (out : List Nat) :
    out.length ≤ (implicitlyProtectedAux t l out).length := by
  induction l generalizing out with
  | nil => exact Nat.le_refl _
  | cons n ns ih =>
    show out.length
      ≤ (implicitlyProtectedAux t ns
          (if n.prot then insertNew out (ancestorIds t n.id) else out)).length
    refine Nat.le_trans ?_ (ih _)
    split
    · exact le_length_insertNew _ _
    · exact Nat.le_refl _

end Verif.Tree

namespace Verif.Equiv

open Aeneas Aeneas.Std Result
open Aeneas.Std.WP
open k7d

/-- `Vec::deref` is the identity on the abstraction. -/
@[simp] theorem absSlice_deref (v : alloc.vec.Vec Std.U64) :
    absSlice (alloc.vec.Vec.deref v) = absIds v := rfl

/-- The derived `PartialEq::ne` on the generated `NodeState` decides
mirror-state disequality. -/
@[simp] theorem nodeState_ne_spec (a b : tree_model.NodeState) :
    core.cmp.PartialEq.ne.trait_default
        tree_model.NodeState.Insts.CoreCmpPartialEqNodeState a b
      = ok (decide (absState a ≠ absState b)) := by
  unfold core.cmp.PartialEq.ne.trait_default core.cmp.PartialEq.ne.default
  simp

-- ## implicitly_protected ≡ Tree.implicitlyProtected

theorem insert_new_loop_equiv (out chain : alloc.vec.Vec Std.U64)
    (j : Std.Usize)
    (hcap : (Tree.insertNew (absIds out) ((absIds chain).drop j.val)).length
      ≤ Usize.max) :
    tree_model.implicitly_protected_loop0_loop0 out chain j
      ⦃ r => absIds r
          = Tree.insertNew (absIds out) ((absIds chain).drop j.val) ⦄ := by
  unfold tree_model.implicitly_protected_loop0_loop0
  simp only
  split
  · rename_i hlt
    have hjlen : j.val < chain.val.length := by scalar_tac
    have hjlen' : j.val < (absIds chain).length := by
      simpa [absIds] using hjlen
    have hdrop : (absIds chain).drop j.val
        = (chain.val[j.val]'hjlen).val :: (absIds chain).drop (j.val + 1) := by
      rw [List.drop_eq_getElem_cons hjlen']
      simp [absIds]
    step as ⟨cj, hcj⟩
    obtain ⟨b, hb, hbPost⟩ := spec_imp_exists
      (contains_id_equiv (alloc.vec.Vec.deref out) cj)
    rw [hb]
    simp only [bind_tc_ok]
    simp only [absSlice_deref] at hbPost
    rw [hdrop] at hcap ⊢
    have hstep : Tree.insertNew (absIds out)
        ((chain.val[j.val]'hjlen).val :: (absIds chain).drop (j.val + 1))
        = Tree.insertNew
            (if (chain.val[j.val]'hjlen).val ∈ absIds out then absIds out
             else absIds out ++ [(chain.val[j.val]'hjlen).val])
            ((absIds chain).drop (j.val + 1)) := rfl
    subst hcj
    split
    · rename_i hbt
      have hmem : (chain.val[j.val]'hjlen).val ∈ absIds out := by
        rw [hbt] at hbPost
        simpa using hbPost
      step as ⟨j1, hj1⟩
      obtain ⟨r, hp, hpost⟩ := spec_imp_exists
        (insert_new_loop_equiv out chain j1
          (by rw [hj1]; rw [hstep, if_pos hmem] at hcap; exact hcap))
      rw [hp]
      simp only [spec_ok]
      rw [hpost, hj1, hstep, if_pos hmem]
    · rename_i hbf
      have hmem : (chain.val[j.val]'hjlen).val ∉ absIds out := by
        have hb' : b = false := by simpa using hbf
        rw [hb'] at hbPost
        simpa using hbPost
      rw [hstep, if_neg hmem] at hcap
      have hlt2 : out.val.length < Usize.max := by
        have := Tree.le_length_insertNew
          (absIds out ++ [(chain.val[j.val]'hjlen).val])
          ((absIds chain).drop (j.val + 1))
        simp only [List.length_append, List.length_cons, List.length_nil,
          absIds, List.length_map] at this hcap ⊢
        omega
      step as ⟨out1, hout1⟩
      step as ⟨j1, hj1⟩
      have habs : absIds out1
          = absIds out ++ [(chain.val[j.val]'hjlen).val] := by
        simp [absIds, hout1]
      obtain ⟨r, hp, hpost⟩ := spec_imp_exists
        (insert_new_loop_equiv out1 chain j1 (by rw [hj1, habs]; exact hcap))
      rw [hp]
      simp only [spec_ok]
      rw [hpost, hj1, habs, hstep, if_neg hmem]
  · rename_i hge
    have hlen : chain.val.length ≤ j.val := by scalar_tac
    have hlen' : (absIds chain).length ≤ j.val := by simpa [absIds] using hlen
    simp only [spec_ok]
    rw [List.drop_eq_nil_of_le hlen']
    rfl
termination_by chain.val.length - j.val
decreasing_by all_goals scalar_decr_tac

theorem implicitly_protected_loop_equiv (t : tree_model.TreeModel)
    (out : alloc.vec.Vec Std.U64) (i : Std.Usize)
    (hanc : ∀ n ∈ t.nodes.val,
      (Tree.ancestorIds (absTree t) n.id.val).length ≤ Usize.max)
    (hcap : (Tree.implicitlyProtectedAux (absTree t)
        ((absTree t).nodes.drop i.val) (absIds out)).length ≤ Usize.max) :
    tree_model.implicitly_protected_loop0 t out i
      ⦃ r => absIds r = Tree.implicitlyProtectedAux (absTree t)
          ((absTree t).nodes.drop i.val) (absIds out) ⦄ := by
  unfold tree_model.implicitly_protected_loop0
  simp only
  split
  · rename_i hlt
    have hilen : i.val < t.nodes.val.length := by scalar_tac
    have hilen' : i.val < (absTree t).nodes.length := by
      simpa [absTree_nodes] using hilen
    step as ⟨ni, hni⟩
    have hdrop : (absTree t).nodes.drop i.val
        = absNode ni :: (absTree t).nodes.drop (i.val + 1) := by
      rw [List.drop_eq_getElem_cons hilen']
      simp only [absTree_nodes, List.getElem_map]
      rw [← hni]
    rw [hdrop] at hcap ⊢
    have hstep : Tree.implicitlyProtectedAux (absTree t)
        (absNode ni :: (absTree t).nodes.drop (i.val + 1)) (absIds out)
        = Tree.implicitlyProtectedAux (absTree t)
            ((absTree t).nodes.drop (i.val + 1))
            (if (absNode ni).prot
             then Tree.insertNew (absIds out)
               (Tree.ancestorIds (absTree t) (absNode ni).id)
             else absIds out) := rfl
    split
    · rename_i hprot
      have hprot' : (absNode ni).prot = true := hprot
      rw [hstep, if_pos hprot'] at hcap
      obtain ⟨chain, hchain, hchainPost⟩ := spec_imp_exists
        (ancestor_ids_equiv t ni.id
          (by
            rw [hni]
            have := hanc _ (List.getElem_mem hilen)
            simpa using this))
      rw [hchain]
      simp only [bind_tc_ok]
      obtain ⟨out1, hout1, hout1Post⟩ := spec_imp_exists
        (insert_new_loop_equiv out chain 0#usize
          (by
            have h0 : ((0#usize : Std.Usize)).val = 0 := by simp
            rw [h0, List.drop_zero, hchainPost]
            refine Nat.le_trans (Tree.le_length_ipAux _ _ _) hcap))
      rw [hout1]
      simp only [bind_tc_ok]
      have h0 : ((0#usize : Std.Usize)).val = 0 := by simp
      rw [h0, List.drop_zero, hchainPost] at hout1Post
      step as ⟨i2, hi2⟩
      obtain ⟨r, hp, hpost⟩ := spec_imp_exists
        (implicitly_protected_loop_equiv t out1 i2 hanc
          (by rw [hi2, hout1Post]; exact hcap))
      rw [hp]
      simp only [spec_ok]
      rw [hpost, hi2, hout1Post, hstep, if_pos hprot']
      simp only [absNode_id]
    · rename_i hprot
      have hprot' : ¬ (absNode ni).prot = true := hprot
      rw [hstep, if_neg hprot'] at hcap
      step as ⟨i2, hi2⟩
      obtain ⟨r, hp, hpost⟩ := spec_imp_exists
        (implicitly_protected_loop_equiv t out i2 hanc
          (by rw [hi2]; exact hcap))
      rw [hp]
      simp only [spec_ok]
      rw [hpost, hi2, hstep, if_neg hprot']
  · rename_i hge
    have hlen : t.nodes.val.length ≤ i.val := by scalar_tac
    have hlen' : (absTree t).nodes.length ≤ i.val := by
      simpa [absTree_nodes] using hlen
    simp only [spec_ok]
    rw [List.drop_eq_nil_of_le hlen']
    rfl
termination_by t.nodes.val.length - i.val
decreasing_by all_goals scalar_decr_tac

/-- Equivalence: `tree_model::implicitly_protected` computes the mirror
`Tree.implicitlyProtected` (and never panics). `hanc`/`hcap` are the
`Vec::push` capacity abort points inherited from `ancestor_ids` and the
dedup-append loop. -/
theorem implicitly_protected_equiv (t : tree_model.TreeModel)
    (hanc : ∀ n ∈ t.nodes.val,
      (Tree.ancestorIds (absTree t) n.id.val).length ≤ Usize.max)
    (hcap : (Tree.implicitlyProtected (absTree t)).length ≤ Usize.max) :
    tree_model.implicitly_protected t
      ⦃ r => absIds r = Tree.implicitlyProtected (absTree t) ⦄ := by
  unfold tree_model.implicitly_protected
  unfold Tree.implicitlyProtected at hcap
  obtain ⟨r, hp, hpost⟩ := spec_imp_exists
    (implicitly_protected_loop_equiv t (alloc.vec.Vec.new Std.U64) 0#usize hanc
      (by
        have h0 : ((0#usize : Std.Usize)).val = 0 := by simp
        rw [h0, List.drop_zero]
        simpa [absIds] using hcap))
  rw [hp]
  simp only [spec_ok]
  rw [hpost]
  unfold Tree.implicitlyProtected
  have h0 : ((0#usize : Std.Usize)).val = 0 := by simp
  rw [h0, List.drop_zero]
  simp [absIds]

-- ## subtree_isolated ≡ Tree.subtreeIsolated

/-- Per-node obligation of `Tree.subtreeIsolated`, split out so the scan
invariant of the generated loop can quantify over a `drop` suffix. -/
def isoAt (t : Tree.TreeModel) (root : Nat) (d : Tree.NodeInfo) : Prop :=
  d.id ≠ root → root ∈ Tree.ancestorIds t d.id → d.state = .evicted

instance (t : Tree.TreeModel) (root : Nat) : DecidablePred (isoAt t root) :=
  fun _ => by unfold isoAt; infer_instance

theorem subtree_isolated_loop_equiv (t : tree_model.TreeModel)
    (root : Std.U64) (i : Std.Usize)
    (hanc : ∀ n ∈ t.nodes.val,
      (Tree.ancestorIds (absTree t) n.id.val).length ≤ Usize.max) :
    tree_model.subtree_isolated_loop t root i
      ⦃ b => b = decide (∀ d ∈ (absTree t).nodes.drop i.val,
          isoAt (absTree t) root.val d) ⦄ := by
  unfold tree_model.subtree_isolated_loop
  simp only
  split
  · rename_i hlt
    have hilen : i.val < t.nodes.val.length := by scalar_tac
    have hilen' : i.val < (absTree t).nodes.length := by
      simpa [absTree_nodes] using hilen
    step as ⟨d, hd⟩
    have hdrop : (absTree t).nodes.drop i.val
        = absNode d :: (absTree t).nodes.drop (i.val + 1) := by
      rw [List.drop_eq_getElem_cons hilen']
      simp only [absTree_nodes, List.getElem_map]
      rw [← hd]
    rw [hdrop]
    split
    · rename_i hne
      have hne' : (absNode d).id ≠ root.val := by
        simp only [absNode_id]; scalar_tac
      simp only [nodeState_ne_spec, bind_tc_ok]
      split
      · rename_i hb
        have hnev : absState d.state ≠ Tree.NodeState.evicted := by
          simpa [absState] using hb
        obtain ⟨v, hv, hvPost⟩ := spec_imp_exists
          (ancestor_ids_equiv t d.id
            (by
              rw [hd]
              have := hanc _ (List.getElem_mem hilen)
              simpa using this))
        rw [hv]
        simp only [bind_tc_ok]
        obtain ⟨b1, hb1, hb1Post⟩ := spec_imp_exists
          (contains_id_equiv (alloc.vec.Vec.deref v) root)
        rw [hb1]
        simp only [bind_tc_ok]
        simp only [absSlice_deref, hvPost] at hb1Post
        split
        · rename_i hbt
          have hmem : root.val ∈ Tree.ancestorIds (absTree t) d.id.val := by
            rw [hbt] at hb1Post
            simpa using hb1Post.symm
          simp only [spec_ok]
          symm
          rw [decide_eq_false_iff_not]
          intro hall
          have hhead := hall (absNode d) (List.mem_cons_self ..)
          unfold isoAt at hhead
          exact hnev (by
            simpa [absNode_state] using
              hhead hne' (by simpa [absNode_id] using hmem))
        · rename_i hbf
          have hb1f : b1 = false := by simpa using hbf
          rw [hb1f] at hb1Post
          have hnmem : root.val ∉ Tree.ancestorIds (absTree t) d.id.val := by
            simpa using hb1Post
          have hQ : isoAt (absTree t) root.val (absNode d) := by
            unfold isoAt
            intro _ hm
            exact absurd (by simpa [absNode_id] using hm) hnmem
          step as ⟨i2, hi2⟩
          obtain ⟨r, hp, hpost⟩ := spec_imp_exists
            (subtree_isolated_loop_equiv t root i2 hanc)
          rw [hp]
          simp only [spec_ok]
          rw [hpost, hi2, decide_eq_decide, List.forall_mem_cons]
          exact (and_iff_right hQ).symm
      · rename_i hb
        have hev : absState d.state = Tree.NodeState.evicted := by
          simpa [absState] using hb
        have hQ : isoAt (absTree t) root.val (absNode d) := by
          unfold isoAt
          intro _ _
          simpa [absNode_state] using hev
        step as ⟨i2, hi2⟩
        obtain ⟨r, hp, hpost⟩ := spec_imp_exists
          (subtree_isolated_loop_equiv t root i2 hanc)
        rw [hp]
        simp only [spec_ok]
        rw [hpost, hi2, decide_eq_decide, List.forall_mem_cons]
        exact (and_iff_right hQ).symm
    · rename_i heq
      have heq' : (absNode d).id = root.val := by
        simp only [absNode_id]; scalar_tac
      have hQ : isoAt (absTree t) root.val (absNode d) := by
        unfold isoAt
        intro hne _
        exact absurd heq' hne
      step as ⟨i2, hi2⟩
      obtain ⟨r, hp, hpost⟩ := spec_imp_exists
        (subtree_isolated_loop_equiv t root i2 hanc)
      rw [hp]
      simp only [spec_ok]
      rw [hpost, hi2, decide_eq_decide, List.forall_mem_cons]
      exact (and_iff_right hQ).symm
  · rename_i hge
    have hlen : t.nodes.val.length ≤ i.val := by scalar_tac
    have hlen' : (absTree t).nodes.length ≤ i.val := by
      simpa [absTree_nodes] using hlen
    simp only [spec_ok]
    rw [List.drop_eq_nil_of_le hlen']
    simp
termination_by t.nodes.val.length - i.val
decreasing_by all_goals scalar_decr_tac

/-- Equivalence: `tree_model::subtree_isolated` decides the mirror
`Tree.subtreeIsolated` (and never panics). `hanc` marks the `Vec::push`
capacity abort points of the per-node `ancestor_ids` calls. -/
theorem subtree_isolated_equiv (t : tree_model.TreeModel) (root : Std.U64)
    (hanc : ∀ n ∈ t.nodes.val,
      (Tree.ancestorIds (absTree t) n.id.val).length ≤ Usize.max) :
    tree_model.subtree_isolated t root
      ⦃ b => b = decide (Tree.subtreeIsolated (absTree t) root.val) ⦄ := by
  unfold tree_model.subtree_isolated
  obtain ⟨b, hb, hbPost⟩ := spec_imp_exists
    (subtree_isolated_loop_equiv t root 0#usize hanc)
  rw [hb]
  simp only [spec_ok]
  rw [hbPost]
  have h0 : ((0#usize : Std.Usize)).val = 0 := by simp
  rw [h0, List.drop_zero, decide_eq_decide]
  unfold Tree.subtreeIsolated isoAt
  exact Iff.rfl

-- ## The shared LRU accumulator

/-- Abstraction: generated `(last_active, id)` accumulator → mirror. -/
def absBest : Option (Std.U64 × Std.U64) → Option (Nat × Nat)
  | none => none
  | some (la, id) => some (la.val, id.val)

@[simp] theorem absBest_none : absBest none = none := rfl

@[simp] theorem absBest_some (la id : Std.U64) :
    absBest (some (la, id)) = some (la.val, id.val) := rfl

-- ## lru_live_victim ≡ Tree.lruLiveVictim

theorem lru_live_victim_loop_equiv (t : tree_model.TreeModel)
    (exempt : Slice Std.U64) (prot : alloc.vec.Vec Std.U64)
    (best : Option (Std.U64 × Std.U64)) (i : Std.Usize)
    (hprot : absIds prot = Tree.implicitlyProtected (absTree t)) :
    tree_model.lru_live_victim_loop t exempt prot best i
      ⦃ r => absBest r
          = Tree.selectLruAux (Tree.eligibleLive (absTree t) (absSlice exempt))
              ((absTree t).nodes.drop i.val) (absBest best) ⦄ := by
  unfold tree_model.lru_live_victim_loop
  simp only
  split
  · rename_i hlt
    have hilen : i.val < t.nodes.val.length := by scalar_tac
    have hilen' : i.val < (absTree t).nodes.length := by
      simpa [absTree_nodes] using hilen
    step as ⟨ni, hni⟩
    have hdrop : (absTree t).nodes.drop i.val
        = absNode ni :: (absTree t).nodes.drop (i.val + 1) := by
      rw [List.drop_eq_getElem_cons hilen']
      simp only [absTree_nodes, List.getElem_map]
      rw [← hni]
    have hstep : Tree.selectLruAux
        (Tree.eligibleLive (absTree t) (absSlice exempt))
        (absNode ni :: (absTree t).nodes.drop (i.val + 1)) (absBest best)
        = Tree.selectLruAux (Tree.eligibleLive (absTree t) (absSlice exempt))
            ((absTree t).nodes.drop (i.val + 1))
            (if Tree.eligibleLive (absTree t) (absSlice exempt) (absNode ni)
             then Tree.betterOf (absBest best) (absNode ni)
             else absBest best) := rfl
    simp only [nodeState_eq_spec, bind_tc_ok]
    obtain ⟨bex, hbex, hbexPost⟩ := spec_imp_exists
      (contains_id_equiv exempt ni.id)
    rw [hbex]
    simp only [bind_tc_ok]
    obtain ⟨bpr, hbpr, hbprPost⟩ := spec_imp_exists
      (contains_id_equiv (alloc.vec.Vec.deref prot) ni.id)
    rw [hbpr]
    simp only [bind_tc_ok]
    simp only [absSlice_deref, hprot] at hbprPost
    split
    · rename_i hlive
      have hlive' : absState ni.state = Tree.NodeState.live := by
        simpa [absState] using hlive
      split
      · rename_i hex
        rw [hex] at hbexPost
        have hex' : ni.id.val ∈ absSlice exempt := by
          simpa using hbexPost.symm
        have hnE : ¬ Tree.eligibleLive (absTree t) (absSlice exempt)
            (absNode ni) := by
          unfold Tree.eligibleLive
          simp only [absNode_id]
          rintro ⟨_, hne, _⟩
          exact hne hex'
        step as ⟨i2, hi2⟩
        obtain ⟨r, hp, hpost⟩ := spec_imp_exists
          (lru_live_victim_loop_equiv t exempt prot best i2 hprot)
        rw [hp]
        simp only [spec_ok]
        rw [hpost, hi2, hdrop, hstep, if_neg hnE]
      · rename_i hex
        have hexf : bex = false := by simpa using hex
        rw [hexf] at hbexPost
        have hex' : ni.id.val ∉ absSlice exempt := by
          simpa using hbexPost.symm
        split
        · rename_i hpr
          rw [hpr] at hbprPost
          have hpr' : ni.id.val ∈ Tree.implicitlyProtected (absTree t) := by
            simpa using hbprPost.symm
          have hnE : ¬ Tree.eligibleLive (absTree t) (absSlice exempt)
              (absNode ni) := by
            unfold Tree.eligibleLive
            simp only [absNode_id]
            rintro ⟨_, _, hnp⟩
            exact hnp hpr'
          step as ⟨i2, hi2⟩
          obtain ⟨r, hp, hpost⟩ := spec_imp_exists
            (lru_live_victim_loop_equiv t exempt prot best i2 hprot)
          rw [hp]
          simp only [spec_ok]
          rw [hpost, hi2, hdrop, hstep, if_neg hnE]
        · rename_i hpr
          have hprf : bpr = false := by simpa using hpr
          rw [hprf] at hbprPost
          have hpr' : ni.id.val ∉ Tree.implicitlyProtected (absTree t) := by
            simpa using hbprPost.symm
          have hE : Tree.eligibleLive (absTree t) (absSlice exempt)
              (absNode ni) := by
            unfold Tree.eligibleLive
            simp only [absNode_id, absNode_state]
            exact ⟨hlive', hex', hpr'⟩
          rcases best with _ | ⟨bla, bid⟩
          · show (do
                let i2 ← i + 1#usize
                tree_model.lru_live_victim_loop t exempt prot
                  (some (ni.last_active, ni.id)) i2)
              ⦃ r => absBest r
                  = Tree.selectLruAux
                      (Tree.eligibleLive (absTree t) (absSlice exempt))
                      ((absTree t).nodes.drop i.val) (absBest none) ⦄
            step as ⟨i2, hi2⟩
            obtain ⟨r, hp, hpost⟩ := spec_imp_exists
              (lru_live_victim_loop_equiv t exempt prot
                (some (ni.last_active, ni.id)) i2 hprot)
            rw [hp]
            simp only [spec_ok]
            rw [hpost, hi2, hdrop, hstep, if_pos hE]
            rfl
          · show (do
                let best1 ←
                  if decide (ni.last_active < bla) = true
                  then ok (some (ni.last_active, ni.id))
                  else ok (some (bla, bid))
                let i2 ← i + 1#usize
                tree_model.lru_live_victim_loop t exempt prot best1 i2)
              ⦃ r => absBest r
                  = Tree.selectLruAux
                      (Tree.eligibleLive (absTree t) (absSlice exempt))
                      ((absTree t).nodes.drop i.val)
                      (absBest (some (bla, bid))) ⦄
            split
            · rename_i hlt2
              have hbo : Tree.betterOf (absBest (some (bla, bid)))
                  (absNode ni) = some (ni.last_active.val, ni.id.val) := by
                simp only [absBest_some, Tree.betterOf]
                rw [if_pos (by simp only [absNode_lastActive]; scalar_tac :
                  (absNode ni).lastActive < bla.val)]
                simp
              simp only [bind_tc_ok]
              step as ⟨i2, hi2⟩
              obtain ⟨r, hp, hpost⟩ := spec_imp_exists
                (lru_live_victim_loop_equiv t exempt prot
                  (some (ni.last_active, ni.id)) i2 hprot)
              rw [hp]
              simp only [spec_ok]
              rw [hpost, hi2, hdrop, hstep, if_pos hE, hbo]
              rfl
            · rename_i hge2
              have hbo : Tree.betterOf (absBest (some (bla, bid)))
                  (absNode ni) = some (bla.val, bid.val) := by
                simp only [absBest_some, Tree.betterOf]
                rw [if_neg (by simp only [absNode_lastActive]; scalar_tac :
                  ¬ (absNode ni).lastActive < bla.val)]
              simp only [bind_tc_ok]
              step as ⟨i2, hi2⟩
              obtain ⟨r, hp, hpost⟩ := spec_imp_exists
                (lru_live_victim_loop_equiv t exempt prot
                  (some (bla, bid)) i2 hprot)
              rw [hp]
              simp only [spec_ok]
              rw [hpost, hi2, hdrop, hstep, if_pos hE, hbo]
              rfl
    · rename_i hlive
      have hnlive : ¬ absState ni.state = Tree.NodeState.live := by
        simpa [absState] using hlive
      have hnE : ¬ Tree.eligibleLive (absTree t) (absSlice exempt)
          (absNode ni) := by
        unfold Tree.eligibleLive
        simp only [absNode_state]
        rintro ⟨hst, _, _⟩
        exact hnlive hst
      step as ⟨i2, hi2⟩
      obtain ⟨r, hp, hpost⟩ := spec_imp_exists
        (lru_live_victim_loop_equiv t exempt prot best i2 hprot)
      rw [hp]
      simp only [spec_ok]
      rw [hpost, hi2, hdrop, hstep, if_neg hnE]
  · rename_i hge
    have hlen : t.nodes.val.length ≤ i.val := by scalar_tac
    have hlen' : (absTree t).nodes.length ≤ i.val := by
      simpa [absTree_nodes] using hlen
    simp only [spec_ok]
    rw [List.drop_eq_nil_of_le hlen']
    rfl
termination_by t.nodes.val.length - i.val
decreasing_by all_goals scalar_decr_tac

/-- Equivalence: `tree_model::lru_live_victim` computes the mirror
`Tree.lruLiveVictim` (and never panics). `hanc`/`hcap` are inherited
from the `implicitly_protected` prologue. -/
theorem lru_live_victim_equiv (t : tree_model.TreeModel)
    (exempt : Slice Std.U64)
    (hanc : ∀ n ∈ t.nodes.val,
      (Tree.ancestorIds (absTree t) n.id.val).length ≤ Usize.max)
    (hcap : (Tree.implicitlyProtected (absTree t)).length ≤ Usize.max) :
    tree_model.lru_live_victim t exempt
      ⦃ r => r.map (·.val)
          = Tree.lruLiveVictim (absTree t) (absSlice exempt) ⦄ := by
  unfold tree_model.lru_live_victim
  obtain ⟨prot, hprot, hprotPost⟩ := spec_imp_exists
    (implicitly_protected_equiv t hanc hcap)
  rw [hprot]
  simp only [bind_tc_ok]
  obtain ⟨best, hbest, hbestPost⟩ := spec_imp_exists
    (lru_live_victim_loop_equiv t exempt prot none 0#usize hprotPost)
  rw [hbest]
  simp only [bind_tc_ok]
  have h0 : ((0#usize : Std.Usize)).val = 0 := by simp
  rw [h0, List.drop_zero, absBest_none] at hbestPost
  unfold Tree.lruLiveVictim Tree.selectLru
  rw [absTree_nodes] at hbestPost ⊢
  rw [← hbestPost]
  rcases best with _ | ⟨la, id⟩
  · simp [absBest]
  · simp [absBest]

-- ## lru_evictable_leaf_subtree ≡ Tree.lruEvictableLeafSubtree

theorem lru_evictable_leaf_subtree_loop_equiv (t : tree_model.TreeModel)
    (prot : alloc.vec.Vec Std.U64)
    (best : Option (Std.U64 × Std.U64)) (i : Std.Usize)
    (hanc : ∀ n ∈ t.nodes.val,
      (Tree.ancestorIds (absTree t) n.id.val).length ≤ Usize.max)
    (hprot : absIds prot = Tree.implicitlyProtected (absTree t)) :
    tree_model.lru_evictable_leaf_subtree_loop t prot best i
      ⦃ r => absBest r
          = Tree.selectLruAux (Tree.eligibleLeaf (absTree t))
              ((absTree t).nodes.drop i.val) (absBest best) ⦄ := by
  unfold tree_model.lru_evictable_leaf_subtree_loop
  simp only
  split
  · rename_i hlt
    have hilen : i.val < t.nodes.val.length := by scalar_tac
    have hilen' : i.val < (absTree t).nodes.length := by
      simpa [absTree_nodes] using hilen
    step as ⟨ni, hni⟩
    have hdrop : (absTree t).nodes.drop i.val
        = absNode ni :: (absTree t).nodes.drop (i.val + 1) := by
      rw [List.drop_eq_getElem_cons hilen']
      simp only [absTree_nodes, List.getElem_map]
      rw [← hni]
    have hstep : Tree.selectLruAux (Tree.eligibleLeaf (absTree t))
        (absNode ni :: (absTree t).nodes.drop (i.val + 1)) (absBest best)
        = Tree.selectLruAux (Tree.eligibleLeaf (absTree t))
            ((absTree t).nodes.drop (i.val + 1))
            (if Tree.eligibleLeaf (absTree t) (absNode ni)
             then Tree.betterOf (absBest best) (absNode ni)
             else absBest best) := rfl
    simp only [nodeState_eq_spec, bind_tc_ok]
    obtain ⟨bpr, hbpr, hbprPost⟩ := spec_imp_exists
      (contains_id_equiv (alloc.vec.Vec.deref prot) ni.id)
    rw [hbpr]
    simp only [bind_tc_ok]
    simp only [absSlice_deref, hprot] at hbprPost
    obtain ⟨biso, hbiso, hbisoPost⟩ := spec_imp_exists
      (subtree_isolated_equiv t ni.id hanc)
    rw [hbiso]
    simp only [bind_tc_ok]
    split
    · rename_i hsusp
      have hsusp' : absState ni.state = Tree.NodeState.suspended := by
        simpa [absState] using hsusp
      split
      · rename_i hpr
        rw [hpr] at hbprPost
        have hpr' : ni.id.val ∈ Tree.implicitlyProtected (absTree t) := by
          simpa using hbprPost.symm
        have hnE : ¬ Tree.eligibleLeaf (absTree t) (absNode ni) := by
          unfold Tree.eligibleLeaf
          simp only [absNode_id]
          rintro ⟨_, hnp, _⟩
          exact hnp hpr'
        step as ⟨i2, hi2⟩
        obtain ⟨r, hp, hpost⟩ := spec_imp_exists
          (lru_evictable_leaf_subtree_loop_equiv t prot best i2 hanc hprot)
        rw [hp]
        simp only [spec_ok]
        rw [hpost, hi2, hdrop, hstep, if_neg hnE]
      · rename_i hpr
        have hprf : bpr = false := by simpa using hpr
        rw [hprf] at hbprPost
        have hpr' : ni.id.val ∉ Tree.implicitlyProtected (absTree t) := by
          simpa using hbprPost.symm
        split
        · rename_i hiso
          rw [hiso] at hbisoPost
          have hiso' : Tree.subtreeIsolated (absTree t) ni.id.val := by
            simpa using hbisoPost.symm
          have hE : Tree.eligibleLeaf (absTree t) (absNode ni) := by
            unfold Tree.eligibleLeaf
            simp only [absNode_id, absNode_state]
            exact ⟨hsusp', hpr', hiso'⟩
          rcases best with _ | ⟨bla, bid⟩
          · show (do
                let i2 ← i + 1#usize
                tree_model.lru_evictable_leaf_subtree_loop t prot
                  (some (ni.last_active, ni.id)) i2)
              ⦃ r => absBest r
                  = Tree.selectLruAux (Tree.eligibleLeaf (absTree t))
                      ((absTree t).nodes.drop i.val) (absBest none) ⦄
            step as ⟨i2, hi2⟩
            obtain ⟨r, hp, hpost⟩ := spec_imp_exists
              (lru_evictable_leaf_subtree_loop_equiv t prot
                (some (ni.last_active, ni.id)) i2 hanc hprot)
            rw [hp]
            simp only [spec_ok]
            rw [hpost, hi2, hdrop, hstep, if_pos hE]
            rfl
          · show (do
                let best1 ←
                  if decide (ni.last_active < bla) = true
                  then ok (some (ni.last_active, ni.id))
                  else ok (some (bla, bid))
                let i2 ← i + 1#usize
                tree_model.lru_evictable_leaf_subtree_loop t prot best1 i2)
              ⦃ r => absBest r
                  = Tree.selectLruAux (Tree.eligibleLeaf (absTree t))
                      ((absTree t).nodes.drop i.val)
                      (absBest (some (bla, bid))) ⦄
            split
            · rename_i hlt2
              have hbo : Tree.betterOf (absBest (some (bla, bid)))
                  (absNode ni) = some (ni.last_active.val, ni.id.val) := by
                simp only [absBest_some, Tree.betterOf]
                rw [if_pos (by simp only [absNode_lastActive]; scalar_tac :
                  (absNode ni).lastActive < bla.val)]
                simp
              simp only [bind_tc_ok]
              step as ⟨i2, hi2⟩
              obtain ⟨r, hp, hpost⟩ := spec_imp_exists
                (lru_evictable_leaf_subtree_loop_equiv t prot
                  (some (ni.last_active, ni.id)) i2 hanc hprot)
              rw [hp]
              simp only [spec_ok]
              rw [hpost, hi2, hdrop, hstep, if_pos hE, hbo]
              rfl
            · rename_i hge2
              have hbo : Tree.betterOf (absBest (some (bla, bid)))
                  (absNode ni) = some (bla.val, bid.val) := by
                simp only [absBest_some, Tree.betterOf]
                rw [if_neg (by simp only [absNode_lastActive]; scalar_tac :
                  ¬ (absNode ni).lastActive < bla.val)]
              simp only [bind_tc_ok]
              step as ⟨i2, hi2⟩
              obtain ⟨r, hp, hpost⟩ := spec_imp_exists
                (lru_evictable_leaf_subtree_loop_equiv t prot
                  (some (bla, bid)) i2 hanc hprot)
              rw [hp]
              simp only [spec_ok]
              rw [hpost, hi2, hdrop, hstep, if_pos hE, hbo]
              rfl
        · rename_i hiso
          have hisof : biso = false := by simpa using hiso
          rw [hisof] at hbisoPost
          have hiso' : ¬ Tree.subtreeIsolated (absTree t) ni.id.val := by
            simpa using hbisoPost.symm
          have hnE : ¬ Tree.eligibleLeaf (absTree t) (absNode ni) := by
            unfold Tree.eligibleLeaf
            simp only [absNode_id]
            rintro ⟨_, _, hsub⟩
            exact hiso' hsub
          step as ⟨i2, hi2⟩
          obtain ⟨r, hp, hpost⟩ := spec_imp_exists
            (lru_evictable_leaf_subtree_loop_equiv t prot best i2 hanc hprot)
          rw [hp]
          simp only [spec_ok]
          rw [hpost, hi2, hdrop, hstep, if_neg hnE]
    · rename_i hsusp
      have hnsusp : ¬ absState ni.state = Tree.NodeState.suspended := by
        simpa [absState] using hsusp
      have hnE : ¬ Tree.eligibleLeaf (absTree t) (absNode ni) := by
        unfold Tree.eligibleLeaf
        simp only [absNode_state]
        rintro ⟨hst, _, _⟩
        exact hnsusp hst
      step as ⟨i2, hi2⟩
      obtain ⟨r, hp, hpost⟩ := spec_imp_exists
        (lru_evictable_leaf_subtree_loop_equiv t prot best i2 hanc hprot)
      rw [hp]
      simp only [spec_ok]
      rw [hpost, hi2, hdrop, hstep, if_neg hnE]
  · rename_i hge
    have hlen : t.nodes.val.length ≤ i.val := by scalar_tac
    have hlen' : (absTree t).nodes.length ≤ i.val := by
      simpa [absTree_nodes] using hlen
    simp only [spec_ok]
    rw [List.drop_eq_nil_of_le hlen']
    rfl
termination_by t.nodes.val.length - i.val
decreasing_by all_goals scalar_decr_tac

/-- Equivalence: `tree_model::lru_evictable_leaf_subtree` computes the
mirror `Tree.lruEvictableLeafSubtree` (and never panics). `hanc`/`hcap`
are inherited from `implicitly_protected` and the per-node
`subtree_isolated` calls. -/
theorem lru_evictable_leaf_subtree_equiv (t : tree_model.TreeModel)
    (hanc : ∀ n ∈ t.nodes.val,
      (Tree.ancestorIds (absTree t) n.id.val).length ≤ Usize.max)
    (hcap : (Tree.implicitlyProtected (absTree t)).length ≤ Usize.max) :
    tree_model.lru_evictable_leaf_subtree t
      ⦃ r => r.map (·.val) = Tree.lruEvictableLeafSubtree (absTree t) ⦄ := by
  unfold tree_model.lru_evictable_leaf_subtree
  obtain ⟨prot, hprot, hprotPost⟩ := spec_imp_exists
    (implicitly_protected_equiv t hanc hcap)
  rw [hprot]
  simp only [bind_tc_ok]
  obtain ⟨best, hbest, hbestPost⟩ := spec_imp_exists
    (lru_evictable_leaf_subtree_loop_equiv t prot none 0#usize hanc hprotPost)
  rw [hbest]
  simp only [bind_tc_ok]
  have h0 : ((0#usize : Std.Usize)).val = 0 := by simp
  rw [h0, List.drop_zero, absBest_none] at hbestPost
  unfold Tree.lruEvictableLeafSubtree Tree.selectLru
  rw [absTree_nodes] at hbestPost ⊢
  rw [← hbestPost]
  rcases best with _ | ⟨la, id⟩
  · simp [absBest]
  · simp [absBest]

end Verif.Equiv
