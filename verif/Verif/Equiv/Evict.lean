-- internal notes"What to build / 3.6" — equivalence for the Tier-1 RAM
-- eviction loop `auto_evict_ram`. Composes the accounting (3.3) and LRU
-- (3.5) equivalences; the loop recurses on the fuel scalar.
--
-- The loop threads the whole `TreeModel` through `set_state`, so the
-- `hanc`/`hcap` capacity side conditions must survive each iteration.
-- The mirror half of this file proves that `setState` changes no id,
-- parent, or protection flag — hence neither `ancestorIds` nor
-- `implicitlyProtected` — which is exactly what re-establishes the
-- side conditions for the recursive call.

import Verif.Equiv.Lru

namespace Verif.Tree

@[simp] theorem setStateNode_prot (id : Nat) (s : NodeState) (n : NodeInfo) :
    (setStateNode id s n).prot = n.prot := by
  unfold setStateNode; split <;> rfl

@[simp] theorem setState_nodes (t : TreeModel) (v : Nat) (s : NodeState) :
    (setState t v s).nodes = t.nodes.map (setStateNode v s) := rfl

theorem lookup_setState (t : TreeModel) (v : Nat) (s : NodeState) (id : Nat) :
    lookup (setState t v s) id = (lookup t id).map (setStateNode v s) := by
  unfold lookup
  rw [setState_nodes, List.find?_map]
  have hp : ((fun n : NodeInfo => n.id == id) ∘ setStateNode v s)
      = fun n : NodeInfo => n.id == id := by
    funext n
    simp [Function.comp]
  rw [hp]

theorem parentOf_setState (t : TreeModel) (v : Nat) (s : NodeState)
    (id : Nat) : parentOf (setState t v s) id = parentOf t id := by
  unfold parentOf
  rw [lookup_setState]
  cases lookup t id <;> simp

theorem maxId_setState (t : TreeModel) (v : Nat) (s : NodeState) :
    maxId (setState t v s) = maxId t := by
  unfold maxId
  rw [setState_nodes, List.foldl_map]
  congr 1
  funext m n
  rw [setStateNode_id]

theorem ancestorWalk_setState (t : TreeModel) (v : Nat) (s : NodeState) :
    ∀ (f : Nat) (c : Option Nat),
      ancestorWalk (setState t v s) f c = ancestorWalk t f c := by
  intro f
  induction f with
  | zero => intro c; rfl
  | succ f ih =>
    intro c
    cases c with
    | none => rfl
    | some c =>
      show c :: ancestorWalk (setState t v s) f (parentOf (setState t v s) c)
          = c :: ancestorWalk t f (parentOf t c)
      rw [parentOf_setState, ih]

theorem ancestorIds_setState (t : TreeModel) (v : Nat) (s : NodeState)
    (id : Nat) : ancestorIds (setState t v s) id = ancestorIds t id := by
  unfold ancestorIds
  rw [maxId_setState, ancestorWalk_setState]

theorem ipAux_setState (t : TreeModel) (v : Nat) (s : NodeState)
    (l : List NodeInfo) (out : List Nat) :
    implicitlyProtectedAux (setState t v s) (l.map (setStateNode v s)) out
      = implicitlyProtectedAux t l out := by
  induction l generalizing out with
  | nil => rfl
  | cons n ns ih =>
    show implicitlyProtectedAux (setState t v s) (ns.map (setStateNode v s))
        (if (setStateNode v s n).prot then
          insertNew out (ancestorIds (setState t v s) (setStateNode v s n).id)
         else out)
      = implicitlyProtectedAux t ns
          (if n.prot then insertNew out (ancestorIds t n.id) else out)
    rw [setStateNode_prot, setStateNode_id, ancestorIds_setState, ih]

theorem implicitlyProtected_setState (t : TreeModel) (v : Nat)
    (s : NodeState) :
    implicitlyProtected (setState t v s) = implicitlyProtected t :=
  ipAux_setState t v s t.nodes []

end Verif.Tree

namespace Verif.Equiv

open Aeneas Aeneas.Std Result
open Aeneas.Std.WP
open k7d

-- ## auto_evict_ram ≡ Tree.autoEvictRam

theorem auto_evict_ram_loop_equiv (exempt : Slice Std.U64)
    (cur : tree_model.TreeModel) (fuel : Std.Usize)
    (hanc : ∀ id, (Tree.ancestorIds (absTree cur) id).length ≤ Usize.max)
    (hcap : (Tree.implicitlyProtected (absTree cur)).length ≤ Usize.max) :
    tree_model.auto_evict_ram_loop exempt cur fuel
      ⦃ r => absTree r
          = Tree.autoEvictLoop (absSlice exempt) fuel.val (absTree cur) ⦄ := by
  unfold tree_model.auto_evict_ram_loop
  split
  · rename_i hpos
    obtain ⟨f, hf⟩ : ∃ f, fuel.val = f + 1 := ⟨fuel.val - 1, by scalar_tac⟩
    obtain ⟨bR, hbR, hbRPost⟩ := spec_imp_exists (over_ram_equiv cur)
    rw [hbR]
    simp only [bind_tc_ok]
    split
    · rename_i hbt
      rw [hbt] at hbRPost
      have hor : Tree.overRam (absTree cur) := by simpa using hbRPost.symm
      obtain ⟨o, ho, hoPost⟩ := spec_imp_exists
        (lru_live_victim_equiv cur exempt (fun n _ => hanc n.id.val) hcap)
      rw [ho]
      simp only [bind_tc_ok]
      cases o with
      | none =>
        show (ok cur : Result tree_model.TreeModel)
          ⦃ r => absTree r
              = Tree.autoEvictLoop (absSlice exempt) fuel.val (absTree cur) ⦄
        have hv : Tree.lruLiveVictim (absTree cur) (absSlice exempt)
            = none := by simpa using hoPost.symm
        simp only [spec_ok]
        rw [hf]
        simp only [Tree.autoEvictLoop]
        rw [if_neg (by rintro ⟨hno, _⟩; exact hno hor), hv]
      | some v =>
        show (do
            let cur1 ← tree_model.set_state cur v
              tree_model.NodeState.Suspended
            let fuel1 ← fuel - 1#usize
            tree_model.auto_evict_ram_loop exempt cur1 fuel1)
          ⦃ r => absTree r
              = Tree.autoEvictLoop (absSlice exempt) fuel.val (absTree cur) ⦄
        obtain ⟨cur1, hc1, hc1Post⟩ := spec_imp_exists
          (set_state_equiv cur v tree_model.NodeState.Suspended)
        rw [hc1]
        simp only [bind_tc_ok]
        step as ⟨fuel1, hfuel1⟩
        have hsusp : absState tree_model.NodeState.Suspended
            = Tree.NodeState.suspended := rfl
        rw [hsusp] at hc1Post
        obtain ⟨r, hp, hpost⟩ := spec_imp_exists
          (auto_evict_ram_loop_equiv exempt cur1 fuel1
            (by
              intro id
              rw [hc1Post, Tree.ancestorIds_setState]
              exact hanc id)
            (by
              rw [hc1Post, Tree.implicitlyProtected_setState]
              exact hcap))
        rw [hp]
        simp only [spec_ok]
        have hf1 : fuel1.val = f := by scalar_tac
        have hv : Tree.lruLiveVictim (absTree cur) (absSlice exempt)
            = some v.val := by simpa using hoPost.symm
        rw [hpost, hc1Post, hf1, hf]
        simp only [Tree.autoEvictLoop]
        rw [if_neg (by rintro ⟨hno, _⟩; exact hno hor), hv]
    · rename_i hbf
      have hbRf : bR = false := by simpa using hbf
      rw [hbRf] at hbRPost
      have hnor : ¬ Tree.overRam (absTree cur) := by simpa using hbRPost.symm
      obtain ⟨bC, hbC, hbCPost⟩ := spec_imp_exists (over_count_equiv cur 0#u32)
      rw [hbC]
      simp only [bind_tc_ok]
      split
      · rename_i hbt
        rw [hbt] at hbCPost
        have hoc : Tree.overCount (absTree cur) (0#u32).val := by
          simpa using hbCPost.symm
        obtain ⟨o, ho, hoPost⟩ := spec_imp_exists
          (lru_live_victim_equiv cur exempt (fun n _ => hanc n.id.val) hcap)
        rw [ho]
        simp only [bind_tc_ok]
        cases o with
        | none =>
          show (ok cur : Result tree_model.TreeModel)
            ⦃ r => absTree r
                = Tree.autoEvictLoop (absSlice exempt) fuel.val (absTree cur) ⦄
          have hv : Tree.lruLiveVictim (absTree cur) (absSlice exempt)
              = none := by simpa using hoPost.symm
          simp only [spec_ok]
          rw [hf]
          simp only [Tree.autoEvictLoop]
          rw [if_neg (by rintro ⟨_, hno⟩; exact hno (by simpa using hoc)), hv]
        | some v =>
          show (do
              let cur1 ← tree_model.set_state cur v
                tree_model.NodeState.Suspended
              let fuel1 ← fuel - 1#usize
              tree_model.auto_evict_ram_loop exempt cur1 fuel1)
            ⦃ r => absTree r
                = Tree.autoEvictLoop (absSlice exempt) fuel.val (absTree cur) ⦄
          obtain ⟨cur1, hc1, hc1Post⟩ := spec_imp_exists
            (set_state_equiv cur v tree_model.NodeState.Suspended)
          rw [hc1]
          simp only [bind_tc_ok]
          step as ⟨fuel1, hfuel1⟩
          have hsusp : absState tree_model.NodeState.Suspended
              = Tree.NodeState.suspended := rfl
          rw [hsusp] at hc1Post
          obtain ⟨r, hp, hpost⟩ := spec_imp_exists
            (auto_evict_ram_loop_equiv exempt cur1 fuel1
              (by
                intro id
                rw [hc1Post, Tree.ancestorIds_setState]
                exact hanc id)
              (by
                rw [hc1Post, Tree.implicitlyProtected_setState]
                exact hcap))
          rw [hp]
          simp only [spec_ok]
          have hf1 : fuel1.val = f := by scalar_tac
          have hv : Tree.lruLiveVictim (absTree cur) (absSlice exempt)
              = some v.val := by simpa using hoPost.symm
          rw [hpost, hc1Post, hf1, hf]
          simp only [Tree.autoEvictLoop]
          rw [if_neg (by rintro ⟨_, hno⟩; exact hno (by simpa using hoc)), hv]
      · rename_i hbf2
        have hbCf : bC = false := by simpa using hbf2
        rw [hbCf] at hbCPost
        have hnoc : ¬ Tree.overCount (absTree cur) (0#u32).val := by
          simpa using hbCPost.symm
        simp only [spec_ok]
        rw [hf]
        simp only [Tree.autoEvictLoop]
        rw [if_pos ⟨hnor, by simpa using hnoc⟩]
  · rename_i hz
    have h0 : fuel.val = 0 := by scalar_tac
    simp only [spec_ok]
    rw [h0]
    rfl
termination_by fuel.val
decreasing_by all_goals scalar_decr_tac

/-- Equivalence: `tree_model::auto_evict_ram` computes the mirror
`Tree.autoEvictRam` (and never panics). `hanc`/`hcap` are the
`Vec::push` capacity abort points inherited from `implicitly_protected`
inside each `lru_live_victim` call; `hanc` is quantified over all ids
because eviction rewrites states but never ids, parents, or protection
flags (the `setState` invariance lemmas above). -/
theorem auto_evict_ram_equiv (t : tree_model.TreeModel)
    (exempt : Slice Std.U64)
    (hanc : ∀ id, (Tree.ancestorIds (absTree t) id).length ≤ Usize.max)
    (hcap : (Tree.implicitlyProtected (absTree t)).length ≤ Usize.max) :
    tree_model.auto_evict_ram t exempt
      ⦃ r => absTree r = Tree.autoEvictRam (absTree t) (absSlice exempt) ⦄ := by
  unfold tree_model.auto_evict_ram
  simp only [treeModel_clone_eq, bind_tc_ok]
  obtain ⟨r, hp, hpost⟩ := spec_imp_exists
    (auto_evict_ram_loop_equiv exempt t (alloc.vec.Vec.len t.nodes) hanc hcap)
  rw [hp]
  simp only [spec_ok]
  rw [hpost]
  unfold Tree.autoEvictRam
  have hlen : (alloc.vec.Vec.len t.nodes).val = (absTree t).nodes.length := by
    simp [absTree_nodes]
  rw [hlen]

end Verif.Equiv
