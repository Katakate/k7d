-- internal notes"What to build / 3.2" — equivalence for the rebuild
-- loops: `touch`, `set_state`, `set_protected`, `add_child`. Each scans
-- `t.nodes` and pushes a (possibly updated) copy of every node into a
-- fresh `Vec`, so on top of the scan recipe from `Scans.lean` these
-- proofs thread a `Vec.push` capacity invariant
-- (`built + remaining ≤ usize::MAX`) through the induction.
--
-- `add_child` needs two genuine side conditions — `t.nodes.len() <
-- usize::MAX` (the final push of the new child) and `children.len() <
-- usize::MAX` per node (the parent-bump push). They mark the real Rust
-- abort points (`Vec::push` capacity overflow); on any tree that fits in
-- memory both hold trivially.

import Verif.Equiv.Scans

namespace Verif.Tree

-- Mirrors for the two rebuild helpers no Group A–D theorem needed
-- (the equivalence theorems below are their only consumers). Same
-- style as `bumpParent` / `setStateNode` in the mirror files.

/-- Mirror of the per-node update in `tree_model::touch`. -/
def touchNode (id now : Nat) (n : NodeInfo) : NodeInfo :=
  if n.id = id then { n with lastActive := now } else n

/-- Mirror of `tree_model::touch`. -/
def touch (t : TreeModel) (id now : Nat) : TreeModel :=
  { t with nodes := t.nodes.map (touchNode id now) }

/-- Mirror of the per-node update in `tree_model::set_protected`. -/
def setProtNode (id : Nat) (p : Bool) (n : NodeInfo) : NodeInfo :=
  if n.id = id then { n with prot := p } else n

/-- Mirror of `tree_model::set_protected`. -/
def setProtected (t : TreeModel) (id : Nat) (p : Bool) : TreeModel :=
  { t with nodes := t.nodes.map (setProtNode id p) }

end Verif.Tree

namespace Verif.Equiv

open Aeneas Aeneas.Std Result
open Aeneas.Std.WP
open k7d

-- ## touch ≡ Tree.touch

theorem touch_loop_equiv (t : tree_model.TreeModel) (id now : Std.U64)
    (nodes : alloc.vec.Vec tree_model.NodeInfo) (i : Std.Usize)
    (hcap : nodes.val.length + (t.nodes.val.length - i.val) ≤ Usize.max) :
    tree_model.touch_loop t id now nodes i
      ⦃ tb out => tb = t.budget ∧
          out.val.map absNode = nodes.val.map absNode
            ++ ((t.nodes.val.drop i.val).map absNode).map
                (Tree.touchNode id.val now.val) ⦄ := by
  unfold tree_model.touch_loop
  simp only
  split
  · rename_i hlt
    have hilen : i.val < t.nodes.val.length := by scalar_tac
    have hdrop : t.nodes.val.drop i.val
        = (t.nodes.val[i.val]'hilen) :: t.nodes.val.drop (i.val + 1) :=
      List.drop_eq_getElem_cons hilen
    step as ⟨ni, hni⟩
    simp only [nodeInfo_clone_eq, bind_tc_ok]
    split
    · rename_i heq
      subst hni
      simp only [bind_tc_ok]
      step as ⟨nodes1, hnodes1⟩
      step as ⟨i2, hi2⟩
      obtain ⟨⟨tb, out⟩, hp, hpost⟩ :=
        spec_imp_exists (touch_loop_equiv t id now nodes1 i2 (by scalar_tac))
      simp only [WP.uncurry'_pair] at hpost
      rw [hp]
      simp only [spec_ok, WP.uncurry'_pair]
      refine ⟨hpost.1, ?_⟩
      rw [hpost.2, hnodes1, hi2, hdrop]
      simp only [List.map_append, List.map_cons, List.append_assoc,
        List.cons_append, List.nil_append, List.map_nil]
      congr 2
      unfold Tree.touchNode
      rw [if_pos (by simp [heq])]
      rfl
    · rename_i hne
      subst hni
      simp only [bind_tc_ok]
      step as ⟨nodes1, hnodes1⟩
      step as ⟨i2, hi2⟩
      obtain ⟨⟨tb, out⟩, hp, hpost⟩ :=
        spec_imp_exists (touch_loop_equiv t id now nodes1 i2 (by scalar_tac))
      simp only [WP.uncurry'_pair] at hpost
      rw [hp]
      simp only [spec_ok, WP.uncurry'_pair]
      refine ⟨hpost.1, ?_⟩
      rw [hpost.2, hnodes1, hi2, hdrop]
      simp only [List.map_append, List.map_cons, List.append_assoc,
        List.cons_append, List.nil_append, List.map_nil]
      congr 2
      unfold Tree.touchNode
      rw [if_neg (by simp; intro hv; exact hne (by scalar_tac))]
  · rename_i hge
    have hlen : t.nodes.val.length ≤ i.val := by scalar_tac
    simp only [spec_ok, WP.uncurry'_pair]
    rw [List.drop_eq_nil_of_le hlen]
    simp
termination_by t.nodes.val.length - i.val
decreasing_by all_goals scalar_decr_tac

/-- Equivalence: `tree_model::touch` computes the mirror `Tree.touch`
(and never panics). -/
theorem touch_equiv (t : tree_model.TreeModel) (id now : Std.U64) :
    tree_model.touch t id now
      ⦃ t' => absTree t' = Tree.touch (absTree t) id.val now.val ⦄ := by
  unfold tree_model.touch
  obtain ⟨⟨tb, out⟩, hp, hpost⟩ := spec_imp_exists
    (touch_loop_equiv t id now (alloc.vec.Vec.new tree_model.NodeInfo)
      0#usize (by have := t.nodes.property; simp; scalar_tac))
  simp only [WP.uncurry'_pair] at hpost
  obtain ⟨htb, hout⟩ := hpost
  subst htb
  rw [hp]
  show WP.spec (ok ({ nodes := out, budget := t.budget }
    : tree_model.TreeModel)) _
  simp only [spec_ok]
  unfold Tree.touch
  simp only [absTree, Tree.TreeModel.mk.injEq, and_true]
  rw [hout]
  simp

-- ## set_state ≡ Tree.setState

theorem set_state_loop_equiv (t : tree_model.TreeModel) (id : Std.U64)
    (s : tree_model.NodeState)
    (nodes : alloc.vec.Vec tree_model.NodeInfo) (i : Std.Usize)
    (hcap : nodes.val.length + (t.nodes.val.length - i.val) ≤ Usize.max) :
    tree_model.set_state_loop t id s nodes i
      ⦃ tb out => tb = t.budget ∧
          out.val.map absNode = nodes.val.map absNode
            ++ ((t.nodes.val.drop i.val).map absNode).map
                (Tree.setStateNode id.val (absState s)) ⦄ := by
  unfold tree_model.set_state_loop
  simp only
  split
  · rename_i hlt
    have hilen : i.val < t.nodes.val.length := by scalar_tac
    have hdrop : t.nodes.val.drop i.val
        = (t.nodes.val[i.val]'hilen) :: t.nodes.val.drop (i.val + 1) :=
      List.drop_eq_getElem_cons hilen
    step as ⟨ni, hni⟩
    simp only [nodeInfo_clone_eq, bind_tc_ok]
    split
    · rename_i heq
      subst hni
      simp only [bind_tc_ok]
      step as ⟨nodes1, hnodes1⟩
      step as ⟨i2, hi2⟩
      obtain ⟨⟨tb, out⟩, hp, hpost⟩ :=
        spec_imp_exists (set_state_loop_equiv t id s nodes1 i2 (by scalar_tac))
      simp only [WP.uncurry'_pair] at hpost
      rw [hp]
      simp only [spec_ok, WP.uncurry'_pair]
      refine ⟨hpost.1, ?_⟩
      rw [hpost.2, hnodes1, hi2, hdrop]
      simp only [List.map_append, List.map_cons, List.append_assoc,
        List.cons_append, List.nil_append, List.map_nil]
      congr 2
      unfold Tree.setStateNode
      rw [if_pos (by simp [heq])]
      rfl
    · rename_i hne
      subst hni
      simp only [bind_tc_ok]
      step as ⟨nodes1, hnodes1⟩
      step as ⟨i2, hi2⟩
      obtain ⟨⟨tb, out⟩, hp, hpost⟩ :=
        spec_imp_exists (set_state_loop_equiv t id s nodes1 i2 (by scalar_tac))
      simp only [WP.uncurry'_pair] at hpost
      rw [hp]
      simp only [spec_ok, WP.uncurry'_pair]
      refine ⟨hpost.1, ?_⟩
      rw [hpost.2, hnodes1, hi2, hdrop]
      simp only [List.map_append, List.map_cons, List.append_assoc,
        List.cons_append, List.nil_append, List.map_nil]
      congr 2
      unfold Tree.setStateNode
      rw [if_neg (by simp; intro hv; exact hne (by scalar_tac))]
  · rename_i hge
    have hlen : t.nodes.val.length ≤ i.val := by scalar_tac
    simp only [spec_ok, WP.uncurry'_pair]
    rw [List.drop_eq_nil_of_le hlen]
    simp
termination_by t.nodes.val.length - i.val
decreasing_by all_goals scalar_decr_tac

/-- Equivalence: `tree_model::set_state` computes the mirror
`Tree.setState` (and never panics). -/
theorem set_state_equiv (t : tree_model.TreeModel) (id : Std.U64)
    (s : tree_model.NodeState) :
    tree_model.set_state t id s
      ⦃ t' => absTree t' = Tree.setState (absTree t) id.val (absState s) ⦄ := by
  unfold tree_model.set_state
  obtain ⟨⟨tb, out⟩, hp, hpost⟩ := spec_imp_exists
    (set_state_loop_equiv t id s (alloc.vec.Vec.new tree_model.NodeInfo)
      0#usize (by have := t.nodes.property; simp; scalar_tac))
  simp only [WP.uncurry'_pair] at hpost
  obtain ⟨htb, hout⟩ := hpost
  subst htb
  rw [hp]
  show WP.spec (ok ({ nodes := out, budget := t.budget }
    : tree_model.TreeModel)) _
  simp only [spec_ok]
  unfold Tree.setState
  simp only [absTree, Tree.TreeModel.mk.injEq, and_true]
  rw [hout]
  simp

-- ## set_protected ≡ Tree.setProtected

theorem set_protected_loop_equiv (t : tree_model.TreeModel) (id : Std.U64)
    (p : Bool)
    (nodes : alloc.vec.Vec tree_model.NodeInfo) (i : Std.Usize)
    (hcap : nodes.val.length + (t.nodes.val.length - i.val) ≤ Usize.max) :
    tree_model.set_protected_loop t id p nodes i
      ⦃ tb out => tb = t.budget ∧
          out.val.map absNode = nodes.val.map absNode
            ++ ((t.nodes.val.drop i.val).map absNode).map
                (Tree.setProtNode id.val p) ⦄ := by
  unfold tree_model.set_protected_loop
  simp only
  split
  · rename_i hlt
    have hilen : i.val < t.nodes.val.length := by scalar_tac
    have hdrop : t.nodes.val.drop i.val
        = (t.nodes.val[i.val]'hilen) :: t.nodes.val.drop (i.val + 1) :=
      List.drop_eq_getElem_cons hilen
    step as ⟨ni, hni⟩
    simp only [nodeInfo_clone_eq, bind_tc_ok]
    split
    · rename_i heq
      subst hni
      simp only [bind_tc_ok]
      step as ⟨nodes1, hnodes1⟩
      step as ⟨i2, hi2⟩
      obtain ⟨⟨tb, out⟩, hp, hpost⟩ := spec_imp_exists
        (set_protected_loop_equiv t id p nodes1 i2 (by scalar_tac))
      simp only [WP.uncurry'_pair] at hpost
      rw [hp]
      simp only [spec_ok, WP.uncurry'_pair]
      refine ⟨hpost.1, ?_⟩
      rw [hpost.2, hnodes1, hi2, hdrop]
      simp only [List.map_append, List.map_cons, List.append_assoc,
        List.cons_append, List.nil_append, List.map_nil]
      congr 2
      unfold Tree.setProtNode
      rw [if_pos (by simp [heq])]
      rfl
    · rename_i hne
      subst hni
      simp only [bind_tc_ok]
      step as ⟨nodes1, hnodes1⟩
      step as ⟨i2, hi2⟩
      obtain ⟨⟨tb, out⟩, hp, hpost⟩ := spec_imp_exists
        (set_protected_loop_equiv t id p nodes1 i2 (by scalar_tac))
      simp only [WP.uncurry'_pair] at hpost
      rw [hp]
      simp only [spec_ok, WP.uncurry'_pair]
      refine ⟨hpost.1, ?_⟩
      rw [hpost.2, hnodes1, hi2, hdrop]
      simp only [List.map_append, List.map_cons, List.append_assoc,
        List.cons_append, List.nil_append, List.map_nil]
      congr 2
      unfold Tree.setProtNode
      rw [if_neg (by simp; intro hv; exact hne (by scalar_tac))]
  · rename_i hge
    have hlen : t.nodes.val.length ≤ i.val := by scalar_tac
    simp only [spec_ok, WP.uncurry'_pair]
    rw [List.drop_eq_nil_of_le hlen]
    simp
termination_by t.nodes.val.length - i.val
decreasing_by all_goals scalar_decr_tac

/-- Equivalence: `tree_model::set_protected` computes the mirror
`Tree.setProtected` (and never panics). -/
theorem set_protected_equiv (t : tree_model.TreeModel) (id : Std.U64)
    (p : Bool) :
    tree_model.set_protected t id p
      ⦃ t' => absTree t' = Tree.setProtected (absTree t) id.val p ⦄ := by
  unfold tree_model.set_protected
  obtain ⟨⟨tb, out⟩, hp, hpost⟩ := spec_imp_exists
    (set_protected_loop_equiv t id p (alloc.vec.Vec.new tree_model.NodeInfo)
      0#usize (by have := t.nodes.property; simp; scalar_tac))
  simp only [WP.uncurry'_pair] at hpost
  obtain ⟨htb, hout⟩ := hpost
  subst htb
  rw [hp]
  show WP.spec (ok ({ nodes := out, budget := t.budget }
    : tree_model.TreeModel)) _
  simp only [spec_ok]
  unfold Tree.setProtected
  simp only [absTree, Tree.TreeModel.mk.injEq, and_true]
  rw [hout]
  simp

-- ## add_child ≡ Tree.addChild

theorem add_child_loop_equiv (t : tree_model.TreeModel)
    (parent new_id now : Std.U64)
    (nodes : alloc.vec.Vec tree_model.NodeInfo) (i : Std.Usize)
    (hcap : nodes.val.length + (t.nodes.val.length - i.val) ≤ Usize.max)
    (hchild : ∀ n ∈ t.nodes.val, n.children.val.length < Usize.max) :
    tree_model.add_child_loop t parent new_id now nodes i
      ⦃ tb out => tb = t.budget ∧
          out.val.map absNode = nodes.val.map absNode
            ++ ((t.nodes.val.drop i.val).map absNode).map
                (Tree.bumpParent parent.val new_id.val now.val) ⦄ := by
  unfold tree_model.add_child_loop
  simp only
  split
  · rename_i hlt
    have hilen : i.val < t.nodes.val.length := by scalar_tac
    have hdrop : t.nodes.val.drop i.val
        = (t.nodes.val[i.val]'hilen) :: t.nodes.val.drop (i.val + 1) :=
      List.drop_eq_getElem_cons hilen
    step as ⟨ni, hni⟩
    simp only [nodeInfo_clone_eq, bind_tc_ok]
    split
    · rename_i heq
      subst hni
      have hclen : (t.nodes.val[i.val]'hilen).children.val.length < Usize.max :=
        hchild _ (List.getElem_mem hilen)
      step as ⟨v1, hv1⟩
      step as ⟨nodes1, hnodes1⟩
      step as ⟨i3, hi3⟩
      obtain ⟨⟨tb, out⟩, hp, hpost⟩ := spec_imp_exists
        (add_child_loop_equiv t parent new_id now nodes1 i3
          (by scalar_tac) hchild)
      simp only [WP.uncurry'_pair] at hpost
      rw [hp]
      simp only [spec_ok, WP.uncurry'_pair]
      refine ⟨hpost.1, ?_⟩
      rw [hpost.2, hnodes1, hi3, hdrop]
      simp only [List.map_append, List.map_cons, List.append_assoc,
        List.cons_append, List.nil_append, List.map_nil]
      congr 2
      unfold Tree.bumpParent
      rw [if_pos (by simp [heq])]
      simp only [absNode, hv1]
      simp [List.map_append]
    · rename_i hne
      subst hni
      simp only [bind_tc_ok]
      step as ⟨nodes1, hnodes1⟩
      step as ⟨i3, hi3⟩
      obtain ⟨⟨tb, out⟩, hp, hpost⟩ := spec_imp_exists
        (add_child_loop_equiv t parent new_id now nodes1 i3
          (by scalar_tac) hchild)
      simp only [WP.uncurry'_pair] at hpost
      rw [hp]
      simp only [spec_ok, WP.uncurry'_pair]
      refine ⟨hpost.1, ?_⟩
      rw [hpost.2, hnodes1, hi3, hdrop]
      simp only [List.map_append, List.map_cons, List.append_assoc,
        List.cons_append, List.nil_append, List.map_nil]
      congr 2
      unfold Tree.bumpParent
      rw [if_neg (by simp; intro hv; exact hne (by scalar_tac))]
  · rename_i hge
    have hlen : t.nodes.val.length ≤ i.val := by scalar_tac
    simp only [spec_ok, WP.uncurry'_pair]
    rw [List.drop_eq_nil_of_le hlen]
    simp
termination_by t.nodes.val.length - i.val
decreasing_by all_goals scalar_decr_tac

/-- Equivalence: `tree_model::add_child` computes the mirror
`Tree.addChild` (and never panics). The two `usize::MAX` side conditions
mark the genuine Rust abort points — the `Vec::push` of the new child
node and of the parent's new child id. -/
theorem add_child_equiv (t : tree_model.TreeModel)
    (parent new_id now : Std.U64)
    (hlen : t.nodes.val.length < Usize.max)
    (hchild : ∀ n ∈ t.nodes.val, n.children.val.length < Usize.max) :
    tree_model.add_child t parent new_id now
      ⦃ t' => absTree t'
          = Tree.addChild (absTree t) parent.val new_id.val now.val ⦄ := by
  unfold tree_model.add_child
  obtain ⟨o, ho, hoPost⟩ := spec_imp_exists (find_index_equiv t parent)
  rw [ho]
  simp only [bind_tc_ok, core.option.Option.is_none]
  cases o with
  | none =>
    have hlook : Tree.lookup (absTree t) parent.val = none := hoPost
    simp only [Option.isNone_none, if_true, treeModel_clone_eq, spec_ok]
    unfold Tree.addChild
    rw [if_pos (Or.inl hlook)]
  | some k =>
    obtain ⟨hk, hlk⟩ := hoPost
    simp only [Option.isNone_some, Bool.false_eq_true, if_false]
    obtain ⟨o1, ho1, ho1Post⟩ := spec_imp_exists (find_index_equiv t new_id)
    rw [ho1]
    simp only [bind_tc_ok, core.option.Option.is_some]
    cases o1 with
    | some k1 =>
      obtain ⟨h1, hl1⟩ := ho1Post
      simp only [Option.isSome_some, if_true, treeModel_clone_eq, spec_ok]
      unfold Tree.addChild
      rw [if_pos (Or.inr (by rw [hl1]; rfl))]
    | none =>
      have hlook1 : Tree.lookup (absTree t) new_id.val = none := ho1Post
      simp only [Option.isSome_none, Bool.false_eq_true, if_false]
      obtain ⟨⟨tb, out⟩, hp, hpost⟩ := spec_imp_exists
        (add_child_loop_equiv t parent new_id now
          (alloc.vec.Vec.new tree_model.NodeInfo) 0#usize
          (by have := t.nodes.property; simp; scalar_tac) hchild)
      simp only [WP.uncurry'_pair] at hpost
      obtain ⟨htb, hout⟩ := hpost
      subst htb
      simp only [List.map_nil, List.nil_append] at hout
      rw [hp]
      simp only [bind_tc_ok]
      have houtlen : out.val.length = t.nodes.val.length := by
        have := congrArg List.length hout
        simpa using this
      step as ⟨nodes1, hnodes1⟩
      unfold Tree.addChild
      rw [if_neg (by
        push Not
        exact ⟨by rw [hlk]; simp, by rw [hlook1]; simp⟩)]
      simp only [absTree, Tree.TreeModel.mk.injEq, and_true]
      rw [hnodes1]
      simp only [List.map_append, List.map_cons, List.map_nil]
      rw [hout]
      simp only [List.map_map]
      congr 1

end Verif.Equiv
