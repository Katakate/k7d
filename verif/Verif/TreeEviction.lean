-- Groups C + D — Eviction policy correctness and
-- eviction-loop termination / post-condition.
--
-- Group C, for the pure eviction policy in `crate::tree_model`:
--   * `lru_victim_is_minimum` — `lru_live_victim` returns an eligible
--     (Live, non-exempt, non-protected) node whose `last_active` is
--     minimal among all eligible nodes; `None` only when no node is
--     eligible.
--   * `implicitly_protected_includes_ancestors` — every ancestor of a
--     protected node is in `implicitly_protected`.
--   * `leaf_subtree_has_no_live_descendants` —
--     `lru_evictable_leaf_subtree` never picks a node with a Live or
--     Suspended strict descendant.
--
-- Group D, for the Tier-1 RAM eviction loop `auto_evict_ram`:
--   * `auto_evict_ram_terminates` — the loop's fuel bound
--     (`t.nodes.len()` in the Rust source) never cuts it short: every
--     fuel at or above the live-node count computes the same (fixed
--     point) result. Each iteration suspends one Live node, so the
--     live-node count is the strictly decreasing measure.
--   * `auto_evict_ram_post` — on exit, either the tree is under both
--     the RAM and count budgets, or every remaining Live node is
--     exempt or (implicitly) protected.
--   * `auto_evict_ram_preserves_well_formed` — the loop only flips
--     `state` fields, so the Group A shape invariants survive.
--
-- Bonus (referenced from the `ancestor_ids` doc comment in
-- `tree_model.rs`):
--   * `ancestor_ids_fuel_never_truncates` — on a well-formed tree the
--     `max_id + 2` fuel of the ancestor walk never truncates a real
--     chain (parent ids strictly decrease, so a chain from `id` has at
--     most `id + 1` elements).
--
-- Mirror rationale: see the file-level notes in `Verif/TreeShape.lean`
-- and `Verif/K7dlCodec.lean`. Every definition below mirrors its
-- `tree_model.rs` namesake branch-for-branch; change one, update the
-- other. Equivalence with the Rust source is machine-checked in
-- `Verif/Equiv/`; the `…_rust` corollaries live in
-- `Verif/Equiv/Transfer.lean`.

import Verif.TreeBudget

namespace Verif.Tree

-- ## Ancestor walk (mirrors `max_id` / `ancestor_ids`)

/-- Mirror of `tree_model::max_id`. -/
def maxId (t : TreeModel) : Nat :=
  t.nodes.foldl (fun m n => max m n.id) 0

/-- The fuel-bounded parent walk inside `tree_model::ancestor_ids`. -/
def ancestorWalk (t : TreeModel) : Nat → Option Nat → List Nat
  | 0, _ => []
  | _ + 1, none => []
  | fuel + 1, some c => c :: ancestorWalk t fuel (parentOf t c)

/-- Mirror of `tree_model::ancestor_ids`: the inclusive ancestor chain
`[id, parent, …, root]`, fuel-bounded by `max_id().saturating_add(2)` —
saturation-exact, like every mirror. -/
def ancestorIds (t : TreeModel) (id : Nat) : List Nat :=
  ancestorWalk t (satAdd U64_MAX (maxId t) 2) (some id)

/-- The walk always starts with the queried id. -/
theorem ancestor_mem_self (t : TreeModel) (id : Nat) :
    id ∈ ancestorIds t id := by
  unfold ancestorIds
  obtain ⟨k, hk⟩ : ∃ k, satAdd U64_MAX (maxId t) 2 = k + 1 :=
    ⟨satAdd U64_MAX (maxId t) 2 - 1, by unfold satAdd U64_MAX; omega⟩
  rw [hk]
  simp [ancestorWalk]

/-- `parentOf` follows `parentLt`: parents have strictly smaller ids. -/
theorem parentOf_lt (t : TreeModel) (hwf : WellFormed t) (id p : Nat)
    (h : parentOf t id = some p) : p < id := by
  unfold parentOf at h
  cases hl : lookup t id with
  | none => rw [hl] at h; exact absurd h (by simp)
  | some n =>
    rw [hl] at h
    obtain ⟨hmem, hid⟩ := lookup_some t id n hl
    exact hid ▸ hwf.parentLt n hmem p h

/-- The accumulator only grows under `foldl max`. -/
theorem foldl_max_le_acc (l : List NodeInfo) (acc : Nat) :
    acc ≤ l.foldl (fun m n => max m n.id) acc := by
  induction l generalizing acc with
  | nil => exact Nat.le_refl acc
  | cons x xs ih => exact Nat.le_trans (Nat.le_max_left acc x.id) (ih (max acc x.id))

/-- Every member's id is bounded by the running `foldl max`. -/
theorem mem_le_foldl_max {l : List NodeInfo} {n : NodeInfo} (hn : n ∈ l) :
    ∀ acc, n.id ≤ l.foldl (fun m x => max m x.id) acc := by
  induction hn with
  | head rest =>
    intro acc
    exact Nat.le_trans (Nat.le_max_right acc n.id) (foldl_max_le_acc rest _)
  | tail x _ ih =>
    intro acc
    exact ih _

/-- Every member's id is bounded by `maxId`. -/
theorem mem_le_maxId (t : TreeModel) (n : NodeInfo) (hn : n ∈ t.nodes) :
    n.id ≤ maxId t :=
  mem_le_foldl_max hn 0

/-- On a well-formed tree the walk's result is fuel-independent above
`c`: parent ids strictly decrease, so the chain from `c` has at most
`c + 1` elements. -/
theorem ancestor_walk_fuel_irrelevant (t : TreeModel) (hwf : WellFormed t)
    (c : Nat) :
    ∀ f1 f2, c < f1 → c < f2 →
      ancestorWalk t f1 (some c) = ancestorWalk t f2 (some c) := by
  induction c using Nat.strong_induction_on with
  | _ c ih =>
    intro f1 f2 h1 h2
    obtain ⟨k1, rfl⟩ : ∃ k, f1 = k + 1 := ⟨f1 - 1, by omega⟩
    obtain ⟨k2, rfl⟩ : ∃ k, f2 = k + 1 := ⟨f2 - 1, by omega⟩
    simp only [ancestorWalk, List.cons.injEq, true_and]
    cases hpo : parentOf t c with
    | none => cases k1 <;> cases k2 <;> simp [ancestorWalk]
    | some p =>
      have hplt : p < c := parentOf_lt t hwf c p hpo
      exact ih p hplt k1 k2 (by omega) (by omega)

/-- Group A/C bridge, referenced from the `ancestor_ids` doc comment in
`tree_model.rs`: the `max_id().saturating_add(2)` fuel never truncates a
real chain — any fuel above the node's own id walks the identical chain.
The `n.id + 2 ≤ u64::MAX` side condition is where the Rust fuel
saturates: a node with id `u64::MAX - 1` or above caps the fuel at
`u64::MAX`, which a (2^64-element) maximal chain could in principle
exceed. -/
theorem ancestor_ids_fuel_never_truncates (t : TreeModel) (hwf : WellFormed t)
    (n : NodeInfo) (hn : n ∈ t.nodes) (f : Nat) (hf : n.id < f)
    (hid : n.id + 2 ≤ U64_MAX) :
    ancestorWalk t f (some n.id) = ancestorIds t n.id := by
  unfold ancestorIds
  refine ancestor_walk_fuel_irrelevant t hwf n.id f _ hf ?_
  have := mem_le_maxId t n hn
  unfold satAdd U64_MAX at *
  omega

-- ## Restore-chain depth (mirrors `restore_chain_depth`)

/-- The fuel-bounded walk inside `tree_model::restore_chain_depth`: one
parent hop per fuel unit, counting non-checkpoint nodes until the first
`hasBase` ancestor (`satAdd USIZE_MAX` mirrors the Rust
`usize::saturating_add` on the depth counter). `none` for a missing
node, a root path with no checkpoint, or fuel exhaustion. -/
def restoreChainWalk (t : TreeModel) : Nat → Nat → Option Nat → Option Nat
  | 0, _, _ => none
  | _ + 1, _, none => none
  | fuel + 1, depth, some c =>
    match lookup t c with
    | none => none
    | some n =>
      if n.hasBase then some depth
      else restoreChainWalk t fuel (satAdd USIZE_MAX depth 1) n.parent

/-- Mirror of `tree_model::restore_chain_depth`: how many `delta.pack`s
a resume must apply — non-checkpoint hops from `id` (inclusive) to the
nearest `hasBase` ancestor. Fuel-bounded by `max_id().saturating_add(2)`
like `ancestorIds`; saturation-exact, like every mirror. -/
def restoreChainDepth (t : TreeModel) (id : Nat) : Option Nat :=
  restoreChainWalk t (satAdd U64_MAX (maxId t) 2) 0 (some id)

/-- The Rust fuel `max_id().saturating_add(2)` is at least 2 — enough
for the two theorems below to unfold the walk without side conditions. -/
theorem restore_fuel_ge_two (t : TreeModel) :
    2 ≤ satAdd U64_MAX (maxId t) 2 := by
  unfold satAdd U64_MAX; omega

/-- `usize::MAX` is positive (needed to evaluate the first saturating
depth increment exactly). -/
theorem one_le_usize_max : 1 ≤ USIZE_MAX := by
  unfold USIZE_MAX
  rcases System.Platform.numBits_eq with h | h <;> rw [h] <;> norm_num

/-- A checkpoint node's restore chain is 0 — resume reads
its own `memory.bin` and applies no deltas. -/
theorem restore_chain_depth_checkpoint (t : TreeModel) (id : Nat)
    (n : NodeInfo) (hl : lookup t id = some n) (hb : n.hasBase = true) :
    restoreChainDepth t id = some 0 := by
  unfold restoreChainDepth
  obtain ⟨k, hk⟩ : ∃ k, satAdd U64_MAX (maxId t) 2 = k + 1 :=
    ⟨satAdd U64_MAX (maxId t) 2 - 1, by have := restore_fuel_ge_two t; omega⟩
  rw [hk]
  simp [restoreChainWalk, hl, hb]

/-- The load-bearing distinction: a non-checkpoint node
whose *parent* is a checkpoint has restore chain exactly 1 — however
deep it sits in the tree graph. `root → child → grandchild` is graph
depth 2, yet the grandchild's restore chain is 1 once the child was
prepared (`fork_batch` always prepares its source). -/
theorem restore_chain_depth_hop (t : TreeModel) (id p : Nat)
    (n m : NodeInfo) (hl : lookup t id = some n) (hb : n.hasBase = false)
    (hp : n.parent = some p) (hlp : lookup t p = some m)
    (hbp : m.hasBase = true) :
    restoreChainDepth t id = some 1 := by
  unfold restoreChainDepth
  obtain ⟨k, hk⟩ : ∃ k, satAdd U64_MAX (maxId t) 2 = k + 2 :=
    ⟨satAdd U64_MAX (maxId t) 2 - 2, by have := restore_fuel_ge_two t; omega⟩
  have hs : satAdd USIZE_MAX 0 1 = 1 := by
    unfold satAdd; have := one_le_usize_max; omega
  rw [hk]
  simp [restoreChainWalk, hl, hb, hp, hs, hlp, hbp]

-- ## Implicit protection (mirrors `implicitly_protected`)

/-- The dedup-append inner loop of `tree_model::implicitly_protected`. -/
def insertNew : List Nat → List Nat → List Nat
  | out, [] => out
  | out, c :: rest => insertNew (if c ∈ out then out else out ++ [c]) rest

/-- The outer loop of `tree_model::implicitly_protected`. -/
def implicitlyProtectedAux (t : TreeModel) : List NodeInfo → List Nat → List Nat
  | [], out => out
  | n :: ns, out =>
    implicitlyProtectedAux t ns
      (if n.prot then insertNew out (ancestorIds t n.id) else out)

/-- Mirror of `tree_model::implicitly_protected`: every explicitly
protected node and all of its ancestors. -/
def implicitlyProtected (t : TreeModel) : List Nat :=
  implicitlyProtectedAux t t.nodes []

theorem mem_insertNew_left {a : Nat} {out : List Nat} (chain : List Nat)
    (h : a ∈ out) : a ∈ insertNew out chain := by
  induction chain generalizing out with
  | nil => exact h
  | cons c rest ih =>
    apply ih
    split
    · exact h
    · exact List.mem_append_left _ h

theorem mem_insertNew_right {a : Nat} (out : List Nat) {chain : List Nat}
    (h : a ∈ chain) : a ∈ insertNew out chain := by
  induction chain generalizing out with
  | nil => cases h
  | cons c rest ih =>
    rcases List.mem_cons.mp h with rfl | hrest
    · show a ∈ insertNew (if a ∈ out then out else out ++ [a]) rest
      refine mem_insertNew_left rest ?_
      by_cases hc : a ∈ out
      · rw [if_pos hc]; exact hc
      · rw [if_neg hc]
        exact List.mem_append_right _ (List.mem_singleton.mpr rfl)
    · exact ih _ hrest

theorem mem_ipAux_left (t : TreeModel) {a : Nat} (l : List NodeInfo)
    {out : List Nat} (h : a ∈ out) : a ∈ implicitlyProtectedAux t l out := by
  induction l generalizing out with
  | nil => exact h
  | cons n ns ih =>
    apply ih
    split
    · exact mem_insertNew_left _ h
    · exact h

theorem mem_ipAux_of_chain (t : TreeModel) {n : NodeInfo} {a : Nat}
    {l : List NodeInfo} (hn : n ∈ l) (hp : n.prot = true)
    (ha : a ∈ ancestorIds t n.id) (out : List Nat) :
    a ∈ implicitlyProtectedAux t l out := by
  induction l generalizing out with
  | nil => cases hn
  | cons m ms ih =>
    rcases List.mem_cons.mp hn with rfl | hmem
    · exact mem_ipAux_left t ms (by rw [if_pos hp]; exact mem_insertNew_right _ ha)
    · exact ih hmem _

/-- Group C: protection is ancestor-closed — every entry of a protected
node's ancestor chain is implicitly protected. -/
theorem implicitly_protected_includes_ancestors
    (t : TreeModel) (n : NodeInfo) (hn : n ∈ t.nodes) (hp : n.prot = true) :
    ∀ a ∈ ancestorIds t n.id, a ∈ implicitlyProtected t :=
  fun _ ha => mem_ipAux_of_chain t hn hp ha []

-- ## LRU selection (mirrors the `best: Option<(last_active, id)>` loops)

/-- The "replace `best`?" step of the Rust loops: keep the accumulator
unless it is unset or the candidate is strictly more stale. -/
def betterOf (best : Option (Nat × Nat)) (n : NodeInfo) : Option (Nat × Nat) :=
  match best with
  | none => some (n.lastActive, n.id)
  | some (bla, bid) =>
    if n.lastActive < bla then some (n.lastActive, n.id) else some (bla, bid)

/-- The accumulator loop shared by `lru_live_victim` and
`lru_evictable_leaf_subtree`: scan `nodes` in order, keep the
`(last_active, id)` of the `P`-eligible node with the strictly smallest
`last_active` (first wins ties). -/
def selectLruAux (P : NodeInfo → Prop) [DecidablePred P] :
    List NodeInfo → Option (Nat × Nat) → Option (Nat × Nat)
  | [], best => best
  | n :: ns, best => selectLruAux P ns (if P n then betterOf best n else best)

/-- The final `match best { … }` of both Rust functions. -/
def selectLru (P : NodeInfo → Prop) [DecidablePred P]
    (nodes : List NodeInfo) : Option Nat :=
  match selectLruAux P nodes none with
  | none => none
  | some (_, id) => some id

/-- `betterOf` always yields an accumulator. -/
theorem betterOf_eq_some (b : Option (Nat × Nat)) (n : NodeInfo) :
    ∃ p, betterOf b n = some p := by
  unfold betterOf
  rcases b with _ | ⟨bla, bid⟩
  · exact ⟨_, rfl⟩
  · dsimp only
    split <;> exact ⟨_, rfl⟩

/-- The accumulator's `last_active` never exceeds the candidate's. -/
theorem betterOf_le_new (b : Option (Nat × Nat)) (n : NodeInfo) (la id : Nat)
    (h : betterOf b n = some (la, id)) : la ≤ n.lastActive := by
  unfold betterOf at h
  rcases b with _ | ⟨bla, bid⟩
  · simp only [Option.some.injEq, Prod.mk.injEq] at h
    omega
  · dsimp only at h
    split at h <;> rename_i hlt <;>
      simp only [Option.some.injEq, Prod.mk.injEq] at h <;> omega

/-- The accumulator's `last_active` never grows. -/
theorem betterOf_le_old (bla bid : Nat) (n : NodeInfo) (la id : Nat)
    (h : betterOf (some (bla, bid)) n = some (la, id)) : la ≤ bla := by
  unfold betterOf at h
  dsimp only at h
  split at h <;> rename_i hlt <;>
    simp only [Option.some.injEq, Prod.mk.injEq] at h <;> omega

/-- The accumulator is the old one or the candidate. -/
theorem betterOf_sound (b : Option (Nat × Nat)) (n : NodeInfo) (la id : Nat)
    (h : betterOf b n = some (la, id)) :
    b = some (la, id) ∨ (n.lastActive = la ∧ n.id = id) := by
  unfold betterOf at h
  rcases b with _ | ⟨bla, bid⟩
  · simp only [Option.some.injEq, Prod.mk.injEq] at h
    exact Or.inr h
  · dsimp only at h
    split at h <;> simp only [Option.some.injEq, Prod.mk.injEq] at h
    · exact Or.inr h
    · exact Or.inl (by rw [h.1, h.2])

variable {P : NodeInfo → Prop} [DecidablePred P]

/-- Once the accumulator is set it never resets. -/
theorem selectLruAux_isSome (l : List NodeInfo) (b : Nat × Nat) :
    (selectLruAux P l (some b)).isSome := by
  induction l generalizing b with
  | nil => rfl
  | cons n ns ih =>
    show (selectLruAux P ns (if P n then betterOf (some b) n else some b)).isSome
    by_cases hP : P n
    · rw [if_pos hP]
      obtain ⟨p, hp⟩ := betterOf_eq_some (some b) n
      rw [hp]
      exact ih p
    · rw [if_neg hP]
      exact ih b

theorem selectLruAux_ne_none (l : List NodeInfo) (b : Nat × Nat) :
    selectLruAux P l (some b) ≠ none := by
  intro h
  have hs := selectLruAux_isSome (P := P) l b
  rw [h] at hs
  exact absurd hs (by simp)

/-- Completeness: a `none` result means no node was eligible. -/
theorem selectLruAux_none (l : List NodeInfo) (b : Option (Nat × Nat))
    (h : selectLruAux P l b = none) : ∀ n ∈ l, ¬ P n := by
  induction l generalizing b with
  | nil => intro n hn; cases hn
  | cons m ms ih =>
    replace h : selectLruAux P ms (if P m then betterOf b m else b) = none := h
    intro n hn
    by_cases hP : P m
    · exfalso
      rw [if_pos hP] at h
      obtain ⟨p, hp⟩ := betterOf_eq_some b m
      rw [hp] at h
      exact selectLruAux_ne_none ms p h
    · rw [if_neg hP] at h
      rcases List.mem_cons.mp hn with rfl | hmem
      · exact hP
      · exact ih b h n hmem

/-- Soundness: a `some` result is the seed or an eligible list member. -/
theorem selectLruAux_sound (l : List NodeInfo) (b : Option (Nat × Nat))
    (la id : Nat) (h : selectLruAux P l b = some (la, id)) :
    b = some (la, id) ∨ ∃ n ∈ l, P n ∧ n.lastActive = la ∧ n.id = id := by
  induction l generalizing b with
  | nil => exact Or.inl h
  | cons m ms ih =>
    replace h :
        selectLruAux P ms (if P m then betterOf b m else b) = some (la, id) := h
    by_cases hP : P m
    · rw [if_pos hP] at h
      rcases ih _ h with heq | ⟨n, hn, hPn, hla, hid⟩
      · rcases betterOf_sound b m la id heq with hb | ⟨hla, hid⟩
        · exact Or.inl hb
        · exact Or.inr ⟨m, List.mem_cons_self .., hP, hla, hid⟩
      · exact Or.inr ⟨n, List.mem_cons_of_mem m hn, hPn, hla, hid⟩
    · rw [if_neg hP] at h
      rcases ih _ h with heq | ⟨n, hn, hPn, hla, hid⟩
      · exact Or.inl heq
      · exact Or.inr ⟨n, List.mem_cons_of_mem m hn, hPn, hla, hid⟩

/-- The result's `last_active` never exceeds the seed's. -/
theorem selectLruAux_le (l : List NodeInfo) (bla bid la id : Nat)
    (h : selectLruAux P l (some (bla, bid)) = some (la, id)) : la ≤ bla := by
  induction l generalizing bla bid with
  | nil =>
    replace h : (some (bla, bid) : Option (Nat × Nat)) = some (la, id) := h
    simp only [Option.some.injEq, Prod.mk.injEq] at h
    omega
  | cons m ms ih =>
    replace h :
        selectLruAux P ms
          (if P m then betterOf (some (bla, bid)) m else some (bla, bid))
          = some (la, id) := h
    by_cases hP : P m
    · rw [if_pos hP] at h
      obtain ⟨⟨la', id'⟩, hp⟩ := betterOf_eq_some (some (bla, bid)) m
      rw [hp] at h
      exact Nat.le_trans (ih la' id' h) (betterOf_le_old bla bid m la' id' hp)
    · rw [if_neg hP] at h
      exact ih bla bid h

/-- Minimality: the result's `last_active` is ≤ every eligible member's. -/
theorem selectLruAux_min (l : List NodeInfo) (b : Option (Nat × Nat))
    (la id : Nat) (h : selectLruAux P l b = some (la, id)) :
    ∀ m ∈ l, P m → la ≤ m.lastActive := by
  induction l generalizing b with
  | nil => intro m hm; cases hm
  | cons n ns ih =>
    replace h :
        selectLruAux P ns (if P n then betterOf b n else b) = some (la, id) := h
    intro m hm hPm
    by_cases hP : P n
    · rw [if_pos hP] at h
      rcases List.mem_cons.mp hm with rfl | hmem
      · obtain ⟨⟨la', id'⟩, hp⟩ := betterOf_eq_some b m
        rw [hp] at h
        exact Nat.le_trans (selectLruAux_le ns la' id' la id h)
          (betterOf_le_new b m la' id' hp)
      · exact ih _ h m hmem hPm
    · rw [if_neg hP] at h
      rcases List.mem_cons.mp hm with rfl | hmem
      · exact absurd hPm hP
      · exact ih _ h m hmem hPm

/-- `selectLru` returning `none` means no eligible node exists. -/
theorem selectLru_none (l : List NodeInfo) (h : selectLru P l = none) :
    ∀ n ∈ l, ¬ P n := by
  unfold selectLru at h
  cases haux : selectLruAux P l none with
  | none => exact selectLruAux_none l none haux
  | some p => rw [haux] at h; cases h

/-- `selectLru` returning `some v` names an eligible node with minimal
`last_active`. -/
theorem selectLru_sound (l : List NodeInfo) (v : Nat)
    (h : selectLru P l = some v) :
    ∃ n ∈ l, P n ∧ n.id = v ∧ ∀ m ∈ l, P m → n.lastActive ≤ m.lastActive := by
  unfold selectLru at h
  cases haux : selectLruAux P l none with
  | none => rw [haux] at h; cases h
  | some p =>
    obtain ⟨la, id⟩ := p
    rw [haux] at h
    replace h : some id = some v := h
    injection h with h
    rcases selectLruAux_sound l none la id haux with heq | ⟨n, hn, hPn, hla, hid⟩
    · cases heq
    · exact ⟨n, hn, hPn, by rw [hid, h],
        fun m hm hPm => hla ▸ selectLruAux_min l none la id haux m hm hPm⟩

-- ## LRU live victim (mirrors `lru_live_victim`)

/-- Eligibility filter of `tree_model::lru_live_victim`: Live, not
exempt, not implicitly protected. -/
def eligibleLive (t : TreeModel) (exempt : List Nat) (n : NodeInfo) : Prop :=
  n.state = .live ∧ n.id ∉ exempt ∧ n.id ∉ implicitlyProtected t

instance (t : TreeModel) (exempt : List Nat) :
    DecidablePred (eligibleLive t exempt) := fun n => by
  unfold eligibleLive; infer_instance

/-- Mirror of `tree_model::lru_live_victim`. -/
def lruLiveVictim (t : TreeModel) (exempt : List Nat) : Option Nat :=
  selectLru (eligibleLive t exempt) t.nodes

theorem lruLiveVictim_none (t : TreeModel) (exempt : List Nat)
    (h : lruLiveVictim t exempt = none) :
    ∀ n ∈ t.nodes, ¬ eligibleLive t exempt n :=
  selectLru_none t.nodes h

theorem lruLiveVictim_sound (t : TreeModel) (exempt : List Nat) (v : Nat)
    (h : lruLiveVictim t exempt = some v) :
    ∃ n ∈ t.nodes, eligibleLive t exempt n ∧ n.id = v ∧
      ∀ m ∈ t.nodes, eligibleLive t exempt m → n.lastActive ≤ m.lastActive :=
  selectLru_sound t.nodes v h

/-- Group C: LRU correctness — `lru_live_victim` returns the eligible
node with the smallest `last_active`, and `None` only when no node is
eligible. -/
theorem lru_victim_is_minimum (t : TreeModel) (exempt : List Nat) :
    match lruLiveVictim t exempt with
    | none => ∀ n ∈ t.nodes, ¬ eligibleLive t exempt n
    | some vid => ∃ n ∈ t.nodes, eligibleLive t exempt n ∧ n.id = vid ∧
        ∀ m ∈ t.nodes, eligibleLive t exempt m →
          n.lastActive ≤ m.lastActive := by
  cases h : lruLiveVictim t exempt with
  | none => exact lruLiveVictim_none t exempt h
  | some vid => exact lruLiveVictim_sound t exempt vid h

-- ## Evictable leaf subtrees (mirrors `subtree_isolated` /
-- `lru_evictable_leaf_subtree`)

/-- Mirror of `tree_model::subtree_isolated`: every strict descendant of
`root` is Evicted (a node `d` is a strict descendant iff `d ≠ root` and
`root` is on `d`'s ancestor chain). -/
def subtreeIsolated (t : TreeModel) (root : Nat) : Prop :=
  ∀ d ∈ t.nodes, d.id ≠ root → root ∈ ancestorIds t d.id →
    d.state = .evicted

instance (t : TreeModel) (root : Nat) : Decidable (subtreeIsolated t root) := by
  unfold subtreeIsolated; infer_instance

/-- Eligibility filter of `tree_model::lru_evictable_leaf_subtree`:
Suspended, not implicitly protected, subtree fully Evicted. -/
def eligibleLeaf (t : TreeModel) (n : NodeInfo) : Prop :=
  n.state = .suspended ∧ n.id ∉ implicitlyProtected t ∧
    subtreeIsolated t n.id

instance (t : TreeModel) : DecidablePred (eligibleLeaf t) := fun n => by
  unfold eligibleLeaf; infer_instance

/-- Mirror of `tree_model::lru_evictable_leaf_subtree`. -/
def lruEvictableLeafSubtree (t : TreeModel) : Option Nat :=
  selectLru (eligibleLeaf t) t.nodes

/-- Group C: the disk-tier evictor never picks a subtree root with a
Live or Suspended strict descendant. -/
theorem leaf_subtree_has_no_live_descendants (t : TreeModel) :
    match lruEvictableLeafSubtree t with
    | none => True
    | some root => ∀ d ∈ t.nodes, root ∈ ancestorIds t d.id → d.id ≠ root →
        d.state ≠ .live ∧ d.state ≠ .suspended := by
  cases h : lruEvictableLeafSubtree t with
  | none => trivial
  | some root =>
    obtain ⟨n, _, ⟨_, _, hiso⟩, hid, _⟩ := selectLru_sound t.nodes root h
    intro d hd hanc hne
    rw [← hid] at hanc hne
    have hev : d.state = .evicted := hiso d hd hne hanc
    rw [hev]
    exact ⟨by simp, by simp⟩

-- ## The Tier-1 RAM eviction loop (mirrors `set_state` / `auto_evict_ram`)

/-- The per-node update of `tree_model::set_state`. -/
def setStateNode (id : Nat) (s : NodeState) (n : NodeInfo) : NodeInfo :=
  if n.id = id then { n with state := s } else n

/-- Mirror of `tree_model::set_state`. -/
def setState (t : TreeModel) (id : Nat) (s : NodeState) : TreeModel :=
  { t with nodes := t.nodes.map (setStateNode id s) }

@[simp] theorem setStateNode_id (id : Nat) (s : NodeState) (n : NodeInfo) :
    (setStateNode id s n).id = n.id := by
  unfold setStateNode; split <;> rfl

@[simp] theorem setStateNode_parent (id : Nat) (s : NodeState) (n : NodeInfo) :
    (setStateNode id s n).parent = n.parent := by
  unfold setStateNode; split <;> rfl

@[simp] theorem setStateNode_children (id : Nat) (s : NodeState) (n : NodeInfo) :
    (setStateNode id s n).children = n.children := by
  unfold setStateNode; split <;> rfl

/-- `set_state` only touches `state`, so the Group A shape invariants
survive it. -/
theorem setState_preserves_well_formed (t : TreeModel) (id : Nat)
    (s : NodeState) (hwf : WellFormed t) : WellFormed (setState t id s) := by
  set f := setStateNode id s with hf
  constructor
  · have hmap : (t.nodes.map f).map NodeInfo.id = t.nodes.map NodeInfo.id := by
      rw [List.map_map]
      exact List.map_congr_left (fun n _ => setStateNode_id id s n)
    rw [setState, hmap]
    exact hwf.idsNodup
  · intro n' hn' p hp
    obtain ⟨n, hn, rfl⟩ := List.mem_map.mp hn'
    rw [setStateNode_parent] at hp
    rw [setStateNode_id]
    exact hwf.parentLt n hn p hp
  · intro n' hn' p hp
    obtain ⟨n, hn, rfl⟩ := List.mem_map.mp hn'
    rw [setStateNode_parent] at hp
    obtain ⟨m, hm, hmid⟩ := hwf.parentMem n hn p hp
    exact ⟨f m, List.mem_map_of_mem hm, by rw [hf, setStateNode_id]; exact hmid⟩
  · intro n' hn' c hc
    obtain ⟨n, hn, rfl⟩ := List.mem_map.mp hn'
    rw [setStateNode_children] at hc
    obtain ⟨m, hm, hmid, hmp⟩ := hwf.childLink n hn c hc
    exact ⟨f m, List.mem_map_of_mem hm,
      by rw [hf, setStateNode_id]; exact hmid,
      by rw [hf, setStateNode_parent, setStateNode_id]; exact hmp⟩

/-- Live-node count: the strictly decreasing measure of the loop. -/
def liveCount (t : TreeModel) : Nat := (liveNodes t.nodes).length

/-- Head-step arithmetic for the live-node count. -/
theorem liveNodes_cons_length (n : NodeInfo) (l : List NodeInfo) :
    (liveNodes (n :: l)).length =
      (if n.state = NodeState.live then 1 else 0) + (liveNodes l).length := by
  unfold liveNodes
  rw [List.filter_cons]
  by_cases h : n.state = NodeState.live
  · rw [if_pos (by simp [h]), if_pos h]
    simp [Nat.add_comm]
  · rw [if_neg (by simp [h]), if_neg h]
    omega

/-- Suspending node `v` leaves a node Live iff it was Live and isn't `v`. -/
theorem setStateNode_suspend_state (v : Nat) (m : NodeInfo) :
    (setStateNode v NodeState.suspended m).state = NodeState.live ↔
      (m.id ≠ v ∧ m.state = NodeState.live) := by
  unfold setStateNode
  by_cases hid : m.id = v
  · rw [if_pos hid]
    simp [hid]
  · rw [if_neg hid]
    simp [hid]

/-- `set_state` leaves non-targets untouched. -/
theorem setStateNode_skip (v : Nat) (s : NodeState) (m : NodeInfo)
    (h : m.id ≠ v) : setStateNode v s m = m := by
  unfold setStateNode
  rw [if_neg h]

/-- Suspending never creates Live nodes. -/
theorem liveNodes_suspend_le (v : Nat) (l : List NodeInfo) :
    (liveNodes (l.map (setStateNode v .suspended))).length
      ≤ (liveNodes l).length := by
  induction l with
  | nil => simp [liveNodes]
  | cons m ms ih =>
    rw [List.map_cons, liveNodes_cons_length, liveNodes_cons_length]
    by_cases hid : m.id = v
    · rw [if_neg (by simp [setStateNode_suspend_state, hid])]
      split <;> omega
    · rw [setStateNode_skip v _ m hid]
      split <;> omega

/-- Suspending a Live member strictly decreases the live-node count. -/
theorem liveNodes_suspend_lt (v : Nat) {l : List NodeInfo} {n : NodeInfo}
    (hn : n ∈ l) (hlive : n.state = .live) (hid : n.id = v) :
    (liveNodes (l.map (setStateNode v .suspended))).length
      < (liveNodes l).length := by
  induction hn with
  | head rest =>
    -- Head is the victim: contributes 1 on the right, 0 on the left.
    rw [List.map_cons, liveNodes_cons_length, liveNodes_cons_length,
      if_neg (by simp [setStateNode_suspend_state, hid]), if_pos hlive]
    have hle := liveNodes_suspend_le v rest
    omega
  | tail b _ ih =>
    -- Victim in the tail: head contributions are equal or ≤, tail strictly <.
    rw [List.map_cons, liveNodes_cons_length, liveNodes_cons_length]
    by_cases hidb : b.id = v
    · rw [if_neg (by simp [setStateNode_suspend_state, hidb])]
      split <;> omega
    · rw [setStateNode_skip v _ b hidb]
      split <;> omega

/-- A tree with zero live count has no Live nodes at all. -/
theorem liveCount_zero_no_live (t : TreeModel) (h : liveCount t = 0) :
    liveNodes t.nodes = [] := by
  unfold liveCount at h
  cases hl : liveNodes t.nodes with
  | nil => rfl
  | cons a rest => rw [hl] at h; simp at h

/-- The recursive core of `tree_model::auto_evict_ram` (fuel-bounded,
exactly as in the Rust source). -/
def autoEvictLoop (exempt : List Nat) : Nat → TreeModel → TreeModel
  | 0, cur => cur
  | fuel + 1, cur =>
    if ¬ overRam cur ∧ ¬ overCount cur 0 then cur
    else
      match lruLiveVictim cur exempt with
      | none => cur
      | some v => autoEvictLoop exempt fuel (setState cur v .suspended)

/-- Mirror of `tree_model::auto_evict_ram` (fuel = node count, as in the
Rust source). -/
def autoEvictRam (t : TreeModel) (exempt : List Nat) : TreeModel :=
  autoEvictLoop exempt t.nodes.length t

/-- A tree with no Live nodes exits the loop immediately at any fuel. -/
theorem autoEvictLoop_no_live (exempt : List Nat) (fuel : Nat) (t : TreeModel)
    (h : liveCount t = 0) : autoEvictLoop exempt fuel t = t := by
  have hstop := no_live_not_over t (liveCount_zero_no_live t h)
  cases fuel with
  | zero => rfl
  | succ fuel => rw [autoEvictLoop, if_pos hstop]

/-- Picking a victim strictly decreases the live count. -/
theorem victim_decreases_liveCount (t : TreeModel) (exempt : List Nat)
    (v : Nat) (h : lruLiveVictim t exempt = some v) :
    liveCount (setState t v .suspended) < liveCount t := by
  obtain ⟨n, hn, ⟨hlive, _, _⟩, hid, _⟩ := lruLiveVictim_sound t exempt v h
  exact liveNodes_suspend_lt v hn hlive hid

/-- Group D, termination: the loop result is fuel-independent for every
fuel at or above the live-node count — i.e. the live-node count is a
strictly decreasing measure and the fuel bound never cuts the loop
short. -/
theorem auto_evict_loop_fuel_irrelevant (exempt : List Nat) :
    ∀ f1 t f2, liveCount t ≤ f1 → liveCount t ≤ f2 →
      autoEvictLoop exempt f1 t = autoEvictLoop exempt f2 t := by
  intro f1
  induction f1 with
  | zero =>
    intro t f2 h1 _
    rw [autoEvictLoop, autoEvictLoop_no_live exempt f2 t (by omega)]
  | succ f1 ih =>
    intro t f2 h1 h2
    cases f2 with
    | zero =>
      rw [autoEvictLoop, autoEvictLoop_no_live exempt (f1 + 1) t (by omega)]
    | succ f2 =>
      by_cases hstop : ¬ overRam t ∧ ¬ overCount t 0
      · rw [autoEvictLoop, autoEvictLoop, if_pos hstop, if_pos hstop]
      · rw [autoEvictLoop, autoEvictLoop, if_neg hstop, if_neg hstop]
        cases hv : lruLiveVictim t exempt with
        | none => rfl
        | some v =>
          have hdec := victim_decreases_liveCount t exempt v hv
          exact ih (setState t v .suspended) f2 (by omega) (by omega)

/-- Live count never exceeds the node count — the Rust fuel qualifies. -/
theorem liveCount_le_len (t : TreeModel) : liveCount t ≤ t.nodes.length :=
  List.length_filter_le _ t.nodes

/-- Group D, termination (top level): `auto_evict_ram`'s `nodes.len()`
fuel computes the loop's true fixed point — any fuel at or above the
live-node count yields the identical result. -/
theorem auto_evict_ram_terminates (t : TreeModel) (exempt : List Nat)
    (f : Nat) (hf : liveCount t ≤ f) :
    autoEvictLoop exempt f t = autoEvictRam t exempt :=
  auto_evict_loop_fuel_irrelevant exempt f t t.nodes.length hf
    (liveCount_le_len t)

/-- Group D, post-condition (loop invariant form). -/
theorem auto_evict_loop_post (exempt : List Nat) :
    ∀ fuel t, liveCount t ≤ fuel →
      (¬ overRam (autoEvictLoop exempt fuel t)
          ∧ ¬ overCount (autoEvictLoop exempt fuel t) 0)
        ∨ (∀ n ∈ (autoEvictLoop exempt fuel t).nodes, n.state = .live →
            n.id ∈ exempt
              ∨ n.id ∈ implicitlyProtected (autoEvictLoop exempt fuel t)) := by
  intro fuel
  induction fuel with
  | zero =>
    intro t h
    left
    rw [autoEvictLoop]
    exact no_live_not_over t (liveCount_zero_no_live t (by omega))
  | succ fuel ih =>
    intro t h
    by_cases hstop : ¬ overRam t ∧ ¬ overCount t 0
    · left
      rw [autoEvictLoop, if_pos hstop]
      exact hstop
    · cases hv : lruLiveVictim t exempt with
      | none =>
        right
        rw [autoEvictLoop, if_neg hstop, hv]
        intro n hn hlive
        have hnel := lruLiveVictim_none t exempt hv n hn
        by_cases hex : n.id ∈ exempt
        · exact Or.inl hex
        · by_cases hpr : n.id ∈ implicitlyProtected t
          · exact Or.inr hpr
          · exact absurd ⟨hlive, hex, hpr⟩ hnel
      | some v =>
        have hdec := victim_decreases_liveCount t exempt v hv
        rw [autoEvictLoop, if_neg hstop, hv]
        exact ih (setState t v .suspended) (by omega)

/-- Group D: on exit, `auto_evict_ram` is either under both the RAM and
count budgets, or every remaining Live node is exempt or implicitly
protected. -/
theorem auto_evict_ram_post (t : TreeModel) (exempt : List Nat) :
    (¬ overRam (autoEvictRam t exempt)
        ∧ ¬ overCount (autoEvictRam t exempt) 0)
      ∨ (∀ n ∈ (autoEvictRam t exempt).nodes, n.state = .live →
          n.id ∈ exempt ∨ n.id ∈ implicitlyProtected (autoEvictRam t exempt)) :=
  auto_evict_loop_post exempt t.nodes.length t (liveCount_le_len t)

/-- Group D: the eviction loop preserves the Group A shape invariants
(it only flips `state` fields). -/
theorem auto_evict_ram_preserves_well_formed (t : TreeModel)
    (exempt : List Nat) (hwf : WellFormed t) :
    WellFormed (autoEvictRam t exempt) := by
  unfold autoEvictRam
  generalize t.nodes.length = fuel
  induction fuel generalizing t with
  | zero => exact hwf
  | succ fuel ih =>
    rw [autoEvictLoop]
    split
    · exact hwf
    · cases lruLiveVictim t exempt with
      | none => exact hwf
      | some v => exact ih _ (setState_preserves_well_formed t v .suspended hwf)

end Verif.Tree
