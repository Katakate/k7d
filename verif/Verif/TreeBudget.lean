-- Group B — Budget accounting invariants.
--
-- We prove, for the pure budget accounting in `crate::tree_model`:
--   * `usage_ram_is_sat_sum_of_live` — `usage().live_ram_bytes` is exactly
--     the saturating (`u64::saturating_add`) sum of `est_ram_bytes` over
--     Live nodes; `usage_ram_is_sum_of_live` recovers the plain sum under
--     the honest `sum ≤ u64::MAX` side condition.
--   * `usage_vm_count_is_sat_sum_of_live` / `usage_vm_count_is_sum_of_live`
--     — the same pair for `live_vm_count` (an N-VM
--     cluster node counts as N; `usize::saturating_add`).
--   * `usage_count_is_count_of_live` — `usage().live_node_count` is
--     exactly the number of Live nodes (plain `+= 1` in the Rust; no
--     saturation).
--   * `ram_soft_limit_below_max` — the 85% proactive soft limit never
--     exceeds `max_live_ram_bytes`, for every budget (saturation
--     included).
--
-- Mirror rationale: see the file-level note in `Verif/TreeShape.lean`
-- (and `Verif/K7dlCodec.lean` for the original Groups E/F precedent).
-- `usageAux` mirrors the Rust accumulator loop branch-for-branch,
-- **saturation included**:
-- `satAdd U64_MAX` mirrors `u64::saturating_add` and
-- `satAdd USIZE_MAX` mirrors `usize::saturating_add`, so the
-- mirror ↔ Aeneas equivalence theorems in `Verif/Equiv/` are
-- unconditional. `ramSoftLimit` mirrors the saturation explicitly
-- (`min · U64_MAX`) because the theorem's truth depends on it.

import Verif.TreeShape

namespace Verif.Tree

/-- `u64::MAX`, the `u64` saturation ceiling. -/
def U64_MAX : Nat := 18446744073709551615

/-- `usize::MAX` — platform-dependent, exactly as Aeneas models `Usize`
(`2 ^ System.Platform.numBits - 1`, with `numBits ∈ {32, 64}`). -/
def USIZE_MAX : Nat := 2 ^ System.Platform.numBits - 1

/-- Mirror of the Rust `saturating_add` family: `cap` is the width's MAX
(`U64_MAX` for `u64`, `USIZE_MAX` for `usize`). -/
def satAdd (cap a b : Nat) : Nat := min (a + b) cap

/-- Mirror of `u64::saturating_mul`. -/
def satMul (a b : Nat) : Nat := min (a * b) U64_MAX

/-- Saturating left fold of `satAdd cap` — the closed form of the Rust
accumulator loops in `usage`. -/
def satSum (cap : Nat) (l : List Nat) (acc : Nat) : Nat :=
  l.foldl (satAdd cap) acc

/-- Below the ceiling, the saturating fold is the plain sum — the bridge
back to the readable sum-of-live statements. -/
theorem satSum_eq_sum (cap : Nat) (l : List Nat) (acc : Nat)
    (h : acc + l.sum ≤ cap) : satSum cap l acc = acc + l.sum := by
  induction l generalizing acc with
  | nil => simp [satSum]
  | cons x xs ih =>
    simp only [List.sum_cons] at h
    have hx : satAdd cap acc x = acc + x := by
      unfold satAdd; omega
    show satSum cap xs (satAdd cap acc x) = acc + (x + xs.sum)
    rw [hx, ih (acc + x) (by omega)]
    omega

/-- Mirror of `tree_model::TreeUsage`. -/
structure TreeUsage where
  liveVmCount : Nat
  liveRamBytes : Nat
  diskBytes : Nat
  totalNodes : Nat
  liveNodeCount : Nat

/-- Mirror of the accumulator loop in `tree_model::usage`
(saturation-exact: `u64::saturating_add` on the byte counters,
`usize::saturating_add` on the VM counter, plain `+= 1` on the
node counter — exactly as in the Rust). -/
def usageAux : List NodeInfo → TreeUsage → TreeUsage
  | [], u => u
  | n :: ns, u =>
    usageAux ns
      { u with
        liveVmCount :=
          if n.state = .live then satAdd USIZE_MAX u.liveVmCount n.vmCount
          else u.liveVmCount,
        liveRamBytes :=
          if n.state = .live then satAdd U64_MAX u.liveRamBytes n.estRamBytes
          else u.liveRamBytes,
        liveNodeCount :=
          if n.state = .live then u.liveNodeCount + 1 else u.liveNodeCount,
        diskBytes := satAdd U64_MAX u.diskBytes n.diskBytes }

/-- Mirror of `tree_model::usage`. -/
def usage (t : TreeModel) : TreeUsage :=
  { usageAux t.nodes ⟨0, 0, 0, 0, 0⟩ with totalNodes := t.nodes.length }

/-- The Live nodes of a node list. -/
def liveNodes (l : List NodeInfo) : List NodeInfo :=
  l.filter (fun n => decide (n.state = NodeState.live))

/-- Closed form of the accumulator loop: each `usageAux` field is the
saturating fold (plain count for `liveNodeCount`) of the corresponding
projection over the list, seeded by the accumulator. -/
theorem usageAux_spec (l : List NodeInfo) (u : TreeUsage) :
    usageAux l u =
      { liveVmCount :=
          satSum USIZE_MAX ((liveNodes l).map NodeInfo.vmCount) u.liveVmCount,
        liveRamBytes :=
          satSum U64_MAX ((liveNodes l).map NodeInfo.estRamBytes)
            u.liveRamBytes,
        diskBytes := satSum U64_MAX (l.map NodeInfo.diskBytes) u.diskBytes,
        totalNodes := u.totalNodes,
        liveNodeCount := u.liveNodeCount + (liveNodes l).length } := by
  induction l generalizing u with
  | nil => simp [usageAux, liveNodes, satSum]
  | cons n ns ih =>
    by_cases hlive : n.state = NodeState.live
    · simp [usageAux, ih, liveNodes, hlive, satSum, Nat.add_assoc]
      omega
    · simp [usageAux, ih, liveNodes, hlive, satSum]

/-- Group B (saturation-exact form): `usage().live_ram_bytes` is the
saturating sum of `est_ram_bytes` over Live nodes. -/
theorem usage_ram_is_sat_sum_of_live (t : TreeModel) :
    (usage t).liveRamBytes
      = satSum U64_MAX ((liveNodes t.nodes).map NodeInfo.estRamBytes) 0 := by
  simp [usage, usageAux_spec]

/-- Group B: below `u64::MAX` (the honest side condition — above it the
Rust saturates and no sum statement is true), `usage().live_ram_bytes`
= Σ `est_ram_bytes` over Live nodes. -/
theorem usage_ram_is_sum_of_live (t : TreeModel)
    (h : ((liveNodes t.nodes).map NodeInfo.estRamBytes).sum ≤ U64_MAX) :
    (usage t).liveRamBytes
      = ((liveNodes t.nodes).map NodeInfo.estRamBytes).sum := by
  rw [usage_ram_is_sat_sum_of_live, satSum_eq_sum _ _ _ (by omega)]
  exact Nat.zero_add _

/-- Group B (saturation-exact form): `usage().live_vm_count` is the
saturating sum of `vm_count` over Live nodes. -/
theorem usage_vm_count_is_sat_sum_of_live (t : TreeModel) :
    (usage t).liveVmCount
      = satSum USIZE_MAX ((liveNodes t.nodes).map NodeInfo.vmCount) 0 := by
  simp [usage, usageAux_spec]

/-- Group B: below `usize::MAX`, `usage().live_vm_count` = Σ `vm_count`
over Live nodes. -/
theorem usage_vm_count_is_sum_of_live (t : TreeModel)
    (h : ((liveNodes t.nodes).map NodeInfo.vmCount).sum ≤ USIZE_MAX) :
    (usage t).liveVmCount
      = ((liveNodes t.nodes).map NodeInfo.vmCount).sum := by
  rw [usage_vm_count_is_sat_sum_of_live, satSum_eq_sum _ _ _ (by omega)]
  exact Nat.zero_add _

/-- Group B: `usage().live_node_count` = number of Live nodes (the Rust
uses a plain `+= 1` here, so no saturation and no side condition). -/
theorem usage_count_is_count_of_live (t : TreeModel) :
    (usage t).liveNodeCount = (liveNodes t.nodes).length := by
  simp [usage, usageAux_spec]

/-- Mirror of `tree_model::TreeBudget::ram_soft_limit` (×85/100 with
saturating multiply). -/
def ramSoftLimit (b : TreeBudget) : Nat :=
  satMul b.maxLiveRamBytes 85 / 100

/-- Group B: the proactive soft limit never exceeds the hard RAM budget.

No side condition: below the saturation point this is `x*85/100 ≤ x`;
at saturation the result is `U64_MAX/100`, and any `x` big enough to
saturate (`x*85 ≥ U64_MAX`) is far above that. -/
theorem ram_soft_limit_below_max (b : TreeBudget) :
    ramSoftLimit b ≤ b.maxLiveRamBytes := by
  unfold ramSoftLimit satMul U64_MAX
  omega

-- Budget predicates (mirrors of `tree_model::{over_ram, over_count,
-- over_disk}`), used by the Group D eviction-loop theorems in
-- `Verif/TreeEviction.lean`. The Rust `saturating_add` in `over_count`
-- is mirrored saturation-exactly by `satAdd USIZE_MAX`.

/-- Mirror of `tree_model::over_ram`. -/
def overRam (t : TreeModel) : Prop :=
  ramSoftLimit t.budget < (usage t).liveRamBytes

/-- Mirror of `tree_model::over_count`. -/
def overCount (t : TreeModel) (incoming : Nat) : Prop :=
  t.budget.maxLiveVms < satAdd USIZE_MAX (usage t).liveVmCount incoming

/-- Mirror of `tree_model::over_disk`. -/
def overDisk (t : TreeModel) : Prop :=
  t.budget.maxDiskBytes < (usage t).diskBytes

instance (t : TreeModel) : Decidable (overRam t) := by
  unfold overRam; infer_instance

instance (t : TreeModel) (i : Nat) : Decidable (overCount t i) := by
  unfold overCount; infer_instance

instance (t : TreeModel) : Decidable (overDisk t) := by
  unfold overDisk; infer_instance

/-- A tree with no Live nodes is under both RAM and count budgets — the
base case of the Group D eviction-loop proofs. -/
theorem no_live_not_over (t : TreeModel) (h : liveNodes t.nodes = []) :
    ¬ overRam t ∧ ¬ overCount t 0 := by
  constructor
  · unfold overRam
    rw [usage_ram_is_sat_sum_of_live, h]
    simp [satSum]
  · unfold overCount
    rw [usage_vm_count_is_sat_sum_of_live, h]
    simp [satSum, satAdd]

end Verif.Tree
