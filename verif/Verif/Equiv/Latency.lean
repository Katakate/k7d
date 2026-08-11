-- internal notes� equivalence for Group F: the Aeneas translation
-- of `tree_model::fork_warm_budget_ns` computes the saturation-exact
-- mirror `Verif.Latency.forkWarmBudgetNs`. Straight-line arithmetic
-- (division by the nonzero per-page constant, one overflow guard, one
-- multiply, one `saturating_add`) — no loop; the proof is the
-- `ram_soft_limit_equiv` recipe from `Equiv/Acct.lean`.

import Verif.Equiv.Acct
import Verif.Latency

namespace Verif.Equiv

open Aeneas Aeneas.Std Result
open Aeneas.Std.WP
open k7d

/-- The generated per-page constant evaluates to the mirror value. -/
theorem fork_warm_per_page_ns_val :
    tree_model.FORK_WARM_PER_PAGE_NS.val = Latency.forkWarmPerPageNs := by
  simp [tree_model.FORK_WARM_PER_PAGE_NS, Latency.forkWarmPerPageNs]

/-- The generated base constant evaluates to the mirror value. -/
theorem fork_warm_base_ns_val :
    tree_model.FORK_WARM_BASE_NS.val = Latency.forkWarmBaseNs := by
  simp [tree_model.FORK_WARM_BASE_NS, Latency.forkWarmBaseNs]

-- Mirror-side branch lemmas (no generated names): pick the guard arm.

theorem forkWarmBudgetNs_of_guard {d : Nat}
    (h : Tree.U64_MAX / Latency.forkWarmPerPageNs < d) :
    Latency.forkWarmBudgetNs d
      = Tree.satAdd Tree.U64_MAX Latency.forkWarmBaseNs Tree.U64_MAX := by
  unfold Latency.forkWarmBudgetNs
  rw [if_pos h]

theorem forkWarmBudgetNs_of_no_guard {d : Nat}
    (h : ¬ Tree.U64_MAX / Latency.forkWarmPerPageNs < d) :
    Latency.forkWarmBudgetNs d
      = Tree.satAdd Tree.U64_MAX Latency.forkWarmBaseNs
          (Latency.forkWarmPerPageNs * d) := by
  unfold Latency.forkWarmBudgetNs
  rw [if_neg h]

/-- Equivalence: `tree_model::fork_warm_budget_ns` computes the mirror
`Latency.forkWarmBudgetNs` (and never panics) — including the explicit
saturation guard the Rust uses in place of `saturating_mul`. -/
theorem fork_warm_budget_ns_equiv (d : Std.U64) :
    tree_model.fork_warm_budget_ns d
      ⦃ r => r.val = Latency.forkWarmBudgetNs d.val ⦄ := by
  unfold tree_model.fork_warm_budget_ns
  step as ⟨i, hi⟩
  · -- The per-page divisor is nonzero.
    simp [tree_model.FORK_WARM_PER_PAGE_NS]
  split
  · rename_i hgt
    have hguard : Tree.U64_MAX / Latency.forkWarmPerPageNs < d.val := by
      rw [← core_u64_max_val, ← fork_warm_per_page_ns_val]
      scalar_tac
    simp only [bind_tc_ok, spec_ok, u64_saturating_add_val]
    rw [forkWarmBudgetNs_of_guard hguard, ← core_u64_max_val,
      ← fork_warm_base_ns_val]
  · rename_i hle
    have hnoguard : ¬ Tree.U64_MAX / Latency.forkWarmPerPageNs < d.val := by
      rw [← core_u64_max_val, ← fork_warm_per_page_ns_val]
      scalar_tac
    step as ⟨scaled, hscaled⟩
    · -- `500 * d` stays below `u64::MAX` when the guard did not fire.
      have h1 := fork_warm_per_page_ns_val
      have h2 := core_u64_max_val
      simp only [Latency.forkWarmPerPageNs, Tree.U64_MAX] at *
      scalar_tac
    · simp only [u64_saturating_add_val]
      rw [forkWarmBudgetNs_of_no_guard hnoguard, ← fork_warm_per_page_ns_val,
        ← fork_warm_base_ns_val, ← hscaled]

end Verif.Equiv
