-- Group F — Latency budget.
--
-- We prove two properties of `tree_model::fork_warm_budget_ns`:
--   * base — `dirty_pages = 0` ⇒ result equals `FORK_WARM_BASE_NS`.
--   * monotone — `a ≤ b` ⇒ `forkWarmBudgetNs a ≤ forkWarmBudgetNs b`.
--
-- internal notes: the Rust source is raw `u64` nanoseconds (the original
-- `Duration`-typed `fork_warm_budget` blocked equivalence — Aeneas models
-- `std::time::Duration` opaquely; `latency.rs` keeps the `Duration`
-- wrapper for callers). The mirror below is **saturation-exact**: the
-- guarded multiply mirrors the Rust's explicit overflow guard
-- (`d > u64::MAX / per_page ⇒ u64::MAX`, the `ram_soft_limit` idiom —
-- CHALLENGES.md #24) and `Tree.satAdd` mirrors `u64::saturating_add`, so
-- the mirror ↔ Aeneas equivalence in `Verif/Equiv/Latency.lean` is
-- unconditional. The readable non-saturating form is recovered by
-- `fork_warm_budget_ns_eq_sum` under a no-overflow side condition (same
-- style as the Group B split in `TreeBudget.lean`).
--
-- The theorems to cite from the Rust doc comments are the `_rust`
-- corollaries in `Verif/Equiv/Transfer.lean` — they speak about the
-- Aeneas translation of the Rust function directly.

import Verif.TreeBudget

namespace Verif.Latency

open Verif.Tree (satAdd U64_MAX)

/-- Mirror of `crate::tree_model::FORK_WARM_BASE_NS` (2 ms). -/
def forkWarmBaseNs : Nat := 2_000_000

/-- Mirror of `crate::tree_model::FORK_WARM_PER_PAGE_NS` (500 ns). -/
def forkWarmPerPageNs : Nat := 500

/-- Mirror of `crate::tree_model::fork_warm_budget_ns`
(saturation-exact: guarded multiply + `u64::saturating_add`). -/
def forkWarmBudgetNs (dirtyPages : Nat) : Nat :=
  let scaled :=
    if U64_MAX / forkWarmPerPageNs < dirtyPages then U64_MAX
    else forkWarmPerPageNs * dirtyPages
  satAdd U64_MAX forkWarmBaseNs scaled

/-- Group F base case: zero dirty pages ⇒ base budget only. -/
theorem fork_warm_budget_base (z : Nat) (h : z = 0) :
    forkWarmBudgetNs z = forkWarmBaseNs := by
  subst h
  simp [forkWarmBudgetNs, satAdd, forkWarmBaseNs, U64_MAX, forkWarmPerPageNs]

/-- Group F monotonicity: more dirty pages ⇒ never a smaller budget. -/
theorem fork_warm_budget_monotone (a b : Nat) (h : a ≤ b) :
    forkWarmBudgetNs a ≤ forkWarmBudgetNs b := by
  unfold forkWarmBudgetNs satAdd
  simp only [forkWarmPerPageNs, forkWarmBaseNs, U64_MAX]
  split <;> split <;> omega

/-- Readable corollary: below the `u64` ceiling the budget is the plain
sum `base + per_page * dirty_pages` (the honest side condition — above
it the Rust saturates and no sum statement is true). -/
theorem fork_warm_budget_ns_eq_sum (d : Nat)
    (h : forkWarmBaseNs + forkWarmPerPageNs * d ≤ U64_MAX) :
    forkWarmBudgetNs d = forkWarmBaseNs + forkWarmPerPageNs * d := by
  unfold forkWarmBudgetNs satAdd
  simp only [forkWarmPerPageNs, forkWarmBaseNs, U64_MAX] at *
  split <;> omega

end Verif.Latency
