-- Re-export wrapper around the Aeneas-generated `Verif/K7d.lean`.
--
-- Aeneas names the generated top-level module after the Cargo crate
-- (`k7d`), so on a fresh `make verif-gen` it writes `Verif/K7d.lean`.
-- The proofs import `Verif.TreeModel`, so this thin wrapper
-- bridges the two so the proof files only ever import `Verif.TreeModel`.
--
-- Hand-edits to `Verif/K7d.lean` are forbidden (it is overwritten on
-- every regeneration). Hand-edits to *this* file are fine.

import Verif.K7d
