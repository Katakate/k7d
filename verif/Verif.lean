-- Top-level entry point for the Aeneas-translated proofs of
-- `crates/k7d/src/tree_model.rs`.
--
-- Each file under `Verif/` holds the theorems for one
-- group. `TreeModel` is the Aeneas-generated functional model (regenerated
-- by `make verif-gen`; do not hand-edit). The other files are hand-written
-- proofs against that model.

import Verif.TreeModel
import Verif.TreeShape
import Verif.TreeBudget
import Verif.TreeEviction
import Verif.Latency
import Verif.K7dlCodec
import Verif.Equiv.Abs
import Verif.Equiv.Scans
import Verif.Equiv.Rebuild
import Verif.Equiv.Acct
import Verif.Equiv.Anc
import Verif.Equiv.Lru
import Verif.Equiv.Evict
import Verif.Equiv.Latency
import Verif.Equiv.K7dl
import Verif.Equiv.Transfer
