"""Named fault injectors. `fault_id` on POST /lease selects one.

Unknown ids are loud — the allowlist is in the error, never a silent
`none`. Each entry exposes `inject`, `fault_visible`, `healthy`, and
`good_fix_hint` so scoring can compute `contained` + `restored`
without defaulting either term.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from faults.kill_member_0 import KillMember0
from faults.none import NoneFault
from faults.partition_member_0 import PartitionMember0
from faults.relay import Relay
from faults.scripted import ScriptedFault, registry as scenario_registry
from faults.tetra_churn import TetraChurn

# The scripted family: the catalog key is `scripted` and the
# scenario id picks the directory. One entry, not one per scenario, so
# the pack can grow without a k7d change.
SCRIPTED_ID = "scripted"


class UnknownFault(ValueError):
    def __init__(self, fault_id: str, known: list[str]) -> None:
        self.fault_id = fault_id
        self.known = list(known)
        super().__init__(
            f"unknown fault_id {fault_id!r}; allowlist: {', '.join(self.known)}"
        )


class UnknownScenario(ValueError):
    def __init__(self, scenario_id: str, known: list[str]) -> None:
        self.scenario_id = scenario_id
        self.known = list(known)
        super().__init__(
            f"unknown scenario_id {scenario_id!r}; loaded: "
            f"{', '.join(self.known) if self.known else '(none)'}"
        )


_INSTANCES = (
    NoneFault(),
    KillMember0(),
    PartitionMember0(),
    TetraChurn(),
    Relay(),
)
CATALOG: dict[str, Any] = {f.id: f for f in _INSTANCES}

# Free-form GRPO: every member sees the same simple
# incident. Catalog relays stay on incident/selfplay.
GRPO_FAULTS = frozenset(
    {"kill-member-0", "partition-member-0", "none", SCRIPTED_ID}
)

_SCENARIOS: dict[str, ScriptedFault] = {}
_SCENARIO_ROOT: Path | None = None


def set_scenario_root(root: Path | str | None) -> int:
    """Load the pack at gym start. Loud on a bad scenario; returns count."""
    global _SCENARIO_ROOT
    _SCENARIOS.clear()
    _SCENARIO_ROOT = None
    if root in (None, ""):
        return 0
    path = Path(str(root))
    _SCENARIOS.update(scenario_registry(path))
    _SCENARIO_ROOT = path
    return len(_SCENARIOS)


def scenario_root() -> Path | None:
    return _SCENARIO_ROOT


def scenario_ids() -> list[str]:
    return sorted(_SCENARIOS)


def get_scenario(scenario_id: str) -> ScriptedFault:
    if _SCENARIO_ROOT is None:
        raise ValueError(
            "fault_id='scripted' needs a scenario pack; start the gym with "
            "GYM_SCENARIO_DIR=<k7-scenarios>/scenarios"
        )
    fault = _SCENARIOS.get(scenario_id)
    if fault is None:
        raise UnknownScenario(scenario_id, scenario_ids())
    return fault


def require_grpo_fault(fault_id: str) -> None:
    """Loud unless `fault_id` is a per-member GRPO injector."""
    if fault_id not in GRPO_FAULTS:
        raise ValueError(
            f"GYM_SCOREBOARD=grpo requires fault_id in "
            f"{sorted(GRPO_FAULTS)}, got {fault_id!r}"
        )


def allowlist() -> list[str]:
    return sorted(CATALOG)


def get(fault_id: str) -> Any:
    if fault_id == SCRIPTED_ID:
        raise ValueError(
            "fault_id='scripted' needs scenario_id; use get_scenario(scenario_id)"
        )
    fault = CATALOG.get(fault_id)
    if fault is None:
        raise UnknownFault(fault_id, allowlist())
    return fault
