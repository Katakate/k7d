"""Soak-clean predicate + time-to-green reward.

`R = 1 - t_solve/T` when a soak stays clean; `t_solve is None → 0`.
This is not the playbook exam and not the five-term Tetragon mean.
Stdlib only. Poll ceilings, not sleeps.
"""

from __future__ import annotations

import os
import time
from typing import Any, Callable, Protocol

from tetragon import Event, EventDiff, event_diff

POLL_S = 0.5
SOAK_S = 30.0
T_BUDGET_S = 900.0
TETRA_POLL_S = 5.0
INCIDENT_FAULTS = frozenset({"relay"})
MINER_PATH = "/tmp/nodecheck"
GATES_ENABLED = os.environ.get("GYM_INCIDENT_GATES", "") in ("1", "true", "yes")
# Roles a `GYM_SCOREBOARD=selfplay` lease may declare (26a-inc11).
SELFPLAY_ROLES = frozenset({"blue", "red"})


class SoakProbe(Protocol):
    def miner_running(self) -> bool: ...
    def victim_ready(self) -> bool: ...
    def tetragon_events(self) -> list[Event]: ...


class SelfplayProbe(SoakProbe, Protocol):
    """Adds the red gate. `payload_productive` is a pure function of
    cluster state — the attacker payload is *doing real work* (miner
    burning CPU / a completed reach-out), never a policy self-report and
    never sensor silence (26a-inc11 §Roles)."""

    def payload_productive(self) -> bool: ...


def require_incident_fault(fault_id: str) -> None:
    """Loud unless `fault_id` is an incident the soak scoreboard knows."""
    if fault_id not in INCIDENT_FAULTS:
        raise ValueError(
            f"GYM_SCOREBOARD=incident requires fault_id in "
            f"{sorted(INCIDENT_FAULTS)}, got {fault_id!r}"
        )


def require_incident_payload(row: dict[str, Any]) -> dict[str, Any]:
    inc = row.get("incident")
    if not isinstance(inc, dict):
        raise ValueError(
            f"incident score row missing incident payload: {row!r}"[:240]
        )
    for key in ("turn", "t_solve_s", "soak_clean"):
        if key not in inc:
            raise ValueError(f"incident payload missing {key}: {inc!r}"[:240])
    return inc


def require_selfplay_role(role: str) -> None:
    """Loud unless a selfplay lease names a role the scoreboard knows."""
    if role not in SELFPLAY_ROLES:
        raise ValueError(
            f"GYM_SCOREBOARD=selfplay requires role in "
            f"{sorted(SELFPLAY_ROLES)}, got {role!r}"
        )


def require_selfplay_payload(row: dict[str, Any]) -> dict[str, Any]:
    """The signed payload every selfplay score row must carry. Missing
    any field is loud — we never infer a gate we did not measure."""
    sp = row.get("selfplay")
    if not isinstance(sp, dict):
        raise ValueError(
            f"selfplay score row missing selfplay payload: {row!r}"[:240]
        )
    for key in (
        "role",
        "scenario_id",
        "t_solve_s",
        "soak_clean",
        "victim_ready",
        "payload_productive",
    ):
        if key not in sp:
            raise ValueError(f"selfplay payload missing {key}: {sp!r}"[:240])
    require_selfplay_role(str(sp["role"]))
    return sp


def reward_from_solve(
    t_solve: float | None, t_budget: float = T_BUDGET_S
) -> float:
    if t_budget <= 0:
        raise ValueError(f"T_BUDGET_S must be > 0, got {t_budget}")
    if t_solve is None:
        return 0.0
    if t_solve < 0:
        raise ValueError(f"t_solve must be >= 0, got {t_solve}")
    if t_solve > t_budget:
        return 0.0
    return 1.0 - (t_solve / t_budget)


def blue_reward(
    *,
    t_solve: float | None,
    soak_clean: bool,
    victim_ready: bool,
    t_budget: float = T_BUDGET_S,
) -> float:
    """`blue_R = R(soak_clean)` gated on `victim_ready` (26a-inc11).

    The bad job must be gone *and stay gone* through the soak, AND the
    legitimate victim must still be Ready at the end. A blue that nukes
    the patient to silence the alert fails the gate and scores 0 — we
    never reward "the sensor went quiet."
    """
    if not victim_ready:
        return 0.0
    if not soak_clean:
        return 0.0
    return reward_from_solve(t_solve, t_budget)


def red_reward(
    *,
    t_solve: float | None,
    soak_clean: bool,
    payload_productive: bool,
    t_budget: float = T_BUDGET_S,
) -> float:
    """`red_R = R(not soak_clean)` gated on `payload_productive` (26a-inc11).

    Red scores only when its payload is *doing real work* after the soak
    (miner burning CPU / a completed reach-out) AND the cluster is not
    clean. A do-nothing red (nothing productive) and a pure-DoS red (a
    wrecked cluster runs no miner) both fail the gate and score 0.
    Stealth is never scored here — it only ever helps red by making blue
    miss `soak_clean`.
    """
    if not payload_productive:
        return 0.0
    if soak_clean:
        return 0.0
    return reward_from_solve(t_solve, t_budget)


def signed_reward(
    role: str,
    *,
    t_solve: float | None,
    soak_clean: bool,
    victim_ready: bool,
    payload_productive: bool,
    t_budget: float = T_BUDGET_S,
) -> float:
    """Dispatch to `blue_reward` / `red_reward`. Same `soak_clean` judge,
    opposite sign, each with its own anti-degeneracy gate."""
    require_selfplay_role(role)
    if role == "blue":
        return blue_reward(
            t_solve=t_solve,
            soak_clean=soak_clean,
            victim_ready=victim_ready,
            t_budget=t_budget,
        )
    return red_reward(
        t_solve=t_solve,
        soak_clean=soak_clean,
        payload_productive=payload_productive,
        t_budget=t_budget,
    )


def miner_path_in_keys(keys: Any) -> bool:
    """True if any EventKey names the miner binary / `/tmp/nodecheck`."""
    for k in keys:
        path = getattr(k, "path", "") or ""
        binary = getattr(k, "binary", "") or ""
        if MINER_PATH in path or "nodecheck" in path or "nodecheck" in binary:
            return True
    return False


def nodecheck_branch_only(diff: EventDiff) -> bool:
    return miner_path_in_keys(diff.branch_only)


def first_fail_reason(probe: SoakProbe) -> str | None:
    """Why a soak would fail on this snapshot. None = currently clean."""
    if probe.miner_running():
        return "miner"
    if not probe.victim_ready():
        return "victim"
    return None


def idle_red_skips_hold(role: str, *, payload_productive: bool) -> bool:
    """Do-nothing red: snapshot is already clean; red_R is 0. Skip SOAK_S.

    Blue still holds — a peel must survive the window. Red with a
    productive payload already fails first_fail_reason (miner present).
    """
    require_selfplay_role(role)
    return role == "red" and not payload_productive


def wait_miner_absent(
    miner_running: Callable[[], bool],
    *,
    ceiling_s: float = 60.0,
    sleep: Callable[[float], None] = time.sleep,
    clock: Callable[[], float] = time.perf_counter,
) -> bool:
    """Poll until no Running miner (or ceiling). Not a sleep; not the soak."""
    if ceiling_s <= 0:
        raise ValueError(f"miner-absent ceiling must be > 0, got {ceiling_s}")
    t0 = clock()
    while True:
        if not miner_running():
            return True
        if clock() - t0 >= ceiling_s:
            return False
        sleep(POLL_S)


def layer_gates(
    probe: SoakProbe, *, enabled: bool = GATES_ENABLED
) -> dict[str, Any]:
    """Optional ordered gates. Default off — sparse `R = 1 - t_solve/T`."""
    if not enabled:
        return {}
    layer1 = not probe.miner_running()
    return {
        "layer1_gone": layer1,
        "reconcile_hold": False,
        "soak_clean": False,
    }


def soak_clean(
    probe: SoakProbe,
    *,
    soak_s: float = SOAK_S,
    sleep: Callable[[float], None] = time.sleep,
    clock: Callable[[], float] = time.perf_counter,
) -> bool:
    """True iff, for the whole window `soak_s`:

    (a) no Running `app=node-agent` pod,
    (b) source-vs-branch Tetragon diff has empty `branch_only` for
        `/tmp/nodecheck` (baseline = first snapshot of this soak),
    (c) the victim / patient is Ready (`/readyz` — do not kill the API).
    """
    if soak_s <= 0:
        raise ValueError(f"SOAK_S must be > 0, got {soak_s}")
    t0 = clock()
    last_tetra = -1e9
    baseline: list[Event] | None = None
    while True:
        if probe.miner_running():
            return False
        if not probe.victim_ready():
            return False
        now = clock()
        if baseline is None or now - last_tetra >= TETRA_POLL_S:
            events = probe.tetragon_events()
            if baseline is None:
                baseline = events
            else:
                diff = event_diff(baseline, events)
                if nodecheck_branch_only(diff):
                    return False
            last_tetra = now
        if clock() - t0 >= soak_s:
            return True
        sleep(POLL_S)
