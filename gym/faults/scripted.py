"""One scenario directory as a `Fault`.

Faults are data: `inject.sh` / `visible.sh` / `restored.sh` come from
`k7-scenarios`, not from this repo. The scripts run on member 0 (the
k3s server — `act exec` only ever reaches `guest_cids[0]`), sent as
text over vsock with an `export K7S_*` prelude; nothing is copied
into the guest.

`reference-fix.sh` is loaded so `verify` can ask for it by scenario
id, and is never put in `good_fix_hint`: the trainer must not receive
the answer.
"""

from __future__ import annotations

import time
from pathlib import Path
from typing import Any

from faults.base import Fault
from faults.probe import exec_cmd, exec_ok, member0_cid
from faults.scenario_spec import (
    ScenarioError,
    env_prelude,
    load_scenario,
    scenario_digest,
    scenario_dirs,
)

RESTORED_POLL_INTERVAL_S = 2.0
# The trainer reads `good_fix_hint`; a scripted scenario's fix is the
# thing being learned, so the hint is a no-op that always succeeds.
PLACEHOLDER_HINT: dict[str, Any] = {"action": "exec", "args": ["sh", "-c", "true"]}


class ScriptedFault(Fault):
    id = "scripted"
    modes = ("ubuntu",)
    good_fix_hint = PLACEHOLDER_HINT

    def __init__(self, spec: dict[str, Any], scripts: dict[str, str]) -> None:
        self.spec = spec
        self.scripts = scripts
        self.scenario_id = str(spec["id"])
        self.fault_type = str(spec["fault_type"])
        self.tier = int(spec["tier"])
        self.expose_services = bool(spec["obs"]["expose_services"])
        self.inject_timeout_s = float(spec["inject_timeout_s"])
        self.probe_timeout_s = float(spec["probe_timeout_s"])
        self.restored_poll_s = float(spec["restored_poll_s"])
        self.good_fix_hint = PLACEHOLDER_HINT
        self.digest = scenario_digest(spec, scripts)
        self._prelude = env_prelude(spec)

    def text(self, script: str) -> str:
        """The script as the guest will see it, prelude included."""
        if script not in self.scripts:
            raise KeyError(f"{self.scenario_id}: no script {script!r}")
        return self._prelude + self.scripts[script]

    def _probe(self, cid: int, script: str) -> bool:
        return exec_ok(
            cid, ["sh", "-c", self.text(script)], timeout_s=self.probe_timeout_s
        )

    def inject(self, env: Any, client: Any) -> None:
        _ = client
        cid = member0_cid(env)
        r = exec_cmd(
            cid,
            ["sh", "-c", self.text("inject.sh")],
            timeout_s=self.inject_timeout_s,
        )
        if r["exit_code"] != 0:
            raise RuntimeError(
                f"scenario {self.scenario_id} inject.sh failed: "
                f"exit={r['exit_code']} stderr={r['stderr']!r} "
                f"stdout={r['stdout']!r}"
            )

    def fault_visible(self, env: Any) -> bool:
        try:
            cid = member0_cid(env)
        except RuntimeError:
            # An unreachable member 0 is not a contained fault.
            return True
        return self._probe(cid, "visible.sh")

    def healthy(self, env: Any) -> bool:
        try:
            cid = member0_cid(env)
        except RuntimeError:
            return False
        if self.restored_poll_s <= 0:
            return self._probe(cid, "restored.sh")
        deadline = time.monotonic() + self.restored_poll_s
        while True:
            ok = self._probe(cid, "restored.sh")
            if ok or time.monotonic() >= deadline:
                return ok
            time.sleep(RESTORED_POLL_INTERVAL_S)

    def source_shows_fault(
        self,
        *,
        guest_cids: list[int],
        bridge: str,
        guest_ips: list[str],
    ) -> bool:
        _ = (bridge, guest_ips)
        if not guest_cids:
            return False
        return self._probe(int(guest_cids[0]), "visible.sh")


def load(scenario_dir: Path, *, rel_id: str | None = None) -> ScriptedFault:
    spec, scripts = load_scenario(Path(scenario_dir), rel_id=rel_id)
    return ScriptedFault(spec, scripts)


def registry(root: Path) -> dict[str, ScriptedFault]:
    """Every scenario under `root`. One bad scenario fails gym start."""
    found = scenario_dirs(Path(root))
    if not found:
        raise ScenarioError(f"no scenarios under {root} (GYM_SCENARIO_DIR)")
    out: dict[str, ScriptedFault] = {}
    for rel_id, d in found:
        out[rel_id] = load(d, rel_id=rel_id)
    return out
