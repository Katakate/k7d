#!/usr/bin/env python3
"""Lease/act/score harvest for the four gym-only plots.

*****************************************************************************
THIS DOES NOT TRAIN A MODEL. NO GPU. NO GRPO.

Policies are scripted: `noop` (score after inject) and `oracle`
(apply the fault's good_fix_hint, then score). `--scoreboard playbook`
runs the same 20-page SRE exam on every member.
`--scoreboard incident` peels `relay` until a soak stays clean
(`R = 1 - t_solve/T`). Rows are
eval_kind=gym-scripted with a live_run_id. The renderer stamps

    LIVE GYM EVAL <id> -- NOT A TRAINED POLICY

There is no learning curve. Default scoreboard is `health`.
`--scoreboard tetragon` requires pinned helm and installs
Cilium+Tetragon on the Ubuntu gym source. See README.md.
*****************************************************************************
"""

from __future__ import annotations

import argparse
import json
import os
import signal
import subprocess
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any

_GYM = Path(__file__).resolve().parents[1]
_REPO = _GYM.parent
if str(_GYM) not in sys.path:
    sys.path.insert(0, str(_GYM))

from plots.common import load_jsonl  # noqa: E402
from plots.render import render  # noqa: E402


def _http(method: str, url: str, body: dict[str, Any] | None = None) -> dict[str, Any]:
    data = None if body is None else json.dumps(body).encode()
    req = urllib.request.Request(
        url,
        data=data,
        method=method,
        headers={"Content-Type": "application/json"} if data else {},
    )
    try:
        # Reset n=2 is two Ubuntu bring-ups in one /lease; each can
        # take CLUSTER_READY_S (600s). Do not silently shrink n.
        with urllib.request.urlopen(req, timeout=3600) as resp:
            raw = resp.read().decode()
    except urllib.error.HTTPError as e:
        detail = e.read().decode() if e.fp else ""
        raise RuntimeError(f"{method} {url}: HTTP {e.code}: {detail}") from e
    rec = json.loads(raw) if raw.strip() else {}
    if not isinstance(rec, dict):
        raise RuntimeError(f"{method} {url}: expected object, got {type(rec)}")
    return rec


def wait_healthz(base: str, timeout_s: float) -> None:
    deadline = time.time() + timeout_s
    last = ""
    while time.time() < deadline:
        try:
            rec = _http("GET", f"{base}/healthz")
            if rec.get("ok") and rec.get("k7d") == "ready":
                return
            last = json.dumps(rec)
        except (RuntimeError, urllib.error.URLError, TimeoutError, OSError) as e:
            last = str(e)
        time.sleep(2)
    raise RuntimeError(f"gym {base} not ready after {timeout_s}s: {last}")


class GymProc:
    def __init__(self, log: Path, *argv: str, env: dict[str, str]) -> None:
        self.log = log
        env = dict(env)
        env["PYTHONUNBUFFERED"] = "1"
        self.proc = subprocess.Popen(
            [sys.executable, "-u", str(_GYM / "server.py"), *argv],
            cwd=str(_REPO),
            env=env,
            stdout=self.log.open("w"),
            stderr=subprocess.STDOUT,
        )

    def wait_dead(self, timeout_s: float = 60) -> None:
        try:
            self.proc.wait(timeout=timeout_s)
        except subprocess.TimeoutExpired:
            self.proc.kill()
            self.proc.wait(timeout=10)

    def stop(self) -> None:
        if self.proc.poll() is not None:
            return
        self.proc.send_signal(signal.SIGTERM)
        self.wait_dead()


def gym_env(
    port: int, start_mode: str, tree_id: str, scoreboard: str | None = None
) -> dict[str, str]:
    env = os.environ.copy()
    sb = scoreboard or os.environ.get("GYM_SCOREBOARD", "health")
    env.update(
        {
            "GYM_SOURCE_MODE": "ubuntu",
            "GYM_START_MODE": start_mode,
            "GYM_SCOREBOARD": sb,
            "GYM_MEMORY_MB": os.environ.get("GYM_MEMORY_MB", "2048"),
            "GYM_MAX_LIVE_VMS": os.environ.get("GYM_MAX_LIVE_VMS", "64"),
            "GYM_MAX_LEASES": "4",
            "GYM_K7D_TIMEOUT_S": os.environ.get("GYM_K7D_TIMEOUT_S", "300"),
            "GYM_BIND": "127.0.0.1",
            "GYM_PORT": str(port),
            "GYM_SOURCE_TREE_ID": tree_id,
        }
    )
    if start_mode == "reset":
        env["GYM_RESET_MEASUREMENT"] = "1"
    if sb in ("playbook", "incident"):
        env["GYM_READY_GATE"] = "api"
    return env


def _miner_running(base: str, env_id: str) -> bool:
    """Running `app=node-agent` via guest kubectl. Loud on exec failure."""
    from faults.relay import RELAY_MINER

    rec = _http(
        "POST",
        f"{base}/env/{env_id}/act",
        {
            "action": "exec",
            "args": [
                "k3s",
                "kubectl",
                "get",
                "pods",
                "-n",
                "default",
                "-l",
                f"app={RELAY_MINER}",
                "--field-selector=status.phase=Running",
                "--no-headers",
            ],
            "timeout_s": 20,
        },
    )
    if not rec.get("ok"):
        raise RuntimeError(f"miner probe failed on {env_id}: {rec}"[:240])
    return bool((rec.get("stdout") or "").strip())


def apply_hint(
    base: str, env_id: str, hint: dict[str, Any], timeout_s: float
) -> dict[str, Any]:
    if not isinstance(hint, dict) or "action" not in hint:
        raise RuntimeError(f"hint missing action: {hint!r}"[:240])
    body = {
        "action": hint["action"],
        "args": list(hint.get("args") or []),
        "timeout_s": timeout_s,
    }
    return _http("POST", f"{base}/env/{env_id}/act", body)


def apply_oracle(base: str, lease: dict[str, Any], timeout_s: float) -> None:
    hint = lease.get("good_fix_hint")
    if not isinstance(hint, dict) or "action" not in hint:
        raise RuntimeError(f"lease missing good_fix_hint: {lease!r}"[:240])
    env0 = next((e for e in lease["envs"] if int(e["index"]) == 0), None)
    if env0 is None:
        raise RuntimeError("lease missing env index 0")
    rec = apply_hint(base, env0["env_id"], hint, timeout_s)
    if not rec.get("ok"):
        raise RuntimeError(f"oracle act failed: {rec}")
    args = list(hint.get("args") or [])
    # Blind 20s sleep was the tetra3 oracle tax. Only poll when
    # the hint actually restarts the apiserver.
    if args[:2] == ["systemctl", "start"]:
        _wait_unit_active(base, env0["env_id"], args[-1], timeout_s)


def _wait_unit_active(
    base: str, env_id: str, unit: str, timeout_s: float
) -> None:
    deadline = time.time() + max(1.0, timeout_s)
    last = ""
    while time.time() < deadline:
        rec = _http(
            "POST",
            f"{base}/env/{env_id}/act",
            {
                "action": "exec",
                "args": ["systemctl", "is-active", unit],
                "timeout_s": 8,
            },
        )
        last = rec.get("stdout") or rec.get("stderr") or ""
        if rec.get("ok") and "active" in last.split():
            return
        time.sleep(1)
    raise RuntimeError(f"oracle {unit} never active: {last}")


def _record_image(base: str, lease: dict[str, Any]) -> dict[str, str]:
    env0 = next((e for e in lease["envs"] if int(e["index"]) == 0), None)
    if env0 is None:
        raise RuntimeError("lease missing env index 0 for crictl images")
    rec = _http(
        "POST",
        f"{base}/env/{env0['env_id']}/act",
        {
            "action": "exec",
            "args": ["k3s", "crictl", "images", "--digests"],
            "timeout_s": 20,
        },
    )
    text = (rec.get("stdout") or "") + (rec.get("stderr") or "")
    from playbook import PINNED_IMAGE, discover_pinned_image

    def _exec(_cid: int, _args: list[str], _t: float = 20) -> dict[str, Any]:
        return {
            "exit_code": 0 if rec.get("ok") else 1,
            "stdout": rec.get("stdout") or "",
            "stderr": rec.get("stderr") or "",
        }

    pin = discover_pinned_image(_exec, 0)
    print(
        f"pinned image name={pin['name']} digest={pin.get('digest')!r}",
        flush=True,
    )
    _ = (PINNED_IMAGE, text)
    return pin


def one_playbook_group(
    *,
    base: str,
    start_mode: str,
    n: int,
    group_id: str,
    live_run_id: str,
    ttl_s: float,
    turns: int,
) -> list[dict[str, Any]]:
    """Same page on every member each turn. No env0-only inject."""
    from playbook import require_playbook_payload

    t0 = time.perf_counter()
    lease = _http(
        "POST",
        f"{base}/lease",
        {"fault_id": "none", "n": n, "group_id": group_id, "ttl_s": ttl_s},
    )
    rows: list[dict[str, Any]] = []
    try:
        pin = _record_image(base, lease)
        envs = sorted(lease["envs"], key=lambda e: int(e["index"]))
        if len(envs) != n:
            raise RuntimeError(f"{group_id}: leased {len(envs)} envs, want {n}")
        for turn in range(1, turns + 1):
            for e in envs:
                act = _http(
                    "POST",
                    f"{base}/env/{e['env_id']}/act",
                    {
                        "action": "playbook",
                        "args": [str(turn)],
                        "timeout_s": 45,
                    },
                )
                print(
                    f"  {group_id} member={e['index']} turn={turn} "
                    f"ok={act.get('ok')} {act.get('stdout', '')[:80]}",
                    flush=True,
                )
            scored = _http(
                "POST",
                f"{base}/lease/{lease['lease_id']}/score",
                {"turn": turn},
            )
            wall_s = time.perf_counter() - t0
            chunk = scored.get("scores") or []
            if len(chunk) != n:
                raise RuntimeError(
                    f"{group_id} turn={turn}: expected {n} scores, got {len(chunk)}"
                )
            for i, row in enumerate(chunk):
                require_playbook_payload(row)
                rec: dict[str, Any] = {
                    "kind": "episode",
                    "eval_kind": "gym-scripted",
                    "live_run_id": live_run_id,
                    "start_mode": start_mode,
                    "checkpoint": "playbook",
                    "fault_id": "none",
                    "group_id": group_id,
                    "member": i,
                    "reward": float(row["reward"]),
                    "terms": row.get("terms"),
                    "wall_s": wall_s,
                    "step": turn,
                    "turn": turn,
                    "scoreboard": "playbook",
                    "playbook": row["playbook"],
                    "image": pin.get("name"),
                    "image_digest": pin.get("digest"),
                }
                rows.append(rec)
        return rows
    finally:
        try:
            _http("POST", f"{base}/lease/{lease['lease_id']}/release", {})
        except RuntimeError as e:
            print(f"release {lease.get('lease_id')}: {e}", file=sys.stderr)


def one_incident_group(
    *,
    base: str,
    start_mode: str,
    checkpoint: str,
    n: int,
    group_id: str,
    fault_id: str,
    live_run_id: str,
    ttl_s: float,
    turns: int,
) -> list[dict[str, Any]]:
    """Same remediating act + soak on every member each turn."""
    from soak import (
        SOAK_S,
        require_incident_fault,
        require_incident_payload,
        wait_miner_absent,
    )
    from faults.relay import shallow_fix_hint

    require_incident_fault(fault_id)
    t0 = time.perf_counter()
    lease = _http(
        "POST",
        f"{base}/lease",
        {"fault_id": fault_id, "n": n, "group_id": group_id, "ttl_s": ttl_s},
    )
    rows: list[dict[str, Any]] = []
    try:
        pin = _record_image(base, lease)
        envs = sorted(lease["envs"], key=lambda e: int(e["index"]))
        if len(envs) != n:
            raise RuntimeError(f"{group_id}: leased {len(envs)} envs, want {n}")
        if checkpoint == "oracle":
            hint = lease.get("good_fix_hint")
            if not isinstance(hint, dict) or "action" not in hint:
                raise RuntimeError(f"lease missing good_fix_hint: {lease!r}"[:240])
        elif checkpoint == "shallow":
            hint = shallow_fix_hint()
        else:
            raise ValueError(
                f"incident checkpoint must be oracle|shallow, got {checkpoint!r}"
            )
        for turn in range(1, turns + 1):
            for e in envs:
                act_t0 = time.perf_counter()
                rem = apply_hint(base, e["env_id"], hint, timeout_s=60)
                # kubectl delete returns before the pod leaves Running
                # (CHALLENGES #173). t_solve includes this wait — it is
                # remediation wall time, not a sleep.
                gone = wait_miner_absent(
                    lambda eid=e["env_id"]: _miner_running(base, eid)
                )
                t_solve = time.perf_counter() - act_t0
                print(
                    f"  {group_id} member={e['index']} turn={turn} "
                    f"ckpt={checkpoint} peel_ok={rem.get('ok')} "
                    f"miner_gone={gone} t_solve={t_solve:.2f}s",
                    flush=True,
                )
                soak = _http(
                    "POST",
                    f"{base}/env/{e['env_id']}/act",
                    {
                        "action": "incident",
                        "args": [str(turn)],
                        "t_solve_s": t_solve,
                        "timeout_s": SOAK_S + 90,
                    },
                )
                print(
                    f"  {group_id} member={e['index']} turn={turn} "
                    f"soak={soak.get('ok')} {soak.get('stdout', '')[:80]}",
                    flush=True,
                )
            scored = _http(
                "POST",
                f"{base}/lease/{lease['lease_id']}/score",
                {"turn": turn},
            )
            wall_s = time.perf_counter() - t0
            chunk = scored.get("scores") or []
            if len(chunk) != n:
                raise RuntimeError(
                    f"{group_id} turn={turn}: expected {n} scores, got {len(chunk)}"
                )
            for i, row in enumerate(chunk):
                require_incident_payload(row)
                rec: dict[str, Any] = {
                    "kind": "episode",
                    "eval_kind": "gym-scripted",
                    "live_run_id": live_run_id,
                    "start_mode": start_mode,
                    "checkpoint": checkpoint,
                    "fault_id": fault_id,
                    "group_id": group_id,
                    "member": i,
                    "reward": float(row["reward"]),
                    "terms": row.get("terms"),
                    "wall_s": wall_s,
                    "step": turn,
                    "turn": turn,
                    "scoreboard": "incident",
                    "incident": row["incident"],
                    "image": pin.get("name"),
                    "image_digest": pin.get("digest"),
                }
                rows.append(rec)
        return rows
    finally:
        try:
            _http("POST", f"{base}/lease/{lease['lease_id']}/release", {})
        except RuntimeError as e:
            print(f"release {lease.get('lease_id')}: {e}", file=sys.stderr)


BLUE_CHECKPOINTS = ("oracle", "shallow")
RED_CHECKPOINTS = ("catalog", "noop")
PAYLOAD_WAIT_S = 60.0


def _payload_productive(base: str, env_id: str) -> bool:
    """Poll: miner Running AND burning CPU over a short window. The relay
    miner forks a fresh sha256sum each iteration, so instantaneous %cpu
    misses the children; the parent reaps them, so utime+stime+cutime+
    cstime over the window captures the real burn."""
    from faults.relay import RELAY_MINER

    probe = (
        "k3s kubectl get pods -n default -l app="
        f"{RELAY_MINER} --field-selector=status.phase=Running "
        "--no-headers 2>/dev/null | grep -q . || exit 1\n"
        "read_j() { tot=0; for p in $(pgrep -f /tmp/nodecheck 2>/dev/null); do "
        "st=$(cat /proc/$p/stat 2>/dev/null) || continue; rest=${st#*) }; "
        "set -- $rest; tot=$((tot + ${12} + ${13} + ${14} + ${15})); done; "
        'echo "$tot"; }\n'
        "a=$(read_j); sleep 4; b=$(read_j); "
        "hz=$(getconf CLK_TCK); "
        "awk -v d=$((b - a)) -v hz=$hz 'BEGIN{exit !((100.0*d/hz/4.0)>=2.0)}'"
    )
    rec = _http(
        "POST",
        f"{base}/env/{env_id}/act",
        {"action": "exec", "args": ["sh", "-c", probe], "timeout_s": 20},
    )
    return bool(rec.get("ok"))


def _red_plant_script() -> str:
    """The scripted red opening as one living-off-the-land shell: apply
    the miner Deployment, then plant the systemd reseed chain. Red runs
    this through its node-exec foothold (no egress fetch)."""
    from incidents_load import incidents_mod

    relay = incidents_mod().CATALOG["relay"]
    return (
        "cat >/tmp/k7-red-open.yaml <<'EOFRED'\n"
        f"{relay.yaml}"
        "EOFRED\n"
        "k3s kubectl apply -f /tmp/k7-red-open.yaml && "
        f"{relay.plant_script()}"
    )


def one_selfplay_group(
    *,
    base: str,
    start_mode: str,
    role: str,
    scenario_id: str,
    checkpoint: str,
    n: int,
    group_id: str,
    live_run_id: str,
    ttl_s: float,
    turns: int,
) -> list[dict[str, Any]]:
    """One self-play group: fork the settled opponent, run the on-trial
    policy on every member each turn, soak, and score the signed reward.

    Blue on trial: settle branch is planted (scripted red); blue peels
    (oracle=full, shallow=layer-1). Red on trial: settle branch is a
    defended clean baseline; red plants from its foothold (catalog=full
    chain, noop=nothing → fails payload_productive).
    """
    from soak import SOAK_S, require_selfplay_payload, wait_miner_absent
    from faults.relay import shallow_fix_hint

    if role not in ("blue", "red"):
        raise ValueError(f"selfplay role must be blue|red, got {role!r}")
    if role == "blue" and checkpoint not in BLUE_CHECKPOINTS:
        raise ValueError(f"blue checkpoint must be {BLUE_CHECKPOINTS}, got {checkpoint!r}")
    if role == "red" and checkpoint not in RED_CHECKPOINTS:
        raise ValueError(f"red checkpoint must be {RED_CHECKPOINTS}, got {checkpoint!r}")

    t0 = time.perf_counter()
    lease = _http(
        "POST",
        f"{base}/lease",
        {
            "role": role,
            "scenario_id": scenario_id,
            "n": n,
            "group_id": group_id,
            "ttl_s": ttl_s,
        },
    )
    rows: list[dict[str, Any]] = []
    try:
        pin = _record_image(base, lease)
        envs = sorted(lease["envs"], key=lambda e: int(e["index"]))
        if len(envs) != n:
            raise RuntimeError(f"{group_id}: leased {len(envs)} envs, want {n}")
        blue_hint = None
        if role == "blue":
            if checkpoint == "oracle":
                blue_hint = lease.get("good_fix_hint")
                if not isinstance(blue_hint, dict) or "action" not in blue_hint:
                    raise RuntimeError(f"lease missing good_fix_hint: {lease!r}"[:240])
            else:
                blue_hint = shallow_fix_hint()
        for turn in range(1, turns + 1):
            for e in envs:
                act_t0 = time.perf_counter()
                if role == "blue":
                    apply_hint(base, e["env_id"], blue_hint, timeout_s=60)
                    wait_miner_absent(
                        lambda eid=e["env_id"]: _miner_running(base, eid)
                    )
                    t_solve = time.perf_counter() - act_t0
                else:
                    if checkpoint == "catalog":
                        rem = _http(
                            "POST",
                            f"{base}/env/{e['env_id']}/act",
                            {
                                "action": "exec",
                                "args": ["sh", "-c", _red_plant_script()],
                                "timeout_s": 90,
                            },
                        )
                        if not rem.get("ok"):
                            raise RuntimeError(
                                f"red catalog plant failed on {e['env_id']}: "
                                f"{rem}"[:240]
                            )
                        # Wait until the payload is actually productive.
                        deadline = time.time() + PAYLOAD_WAIT_S
                        while time.time() < deadline:
                            if _payload_productive(base, e["env_id"]):
                                break
                            time.sleep(2)
                    t_solve = time.perf_counter() - act_t0
                soak = _http(
                    "POST",
                    f"{base}/env/{e['env_id']}/act",
                    {
                        "action": "selfplay",
                        "args": [str(turn)],
                        "t_solve_s": t_solve,
                        "timeout_s": SOAK_S + 90,
                    },
                )
                sp = soak.get("selfplay") or {}
                print(
                    f"  {group_id} member={e['index']} turn={turn} "
                    f"role={role} ckpt={checkpoint} clean={sp.get('soak_clean')} "
                    f"victim={sp.get('victim_ready')} "
                    f"payload={sp.get('payload_productive')} t_solve={t_solve:.2f}s",
                    flush=True,
                )
            scored = _http(
                "POST",
                f"{base}/lease/{lease['lease_id']}/score",
                {"turn": turn},
            )
            wall_s = time.perf_counter() - t0
            chunk = scored.get("scores") or []
            if len(chunk) != n:
                raise RuntimeError(
                    f"{group_id} turn={turn}: expected {n} scores, got {len(chunk)}"
                )
            for i, row in enumerate(chunk):
                require_selfplay_payload(row)
                rec: dict[str, Any] = {
                    "kind": "episode",
                    "eval_kind": "gym-scripted",
                    "live_run_id": live_run_id,
                    "start_mode": start_mode,
                    "checkpoint": checkpoint,
                    "fault_id": lease.get("fault_id"),
                    "group_id": group_id,
                    "member": i,
                    "reward": float(row["reward"]),
                    "terms": row.get("terms"),
                    "wall_s": wall_s,
                    "step": turn,
                    "turn": turn,
                    "scoreboard": "selfplay",
                    "role": role,
                    "scenario_id": scenario_id,
                    "selfplay": row["selfplay"],
                    "image": pin.get("name"),
                    "image_digest": pin.get("digest"),
                }
                rows.append(rec)
        return rows
    finally:
        try:
            _http("POST", f"{base}/lease/{lease['lease_id']}/release", {})
        except RuntimeError as e:
            print(f"release {lease.get('lease_id')}: {e}", file=sys.stderr)


def one_reset_selfplay_group(
    *,
    base: str,
    role: str,
    scenario_id: str,
    checkpoint: str,
    n: int,
    group_id: str,
    live_run_id: str,
    ttl_s: float,
    turns: int,
) -> list[dict[str, Any]]:
    """Sequential n=1 reset leases. Two live Cilium clusters collide on
    10.200.0.1 (CHALLENGES #149); keep n, never silently shrink (#154)."""
    if n < 2:
        raise ValueError(f"reset selfplay group needs n>=2, got {n}")
    print(
        f"{group_id}: sequential n=1 reset selfplay leases (Cilium, "
        f"CHALLENGES #149); keeping n={n}, not shrinking",
        flush=True,
    )
    rows: list[dict[str, Any]] = []
    for i in range(n):
        part = one_selfplay_group(
            base=base,
            start_mode="reset",
            role=role,
            scenario_id=scenario_id,
            checkpoint=checkpoint,
            n=1,
            group_id=f"{group_id}-p{i}",
            live_run_id=live_run_id,
            ttl_s=ttl_s,
            turns=turns,
        )
        for rec in part:
            rec["group_id"] = group_id
            rec["member"] = i
            rows.append(rec)
    members = {r["member"] for r in rows}
    if members != set(range(n)):
        raise RuntimeError(
            f"{group_id}: expected members 0..{n-1}, got {sorted(members)} "
            "(do not silently shrink n — CHALLENGES #154)"
        )
    return rows


def one_group(
    *,
    base: str,
    start_mode: str,
    checkpoint: str,
    n: int,
    group_id: str,
    fault_id: str,
    live_run_id: str,
    ttl_s: float,
    scoreboard: str,
    turns: int = 1,
    role: str = "",
    scenario_id: str = "",
) -> list[dict[str, Any]]:
    if scoreboard == "playbook":
        return one_playbook_group(
            base=base,
            start_mode=start_mode,
            n=n,
            group_id=group_id,
            live_run_id=live_run_id,
            ttl_s=ttl_s,
            turns=turns,
        )
    if scoreboard == "incident":
        return one_incident_group(
            base=base,
            start_mode=start_mode,
            checkpoint=checkpoint,
            n=n,
            group_id=group_id,
            fault_id=fault_id,
            live_run_id=live_run_id,
            ttl_s=ttl_s,
            turns=turns,
        )
    if scoreboard == "selfplay":
        return one_selfplay_group(
            base=base,
            start_mode=start_mode,
            role=role,
            scenario_id=scenario_id,
            checkpoint=checkpoint,
            n=n,
            group_id=group_id,
            live_run_id=live_run_id,
            ttl_s=ttl_s,
            turns=turns,
        )
    t0 = time.perf_counter()
    lease = _http(
        "POST",
        f"{base}/lease",
        {"fault_id": fault_id, "n": n, "group_id": group_id, "ttl_s": ttl_s},
    )
    try:
        if checkpoint == "oracle":
            apply_oracle(base, lease, timeout_s=45)
        elif checkpoint != "noop":
            raise ValueError(f"checkpoint must be noop|oracle, got {checkpoint!r}")
        scored = _http("POST", f"{base}/lease/{lease['lease_id']}/score")
        wall_s = time.perf_counter() - t0
        rows = []
        for i, row in enumerate(scored.get("scores") or []):
            if scoreboard == "tetragon" and "event_diff" not in row:
                raise RuntimeError(
                    f"{group_id} member {i}: tetragon score missing event_diff"
                )
            rec = {
                "kind": "episode",
                "eval_kind": "gym-scripted",
                "live_run_id": live_run_id,
                "start_mode": start_mode,
                "checkpoint": checkpoint,
                "fault_id": fault_id,
                "group_id": group_id,
                "member": i,
                "reward": float(row["reward"]),
                "terms": row.get("terms"),
                "wall_s": wall_s,
                "step": 0,
                "scoreboard": scored.get("scoreboard") or scoreboard,
            }
            if "event_diff" in row:
                rec["event_diff"] = row["event_diff"]
            rows.append(rec)
        if len(rows) != n:
            raise RuntimeError(
                f"{group_id}: expected {n} scored members, got {len(rows)}"
            )
        return rows
    finally:
        try:
            _http("POST", f"{base}/lease/{lease['lease_id']}/release", {})
        except RuntimeError as e:
            print(f"release {lease.get('lease_id')}: {e}", file=sys.stderr)


def one_reset_incident_group(
    *,
    base: str,
    checkpoint: str,
    n: int,
    group_id: str,
    fault_id: str,
    live_run_id: str,
    ttl_s: float,
    turns: int,
) -> list[dict[str, Any]]:
    """Sequential n=1 leases. Two live Cilium clusters collide on
    10.200.0.1 (CHALLENGES #149). Plant relay on every member. Never
    silently shrink n (CHALLENGES #154)."""
    if n < 2:
        raise ValueError(f"reset incident group needs n>=2, got {n}")
    print(
        f"{group_id}: sequential n=1 reset leases (Cilium, CHALLENGES #149); "
        f"keeping n={n}, not shrinking",
        flush=True,
    )
    rows: list[dict[str, Any]] = []
    for i in range(n):
        part = one_incident_group(
            base=base,
            start_mode="reset",
            checkpoint=checkpoint,
            n=1,
            group_id=f"{group_id}-p{i}",
            fault_id=fault_id,
            live_run_id=live_run_id,
            ttl_s=ttl_s,
            turns=turns,
        )
        for rec in part:
            rec["group_id"] = group_id
            rec["member"] = i
            rec["fault_id"] = fault_id
            rows.append(rec)
    members = {r["member"] for r in rows}
    if members != set(range(n)):
        raise RuntimeError(
            f"{group_id}: expected members 0..{n-1}, got {sorted(members)} "
            "(do not silently shrink n — CHALLENGES #154)"
        )
    return rows


def one_reset_tetragon_group(
    *,
    base: str,
    checkpoint: str,
    n: int,
    group_id: str,
    fault_id: str,
    live_run_id: str,
    ttl_s: float,
) -> list[dict[str, Any]]:
    """One cluster at a time. Two live reset guests both use 10.200.0.1
    and the second Cilium never Ready (CHALLENGES #149)."""
    if n < 2:
        raise ValueError(f"reset tetragon group needs n>=2, got {n}")
    rows: list[dict[str, Any]] = []
    for i in range(n):
        fid = fault_id if i == 0 else "none"
        part = one_group(
            base=base,
            start_mode="reset",
            checkpoint=checkpoint,
            n=1,
            group_id=f"{group_id}-p{i}",
            fault_id=fid,
            live_run_id=live_run_id,
            ttl_s=ttl_s,
            scoreboard="tetragon",
        )
        rec = part[0]
        rec["group_id"] = group_id
        rec["member"] = i
        rec["fault_id"] = fault_id
        rows.append(rec)
    return rows


def run_arm(
    *,
    start_mode: str,
    port: int,
    tree_id: str,
    n: int,
    groups: int,
    checkpoints: list[str],
    fault_id: str,
    live_run_id: str,
    ttl_s: float,
    scoreboard: str,
    log_dir: Path,
    skip_groups: set[str] | None = None,
    emit: Any | None = None,
    turns: int = 1,
    role: str = "",
    scenario_id: str = "",
) -> list[dict[str, Any]]:
    base = f"http://127.0.0.1:{port}"
    log = log_dir / f"gym-{start_mode}.log"
    extra = ["--reset-measurement"] if start_mode == "reset" else []
    if scoreboard in ("playbook", "incident", "selfplay"):
        extra.extend(["--ready-gate", "api"])
    proc = GymProc(
        log,
        "--source-mode",
        "ubuntu",
        "--start-mode",
        start_mode,
        "--scoreboard",
        scoreboard,
        "--memory-mb",
        os.environ.get("GYM_MEMORY_MB", "2048"),
        "--port",
        str(port),
        "--source-tree-id",
        tree_id,
        *extra,
        env=gym_env(port, start_mode, tree_id, scoreboard),
    )
    try:
        wait_healthz(base, timeout_s=700)
        rows: list[dict[str, Any]] = []
        for ckpt in checkpoints:
            for g in range(groups):
                gid = f"{live_run_id}-{start_mode}-{ckpt}-g{g}"
                if skip_groups and gid in skip_groups:
                    print(f"skip {gid} (already in jsonl)", flush=True)
                    continue
                print(f"harvest {gid} n={n}", flush=True)
                if start_mode == "reset" and scoreboard == "incident":
                    chunk = one_reset_incident_group(
                        base=base,
                        checkpoint=ckpt,
                        n=n,
                        group_id=gid,
                        fault_id=fault_id,
                        live_run_id=live_run_id,
                        ttl_s=ttl_s,
                        turns=turns,
                    )
                elif start_mode == "reset" and scoreboard == "selfplay":
                    chunk = one_reset_selfplay_group(
                        base=base,
                        role=role,
                        scenario_id=scenario_id,
                        checkpoint=ckpt,
                        n=n,
                        group_id=gid,
                        live_run_id=live_run_id,
                        ttl_s=ttl_s,
                        turns=turns,
                    )
                elif start_mode == "reset" and scoreboard == "tetragon":
                    chunk = one_reset_tetragon_group(
                        base=base,
                        checkpoint=ckpt,
                        n=n,
                        group_id=gid,
                        fault_id=fault_id,
                        live_run_id=live_run_id,
                        ttl_s=ttl_s,
                    )
                else:
                    chunk = one_group(
                        base=base,
                        start_mode=start_mode,
                        checkpoint=ckpt,
                        n=n,
                        group_id=gid,
                        fault_id=fault_id,
                        live_run_id=live_run_id,
                        ttl_s=ttl_s,
                        scoreboard=scoreboard,
                        turns=turns,
                        role=role,
                        scenario_id=scenario_id,
                    )
                rows.extend(chunk)
                if emit is not None:
                    emit(chunk)
        return rows
    except Exception:
        print(f"gym log {log}:\n{log.read_text()[-4000:]}", file=sys.stderr)
        raise
    finally:
        proc.stop()


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--out", type=Path, required=True)
    p.add_argument("--live-run-id", default=time.strftime("gym-%Y%m%d-%H%M%S"))
    p.add_argument("--fault-id", default="kill-member-0")
    p.add_argument("--fork-n", type=int, default=8)
    p.add_argument(
        "--reset-n",
        type=int,
        default=8,
        help="reset group size. Must equal --fork-n. Tetragon reset "
        "is sequential n=1 leases (CHALLENGES #149); do not subsample.",
    )
    p.add_argument("--groups", type=int, default=2)
    p.add_argument(
        "--turns",
        type=int,
        default=1,
        help="playbook pages or incident remediating turns. "
        "Health/tetragon stay 1.",
    )
    p.add_argument("--port", type=int, default=18080)
    p.add_argument("--ttl-s", type=float, default=1800)
    p.add_argument("--scoreboard", default=os.environ.get("GYM_SCOREBOARD", "health"))
    p.add_argument(
        "--role",
        choices=("blue", "red"),
        help="selfplay role on trial. Required for "
        "--scoreboard selfplay; the frozen opponent is scripted.",
    )
    p.add_argument(
        "--scenario",
        default="relay-foothold",
        help="selfplay scenario id (payload + foothold + victim)",
    )
    p.add_argument(
        "--only-arm",
        choices=("fork", "reset", "both"),
        default="both",
    )
    p.add_argument(
        "--append-jsonl",
        type=Path,
        help="existing gym-scripted JSONL to extend (same live_run_id)",
    )
    return p.parse_args(argv)


# MCP smoke leftover held 10.200.0.1 and hung later Cilium pulls
# (CHALLENGES #150). Harvest must reap it, not only gym-src-eval-*.
REAP_PREFIXES = ("gym-rst-", "k7mcp-smoke-")
GATEWAY_IP = "10.200.0.1"
DISKS_DIR = Path("/var/lib/k7d/disks")
# One 3-node reset + Cilium extract. 96G XFS at 2G free → guest EIO.
MIN_DISKS_FREE = 12 * 1024**3


def should_reap_tree(tid: str, prefix: str = "gym-src-eval-") -> bool:
    return tid.startswith(prefix) or any(tid.startswith(p) for p in REAP_PREFIXES)


def bridges_holding_gateway() -> list[str]:
    from host import list_bridges

    held: list[str] = []
    for br in sorted(list_bridges()):
        r = subprocess.run(
            ["ip", "-br", "addr", "show", "dev", br],
            check=False,
            capture_output=True,
            text=True,
        )
        if GATEWAY_IP in (r.stdout or ""):
            held.append(br)
    return held


def _reap_one_tree(client: Any, tid: str) -> None:
    print(f"drop leftover {tid}", flush=True)
    try:
        nodes = client.tree_nodes(tid).get("nodes") or []
        if any(n.get("id") == "root" for n in nodes):
            try:
                client.tree_unprotect(tid, "root")
            except RuntimeError:
                pass
            client.tree_prune(tid, "root")
        client.tree_drop(tid)
    except RuntimeError as e:
        print(f"  drop {tid}: {e}", flush=True)


def drop_eval_trees(prefix: str = "gym-src-eval-") -> None:
    """Drop leftover harvest / MCP sources so 10.200.0.2 is not taken.

    Also stop orphan create_vm guests (no tree, no sandbox_id). A killed
    harvest can leave those on the TAP; host kubectl then hits the wrong
    10.200.0.2 (CHALLENGES #144) and `make check` Ubuntu smoke fails x509.
    A leftover `k7mcp-smoke-*` bridge holding 10.200.0.1 hangs the next
    Cilium pull (CHALLENGES #150).
    """
    sys.path.insert(0, str(_REPO / "examples" / "cluster-tree-search"))
    from host import k7_bridge_name  # noqa: E402
    from k7d_client import K7dClient  # noqa: E402

    client = K7dClient()
    listed = client.tree_list()
    trees = listed.get("trees") or []
    for t in trees:
        tid = t.get("tree_id") if isinstance(t, dict) else t
        if not isinstance(tid, str) or not should_reap_tree(tid, prefix):
            continue
        _reap_one_tree(client, tid)
    leftover = client.tree_list().get("trees") or []
    held = bridges_holding_gateway()
    if held:
        for t in leftover:
            tid = t.get("tree_id") if isinstance(t, dict) else t
            if not isinstance(tid, str):
                continue
            if k7_bridge_name(tid) in held:
                _reap_one_tree(client, tid)
        held = bridges_holding_gateway()
        if held:
            raise SystemExit(
                f"{GATEWAY_IP} still on {held} after leftover drop "
                "(CHALLENGES #150); not starting harvest"
            )
    leftover = client.tree_list().get("trees") or []
    if not leftover:
        for vm in client.list_vms().get("vms") or []:
            if not isinstance(vm, dict) or vm.get("sandbox_id"):
                continue
            vid = vm.get("vm_id")
            if not isinstance(vid, str):
                continue
            print(f"stop leftover orphan {vid}", flush=True)
            try:
                client.stop_vm(vid)
            except RuntimeError as e:
                print(f"  stop {vid}: {e}", flush=True)
    reap_leftover_gym_disks()
    from ubuntu import prune_unused_base_images

    pruned = prune_unused_base_images()
    if pruned:
        print(f"pruned {pruned} unused ubuntu base-image files", flush=True)
    assert_disks_headroom()


def reap_leftover_gym_disks(disks_dir: Path | None = None) -> int:
    """Unlink leftover `ubuntu-gym-*.img`. Reset release used to leave them."""
    d = disks_dir or DISKS_DIR
    if not d.is_dir():
        return 0
    n = 0
    for p in sorted(d.glob("ubuntu-gym-*.img")):
        print(f"unlink leftover disk {p}", flush=True)
        try:
            p.unlink()
            n += 1
        except OSError as e:
            print(f"  unlink {p}: {e}", flush=True)
    return n


def assert_disks_headroom(disks_dir: Path | None = None, need: int = MIN_DISKS_FREE) -> None:
    d = disks_dir or DISKS_DIR
    if not d.is_dir():
        raise SystemExit(f"reflink XFS missing at {d}")
    st = os.statvfs(d)
    got = st.f_bavail * st.f_frsize
    if got < need:
        raise SystemExit(
            f"{d} has {got} free, need {need} "
            "(leftover ubuntu-gym-*.img fill the 96G XFS; guest "
            "crictl pull then EIO — CHALLENGES #151)"
        )


def main(argv: list[str] | None = None) -> int:
    ns = parse_args(argv)
    if ns.scoreboard == "playbook":
        from playbook import refuse_inject_fault

        refuse_inject_fault(ns.fault_id)
        if ns.turns < 1:
            raise SystemExit(f"--turns must be >= 1, got {ns.turns}")
    elif ns.scoreboard == "incident":
        from soak import require_incident_fault

        require_incident_fault(ns.fault_id)
        if ns.turns < 1:
            raise SystemExit(f"--turns must be >= 1, got {ns.turns}")
    elif ns.scoreboard == "selfplay":
        from red import get_scenario
        from soak import require_selfplay_role

        if not ns.role:
            raise SystemExit("--scoreboard selfplay requires --role blue|red")
        require_selfplay_role(ns.role)
        get_scenario(ns.scenario)  # loud if unknown
        if ns.turns < 1:
            raise SystemExit(f"--turns must be >= 1, got {ns.turns}")
    elif ns.turns != 1:
        raise SystemExit(
            f"--turns {ns.turns} is playbook/incident-only; "
            f"scoreboard={ns.scoreboard} stays one poke"
        )
    if ns.fork_n != ns.reset_n and ns.only_arm == "both":
        raise SystemExit(
            f"--fork-n {ns.fork_n} != --reset-n {ns.reset_n}: "
            "headline std is not comparable; harvest the same n "
            "(reset is sequential, not parallel CoW)"
        )
    if ns.scoreboard in ("tetragon", "incident", "selfplay"):
        from sensors import ensure_helm

        ensure_helm()
    ns.out.mkdir(parents=True, exist_ok=True)
    drop_eval_trees()
    try:
        return _harvest(ns)
    finally:
        drop_eval_trees()


def _harvest(ns: argparse.Namespace) -> int:
    run_id = ns.live_run_id
    tree = f"gym-src-eval-{run_id}"
    if ns.scoreboard == "playbook":
        checkpoints = ["playbook"]
    elif ns.scoreboard == "incident":
        checkpoints = ["oracle", "shallow"]
    elif ns.scoreboard == "selfplay":
        checkpoints = (
            ["oracle", "shallow"] if ns.role == "blue" else ["catalog", "noop"]
        )
    else:
        checkpoints = ["noop", "oracle"]
    rows: list[dict[str, Any]] = []
    jsonl = ns.append_jsonl or (ns.out / f"{run_id}.jsonl")
    if ns.append_jsonl:
        if not ns.append_jsonl.is_file():
            raise SystemExit(f"--append-jsonl missing: {ns.append_jsonl}")
        rows.extend(json.loads(line) for line in ns.append_jsonl.read_text().splitlines() if line.strip())
        ids = {r.get("live_run_id") for r in rows}
        if ids != {run_id}:
            raise SystemExit(f"append jsonl live_run_id {ids} != {run_id}")

    def _flush() -> None:
        jsonl.write_text("".join(json.dumps(r) + "\n" for r in rows))
        print(f"wrote {len(rows)} rows {jsonl}", flush=True)

    def _emit(chunk: list[dict[str, Any]]) -> None:
        rows.extend(chunk)
        _flush()

    skip = {str(r["group_id"]) for r in rows if r.get("group_id")}
    if ns.only_arm in ("fork", "both"):
        run_arm(
            start_mode="fork",
            port=ns.port,
            tree_id=tree,
            n=ns.fork_n,
            groups=ns.groups,
            checkpoints=checkpoints,
            fault_id=ns.fault_id,
            live_run_id=run_id,
            ttl_s=ns.ttl_s,
            scoreboard=ns.scoreboard,
            log_dir=ns.out,
            skip_groups=skip,
            emit=_emit,
            turns=ns.turns,
            role=ns.role or "",
            scenario_id=ns.scenario,
        )
        drop_eval_trees()
        skip = {str(r["group_id"]) for r in rows if r.get("group_id")}
    if ns.only_arm in ("reset", "both"):
        run_arm(
            start_mode="reset",
            port=ns.port,
            tree_id=tree,
            n=ns.reset_n,
            groups=ns.groups,
            checkpoints=checkpoints,
            fault_id=ns.fault_id,
            live_run_id=run_id,
            ttl_s=ns.ttl_s,
            scoreboard=ns.scoreboard,
            log_dir=ns.out,
            skip_groups=skip,
            emit=_emit,
            turns=ns.turns,
            role=ns.role or "",
            scenario_id=ns.scenario,
        )
    print(jsonl)
    loaded = load_jsonl([jsonl])
    if ns.scoreboard == "playbook":
        from plots.render import plot_std_passed_vs_turn, plot_std_vs_turn

        dest_dir = ns.out / "plots"
        dest_dir.mkdir(parents=True, exist_ok=True)
        dest = dest_dir / "std-vs-turn.svg"
        plot_std_vs_turn(loaded, dest)
        print(dest)
        dest_n = dest_dir / "std-passed-vs-turn.svg"
        plot_std_passed_vs_turn(loaded, dest_n)
        print(dest_n)
    elif ns.scoreboard == "incident":
        from plots.render import (
            plot_incident_solve_std_vs_turn,
            plot_incident_std_vs_turn,
        )

        dest_dir = ns.out / "plots"
        dest_dir.mkdir(parents=True, exist_ok=True)
        dest = dest_dir / "std-r-vs-turn.svg"
        plot_incident_std_vs_turn(loaded, dest)
        print(dest)
        dest_s = dest_dir / "std-solve-vs-turn.svg"
        plot_incident_solve_std_vs_turn(loaded, dest_s)
        print(dest_s)
    elif ns.scoreboard == "selfplay":
        from plots.render import plot_selfplay_std_vs_turn

        dest_dir = ns.out / "plots"
        dest_dir.mkdir(parents=True, exist_ok=True)
        dest = dest_dir / f"std-r-vs-turn-{ns.role}.svg"
        plot_selfplay_std_vs_turn(loaded, dest, role=ns.role)
        print(dest)
    else:
        for p in render(loaded, ns.out / "plots"):
            print(p)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
