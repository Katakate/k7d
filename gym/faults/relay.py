"""Promote `incidents.Relay` into a gym Fault. No chain reimplementation.

`inject` applies the catalog Deployment via the member-0 guest API,
waits until the miner is Running, then `plant_host`s layers 2/3.
Ubuntu only. The apiserver stays up (this is a fix task, not
`kill-member-0`; CHALLENGES #146 does not apply).
"""

from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any

from faults.base import Fault
from faults.probe import exec_cmd, member0_cid
from incidents_load import incidents_mod
from scoring import curl_api

_inc = incidents_mod()
RELAY_MINER = _inc.RELAY_MINER
RELAY_MINER_BIN = _inc.RELAY_MINER_BIN
RELAY_MINER_PATH = f"/tmp/{RELAY_MINER_BIN}"
MINER_PODS_PATH = (
    "/api/v1/namespaces/default/pods"
    f"?labelSelector=app%3D{RELAY_MINER}"
    "&fieldSelector=status.phase%3DRunning"
)
VISIBLE_CEILING_S = 120.0
POLL_S = 2.0


def _relay() -> Any:
    return _inc.Relay()


def miner_running_via_api(
    bridge: str,
    *,
    cert: Path | None,
    key: Path | None,
    guest_ip: str = "10.200.0.2",
    timeout_s: float = 20,
) -> bool:
    """Mirror `Relay.visible` through the member API (no host kubectl)."""
    if not bridge or cert is None or key is None:
        raise RuntimeError(
            f"relay visible needs bridge+certs, got bridge={bridge!r} "
            f"cert={cert} key={key}"
        )
    if not cert.is_file() or not key.is_file():
        raise RuntimeError(f"relay visible: certs missing cert={cert} key={key}")
    code, body, _err = curl_api(
        bridge,
        MINER_PODS_PATH,
        guest_ip=guest_ip,
        cert=cert,
        key=key,
        timeout_s=timeout_s,
    )
    if code < 200 or code >= 400:
        return False
    try:
        items = (json.loads(body) or {}).get("items") or []
    except (json.JSONDecodeError, TypeError):
        return False
    return bool(items)


def miner_running_via_exec(cid: int, timeout_s: float = 20) -> bool:
    r = exec_cmd(
        cid,
        [
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
        timeout_s=timeout_s,
    )
    return r["exit_code"] == 0 and bool((r.get("stdout") or "").strip())


def _env_certs(env: Any) -> tuple[Path | None, Path | None]:
    cert_s = getattr(env, "cert_path", "") or ""
    key_s = getattr(env, "key_path", "") or ""
    cert, key = Path(cert_s) if cert_s else None, Path(key_s) if key_s else None
    if cert is not None and key is not None and cert.is_file() and key.is_file():
        return cert, key
    return None, None


def env_miner_running(env: Any) -> bool:
    cert, key = _env_certs(env)
    bridge = getattr(env, "bridge", "") or ""
    ips = getattr(env, "guest_ips", None) or []
    ip0 = ips[0] if ips else "10.200.0.2"
    if bridge and cert is not None and key is not None:
        return miner_running_via_api(bridge, cert=cert, key=key, guest_ip=ip0)
    cid = member0_cid(env)
    return miner_running_via_exec(cid)


def shallow_fix_hint() -> dict[str, Any]:
    """Layer-1 only — `Relay.remediate` deploy delete. Soak must fail."""
    return {
        "action": "exec",
        "args": [
            "k3s",
            "kubectl",
            "delete",
            "deploy",
            RELAY_MINER,
            "-n",
            "default",
            "--ignore-not-found=true",
        ],
    }


class Relay(Fault):
    id = "relay"
    modes = ("ubuntu",)
    keep_apiserver: bool = True
    tetragon_paths: tuple[str, ...] = (RELAY_MINER_PATH,)
    source_mode: str = "ubuntu"

    def __init__(self) -> None:
        relay = _relay()
        self.good_fix_hint = {
            "action": "exec",
            "args": ["sh", "-c", relay.remediate_cmd()],
        }

    def inject(self, env: Any, client: Any) -> None:
        _ = client
        if self.source_mode != "ubuntu":
            raise RuntimeError(
                f"relay inject is ubuntu-only, got source_mode={self.source_mode!r}"
            )
        cids = list(getattr(env, "guest_cids", None) or [])
        if not cids:
            raise RuntimeError("relay.inject: guest_cids empty")
        cid = int(cids[0])
        relay = _relay()
        yaml = relay.yaml
        script = (
            "cat >/tmp/k7-relay.yaml <<'EOFYAML'\n"
            f"{yaml}"
            "EOFYAML\n"
            "k3s kubectl apply -f /tmp/k7-relay.yaml"
        )
        r = exec_cmd(cid, ["sh", "-c", script], timeout_s=40)
        if r["exit_code"] != 0:
            raise RuntimeError(
                f"relay apply failed: exit={r['exit_code']} "
                f"stderr={r['stderr']!r} stdout={r['stdout']!r}"
            )
        deadline = time.monotonic() + VISIBLE_CEILING_S
        while time.monotonic() < deadline:
            if env_miner_running(env):
                break
            time.sleep(POLL_S)
        else:
            raise RuntimeError("relay: node-agent never became Running")
        relay.plant_host(cids)

    def fault_visible(self, env: Any) -> bool:
        try:
            return env_miner_running(env)
        except RuntimeError:
            return True

    def healthy(self, env: Any) -> bool:
        try:
            return not env_miner_running(env)
        except RuntimeError:
            return False

    def source_shows_fault(
        self,
        *,
        guest_cids: list[int],
        bridge: str,
        guest_ips: list[str],
    ) -> bool:
        if not guest_cids:
            return False
        _ = (bridge, guest_ips)
        return miner_running_via_exec(int(guest_cids[0]))
