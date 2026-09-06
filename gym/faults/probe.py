"""Guest probes used by injectors. Every call has a timeout."""

from __future__ import annotations

from typing import Any

import agent


def exec_cmd(
    cid: int, args: list[str], *, timeout_s: float = 8
) -> dict[str, Any]:
    return agent.exec_cmd(cid, args, timeout_s)


def exec_ok(cid: int, args: list[str], *, timeout_s: float = 5) -> bool:
    try:
        r = exec_cmd(cid, args, timeout_s=timeout_s)
    except (OSError, RuntimeError):
        return False
    return r["exit_code"] == 0


def member0_cid(env: Any) -> int:
    cids = getattr(env, "guest_cids", None) or []
    if not cids:
        raise RuntimeError("env has no guest_cids (cannot reach member 0)")
    return int(cids[0])
