"""Tetragon multi-path churn (26a-inc7). Ubuntu + keep_apiserver only.

kill-member-0 + one fd_install path is a 0.8/1.0 bit. This injects
several `/tmp/k7d-tetra-churn-*` files from one pinned busybox pod
so branch_only can be more than one key. Does not stop k3s.
"""

from __future__ import annotations

from typing import Any

from faults.base import Fault
from faults.probe import exec_cmd, exec_ok, member0_cid

CHURN_PATHS: tuple[str, ...] = tuple(
    f"/tmp/k7d-tetra-churn-{i}" for i in range(5)
)
INJECT_POD = "k7-tetra-churn"


class TetraChurn(Fault):
    id = "tetra-churn"
    modes = ("ubuntu",)
    good_fix_hint: dict[str, Any] = {
        "action": "exec",
        "args": ["rm", "-f", *CHURN_PATHS],
    }
    tetragon_paths: tuple[str, ...] = CHURN_PATHS
    source_mode: str = "ubuntu"
    keep_apiserver: bool = True

    def inject(self, env: Any, client: Any) -> None:
        _ = client
        cid = member0_cid(env)
        for p in CHURN_PATHS:
            mark = exec_cmd(cid, ["touch", p], timeout_s=8)
            if mark["exit_code"] != 0:
                raise RuntimeError(
                    f"tetra-churn marker {p} failed: exit={mark['exit_code']} "
                    f"stderr={mark['stderr']!r}"
                )
        from pathlib import Path

        from tetragon import create_inject_pod, wait_path_events

        bridge = getattr(env, "bridge", "") or ""
        cert = Path(getattr(env, "cert_path", "") or "")
        key = Path(getattr(env, "key_path", "") or "")
        if not bridge or not cert.is_file() or not key.is_file():
            raise RuntimeError(
                f"tetra-churn needs env.bridge and kube certs, "
                f"got bridge={bridge!r} cert={cert} key={key}"
            )
        create_inject_pod(
            bridge, cert, key, INJECT_POD, CHURN_PATHS[0], extra=CHURN_PATHS[1:]
        )
        for p in CHURN_PATHS:
            wait_path_events(bridge, cert, key, p)

    def fault_visible(self, env: Any) -> bool:
        try:
            cid = member0_cid(env)
        except RuntimeError:
            return True
        return all(
            exec_ok(cid, ["test", "-f", p], timeout_s=5) for p in CHURN_PATHS
        )

    def healthy(self, env: Any) -> bool:
        try:
            cid = member0_cid(env)
        except RuntimeError:
            return False
        return all(
            not exec_ok(cid, ["test", "-f", p], timeout_s=5) for p in CHURN_PATHS
        )

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
        cid = int(guest_cids[0])
        return any(
            exec_ok(cid, ["test", "-f", p], timeout_s=5) for p in CHURN_PATHS
        )
