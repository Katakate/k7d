"""Kill member 0 of one sibling — restorable process / unit death.

Create-mode PID 1 is `k7-agent` (`guest/rootfs/init.sh` execs it).
`kill -9 1` would take vsock with it: `act` cannot restore, and score
would only see a dead ping. The injector SIGKILLs a planted canary on
member 0 instead; the documented fix respawns it.

Ubuntu PID 1 is systemd (`guest/ubuntu/units/k7-agent.service` is
`Restart=always`). `kill -9 1` is unrestorable. Ubuntu mode stops
`k3s.service` on member 0 (the server) and the good fix is
`systemctl start k3s.service` — `act` exec always hits cid[0].
Inject after the batch, on env index 0 only — never the source.
"""

from __future__ import annotations

from typing import Any

from faults.base import Fault
from faults.probe import exec_cmd, exec_ok, member0_cid

MARKER = "/tmp/k7-fault-kill"
RESTORED = "/tmp/k7-fault-restored"
PIDFILE = "/tmp/k7-member0.pid"

# Visibility is the kill marker: `kill -0` stays true for a zombie
# until PID 1 (k7-agent) reaps. The good fix must not leave a
# background `sleep` — busybox ash waits on it and `act` times out.
_INJECT = (
    f"sleep 86400 & echo $! > {PIDFILE}; "
    f"kill -9 $(cat {PIDFILE}) || exit 1; "
    f"rm -f {RESTORED}; "
    f"echo 1 > {MARKER}"
)
_FIX = f"rm -f {MARKER}; echo 1 > {RESTORED}"
_VISIBLE = f"test -f {MARKER}"
_HEALTHY = f"test ! -f {MARKER} && test -f {RESTORED}"


_UBUNTU_UNIT = "k3s.service"
_UBUNTU_STOP = ["systemctl", "stop", _UBUNTU_UNIT]
_UBUNTU_START = ["systemctl", "start", _UBUNTU_UNIT]
# 25a-inc4 kprobe prefix. Touch so Tetragon sees a child-only path.
TETRAGON_PATH = "/tmp/k7d-tetra-kill-member-0"
INJECT_POD = "k7-kill-member-0"
_UBUNTU_DOWN = (
    f"test \"$(systemctl is-active {_UBUNTU_UNIT} 2>/dev/null || true)\" != active"
)
_UBUNTU_UP = f"systemctl is-active {_UBUNTU_UNIT}"


class KillMember0(Fault):
    id = "kill-member-0"
    modes = ("create", "adopt", "ubuntu")
    good_fix_hint: dict[str, Any] = {
        "action": "exec",
        "args": ["sh", "-c", _FIX],
    }
    tetragon_paths: tuple[str, ...] = (TETRAGON_PATH,)
    source_mode: str = "create"
    # Tetragon collection is HTTPS to 10.200.0.2:6443. Stopping
    # k3s.service on the server takes that API down (CHALLENGES #146).
    keep_apiserver: bool = False

    def inject(self, env: Any, client: Any) -> None:
        _ = client
        cid = member0_cid(env)
        if self.source_mode == "ubuntu":
            mark = exec_cmd(cid, ["touch", TETRAGON_PATH], timeout_s=8)
            if mark["exit_code"] != 0:
                raise RuntimeError(
                    f"kill-member-0 tetragon marker {TETRAGON_PATH} failed: "
                    f"exit={mark['exit_code']} stderr={mark['stderr']!r}"
                )
            if self.keep_apiserver:
                # Host touch is not a Tetragon event (CHALLENGES #147).
                # 25a-inc4 fires fd_install from a pinned busybox pod.
                from pathlib import Path

                from tetragon import create_inject_pod, wait_path_events

                bridge = getattr(env, "bridge", "") or ""
                cert = Path(getattr(env, "cert_path", "") or "")
                key = Path(getattr(env, "key_path", "") or "")
                if not bridge or not cert.is_file() or not key.is_file():
                    raise RuntimeError(
                        "tetragon inject needs env.bridge and kube certs, "
                        f"got bridge={bridge!r} cert={cert} key={key}"
                    )
                create_inject_pod(bridge, cert, key, INJECT_POD, TETRAGON_PATH)
                wait_path_events(bridge, cert, key, TETRAGON_PATH)
                return
            r = exec_cmd(cid, _UBUNTU_STOP, timeout_s=45)
            if r["exit_code"] != 0:
                raise RuntimeError(
                    f"kill-member-0 ubuntu stop {_UBUNTU_UNIT} failed: "
                    f"exit={r['exit_code']} stderr={r['stderr']!r} "
                    f"stdout={r['stdout']!r}"
                )
            return
        r = exec_cmd(cid, ["sh", "-c", _INJECT], timeout_s=8)
        if r["exit_code"] != 0:
            raise RuntimeError(
                f"kill-member-0 inject failed: exit={r['exit_code']} "
                f"stderr={r['stderr']!r} stdout={r['stdout']!r}"
            )

    def fault_visible(self, env: Any) -> bool:
        try:
            cid = member0_cid(env)
        except RuntimeError:
            return True
        if self.source_mode == "ubuntu":
            if self.keep_apiserver:
                return exec_ok(cid, ["test", "-f", TETRAGON_PATH], timeout_s=5)
            return exec_ok(cid, ["sh", "-c", _UBUNTU_DOWN], timeout_s=8)
        return exec_ok(cid, ["sh", "-c", _VISIBLE], timeout_s=5)

    def healthy(self, env: Any) -> bool:
        try:
            cid = member0_cid(env)
        except RuntimeError:
            return False
        if self.source_mode == "ubuntu":
            if self.keep_apiserver:
                return not exec_ok(cid, ["test", "-f", TETRAGON_PATH], timeout_s=5)
            return exec_ok(cid, ["sh", "-c", _UBUNTU_UP], timeout_s=8)
        return exec_ok(cid, ["sh", "-c", _HEALTHY], timeout_s=5)

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
        if self.source_mode == "ubuntu":
            if self.keep_apiserver:
                return exec_ok(cid, ["test", "-f", TETRAGON_PATH], timeout_s=5)
            return exec_ok(cid, ["sh", "-c", _UBUNTU_DOWN], timeout_s=8)
        return exec_ok(cid, ["sh", "-c", _VISIBLE], timeout_s=5)
