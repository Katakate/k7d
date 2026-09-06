"""Partition member 0 of one sibling — drop eth0, restore with eth0 up.

Verify via vsock `ip link` (not ICMP). Forks share guest IPs and the
host puts `10.200.0.1/24` on every `k7-br-*`, so `ping -I <bridge>`
is the wrong probe. Vsock stays up with eth0 down, so the scripted
fix can still `exec`.
"""

from __future__ import annotations

from typing import Any

from faults.base import Fault
from faults.probe import exec_cmd, exec_ok, member0_cid

# Busybox ash treats `$((0x1003 & 1))` as 0 (stops at `x`), so a
# sysfs hex flags check made every NIC look DOWN and "leaked" onto
# the source. Match the first `ip link` line: `,UP` / `<UP` is
# IFF_UP, and does not match `LOWER_UP` alone.
_UP = "ip link show eth0 | sed -n '1p' | grep -qE '<UP|,UP'"
_DOWN = "ip link show eth0 | sed -n '1p' | grep -qvE '<UP|,UP'"


class PartitionMember0(Fault):
    id = "partition-member-0"
    modes = ("create", "adopt", "ubuntu")
    good_fix_hint: dict[str, Any] = {
        "action": "exec",
        "args": ["ip", "link", "set", "eth0", "up"],
    }

    def inject(self, env: Any, client: Any) -> None:
        _ = client
        cid = member0_cid(env)
        r = exec_cmd(cid, ["ip", "link", "set", "eth0", "down"], timeout_s=8)
        if r["exit_code"] != 0:
            raise RuntimeError(
                f"partition-member-0 inject failed: exit={r['exit_code']} "
                f"stderr={r['stderr']!r} stdout={r['stdout']!r}"
            )

    def fault_visible(self, env: Any) -> bool:
        try:
            cid = member0_cid(env)
        except RuntimeError:
            return True
        return exec_ok(cid, ["sh", "-c", _DOWN], timeout_s=5)

    def healthy(self, env: Any) -> bool:
        try:
            cid = member0_cid(env)
        except RuntimeError:
            return False
        return exec_ok(cid, ["sh", "-c", _UP], timeout_s=5)

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
        return exec_ok(int(guest_cids[0]), ["sh", "-c", _DOWN], timeout_s=5)
