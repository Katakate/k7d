"""No-op injector. Vacuous contain + restore."""

from __future__ import annotations

from typing import Any

from faults.base import Fault


class NoneFault(Fault):
    id = "none"
    modes = ("create", "adopt", "ubuntu")
    good_fix_hint: dict[str, Any] = {"action": "exec", "args": ["true"]}

    def inject(self, env: Any, client: Any) -> None:
        _ = (env, client)

    def fault_visible(self, env: Any) -> bool:
        _ = env
        return False

    def healthy(self, env: Any) -> bool:
        _ = env
        return True

    def source_shows_fault(
        self,
        *,
        guest_cids: list[int],
        bridge: str,
        guest_ips: list[str],
    ) -> bool:
        _ = (guest_cids, bridge, guest_ips)
        return False
