"""Shared injector surface. No silent defaults — every method is explicit."""

from __future__ import annotations

from typing import Any


class Fault:
    """One named injector. Subclasses set `id`, `modes`, `good_fix_hint`."""

    id: str
    modes: tuple[str, ...]
    good_fix_hint: dict[str, Any]
    # Always the first sibling (env index 0), first cluster member.
    target_index: int = 0
    target_member: int = 0

    def inject(self, env: Any, client: Any) -> None:
        raise NotImplementedError(f"{self.id}.inject")

    def fault_visible(self, env: Any) -> bool:
        raise NotImplementedError(f"{self.id}.fault_visible")

    def healthy(self, env: Any) -> bool:
        raise NotImplementedError(f"{self.id}.healthy")

    def source_shows_fault(
        self,
        *,
        guest_cids: list[int],
        bridge: str,
        guest_ips: list[str],
    ) -> bool:
        raise NotImplementedError(f"{self.id}.source_shows_fault")
