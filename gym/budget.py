"""TreeBudget sizing from group shape.

A group of N branches over a C-VM cluster is N×C new live VMs plus the
source. The daemon default (`default_tree_budget`, max_live_vms=8) cannot
fit N=8 × 3. Reject that in the gym, with the arithmetic in the message,
before `tree_fork_batch` runs — a mid-batch BudgetExhausted leaves a
partially forked group.
"""

from __future__ import annotations

from dataclasses import dataclass


# Mirrors crates/k7d/src/control.rs `default_tree_budget`.
DEFAULT_TREE_MAX_LIVE_VMS = 8
DEFAULT_TREE_MAX_LIVE_RAM_BYTES = 8 * 1024 * 1024 * 1024
DEFAULT_TREE_MAX_DISK_BYTES = 32 * 1024 * 1024 * 1024
DEFAULT_TREE_MAX_CHAIN_DEPTH = 1

# Per-VM guest RAM the gym boots in create mode (matches the demo).
DEFAULT_MEMORY_MB = 256


@dataclass(frozen=True)
class LeaseNeed:
    """How many live VMs / bytes a lease would add on top of `live_already`."""

    n: int
    vms_per_branch: int
    source_vms: int
    live_already: int
    max_live_vms: int
    memory_bytes_per_vm: int
    max_live_ram_bytes: int

    @property
    def incoming_vms(self) -> int:
        return self.n * self.vms_per_branch

    @property
    def needed_live_vms(self) -> int:
        return self.live_already + self.incoming_vms

    @property
    def needed_ram_bytes(self) -> int:
        return self.needed_live_vms * self.memory_bytes_per_vm

    def rejection(self) -> str | None:
        """Human-readable 4xx body, or None if the lease fits.

        Numbers are spelled out so a trainer (or the Rust test) can
        assert the arithmetic without scraping k7d logs.
        """
        reasons: list[str] = []
        leased = self.live_already - self.source_vms
        if self.needed_live_vms > self.max_live_vms:
            reasons.append(
                f"need {self.needed_live_vms} live VMs "
                f"(source={self.source_vms} + already_leased={leased} "
                f"+ n={self.n} * vms_per_branch={self.vms_per_branch}) "
                f"> max_live_vms={self.max_live_vms}"
            )
        if self.needed_ram_bytes > self.max_live_ram_bytes:
            reasons.append(
                f"need {self.needed_ram_bytes} RAM bytes "
                f"({self.needed_live_vms} VMs * {self.memory_bytes_per_vm} B/VM) "
                f"> max_live_ram_bytes={self.max_live_ram_bytes}"
            )
        if not reasons:
            return None
        return "lease rejected: " + "; ".join(reasons)


def lease_need(
    *,
    n: int,
    vms_per_branch: int,
    source_vms: int,
    live_already: int,
    max_live_vms: int,
    memory_bytes_per_vm: int,
    max_live_ram_bytes: int,
) -> LeaseNeed:
    if n < 1:
        raise ValueError(f"n must be >= 1, got {n}")
    if vms_per_branch < 1:
        raise ValueError(f"vms_per_branch must be >= 1, got {vms_per_branch}")
    if source_vms < 1:
        raise ValueError(f"source_vms must be >= 1, got {source_vms}")
    if live_already < source_vms:
        raise ValueError(
            f"live_already={live_already} is below source_vms={source_vms}"
        )
    return LeaseNeed(
        n=n,
        vms_per_branch=vms_per_branch,
        source_vms=source_vms,
        live_already=live_already,
        max_live_vms=max_live_vms,
        memory_bytes_per_vm=memory_bytes_per_vm,
        max_live_ram_bytes=max_live_ram_bytes,
    )


@dataclass(frozen=True)
class ResetNeed:
    """Full-cluster bring-up per member — no CoW, no shared source."""

    n: int
    vms_per_branch: int
    memory_bytes_per_vm: int
    max_live_vms: int
    max_live_ram_bytes: int

    @property
    def needed_vms(self) -> int:
        return self.n * self.vms_per_branch

    @property
    def needed_ram_bytes(self) -> int:
        return self.needed_vms * self.memory_bytes_per_vm

    def rejection(self) -> str | None:
        reasons: list[str] = []
        if self.needed_vms > self.max_live_vms:
            reasons.append(
                f"reset is not CoW: need {self.needed_vms} live VMs "
                f"(n={self.n} × {self.vms_per_branch} full clusters, "
                f"no shared source) > max_live_vms={self.max_live_vms} "
                f"(fork-sized leftover max_live_vms=8 cannot hold reset)"
            )
        if self.needed_ram_bytes > self.max_live_ram_bytes:
            reasons.append(
                f"reset is not CoW: need {self.needed_ram_bytes} RAM bytes "
                f"({self.needed_vms} VMs × {self.memory_bytes_per_vm} B/VM) "
                f"> max_live_ram_bytes={self.max_live_ram_bytes} "
                "(do not admit on fork CoW RSS ~0.6 GiB/3-node)"
            )
        if not reasons:
            return None
        return "lease rejected: " + "; ".join(reasons)


def reset_need(
    *,
    n: int,
    vms_per_branch: int,
    memory_bytes_per_vm: int,
    max_live_vms: int,
    max_live_ram_bytes: int,
) -> ResetNeed:
    if n < 1:
        raise ValueError(f"n must be >= 1, got {n}")
    if vms_per_branch < 1:
        raise ValueError(f"vms_per_branch must be >= 1, got {vms_per_branch}")
    return ResetNeed(
        n=n,
        vms_per_branch=vms_per_branch,
        memory_bytes_per_vm=memory_bytes_per_vm,
        max_live_vms=max_live_vms,
        max_live_ram_bytes=max_live_ram_bytes,
    )


def tree_budget(
    *,
    max_live_vms: int,
    max_live_ram_bytes: int,
    max_disk_bytes: int,
    max_chain_depth: int = 32,
) -> dict[str, int]:
    """Explicit TreeBudget dict for `tree_create*` / `tree_adopt_cluster`."""
    return {
        "max_live_vms": max_live_vms,
        "max_live_ram_bytes": max_live_ram_bytes,
        "max_disk_bytes": max_disk_bytes,
        "max_chain_depth": max_chain_depth,
    }
