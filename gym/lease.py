"""In-memory lease table + TTL helpers. No k7d calls in this module.

The server owns the k7d prune/drop path and calls it from the same
function for an explicit `/release` and for the reaper, so the two
cannot diverge.
"""

from __future__ import annotations

import threading
import time
import uuid
from dataclasses import dataclass, field
from typing import Any


def new_lease_id() -> str:
    return "lease-" + uuid.uuid4().hex[:16]


def new_env_id(lease_id: str, index: int) -> str:
    return f"{lease_id}-{index}"


@dataclass
class Env:
    env_id: str
    branch_node_id: str
    index: int
    bridge: str
    guest_ips: list[str]
    guest_cids: list[int]
    tree_id: str = ""
    baseline_raw: str = ""
    cert_path: str = ""
    key_path: str = ""
    disks: list[str] = field(default_factory=list)
    playbook_results: list[dict[str, Any]] = field(default_factory=list)
    incident_results: list[dict[str, Any]] = field(default_factory=list)
    selfplay_results: list[dict[str, Any]] = field(default_factory=list)
    role: str = ""
    scenario_id: str = ""
    foothold_token: str = ""
    cluster_id: str = ""
    autowarp_mode: str = "off"

    def as_public(self) -> dict[str, Any]:
        pub = {
            "env_id": self.env_id,
            "branch_node_id": self.branch_node_id,
            "index": self.index,
            "bridge": self.bridge,
            "guest_ips": list(self.guest_ips),
        }
        if self.tree_id:
            pub["tree_id"] = self.tree_id
        if self.cluster_id:
            pub["cluster_id"] = self.cluster_id
        if self.autowarp_mode != "off":
            pub["autowarp_mode"] = self.autowarp_mode
        return pub


@dataclass
class Lease:
    lease_id: str
    node_id: str
    group_id: str
    fault_id: str
    tree_id: str
    source_node_id: str
    n: int
    created_at: float
    expires_at: float
    envs: list[Env]
    client: str = ""
    # Set only for fault_id="scripted" (27a-inc1); picks the pack entry.
    scenario_id: str = ""
    released: bool = False
    pending: bool = False
    releasing: bool = False
    extra: dict[str, Any] = field(default_factory=dict)
    autowarp_mode: str = "off"

    def is_expired(self, now: float | None = None) -> bool:
        if self.released:
            return False
        return (now if now is not None else time.time()) >= self.expires_at

    def live_vms(self, vms_per_branch: int) -> int:
        return self.n * vms_per_branch

    def as_public(self) -> dict[str, Any]:
        return {
            "lease_id": self.lease_id,
            "node_id": self.node_id,
            "group_id": self.group_id,
            "fault_id": self.fault_id,
            "scenario_id": self.scenario_id,
            "tree_id": self.tree_id,
            "source_node_id": self.source_node_id,
            "n": self.n,
            "created_at": self.created_at,
            "expires_at": self.expires_at,
            "released": self.released,
            "pending": self.pending,
            "client": self.client,
            "autowarp_mode": self.autowarp_mode,
            "envs": [e.as_public() for e in self.envs],
        }


class LeaseTable:
    """Thread-safe map of in-flight leases. Released rows are dropped."""

    def __init__(self, max_leases: int) -> None:
        if max_leases < 1:
            raise ValueError(f"max_leases must be >= 1, got {max_leases}")
        self.max_leases = max_leases
        self._mu = threading.Lock()
        self._leases: dict[str, Lease] = {}

    def in_flight(self) -> int:
        with self._mu:
            return self._in_flight_locked()

    def _in_flight_locked(self) -> int:
        return sum(1 for L in self._leases.values() if not L.released)

    def live_vms_in_flight(self, vms_per_branch: int) -> int:
        with self._mu:
            return sum(
                L.live_vms(vms_per_branch)
                for L in self._leases.values()
                if not L.released
            )

    def get(self, lease_id: str) -> Lease | None:
        with self._mu:
            L = self._leases.get(lease_id)
            return None if L is None or L.released else L

    def env_by_cid(self, cid: int) -> Env | None:
        with self._mu:
            for L in self._leases.values():
                if L.released:
                    continue
                for e in L.envs:
                    if cid in e.guest_cids:
                        return e
        return None

    def env(self, env_id: str) -> tuple[Lease, Env] | None:
        with self._mu:
            for L in self._leases.values():
                if L.released:
                    continue
                for e in L.envs:
                    if e.env_id == env_id:
                        return L, e
        return None

    def reserve(
        self,
        lease: Lease,
    ) -> str | None:
        """Insert a pending lease. Returns a 4xx message on admission fail."""
        with self._mu:
            if self._in_flight_locked() >= self.max_leases:
                return (
                    f"lease rejected: leases_in_flight="
                    f"{self._in_flight_locked()} >= max_leases={self.max_leases}"
                )
            if lease.lease_id in self._leases:
                return f"lease rejected: duplicate lease_id {lease.lease_id}"
            lease.pending = True
            self._leases[lease.lease_id] = lease
            return None

    def commit(self, lease_id: str, envs: list[Env]) -> Lease:
        with self._mu:
            L = self._leases.get(lease_id)
            if L is None:
                raise KeyError(f"no such lease: {lease_id}")
            L.envs = envs
            L.n = len(envs)
            L.pending = False
            return L

    def append_envs(self, lease_id: str, envs: list[Env]) -> Lease:
        """Add mid-episode children. Updates n so admission counts them."""
        if not envs:
            raise ValueError("append_envs needs at least one env")
        with self._mu:
            L = self._leases.get(lease_id)
            if L is None or L.released:
                raise KeyError(f"no such lease: {lease_id}")
            if L.pending or L.releasing:
                raise RuntimeError(
                    f"lease {lease_id} cannot take children "
                    f"(pending={L.pending} releasing={L.releasing})"
                )
            L.envs.extend(envs)
            L.n = len(L.envs)
            return L

    def abandon(self, lease_id: str) -> Lease | None:
        """Drop a pending reservation (fork failed before commit)."""
        with self._mu:
            return self._leases.pop(lease_id, None)

    def begin_release(self, lease_id: str) -> Lease | None:
        """Mark in-flight so GET still sees the lease until prune finishes."""
        with self._mu:
            L = self._leases.get(lease_id)
            if L is None or L.released:
                return None
            if L.releasing:
                return None
            L.releasing = True
            return L

    def mark_released(self, lease_id: str) -> Lease | None:
        with self._mu:
            L = self._leases.pop(lease_id, None)
            if L is None:
                return None
            L.released = True
            L.releasing = False
            return L

    def expired(self, now: float | None = None) -> list[Lease]:
        t = now if now is not None else time.time()
        with self._mu:
            return [
                L
                for L in self._leases.values()
                if (not L.released)
                and (not L.pending)
                and (not L.releasing)
                and L.expires_at <= t
            ]

    def all_ids(self) -> list[str]:
        with self._mu:
            return [L.lease_id for L in self._leases.values() if not L.released]
