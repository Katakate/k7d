"""Host-side residue and capacity probes (sysfs / proc). Stdlib only."""

from __future__ import annotations

import subprocess
from contextlib import contextmanager
from pathlib import Path
from typing import Iterator


NET = Path("/sys/class/net")


def list_bridges() -> set[str]:
    """Every `k7-br-*` link currently in the root netns."""
    if not NET.is_dir():
        return set()
    return {p.name for p in NET.iterdir() if p.name.startswith("k7-br-")}


def bridge_port_count(name: str) -> int:
    brif = Path(f"/sys/class/net/{name}/brif")
    if not brif.is_dir():
        return 0
    return sum(1 for _ in brif.iterdir())


def list_taps() -> set[str]:
    """TUN/TAP devices (the k7d leftover that survives a missing Drop)."""
    if not NET.is_dir():
        return set()
    return {p.name for p in NET.iterdir() if (p / "tun_flags").is_file()}


def free_ram_bytes() -> int:
    """MemAvailable from /proc/meminfo. Loud if the file is unreadable."""
    text = Path("/proc/meminfo").read_text()
    for line in text.splitlines():
        if line.startswith("MemAvailable:"):
            parts = line.split()
            return int(parts[1]) * 1024
    raise RuntimeError("MemAvailable missing from /proc/meminfo")


def k7d_vmrss_bytes(pid: int | None = None) -> int | None:
    """Rss of the k7d daemon, if we can see it. None if not running."""
    if pid is None:
        try:
            pids = Path("/run/k7d").joinpath("k7d.pid")
            if pids.is_file():
                pid = int(pids.read_text().strip())
        except (OSError, ValueError):
            pid = None
    if pid is None:
        # Best-effort: first k7d in /proc. Not used for admission.
        for proc in Path("/proc").iterdir():
            if not proc.name.isdigit():
                continue
            try:
                comm = (proc / "comm").read_text().strip()
            except OSError:
                continue
            if comm == "k7d":
                pid = int(proc.name)
                break
    if pid is None:
        return None
    try:
        for line in Path(f"/proc/{pid}/status").read_text().splitlines():
            if line.startswith("VmRSS:"):
                return int(line.split()[1]) * 1024
    except OSError:
        return None
    return None


def guest_ips(vm_count: int) -> list[str]:
    """Per-vm_index IPv4 on the k7 cluster subnet (10.200.0.{2+i})."""
    if vm_count < 1:
        raise ValueError(f"vm_count must be >= 1, got {vm_count}")
    return [f"10.200.0.{2 + i}" for i in range(vm_count)]


def fnv1a_5hex(data: str) -> str:
    """Match `bridge_short_tag` in crates/k7d/src/network.rs."""
    h = 0xCBF2_9CE4_8422_2325
    for b in data.encode():
        h ^= b
        h = (h * 0x0000_0100_0000_01B3) & 0xFFFFFFFFFFFFFFFF
    return f"{h & 0xF_FFFF:05x}"


@contextmanager
def pin_guest_route(bridge: str, guest_ip: str) -> Iterator[None]:
    """Steer host kubectl/helm at one cluster's 10.200.0.2.

    Reset n=8 keeps eight live bridges, each with 10.200.0.1/24.
    Without a /32, `wait_nodes_ready` hits a sibling's apiserver
    (x509 unknown authority) and 502s the lease.
    """
    if not bridge or not guest_ip:
        raise RuntimeError(
            f"pin_guest_route needs bridge and guest_ip, got {bridge!r} {guest_ip!r}"
        )
    if bridge not in list_bridges():
        raise RuntimeError(f"pin_guest_route: {bridge} is not a live k7-br-*")
    r = subprocess.run(
        ["ip", "route", "replace", f"{guest_ip}/32", "dev", bridge],
        check=False,
        capture_output=True,
        text=True,
    )
    if r.returncode != 0:
        raise RuntimeError(
            f"ip route replace {guest_ip}/32 dev {bridge} failed: "
            f"{r.stderr or r.stdout}"
        )
    try:
        yield
    finally:
        subprocess.run(
            ["ip", "route", "del", f"{guest_ip}/32", "dev", bridge],
            check=False,
            capture_output=True,
            text=True,
        )


def k7_bridge_name(cluster_id: str) -> str:
    """Derive `k7-br-*` from a cluster id the same way k7d does."""
    max_suffix = 9
    if len(cluster_id) <= max_suffix:
        suffix = cluster_id
    else:
        h = fnv1a_5hex(cluster_id)
        suffix = f"{cluster_id[:3]}-{h[:5]}"
    return f"k7-br-{suffix}"


def residue(*, bridges: set[str], taps: set[str], tree_node_ids: list[str]) -> dict:
    return {
        "bridges": sorted(bridges),
        "taps": sorted(taps),
        "tree_node_ids": sorted(tree_node_ids),
    }
