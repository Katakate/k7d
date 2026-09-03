"""Real vsock probes of live tree guests.

No synthetic RTT / dirty / page counts. Each tick is a measured ping or
exec against a guest agent (gym/agent.py, vsock port 1024).
"""

from __future__ import annotations

import random
import sys
import threading
import time
from pathlib import Path
from typing import Any

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parents[1] / "gym"))

import agent as guest_agent  # noqa: E402


def parse_uptime(text: str) -> float | None:
    """First field of ``/proc/uptime`` (seconds). None if missing/unparseable."""
    if not text:
        return None
    first = text.split()[0] if text.split() else ""
    try:
        return float(first)
    except ValueError:
        return None


def live_targets(trees: dict[str, Any]) -> list[tuple[str, str, int]]:
    """(tree_id, node_id, cid) for live members only."""
    out: list[tuple[str, str, int]] = []
    for tid, slot in (trees or {}).items():
        nodes = slot.get("nodes") or {}
        members = slot.get("members") or {}
        for nid, cids in members.items():
            node = nodes.get(nid) or {}
            if node and node.get("state") not in (None, "live"):
                continue
            for cid in cids or []:
                try:
                    out.append((tid, nid, int(cid)))
                except (TypeError, ValueError):
                    continue
    return out


def root_server_target(trees: dict[str, Any]) -> tuple[str, str, int] | None:
    """Root node's first CID (the k3s server). Guest-clock source."""
    for tid, slot in (trees or {}).items():
        nodes = slot.get("nodes") or {}
        members = slot.get("members") or {}
        for nid, node in nodes.items():
            if node.get("parent"):
                continue
            if node.get("state") not in (None, "live"):
                continue
            cids = members.get(nid) or []
            if not cids:
                continue
            try:
                return tid, nid, int(cids[0])
            except (TypeError, ValueError):
                continue
    return None


def probe_one(cid: int, n: int) -> dict[str, Any]:
    """Ping the guest; periodically exec real /proc reads and a small write."""
    t0 = time.perf_counter()
    ok = guest_agent.ping(cid, timeout_s=0.45)
    ping_ms = (time.perf_counter() - t0) * 1000
    result: dict[str, Any] = {
        "cid": cid,
        "ok": ok,
        "ping_ms": round(ping_ms, 2),
        "uptime": "",
        "loadavg": "",
        "wrote": False,
        "exec_ms": None,
        "error": "",
    }
    if not ok:
        result["error"] = "ping-fail"
        return result
    # Exec is the expensive/real path — not every ping, so we stay honest
    # about rate (user can speed the video up later).
    if n % 3 == 0:
        t1 = time.perf_counter()
        try:
            up = guest_agent.exec_cmd(cid, ["cat", "/proc/uptime"], timeout_s=0.8)
            la = guest_agent.exec_cmd(cid, ["cat", "/proc/loadavg"], timeout_s=0.8)
            result["uptime"] = (up.get("stdout") or "").strip()
            result["loadavg"] = (la.get("stdout") or "").strip()
            if n % 9 == 0:
                guest_agent.exec_cmd(
                    cid,
                    ["sh", "-c", f"echo n={n} t={int(time.time())} >> /tmp/k7view-probe"],
                    timeout_s=0.8,
                )
                result["wrote"] = True
        except (OSError, RuntimeError) as exc:
            result["error"] = str(exc)[:160]
        result["exec_ms"] = round((time.perf_counter() - t1) * 1000, 1)
    return result


def format_probe(p: dict[str, Any]) -> str:
    bits = [f"vsock cid={p['cid']}", f"ping={p['ping_ms']:.2f}ms"]
    if not p.get("ok"):
        bits.append(p.get("error") or "fail")
        return " ".join(bits)
    if p.get("uptime"):
        bits.append(f"uptime={p['uptime'].split()[0]}")
    if p.get("loadavg"):
        bits.append(f"load={p['loadavg'].split()[0]}")
    if p.get("exec_ms") is not None:
        bits.append(f"exec={p['exec_ms']:.1f}ms")
    if p.get("wrote"):
        bits.append("wrote /tmp/k7view-probe")
    if p.get("error"):
        bits.append(p["error"])
    return " ".join(bits)


class RealProbe:
    """Background vsock to live guests. Not a visible cursor.

    Picks a random CID, waits a jittered gap, and does not ingest ticks
    or traces — those painted a yellow walk across the tree. Dirty-page
    movement still shows up via k7d ``tree_nodes``.
    """

    def __init__(self, store: Any, ingest_fn: Any, interval: float = 0.05) -> None:
        self.store = store
        self.ingest_fn = ingest_fn
        self.interval = interval
        self.n = 0
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None

    def start(self) -> None:
        if self._thread and self._thread.is_alive():
            return
        self._stop.clear()
        self._thread = threading.Thread(
            target=self._loop, name="k7view-probe", daemon=True
        )
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        if self._thread:
            self._thread.join(timeout=2)

    def _loop(self) -> None:
        while not self._stop.is_set():
            gap = random.uniform(0.35, 1.8)
            if self._stop.wait(gap):
                return
            targets = live_targets(getattr(self.store, "trees", {}))
            if not targets:
                continue
            self.n += 1
            root = root_server_target(getattr(self.store, "trees", {}))
            # Exec ticks (uptime) prefer the root server — that is the
            # guest-clock source. Other ticks stay a random live CID.
            if self.n % 3 == 0 and root is not None:
                tid, nid, cid = root
            else:
                tid, nid, cid = random.choice(targets)
            try:
                result = probe_one(cid, self.n)
            except Exception:
                continue
            up = parse_uptime(result.get("uptime") or "")
            if up is None:
                continue
            try:
                self.ingest_fn(
                    [
                        {
                            "type": "guest_clock",
                            "tree_id": tid,
                            "node_id": nid,
                            "cid": cid,
                            "uptime_s": up,
                        }
                    ]
                )
            except Exception:
                continue
