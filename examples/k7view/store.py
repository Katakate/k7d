"""In-memory join of k7d tree snapshots + agent ingest.

Pure Python: no socket, no HTTP. The server polls k7d and calls
``apply_snapshot``; the scenario posts notes/traces via ``ingest``.
"""

from __future__ import annotations

import time
from typing import Any


def now_ms() -> int:
    return int(time.time() * 1000)


def _norm_node(n: dict[str, Any]) -> dict[str, Any]:
    """Lowercase state/kind so the stub daemon ("Live") renders like k7d."""
    out = dict(n)
    if isinstance(out.get("state"), str):
        out["state"] = out["state"].lower()
    if isinstance(out.get("kind"), str):
        out["kind"] = out["kind"].lower()
    return out


def _new_slot(tree_id: str, kind: str, memory_mb: int) -> dict[str, Any]:
    return {
        "tree_id": tree_id,
        "kind": kind,
        "nodes": {},
        "members": {},
        "notes": {},
        "traces": {},
        "latencies": {},
        "errors": {},
        "cmds": {},
        "execs": {},
        "verdicts": {},
        "budget": None,
        "usage": None,
        "memory_mb": memory_mb,
        "live_dilation": {},
        "live_cpu": {},
        "dilation_ladder": {},
        "dilation_policy": {},
        "dilation_trajectory": {},
        "guest_clock": None,
    }


def estimate_usage(nodes: list[dict[str, Any]], memory_mb: int) -> dict[str, int]:
    """Best-effort usage when the daemon does not yet return TreeUsage."""
    live_vm = 0
    live_ram = 0
    disk = 0
    live_nodes = 0
    page = 4096
    fallback = memory_mb * 1024 * 1024
    for n in nodes:
        vmc = int(n.get("vm_count") or 1)
        dirty = int(n.get("dirty_page_count") or 0)
        disk += dirty * page
        if n.get("state") == "live":
            live_nodes += 1
            live_vm += vmc
            live_ram += dirty * page if dirty else fallback * vmc
    return {
        "live_vm_count": live_vm,
        "live_ram_bytes": live_ram,
        "disk_bytes": disk,
        "total_nodes": len(nodes),
        "live_node_count": live_nodes,
    }


def diff_nodes(
    tree_id: str,
    prev: dict[str, dict[str, Any]],
    cur: dict[str, dict[str, Any]],
    ts: int,
) -> list[dict[str, Any]]:
    """Derive topology events from two ``id → NodeInfo`` maps."""
    events: list[dict[str, Any]] = []
    for nid, node in cur.items():
        if nid not in prev:
            events.append(
                {
                    "ts_unix_ms": ts,
                    "tree_id": tree_id,
                    "op": "appear",
                    "node_id": nid,
                    "parent_id": node.get("parent"),
                    "label": node.get("label") or nid,
                    "state": node.get("state"),
                }
            )
            continue
        old = prev[nid]
        if old.get("state") != node.get("state"):
            op = {
                "evicted": "evict",
                "suspended": "suspend",
                "live": "resume",
            }.get(str(node.get("state")), "state")
            events.append(
                {
                    "ts_unix_ms": ts,
                    "tree_id": tree_id,
                    "op": op,
                    "node_id": nid,
                    "parent_id": node.get("parent"),
                    "label": node.get("label") or nid,
                    "state": node.get("state"),
                    "prev_state": old.get("state"),
                }
            )
        if (not old.get("protected")) and node.get("protected"):
            events.append(
                {
                    "ts_unix_ms": ts,
                    "tree_id": tree_id,
                    "op": "protect",
                    "node_id": nid,
                    "label": node.get("label") or nid,
                }
            )
        if old.get("protected") and not node.get("protected"):
            events.append(
                {
                    "ts_unix_ms": ts,
                    "tree_id": tree_id,
                    "op": "unprotect",
                    "node_id": nid,
                    "label": node.get("label") or nid,
                }
            )
    for nid, old in prev.items():
        if nid not in cur:
            events.append(
                {
                    "ts_unix_ms": ts,
                    "tree_id": tree_id,
                    "op": "prune",
                    "node_id": nid,
                    "parent_id": old.get("parent"),
                    "label": old.get("label") or nid,
                }
            )
    return events


class ViewStore:
    """Join k7d snapshots to agent annotations."""

    def __init__(self, event_cap: int = 800) -> None:
        self.event_cap = event_cap
        self.connected = False
        self.error: str | None = None
        self.run: dict[str, Any] = {"phase": "idle", "goal": "", "tree_id": ""}
        self.trees: dict[str, dict[str, Any]] = {}
        self.events: list[dict[str, Any]] = []
        self.meta: list[dict[str, Any]] = []
        self.beats: list[dict[str, Any]] = []
        self.activity: dict[str, int] = {}
        self.clock_ms = now_ms()
        self.bus_n = 0
        self.last_tick = ""
        self._seq = 0

    def _push(self, event: dict[str, Any]) -> dict[str, Any]:
        self._seq += 1
        event = dict(event)
        event.setdefault("ts_unix_ms", now_ms())
        event["seq"] = self._seq
        self.events.append(event)
        if len(self.events) > self.event_cap:
            self.events = self.events[-self.event_cap :]
        return event

    def totals(self) -> dict[str, int]:
        """Cross-tree counts for the header (demo / max-load)."""
        trees = 0
        nodes = 0
        live_nodes = 0
        live_vms = 0
        forks = 0
        for slot in self.trees.values():
            trees += 1
            ns = slot.get("nodes") or {}
            nodes += len(ns)
            for n in ns.values():
                if n.get("state") == "live":
                    live_nodes += 1
            usage = slot.get("usage") or {}
            live_vms += int(usage.get("live_vm_count") or 0)
            forks += len(slot.get("latencies") or {})
        return {
            "trees": trees,
            "nodes": nodes,
            "live_nodes": live_nodes,
            "live_vms": live_vms,
            "forks": forks,
        }

    def snapshot(self) -> dict[str, Any]:
        return {
            "connected": self.connected,
            "error": self.error,
            "run": self.run,
            "trees": self.trees,
            "events": self.events[-200:],
            "meta": self.meta[-80:],
            "beats": self.beats[-40:],
            "seq": self._seq,
            "totals": self.totals(),
            "activity": self.activity,
            "clock_ms": now_ms(),
            "bus_n": self.bus_n,
            "last_tick": self.last_tick,
        }

    def apply_snapshot(
        self,
        tree_id: str,
        nodes: list[dict[str, Any]],
        *,
        kind: str = "cluster",
        memory_mb: int = 256,
        usage: dict[str, Any] | None = None,
        budget: dict[str, Any] | None = None,
        live_guest_cids: dict[str, Any] | None = None,
        live_dilation: dict[str, Any] | None = None,
        live_cpu: dict[str, Any] | None = None,
        dilation_ladder: dict[str, Any] | None = None,
        dilation_policy: dict[str, Any] | None = None,
        dilation_trajectory: dict[str, Any] | None = None,
    ) -> list[dict[str, Any]]:
        ts = now_ms()
        cur = {n["id"]: _norm_node(n) for n in nodes if "id" in n}
        slot = self.trees.setdefault(tree_id, _new_slot(tree_id, kind, memory_mb))
        prev = slot.get("nodes") or {}
        # Tombstones: a node the daemon no longer lists was pruned. Keep
        # its record (greyed in the UI, notes/cmds/verdicts stay
        # readable) so the explored tree stays visible. Only non-pruned
        # prev entries participate in the diff, so `prune` fires once.
        prev_alive = {i: n for i, n in prev.items() if n.get("state") != "pruned"}
        derived = diff_nodes(tree_id, prev_alive, cur, ts)
        merged = dict(cur)
        for nid, old in prev.items():
            if nid not in cur:
                stone = dict(old)
                stone["state"] = "pruned"
                stone.setdefault("pruned_at_unix_ms", ts)
                merged[nid] = stone
        slot["nodes"] = merged
        slot["kind"] = kind
        if usage is not None:
            slot["usage"] = usage
        else:
            slot["usage"] = estimate_usage(
                list(cur.values()), int(slot.get("memory_mb") or memory_mb)
            )
        if budget is not None:
            slot["budget"] = budget
        if live_guest_cids:
            for nid, cids in live_guest_cids.items():
                slot["members"][nid] = list(cids or [])
        if live_dilation is not None:
            out: dict[str, int] = {}
            for nid, factor in live_dilation.items():
                try:
                    out[str(nid)] = int(factor)
                except (TypeError, ValueError) as exc:
                    raise ValueError(
                        f"live_dilation[{nid!r}] is not an int: {factor!r}"
                    ) from exc
            slot["live_dilation"] = out
        if live_cpu is not None:
            slot["live_cpu"] = {
                str(nid): list(rows or []) for nid, rows in live_cpu.items()
            }
        if dilation_ladder is not None:
            slot["dilation_ladder"] = {
                str(nid): [int(r) for r in (rungs or [])]
                for nid, rungs in dilation_ladder.items()
            }
        if dilation_policy is not None:
            slot["dilation_policy"] = {str(k): str(v) for k, v in dilation_policy.items()}
        if dilation_trajectory is not None:
            slot["dilation_trajectory"] = {
                str(nid): [int(r) for r in (rungs or [])]
                for nid, rungs in dilation_trajectory.items()
            }
        emitted = [self._push(e) for e in derived]
        return emitted

    def drop_tree(self, tree_id: str) -> list[dict[str, Any]]:
        slot = self.trees.pop(tree_id, None)
        if not slot:
            return []
        return [
            self._push(
                {
                    "tree_id": tree_id,
                    "op": "drop",
                    "node_id": tree_id,
                    "label": tree_id,
                }
            )
        ]

    def ingest(self, payload: dict[str, Any]) -> dict[str, Any]:
        kind = payload.get("type") or payload.get("op")
        if not kind:
            raise ValueError("ingest requires type")
        tree_id = payload.get("tree_id") or self.run.get("tree_id") or ""
        if kind == "run":
            self.run = {
                "phase": payload.get("phase") or "idle",
                "goal": payload.get("goal") or self.run.get("goal") or "",
                "tree_id": payload.get("tree_id") or self.run.get("tree_id") or "",
            }
            return self._push(
                {
                    "tree_id": self.run["tree_id"],
                    "op": "run",
                    "label": self.run["phase"],
                    "text": self.run.get("goal"),
                }
            )
        if not tree_id:
            raise ValueError("ingest requires tree_id")
        slot = self.trees.setdefault(tree_id, _new_slot(tree_id, "cluster", 256))
        node_id = payload.get("node_id") or ""
        if kind == "budget":
            slot["budget"] = payload.get("budget")
            if payload.get("memory_mb") is not None:
                slot["memory_mb"] = int(payload["memory_mb"])
            return self._push(
                {
                    "tree_id": tree_id,
                    "op": "budget",
                    "label": "budget",
                }
            )
        if kind == "members":
            slot["members"][node_id] = list(payload.get("guest_cids") or [])
            return self._push(
                {
                    "tree_id": tree_id,
                    "op": "members",
                    "node_id": node_id,
                    "label": node_id,
                }
            )
        if kind == "note":
            slot["notes"][node_id] = payload.get("text") or payload.get("reason") or ""
            return self._push(
                {
                    "tree_id": tree_id,
                    "op": "note",
                    "node_id": node_id,
                    "label": node_id,
                    "reason": slot["notes"][node_id],
                    "text": slot["notes"][node_id],
                }
            )
        if kind == "cmd":
            slot["cmds"][node_id] = {
                "cmd": payload.get("cmd") or payload.get("text") or "",
                "exit_code": payload.get("exit_code"),
                "destructive": bool(payload.get("destructive")),
                "on_source": bool(payload.get("on_source")),
                "ts_unix_ms": payload.get("ts_unix_ms") or now_ms(),
            }
            # Per-member history for the drawer drill-down (member VM →
            # commands → output). Purely what the agent already ran and
            # the MCP log already recorded — no extra exec, no probing.
            execs = slot.setdefault("execs", {}).setdefault(node_id, [])
            execs.append(
                {
                    "member": payload.get("member"),
                    "cmd": slot["cmds"][node_id]["cmd"],
                    "exit_code": payload.get("exit_code"),
                    "destructive": bool(payload.get("destructive")),
                    "stdout": payload.get("stdout") or "",
                    "stderr": payload.get("stderr") or "",
                    "ts_unix_ms": slot["cmds"][node_id]["ts_unix_ms"],
                }
            )
            execs[:] = execs[-30:]
            return self._push(
                {
                    "tree_id": tree_id,
                    "op": "cmd",
                    "node_id": node_id,
                    "label": node_id,
                    "destructive": bool(payload.get("destructive")),
                    "on_source": bool(payload.get("on_source")),
                    "text": slot["cmds"][node_id]["cmd"],
                }
            )
        if kind == "verdict":
            slot["verdicts"][node_id] = {
                "clean": bool(payload.get("clean")),
                "branch_only": int(payload.get("branch_only") or 0),
                "source_only": int(payload.get("source_only") or 0),
                "sample": payload.get("sample") or "",
                "ts_unix_ms": payload.get("ts_unix_ms") or now_ms(),
            }
            return self._push(
                {
                    "tree_id": tree_id,
                    "op": "verdict",
                    "node_id": node_id,
                    "label": node_id,
                    "clean": bool(payload.get("clean")),
                    "branch_only": int(payload.get("branch_only") or 0),
                    "source_only": int(payload.get("source_only") or 0),
                    "text": payload.get("sample") or "",
                }
            )
        if kind == "beat":
            name = payload.get("name") or payload.get("text")
            if not name:
                raise ValueError("beat ingest requires name")
            beat = {
                "ts_unix_ms": payload.get("ts_unix_ms") or now_ms(),
                "tree_id": tree_id,
                "name": str(name),
                "node_id": node_id,
                "text": payload.get("detail") or "",
            }
            self.beats.append(beat)
            self.beats[:] = self.beats[-40:]
            return self._push(
                {
                    "tree_id": tree_id,
                    "op": "beat",
                    "node_id": node_id,
                    "label": beat["name"],
                    "text": beat["text"],
                }
            )
        if kind == "meta":
            item = {
                "ts_unix_ms": payload.get("ts_unix_ms") or now_ms(),
                "tree_id": tree_id,
                "node_id": node_id,
                "action": payload.get("action") or payload.get("role") or "decide",
                "text": payload.get("text") or "",
            }
            self.meta.append(item)
            self.meta[:] = self.meta[-80:]
            return self._push(
                {
                    "tree_id": tree_id,
                    "op": "meta",
                    "node_id": node_id,
                    "label": item["action"],
                    "text": item["text"],
                }
            )
        if kind == "trace":
            traces = slot["traces"].setdefault(node_id, [])
            span = {
                "ts_unix_ms": payload.get("ts_unix_ms") or now_ms(),
                "role": payload.get("role") or "thinking",
                "text": payload.get("text") or "",
            }
            if payload.get("replace") and traces and traces[-1].get("role") == span["role"]:
                traces[-1] = span
            else:
                traces.append(span)
            traces[:] = traces[-80:]
            return self._push(
                {
                    "tree_id": tree_id,
                    "op": "trace",
                    "node_id": node_id,
                    "label": node_id,
                    "role": span["role"],
                    "text": span["text"],
                }
            )
        if kind == "latency":
            slot["latencies"][node_id] = {
                "latency_ms": payload.get("latency_ms"),
                "cow": payload.get("cow") or [],
            }
            return self._push(
                {
                    "tree_id": tree_id,
                    "op": "latency",
                    "node_id": node_id,
                    "parent_id": payload.get("parent_id"),
                    "label": node_id,
                    "latency_ms": payload.get("latency_ms"),
                    "cow": payload.get("cow") or [],
                }
            )
        if kind == "guest_clock":
            up = payload.get("uptime_s")
            if up is None:
                raise ValueError("guest_clock ingest requires uptime_s")
            try:
                uptime_s = float(up)
            except (TypeError, ValueError) as exc:
                raise ValueError(f"guest_clock uptime_s is not a float: {up!r}") from exc
            clock = dict(slot.get("guest_clock") or {})
            if clock.get("base_uptime_s") is None:
                clock["base_uptime_s"] = uptime_s
            clock["uptime_s"] = uptime_s
            clock["node_id"] = node_id
            clock["cid"] = payload.get("cid")
            clock["ts_unix_ms"] = payload.get("ts_unix_ms") or now_ms()
            slot["guest_clock"] = clock
            # A sample every second must not enter the event log. That
            # log rides along on full snapshots and would rebuild the
            # tree while CPU and dilation are moving.
            return {
                "tree_id": tree_id,
                "op": "guest_clock",
                "node_id": node_id,
                "label": node_id or tree_id,
                "uptime_s": uptime_s,
            }
        if kind == "tick":
            self.clock_ms = now_ms()
            self.bus_n += 1
            if node_id:
                self.activity[node_id] = self.clock_ms
            text = payload.get("text") or f"tick {self.bus_n}"
            self.last_tick = text
            return self._push(
                {
                    "tree_id": tree_id,
                    "op": "tick",
                    "node_id": node_id,
                    "label": node_id or tree_id,
                    "text": text,
                }
            )
        if kind == "error":
            slot["errors"][node_id] = payload.get("text") or "error"
            return self._push(
                {
                    "tree_id": tree_id,
                    "op": "error",
                    "node_id": node_id,
                    "label": node_id,
                    "text": slot["errors"][node_id],
                }
            )
        raise ValueError(f"unknown ingest type: {kind}")
