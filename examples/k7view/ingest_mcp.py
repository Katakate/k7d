#!/usr/bin/env python3
"""Bridge a 27a-inc1 MCP JSONL log into k7view's /api/ingest.

k7view stays a pure observer: this process *reads* the JSONL that
``examples/k7d-mcp/tools.py`` appends for every tool call and posts
notes / commands / Tetragon verdicts / fork latencies / timeline beats
to the view server. Nothing is written to k7d or to ``tree.json``.

Modes:
  --follow LOG.jsonl   tail a live agent run (the recording path)
  --dir DIR            follow the newest *.jsonl in DIR (new runs picked up)
  --replay LOG.jsonl   re-post a finished run with original pacing
                       (``--speed N`` to compress); with --stub-socket the
                       topology is mirrored onto gym/stub.py's k7d socket so
                       the whole screen replays offline

Stdlib only.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent / "cluster-tree-search"))


def post(url: str, payload: list[dict[str, Any]] | dict[str, Any]) -> None:
    if not url or not payload:
        return
    data = json.dumps(payload).encode()
    req = urllib.request.Request(
        url, data=data, headers={"Content-Type": "application/json"}, method="POST"
    )
    try:
        with urllib.request.urlopen(req, timeout=5) as resp:
            resp.read()
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        print(f"[ingest-mcp] view post failed: {exc}", file=sys.stderr)


def _short(s: str, n: int = 110) -> str:
    s = str(s or "").strip().replace("\n", " ")
    return s if len(s) <= n else s[: n - 1] + "…"


class StubTopo:
    """Mirror JSONL topology onto gym/stub.py's k7d socket (offline replay)."""

    def __init__(self, socket_path: str) -> None:
        from k7d_client import K7dClient  # noqa: PLC0415 — optional dep path

        self.client = K7dClient(socket_path)
        self.tree_id = "stub-tree"
        self.map: dict[str, str] = {"root": "root"}

    def to_stub(self, node_id: str) -> str:
        return self.map.get(node_id, node_id)

    def fork(self, source: str, real_ids: list[str]) -> None:
        resp = self.client.tree_fork_batch(
            self.tree_id, self.to_stub(source), real_ids
        )
        for f, rid in zip(resp.get("forks") or [], real_ids):
            self.map[rid] = f["node_id"]

    def verb(self, name: str, node_id: str) -> None:
        fn = {
            "protect": self.client.tree_protect,
            "prune": self.client.tree_prune,
        }.get(name)
        if fn is None:
            return
        try:
            fn(self.tree_id, self.to_stub(node_id))
        except RuntimeError as exc:
            print(f"[ingest-mcp] stub {name} {node_id}: {exc}", file=sys.stderr)


class Bridge:
    """Translate MCP JSONL records into k7view ingest payloads."""

    def __init__(self, topo: StubTopo | None = None) -> None:
        self.topo = topo
        self.beats_seen: set[str] = set()
        self.fixed: set[str] = set()  # nodes that saw a destructive cmd
        self.phase_posted = False

    def _tree(self, rec: dict[str, Any]) -> str:
        if self.topo:
            return self.topo.tree_id
        return str(rec.get("tree_id") or "")

    def _node(self, node_id: str) -> str:
        if self.topo:
            return self.topo.to_stub(node_id)
        return node_id

    def _beat(self, tree: str, name: str, node_id: str = "") -> list[dict[str, Any]]:
        if name in self.beats_seen:
            return []
        self.beats_seen.add(name)
        return [{"type": "beat", "tree_id": tree, "name": name, "node_id": node_id}]

    def translate(self, rec: dict[str, Any]) -> list[dict[str, Any]]:
        tool = rec.get("tool")
        tree = self._tree(rec)
        if not tool or not tree:
            return []
        out: list[dict[str, Any]] = []
        if not self.phase_posted:
            self.phase_posted = True
            arm = rec.get("arm") or "fork"
            out.append({"type": "run", "tree_id": tree, "phase": f"agent-{arm}"})
        ok = bool(rec.get("ok"))
        result = rec.get("result") or {}
        args = rec.get("args") or {}
        rid = str(args.get("node_id") or rec.get("node_id") or "")
        node = self._node(rid)

        if not ok:
            err = _short(rec.get("error") or "tool error")
            out.append({"type": "error", "tree_id": tree, "node_id": node, "text": err})
            out.append(
                {"type": "meta", "tree_id": tree, "node_id": node,
                 "action": "error", "text": f"{tool}: {err}"}
            )
            return out

        if tool == "fork_batch":
            if self.topo:
                self.topo.fork(rid, [f["node_id"] for f in result.get("forks") or []])
            forks = result.get("forks") or []
            # One measured number: tree_fork_batch wall. Do not invent a
            # per-child by dividing — the daemon does not report that.
            ns = rec.get("latency_ns")
            if ns is None:
                ns = result.get("latency_ns")
            batch_ms = round(int(ns) / 1e6, 1) if ns is not None else None
            for f in forks:
                fid = self._node(f["node_id"])
                out.append(
                    {"type": "members", "tree_id": tree, "node_id": fid,
                     "guest_cids": f.get("guest_cids") or []}
                )
                cow_full = f.get("fork_memory_full_copy") or []
                out.append(
                    {"type": "latency", "tree_id": tree, "node_id": fid,
                     "parent_id": node,
                     "latency_ms": batch_ms,
                     "cow": [not x for x in cow_full] or [True]}
                )
                out.append(
                    {"type": "note", "tree_id": tree, "node_id": fid,
                     "text": f"hypothesis — forked from {rid}"}
                )
            out.extend(self._beat(tree, "fork", node))
            total = fmt_ms(ns) if ns is not None else "latency_ns missing"
            out.append(
                {"type": "meta", "tree_id": tree, "node_id": node, "action": "fork",
                 "text": f"fork {len(forks)} hypotheses from {rid} ({total})"}
            )
            return out

        if tool == "branch_exec":
            cmd = str(args.get("cmd") or "")
            code = (result or {}).get("exit_code")
            destructive = bool(rec.get("destructive"))
            on_source = bool(rec.get("on_source"))
            out.append(
                {"type": "cmd", "tree_id": tree, "node_id": node, "cmd": _short(cmd, 160),
                 "exit_code": code, "destructive": destructive, "on_source": on_source,
                 # per-member drill-down: which VM ran it and what it said
                 "member": args.get("member"),
                 "stdout": _short(str((result or {}).get("stdout") or ""), 4000),
                 "stderr": _short(str((result or {}).get("stderr") or ""), 1200)}
            )
            out.append(
                {"type": "trace", "tree_id": tree, "node_id": node, "role": "tool",
                 "text": f"$ {_short(cmd, 90)} → exit {code}"}
            )
            if destructive:
                self.fixed.add(rid)
            if destructive and on_source:
                out.extend(self._beat(tree, "remediate", node))
            elif destructive:
                out.extend(self._beat(tree, "try-fix", node))
            else:
                out.extend(self._beat(tree, "inspect", node))
            out.append(
                {"type": "meta", "tree_id": tree, "node_id": node, "action": "exec",
                 "text": f"$ {_short(cmd, 70)} on {rid}"
                         + (" (live source)" if on_source else "")}
            )
            return out

        if tool == "tetragon_diff":
            branch_only = result.get("branch_only") or []
            source_only = result.get("source_only") or []
            clean = bool(result.get("clean"))
            out.append(
                {"type": "verdict", "tree_id": tree, "node_id": node, "clean": clean,
                 "branch_only": len(branch_only), "source_only": len(source_only),
                 "sample": _short(branch_only[0] if branch_only else "", 140)}
            )
            # "verified" = a post-fix diff with no branch-only events: the
            # suspicious stream is gone on this branch.
            if rid in self.fixed and not branch_only:
                out.extend(self._beat(tree, "verified", node))
            if clean:
                text = f"diff {rid}: clean vs source"
            elif branch_only:
                text = f"diff {rid}: {len(branch_only)} new on branch"
            else:
                text = f"diff {rid}: {len(source_only)} events gone vs source"
            out.append(
                {"type": "meta", "tree_id": tree, "node_id": node,
                 "action": "tetragon", "text": text}
            )
            return out

        if tool in ("protect", "prune"):
            if self.topo:
                self.topo.verb(tool, rid)
            out.extend(self._beat(tree, tool, node))
            if tool == "protect":
                out.append(
                    {"type": "note", "tree_id": tree, "node_id": node,
                     "text": "protected — agent chose this branch"}
                )
            out.append(
                {"type": "meta", "tree_id": tree, "node_id": node,
                 "action": tool, "text": f"{tool} {rid}"}
            )
            return out

        if tool == "rollback":
            new_id = self._node(str(result.get("node_id") or ""))
            if new_id:
                out.append(
                    {"type": "members", "tree_id": tree, "node_id": new_id,
                     "guest_cids": result.get("guest_cids") or []}
                )
            out.append(
                {"type": "meta", "tree_id": tree, "node_id": new_id or node,
                 "action": "rollback", "text": f"rollback from {rid}"}
            )
            return out

        if tool == "tree_status":
            usage = rec.get("usage") or {}
            budget = rec.get("budget") or {}
            vms = usage.get("live_vm_count")
            cap = budget.get("max_live_vms")
            out.extend(self._beat(tree, "inspect", node))
            out.append(
                {"type": "meta", "tree_id": tree, "action": "status",
                 "text": f"tree_status — {vms}/{cap} live vms"}
            )
            return out

        out.append(
            {"type": "meta", "tree_id": tree, "node_id": node,
             "action": tool, "text": _short(json.dumps(args), 80)}
        )
        return out


def fmt_ms(ns: Any) -> str:
    ms = int(ns) / 1e6
    return f"{ms / 1000:.2f} s" if ms >= 1000 else f"{ms:.0f} ms"


def iter_follow(path: Path, from_start: bool) -> Any:
    """Yield appended JSONL lines forever (tail -f semantics)."""
    pos = 0 if from_start else (path.stat().st_size if path.exists() else 0)
    while True:
        if path.exists():
            size = path.stat().st_size
            if size < pos:
                pos = 0  # truncated / rotated
            if size > pos:
                with path.open("r", encoding="utf-8") as f:
                    f.seek(pos)
                    chunk = f.read()
                    pos = f.tell()
                for line in chunk.splitlines():
                    if line.strip():
                        yield line
        time.sleep(0.25)


def newest_jsonl(d: Path) -> Path | None:
    files = sorted(d.glob("*.jsonl"), key=lambda p: p.stat().st_mtime)
    return files[-1] if files else None


def run_follow(ns: argparse.Namespace, ingest_url: str) -> int:
    bridge = Bridge()
    if ns.dir:
        d = Path(ns.dir)
        current: Path | None = None
        gen = None
        print(f"[ingest-mcp] watching {d} for *.jsonl", flush=True)
        while True:
            latest = newest_jsonl(d)
            if latest and latest != current:
                current = latest
                bridge = Bridge()  # new run, new beats
                gen = iter_follow(current, ns.from_start)
                print(f"[ingest-mcp] following {current}", flush=True)
            if gen is None:
                time.sleep(0.5)
                continue
            drained = 0
            for line in gen:
                post(ingest_url, bridge.translate(json.loads(line)))
                drained += 1
                if drained >= 50:
                    break  # re-check for a newer file
            time.sleep(0.1)
    path = Path(ns.follow)
    print(f"[ingest-mcp] following {path}", flush=True)
    for line in iter_follow(path, ns.from_start):
        post(ingest_url, bridge.translate(json.loads(line)))
    return 0


def run_replay(ns: argparse.Namespace, ingest_url: str) -> int:
    path = Path(ns.replay)
    rows = [json.loads(x) for x in path.read_text().splitlines() if x.strip()]
    if not rows:
        raise SystemExit(f"no records in {path}")
    topo = StubTopo(ns.stub_socket) if ns.stub_socket else None
    bridge = Bridge(topo)
    print(
        f"[ingest-mcp] replaying {len(rows)} records from {path} "
        f"speed={ns.speed}x stub={'on' if topo else 'off'}",
        flush=True,
    )
    prev_ts: float | None = None
    for rec in rows:
        ts = float(rec.get("ts") or 0)
        if prev_ts is not None and ts > prev_ts:
            time.sleep(min(8.0, (ts - prev_ts) / max(0.1, ns.speed)))
        prev_ts = ts
        post(ingest_url, bridge.translate(rec))
    post(ingest_url, [{"type": "run", "tree_id": bridge._tree(rows[-1]), "phase": "idle"}])
    print("[ingest-mcp] replay done", flush=True)
    return 0


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    mode = ap.add_mutually_exclusive_group(required=True)
    mode.add_argument("--follow", help="tail one live JSONL")
    mode.add_argument("--dir", help="follow the newest *.jsonl in a directory")
    mode.add_argument("--replay", help="re-post a finished JSONL with pacing")
    ap.add_argument("--view", default=os.environ.get("K7VIEW_URL", "http://127.0.0.1:7474"))
    ap.add_argument("--speed", type=float, default=1.0, help="replay speed multiplier")
    ap.add_argument("--from-start", action="store_true", help="follow from byte 0")
    ap.add_argument(
        "--stub-socket",
        help="replay only: mirror topology onto gym/stub.py --k7d-socket PATH",
    )
    ns = ap.parse_args(argv)
    ingest_url = ns.view.rstrip("/") + "/api/ingest"
    if ns.replay:
        return run_replay(ns, ingest_url)
    return run_follow(ns, ingest_url)


if __name__ == "__main__":
    raise SystemExit(main())
