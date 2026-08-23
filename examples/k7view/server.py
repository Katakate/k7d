#!/usr/bin/env python3
"""k7view HTTP + SSE observer.

Polls the k7d control socket and serves the dashboard. Stdlib only.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, urlparse

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent / "cluster-tree-search"))

from k7d_client import K7dClient  # noqa: E402
from probe import RealProbe  # noqa: E402
from store import ViewStore  # noqa: E402

STATIC = HERE / "static"
MAX_SERIAL = 48 * 1024
ACTIONS = (
    "protect",
    "unprotect",
    "suspend",
    "resume",
    "prune",
    "auto_evict",
)


class Fanout:
    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._subs: list[Any] = []

    def subscribe(self) -> Any:
        q: list[bytes] = []
        cond = threading.Condition()
        with self._lock:
            self._subs.append((q, cond))
        return q, cond

    def unsubscribe(self, handle: Any) -> None:
        with self._lock:
            try:
                self._subs.remove(handle)
            except ValueError:
                pass

    def publish(self, obj: dict[str, Any]) -> None:
        raw = (f"data: {json.dumps(obj, separators=(',', ':'))}\n\n").encode()
        with self._lock:
            subs = list(self._subs)
        for q, cond in subs:
            with cond:
                q.append(raw)
                if len(q) > 400:
                    del q[:-200]
                cond.notify()


class App:
    def __init__(self, client: K7dClient, poll_ms: int) -> None:
        self.client = client
        self.poll_ms = poll_ms
        self.store = ViewStore()
        self.fanout = Fanout()
        self._stop = threading.Event()
        self.probe = RealProbe(self.store, self._ingest_probe)
        self._last_sig: tuple | None = None

    def _ingest_probe(self, items: list[dict[str, Any]]) -> None:
        return

    def _view_sig(self) -> tuple:
        parts: list[Any] = [self.store._seq, (self.store.run or {}).get("phase"), self.store.connected]
        for tid, slot in sorted(self.store.trees.items()):
            usage = slot.get("usage") or {}
            parts.append(
                (
                    tid,
                    usage.get("live_vm_count"),
                    usage.get("disk_bytes"),
                    usage.get("live_ram_bytes"),
                )
            )
            for nid, n in sorted((slot.get("nodes") or {}).items()):
                parts.append((nid, n.get("state"), n.get("protected"), n.get("dirty_page_count")))
        return tuple(parts)

    def emit(self, events: list[dict[str, Any]]) -> None:
        snap = self.store.snapshot()
        if events:
            self.fanout.publish({"kind": "events", "events": events, "state": snap})
        else:
            self.fanout.publish({"kind": "state", "state": snap})

    def poll_once(self) -> None:
        try:
            listed = self.client.tree_list()
            trees = listed.get("trees") or []
            self.store.connected = True
            self.store.error = None
            seen = {t.get("tree_id") for t in trees if t.get("tree_id")}
            events: list[dict[str, Any]] = []
            for t in trees:
                tid = t.get("tree_id")
                if not tid:
                    continue
                resp = self.client.tree_nodes(tid)
                nodes = resp.get("nodes") or []
                events.extend(
                    self.store.apply_snapshot(
                        tid,
                        nodes,
                        kind=t.get("kind") or "cluster",
                        usage=resp.get("usage") or t.get("usage"),
                        budget=resp.get("budget") or t.get("budget"),
                        live_guest_cids=resp.get("live_guest_cids"),
                    )
                )
            for tid in list(self.store.trees):
                if tid not in seen:
                    events.extend(self.store.drop_tree(tid))
            sig = self._view_sig()
            if events or sig != self._last_sig:
                self._last_sig = sig
                self.emit(events)
        except Exception as exc:  # noqa: BLE001 — surface to the UI
            self.store.connected = False
            self.store.error = str(exc)
            self.fanout.publish({"kind": "state", "state": self.store.snapshot()})

    def loop(self) -> None:
        while not self._stop.is_set():
            self.poll_once()
            self._stop.wait(self.poll_ms / 1000.0)

    def stop(self) -> None:
        self._stop.set()


def make_handler(app: App) -> type[BaseHTTPRequestHandler]:
    class Handler(BaseHTTPRequestHandler):
        def log_message(self, fmt: str, *args: Any) -> None:
            sys.stderr.write("%s - %s\n" % (self.address_string(), fmt % args))

        def _send(self, code: int, body: bytes, ctype: str) -> None:
            self.send_response(code)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(body)

        def _json(self, code: int, obj: Any) -> None:
            raw = json.dumps(obj).encode()
            self._send(code, raw, "application/json")

        def do_GET(self) -> None:  # noqa: N802
            path = urlparse(self.path).path
            if path in ("/", "/index.html"):
                self._send(200, (STATIC / "index.html").read_bytes(), "text/html; charset=utf-8")
                return
            if path.startswith("/static/"):
                rel = path[len("/static/") :]
                fp = (STATIC / rel).resolve()
                if not str(fp).startswith(str(STATIC.resolve())) or not fp.is_file():
                    self._send(404, b"not found", "text/plain")
                    return
                ctype = {
                    ".js": "text/javascript; charset=utf-8",
                    ".css": "text/css; charset=utf-8",
                    ".svg": "image/svg+xml",
                }.get(fp.suffix, "application/octet-stream")
                self._send(200, fp.read_bytes(), ctype)
                return
            if path == "/api/state":
                self._json(200, app.store.snapshot())
                return
            if path == "/api/serial":
                qs = parse_qs(urlparse(self.path).query)
                cid_s = (qs.get("cid") or [""])[0]
                if not cid_s:
                    self._json(400, {"error": "cid required"})
                    return
                try:
                    resp = app.client.dump_serial(guest_cid=int(cid_s))
                except Exception as exc:  # noqa: BLE001
                    self._json(400, {"error": str(exc)})
                    return
                text = resp.get("console") or ""
                if len(text) > MAX_SERIAL:
                    text = text[-MAX_SERIAL:]
                self._json(200, {"cid": int(cid_s), "console": text})
                return
            if path == "/api/events":
                self.send_response(200)
                self.send_header("Content-Type", "text/event-stream")
                self.send_header("Cache-Control", "no-store")
                self.send_header("Connection", "keep-alive")
                self.end_headers()
                handle = app.fanout.subscribe()
                q, cond = handle
                try:
                    hello = {
                        "kind": "state",
                        "state": app.store.snapshot(),
                    }
                    self.wfile.write(
                        f"data: {json.dumps(hello, separators=(',', ':'))}\n\n".encode()
                    )
                    self.wfile.flush()
                    while True:
                        with cond:
                            if not q:
                                cond.wait(timeout=20)
                            chunk = b"".join(q)
                            q.clear()
                        if chunk:
                            self.wfile.write(chunk)
                            self.wfile.flush()
                        else:
                            self.wfile.write(b": ping\n\n")
                            self.wfile.flush()
                except BrokenPipeError:
                    pass
                finally:
                    app.fanout.unsubscribe(handle)
                return
            self._send(404, b"not found", "text/plain")

        def do_POST(self) -> None:  # noqa: N802
            path = urlparse(self.path).path
            length = int(self.headers.get("Content-Length") or "0")
            raw = self.rfile.read(length) if length else b"{}"
            try:
                payload = json.loads(raw.decode() or "{}")
            except json.JSONDecodeError as exc:
                self._json(400, {"error": f"bad json: {exc}"})
                return
            if path == "/api/ingest":
                if isinstance(payload, list):
                    items = payload
                else:
                    items = [payload]
                events = []
                try:
                    for item in items:
                        events.append(app.store.ingest(item))
                except ValueError as exc:
                    self._json(400, {"error": str(exc)})
                    return
                app.emit(events)
                self._json(200, {"ok": True, "n": len(events)})
                return
            if path == "/api/action":
                op = str(payload.get("op") or "")
                tree_id = str(payload.get("tree_id") or "")
                node_id = str(payload.get("node_id") or "")
                if op not in ACTIONS:
                    self._json(400, {"error": f"unknown action: {op}"})
                    return
                if not tree_id:
                    self._json(400, {"error": "tree_id required"})
                    return
                if op != "auto_evict" and not node_id:
                    self._json(400, {"error": "node_id required"})
                    return
                try:
                    if op == "protect":
                        resp = app.client.tree_protect(tree_id, node_id)
                    elif op == "unprotect":
                        resp = app.client.tree_unprotect(tree_id, node_id)
                    elif op == "suspend":
                        resp = app.client.tree_suspend(tree_id, node_id)
                    elif op == "resume":
                        resp = app.client.tree_resume(tree_id, node_id)
                    elif op == "prune":
                        resp = app.client.tree_prune(tree_id, node_id)
                    else:
                        resp = app.client.tree_auto_evict(tree_id)
                except Exception as exc:  # noqa: BLE001
                    self._json(400, {"error": str(exc)})
                    return
                app.store.ingest(
                    {
                        "type": "meta",
                        "tree_id": tree_id,
                        "node_id": node_id,
                        "action": op,
                        "text": f"operator {op} {node_id or tree_id}",
                    }
                )
                app.poll_once()
                self._json(200, {"ok": True, "op": op, "resp": resp})
                return
            self._send(404, b"not found", "text/plain")

    return Handler


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--bind", default=os.environ.get("K7VIEW_BIND", "127.0.0.1"))
    ap.add_argument("--port", type=int, default=int(os.environ.get("K7VIEW_PORT", "7474")))
    ap.add_argument("--poll-ms", type=int, default=int(os.environ.get("K7VIEW_POLL_MS", "50")))
    ap.add_argument("--socket", default=os.environ.get("K7D_SOCKET", "/run/k7d/k7d.sock"))
    args = ap.parse_args()
    if not STATIC.is_dir():
        raise SystemExit(f"missing static dir: {STATIC}")
    app = App(K7dClient(args.socket), args.poll_ms)
    thread = threading.Thread(target=app.loop, name="k7view-poll", daemon=True)
    thread.start()
    app.probe.start()
    httpd = ThreadingHTTPServer((args.bind, args.port), make_handler(app))
    print(
        f"k7d-view http://{args.bind}:{args.port}/  socket={args.socket} "
        f"poll={args.poll_ms}ms vsock-probe=on",
        flush=True,
    )
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\nstopping", flush=True)
    finally:
        app.probe.stop()
        app.stop()
        httpd.server_close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
