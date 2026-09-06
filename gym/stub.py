#!/usr/bin/env python3
"""Fake gym HTTP server for router tests. No k7d, no fork.

Implements the frozen gym contract well enough that ``gym/router.py``
can place groups, proxy act/obs/score/release, and see a 503 drain.
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import signal
import socket
import sys
import threading
import time
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any
from urllib.parse import urlparse

log = logging.getLogger("gym-stub")


class Stub:
    def __init__(self, node_id: str, token: str | None, drain_file: str) -> None:
        self.node_id = node_id
        self.token = token
        self.drain_file = drain_file
        self.leases: dict[str, dict[str, Any]] = {}
        self.envs: dict[str, str] = {}
        self.lock = threading.Lock()
        self._drained = False

    def drained(self) -> bool:
        if self._drained:
            return True
        if self.drain_file and os.path.exists(self.drain_file):
            return True
        return False

    def mark_drained(self) -> None:
        self._drained = True

    def healthz(self) -> tuple[int, dict[str, Any]]:
        if self.drained():
            return 503, {
                "ok": False,
                "k7d": "unavailable",
                "error": "stub drained",
                "leases_in_flight": len(self.leases),
                "max_leases": 4,
            }
        return 200, {
            "ok": True,
            "k7d": "ready",
            "free_ram_bytes": 64 * 1024**3,
            "leases_in_flight": len(self.leases),
            "max_leases": 4,
        }

    def lease(self, body: dict[str, Any]) -> dict[str, Any]:
        for key in ("fault_id", "n", "group_id", "ttl_s"):
            if key not in body:
                raise ValueError(f"POST /lease missing {key}")
        n = int(body["n"])
        if n < 1:
            raise ValueError(f"n must be >= 1, got {n}")
        lid = f"lease-{uuid.uuid4().hex[:12]}"
        envs = []
        for i in range(n):
            eid = f"{lid}-env-{i}"
            envs.append(
                {
                    "env_id": eid,
                    "branch_node_id": f"br-{i}",
                    "index": i,
                    "bridge": f"k7-br-stub{i}",
                    "guest_ips": ["10.200.0.2", "10.200.0.3", "10.200.0.4"],
                }
            )
        rec = {
            "lease_id": lid,
            "node_id": self.node_id,
            "tree_id": f"gym-src-stub-{self.node_id}",
            "source_node_id": "root",
            "group_id": str(body["group_id"]),
            "fault_id": str(body["fault_id"]),
            "good_fix_hint": {},
            "inject_ms": 0.0,
            "envs": envs,
            "expires_at": time.time() + float(body["ttl_s"]),
        }
        with self.lock:
            self.leases[lid] = rec
            for e in envs:
                self.envs[e["env_id"]] = lid
        return {k: rec[k] for k in rec if k != "expires_at"} | {"inject_ms": 0.0}

    def get_lease(self, lid: str) -> dict[str, Any] | None:
        with self.lock:
            rec = self.leases.get(lid)
            return dict(rec) if rec else None

    def act(self, env_id: str, body: dict[str, Any]) -> dict[str, Any]:
        with self.lock:
            if env_id not in self.envs:
                raise KeyError(f"no such env: {env_id}")
        return {
            "ok": True,
            "stdout": f"stub-act {self.node_id} {body.get('action')}",
            "stderr": "",
            "exit_code": 0,
            "elapsed_ms": 0.1,
            "node_id": self.node_id,
        }

    def obs(self, env_id: str) -> dict[str, Any]:
        with self.lock:
            if env_id not in self.envs:
                raise KeyError(f"no such env: {env_id}")
        observation = {"stub": True, "node_id": self.node_id, "env_id": env_id}
        packed = json.dumps(observation, separators=(",", ":"))
        return {
            "observation": observation,
            "truncated_bytes": 0,
            "byte_count": len(packed),
            "node_id": self.node_id,
        }

    def score(self, lid: str) -> dict[str, Any]:
        rec = self.get_lease(lid)
        if rec is None:
            raise KeyError(f"no such lease: {lid}")
        scores = []
        for e in rec["envs"]:
            scores.append(
                {
                    "env_id": e["env_id"],
                    "reward": 1.0,
                    "terms": {
                        "liveness": 1.0,
                        "workload_ready": 1.0,
                        "source_intact": 1.0,
                        "contained": 1.0,
                        "restored": 1.0,
                    },
                }
            )
        return {"scores": scores, "node_id": self.node_id}

    def fork(self, env_id: str, body: dict[str, Any]) -> dict[str, Any]:
        if "n" not in body:
            raise ValueError("POST /env/{id}/fork missing n")
        n = int(body["n"])
        if n < 1:
            raise ValueError(f"n must be >= 1, got {n}")
        labels = body.get("labels")
        if labels is not None and (
            not isinstance(labels, list) or len(labels) != n
        ):
            raise ValueError(f"labels length must equal n={n}")
        with self.lock:
            lid = self.envs.get(env_id)
            if lid is None:
                raise KeyError(f"no such env: {env_id}")
            rec = self.leases[lid]
            start = max(int(e["index"]) for e in rec["envs"]) + 1
            children = []
            for i in range(n):
                idx = start + i
                eid = f"{lid}-env-{idx}"
                child = {
                    "env_id": eid,
                    "branch_node_id": f"br-{idx}",
                    "index": idx,
                    "bridge": f"k7-br-stub{idx}",
                    "guest_ips": ["10.200.0.2", "10.200.0.3", "10.200.0.4"],
                    "guest_cids": [100 + idx, 101 + idx, 102 + idx],
                }
                rec["envs"].append(child)
                self.envs[eid] = lid
                children.append(child)
        return {
            "envs": children,
            "parent_env_id": env_id,
            "lease_id": lid,
        }

    def prepare(self, env_id: str) -> dict[str, Any]:
        with self.lock:
            lid = self.envs.get(env_id)
            if lid is None:
                raise KeyError(f"no such env: {env_id}")
            rec = self.leases[lid]
            node_id = ""
            for e in rec["envs"]:
                if e["env_id"] == env_id:
                    node_id = str(e.get("branch_node_id") or "")
                    break
        return {
            "ok": True,
            "env_id": env_id,
            "lease_id": lid,
            "node_id": node_id,
            "prepare_s": 0.0,
        }

    def release(self, lid: str) -> dict[str, Any]:
        with self.lock:
            rec = self.leases.pop(lid, None)
            if rec is None:
                raise KeyError(f"no such lease: {lid}")
            for e in rec["envs"]:
                self.envs.pop(e["env_id"], None)
        return {
            "released": True,
            "pruned": [e["branch_node_id"] for e in rec["envs"]],
            "residue": {
                "bridges": [],
                "taps": [],
                "tree_node_ids": [],
                "errors": [],
            },
            "node_id": self.node_id,
        }


class Handler(BaseHTTPRequestHandler):
    stub: Stub

    def log_message(self, fmt: str, *args: Any) -> None:
        log.info("%s %s", self.address_string(), fmt % args)

    def _read_json(self) -> dict[str, Any]:
        length = int(self.headers.get("Content-Length") or "0")
        raw = self.rfile.read(length) if length else b"{}"
        if not raw:
            return {}
        data = json.loads(raw.decode())
        if not isinstance(data, dict):
            raise ValueError("JSON body must be an object")
        return data

    def _auth(self) -> bool:
        token = self.stub.token
        if not token:
            return True
        if self.headers.get("X-Gym-Token") != token:
            self._send(401, {"error": "missing or wrong X-Gym-Token"})
            return False
        return True

    def _send(self, code: int, body: dict[str, Any]) -> None:
        body.setdefault("node_id", self.stub.node_id)
        payload = json.dumps(body, separators=(",", ":")).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def do_GET(self) -> None:  # noqa: N802
        if not self._auth():
            return
        path = urlparse(self.path).path
        if path == "/healthz":
            code, body = self.stub.healthz()
            self._send(code, body)
            return
        if path.startswith("/lease/"):
            lid = path[len("/lease/") :]
            rec = self.stub.get_lease(lid)
            if rec is None:
                self._send(404, {"error": f"no such lease: {lid}"})
                return
            self._send(200, rec)
            return
        self._send(404, {"error": f"no such path: {path}"})

    def do_POST(self) -> None:  # noqa: N802
        if not self._auth():
            return
        path = urlparse(self.path).path
        try:
            body = self._read_json()
        except (ValueError, json.JSONDecodeError) as e:
            self._send(400, {"error": f"bad json: {e}"})
            return
        try:
            if path == "/lease":
                self._send(200, self.stub.lease(body))
                return
            if path == "/__drain":
                self.stub.mark_drained()
                self._send(200, {"drained": True})
                return
            if path.endswith("/act") and path.startswith("/env/"):
                env_id = path[len("/env/") : -len("/act")]
                self._send(200, self.stub.act(env_id, body))
                return
            if path.endswith("/obs") and path.startswith("/env/"):
                env_id = path[len("/env/") : -len("/obs")]
                self._send(200, self.stub.obs(env_id))
                return
            if path.endswith("/prepare") and path.startswith("/env/"):
                env_id = path[len("/env/") : -len("/prepare")]
                self._send(200, self.stub.prepare(env_id))
                return
            if path.endswith("/fork") and path.startswith("/env/"):
                env_id = path[len("/env/") : -len("/fork")]
                self._send(200, self.stub.fork(env_id, body))
                return
            if path.endswith("/score") and path.startswith("/lease/"):
                lid = path[len("/lease/") : -len("/score")]
                self._send(200, self.stub.score(lid))
                return
            if path.endswith("/release") and path.startswith("/lease/"):
                lid = path[len("/lease/") : -len("/release")]
                self._send(200, self.stub.release(lid))
                return
            self._send(404, {"error": f"no such path: {path}"})
        except KeyError as e:
            self._send(404, {"error": str(e)})
        except ValueError as e:
            self._send(400, {"error": str(e)})
        except Exception as e:
            log.exception("POST %s", path)
            self._send(500, {"error": str(e)})


class K7dSocketStub:
    """Unix-socket k7d control-plane stub for MCP tests. No KVM.

    Speaks the same JSON-lines protocol as `/run/k7d/k7d.sock` for the
    tree verbs the MCP server wraps. Unknown ops and bad node ids are
    loud `status=error` replies — never a silent ok.
    """

    TREE_ID = "stub-tree"
    SOURCE = "root"

    def __init__(self) -> None:
        now = int(time.time())
        self._lock = threading.Lock()
        self._seq = 0
        self.budget = {
            "max_live_vms": 24,
            "max_live_ram_bytes": 64 * 1024**3,
            "max_disk_bytes": 256 * 1024**3,
            "max_chain_depth": 32,
        }
        self.nodes: dict[str, dict[str, Any]] = {
            self.SOURCE: {
                "id": self.SOURCE,
                "parent": None,
                "children": [],
                "state": "Live",
                "dirty_page_count": 0,
                "has_base_snapshot": True,
                "label": "source",
                "created_at_unix": now,
                "last_active_at_unix": now,
                "protected": True,
                "kind": "Cluster",
                "vm_count": 3,
            }
        }
        self.cids: dict[str, list[int]] = {self.SOURCE: [3, 4, 5]}
        self.events: dict[str, list[str]] = {
            self.SOURCE: [
                "process_kprobe policy=k7d-kprobe-fd-install path=/tmp/k7d-tetra-source"
            ]
        }

    def usage(self) -> dict[str, Any]:
        live = [n for n in self.nodes.values() if n.get("state") == "Live"]
        live_vms = sum(int(n.get("vm_count") or 0) for n in live)
        return {
            "live_vm_count": live_vms,
            "live_ram_bytes": live_vms * 2048 * 1024 * 1024,
            "disk_bytes": live_vms * 64 * 1024 * 1024,
            "total_nodes": len(self.nodes),
            "live_node_count": len(live),
        }

    def handle(self, req: dict[str, Any]) -> dict[str, Any]:
        op = req.get("op")
        if not op:
            return {"status": "error", "message": "request missing op"}
        with self._lock:
            if op == "ping":
                return {"status": "pong", "version": "stub"}
            if op == "tree_list":
                return {
                    "status": "tree_list",
                    "trees": [
                        {
                            "tree_id": self.TREE_ID,
                            "kind": "cluster",
                            "nodes": len(self.nodes),
                            "usage": self.usage(),
                            "budget": self.budget,
                        }
                    ],
                }
            if op == "tree_nodes":
                tid = req.get("tree_id")
                if tid != self.TREE_ID:
                    return {"status": "error", "message": f"no such tree: {tid}"}
                return {
                    "status": "tree_node_list",
                    "nodes": list(self.nodes.values()),
                    "usage": self.usage(),
                    "budget": self.budget,
                    "live_guest_cids": {k: list(v) for k, v in self.cids.items()},
                }
            if op == "tree_prepare_fork_source":
                nid, err = self._need_node(req)
                if err:
                    return err
                return {"status": "ok", "node_id": nid}
            if op == "tree_fork_batch":
                return self._fork_batch(req)
            if op == "tree_protect":
                return self._mutate(req, protected=True)
            if op == "tree_unprotect":
                return self._mutate(req, protected=False)
            if op == "tree_prune":
                return self._prune(req)
            if op == "tree_rollback":
                return self._rollback(req)
            if op == "tree_drop":
                tid = req.get("tree_id")
                if tid != self.TREE_ID:
                    return {"status": "error", "message": f"no such tree: {tid}"}
                self.nodes = {}
                self.cids = {}
                return {"status": "ok"}
            if op == "auto_warp":
                mode = req.get("mode")
                if mode not in ("off", "jump", "micro"):
                    return {
                        "status": "error",
                        "message": f"auto_warp: mode must be off|jump|micro, got {mode!r}",
                    }
                return {
                    "status": "auto_warp",
                    "cluster_id": req.get("cluster_id"),
                    "mode": mode,
                    "holders": [],
                    "stats": {},
                }
            if op == "auto_warp_status":
                return {
                    "status": "auto_warp",
                    "cluster_id": req.get("cluster_id"),
                    "mode": "off",
                    "holders": [],
                    "stats": {},
                }
            if op == "auto_warp_hold":
                return {
                    "status": "auto_warp",
                    "cluster_id": req.get("cluster_id"),
                    "mode": "off",
                    "holders": [req.get("holder")] if req.get("hold") else [],
                    "stats": {},
                }
            if op == "dump_serial":
                return {
                    "status": "serial_dump",
                    "vm_id": "stub",
                    "guest_cid": int(req.get("guest_cid") or 0),
                    "console": "stub-serial",
                }
            return {"status": "error", "message": f"unknown op: {op}"}

    def _need_node(self, req: dict[str, Any]) -> tuple[str | None, dict[str, Any] | None]:
        tid = req.get("tree_id")
        nid = req.get("node_id") or req.get("source_id")
        if tid != self.TREE_ID:
            return None, {"status": "error", "message": f"no such tree: {tid}"}
        if nid not in self.nodes:
            return None, {"status": "error", "message": f"no such node: {nid}"}
        return str(nid), None

    def _fork_batch(self, req: dict[str, Any]) -> dict[str, Any]:
        nid, err = self._need_node(req)
        if err:
            return err
        assert nid is not None
        labels = req.get("labels")
        if not isinstance(labels, list) or not labels:
            return {"status": "error", "message": "tree_fork_batch: labels must be non-empty"}
        forks = []
        parent = self.nodes[nid]
        for label in labels:
            self._seq += 1
            child = f"br-{self._seq}"
            now = int(time.time())
            self.nodes[child] = {
                "id": child,
                "parent": nid,
                "children": [],
                "state": "Live",
                "dirty_page_count": 0,
                "has_base_snapshot": False,
                "label": str(label),
                "created_at_unix": now,
                "last_active_at_unix": now,
                "protected": False,
                "kind": "Cluster",
                "vm_count": 3,
            }
            parent.setdefault("children", []).append(child)
            self.cids[child] = [30 + self._seq, 31 + self._seq, 32 + self._seq]
            self.events[child] = [
                "process_kprobe policy=k7d-kprobe-fd-install path=/tmp/k7d-tetra-child"
            ]
            forks.append(
                {
                    "node_id": child,
                    "guest_cids": list(self.cids[child]),
                    "fork_memory_full_copy": [False, False, False],
                    "latency_ns": 1_100_000_000,
                }
            )
        return {
            "status": "tree_fork_batch",
            "forks": forks,
            "latency_ns": 1_100_000_000,
        }

    def _mutate(self, req: dict[str, Any], *, protected: bool) -> dict[str, Any]:
        nid, err = self._need_node(req)
        if err:
            return err
        assert nid is not None
        self.nodes[nid]["protected"] = protected
        return {"status": "ok"}

    def _prune(self, req: dict[str, Any]) -> dict[str, Any]:
        nid, err = self._need_node(req)
        if err:
            return err
        assert nid is not None
        doomed = [nid]
        stack = list(self.nodes[nid].get("children") or [])
        while stack:
            cur = stack.pop()
            doomed.append(cur)
            stack.extend(self.nodes.get(cur, {}).get("children") or [])
        parent_id = self.nodes[nid].get("parent")
        if parent_id and parent_id in self.nodes:
            kids = self.nodes[parent_id].get("children") or []
            self.nodes[parent_id]["children"] = [c for c in kids if c != nid]
        for d in doomed:
            self.nodes.pop(d, None)
            self.cids.pop(d, None)
            self.events.pop(d, None)
        return {"status": "ok"}

    def _rollback(self, req: dict[str, Any]) -> dict[str, Any]:
        nid, err = self._need_node(req)
        if err:
            return err
        label = req.get("label")
        if not label:
            return {"status": "error", "message": "tree_rollback: label required"}
        return self._fork_batch(
            {
                "tree_id": req.get("tree_id"),
                "source_id": nid,
                "labels": [str(label)],
            }
        )


def serve_k7d_socket(path: str) -> None:
    """Accept one JSON-line request per connection, like k7d."""
    if os.path.exists(path):
        os.unlink(path)
    stub = K7dSocketStub()
    sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    sock.bind(path)
    sock.listen(16)
    print(f"STUB_K7D_SOCKET={path}", flush=True)
    log.info("k7d stub listening on %s", path)

    def stop(signum: int, _frame: Any) -> None:
        log.info("signal %s", signum)
        try:
            sock.close()
        except OSError:
            pass

    signal.signal(signal.SIGTERM, stop)
    signal.signal(signal.SIGINT, stop)
    try:
        while True:
            try:
                conn, _ = sock.accept()
            except OSError:
                break
            with conn:
                buf = b""
                while b"\n" not in buf:
                    chunk = conn.recv(65536)
                    if not chunk:
                        break
                    buf += chunk
                if not buf.strip():
                    continue
                try:
                    req = json.loads(buf.split(b"\n", 1)[0].decode())
                    if not isinstance(req, dict):
                        resp = {"status": "error", "message": "JSON body must be an object"}
                    else:
                        resp = stub.handle(req)
                except (json.JSONDecodeError, ValueError) as e:
                    resp = {"status": "error", "message": f"bad json: {e}"}
                conn.sendall((json.dumps(resp, separators=(",", ":")) + "\n").encode())
    finally:
        try:
            sock.close()
        except OSError:
            pass
        try:
            os.unlink(path)
        except FileNotFoundError:
            pass


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    env = os.environ
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--bind", default=env.get("GYM_BIND", "127.0.0.1"))
    p.add_argument("--port", type=int, default=int(env.get("GYM_PORT", "0")))
    p.add_argument(
        "--node-id", default=env.get("GYM_NODE_ID") or f"stub-{os.getpid()}"
    )
    p.add_argument("--token", default=env.get("GYM_TOKEN", ""))
    p.add_argument(
        "--drain-file", default=env.get("GYM_STUB_DRAIN_FILE", "")
    )
    p.add_argument(
        "--k7d-socket",
        default=env.get("GYM_STUB_K7D_SOCKET", ""),
        help="If set, speak the k7d JSON-lines protocol on this Unix socket "
        "(MCP tests). HTTP gym stub is not started.",
    )
    return p.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )
    ns = parse_args(argv)
    if ns.k7d_socket:
        serve_k7d_socket(ns.k7d_socket)
        return 0
    stub = Stub(ns.node_id, ns.token or None, ns.drain_file)
    Handler.stub = stub
    httpd = ThreadingHTTPServer((ns.bind, ns.port), Handler)
    host, port = httpd.server_address[:2]
    print(f"STUB_LISTEN={host}:{port}", flush=True)
    log.info("stub listening on %s:%s node_id=%s", host, port, ns.node_id)

    def stop(signum: int, _frame: Any) -> None:
        log.info("signal %s", signum)
        threading.Thread(target=httpd.shutdown, daemon=True).start()

    signal.signal(signal.SIGTERM, stop)
    signal.signal(signal.SIGINT, stop)
    try:
        httpd.serve_forever()
    finally:
        httpd.server_close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
