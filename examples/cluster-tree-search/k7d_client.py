#!/usr/bin/env python3
"""Minimal JSON-lines client for the k7d control socket.

Not a product SDK — just enough for the cluster-tree-search demo
and the gym. `gym/server.py` imports this module (dependency points
gym → examples/; the demo does not import gym). Talks to `/run/k7d/k7d.sock`
(override with `K7D_SOCKET`). Failures are loud: non-`ok` /
unexpected status raise RuntimeError.
"""

from __future__ import annotations

import json
import os
import socket
from pathlib import Path
from typing import Any


DEFAULT_SOCKET = os.environ.get("K7D_SOCKET", "/run/k7d/k7d.sock")
TEST_TREE_MARKER = ".k7d-test-tree"
_TREE_CREATE_OPS = frozenset(
    {"tree_create", "tree_create_cluster", "tree_adopt_cluster"}
)


def mark_test_tree(tree_id: str) -> None:
    """Write `.k7d-test-tree` into the on-disk tree dir.

    The stranded-tree sweep reaps only marked dirs. Unmarked operator
    trees are never touched. A stub client that never creates a dir is
    a no-op here — the real daemon always leaves `{tree_root}/{id}`.
    """
    if not tree_id:
        raise RuntimeError("mark_test_tree: empty tree_id")
    roots = [Path("/var/lib/k7d/trees"), Path("/var/lib/k7d/disks/trees")]
    env = os.environ.get("K7D_TREE_ROOT")
    if env:
        roots.insert(0, Path(env))
    for root in roots:
        d = root / tree_id
        if d.is_dir():
            (d / TEST_TREE_MARKER).touch()
            return


class K7dClient:
    def __init__(
        self, path: str | Path = DEFAULT_SOCKET, timeout: float = 600
    ) -> None:
        self.path = str(path)
        self.timeout = timeout

    def call(
        self, req: dict[str, Any], timeout: float | None = None
    ) -> dict[str, Any]:
        payload = (json.dumps(req, separators=(",", ":")) + "\n").encode()
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as sock:
            sock.settimeout(self.timeout if timeout is None else timeout)
            sock.connect(self.path)
            sock.sendall(payload)
            # One JSON object per response line.
            buf = b""
            while b"\n" not in buf:
                chunk = sock.recv(65536)
                if not chunk:
                    break
                buf += chunk
        if not buf.strip():
            raise RuntimeError(f"empty response from {self.path} for {req.get('op')}")
        line = buf.split(b"\n", 1)[0]
        resp = json.loads(line.decode())
        status = resp.get("status")
        if status == "error":
            raise RuntimeError(f"{req.get('op')}: {resp.get('message')}")
        if req.get("op") in _TREE_CREATE_OPS:
            tid = resp.get("tree_id") or req.get("tree_id")
            if not tid:
                raise RuntimeError(
                    f"{req.get('op')} succeeded with no tree_id in request or reply"
                )
            mark_test_tree(str(tid))
        return resp

    def ping(self) -> dict[str, Any]:
        return self.call({"op": "ping"})

    def create_vm(
        self, config: dict[str, Any], *, timeout: float | None = 180
    ) -> dict[str, Any]:
        return self.call({"op": "create_vm", "config": config}, timeout=timeout)

    def stop_vm(self, vm_id: str) -> dict[str, Any]:
        return self.call({"op": "stop_vm", "vm_id": vm_id})

    def tree_create(
        self,
        config: dict[str, Any],
        *,
        tree_id: str | None = None,
        budget: dict[str, Any] | None = None,
        timeout: float | None = 300,
    ) -> dict[str, Any]:
        req: dict[str, Any] = {"op": "tree_create", "config": config}
        if tree_id is not None:
            req["tree_id"] = tree_id
        if budget is not None:
            req["budget"] = budget
        return self.call(req, timeout=timeout)

    def tree_create_cluster(
        self,
        vm_count: int,
        config: dict[str, Any],
        *,
        tree_id: str | None = None,
        budget: dict[str, Any] | None = None,
        timeout: float | None = 300,
    ) -> dict[str, Any]:
        req: dict[str, Any] = {
            "op": "tree_create_cluster",
            "vm_count": vm_count,
            "config": config,
        }
        if tree_id is not None:
            req["tree_id"] = tree_id
        if budget is not None:
            req["budget"] = budget
        return self.call(req, timeout=timeout)

    def tree_adopt_cluster(
        self,
        vm_ids: list[str],
        *,
        tree_id: str | None = None,
        budget: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        req: dict[str, Any] = {"op": "tree_adopt_cluster", "vm_ids": vm_ids}
        if tree_id is not None:
            req["tree_id"] = tree_id
        if budget is not None:
            req["budget"] = budget
        return self.call(req)

    def tree_fork_batch(
        self,
        tree_id: str,
        source_id: str,
        labels: list[str],
        timeout: float | None = 180,
        dilation: int | None = None,
    ) -> dict[str, Any]:
        req: dict[str, Any] = {
            "op": "tree_fork_batch",
            "tree_id": tree_id,
            "source_id": source_id,
            "labels": labels,
        }
        if dilation is not None:
            req["dilation"] = dilation
        return self.call(req, timeout=timeout)

    def tree_prepare_fork_source(
        self,
        tree_id: str,
        node_id: str,
        timeout: float | None = 300,
    ) -> dict[str, Any]:
        return self.call(
            {
                "op": "tree_prepare_fork_source",
                "tree_id": tree_id,
                "node_id": node_id,
            },
            timeout=timeout,
        )

    def tree_rollback(self, tree_id: str, node_id: str, label: str) -> dict[str, Any]:
        return self.call(
            {
                "op": "tree_rollback",
                "tree_id": tree_id,
                "node_id": node_id,
                "label": label,
            }
        )

    def tree_protect(self, tree_id: str, node_id: str) -> dict[str, Any]:
        return self.call(
            {"op": "tree_protect", "tree_id": tree_id, "node_id": node_id}
        )

    def tree_unprotect(self, tree_id: str, node_id: str) -> dict[str, Any]:
        return self.call(
            {"op": "tree_unprotect", "tree_id": tree_id, "node_id": node_id}
        )

    def tree_prune(self, tree_id: str, node_id: str) -> dict[str, Any]:
        return self.call(
            {"op": "tree_prune", "tree_id": tree_id, "node_id": node_id}
        )

    def tree_drop(self, tree_id: str) -> dict[str, Any]:
        return self.call({"op": "tree_drop", "tree_id": tree_id})

    def tree_open(self, tree_id: str) -> dict[str, Any]:
        return self.call({"op": "tree_open", "tree_id": tree_id})

    def tree_nodes(self, tree_id: str) -> dict[str, Any]:
        return self.call({"op": "tree_nodes", "tree_id": tree_id})

    def tree_list(self) -> dict[str, Any]:
        return self.call({"op": "tree_list"})

    def tree_auto_evict(self, tree_id: str) -> dict[str, Any]:
        return self.call({"op": "tree_auto_evict", "tree_id": tree_id})

    def tree_suspend(self, tree_id: str, node_id: str) -> dict[str, Any]:
        return self.call({"op": "tree_suspend", "tree_id": tree_id, "node_id": node_id})

    def tree_resume(self, tree_id: str, node_id: str) -> dict[str, Any]:
        return self.call({"op": "tree_resume", "tree_id": tree_id, "node_id": node_id})

    def dump_serial(
        self, *, vm_id: str | None = None, guest_cid: int | None = None
    ) -> dict[str, Any]:
        req: dict[str, Any] = {"op": "dump_serial"}
        if vm_id is not None:
            req["vm_id"] = vm_id
        if guest_cid is not None:
            req["guest_cid"] = guest_cid
        return self.call(req)

    def list_vms(self) -> dict[str, Any]:
        return self.call({"op": "list_vms"})

    def auto_warp(self, cluster_id: str, mode: str) -> dict[str, Any]:
        """Start, switch, or stop a cluster's auto-warp loop.

        ``mode`` is ``off`` | ``jump`` | ``micro``. ``off`` returns the
        finished run's counters.
        """
        return self.call(
            {"op": "auto_warp", "cluster_id": cluster_id, "mode": mode}
        )

    def auto_warp_status(self, cluster_id: str) -> dict[str, Any]:
        return self.call({"op": "auto_warp_status", "cluster_id": cluster_id})

    def auto_warp_hold(
        self, cluster_id: str, holder: str, hold: bool
    ) -> dict[str, Any]:
        """Fifth safety check: gym exec over vsock must hold first."""
        return self.call(
            {
                "op": "auto_warp_hold",
                "cluster_id": cluster_id,
                "holder": holder,
                "hold": hold,
            }
        )
