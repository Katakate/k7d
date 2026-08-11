#!/usr/bin/env python3
"""Minimal JSON-lines client for the k7d control socket.

Not a product SDK — just enough for the cluster-tree-search demo.
Talks to `/run/k7d/k7d.sock` (override with `K7D_SOCKET`).
Failures are loud: non-`ok` / unexpected status raise RuntimeError.
"""

from __future__ import annotations

import json
import os
import socket
from pathlib import Path
from typing import Any


DEFAULT_SOCKET = os.environ.get("K7D_SOCKET", "/run/k7d/k7d.sock")


class K7dClient:
    def __init__(self, path: str | Path = DEFAULT_SOCKET) -> None:
        self.path = str(path)

    def call(self, req: dict[str, Any]) -> dict[str, Any]:
        payload = (json.dumps(req, separators=(",", ":")) + "\n").encode()
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as sock:
            sock.settimeout(600)
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
        return resp

    def ping(self) -> dict[str, Any]:
        return self.call({"op": "ping"})

    def tree_create_cluster(
        self,
        vm_count: int,
        config: dict[str, Any],
        *,
        tree_id: str | None = None,
        budget: dict[str, Any] | None = None,
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
        return self.call(req)

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
        self, tree_id: str, source_id: str, labels: list[str]
    ) -> dict[str, Any]:
        return self.call(
            {
                "op": "tree_fork_batch",
                "tree_id": tree_id,
                "source_id": source_id,
                "labels": labels,
            }
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

    def tree_nodes(self, tree_id: str) -> dict[str, Any]:
        return self.call({"op": "tree_nodes", "tree_id": tree_id})

    def list_vms(self) -> dict[str, Any]:
        return self.call({"op": "list_vms"})
