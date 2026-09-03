"""MCP tool implementations. Talk to k7d over the Unix socket only."""

from __future__ import annotations

import os
import secrets
import sys
import time
from pathlib import Path
from typing import Any

HERE = Path(__file__).resolve().parent
REPO = HERE.parents[1]
sys.path.insert(0, str(REPO / "examples" / "cluster-tree-search"))
sys.path.insert(0, str(REPO / "gym"))

from k7d_client import K7dClient  # noqa: E402

import agent  # noqa: E402
from host import k7_bridge_name, list_bridges  # noqa: E402
from logutil import JsonlLog  # noqa: E402
from mutation import looks_destructive as _looks_destructive  # noqa: E402
from scoring import curl_api  # noqa: E402

TETRAGON_NS = "kube-system"
TETRAGON_LABEL = "app.kubernetes.io/name=tetragon"


class ToolError(RuntimeError):
    """Loud tool failure. Never retried by this layer."""


class K7dMcp:
    def __init__(
        self,
        client: K7dClient,
        *,
        tree_id: str,
        log: JsonlLog,
        no_fork: bool = False,
        source_node: str = "root",
        certs_dir: Path | None = None,
        guest_ip: str = "10.200.0.2",
    ) -> None:
        self.client = client
        self.tree_id = tree_id
        self.log = log
        self.no_fork = no_fork
        self.source_node = source_node
        self.certs_dir = Path(certs_dir) if certs_dir else None
        self.guest_ip = guest_ip

    def _usage_snapshot(self) -> tuple[dict[str, Any], dict[str, Any]]:
        if not self.tree_id:
            return {}, {}
        try:
            resp = self.client.tree_nodes(self.tree_id)
        except RuntimeError:
            return {}, {}
        return dict(resp.get("usage") or {}), dict(resp.get("budget") or {})

    def _record(
        self,
        tool: str,
        args: dict[str, Any],
        t0: float,
        *,
        ok: bool,
        error: str | None,
        result: Any,
        extra: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        usage, budget = self._usage_snapshot()
        rec = {
            "tool": tool,
            "args": args,
            "ok": ok,
            "error": error,
            "latency_s": time.perf_counter() - t0,
            "usage": usage,
            "budget": budget,
            "tree_id": self.tree_id,
            "result": result,
        }
        if extra:
            rec.update(extra)
        self.log.append(rec)
        return rec

    def _require_tree(self) -> None:
        if not self.tree_id:
            raise ToolError("K7D_TREE_ID is required (no silent tree pick)")

    def _forbid_fork(self, tool: str) -> None:
        if self.no_fork:
            raise ToolError(
                f"baseline arm: {tool} disabled (only branch_exec on the live source)"
            )

    def _nodes(self) -> dict[str, Any]:
        self._require_tree()
        return self.client.tree_nodes(self.tree_id)

    def _cids(self, node_id: str) -> list[int]:
        resp = self._nodes()
        live = resp.get("live_guest_cids") or {}
        raw = live.get(node_id)
        if not raw:
            raise ToolError(f"no live guest_cids for node {node_id!r}")
        return [int(c) for c in raw]

    def _ids(self) -> set[str]:
        return {n["id"] for n in (self._nodes().get("nodes") or [])}

    def tree_status(self) -> dict[str, Any]:
        t0 = time.perf_counter()
        try:
            listing = self.client.tree_list()
            detail = None
            if self.tree_id:
                try:
                    detail = self.client.tree_nodes(self.tree_id)
                except RuntimeError as e:
                    raise ToolError(str(e)) from e
            result = {"trees": listing.get("trees") or [], "tree": detail}
            self._record("tree_status", {}, t0, ok=True, error=None, result=result)
            return result
        except Exception as e:
            self._record("tree_status", {}, t0, ok=False, error=str(e), result=None)
            raise

    def fork_batch(self, node_id: str, n: int) -> dict[str, Any]:
        t0 = time.perf_counter()
        args = {"node_id": node_id, "n": n}
        try:
            self._require_tree()
            self._forbid_fork("fork_batch")
            if n < 1:
                raise ToolError(f"fork_batch n must be >= 1, got {n}")
            if node_id not in self._ids():
                raise ToolError(f"no such node: {node_id}")
            # Unordered ids — a trailing -0 was an accidental "favorite" cue.
            labels = [f"hyp-{secrets.token_hex(4)}" for _ in range(n)]
            resp = self.client.tree_fork_batch(self.tree_id, node_id, labels)
            result = {
                "forks": resp.get("forks") or [],
                "latency_ns": resp.get("latency_ns"),
                "labels": labels,
            }
            extra = {
                "latency_ns": resp.get("latency_ns"),
                "node_id": node_id,
                "destructive": False,
                "on_source": False,
            }
            self._record(
                "fork_batch", args, t0, ok=True, error=None, result=result, extra=extra
            )
            return result
        except Exception as e:
            self._record("fork_batch", args, t0, ok=False, error=str(e), result=None)
            raise

    def branch_exec(self, node_id: str, member: int, cmd: str) -> dict[str, Any]:
        t0 = time.perf_counter()
        args = {"node_id": node_id, "member": member, "cmd": cmd}
        try:
            self._require_tree()
            if self.no_fork and node_id != self.source_node:
                raise ToolError(
                    f"baseline arm: branch_exec only allowed on source "
                    f"{self.source_node!r}, got {node_id!r}"
                )
            if node_id not in self._ids():
                raise ToolError(f"no such node: {node_id}")
            if member < 0:
                raise ToolError(f"member must be >= 0, got {member}")
            if not cmd or not str(cmd).strip():
                raise ToolError("branch_exec cmd must be non-empty")
            if os.environ.get("K7D_MCP_STUB_EXEC"):
                result = {
                    "stdout": f"stub-exec {node_id} member={member} {cmd}",
                    "stderr": "",
                    "exit_code": 0,
                    "guest_cid": 0,
                }
            else:
                cids = self._cids(node_id)
                if member >= len(cids):
                    raise ToolError(
                        f"member {member} out of range for {node_id} (have {len(cids)})"
                    )
                cid = cids[member]
                # Long enough to soak past a timer-based reseeder (the
                # `dormant` incident's layers fire at ~75-90s), so a
                # `sleep 120; recheck` confirmation completes instead of
                # timing out mid-soak. Only reached on a genuinely stuck
                # command; normal execs return in well under a second.
                r = agent.exec_cmd(cid, ["sh", "-c", cmd], timeout_s=240)
                result = {
                    "stdout": r["stdout"],
                    "stderr": r["stderr"],
                    "exit_code": r["exit_code"],
                    "guest_cid": cid,
                }
            extra = {
                "node_id": node_id,
                "destructive": _looks_destructive(cmd),
                "on_source": node_id == self.source_node,
            }
            self._record(
                "branch_exec", args, t0, ok=True, error=None, result=result, extra=extra
            )
            return result
        except Exception as e:
            self._record("branch_exec", args, t0, ok=False, error=str(e), result=None)
            raise

    def tetragon_diff(self, node_id: str) -> dict[str, Any]:
        t0 = time.perf_counter()
        args = {"node_id": node_id}
        try:
            self._require_tree()
            if node_id not in self._ids():
                raise ToolError(f"no such node: {node_id}")
            if os.environ.get("K7D_MCP_STUB_EXEC"):
                result = {
                    "source_only": [],
                    "branch_only": [
                        "process_kprobe policy=k7d-kprobe-fd-install path=/tmp/k7d-tetra-child"
                    ],
                    "source_lines": 1,
                    "branch_lines": 1,
                    "clean": False,
                }
            else:
                src = _tetragon_events(
                    self._bridge(self.source_node),
                    self.certs_dir,
                    self.guest_ip,
                )
                br = _tetragon_events(
                    self._bridge(node_id), self.certs_dir, self.guest_ip
                )
                src_set, br_set = set(src.splitlines()), set(br.splitlines())
                result = {
                    "source_only": sorted(src_set - br_set)[:80],
                    "branch_only": sorted(br_set - src_set)[:80],
                    "source_lines": len(src_set),
                    "branch_lines": len(br_set),
                    "clean": not (br_set - src_set) and not (src_set - br_set),
                }
            extra = {"node_id": node_id, "destructive": False, "on_source": False}
            self._record(
                "tetragon_diff", args, t0, ok=True, error=None, result=result, extra=extra
            )
            return result
        except Exception as e:
            self._record("tetragon_diff", args, t0, ok=False, error=str(e), result=None)
            raise

    def protect(self, node_id: str) -> dict[str, Any]:
        return self._verb("protect", node_id, self.client.tree_protect)

    def prune(self, node_id: str) -> dict[str, Any]:
        return self._verb("prune", node_id, self.client.tree_prune)

    def rollback(self, node_id: str, label: str | None = None) -> dict[str, Any]:
        t0 = time.perf_counter()
        lab = label or f"rb-{int(time.time())}"
        args = {"node_id": node_id, "label": lab}
        try:
            self._require_tree()
            self._forbid_fork("rollback")
            if node_id not in self._ids():
                raise ToolError(f"no such node: {node_id}")
            resp = self.client.tree_rollback(self.tree_id, node_id, lab)
            extra = {
                "latency_ns": resp.get("latency_ns"),
                "node_id": node_id,
                "destructive": False,
                "on_source": False,
            }
            self._record(
                "rollback", args, t0, ok=True, error=None, result=resp, extra=extra
            )
            return resp
        except Exception as e:
            self._record("rollback", args, t0, ok=False, error=str(e), result=None)
            raise

    def _verb(self, name: str, node_id: str, fn: Any) -> dict[str, Any]:
        t0 = time.perf_counter()
        args = {"node_id": node_id}
        try:
            self._require_tree()
            self._forbid_fork(name)
            if node_id not in self._ids():
                raise ToolError(f"no such node: {node_id}")
            resp = fn(self.tree_id, node_id)
            extra = {
                "node_id": node_id,
                "destructive": name == "prune",
                "on_source": node_id == self.source_node,
            }
            self._record(name, args, t0, ok=True, error=None, result=resp, extra=extra)
            return resp if isinstance(resp, dict) else {"status": "ok"}
        except Exception as e:
            self._record(name, args, t0, ok=False, error=str(e), result=None)
            raise

    def _bridge(self, node_id: str) -> str:
        if node_id == self.source_node:
            cluster_id = self.tree_id
        else:
            cluster_id = f"{self.tree_id}-{node_id}"
        name = k7_bridge_name(cluster_id)
        visible = list_bridges()
        if name not in visible and not os.environ.get("K7D_MCP_STUB_EXEC"):
            raise ToolError(
                f"bridge {name} for node {node_id} is not on the host "
                f"(k7-br-*={sorted(visible)})"
            )
        return name


def _tetragon_events(bridge: str, certs_dir: Path | None, guest_ip: str) -> str:
    if certs_dir is None:
        raise ToolError("certs_dir required for tetragon_diff (host kubeconfig pair)")
    cert, key = certs_dir / "client.pem", certs_dir / "client-key.pem"
    if not cert.is_file() or not key.is_file():
        raise ToolError(f"missing certs in {certs_dir}")
    selector = TETRAGON_LABEL.replace("/", "%2F").replace("=", "%3D")
    code, body, err = curl_api(
        bridge,
        f"/api/v1/namespaces/{TETRAGON_NS}/pods?labelSelector={selector}",
        guest_ip=guest_ip,
        cert=cert,
        key=key,
        timeout_s=20,
    )
    if code >= 400:
        raise ToolError(f"list tetragon pods via {bridge}: http={code} {err} {body[:200]}")
    import json

    try:
        items = (json.loads(body) or {}).get("items") or []
    except json.JSONDecodeError as e:
        raise ToolError(f"tetragon pods json: {e}") from e
    names = [p.get("metadata", {}).get("name") for p in items]
    names = [n for n in names if n]
    if not names:
        raise ToolError(f"no tetragon pods via {bridge}: {body[:300]}")
    chunks: list[str] = []
    for name in names:
        for container in ("export-stdout", "tetragon"):
            path = (
                f"/api/v1/namespaces/{TETRAGON_NS}/pods/{name}/log"
                f"?container={container}&tailLines=20000"
            )
            c, text, e = curl_api(
                bridge, path, guest_ip=guest_ip, cert=cert, key=key, timeout_s=20
            )
            if c < 400:
                chunks.append(text)
    return "\n".join(chunks)
