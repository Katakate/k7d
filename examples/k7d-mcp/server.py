#!/usr/bin/env python3
"""stdio MCP server wrapping the k7d tree API.

k7d itself grows no TCP — this is a node-local sidecar talking to
`/run/k7d/k7d.sock` via `k7d_client.py`. Unknown tools / bad node ids
are loud errors; this process does not retry daemon failures.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
REPO = HERE.parents[1]
sys.path.insert(0, str(HERE))
sys.path.insert(0, str(REPO / "examples" / "cluster-tree-search"))

from k7d_client import K7dClient  # noqa: E402
from logutil import JsonlLog  # noqa: E402
from tools import K7dMcp, ToolError  # noqa: E402

try:
    from mcp.server import MCPServer
except ImportError as e:  # pragma: no cover - pin is mcp==2.0.0
    raise SystemExit(
        f"mcp SDK missing or too old ({e}); pip install -r {HERE / 'requirements.txt'}"
    ) from e


def _mcp() -> K7dMcp:
    socket = os.environ.get("K7D_SOCKET", "/run/k7d/k7d.sock")
    tree_id = os.environ.get("K7D_TREE_ID", "")
    log_path = os.environ.get("K7D_MCP_LOG", str(HERE / "logs" / "mcp.jsonl"))
    arm = os.environ.get("K7D_MCP_ARM", "fork")
    run_id = os.environ.get("K7D_MCP_RUN_ID", f"run-{os.getpid()}")
    no_fork = os.environ.get("K7D_NO_FORK", "") in ("1", "true", "yes")
    source = os.environ.get("K7D_SOURCE_NODE", "root")
    certs = os.environ.get("K7D_CERTS_DIR") or None
    return K7dMcp(
        K7dClient(socket),
        tree_id=tree_id,
        log=JsonlLog(log_path, arm=arm, run_id=run_id),
        no_fork=no_fork,
        source_node=source,
        certs_dir=Path(certs) if certs else None,
    )


TOOLS: K7dMcp | None = None
SERVER = MCPServer("k7d")


def bind(mcp: K7dMcp) -> None:
    """Inject the backend (tests). Production uses env via `_tools()`."""
    global TOOLS
    TOOLS = mcp


def _tools() -> K7dMcp:
    if TOOLS is None:
        bind(_mcp())
    assert TOOLS is not None
    return TOOLS


@SERVER.tool()
def tree_status() -> dict:
    """List trees and the current tree's nodes, usage, and TreeBudget."""
    return _tools().tree_status()


@SERVER.tool()
def fork_batch(node_id: str, n: int) -> dict:
    """Warm-fork `n` hypotheses from `node_id`. Returns branch ids + latency_ns."""
    return _tools().fork_batch(node_id, int(n))


@SERVER.tool()
def branch_exec(node_id: str, member: int, cmd: str) -> dict:
    """Run a shell command on one member of one branch (guest-agent exec)."""
    return _tools().branch_exec(node_id, int(member), cmd)


@SERVER.tool()
def tetragon_diff(node_id: str) -> dict:
    """Diff Tetragon event streams of `node_id` vs the live source."""
    return _tools().tetragon_diff(node_id)


@SERVER.tool()
def protect(node_id: str) -> dict:
    """Mark a node protected from auto-eviction."""
    return _tools().protect(node_id)


@SERVER.tool()
def prune(node_id: str) -> dict:
    """Prune a node and its descendants."""
    return _tools().prune(node_id)


@SERVER.tool()
def rollback(node_id: str, label: str | None = None) -> dict:
    """Non-destructive rollback: fork a new branch from `node_id`."""
    return _tools().rollback(node_id, label)


def main() -> int:
    try:
        SERVER.run()
    except ToolError as e:
        print(str(e), file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
