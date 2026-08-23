"""MCP tool round-trip against gym/stub.py --k7d-socket. No KVM."""

from __future__ import annotations

import asyncio
import json
import os
import socket
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parents[1]
REPO = HERE.parents[1]
sys.path.insert(0, str(HERE))
sys.path.insert(0, str(REPO / "examples" / "cluster-tree-search"))
sys.path.insert(0, str(REPO / "gym"))

from k7d_client import K7dClient  # noqa: E402
from logutil import JsonlLog  # noqa: E402
from tools import K7dMcp, ToolError  # noqa: E402

os.environ.setdefault("K7D_MCP_STUB_EXEC", "1")


def _wait_socket(path: str, ceiling_s: float = 5) -> None:
    deadline = time.monotonic() + ceiling_s
    while time.monotonic() < deadline:
        if os.path.exists(path):
            try:
                with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as s:
                    s.settimeout(0.2)
                    s.connect(path)
                    return
            except OSError:
                time.sleep(0.05)
                continue
        time.sleep(0.05)
    raise RuntimeError(f"stub socket never accepted: {path}")


class TestMcpStub(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.sock = str(Path(self.tmp.name) / "k7d.sock")
        self.log_path = Path(self.tmp.name) / "mcp.jsonl"
        self.proc = subprocess.Popen(
            [
                sys.executable,
                str(REPO / "gym" / "stub.py"),
                "--k7d-socket",
                self.sock,
            ],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        try:
            _wait_socket(self.sock)
        except Exception:
            self.proc.kill()
            raise
        os.environ["K7D_SOCKET"] = self.sock
        os.environ["K7D_TREE_ID"] = "stub-tree"
        os.environ["K7D_MCP_STUB_EXEC"] = "1"
        self.client = K7dClient(self.sock, timeout=5)
        self.mcp = K7dMcp(
            self.client,
            tree_id="stub-tree",
            log=JsonlLog(self.log_path, arm="fork", run_id="stub"),
            no_fork=False,
            certs_dir=None,
        )

    def tearDown(self) -> None:
        self.proc.terminate()
        try:
            self.proc.wait(timeout=3)
        except subprocess.TimeoutExpired:
            self.proc.kill()
        for stream in (self.proc.stdout, self.proc.stderr):
            if stream is not None:
                stream.close()
        self.tmp.cleanup()

    def test_every_tool_and_jsonl(self) -> None:
        st = self.mcp.tree_status()
        self.assertTrue(st["trees"])
        self.assertIn("usage", st["tree"])
        self.assertIn("budget", st["tree"])
        batch = self.mcp.fork_batch("root", 2)
        self.assertEqual(len(batch["forks"]), 2)
        for lab in batch["labels"]:
            self.assertRegex(lab, r"^hyp-[0-9a-f]{8}$")
        self.assertEqual(batch["latency_ns"], 1_100_000_000)
        a, b = batch["forks"][0]["node_id"], batch["forks"][1]["node_id"]
        ex = self.mcp.branch_exec(a, 0, "uname -a")
        self.assertEqual(ex["exit_code"], 0)
        self.assertIn("stub-exec", ex["stdout"])
        diff = self.mcp.tetragon_diff(a)
        self.assertIn("branch_only", diff)
        self.mcp.protect(a)
        self.mcp.rollback("root", "rb-test")
        self.mcp.prune(b)
        lines = [
            json.loads(x)
            for x in self.log_path.read_text().splitlines()
            if x.strip()
        ]
        tools = [r["tool"] for r in lines]
        for name in (
            "tree_status",
            "fork_batch",
            "branch_exec",
            "tetragon_diff",
            "protect",
            "rollback",
            "prune",
        ):
            self.assertIn(name, tools)
        for r in lines:
            self.assertIn("latency_s", r)
            self.assertIn("usage", r)

    def test_bad_node_and_unknown_op_are_loud(self) -> None:
        with self.assertRaises(ToolError) as ctx:
            self.mcp.fork_batch("does-not-exist", 1)
        self.assertIn("no such node", str(ctx.exception))
        with self.assertRaises(RuntimeError) as ctx2:
            self.client.call({"op": "not_a_real_op"})
        self.assertIn("unknown op", str(ctx2.exception))
        with self.assertRaises(ToolError):
            self.mcp.branch_exec("root", 0, "")

    def test_baseline_arm_blocks_forks(self) -> None:
        base = K7dMcp(
            self.client,
            tree_id="stub-tree",
            log=JsonlLog(self.log_path, arm="baseline", run_id="stub-b"),
            no_fork=True,
        )
        with self.assertRaises(ToolError) as ctx:
            base.fork_batch("root", 1)
        self.assertIn("baseline arm", str(ctx.exception))
        with self.assertRaises(ToolError):
            base.protect("root")
        with self.assertRaises(ToolError):
            base.branch_exec("someone-else", 0, "true")
        ok = base.branch_exec("root", 0, "true")
        self.assertEqual(ok["exit_code"], 0)

    def test_mcp_protocol_roundtrip(self) -> None:
        import server as srv

        srv.bind(self.mcp)
        try:
            from mcp import Client
        except ImportError as e:
            raise RuntimeError(
                f"mcp SDK not installed: {e} (pip install -r {HERE / 'requirements.txt'})"
            ) from e

        async def _run() -> None:
            async with Client(srv.SERVER) as client:
                listed = await client.list_tools()
                names = {t.name for t in listed.tools}
                for want in (
                    "tree_status",
                    "fork_batch",
                    "branch_exec",
                    "tetragon_diff",
                    "protect",
                    "prune",
                    "rollback",
                ):
                    self.assertIn(want, names)
                st = await client.call_tool("tree_status", {})
                text = _tool_text(st)
                self.assertIn("stub-tree", text)
                bad = await client.call_tool(
                    "fork_batch", {"node_id": "nope", "n": 1}
                )
                self.assertTrue(
                    getattr(bad, "is_error", False)
                    or "no such node" in _tool_text(bad)
                )

        asyncio.run(_run())


def _tool_text(result: object) -> str:
    parts = []
    content = getattr(result, "content", None) or []
    for c in content:
        parts.append(getattr(c, "text", "") or str(c))
    structured = getattr(result, "structured_content", None)
    if structured:
        parts.append(json.dumps(structured))
    return "\n".join(parts)


if __name__ == "__main__":
    unittest.main()
