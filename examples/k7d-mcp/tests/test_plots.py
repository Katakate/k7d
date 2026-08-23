"""plots.py renders the five inc1 figures from synthetic JSONL. No KVM."""

from __future__ import annotations

import json
import sys
import tempfile
import time
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(HERE))

import plots  # noqa: E402


def _rec(**kw):
    base = {
        "ts": time.time(),
        "arm": "fork",
        "run_id": "syn",
        "ok": True,
        "error": None,
        "latency_s": 0.01,
        "usage": {
            "live_vm_count": 3,
            "live_ram_bytes": 3 * 2048 * 1024 * 1024,
            "disk_bytes": 0,
            "total_nodes": 1,
            "live_node_count": 1,
        },
        "budget": {
            "max_live_vms": 24,
            "max_live_ram_bytes": 64 * 1024**3,
            "max_disk_bytes": 1,
            "max_chain_depth": 32,
        },
        "tree_id": "t",
        "result": {},
    }
    base.update(kw)
    return base


class TestPlots(unittest.TestCase):
    def test_five_plots_from_jsonl(self) -> None:
        t0 = time.time()
        rows = [
            _rec(ts=t0, tool="tree_status"),
            _rec(
                ts=t0 + 1,
                tool="fork_batch",
                latency_ns=1_100_000_000,
                result={"forks": [{"node_id": "a"}, {"node_id": "b"}]},
                usage={
                    "live_vm_count": 9,
                    "live_ram_bytes": 6 * 2048 * 1024 * 1024,
                    "disk_bytes": 0,
                    "total_nodes": 3,
                    "live_node_count": 3,
                },
            ),
            _rec(
                ts=t0 + 2,
                tool="branch_exec",
                destructive=True,
                on_source=False,
                args={"cmd": "kubectl delete pod x"},
            ),
            _rec(ts=t0 + 3, tool="prune", destructive=True, on_source=False),
            _rec(
                ts=t0 + 10,
                tool="tree_status",
                arm="baseline",
                usage={
                    "live_vm_count": 3,
                    "live_ram_bytes": 3 * 2048 * 1024 * 1024,
                    "disk_bytes": 0,
                    "total_nodes": 1,
                    "live_node_count": 1,
                },
            ),
            _rec(
                ts=t0 + 12,
                tool="branch_exec",
                arm="baseline",
                destructive=True,
                on_source=True,
                args={"cmd": "kubectl delete pod x"},
            ),
        ]
        with tempfile.TemporaryDirectory() as td:
            src = Path(td) / "run.jsonl"
            src.write_text("".join(json.dumps(r) + "\n" for r in rows))
            out = Path(td) / "plots"
            written = plots.render(plots.load_jsonl([src]), out)
            names = {p.name for p in written}
            self.assertEqual(names, set(plots.PLOTS))
            for p in written:
                self.assertGreater(p.stat().st_size, 100)


if __name__ == "__main__":
    unittest.main()
