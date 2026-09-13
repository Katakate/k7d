#!/usr/bin/env python3
"""Time Ubuntu 3-node prepare for the GRPO checkpoint.

`tree_adopt_cluster` is the real prepare (`new_cluster` calls
`prepare_fork_source_in` on every member). The later
`tree_prepare_fork_source` RPC is an idempotent no-op if adopt already
wrote the base — we time both so that is visible.

Talks only to `/run/k7d/k7d.sock`. Ubuntu CreateVm × 3. No new k7d
primitives.
"""

from __future__ import annotations

import json
import logging
import os
import sys
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
REPO = HERE.parent
sys.path.insert(0, str(HERE))
sys.path.insert(0, str(REPO / "examples" / "cluster-tree-search"))

from fork_under_load import Cluster  # noqa: E402
from k7d_client import K7dClient  # noqa: E402

log = logging.getLogger("prep")


def _memory_bins(tree_id: str) -> list[dict[str, int | str]]:
    root = Path("/var/lib/k7d/trees") / tree_id / "nodes" / "root" / "members"
    out: list[dict[str, int | str]] = []
    if not root.is_dir():
        return out
    for member in sorted(root.iterdir()):
        mem = member / "memory.bin"
        if mem.is_file():
            out.append({"path": str(mem), "bytes": mem.stat().st_size})
    return out


def main() -> int:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    tree_id = f"prep-{os.getpid()}"
    client = K7dClient()
    client.ping()
    cluster = Cluster(client, tree_id)
    result: dict[str, object] = {"tree_id": tree_id}
    try:
        t_boot = time.perf_counter()
        cluster.bring_up(prepare=False)
        result["bring_up_without_rpc_s"] = round(time.perf_counter() - t_boot, 3)
        # adopt already prepared. This RPC should be wrote_base=false.
        t_rpc = time.perf_counter()
        prep = client.tree_prepare_fork_source(tree_id, cluster.root_id, timeout=300)
        result["prepare_rpc_s"] = round(time.perf_counter() - t_rpc, 3)
        result["prepare_rpc"] = {
            "wrote_base": prep.get("wrote_base"),
            "latency_ns": prep.get("latency_ns"),
            "latency_s": (int(prep["latency_ns"]) / 1e9) if prep.get("latency_ns") is not None else None,
        }
        bins = _memory_bins(tree_id)
        result["memory_bins"] = bins
        result["memory_bin_bytes_sum"] = sum(int(b["bytes"]) for b in bins)
        t_fork = time.perf_counter()
        batch = client.tree_fork_batch(tree_id, cluster.root_id, ["fresh"], timeout=180)
        result["fork_immediate_s"] = round(time.perf_counter() - t_fork, 3)
        forks = list(batch.get("forks") or [])
        result["fork_latency_ns"] = forks[0].get("latency_ns") if forks else None
        usage = client.tree_nodes(tree_id)
        u = usage.get("usage") or {}
        result["post_fork_usage"] = {
            "live_vm_count": u.get("live_vm_count"),
            "live_ram_bytes": u.get("live_ram_bytes"),
        }
        print("PREP_MEASURE " + json.dumps(result, separators=(",", ":")), flush=True)
    finally:
        cluster.teardown()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
