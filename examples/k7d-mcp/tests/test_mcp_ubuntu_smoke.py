"""Ubuntu end-to-end MCP smoke: fork n=2, exec, tetragon_diff, prune.

Runs on the bare-metal node under `make gym-test` / `make remote-check`.
No skip, no #[ignore]. Teardown prunes+drops the tree in finally.
"""

from __future__ import annotations

import os
import sys
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parents[1]
REPO = HERE.parents[1]
sys.path.insert(0, str(HERE))
sys.path.insert(0, str(REPO / "gym"))
sys.path.insert(0, str(REPO / "examples" / "cluster-tree-search"))

from host import list_bridges, list_taps  # noqa: E402
from k7d_client import K7dClient  # noqa: E402
from logutil import JsonlLog  # noqa: E402
from tools import K7dMcp  # noqa: E402

import cluster as cl  # noqa: E402
from scenario_incident import scripted_smoke  # noqa: E402

SOCKET = os.environ.get("K7D_SOCKET", "/run/k7d/k7d.sock")


class TestMcpUbuntuSmoke(unittest.TestCase):
    def test_fork_exec_diff_prune_zero_residue(self) -> None:
        if not Path(SOCKET).exists():
            raise RuntimeError(
                f"k7d socket absent: {SOCKET} (probe the node; do not skip)"
            )
        client = K7dClient(SOCKET, timeout=600)
        pong = client.ping()
        if pong.get("status") != "pong":
            raise RuntimeError(f"k7d ping failed: {pong}")
        tree_id = f"k7mcp-smoke-{os.getpid()}"
        log_path = Path(f"/tmp/{tree_id}.jsonl")
        cluster = None
        before_bridges = list_bridges()
        before_taps = list_taps()
        try:
            cluster = cl.bring_up(
                client,
                tree_id=tree_id,
                repo=REPO,
                victim=False,
                install_cni=True,
                install_tetragon=True,
            )
            mcp = K7dMcp(
                client,
                tree_id=tree_id,
                log=JsonlLog(log_path, arm="fork", run_id=tree_id),
                no_fork=False,
                source_node="root",
                certs_dir=cluster.certs_dir,
            )
            forks = scripted_smoke(mcp)
            self.assertEqual(len(forks), 2)
            leftover = [
                n["id"]
                for n in (client.tree_nodes(tree_id).get("nodes") or [])
                if n["id"] != "root"
            ]
            self.assertEqual(leftover, [], leftover)
        finally:
            if cluster is not None:
                residue = cl.teardown(client, cluster)
                self.assertEqual(residue["tree_node_ids"], [], residue)
                ours = [
                    b
                    for b in residue["bridges"]
                    if b not in before_bridges
                ]
                self.assertEqual(ours, [], residue)
            after_bridges = list_bridges() - before_bridges
            after_taps = list_taps() - before_taps
            self.assertEqual(after_bridges, set(), after_bridges)
            self.assertEqual(after_taps, set(), after_taps)


if __name__ == "__main__":
    unittest.main()
