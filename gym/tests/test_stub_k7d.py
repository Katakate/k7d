"""k7d Unix-socket stub used by examples/k7d-mcp. No KVM."""

from __future__ import annotations

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from stub import K7dSocketStub  # noqa: E402


class TestK7dSocketStub(unittest.TestCase):
    def test_tree_verbs_and_loud_errors(self) -> None:
        s = K7dSocketStub()
        self.assertEqual(s.handle({"op": "ping"})["status"], "pong")
        listing = s.handle({"op": "tree_list"})
        self.assertEqual(listing["trees"][0]["tree_id"], s.TREE_ID)
        nodes = s.handle({"op": "tree_nodes", "tree_id": s.TREE_ID})
        self.assertIn("usage", nodes)
        self.assertIn("budget", nodes)
        prep = s.handle(
            {
                "op": "tree_prepare_fork_source",
                "tree_id": s.TREE_ID,
                "node_id": "root",
            }
        )
        self.assertEqual(prep["status"], "ok")
        batch = s.handle(
            {
                "op": "tree_fork_batch",
                "tree_id": s.TREE_ID,
                "source_id": "root",
                "labels": ["a", "b"],
            }
        )
        self.assertEqual(len(batch["forks"]), 2)
        nid = batch["forks"][0]["node_id"]
        self.assertEqual(
            s.handle({"op": "tree_protect", "tree_id": s.TREE_ID, "node_id": nid})[
                "status"
            ],
            "ok",
        )
        err = s.handle({"op": "tree_prune", "tree_id": s.TREE_ID, "node_id": "nope"})
        self.assertEqual(err["status"], "error")
        self.assertIn("no such node", err["message"])
        unknown = s.handle({"op": "explode"})
        self.assertEqual(unknown["status"], "error")
        self.assertIn("unknown op", unknown["message"])


if __name__ == "__main__":
    unittest.main()
