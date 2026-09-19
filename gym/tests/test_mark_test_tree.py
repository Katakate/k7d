"""`.k7d-test-tree` marker helper — no KVM."""

from __future__ import annotations

import os
import sys
import tempfile
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parents[1]
REPO = HERE.parent
sys.path.insert(0, str(REPO / "examples" / "cluster-tree-search"))

from k7d_client import TEST_TREE_MARKER, mark_test_tree  # noqa: E402


class TestMarkTestTree(unittest.TestCase):
    def test_writes_marker_into_tree_dir(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            tree = root / "gym-src-test"
            tree.mkdir()
            old = os.environ.get("K7D_TREE_ROOT")
            os.environ["K7D_TREE_ROOT"] = str(root)
            try:
                mark_test_tree("gym-src-test")
            finally:
                if old is None:
                    os.environ.pop("K7D_TREE_ROOT", None)
                else:
                    os.environ["K7D_TREE_ROOT"] = old
            self.assertTrue((tree / TEST_TREE_MARKER).is_file())

    def test_empty_id_is_loud(self) -> None:
        with self.assertRaises(RuntimeError):
            mark_test_tree("")


if __name__ == "__main__":
    unittest.main()
