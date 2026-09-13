"""Held-session harness guards — no KVM."""

from __future__ import annotations

import sys
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import held_session as hs


class TestHeldSessionYaml(unittest.TestCase):
    def test_listen_yaml_pins_busybox_and_fifo_keep(self) -> None:
        y = hs.listen_yaml("hs-listen", 9376)
        self.assertIn(hs.BUSYBOX, y)
        self.assertIn("nc -l -p 9376", y)
        self.assertIn("trap '' HUP", y)
        self.assertIn("/tmp/tcp-in", y)
        self.assertIn("nodeName: k7d-10-200-0-2", y)

    def test_hold_yaml_refuses_empty_cluster_ip(self) -> None:
        with self.assertRaises(RuntimeError):
            hs.hold_yaml("hs-hold", "", 9376, "before-fork")
        with self.assertRaises(RuntimeError):
            hs.hold_yaml("hs-hold", "None", 9376, "before-fork")

    def test_hold_yaml_is_one_pipe_not_a_new_nc(self) -> None:
        y = hs.hold_yaml("hs-hold", "10.43.0.10", 9376, "before-fork")
        self.assertIn("echo before-fork", y)
        self.assertIn("cat /tmp/hold-in", y)
        self.assertIn("nc 10.43.0.10 9376", y)
        self.assertEqual(y.count(" | nc "), 1)

    def test_exec_bg_refuses_heredoc_collision(self) -> None:
        with self.assertRaises(RuntimeError):
            hs.exec_bg(1, "hs-listen", "echo\nEOS\nbad", "LISTENING")

    def test_main_refuses_wrong_tree_prefix(self) -> None:
        with patch.object(hs, "K7dClient", MagicMock()):
            with self.assertRaises(RuntimeError) as ctx:
                hs.main(["--tree-id", "ful-nope"])
        self.assertIn("hs-", str(ctx.exception))
