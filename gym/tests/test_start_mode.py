"""GYM_START_MODE=reset guards — no KVM."""

from __future__ import annotations

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from budget import reset_need
from ubuntu import NODE_MEMORY_MB


class TestResetNeed(unittest.TestCase):
    def test_reset_n8_is_not_cow(self) -> None:
        # Fork n=8 over 3 VMs is 3+24=27. Reset is 8×3=24 full clusters,
        # no shared source, no CoW RSS (~0.6 GiB) admission.
        need = reset_need(
            n=8,
            vms_per_branch=3,
            memory_bytes_per_vm=2048 * 1024 * 1024,
            max_live_vms=27,
            max_live_ram_bytes=27 * 2048 * 1024 * 1024,
        )
        self.assertEqual(need.needed_vms, 24)
        self.assertIsNone(need.rejection())

    def test_fork_sized_default_8_vms_is_loud(self) -> None:
        need = reset_need(
            n=3,
            vms_per_branch=3,
            memory_bytes_per_vm=2048 * 1024 * 1024,
            max_live_vms=8,
            max_live_ram_bytes=64 * 1024**3,
        )
        msg = need.rejection()
        self.assertIsNotNone(msg)
        assert msg is not None
        self.assertIn("reset is not CoW", msg)
        self.assertIn("need 9 live VMs", msg)
        self.assertIn("n=3 × 3", msg)
        self.assertIn("fork-sized", msg)

    def test_cow_rss_budget_is_loud(self) -> None:
        # ~0.6 GiB RSS per 3-node fork × n=2 + 1.14 GiB source ≈ 2.3 GiB.
        cow = int(2.4 * 1024**3)
        need = reset_need(
            n=2,
            vms_per_branch=3,
            memory_bytes_per_vm=2048 * 1024 * 1024,
            max_live_vms=64,
            max_live_ram_bytes=cow,
        )
        msg = need.rejection()
        self.assertIsNotNone(msg)
        assert msg is not None
        self.assertIn("reset is not CoW", msg)
        self.assertIn(str(6 * 2048 * 1024 * 1024), msg)


class TestResetFlag(unittest.TestCase):
    def test_reset_without_measurement_ack_is_loud(self) -> None:
        import server

        ns = server.parse_args(
            [
                "--source-mode",
                "ubuntu",
                "--memory-mb",
                "2048",
                "--start-mode",
                "reset",
            ]
        )
        with self.assertRaises(SystemExit) as ctx:
            server.Config(ns)
        self.assertIn("measurement-only", str(ctx.exception))
        self.assertIn("GYM_RESET_MEASUREMENT", str(ctx.exception))

    def test_reset_requires_ubuntu(self) -> None:
        import server

        ns = server.parse_args(
            [
                "--source-mode",
                "create",
                "--start-mode",
                "reset",
                "--reset-measurement",
            ]
        )
        with self.assertRaises(SystemExit) as ctx:
            server.Config(ns)
        self.assertIn("ubuntu", str(ctx.exception))

    def test_reset_ack_ubuntu_starts(self) -> None:
        import server

        ns = server.parse_args(
            [
                "--source-mode",
                "ubuntu",
                "--memory-mb",
                str(NODE_MEMORY_MB),
                "--start-mode",
                "reset",
                "--reset-measurement",
                "--max-live-vms",
                "64",
            ]
        )
        cfg = server.Config(ns)
        self.assertEqual(cfg.start_mode, "reset")
        self.assertTrue(cfg.reset_measurement)

    def test_unknown_start_mode_is_loud(self) -> None:
        import server

        ns = server.parse_args(["--start-mode", "fork"])
        ns.start_mode = "snapshot"
        with self.assertRaises(SystemExit) as ctx:
            server.Config(ns)
        self.assertIn("fork|reset", str(ctx.exception))


if __name__ == "__main__":
    unittest.main()
