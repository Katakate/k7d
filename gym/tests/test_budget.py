"""Budget arithmetic — no KVM."""

from __future__ import annotations

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from budget import (
    DEFAULT_TREE_MAX_LIVE_VMS,
    lease_need,
    tree_budget,
)


class TestLeaseNeed(unittest.TestCase):
    def test_group_of_8_over_3vm_blows_default_budget(self) -> None:
        need = lease_need(
            n=8,
            vms_per_branch=3,
            source_vms=3,
            live_already=3,
            max_live_vms=DEFAULT_TREE_MAX_LIVE_VMS,
            memory_bytes_per_vm=256 * 1024 * 1024,
            max_live_ram_bytes=8 * 1024 * 1024 * 1024,
        )
        self.assertEqual(need.needed_live_vms, 27)
        msg = need.rejection()
        self.assertIsNotNone(msg)
        assert msg is not None
        self.assertIn("need 27 live VMs", msg)
        self.assertIn("source=3", msg)
        self.assertIn("n=8 * vms_per_branch=3", msg)
        self.assertIn("max_live_vms=8", msg)

    def test_n4_fits_64(self) -> None:
        need = lease_need(
            n=4,
            vms_per_branch=3,
            source_vms=3,
            live_already=3,
            max_live_vms=64,
            memory_bytes_per_vm=256 * 1024 * 1024,
            max_live_ram_bytes=64 * 1024**3,
        )
        self.assertEqual(need.needed_live_vms, 15)
        self.assertIsNone(need.rejection())

    def test_in_flight_leases_count(self) -> None:
        need = lease_need(
            n=8,
            vms_per_branch=3,
            source_vms=3,
            live_already=3 + 12,  # source + one n=4 group
            max_live_vms=32,
            memory_bytes_per_vm=256 * 1024 * 1024,
            max_live_ram_bytes=64 * 1024**3,
        )
        # 15 already + 24 incoming = 39 > 32
        self.assertEqual(need.needed_live_vms, 39)
        msg = need.rejection()
        self.assertIsNotNone(msg)
        assert msg is not None
        self.assertIn("already_leased=12", msg)

    def test_ram_rejection_spells_bytes(self) -> None:
        need = lease_need(
            n=4,
            vms_per_branch=3,
            source_vms=3,
            live_already=3,
            max_live_vms=64,
            memory_bytes_per_vm=256 * 1024 * 1024,
            max_live_ram_bytes=1024,  # absurdly small
        )
        msg = need.rejection()
        self.assertIsNotNone(msg)
        assert msg is not None
        self.assertIn("need ", msg)
        self.assertIn("RAM bytes", msg)
        self.assertIn("max_live_ram_bytes=1024", msg)

    def test_n_must_be_positive(self) -> None:
        with self.assertRaises(ValueError) as ctx:
            lease_need(
                n=0,
                vms_per_branch=3,
                source_vms=3,
                live_already=3,
                max_live_vms=64,
                memory_bytes_per_vm=1,
                max_live_ram_bytes=1,
            )
        self.assertIn("n must be >= 1", str(ctx.exception))

    def test_tree_budget_is_explicit(self) -> None:
        b = tree_budget(
            max_live_vms=64,
            max_live_ram_bytes=1,
            max_disk_bytes=2,
            max_chain_depth=32,
        )
        self.assertEqual(
            b,
            {
                "max_live_vms": 64,
                "max_live_ram_bytes": 1,
                "max_disk_bytes": 2,
                "max_chain_depth": 32,
            },
        )


if __name__ == "__main__":
    unittest.main()
