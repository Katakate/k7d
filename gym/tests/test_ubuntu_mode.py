"""Ubuntu source-mode guards — no KVM."""

from __future__ import annotations

import inspect
import os
import sys
import tempfile
import time
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from unittest.mock import patch

from host import fnv1a_5hex, k7_bridge_name, pin_guest_route
from ubuntu import (
    HOST_RAM_PER_NODE_BYTES,
    NODE_MEMORY_MB,
    assert_guest_egress,
    assert_guest_image_pull,
    guest_ip,
    k3s_spec,
    memory_floor_error,
    node_cmdline,
    prune_unused_base_images,
    remove_tree_disks,
    sweep_orphaned_gym_disks,
    tree_budget_floor_error,
    wait_nodes_present_on_bridge,
    wait_nodes_ready_on_bridge,
)


class TestUbuntuGuards(unittest.TestCase):
    def test_memory_floor_refuses_create_mode_leftover(self) -> None:
        msg = memory_floor_error(256)
        self.assertIsNotNone(msg)
        assert msg is not None
        self.assertIn("GYM_MEMORY_MB=256", msg)
        self.assertIn(f"NODE_MEMORY_MB={NODE_MEMORY_MB}", msg)
        self.assertIn("1.35", msg)
        self.assertIsNone(memory_floor_error(2048))
        self.assertIsNone(memory_floor_error(4096))

    def test_tree_budget_spells_source_plus_one_fork(self) -> None:
        msg = tree_budget_floor_error(
            vm_count=3,
            memory_mb=2048,
            max_live_vms=5,
            max_live_ram_bytes=64 * 1024**3,
        )
        self.assertIsNotNone(msg)
        assert msg is not None
        self.assertIn("need 6 live VMs", msg)
        self.assertIn("source=3", msg)
        self.assertIn("GYM_MAX_LIVE_VMS=5", msg)

        ram = tree_budget_floor_error(
            vm_count=3,
            memory_mb=2048,
            max_live_vms=64,
            max_live_ram_bytes=1024,
        )
        self.assertIsNotNone(ram)
        assert ram is not None
        self.assertIn("RAM bytes", ram)
        self.assertIn(str(6 * HOST_RAM_PER_NODE_BYTES), ram)
        self.assertIsNone(
            tree_budget_floor_error(
                vm_count=3,
                memory_mb=2048,
                max_live_vms=64,
                max_live_ram_bytes=64 * 1024**3,
            )
        )

    def test_cmdline_has_root_and_k3s_no_rdinit(self) -> None:
        spec = k3s_spec("server", "10.200.0.2")
        cmd = node_cmdline("10.200.0.2", spec)
        self.assertIn("root=/dev/vda", cmd)
        self.assertIn("k7d.k3s=server,10.200.0.2,", cmd)
        self.assertNotIn("rdinit=", cmd)
        self.assertNotIn("k7d.cni=", cmd)
        none = node_cmdline("10.200.0.2", spec, cni="none")
        self.assertIn("k7d.cni=none", none)
        with self.assertRaises(ValueError) as ctx:
            node_cmdline("10.200.0.2", spec, cni="calico")
        self.assertIn("flannel or none", str(ctx.exception))
        self.assertEqual(guest_ip(0), "10.200.0.2")
        self.assertEqual(guest_ip(2), "10.200.0.4")

    def test_unknown_mode_is_loud(self) -> None:
        import server

        with self.assertRaises(SystemExit) as ctx:
            ns = server.parse_args(["--source-mode", "create"])
            ns.source_mode = "busybox"
            server.Config(ns)
        self.assertIn("create|adopt|ubuntu", str(ctx.exception))

    def test_ubuntu_mode_refuses_256(self) -> None:
        import server

        ns = server.parse_args(
            ["--source-mode", "ubuntu", "--memory-mb", "256"]
        )
        with self.assertRaises(SystemExit) as ctx:
            server.Config(ns)
        self.assertIn("GYM_MEMORY_MB=256", str(ctx.exception))
        self.assertIn("2048", str(ctx.exception))

    def test_fork_bridge_name_matches_k7d_formula(self) -> None:
        """Gym `--interface` must hash `{tree_id}-{node_id}`, not `ctree-{{pid}}`."""
        self.assertEqual(k7_bridge_name("short"), "k7-br-short")
        cid = "gym-src-test-ubuntu-605268-lease-abc-0001"
        h = fnv1a_5hex(cid)
        self.assertEqual(k7_bridge_name(cid), f"k7-br-gym-{h[:5]}")
        self.assertLessEqual(len(k7_bridge_name(cid)), 15)

    def test_pin_guest_route_replaces_and_deletes(self) -> None:
        calls: list[list[str]] = []

        def _run(cmd, **_kw):
            calls.append(list(cmd))
            return type("R", (), {"returncode": 0, "stderr": "", "stdout": ""})()

        with patch("host.list_bridges", return_value={"k7-br-gym-abcde"}):
            with patch("host.subprocess.run", side_effect=_run):
                with pin_guest_route("k7-br-gym-abcde", "10.200.0.2"):
                    pass
        self.assertEqual(
            calls[0][:4], ["ip", "route", "replace", "10.200.0.2/32"]
        )
        self.assertEqual(calls[0][-2:], ["dev", "k7-br-gym-abcde"])
        self.assertEqual(calls[-1][:4], ["ip", "route", "del", "10.200.0.2/32"])

    def test_pin_guest_route_missing_bridge_is_loud(self) -> None:
        with patch("host.list_bridges", return_value=set()):
            with self.assertRaises(RuntimeError) as ctx:
                with pin_guest_route("k7-br-missing", "10.200.0.2"):
                    pass
        self.assertIn("k7-br-missing", str(ctx.exception))

    def test_sweep_orphaned_gym_disks_keeps_live_pid(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            d = Path(td)
            keep = d / f"ubuntu-gym-rst-keep-0-{os.getpid()}.img"
            gone = d / "ubuntu-gym-rst-gone-0-9999999.img"
            keep.write_bytes(b"k")
            gone.write_bytes(b"g")
            with patch("ubuntu.DISKS_DIR", d):
                n = sweep_orphaned_gym_disks()
            self.assertEqual(n, 1)
            self.assertTrue(keep.is_file())
            self.assertFalse(gone.is_file())

    def test_remove_tree_disks_is_scoped(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            d = Path(td)
            a = d / "ubuntu-gym-gym-rst-aaa-0-1.img"
            b = d / "ubuntu-gym-gym-rst-bbb-0-1.img"
            a.write_bytes(b"a")
            b.write_bytes(b"b")
            with patch("ubuntu.DISKS_DIR", d):
                n = remove_tree_disks("gym-rst-aaa")
            self.assertEqual(n, 1)
            self.assertFalse(a.is_file())
            self.assertTrue(b.is_file())

    def test_drop_and_startup_unlink_gym_disks(self) -> None:
        import server

        drop = inspect.getsource(server.Gym._drop_tree_loud)
        self.assertIn("remove_tree_disks", drop)
        sweep = inspect.getsource(server.Gym.startup_sweep)
        self.assertIn("sweep_orphaned_gym_disks", sweep)
        reset = inspect.getsource(server.Gym._envs_from_reset)
        self.assertIn("current not in seen", reset)

    def test_ready_wait_on_missing_bridge_is_loud(self) -> None:
        import tempfile

        with tempfile.TemporaryDirectory() as td:
            cert = Path(td) / "c.pem"
            key = Path(td) / "k.pem"
            cert.write_text("x")
            key.write_text("y")
            with self.assertRaises(RuntimeError) as ctx:
                wait_nodes_ready_on_bridge(
                    "k7-br-does-not-exist", cert, key, 0.05, want=3
                )
            self.assertIn("never Ready via", str(ctx.exception))
            self.assertIn("do not fall back", str(ctx.exception))
            with self.assertRaises(RuntimeError) as ctx2:
                wait_nodes_present_on_bridge(
                    "k7-br-does-not-exist", cert, key, 0.05, want=3
                )
            self.assertIn("never present via", str(ctx2.exception))

    def test_assert_guest_egress_empty_is_loud(self) -> None:
        with self.assertRaises(RuntimeError) as ctx:
            assert_guest_egress([])
        self.assertIn("no guest cids", str(ctx.exception))

    def test_assert_guest_image_pull_empty_is_loud(self) -> None:
        with self.assertRaises(RuntimeError) as ctx:
            assert_guest_image_pull([])
        self.assertIn("no guest cids", str(ctx.exception))

    def test_prune_unused_base_images_keeps_newest_key(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            d = Path(td)
            old = d / "ubuntu-24.04-aaaa.img"
            new = d / "ubuntu-24.04-bbbb.img"
            leftover = d / "ubuntu-24.04-aaaa.qcow2"
            other = d / "not-ubuntu.img"
            old.write_bytes(b"old")
            leftover.write_bytes(b"old-extra")
            other.write_bytes(b"keep")
            time.sleep(0.02)
            new.write_bytes(b"new")
            n = prune_unused_base_images(d)
            self.assertGreaterEqual(n, 1)
            self.assertTrue(new.is_file())
            self.assertFalse(old.is_file())
            self.assertFalse(leftover.is_file())
            self.assertTrue(other.is_file())


if __name__ == "__main__":
    unittest.main()
