"""Gym AutoWarp / dilation mode selection — stub k7d, no KVM."""

from __future__ import annotations

import sys
import time
import unittest
from pathlib import Path
from typing import Any
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import server
from host import k7_bridge_name
from lease import Env, Lease, new_env_id, new_lease_id
from ubuntu import NODE_MEMORY_MB


class RecordingK7d:
    def __init__(self) -> None:
        self.warps: list[tuple[str, str]] = []
        self.holds: list[tuple[str, str, bool]] = []
        self._n = 0
        self.nodes: list[dict[str, Any]] = []
        self.live_dilation: dict[str, int] = {}
        self.fork_dilations: list[int | None] = []

    def tree_fork_batch(
        self,
        tree_id: str,
        source_id: str,
        labels: list[str],
        timeout=None,
        dilation=None,
    ):
        self.fork_dilations.append(dilation)
        forks = []
        for _lab in labels:
            self._n += 1
            forks.append(
                {
                    "node_id": f"child-{self._n}",
                    "guest_cids": [50 + self._n, 51 + self._n, 52 + self._n],
                }
            )
        return {"forks": forks}

    def tree_prune(self, tree_id: str, node_id: str) -> dict[str, Any]:
        return {"status": "ok"}

    def tree_protect(self, tree_id: str, node_id: str) -> dict[str, Any]:
        return {"status": "ok"}

    def tree_nodes(self, tree_id: str) -> dict[str, Any]:
        return {
            "status": "tree_node_list",
            "nodes": list(self.nodes),
            "live_dilation": dict(self.live_dilation),
        }

    def auto_warp(self, cluster_id: str, mode: str) -> dict[str, Any]:
        self.warps.append((cluster_id, mode))
        return {
            "status": "auto_warp",
            "cluster_id": cluster_id,
            "mode": mode,
            "holders": [],
            "stats": {"warps": 3 if mode == "off" else 0, "cycles": 10},
        }

    def auto_warp_hold(
        self, cluster_id: str, holder: str, hold: bool
    ) -> dict[str, Any]:
        self.holds.append((cluster_id, holder, hold))
        return {
            "status": "auto_warp",
            "cluster_id": cluster_id,
            "mode": "jump",
            "holders": [holder] if hold else [],
            "stats": {},
        }


def _gym(default_mode: str = "off") -> server.Gym:
    ns = server.parse_args(
        [
            "--source-mode",
            "create",
            "--autowarp-mode",
            default_mode,
            "--max-live-vms",
            "64",
            "--memory-mb",
            "256",
            "--vm-count",
            "3",
        ]
    )
    g = server.Gym(server.Config(ns))
    g.client = RecordingK7d()  # type: ignore[assignment]
    g.source_vms = 3
    return g


def _seed(g: server.Gym, *, mode: str = "jump") -> Lease:
    lid = new_lease_id()
    tid = g.cfg.source_tree_id
    nid = "br-0"
    env = Env(
        env_id=new_env_id(lid, 0),
        branch_node_id=nid,
        index=0,
        bridge="k7-br-x0",
        guest_ips=["10.200.0.2"],
        guest_cids=[10],
        tree_id=tid,
        cluster_id=f"{tid}-{nid}",
        autowarp_mode=mode,
    )
    now = time.time()
    L = Lease(
        lease_id=lid,
        node_id="node-a",
        group_id="g",
        fault_id="none",
        tree_id=tid,
        source_node_id="root",
        n=1,
        created_at=now,
        expires_at=now + 60,
        envs=[],
        autowarp_mode=mode,
    )
    assert g.leases.reserve(L) is None
    return g.leases.commit(lid, [env])


class TestAutowarpMode(unittest.TestCase):
    def test_config_rejects_unknown_mode(self) -> None:
        ns = server.parse_args(["--autowarp-mode", "fast"])
        with self.assertRaises(SystemExit) as ctx:
            server.Config(ns)
        self.assertIn("off|jump|micro|dilate", str(ctx.exception))

    def test_lease_body_rejects_unknown_mode(self) -> None:
        g = _gym()
        with self.assertRaises(ValueError) as ctx:
            g._autowarp_mode_from_body({"autowarp_mode": "fast"})
        self.assertIn("off|jump|micro|dilate", str(ctx.exception))

    def test_config_rejects_dilate_on_create(self) -> None:
        ns = server.parse_args(
            ["--source-mode", "create", "--autowarp-mode", "dilate"]
        )
        with self.assertRaises(SystemExit) as ctx:
            server.Config(ns)
        self.assertIn("ubuntu", str(ctx.exception))

    def test_config_dilate_on_ubuntu_fork_dilates_the_source(self) -> None:
        cfg = _ubuntu_gym("fork", "dilate").cfg
        self.assertEqual(cfg.source_dilation, server.DILATION_FACTOR)
        self.assertIsNone(_ubuntu_gym("fork", "off").cfg.source_dilation)
        # Reset mode has no shared source: the factor is per lease.
        self.assertIsNone(_ubuntu_gym("reset", "dilate").cfg.source_dilation)

    def test_ubuntu_fork_source_is_brought_up_dilated(self) -> None:
        for mode, want in (("dilate", server.DILATION_FACTOR), ("off", None)):
            g = _ubuntu_gym("fork", mode)
            seen: list[int | None] = []

            def _bring(tid, *, ready_gate=None, dilation=None):
                seen.append(dilation)
                return {
                    "root_id": "root",
                    "guest_cids": [10, 11, 12],
                    "bridge": "k7-br-x",
                    "disks": [],
                    "cert": None,
                    "key": None,
                }

            with patch.object(g, "_bring_up_ubuntu_cluster", _bring), patch.object(
                g, "_bring_source_eth0_up", lambda: None
            ):
                g.prepare_source()
            self.assertEqual(seen, [want], mode)

    def test_reused_source_must_match_the_configured_factor(self) -> None:
        # A source tree from a previous gym reports its live factor; a
        # gym whose mode disagrees must not silently lease on it.
        for mode, live, ok in (
            ("dilate", server.DILATION_FACTOR, True),
            ("off", 1, True),
            ("dilate", 1, False),
            ("off", server.DILATION_FACTOR, False),
        ):
            g = _ubuntu_gym("fork", mode)
            fake = g.client
            assert isinstance(fake, RecordingK7d)
            fake.live_dilation = {"root": live}
            fake.nodes = [{"id": "root", "vm_count": 3}]
            with patch.object(g, "_bring_source_eth0_up", lambda: None):
                if ok:
                    g.prepare_source()
                    self.assertEqual(g.source_node_id, "root", (mode, live))
                else:
                    with self.assertRaises(SystemExit) as ctx:
                        g.prepare_source()
                    self.assertIn(f"x{live}", str(ctx.exception))

    def test_lease_dilate_on_create_is_loud(self) -> None:
        g = _gym()
        with self.assertRaises(ValueError) as ctx:
            g._autowarp_mode_from_body({"autowarp_mode": "dilate"})
        self.assertIn("ubuntu", str(ctx.exception))

    def test_fork_lease_dilate_on_undilated_source_is_legal(self) -> None:
        g = _ubuntu_gym("fork", "off")
        self.assertEqual(g._autowarp_mode_from_body({"autowarp_mode": "dilate"}), "dilate")
        self.assertEqual(g._fork_child_dilation("dilate"), server.DILATION_FACTOR)
        self.assertIsNone(g._fork_child_dilation("off"))

    def test_fork_lease_off_on_dilated_source_is_legal(self) -> None:
        g = _ubuntu_gym("fork", "dilate")
        self.assertEqual(g._autowarp_mode_from_body({}), "dilate")
        self.assertEqual(g._autowarp_mode_from_body({"autowarp_mode": "dilate"}), "dilate")
        for other in ("off", "jump", "micro"):
            self.assertEqual(g._autowarp_mode_from_body({"autowarp_mode": other}), other)
            self.assertEqual(g._fork_child_dilation(other), 1)
        self.assertIsNone(g._fork_child_dilation("dilate"))

    def test_fork_lease_on_dilated_source_tags_dilate_without_auto_warp(self) -> None:
        g = _ubuntu_gym("fork", "dilate")
        g.source_node_id = "root"
        fake = g.client
        assert isinstance(fake, RecordingK7d)
        tid = g.cfg.source_tree_id
        with patch(
            "server.list_bridges",
            lambda: [k7_bridge_name(f"{tid}-child-1")],
        ), patch.object(g, "_inject", lambda *_a, **_k: None), patch.object(
            g, "_api_certs", lambda: (None, None)
        ):
            rec = g.lease(
                {"fault_id": "none", "n": 1, "group_id": "g1", "ttl_s": 30},
                "test",
            )
        self.assertEqual(rec["autowarp_mode"], "dilate")
        self.assertEqual(rec["envs"][0]["autowarp_mode"], "dilate")
        self.assertEqual(fake.warps, [])
        rel = g.release(rec["lease_id"], reason="test")
        self.assertEqual(rel["autowarp"][0]["factor"], server.DILATION_FACTOR)
        self.assertEqual(fake.warps, [])
        self.assertEqual(fake.fork_dilations, [None])

    def test_fork_lease_dilate_on_x1_source_passes_dilation_8(self) -> None:
        g = _ubuntu_gym("fork", "off")
        g.source_node_id = "root"
        fake = g.client
        assert isinstance(fake, RecordingK7d)
        tid = g.cfg.source_tree_id
        with patch(
            "server.list_bridges",
            lambda: [k7_bridge_name(f"{tid}-child-1")],
        ), patch.object(g, "_inject", lambda *_a, **_k: None), patch.object(
            g, "_api_certs", lambda: (None, None)
        ):
            rec = g.lease(
                {
                    "fault_id": "none",
                    "n": 1,
                    "group_id": "g1",
                    "ttl_s": 30,
                    "autowarp_mode": "dilate",
                },
                "test",
            )
        self.assertEqual(rec["autowarp_mode"], "dilate")
        self.assertEqual(fake.fork_dilations, [server.DILATION_FACTOR])
        self.assertEqual(fake.warps, [])

    def test_fork_lease_off_on_x8_source_passes_dilation_1(self) -> None:
        g = _ubuntu_gym("fork", "dilate")
        g.source_node_id = "root"
        fake = g.client
        assert isinstance(fake, RecordingK7d)
        tid = g.cfg.source_tree_id
        with patch(
            "server.list_bridges",
            lambda: [k7_bridge_name(f"{tid}-child-1")],
        ), patch.object(g, "_inject", lambda *_a, **_k: None), patch.object(
            g, "_api_certs", lambda: (None, None)
        ):
            rec = g.lease(
                {
                    "fault_id": "none",
                    "n": 1,
                    "group_id": "g1",
                    "ttl_s": 30,
                    "autowarp_mode": "off",
                },
                "test",
            )
        self.assertEqual(rec["autowarp_mode"], "off")
        self.assertEqual(fake.fork_dilations, [1])
        self.assertEqual(fake.warps, [])

    def test_omitted_mode_on_undilated_source_passes_no_dilation(self) -> None:
        g = _ubuntu_gym("fork", "off")
        g.source_node_id = "root"
        fake = g.client
        assert isinstance(fake, RecordingK7d)
        tid = g.cfg.source_tree_id
        with patch(
            "server.list_bridges",
            lambda: [k7_bridge_name(f"{tid}-child-1")],
        ), patch.object(g, "_inject", lambda *_a, **_k: None), patch.object(
            g, "_api_certs", lambda: (None, None)
        ):
            rec = g.lease(
                {"fault_id": "none", "n": 1, "group_id": "g1", "ttl_s": 30},
                "test",
            )
        self.assertEqual(rec["autowarp_mode"], "off")
        self.assertEqual(fake.fork_dilations, [None])
        self.assertEqual(fake.warps, [])

    def test_omitted_lease_field_uses_config(self) -> None:
        g = _gym("micro")
        self.assertEqual(g._autowarp_mode_from_body({}), "micro")
        g2 = _gym("off")
        self.assertEqual(g2._autowarp_mode_from_body({}), "off")

    def test_lease_enables_jump_and_release_stops(self) -> None:
        g = _gym()
        fake = g.client
        assert isinstance(fake, RecordingK7d)
        tid = g.cfg.source_tree_id

        def _bridge_ok(*_a, **_k):
            return [k7_bridge_name(f"{tid}-child-1")]

        with patch("server.list_bridges", _bridge_ok), patch.object(
            g, "_inject", lambda *_a, **_k: None
        ), patch.object(g, "_api_certs", lambda: (None, None)):
            rec = g.lease(
                {
                    "fault_id": "none",
                    "n": 1,
                    "group_id": "g1",
                    "ttl_s": 30,
                    "autowarp_mode": "jump",
                },
                "test",
            )
        self.assertEqual(rec["autowarp_mode"], "jump")
        self.assertEqual(rec["envs"][0]["autowarp_mode"], "jump")
        self.assertTrue(rec["envs"][0]["cluster_id"].endswith("-child-1"))
        self.assertEqual(fake.warps, [(rec["envs"][0]["cluster_id"], "jump")])

        rel = g.release(rec["lease_id"], reason="test")
        self.assertEqual(rel["autowarp"][0]["mode"], "off")
        self.assertEqual(fake.warps[-1], (rec["envs"][0]["cluster_id"], "off"))

    def test_omitted_mode_does_not_touch_daemon(self) -> None:
        g = _gym("off")
        fake = g.client
        assert isinstance(fake, RecordingK7d)
        tid = g.cfg.source_tree_id
        with patch(
            "server.list_bridges",
            lambda: [k7_bridge_name(f"{tid}-child-1")],
        ), patch.object(g, "_inject", lambda *_a, **_k: None), patch.object(
            g, "_api_certs", lambda: (None, None)
        ):
            rec = g.lease(
                {"fault_id": "none", "n": 1, "group_id": "g1", "ttl_s": 30},
                "test",
            )
        self.assertEqual(rec["autowarp_mode"], "off")
        self.assertEqual(fake.warps, [])
        rel = g.release(rec["lease_id"], reason="test")
        self.assertNotIn("autowarp", rel)

    def test_exec_takes_and_releases_hold(self) -> None:
        g = _gym()
        fake = g.client
        assert isinstance(fake, RecordingK7d)
        L = _seed(g, mode="jump")
        env = L.envs[0]

        def _exec(cid, args, timeout_s=10):
            return {
                "exit_code": 0,
                "stdout": "ok",
                "stderr": "",
            }

        with patch("agent.exec_cmd", _exec):
            rec = g.act(env.env_id, {"action": "exec", "args": ["true"]})
        self.assertTrue(rec["ok"])
        self.assertEqual(
            fake.holds,
            [
                (env.cluster_id, f"gym-exec:{env.env_id}", True),
                (env.cluster_id, f"gym-exec:{env.env_id}", False),
            ],
        )

    def test_exec_hold_released_on_failure(self) -> None:
        g = _gym()
        fake = g.client
        assert isinstance(fake, RecordingK7d)
        L = _seed(g, mode="micro")
        env = L.envs[0]

        def _boom(cid, args, timeout_s=10):
            raise RuntimeError("vsock dead")

        with patch("agent.exec_cmd", _boom):
            with self.assertRaises(RuntimeError):
                g.act(env.env_id, {"action": "exec", "args": ["true"]})
        self.assertEqual([h[2] for h in fake.holds], [True, False])

    def test_off_mode_exec_skips_hold(self) -> None:
        g = _gym()
        fake = g.client
        assert isinstance(fake, RecordingK7d)
        L = _seed(g, mode="off")
        env = L.envs[0]
        with patch(
            "agent.exec_cmd",
            lambda *a, **k: {"exit_code": 0, "stdout": "", "stderr": ""},
        ):
            g.act(env.env_id, {"action": "exec", "args": ["true"]})
        self.assertEqual(fake.holds, [])

    def test_public_lease_names_the_mode(self) -> None:
        g = _gym()
        L = _seed(g, mode="micro")
        pub = L.as_public()
        self.assertEqual(pub["autowarp_mode"], "micro")
        self.assertEqual(pub["envs"][0]["autowarp_mode"], "micro")
        self.assertEqual(pub["envs"][0]["cluster_id"], L.envs[0].cluster_id)

    def test_mid_episode_fork_inherits_mode(self) -> None:
        g = _gym()
        fake = g.client
        assert isinstance(fake, RecordingK7d)
        L = _seed(g, mode="micro")
        parent = L.envs[0]
        tid = parent.tree_id
        child_cid = f"{tid}-child-1"

        def _bridge_ok(*_a, **_k):
            return [k7_bridge_name(child_cid)]

        with patch("server.list_bridges", _bridge_ok), patch.object(
            g, "_api_certs", lambda: (None, None)
        ):
            rec = g.fork_env(parent.env_id, {"n": 1})
        self.assertEqual(rec["envs"][0]["autowarp_mode"], "micro")
        self.assertEqual(rec["envs"][0]["cluster_id"], child_cid)
        self.assertEqual(fake.warps, [(child_cid, "micro")])

    def test_dilate_exec_skips_hold_and_release_skips_auto_warp(self) -> None:
        g = _gym()
        fake = g.client
        assert isinstance(fake, RecordingK7d)
        L = _seed(g, mode="dilate")
        env = L.envs[0]
        with patch(
            "agent.exec_cmd",
            lambda *a, **k: {"exit_code": 0, "stdout": "", "stderr": ""},
        ):
            g.act(env.env_id, {"action": "exec", "args": ["true"]})
        self.assertEqual(fake.holds, [])
        rel = g.release(L.lease_id, reason="test")
        self.assertEqual(fake.warps, [])
        self.assertEqual(rel["autowarp"][0]["mode"], "off")
        self.assertEqual(rel["autowarp"][0]["factor"], server.DILATION_FACTOR)
        self.assertEqual(rel["autowarp"][0]["cluster_id"], env.cluster_id)

    def test_ubuntu_reset_dilate_passes_factor_to_create_vm(self) -> None:
        g = _ubuntu_reset_gym()
        seen: list[int | None] = []

        def _bring(tid, *, ready_gate=None, dilation=None):
            seen.append(dilation)
            return {
                "root_id": "root",
                "guest_cids": [10, 11, 12],
                "bridge": "k7-br-x",
                "disks": [],
                "cert": None,
                "key": None,
            }

        with patch.object(g, "_bring_up_ubuntu_cluster", _bring):
            env = g._reset_one_env("leaseid0", 0, server.DILATION_FACTOR)
        self.assertEqual(seen, [server.DILATION_FACTOR])
        self.assertEqual(env.tree_id, "gym-rst-leaseid0-0")

    def test_ubuntu_reset_lease_dilate_does_not_call_auto_warp(self) -> None:
        g = _ubuntu_reset_gym()
        fake = g.client
        assert isinstance(fake, RecordingK7d)

        def _reset(lid, n, dilation=None):
            self.assertEqual(n, 1)
            self.assertEqual(dilation, server.DILATION_FACTOR)
            tid = g.cfg.source_tree_id
            nid = "rst-0"
            return [
                Env(
                    env_id=new_env_id(lid, 0),
                    branch_node_id=nid,
                    index=0,
                    bridge="k7-br-x0",
                    guest_ips=["10.200.0.2"],
                    guest_cids=[10],
                    tree_id=tid,
                    cluster_id=tid,
                )
            ]

        with patch.object(g, "_envs_from_reset", _reset), patch.object(
            g, "_inject", lambda *_a, **_k: None
        ):
            rec = g.lease(
                {
                    "fault_id": "none",
                    "n": 1,
                    "group_id": "g1",
                    "ttl_s": 30,
                    "autowarp_mode": "dilate",
                },
                "test",
            )
        self.assertEqual(rec["autowarp_mode"], "dilate")
        self.assertEqual(rec["envs"][0]["autowarp_mode"], "dilate")
        self.assertEqual(fake.warps, [])

    def test_dilate_mid_episode_fork_inherits_without_auto_warp(self) -> None:
        # The child runs at the parent's factor by construction, so
        # there is nothing to ask the daemon.
        g = _ubuntu_gym("fork", "dilate")
        fake = g.client
        assert isinstance(fake, RecordingK7d)
        L = _seed(g, mode="dilate")
        parent = L.envs[0]
        child_cid = f"{parent.tree_id}-child-1"
        with patch(
            "server.list_bridges", lambda *_a, **_k: [k7_bridge_name(child_cid)]
        ), patch.object(g, "_api_certs", lambda: (None, None)):
            rec = g.fork_env(parent.env_id, {"n": 1})
        self.assertEqual(rec["envs"][0]["autowarp_mode"], "dilate")
        self.assertEqual(rec["envs"][0]["cluster_id"], child_cid)
        self.assertEqual(fake.warps, [])


def _ubuntu_gym(start_mode: str, autowarp_mode: str = "off") -> server.Gym:
    args = [
        "--source-mode",
        "ubuntu",
        "--start-mode",
        start_mode,
        "--memory-mb",
        str(NODE_MEMORY_MB),
        "--max-live-vms",
        "64",
        "--vm-count",
        "3",
        "--autowarp-mode",
        autowarp_mode,
    ]
    if start_mode == "reset":
        args.append("--reset-measurement")
    g = server.Gym(server.Config(server.parse_args(args)))
    g.client = RecordingK7d()  # type: ignore[assignment]
    g.source_vms = 3
    return g


def _ubuntu_reset_gym() -> server.Gym:
    return _ubuntu_gym("reset")


if __name__ == "__main__":
    unittest.main()
