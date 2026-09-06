"""Incident scoreboard config + missing payload — no KVM."""

from __future__ import annotations

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))


class TestIncidentConfig(unittest.TestCase):
    def test_scoreboard_accepts_incident(self) -> None:
        import server

        ns = server.parse_args(
            [
                "--source-mode",
                "ubuntu",
                "--memory-mb",
                "2048",
                "--scoreboard",
                "incident",
            ]
        )
        cfg = server.Config(ns)
        self.assertEqual(cfg.scoreboard, "incident")
        self.assertEqual(cfg.ready_gate, "api")

    def test_incident_forces_ready_gate_api(self) -> None:
        import server

        ns = server.parse_args(
            [
                "--source-mode",
                "ubuntu",
                "--memory-mb",
                "2048",
                "--scoreboard",
                "incident",
                "--ready-gate",
                "nodes",
            ]
        )
        with self.assertRaises(SystemExit) as ctx:
            server.Config(ns)
        self.assertIn("ready_gate=api", str(ctx.exception))

    def test_incident_refuses_busybox_modes(self) -> None:
        import server

        for mode in ("create", "adopt"):
            ns = server.parse_args(
                ["--source-mode", mode, "--scoreboard", "incident"]
            )
            with self.assertRaises(SystemExit) as ctx:
                server.Config(ns)
            self.assertIn("incident", str(ctx.exception))
            self.assertIn("ubuntu", str(ctx.exception))

    def test_unknown_scoreboard_lists_incident(self) -> None:
        import server

        ns = server.parse_args(["--scoreboard", "health"])
        ns.scoreboard = "batfish"
        with self.assertRaises(SystemExit) as ctx:
            server.Config(ns)
        self.assertIn("incident", str(ctx.exception))

    def test_score_missing_incident_payload_is_loud(self) -> None:
        import server
        from lease import Env, Lease

        ns = server.parse_args(
            [
                "--source-mode",
                "ubuntu",
                "--memory-mb",
                "2048",
                "--scoreboard",
                "incident",
            ]
        )
        gym = server.Gym(server.Config(ns))
        L = Lease(
            lease_id="lease-inc",
            node_id="t",
            group_id="g",
            fault_id="relay",
            tree_id="gym-src-t",
            source_node_id="root",
            n=1,
            created_at=0.0,
            expires_at=9e9,
            envs=[
                Env(
                    env_id="lease-inc-0",
                    branch_node_id="n0",
                    index=0,
                    bridge="k7-br-x",
                    guest_ips=["10.200.0.2"],
                    guest_cids=[10],
                )
            ],
        )
        gym.leases.reserve(L)
        gym.leases.commit(L.lease_id, L.envs)
        with self.assertRaises(ValueError) as ctx:
            gym.score(L.lease_id, turn=1)
        self.assertIn("incident", str(ctx.exception).lower())

    def test_lease_incident_loud_with_wrong_fault(self) -> None:
        import server
        from lease import Env, Lease

        ns = server.parse_args(
            [
                "--source-mode",
                "ubuntu",
                "--memory-mb",
                "2048",
                "--scoreboard",
                "incident",
            ]
        )
        gym = server.Gym(server.Config(ns))
        L = Lease(
            lease_id="lease-bad",
            node_id="t",
            group_id="g",
            fault_id="kill-member-0",
            tree_id="gym-src-t",
            source_node_id="root",
            n=1,
            created_at=0.0,
            expires_at=9e9,
            envs=[
                Env(
                    env_id="lease-bad-0",
                    branch_node_id="n0",
                    index=0,
                    bridge="k7-br-x",
                    guest_ips=["10.200.0.2"],
                    guest_cids=[10],
                )
            ],
        )
        gym.leases.reserve(L)
        gym.leases.commit(L.lease_id, L.envs)
        with self.assertRaises(ValueError) as ctx:
            gym.score(L.lease_id, turn=1)
        self.assertIn("relay", str(ctx.exception))


class TestRelayFault(unittest.TestCase):
    def test_loader_does_not_shadow_gym_server(self) -> None:
        import sys

        from incidents_load import incidents_mod

        incidents_mod()
        mcp = str(
            Path(__file__).resolve().parents[2] / "examples" / "k7d-mcp"
        )
        self.assertNotIn(mcp, sys.path)
        import server

        self.assertTrue(hasattr(server, "Gym"))
        self.assertTrue(hasattr(server.Gym, "_score_incident"))
        self.assertTrue(hasattr(server.Gym, "_score_playbook"))

    def test_delegates_to_incidents_relay(self) -> None:
        from faults import get
        from incidents_load import incidents_mod

        f = get("relay")
        inc = incidents_mod().Relay()
        self.assertEqual(f.id, "relay")
        self.assertEqual(f.modes, ("ubuntu",))
        self.assertTrue(f.keep_apiserver)
        self.assertEqual(f.good_fix_hint["action"], "exec")
        self.assertEqual(f.good_fix_hint["args"][0], "sh")
        self.assertEqual(f.good_fix_hint["args"][2], inc.remediate_cmd())
        from faults.relay import RELAY_MINER, shallow_fix_hint

        self.assertEqual(RELAY_MINER, inc.pod)
        sh = shallow_fix_hint()
        self.assertIn(inc.pod, sh["args"])

    def test_inject_plants_host_after_apply(self) -> None:
        from unittest.mock import patch

        from faults.relay import Relay

        f = Relay()
        f.source_mode = "ubuntu"
        calls: list[list[str]] = []
        planted: list[list[int]] = []

        def fake_exec(_cid: int, args: list[str], timeout_s: float = 8) -> dict:
            _ = timeout_s
            calls.append(list(args))
            return {"exit_code": 0, "stdout": "created", "stderr": ""}

        env = type(
            "E",
            (),
            {
                "guest_cids": [7],
                "bridge": "k7-br-x",
                "cert_path": "/etc/hosts",
                "key_path": "/etc/hosts",
                "guest_ips": ["10.200.0.2"],
            },
        )()
        with (
            patch("faults.relay.exec_cmd", fake_exec),
            patch("faults.relay.env_miner_running", return_value=True),
            patch(
                "faults.relay._relay",
                lambda: type(
                    "R",
                    (),
                    {
                        "yaml": "kind: Deployment\n",
                        "plant_host": lambda self, cids: planted.append(list(cids)),
                    },
                )(),
            ),
        ):
            f.inject(env, None)
        self.assertTrue(any("k3s kubectl apply" in " ".join(a) for a in calls))
        self.assertEqual(planted, [[7]])

    def test_empty_cids_is_loud(self) -> None:
        from faults.relay import Relay

        f = Relay()
        env = type("E", (), {"guest_cids": []})()
        with self.assertRaises(RuntimeError) as ctx:
            f.inject(env, None)
        self.assertIn("guest_cids", str(ctx.exception))


if __name__ == "__main__":
    unittest.main()
