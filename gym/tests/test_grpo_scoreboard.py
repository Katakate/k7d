"""GRPO scoreboard — stub, no KVM."""

from __future__ import annotations

import json
import sys
import tempfile
import threading
import unittest
from http.server import ThreadingHTTPServer
from pathlib import Path
from typing import Any
from unittest.mock import patch
from urllib.request import Request, urlopen

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from faults import GRPO_FAULTS, get, require_grpo_fault  # noqa: E402
from host import k7_bridge_name  # noqa: E402
from lease import Env, Lease  # noqa: E402
from scoring import TERM_KEYS  # noqa: E402


class RecordingK7d:
    def __init__(self) -> None:
        self._n = 0

    def tree_fork_batch(
        self,
        tree_id: str,
        source_id: str,
        labels: list[str],
        timeout=None,
        dilation=None,
    ) -> dict[str, Any]:
        _ = (tree_id, source_id, timeout, dilation)
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


def _grpo_gym():
    import server

    ns = server.parse_args(
        [
            "--source-mode",
            "ubuntu",
            "--memory-mb",
            "2048",
            "--scoreboard",
            "grpo",
            "--max-live-vms",
            "64",
        ]
    )
    g = server.Gym(server.Config(ns))
    g.client = RecordingK7d()  # type: ignore[assignment]
    g.source_vms = 3
    return g


def _envs(n: int, *, cert: str = "", key: str = "") -> list[Env]:
    return [
        Env(
            env_id=f"lease-g-{i}",
            branch_node_id=f"n{i}",
            index=i,
            bridge=f"k7-br-g{i}",
            guest_ips=["10.200.0.2"],
            guest_cids=[10 + i],
            cert_path=cert,
            key_path=key,
        )
        for i in range(n)
    ]


def _commit(gym: Any, envs: list[Env], *, fault_id: str = "kill-member-0") -> Lease:
    L = Lease(
        lease_id="lease-g",
        node_id="t",
        group_id="g",
        fault_id=fault_id,
        tree_id="gym-src-t",
        source_node_id="root",
        n=len(envs),
        created_at=0.0,
        expires_at=9e9,
        envs=envs,
    )
    gym.leases.reserve(L)
    return gym.leases.commit(L.lease_id, envs)


class TestGrpoConfig(unittest.TestCase):
    def test_scoreboard_accepts_grpo(self) -> None:
        import server

        ns = server.parse_args(
            [
                "--source-mode",
                "ubuntu",
                "--memory-mb",
                "2048",
                "--scoreboard",
                "grpo",
            ]
        )
        cfg = server.Config(ns)
        self.assertEqual(cfg.scoreboard, "grpo")

    def test_grpo_refuses_busybox_modes(self) -> None:
        import server

        for mode in ("create", "adopt"):
            ns = server.parse_args(
                ["--source-mode", mode, "--scoreboard", "grpo"]
            )
            with self.assertRaises(SystemExit) as ctx:
                server.Config(ns)
            self.assertIn("grpo", str(ctx.exception))
            self.assertIn("ubuntu", str(ctx.exception))

    def test_unknown_scoreboard_lists_grpo(self) -> None:
        import server

        ns = server.parse_args(["--scoreboard", "health"])
        ns.scoreboard = "batfish"
        with self.assertRaises(SystemExit) as ctx:
            server.Config(ns)
        self.assertIn("grpo", str(ctx.exception))

    def test_require_grpo_fault_refuses_relay(self) -> None:
        with self.assertRaises(ValueError) as ctx:
            require_grpo_fault("relay")
        self.assertIn("relay", str(ctx.exception))
        for fid in GRPO_FAULTS:
            require_grpo_fault(fid)


class TestGrpoInject(unittest.TestCase):
    def test_lease_n8_injects_every_env(self) -> None:
        g = _grpo_gym()
        tid = g.cfg.source_tree_id
        fault = get("kill-member-0")
        calls: list[int] = []

        def fake_inject(env: Env, client: Any) -> None:
            _ = client
            calls.append(env.index)

        bridges = [k7_bridge_name(f"{tid}-child-{i}") for i in range(1, 9)]
        with (
            patch.object(fault, "inject", fake_inject),
            patch.object(fault, "fault_visible", return_value=True),
            patch("server.list_bridges", return_value=bridges),
            patch.object(g, "_api_certs", lambda: (None, None)),
        ):
            rec = g.lease(
                {
                    "fault_id": "kill-member-0",
                    "n": 8,
                    "group_id": "g8",
                    "ttl_s": 60,
                },
                "test",
            )
        # `_inject` fans out over a ThreadPoolExecutor, so completion
        # order is whatever the scheduler picked (visibly so on a 20-core
        # node); the contract is "every env exactly once".
        self.assertEqual(sorted(calls), list(range(8)))
        self.assertEqual(len(rec["envs"]), 8)
        self.assertFalse(fault.keep_apiserver)
        self.assertIn("inject_ms", rec)

    def test_health_inject_stays_env0(self) -> None:
        import server

        ns = server.parse_args(
            [
                "--source-mode",
                "ubuntu",
                "--memory-mb",
                "2048",
                "--scoreboard",
                "health",
            ]
        )
        g = server.Gym(server.Config(ns))
        L = _commit(g, _envs(8))
        fault = get("kill-member-0")
        calls: list[int] = []

        def fake_inject(env: Env, client: Any) -> None:
            _ = client
            calls.append(env.index)

        with (
            patch.object(fault, "inject", fake_inject),
            patch.object(fault, "fault_visible", return_value=True),
        ):
            g._inject(L, fault)
        self.assertEqual(calls, [0])

    def test_lease_relay_is_loud(self) -> None:
        g = _grpo_gym()
        with self.assertRaises(ValueError) as ctx:
            g.lease(
                {
                    "fault_id": "relay",
                    "n": 8,
                    "group_id": "g",
                    "ttl_s": 60,
                },
                "test",
            )
        self.assertIn("relay", str(ctx.exception))
        self.assertIn("grpo", str(ctx.exception))


class TestGrpoScore(unittest.TestCase):
    def test_score_eight_rows_unreachable_stays_200(self) -> None:
        import server

        g = _grpo_gym()
        with tempfile.TemporaryDirectory() as td:
            cert = Path(td) / "c.pem"
            key = Path(td) / "k.pem"
            cert.write_text("c")
            key.write_text("k")
            g.ubuntu_cert, g.ubuntu_key = cert, key
            L = _commit(g, _envs(8, cert=str(cert), key=str(key)))
            fault = get("kill-member-0")

            def visible(env: Env) -> bool:
                if env.index == 7:
                    raise RuntimeError("vsock dead")
                return False

            with (
                patch.object(fault, "fault_visible", visible),
                patch.object(fault, "healthy", return_value=True),
                patch(
                    "server.agent.exec_cmd",
                    return_value={"exit_code": 0, "stdout": "", "stderr": ""},
                ),
                patch("server.curl_readyz", return_value=True),
                patch("server.curl_nodes_ready", return_value=True),
                patch.object(g, "_source_intact", return_value=True),
            ):
                out = g.score(L.lease_id)
                code, body = _http_score(g, L.lease_id)

        self.assertEqual(len(out["scores"]), 8)
        self.assertEqual(out["scoreboard"], "grpo")
        for i, row in enumerate(out["scores"][:7]):
            self.assertEqual(set(row["terms"]), set(TERM_KEYS))
            self.assertEqual(row["reward"], 1.0)
            self.assertNotIn("unreachable", row)
            self.assertEqual(row["env_id"], f"lease-g-{i}")
        dead = out["scores"][7]
        self.assertEqual(dead["terms"]["liveness"], 0.0)
        self.assertEqual(dead["terms"]["workload_ready"], 0.0)
        self.assertEqual(dead["terms"]["contained"], 0.0)
        self.assertEqual(dead["terms"]["restored"], 0.0)
        self.assertEqual(dead["terms"]["source_intact"], 1.0)
        self.assertTrue(dead["unreachable"])
        self.assertEqual(code, 200)
        self.assertEqual(len(body["scores"]), 8)
        self.assertTrue(body["scores"][7]["unreachable"])
        self.assertEqual(body["scores"][0]["reward"], 1.0)

    def test_none_sets_contained_restored(self) -> None:
        g = _grpo_gym()
        L = _commit(g, _envs(2), fault_id="none")
        with (
            patch(
                "server.agent.exec_cmd",
                return_value={"exit_code": 0, "stdout": "", "stderr": ""},
            ),
            patch("server.curl_readyz", return_value=True),
            patch("server.curl_nodes_ready", return_value=True),
            patch.object(g, "_source_intact", return_value=True),
            patch.object(g, "_env_certs", lambda _e: (Path("/etc/hosts"), Path("/etc/hosts"))),
        ):
            out = g.score(L.lease_id)
        for row in out["scores"]:
            self.assertEqual(row["terms"]["contained"], 1.0)
            self.assertEqual(row["terms"]["restored"], 1.0)
            self.assertNotIn("unreachable", row)

    def test_dead_vsock_probe_is_unreachable_even_if_visible_swallows(self) -> None:
        """Catalog exec_ok returns False on vsock death; we must not pay contained=1."""
        g = _grpo_gym()
        L = _commit(g, _envs(2))
        fault = get("kill-member-0")

        def exec_cmd(cid: int, args: list[str], timeout_s: float = 5) -> dict:
            _ = (args, timeout_s)
            if cid == L.envs[1].guest_cids[0]:
                raise RuntimeError("vsock connect timed out")
            return {"exit_code": 0, "stdout": "", "stderr": ""}

        with (
            patch("server.agent.exec_cmd", exec_cmd),
            patch.object(fault, "fault_visible", return_value=False),
            patch.object(fault, "healthy", return_value=True),
            patch("server.curl_readyz", return_value=True),
            patch("server.curl_nodes_ready", return_value=True),
            patch.object(g, "_source_intact", return_value=True),
            patch.object(g, "_env_certs", lambda _e: (Path("/etc/hosts"), Path("/etc/hosts"))),
        ):
            out = g.score(L.lease_id)
        live, dead = out["scores"]
        self.assertEqual(live["reward"], 1.0)
        self.assertNotIn("unreachable", live)
        self.assertTrue(dead["unreachable"])
        self.assertEqual(dead["terms"]["contained"], 0.0)
        self.assertEqual(dead["terms"]["restored"], 0.0)
        self.assertEqual(dead["reward"], 0.2)


class TestGrpoObs(unittest.TestCase):
    def test_obs_services_and_links(self) -> None:
        g = _grpo_gym()
        L = _commit(g, _envs(1))

        def fake_exec(cid: int, args: list[str], timeout_s: float = 5) -> dict:
            _ = timeout_s
            self.assertEqual(cid, L.envs[0].guest_cids[0])
            self.assertEqual(args[:2], ["sh", "-c"])
            self.assertIn("systemctl is-active k3s.service", args[2])
            self.assertIn("ip link show eth0", args[2])
            return {
                "exit_code": 0,
                "stdout": (
                    "inactive\n"
                    "2: eth0: <BROADCAST,MULTICAST> mtu 1500 state DOWN\n"
                ),
                "stderr": "",
            }

        with (
            patch("server.curl_api", return_value=(599, "", "api down")),
            patch("server.curl_readyz", return_value=False),
            patch("server.agent.exec_cmd", fake_exec),
        ):
            out = g.obs(L.envs[0].env_id)
        obs = out["observation"]
        self.assertEqual(obs["services"]["k3s.service"], "inactive")
        self.assertEqual(obs["links"]["eth0"], "down")
        self.assertNotIn("services_error", obs)

    def test_obs_services_error_omits_keys(self) -> None:
        g = _grpo_gym()
        L = _commit(g, _envs(1))

        def boom(*_a: object, **_k: object) -> dict:
            raise RuntimeError("vsock dead")

        with (
            patch("server.curl_api", return_value=(599, "", "api down")),
            patch("server.curl_readyz", return_value=False),
            patch("server.agent.exec_cmd", boom),
        ):
            out = g.obs(L.envs[0].env_id)
        obs = out["observation"]
        self.assertIn("vsock dead", obs["services_error"])
        self.assertNotIn("services", obs)
        self.assertNotIn("links", obs)


def _http_score(gym: Any, lease_id: str) -> tuple[int, dict[str, Any]]:
    import server

    server.Handler.gym = gym
    httpd = ThreadingHTTPServer(("127.0.0.1", 0), server.Handler)
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    host, port = httpd.server_address[:2]
    try:
        req = Request(
            f"http://{host}:{port}/lease/{lease_id}/score",
            data=b"{}",
            method="POST",
        )
        req.add_header("Content-Type", "application/json")
        with urlopen(req, timeout=5) as resp:
            return int(getattr(resp, "status", 200)), json.loads(resp.read())
    finally:
        httpd.shutdown()
        httpd.server_close()


if __name__ == "__main__":
    unittest.main()
