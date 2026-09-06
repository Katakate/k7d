"""Playbook scoreboard — mocked curl/exec, no KVM."""

from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from playbook import (
    INJECT_FAULTS,
    PAGES,
    PINNED_IMAGE,
    Ctx,
    PageResult,
    discover_pinned_image,
    ensure_host_pinned_airgap,
    plant_pinned_airgap,
    refuse_inject_fault,
    require_playbook_payload,
    run_page,
    run_through,
    score_from_results,
    wait_pinned_image,
)


class FakeAPI:
    def __init__(self) -> None:
        self.readyz_ok = True
        self.nodes_ready_ok = True
        self.n_nodes = 3
        self.ns = False
        self.deploy = False
        self.replicas = 0
        self.available = 0
        self.svc = False
        self.ep = False
        self.ep_addrs = 0
        self.scheduled = False
        self.rs_uids = {"rs-a"}
        self.exec_ok = True
        self.posts: list[str] = []

    def curl(
        self,
        _bridge: str,
        path: str,
        *,
        method: str = "GET",
        body: str | None = None,
        **_kw: object,
    ) -> tuple[int, str, str]:
        if path == "/api/v1/nodes":
            items = [{"metadata": {"name": f"n{i}"}} for i in range(self.n_nodes)]
            return 200, json.dumps({"items": items}), ""
        if path == "/api/v1/namespaces/k7-exam":
            if method == "GET":
                if not self.ns:
                    return 404, '{"kind":"Status"}', ""
                return 200, json.dumps({"metadata": {"name": "k7-exam"}}), ""
        if path == "/api/v1/namespaces" and method == "POST":
            self.ns = True
            self.posts.append("ns")
            return 201, json.dumps({"metadata": {"name": "k7-exam"}}), ""
        if path.endswith("/deployments/web"):
            if method == "GET":
                if not self.deploy:
                    return 404, "{}", ""
                return (
                    200,
                    json.dumps(
                        {
                            "metadata": {"name": "web"},
                            "spec": {"replicas": self.replicas},
                            "status": {"availableReplicas": self.available},
                        }
                    ),
                    "",
                )
            if method == "PATCH":
                if not self.deploy:
                    return 404, "{}", "no deploy"
                patch = json.loads(body or "{}")
                spec = patch.get("spec") or {}
                if "replicas" in spec:
                    self.replicas = int(spec["replicas"])
                    self.available = self.replicas
                if "template" in spec:
                    self.rs_uids = {"rs-a", "rs-b"}
                    self.available = self.replicas
                return 200, json.dumps({"spec": {"replicas": self.replicas}}), ""
        if path.endswith("/namespaces/k7-exam/deployments") and method == "POST":
            self.deploy = True
            self.replicas = 1
            self.available = 1
            self.scheduled = True
            self.posts.append("deploy")
            return 201, '{"metadata":{"name":"web"}}', ""
        if path.endswith("/namespaces/k7-exam/pods"):
            items = []
            if self.scheduled:
                items.append(
                    {
                        "spec": {"nodeName": "n0"},
                        "status": {"phase": "Running"},
                    }
                )
            return 200, json.dumps({"items": items}), ""
        if path.endswith("/services/web"):
            if method == "GET":
                return (200, '{"metadata":{"name":"web"}}', "") if self.svc else (404, "{}", "")
        if path.endswith("/namespaces/k7-exam/services") and method == "POST":
            self.svc = True
            self.ep = True
            self.ep_addrs = 1
            self.posts.append("svc")
            return 201, '{"metadata":{"name":"web"}}', ""
        if path.endswith("/endpoints/web"):
            if not self.ep:
                return 404, "{}", ""
            subsets = [{"addresses": [{"ip": "10.42.0.2"}]}] if self.ep_addrs else []
            return 200, json.dumps({"metadata": {"name": "web"}, "subsets": subsets}), ""
        if "replicasets" in path:
            items = [{"metadata": {"uid": u}} for u in sorted(self.rs_uids)]
            return 200, json.dumps({"items": items}), ""
        return 404, "{}", f"unhandled {method} {path}"

    def readyz(self, *_a: object, **_k: object) -> bool:
        return self.readyz_ok

    def nodes_ready(self, *_a: object, **_k: object) -> bool:
        return self.nodes_ready_ok

    def exec_cmd(self, _cid: int, args: list[str], _timeout: float = 12) -> dict:
        if args[:2] == ["k3s", "crictl"]:
            return {
                "exit_code": 0,
                "stdout": f"docker.io/library/busybox 1.36.1 sha256:abc123 {PINNED_IMAGE}\n",
                "stderr": "",
            }
        if self.exec_ok:
            return {"exit_code": 0, "stdout": "k7-exam-ok\n", "stderr": ""}
        return {"exit_code": 1, "stdout": "", "stderr": "no pod"}


def _ctx(api: FakeAPI) -> Ctx:
    return Ctx(
        bridge="k7-br-x",
        cert=None,
        key=None,
        guest_cids=[10],
        curl=api.curl,
        readyz=api.readyz,
        nodes_ready=api.nodes_ready,
        exec_cmd=api.exec_cmd,
    )


class TestPlaybookPages(unittest.TestCase):
    def test_twenty_pages(self) -> None:
        self.assertEqual(len(PAGES), 20)
        self.assertEqual(PAGES[0].id, "api-live")
        self.assertEqual(PAGES[-1].id, "still-serves")

    def test_full_exam_passes(self) -> None:
        api = FakeAPI()
        results = run_through(_ctx(api), 20)
        self.assertEqual(len(results), 20)
        self.assertTrue(all(r.ok for r in results), [r.detail for r in results])
        sc = score_from_results(results, 20)
        self.assertEqual(sc["reward"], 1.0)
        self.assertEqual(sc["playbook"]["passed"], 20)
        self.assertEqual(sc["playbook"]["steps"], [True] * 20)
        self.assertEqual(len(sc["playbook"]["step_s"]), 20)

    def test_continue_after_failed_page(self) -> None:
        api = FakeAPI()
        api.nodes_ready_ok = False
        results = run_through(_ctx(api), 5)
        self.assertTrue(results[0].ok)
        self.assertTrue(results[1].ok)
        self.assertFalse(results[2].ok, "nodes-ready must fail the ceiling")
        self.assertTrue(results[3].ok, "namespace still runs after a fail")
        self.assertTrue(results[4].ok, "apply-deploy still runs")
        sc = score_from_results(results, 5)
        self.assertEqual(sc["playbook"]["passed"], 4)
        self.assertAlmostEqual(sc["reward"], 0.8)
        self.assertEqual(sc["playbook"]["steps"][2], False)

    def test_failed_apply_makes_later_wait_fail(self) -> None:
        api = FakeAPI()

        def curl_no_deploy(bridge: str, path: str, **kw: object):
            if path.endswith("/deployments") and kw.get("method") == "POST":
                return 500, "{}", "apiserver sad"
            return FakeAPI.curl(api, bridge, path, **kw)  # type: ignore[arg-type]

        api.curl = curl_no_deploy  # type: ignore[method-assign]
        ctx = _ctx(api)
        ctx.curl = curl_no_deploy
        results = run_through(ctx, 7)
        self.assertFalse(results[4].ok)
        self.assertFalse(results[5].ok)
        self.assertFalse(results[6].ok)
        sc = score_from_results(results, 7)
        self.assertLess(sc["reward"], 1.0)
        self.assertEqual(len(sc["playbook"]["steps"]), 7)

    def test_reward_is_passed_over_t(self) -> None:
        results = [
            PageResult(True, 0.1, "a"),
            PageResult(False, 1.0, "b"),
            PageResult(True, 0.2, "c"),
        ]
        sc = score_from_results(results, 3)
        self.assertAlmostEqual(sc["reward"], 2.0 / 3.0)
        self.assertEqual(sc["playbook"]["turn"], 3)
        self.assertEqual(sc["playbook"]["total"], 3)

    def test_missing_playbook_payload_is_loud(self) -> None:
        with self.assertRaises(ValueError) as ctx:
            require_playbook_payload({"reward": 0.5})
        self.assertIn("missing playbook", str(ctx.exception))
        with self.assertRaises(ValueError) as ctx2:
            require_playbook_payload({"playbook": {"turn": 1}})
        self.assertIn("passed", str(ctx2.exception))

    def test_inject_faults_are_loud(self) -> None:
        for fid in INJECT_FAULTS:
            with self.assertRaises(ValueError) as ctx:
                refuse_inject_fault(fid)
            self.assertIn("inject fault", str(ctx.exception))
            self.assertIn(fid, str(ctx.exception))
        refuse_inject_fault("none")
        refuse_inject_fault("")

    def test_discover_image_records_digest(self) -> None:
        api = FakeAPI()
        got = discover_pinned_image(api.exec_cmd, 10)
        self.assertEqual(got["name"], PINNED_IMAGE)
        self.assertEqual(got["digest"], "sha256:abc123")

    def test_discover_image_absent_is_loud(self) -> None:
        def empty(_cid: int, _args: list[str], _t: float = 20) -> dict:
            return {"exit_code": 0, "stdout": "REPOSITORY TAG\n", "stderr": ""}

        with self.assertRaises(RuntimeError) as ctx:
            discover_pinned_image(empty, 10)
        self.assertIn("refusing to pull", str(ctx.exception))

    def test_airgap_cache_hit_does_not_pull(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "busybox.tar"
            p.write_bytes(b"airgap")

            def boom(*_a: object, **_k: object) -> None:
                self.fail("cache hit must not pull")

            got = ensure_host_pinned_airgap(p, run=boom)
            self.assertEqual(got, p)

    def test_airgap_host_pull_failure_is_loud(self) -> None:
        def fail(cmd: list[str], **_k: object) -> SimpleNamespace:
            return SimpleNamespace(returncode=1, stderr=f"no {cmd[0]}", stdout="")

        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "busybox.tar"
            with self.assertRaises(RuntimeError) as ctx:
                ensure_host_pinned_airgap(p, run=fail)
            self.assertIn("refusing guest pull", str(ctx.exception))
            self.assertFalse(p.exists())

    def test_plant_missing_disk_is_loud(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            tar = Path(td) / "busybox.tar"
            tar.write_bytes(b"airgap")
            with self.assertRaises(RuntimeError) as ctx:
                plant_pinned_airgap(Path(td) / "missing.img", tar)
            self.assertIn("disk missing", str(ctx.exception))

    def test_wait_pinned_import_timeout_is_loud(self) -> None:
        def empty(_cid: int, _args: list[str], _t: float = 20) -> dict:
            return {"exit_code": 0, "stdout": "REPOSITORY TAG\n", "stderr": ""}

        with self.assertRaises(RuntimeError) as ctx:
            wait_pinned_image(empty, 10, ceiling_s=0.01)
        self.assertIn("airgap plant, not a pull", str(ctx.exception))

    def test_unknown_turn_is_loud(self) -> None:
        with self.assertRaises(ValueError):
            run_page(_ctx(FakeAPI()), 0)
        with self.assertRaises(ValueError):
            run_through(_ctx(FakeAPI()), 21)


class TestPlaybookConfig(unittest.TestCase):
    def test_scoreboard_accepts_playbook(self) -> None:
        import server

        ns = server.parse_args(
            [
                "--source-mode",
                "ubuntu",
                "--memory-mb",
                "2048",
                "--scoreboard",
                "playbook",
            ]
        )
        cfg = server.Config(ns)
        self.assertEqual(cfg.scoreboard, "playbook")
        self.assertEqual(cfg.ready_gate, "api")

    def test_playbook_forces_ready_gate_api(self) -> None:
        import server

        ns = server.parse_args(
            [
                "--source-mode",
                "ubuntu",
                "--memory-mb",
                "2048",
                "--scoreboard",
                "playbook",
                "--ready-gate",
                "nodes",
            ]
        )
        with self.assertRaises(SystemExit) as ctx:
            server.Config(ns)
        self.assertIn("ready_gate=api", str(ctx.exception))

    def test_playbook_refuses_busybox_modes(self) -> None:
        import server

        for mode in ("create", "adopt"):
            ns = server.parse_args(["--source-mode", mode, "--scoreboard", "playbook"])
            with self.assertRaises(SystemExit) as ctx:
                server.Config(ns)
            self.assertIn("playbook", str(ctx.exception))
            self.assertIn("ubuntu", str(ctx.exception))

    def test_unknown_scoreboard_lists_playbook(self) -> None:
        import server

        ns = server.parse_args(["--scoreboard", "health"])
        ns.scoreboard = "batfish"
        with self.assertRaises(SystemExit) as ctx:
            server.Config(ns)
        self.assertIn("playbook", str(ctx.exception))

    def test_lease_playbook_loud_with_inject(self) -> None:
        import server
        from lease import Env, Lease

        ns = server.parse_args(
            [
                "--source-mode",
                "ubuntu",
                "--memory-mb",
                "2048",
                "--scoreboard",
                "playbook",
            ]
        )
        gym = server.Gym(server.Config(ns))
        L = Lease(
            lease_id="lease-x",
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
                    env_id="lease-x-0",
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
        self.assertIn("inject", str(ctx.exception).lower())

    def test_score_missing_playbook_steps_is_loud(self) -> None:
        import server
        from lease import Env, Lease

        ns = server.parse_args(
            [
                "--source-mode",
                "ubuntu",
                "--memory-mb",
                "2048",
                "--scoreboard",
                "playbook",
            ]
        )
        gym = server.Gym(server.Config(ns))
        L = Lease(
            lease_id="lease-y",
            node_id="t",
            group_id="g",
            fault_id="none",
            tree_id="gym-src-t",
            source_node_id="root",
            n=1,
            created_at=0.0,
            expires_at=9e9,
            envs=[
                Env(
                    env_id="lease-y-0",
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
        self.assertIn("playbook", str(ctx.exception).lower())


if __name__ == "__main__":
    unittest.main()
