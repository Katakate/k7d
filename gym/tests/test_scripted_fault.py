"""Scripted (data-driven) faults — stub, no KVM."""

from __future__ import annotations

import sys
import tempfile
import time
import unittest
from pathlib import Path
from typing import Any
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import faults  # noqa: E402
from faults import (  # noqa: E402
    GRPO_FAULTS,
    SCRIPTED_ID,
    UnknownScenario,
    get,
    get_scenario,
    set_scenario_root,
)
from faults.scenario_spec import ScenarioError, env_prelude, parse_yaml  # noqa: E402
from faults.scripted import load, registry  # noqa: E402
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
        timeout: Any = None,
        dilation: Any = None,
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
        _ = (tree_id, node_id)
        return {"status": "ok"}


YAML = """\
id: control-plane-down/k3s-sigstop
fault_type: control-plane-down
variant: k3s-sigstop
tier: 1
summary: "k3s server SIGSTOPped; the unit still reports active."
symptom: "The API server does not answer."
params:
  unit: k3s
inject_timeout_s: 30
probe_timeout_s: 8
restored_poll_s: 0
obs:
  expose_services: false
  must_match:
    - '"readyz":\\s*false'
  must_not_match:
    - 'inactive'
hit_regex: 'systemctl\\s+(re)?start\\s+k3s'
wreck: "systemctl stop k3s; reboot"
"""

SH = "#!/bin/sh\nset -eu\ntrue\n"


def _write(root: Path, *, yaml: str = YAML, scripts: dict[str, str] | None = None) -> Path:
    spec = parse_yaml(yaml) if yaml.strip() else {}
    rel = str(spec.get("id") or "control-plane-down/k3s-sigstop")
    d = root / rel
    d.mkdir(parents=True, exist_ok=True)
    (d / "scenario.yaml").write_text(yaml)
    for name in ("inject.sh", "visible.sh", "restored.sh", "reference-fix.sh"):
        text = (scripts or {}).get(name, SH)
        if text is None:  # the test wants this script missing
            (d / name).unlink(missing_ok=True)
            continue
        (d / name).write_text(text)
    return d


class TestParse(unittest.TestCase):
    def test_subset_round_trip(self) -> None:
        spec = parse_yaml(YAML)
        self.assertEqual(spec["tier"], 1)
        self.assertEqual(spec["params"], {"unit": "k3s"})
        self.assertIs(spec["obs"]["expose_services"], False)
        self.assertEqual(spec["obs"]["must_not_match"], ["inactive"])
        self.assertEqual(spec["wreck"], "systemctl stop k3s; reboot")

    def test_hash_in_quoted_value_is_not_a_comment(self) -> None:
        spec = parse_yaml(YAML.replace("'inactive'", "'k7s#fill'"))
        self.assertEqual(spec["obs"]["must_not_match"], ["k7s#fill"])

    def test_tab_indent_is_loud(self) -> None:
        with self.assertRaises(ScenarioError) as ctx:
            parse_yaml("obs:\n\tfoo: 1\n")
        self.assertIn("tab", str(ctx.exception))

    def test_duplicate_key_is_loud(self) -> None:
        with self.assertRaises(ScenarioError):
            parse_yaml("tier: 1\ntier: 2\n")

    def test_env_prelude_exports_params_and_identity(self) -> None:
        text = env_prelude(parse_yaml(YAML))
        self.assertIn("export K7S_ID='control-plane-down/k3s-sigstop'\n", text)
        self.assertIn("export K7S_TIER='1'\n", text)
        self.assertIn("export K7S_UNIT='k3s'\n", text)


class TestLoadRejects(unittest.TestCase):
    def _reject(self, msg: str, **kw: Any) -> str:
        with tempfile.TemporaryDirectory() as td:
            d = _write(Path(td), **kw)
            with self.assertRaises((ScenarioError, FileNotFoundError)) as ctx:
                load(d, rel_id=f"{d.parent.name}/{d.name}")
        text = str(ctx.exception)
        self.assertIn(msg, text)
        return text

    def test_accepts_the_good_one(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            d = _write(Path(td))
            f = load(d, rel_id="control-plane-down/k3s-sigstop")
        self.assertEqual(f.scenario_id, "control-plane-down/k3s-sigstop")
        self.assertEqual(f.tier, 1)
        self.assertFalse(f.expose_services)
        self.assertEqual(f.good_fix_hint["args"], ["sh", "-c", "true"])

    def test_missing_script(self) -> None:
        self._reject("no restored.sh", scripts={"restored.sh": None})

    def test_id_not_path(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            d = _write(Path(td))
            with self.assertRaises(ScenarioError) as ctx:
                load(d, rel_id="other/elsewhere")
        self.assertIn("directory path", str(ctx.exception))

    def test_unknown_key(self) -> None:
        self._reject("unknown keys", yaml=YAML + "extra_thing: 1\n")

    def test_tier1_may_not_expose_services(self) -> None:
        self._reject(
            "expose_services must be false",
            yaml=YAML.replace("expose_services: false", "expose_services: true"),
        )

    def test_tier1_needs_must_not_match(self) -> None:
        self._reject(
            "must_not_match",
            yaml=YAML.replace(
                "  must_not_match:\n    - 'inactive'\n", "  must_not_match: []\n"
            ),
        )

    def test_empty_regex_is_loud(self) -> None:
        self._reject(
            "matches everything", yaml=YAML.replace("    - 'inactive'\n", "    - ''\n")
        )

    def test_tier0_must_expose_services(self) -> None:
        self._reject(
            "expose_services must be true",
            yaml=YAML.replace("tier: 1", "tier: 0"),
        )

    def test_out_of_range_timeout(self) -> None:
        self._reject("out of range", yaml=YAML.replace("inject_timeout_s: 30", "inject_timeout_s: 900"))

    def test_script_without_set_eu(self) -> None:
        self._reject("set -eu", scripts={"inject.sh": "#!/bin/sh\ntrue\n"})

    def test_script_bashism(self) -> None:
        self._reject(
            "bashism",
            scripts={"visible.sh": "#!/bin/sh\nset -eu\n[[ -f /tmp/x ]]\n"},
        )

    def test_script_too_big(self) -> None:
        self._reject(
            "limit",
            scripts={"inject.sh": "#!/bin/sh\nset -eu\n" + "# pad\n" * 2000},
        )

    def test_script_may_not_reboot(self) -> None:
        self._reject("reboot", scripts={"inject.sh": "#!/bin/sh\nset -eu\nreboot\n"})

    def test_bad_shebang(self) -> None:
        self._reject("#!/bin/sh", scripts={"inject.sh": "#!/bin/bash\nset -eu\n"})


class TestRegistry(unittest.TestCase):
    def test_registry_and_lookup(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            _write(root)
            _write(root, yaml=YAML.replace("k3s-sigstop", "k3s-stopped"))
            reg = registry(root)
            self.assertEqual(
                sorted(reg),
                ["control-plane-down/k3s-sigstop", "control-plane-down/k3s-stopped"],
            )
            self.assertEqual(set_scenario_root(root), 2)
            self.assertEqual(
                get_scenario("control-plane-down/k3s-stopped").variant
                if hasattr(get_scenario("control-plane-down/k3s-stopped"), "variant")
                else "k3s-stopped",
                "k3s-stopped",
            )
            with self.assertRaises(UnknownScenario) as ctx:
                get_scenario("nope/nope")
            self.assertIn("control-plane-down/k3s-sigstop", str(ctx.exception))
        set_scenario_root(None)

    def test_empty_root_is_loud(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            with self.assertRaises(ScenarioError) as ctx:
                registry(Path(td))
        self.assertIn("no scenarios", str(ctx.exception))

    def test_stray_scenario_depth_is_loud(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            _write(root)
            (root / "loose").mkdir()
            (root / "loose" / "scenario.yaml").write_text(YAML)
            with self.assertRaises(ScenarioError) as ctx:
                registry(root)
        self.assertIn("fault_type", str(ctx.exception))

    def test_scripted_is_a_grpo_fault_but_not_gettable_by_id(self) -> None:
        self.assertIn(SCRIPTED_ID, GRPO_FAULTS)
        with self.assertRaises(ValueError) as ctx:
            get(SCRIPTED_ID)
        self.assertIn("scenario_id", str(ctx.exception))

    def test_scenario_without_a_root_is_loud(self) -> None:
        set_scenario_root(None)
        with self.assertRaises(ValueError) as ctx:
            get_scenario("control-plane-down/k3s-stopped")
        self.assertIn("GYM_SCENARIO_DIR", str(ctx.exception))


class TestScriptedProbes(unittest.TestCase):
    def setUp(self) -> None:
        self.td = tempfile.TemporaryDirectory()
        self.addCleanup(self.td.cleanup)
        d = _write(
            Path(self.td.name),
            scripts={"inject.sh": "#!/bin/sh\nset -eu\necho planted\n"},
        )
        self.fault = load(d, rel_id="control-plane-down/k3s-sigstop")
        self.env = Env(
            env_id="lease-s-0",
            branch_node_id="n0",
            index=0,
            bridge="k7-br-s0",
            guest_ips=["10.200.0.2"],
            guest_cids=[77],
        )

    def test_inject_sends_prelude_and_timeout(self) -> None:
        seen: dict[str, Any] = {}

        def fake(cid: int, args: list[str], timeout_s: float) -> dict[str, Any]:
            seen.update(cid=cid, args=args, timeout_s=timeout_s)
            return {"exit_code": 0, "stdout": "planted", "stderr": ""}

        with patch("agent.exec_cmd", fake):
            self.fault.inject(self.env, None)
        self.assertEqual(seen["cid"], 77)
        self.assertEqual(seen["timeout_s"], 30.0)
        self.assertEqual(seen["args"][:2], ["sh", "-c"])
        self.assertTrue(seen["args"][2].startswith("export K7S_ID="))
        self.assertIn("echo planted", seen["args"][2])

    def test_inject_failure_is_loud(self) -> None:
        with patch(
            "agent.exec_cmd",
            return_value={"exit_code": 3, "stdout": "", "stderr": "boom"},
        ):
            with self.assertRaises(RuntimeError) as ctx:
                self.fault.inject(self.env, None)
        self.assertIn("boom", str(ctx.exception))
        self.assertIn("control-plane-down/k3s-sigstop", str(ctx.exception))

    def test_visible_and_healthy_map_exit_codes(self) -> None:
        codes = {"visible.sh": 0, "restored.sh": 1}

        def fake(cid: int, args: list[str], timeout_s: float) -> dict[str, Any]:
            _ = (cid, timeout_s)
            which = "visible.sh" if "visible" in args[2] else "restored.sh"
            return {"exit_code": codes[which], "stdout": "", "stderr": ""}

        # Distinguish the two probes by body text.
        self.fault.scripts["visible.sh"] = "#!/bin/sh\nset -eu\n: visible\n"
        self.fault.scripts["restored.sh"] = "#!/bin/sh\nset -eu\n: restored\n"
        with patch("agent.exec_cmd", fake):
            self.assertTrue(self.fault.fault_visible(self.env))
            self.assertFalse(self.fault.healthy(self.env))
            codes["visible.sh"], codes["restored.sh"] = 1, 0
            self.assertFalse(self.fault.fault_visible(self.env))
            self.assertTrue(self.fault.healthy(self.env))

    def test_unreachable_member0_is_visible_and_unhealthy(self) -> None:
        dead = Env(
            env_id="lease-s-1",
            branch_node_id="n1",
            index=1,
            bridge="k7-br-s1",
            guest_ips=["10.200.0.2"],
            guest_cids=[],
        )
        self.assertTrue(self.fault.fault_visible(dead))
        self.assertFalse(self.fault.healthy(dead))

    def test_restored_poll_returns_true_on_a_later_try(self) -> None:
        self.fault.restored_poll_s = 6.0
        tries = {"n": 0}

        def fake(cid: int, args: list[str], timeout_s: float) -> dict[str, Any]:
            _ = (cid, args, timeout_s)
            tries["n"] += 1
            return {"exit_code": 0 if tries["n"] >= 3 else 1, "stdout": "", "stderr": ""}

        with patch("agent.exec_cmd", fake), patch("faults.scripted.time.sleep"):
            self.assertTrue(self.fault.healthy(self.env))
        self.assertEqual(tries["n"], 3)

    def test_restored_poll_gives_up_at_the_bound(self) -> None:
        self.fault.restored_poll_s = 4.0
        clock = {"t": 0.0}

        def fake(cid: int, args: list[str], timeout_s: float) -> dict[str, Any]:
            _ = (cid, args, timeout_s)
            return {"exit_code": 1, "stdout": "", "stderr": ""}

        def sleep(dt: float) -> None:
            clock["t"] += dt

        with (
            patch("agent.exec_cmd", fake),
            patch("faults.scripted.time.sleep", sleep),
            patch("faults.scripted.time.monotonic", lambda: clock["t"]),
        ):
            self.assertFalse(self.fault.healthy(self.env))
        self.assertGreaterEqual(clock["t"], 4.0)


def _scripted_gym(root: Path) -> Any:
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
            "--scenario-dir",
            str(root),
        ]
    )
    g = server.Gym(server.Config(ns))
    g.client = RecordingK7d()  # type: ignore[assignment]
    g.source_vms = 3
    return g


class TestScriptedLease(unittest.TestCase):
    def setUp(self) -> None:
        self.td = tempfile.TemporaryDirectory()
        self.addCleanup(self.td.cleanup)
        self.addCleanup(set_scenario_root, None)
        self.root = Path(self.td.name)
        _write(self.root)
        self.sid = "control-plane-down/k3s-sigstop"

    def _lease(self, gym: Any, body: dict[str, Any]) -> dict[str, Any]:
        tid = gym.cfg.source_tree_id
        n = int(body["n"])
        bridges = [k7_bridge_name(f"{tid}-child-{i}") for i in range(1, n + 1)]
        with (
            patch("server.list_bridges", return_value=bridges),
            patch.object(gym, "_api_certs", lambda: (None, None)),
            patch(
                "agent.exec_cmd",
                return_value={"exit_code": 0, "stdout": "", "stderr": ""},
            ),
        ):
            return gym.lease(body, "test")

    def test_lease_carries_scenario_id_tier_and_placeholder_hint(self) -> None:
        g = _scripted_gym(self.root)
        rec = self._lease(
            g,
            {
                "fault_id": SCRIPTED_ID,
                "scenario_id": self.sid,
                "n": 2,
                "group_id": "g",
                "ttl_s": 60,
            },
        )
        self.assertEqual(rec["scenario_id"], self.sid)
        self.assertEqual(
            rec["scenario_digest"], get_scenario(self.sid).digest
        )
        self.assertEqual(rec["fault_type"], "control-plane-down")
        self.assertEqual(rec["tier"], 1)
        self.assertEqual(rec["good_fix_hint"]["args"], ["sh", "-c", "true"])
        L = g.leases.get(rec["lease_id"])
        self.assertEqual(L.scenario_id, self.sid)
        self.assertEqual(L.as_public()["scenario_id"], self.sid)

    def test_scripted_without_scenario_id_is_loud(self) -> None:
        g = _scripted_gym(self.root)
        with self.assertRaises(ValueError) as ctx:
            self._lease(
                g, {"fault_id": SCRIPTED_ID, "n": 2, "group_id": "g", "ttl_s": 60}
            )
        self.assertIn("scenario_id", str(ctx.exception))

    def test_unknown_scenario_lists_known_ids(self) -> None:
        g = _scripted_gym(self.root)
        with self.assertRaises(UnknownScenario) as ctx:
            self._lease(
                g,
                {
                    "fault_id": SCRIPTED_ID,
                    "scenario_id": "nope/nope",
                    "n": 2,
                    "group_id": "g",
                    "ttl_s": 60,
                },
            )
        self.assertIn(self.sid, str(ctx.exception))

    def test_scenario_dir_requires_grpo_board(self) -> None:
        import server

        ns = server.parse_args(
            [
                "--source-mode",
                "ubuntu",
                "--memory-mb",
                "2048",
                "--scoreboard",
                "health",
                "--scenario-dir",
                str(self.root),
            ]
        )
        with self.assertRaises(SystemExit) as ctx:
            server.Config(ns)
        self.assertIn("grpo", str(ctx.exception))

    def test_bad_scenario_fails_gym_start(self) -> None:
        _write(self.root, yaml=YAML.replace("k3s-sigstop", "broken") + "junk: 1\n")
        import server

        ns = server.parse_args(
            [
                "--source-mode",
                "ubuntu",
                "--memory-mb",
                "2048",
                "--scoreboard",
                "grpo",
                "--scenario-dir",
                str(self.root),
            ]
        )
        with self.assertRaises(SystemExit) as ctx:
            server.Config(ns)
        self.assertIn("unknown keys", str(ctx.exception))

    def test_inject_runs_every_member_in_parallel(self) -> None:
        g = _scripted_gym(self.root)
        fault = get_scenario(self.sid)
        seen: list[int] = []
        lock = __import__("threading").Lock()

        def slow_inject(env: Env, client: Any) -> None:
            _ = client
            time.sleep(0.2)
            with lock:
                seen.append(env.index)

        tid = g.cfg.source_tree_id
        bridges = [k7_bridge_name(f"{tid}-child-{i}") for i in range(1, 9)]
        t0 = time.perf_counter()
        with (
            patch.object(fault, "inject", slow_inject),
            patch.object(fault, "fault_visible", return_value=True),
            patch("server.list_bridges", return_value=bridges),
            patch.object(g, "_api_certs", lambda: (None, None)),
        ):
            rec = g.lease(
                {
                    "fault_id": SCRIPTED_ID,
                    "scenario_id": self.sid,
                    "n": 8,
                    "group_id": "g8",
                    "ttl_s": 60,
                },
                "test",
            )
        wall = time.perf_counter() - t0
        self.assertEqual(sorted(seen), list(range(8)))
        self.assertLess(wall, 1.2, f"8 x 0.2 s injects took {wall:.2f}s (not parallel)")
        self.assertLess(rec["inject_ms"], 1200.0)

    def test_inject_that_does_not_take_is_loud_and_releases(self) -> None:
        g = _scripted_gym(self.root)
        fault = get_scenario(self.sid)
        tid = g.cfg.source_tree_id
        bridges = [k7_bridge_name(f"{tid}-child-{i}") for i in range(1, 5)]
        released: list[str] = []

        def visible(env: Env) -> bool:
            return env.index != 2

        with (
            patch.object(fault, "inject", lambda env, client: None),
            patch.object(fault, "fault_visible", visible),
            patch("server.list_bridges", return_value=bridges),
            patch.object(g, "_api_certs", lambda: (None, None)),
            patch.object(
                g, "release", lambda lid, reason="": released.append(lid) or {}
            ),
            patch(
                "agent.exec_cmd",
                return_value={"exit_code": 0, "stdout": "", "stderr": ""},
            ),
        ):
            with self.assertRaises(RuntimeError) as ctx:
                g.lease(
                    {
                        "fault_id": SCRIPTED_ID,
                        "scenario_id": self.sid,
                        "n": 4,
                        "group_id": "g4",
                        "ttl_s": 60,
                    },
                    "test",
                )
        self.assertIn("did not take", str(ctx.exception))
        self.assertIn(self.sid, str(ctx.exception))
        self.assertEqual(len(released), 1)


class TestScriptedObsAndScore(unittest.TestCase):
    def setUp(self) -> None:
        self.td = tempfile.TemporaryDirectory()
        self.addCleanup(self.td.cleanup)
        self.addCleanup(set_scenario_root, None)
        self.root = Path(self.td.name)
        _write(self.root)
        _write(
            self.root,
            yaml=YAML.replace("k3s-sigstop", "reference-visible")
            .replace("tier: 1", "tier: 0")
            .replace("expose_services: false", "expose_services: true"),
        )
        self.sid = "control-plane-down/k3s-sigstop"
        self.ref = "control-plane-down/reference-visible"

    def _commit(self, gym: Any, n: int, scenario_id: str) -> Lease:
        envs = [
            Env(
                env_id=f"lease-s-{i}",
                branch_node_id=f"n{i}",
                index=i,
                bridge=f"k7-br-s{i}",
                guest_ips=["10.200.0.2"],
                guest_cids=[20 + i],
            )
            for i in range(n)
        ]
        L = Lease(
            lease_id="lease-s",
            node_id="t",
            group_id="g",
            fault_id=SCRIPTED_ID,
            scenario_id=scenario_id,
            tree_id="gym-src-t",
            source_node_id="root",
            n=n,
            created_at=0.0,
            expires_at=9e9,
            envs=envs,
        )
        gym.leases.reserve(L)
        return gym.leases.commit(L.lease_id, envs)

    def _services_stdout(self) -> dict[str, Any]:
        return {
            "exit_code": 0,
            "stdout": "inactive\n2: eth0: <BROADCAST> mtu 1500 state DOWN\n",
            "stderr": "",
        }

    def test_tier1_obs_hides_services_and_links(self) -> None:
        g = _scripted_gym(self.root)
        L = self._commit(g, 1, self.sid)
        with (
            patch("server.curl_api", return_value=(599, "", "api down")),
            patch("server.curl_readyz", return_value=False),
            patch("server.agent.exec_cmd", return_value=self._services_stdout()),
        ):
            out = g.obs(L.envs[0].env_id)
        obs = out["observation"]
        self.assertNotIn("services", obs)
        self.assertNotIn("links", obs)
        self.assertNotIn("services_error", obs)
        self.assertIs(obs["readyz"], False)
        self.assertEqual(out["scenario_id"], self.sid)
        self.assertEqual(out["scenario_tier"], 1)

    def test_tier0_obs_keeps_services(self) -> None:
        g = _scripted_gym(self.root)
        L = self._commit(g, 1, self.ref)
        with (
            patch("server.curl_api", return_value=(599, "", "api down")),
            patch("server.curl_readyz", return_value=False),
            patch("server.agent.exec_cmd", return_value=self._services_stdout()),
        ):
            out = g.obs(L.envs[0].env_id)
        obs = out["observation"]
        self.assertEqual(obs["services"]["k3s.service"], "inactive")
        self.assertEqual(obs["links"]["eth0"], "down")
        self.assertEqual(out["scenario_tier"], 0)

    def test_catalog_fault_obs_is_unchanged(self) -> None:
        g = _scripted_gym(self.root)
        L = self._commit(g, 1, self.sid)
        L.fault_id = "kill-member-0"
        L.scenario_id = ""
        with (
            patch("server.curl_api", return_value=(599, "", "api down")),
            patch("server.curl_readyz", return_value=False),
            patch("server.agent.exec_cmd", return_value=self._services_stdout()),
        ):
            out = g.obs(L.envs[0].env_id)
        self.assertIn("services", out["observation"])
        self.assertNotIn("scenario_tier", out)

    def test_score_grpo_fixers_noops_and_a_wreck(self) -> None:
        g = _scripted_gym(self.root)
        L = self._commit(g, 8, self.sid)
        fault = get_scenario(self.sid)

        def exec_cmd(cid: int, args: list[str], timeout_s: float = 5) -> dict[str, Any]:
            _ = (args, timeout_s)
            if cid == L.envs[7].guest_cids[0]:
                raise RuntimeError("vsock connect timed out")
            return {"exit_code": 0, "stdout": "", "stderr": ""}

        fixed = {e.env_id for e in L.envs[:4]}
        with (
            patch("server.agent.exec_cmd", exec_cmd),
            patch.object(fault, "fault_visible", lambda e: e.env_id not in fixed),
            patch.object(fault, "healthy", lambda e: e.env_id in fixed),
            patch("server.curl_readyz", lambda *a, **k: True),
            patch("server.curl_nodes_ready", lambda *a, **k: True),
            patch.object(g, "_source_intact", return_value=True),
            patch.object(
                g, "_env_certs", lambda _e: (Path("/etc/hosts"), Path("/etc/hosts"))
            ),
        ):
            out = g.score(L.lease_id)
        self.assertEqual(out["scoreboard"], "grpo")
        self.assertEqual(len(out["scores"]), 8)
        self.assertEqual([r["env_id"] for r in out["scores"]], [e.env_id for e in L.envs])
        for row in out["scores"][:4]:
            self.assertEqual(set(row["terms"]), set(TERM_KEYS))
            self.assertEqual(row["reward"], 1.0)
        for row in out["scores"][4:7]:
            self.assertEqual(row["terms"]["contained"], 0.0)
            self.assertEqual(row["terms"]["restored"], 0.0)
            self.assertEqual(row["reward"], 0.6)
        self.assertTrue(out["scores"][7]["unreachable"])
        self.assertEqual(out["scores"][7]["reward"], 0.2)


class TestDigest(unittest.TestCase):
    def test_digest_changes_with_a_script_edit(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            d = _write(root)
            first = load(d, rel_id="control-plane-down/k3s-sigstop").digest
            (d / "inject.sh").write_text("#!/bin/sh\nset -eu\n: edited\n")
            second = load(d, rel_id="control-plane-down/k3s-sigstop").digest
        self.assertNotEqual(first, second)
        self.assertEqual(len(first), 16)

    def test_digest_changes_with_a_param_edit(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            d = _write(root)
            first = load(d, rel_id="control-plane-down/k3s-sigstop").digest
            (d / "scenario.yaml").write_text(YAML.replace("unit: k3s", "unit: k3s2"))
            second = load(d, rel_id="control-plane-down/k3s-sigstop").digest
        self.assertNotEqual(first, second)


class TestVendoredSpecModule(unittest.TestCase):
    def test_scenario_spec_has_no_third_party_import(self) -> None:
        """k7-scenarios vendors this file verbatim; keep it stdlib-only."""
        text = (Path(faults.__file__).parent / "scenario_spec.py").read_text()
        for bad in ("import yaml", "from yaml", "import jsonschema"):
            self.assertNotIn(bad, text)


if __name__ == "__main__":
    unittest.main()
