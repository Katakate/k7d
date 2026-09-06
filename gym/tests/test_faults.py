"""Fault catalog + score term keys — no KVM."""

from __future__ import annotations

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from faults import UnknownFault, allowlist, get
from scoring import TERM_KEYS, reward_from_terms, terms


class TestCatalog(unittest.TestCase):
    def test_allowlist_has_v0_injectors(self) -> None:
        ids = allowlist()
        self.assertEqual(
            ids,
            [
                "kill-member-0",
                "none",
                "partition-member-0",
                "relay",
                "tetra-churn",
            ],
        )
        for fid in ids:
            f = get(fid)
            self.assertEqual(f.id, fid)
            self.assertIn("ubuntu", f.modes)
            if fid not in ("tetra-churn", "relay"):
                self.assertIn("create", f.modes)
            self.assertIn("action", f.good_fix_hint)
            self.assertIn("args", f.good_fix_hint)

    def test_unknown_fault_lists_allowlist(self) -> None:
        with self.assertRaises(UnknownFault) as ctx:
            get("not-a-fault")
        msg = str(ctx.exception)
        self.assertIn("unknown fault_id 'not-a-fault'", msg)
        self.assertIn("allowlist:", msg)
        for fid in allowlist():
            self.assertIn(fid, msg)

    def test_none_is_vacuous(self) -> None:
        f = get("none")
        f.inject(None, None)
        self.assertFalse(f.fault_visible(None))
        self.assertTrue(f.healthy(None))
        self.assertFalse(
            f.source_shows_fault(guest_cids=[], bridge="", guest_ips=[])
        )


class TestKeepApiserver(unittest.TestCase):
    """Tetragon scoring needs the guest API (CHALLENGES #146)."""

    def test_default_is_stop_k3s(self) -> None:
        from faults.kill_member_0 import KillMember0, TETRAGON_PATH

        f = KillMember0()
        self.assertFalse(f.keep_apiserver)
        self.assertEqual(f.tetragon_paths, (TETRAGON_PATH,))

    def test_keep_apiserver_inject_does_not_stop_k3s(self) -> None:
        from unittest.mock import patch

        from faults.kill_member_0 import INJECT_POD, KillMember0, TETRAGON_PATH

        f = KillMember0()
        f.source_mode = "ubuntu"
        f.keep_apiserver = True
        calls: list[list[str]] = []
        pods: list[tuple[str, str]] = []

        def fake_exec(_cid: int, args: list[str], timeout_s: float = 8) -> dict:
            _ = timeout_s
            calls.append(list(args))
            return {"exit_code": 0, "stdout": "", "stderr": ""}

        def fake_pod(bridge: str, cert: object, key: object, name: str, path: str) -> None:
            _ = (bridge, cert, key)
            pods.append((name, path))

        env = type(
            "E",
            (),
            {
                "guest_cids": [3],
                "bridge": "k7-br-x",
                "cert_path": "/etc/hosts",
                "key_path": "/etc/hosts",
            },
        )()
        with (
            patch("faults.kill_member_0.exec_cmd", fake_exec),
            patch("faults.kill_member_0.member0_cid", return_value=3),
            patch("tetragon.create_inject_pod", fake_pod),
            patch("tetragon.wait_path_events", lambda *_a, **_k: ""),
        ):
            f.inject(env, None)
        self.assertEqual(calls, [["touch", TETRAGON_PATH]])
        self.assertEqual(pods, [(INJECT_POD, TETRAGON_PATH)])

    def test_keep_apiserver_visible_is_the_marker(self) -> None:
        from unittest.mock import patch

        from faults.kill_member_0 import KillMember0, TETRAGON_PATH

        f = KillMember0()
        f.source_mode = "ubuntu"
        f.keep_apiserver = True
        seen: list[list[str]] = []

        def fake_ok(_cid: int, args: list[str], timeout_s: float = 5) -> bool:
            _ = timeout_s
            seen.append(list(args))
            return True

        env = type("E", (), {"guest_cids": [3]})()
        with patch("faults.kill_member_0.exec_ok", fake_ok):
            self.assertTrue(f.fault_visible(env))
            self.assertFalse(f.healthy(env))
        self.assertEqual(seen[0], ["test", "-f", TETRAGON_PATH])
        self.assertEqual(seen[1], ["test", "-f", TETRAGON_PATH])


class TestTetraChurn(unittest.TestCase):
    def test_paths_are_under_kprobe_prefix(self) -> None:
        from faults.tetra_churn import CHURN_PATHS, TetraChurn
        from sensors import PATH_PREFIX

        self.assertEqual(len(CHURN_PATHS), 5)
        for p in CHURN_PATHS:
            self.assertTrue(p.startswith(PATH_PREFIX), p)
        f = TetraChurn()
        self.assertTrue(f.keep_apiserver)
        self.assertEqual(f.modes, ("ubuntu",))
        self.assertEqual(f.tetragon_paths, CHURN_PATHS)
        self.assertEqual(f.good_fix_hint["args"][:2], ["rm", "-f"])

    def test_inject_touches_all_paths_in_one_pod(self) -> None:
        from unittest.mock import patch

        from faults.tetra_churn import CHURN_PATHS, INJECT_POD, TetraChurn

        f = TetraChurn()
        calls: list[list[str]] = []
        pods: list[tuple] = []

        def fake_exec(_cid: int, args: list[str], timeout_s: float = 8) -> dict:
            _ = timeout_s
            calls.append(list(args))
            return {"exit_code": 0, "stdout": "", "stderr": ""}

        def fake_pod(*a, extra=(), **_k):
            pods.append((a[3], a[4], extra))

        env = type(
            "E",
            (),
            {
                "guest_cids": [3],
                "bridge": "k7-br-x",
                "cert_path": "/etc/hosts",
                "key_path": "/etc/hosts",
            },
        )()
        with (
            patch("faults.tetra_churn.exec_cmd", fake_exec),
            patch("faults.tetra_churn.member0_cid", return_value=3),
            patch("tetragon.create_inject_pod", fake_pod),
            patch("tetragon.wait_path_events", lambda *_a, **_k: ""),
        ):
            f.inject(env, None)
        self.assertEqual(calls, [["touch", p] for p in CHURN_PATHS])
        self.assertEqual(pods, [(INJECT_POD, CHURN_PATHS[0], CHURN_PATHS[1:])])


class TestTermKeys(unittest.TestCase):
    def test_five_keys_always_present(self) -> None:
        t = terms(
            liveness=1.0,
            workload_ready=0.0,
            source_intact=1.0,
            contained=1.0,
            restored=0.0,
        )
        self.assertEqual(list(t), list(TERM_KEYS))
        self.assertEqual(reward_from_terms(t), 0.6)

    def test_missing_contained_or_restored_is_loud(self) -> None:
        with self.assertRaises(TypeError):
            terms(  # type: ignore[call-arg]
                liveness=1.0, workload_ready=1.0, source_intact=1.0
            )
        with self.assertRaises(KeyError) as ctx:
            reward_from_terms(
                {
                    "liveness": 1.0,
                    "workload_ready": 1.0,
                    "source_intact": 1.0,
                }
            )
        self.assertIn("contained", str(ctx.exception))


if __name__ == "__main__":
    unittest.main()
