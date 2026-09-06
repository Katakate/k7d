"""Lease table + TTL — no KVM."""

from __future__ import annotations

import sys
import time
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from lease import Env, Lease, LeaseTable, new_env_id, new_lease_id


def _lease(ttl_s: float, n: int = 2, now: float | None = None) -> Lease:
    t = now if now is not None else time.time()
    lid = new_lease_id()
    envs = [
        Env(
            env_id=new_env_id(lid, i),
            branch_node_id=f"br-{i}",
            index=i,
            bridge=f"k7-br-x{i}",
            guest_ips=["10.200.0.2"],
            guest_cids=[100 + i],
        )
        for i in range(n)
    ]
    return Lease(
        lease_id=lid,
        node_id="node-a",
        group_id="g",
        fault_id="none",
        tree_id="gym-src-1",
        source_node_id="root",
        n=n,
        created_at=t,
        expires_at=t + ttl_s,
        envs=envs,
    )


class TestLeaseTable(unittest.TestCase):
    def test_begin_release_keeps_get_until_mark(self) -> None:
        t = LeaseTable(max_leases=1)
        L = _lease(60)
        self.assertIsNone(t.reserve(L))
        t.commit(L.lease_id, L.envs)
        started = t.begin_release(L.lease_id)
        self.assertIsNotNone(started)
        self.assertIsNotNone(t.get(L.lease_id), "GET must still see a releasing lease")
        self.assertIsNone(t.begin_release(L.lease_id), "second begin is a no-op")
        t.mark_released(L.lease_id)
        self.assertIsNone(t.get(L.lease_id))

    def test_reserve_commit_release(self) -> None:
        t = LeaseTable(max_leases=2)
        L = _lease(60)
        L.envs = []
        self.assertIsNone(t.reserve(L))
        self.assertEqual(t.in_flight(), 1)
        committed = t.commit(
            L.lease_id,
            [
                Env(
                    env_id=new_env_id(L.lease_id, 0),
                    branch_node_id="n0",
                    index=0,
                    bridge="k7-br-a",
                    guest_ips=["10.200.0.2"],
                    guest_cids=[3],
                )
            ],
        )
        self.assertFalse(committed.pending)
        got = t.get(L.lease_id)
        self.assertIsNotNone(got)
        released = t.mark_released(L.lease_id)
        self.assertIsNotNone(released)
        assert released is not None
        self.assertTrue(released.released)
        self.assertIsNone(t.get(L.lease_id))
        self.assertEqual(t.in_flight(), 0)

    def test_max_leases(self) -> None:
        t = LeaseTable(max_leases=1)
        a = _lease(60)
        b = _lease(60)
        self.assertIsNone(t.reserve(a))
        msg = t.reserve(b)
        self.assertIsNotNone(msg)
        assert msg is not None
        self.assertIn("max_leases=1", msg)

    def test_ttl_expiry(self) -> None:
        t = LeaseTable(max_leases=4)
        now = 1_000.0
        live = _lease(30, now=now)
        dead = _lease(5, now=now)
        self.assertIsNone(t.reserve(live))
        t.commit(live.lease_id, live.envs)
        self.assertIsNone(t.reserve(dead))
        t.commit(dead.lease_id, dead.envs)
        expired = t.expired(now=now + 6)
        self.assertEqual([e.lease_id for e in expired], [dead.lease_id])
        self.assertTrue(dead.is_expired(now + 6))
        self.assertFalse(live.is_expired(now + 6))

    def test_pending_not_expired(self) -> None:
        t = LeaseTable(max_leases=2)
        now = 50.0
        L = _lease(1, now=now)
        L.envs = []
        self.assertIsNone(t.reserve(L))
        # Still pending (fork in flight): reaper must not reap it.
        self.assertEqual(t.expired(now=now + 10), [])

    def test_abandon_clears_reservation(self) -> None:
        t = LeaseTable(max_leases=1)
        L = _lease(60)
        L.envs = []
        self.assertIsNone(t.reserve(L))
        self.assertIsNotNone(t.abandon(L.lease_id))
        other = _lease(60)
        other.envs = []
        self.assertIsNone(t.reserve(other))

    def test_live_vms_in_flight(self) -> None:
        t = LeaseTable(max_leases=4)
        L = _lease(60, n=4)
        self.assertIsNone(t.reserve(L))
        t.commit(L.lease_id, L.envs)
        self.assertEqual(t.live_vms_in_flight(3), 12)

    def test_env_lookup(self) -> None:
        t = LeaseTable(max_leases=1)
        L = _lease(60, n=2)
        self.assertIsNone(t.reserve(L))
        t.commit(L.lease_id, L.envs)
        found = t.env(L.envs[1].env_id)
        self.assertIsNotNone(found)
        assert found is not None
        self.assertEqual(found[1].index, 1)
        self.assertIsNone(t.env("nope"))


class TestKubectlMap(unittest.TestCase):
    def test_get_nodes_and_raw(self) -> None:
        from scoring import kubectl_to_request

        self.assertEqual(
            kubectl_to_request(["get", "nodes", "-o", "wide"]),
            ("GET", "/api/v1/nodes", None, None),
        )
        self.assertEqual(
            kubectl_to_request(["--raw", "/readyz"]),
            ("GET", "/readyz", None, None),
        )
        self.assertEqual(
            kubectl_to_request(["/api/v1/pods"]),
            ("GET", "/api/v1/pods", None, None),
        )

    def test_unsupported_is_loud(self) -> None:
        from scoring import kubectl_to_request

        with self.assertRaises(ValueError) as ctx:
            kubectl_to_request(["apply", "-f", "-"])
        self.assertIn("unsupported kubectl verb", str(ctx.exception))


class TestScoreTerms(unittest.TestCase):
    def test_never_default_terms(self) -> None:
        from scoring import TERM_KEYS, reward_from_terms, score_create_env

        sc = score_create_env(
            member_alive=[True, True, True],
            source_alive=True,
            contained=1.0,
            restored=1.0,
        )
        self.assertEqual(set(sc["terms"]), set(TERM_KEYS))
        self.assertEqual(sc["reward"], 1.0)
        with self.assertRaises(KeyError):
            reward_from_terms({"liveness": 1.0})
        with self.assertRaises(TypeError):
            score_create_env(  # type: ignore[call-arg]
                member_alive=[True], source_alive=True
            )


if __name__ == "__main__":
    unittest.main()
