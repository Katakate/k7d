"""Soak-clean predicate + incident reward — mocked probe, no KVM."""

from __future__ import annotations

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from soak import (
    INCIDENT_FAULTS,
    MINER_PATH,
    SELFPLAY_ROLES,
    T_BUDGET_S,
    blue_reward,
    first_fail_reason,
    idle_red_skips_hold,
    layer_gates,
    nodecheck_branch_only,
    red_reward,
    require_incident_fault,
    require_incident_payload,
    require_selfplay_payload,
    require_selfplay_role,
    reward_from_solve,
    signed_reward,
    soak_clean,
    wait_miner_absent,
)
from tetragon import Event, EventKey, event_diff


def _ev(path: str, *, background: bool = False) -> Event:
    return Event(
        key=EventKey(
            kind="process_kprobe",
            function="fd_install",
            policy="k7d-fd-install",
            binary="/bin/busybox",
            path=path,
        ),
        raw={},
        background=background,
    )


class FakeProbe:
    def __init__(
        self,
        *,
        miner: bool = False,
        victim: bool = True,
        events: list[Event] | None = None,
        miner_after: int | None = None,
    ) -> None:
        self.miner = miner
        self.victim = victim
        self.events = list(events or [])
        self.miner_after = miner_after
        self.calls = 0

    def miner_running(self) -> bool:
        self.calls += 1
        if self.miner_after is not None and self.calls >= self.miner_after:
            return True
        return self.miner

    def victim_ready(self) -> bool:
        return self.victim

    def tetragon_events(self) -> list[Event]:
        return list(self.events)


class TestReward(unittest.TestCase):
    def test_none_is_zero(self) -> None:
        self.assertEqual(reward_from_solve(None, 100.0), 0.0)

    def test_monotonic_in_t_solve(self) -> None:
        a = reward_from_solve(10.0, 100.0)
        b = reward_from_solve(40.0, 100.0)
        c = reward_from_solve(0.0, 100.0)
        self.assertGreater(c, a)
        self.assertGreater(a, b)
        self.assertAlmostEqual(c, 1.0)
        self.assertAlmostEqual(a, 0.9)
        self.assertAlmostEqual(b, 0.6)

    def test_over_budget_is_zero(self) -> None:
        self.assertEqual(reward_from_solve(901.0, 900.0), 0.0)

    def test_default_budget_is_900(self) -> None:
        self.assertEqual(T_BUDGET_S, 900.0)
        self.assertAlmostEqual(reward_from_solve(90.0), 0.9)


class TestRequireFault(unittest.TestCase):
    def test_relay_ok(self) -> None:
        require_incident_fault("relay")
        self.assertIn("relay", INCIDENT_FAULTS)

    def test_wrong_fault_is_loud(self) -> None:
        with self.assertRaises(ValueError) as ctx:
            require_incident_fault("kill-member-0")
        self.assertIn("incident", str(ctx.exception))
        self.assertIn("relay", str(ctx.exception))

    def test_missing_payload_is_loud(self) -> None:
        with self.assertRaises(ValueError) as ctx:
            require_incident_payload({"reward": 1.0})
        self.assertIn("incident payload", str(ctx.exception))
        with self.assertRaises(ValueError):
            require_incident_payload({"incident": {"turn": 1}})


class TestSoakClean(unittest.TestCase):
    def test_true_when_all_three_hold(self) -> None:
        ticks = {"t": 0.0}

        def clock() -> float:
            return ticks["t"]

        def sleep(dt: float) -> None:
            ticks["t"] += dt

        probe = FakeProbe(miner=False, victim=True, events=[])
        self.assertTrue(
            soak_clean(probe, soak_s=1.0, sleep=sleep, clock=clock)
        )

    def test_false_when_miner_present(self) -> None:
        probe = FakeProbe(miner=True, victim=True, events=[])
        self.assertFalse(
            soak_clean(probe, soak_s=1.0, sleep=lambda _d: None, clock=lambda: 2.0)
        )

    def test_false_when_victim_down(self) -> None:
        probe = FakeProbe(miner=False, victim=False, events=[])
        self.assertFalse(
            soak_clean(probe, soak_s=1.0, sleep=lambda _d: None, clock=lambda: 2.0)
        )

    def test_false_when_miner_respawns_during_soak(self) -> None:
        ticks = {"t": 0.0}

        def clock() -> float:
            return ticks["t"]

        def sleep(dt: float) -> None:
            ticks["t"] += dt

        probe = FakeProbe(miner=False, victim=True, events=[], miner_after=3)
        self.assertFalse(
            soak_clean(probe, soak_s=5.0, sleep=sleep, clock=clock)
        )

    def test_false_on_new_nodecheck_events(self) -> None:
        ticks = {"t": 0.0}

        def clock() -> float:
            return ticks["t"]

        def sleep(dt: float) -> None:
            ticks["t"] += 6.0

        class Growing(FakeProbe):
            def tetragon_events(self) -> list[Event]:
                if ticks["t"] < 1:
                    return []
                return [_ev(MINER_PATH)]

        probe = Growing(miner=False, victim=True)
        self.assertFalse(
            soak_clean(probe, soak_s=12.0, sleep=sleep, clock=clock)
        )

    def test_nodecheck_branch_only(self) -> None:
        base = [_ev("/tmp/other")]
        branch = [_ev("/tmp/other"), _ev(MINER_PATH)]
        diff = event_diff(base, branch)
        self.assertTrue(nodecheck_branch_only(diff))
        self.assertFalse(nodecheck_branch_only(event_diff(branch, branch)))

    def test_gates_default_off(self) -> None:
        self.assertEqual(layer_gates(FakeProbe()), {})

    def test_first_fail_reason(self) -> None:
        self.assertEqual(first_fail_reason(FakeProbe(miner=True)), "miner")
        self.assertEqual(
            first_fail_reason(FakeProbe(miner=False, victim=False)), "victim"
        )
        self.assertIsNone(first_fail_reason(FakeProbe(miner=False, victim=True)))

    def test_idle_red_skips_hold(self) -> None:
        self.assertTrue(idle_red_skips_hold("red", payload_productive=False))
        self.assertFalse(idle_red_skips_hold("red", payload_productive=True))
        self.assertFalse(idle_red_skips_hold("blue", payload_productive=False))
        self.assertFalse(idle_red_skips_hold("blue", payload_productive=True))
        with self.assertRaises(ValueError):
            idle_red_skips_hold("green", payload_productive=False)

    def test_wait_miner_absent(self) -> None:
        ticks = {"t": 0.0, "n": 0}

        def clock() -> float:
            return ticks["t"]

        def sleep(dt: float) -> None:
            ticks["t"] += dt

        def miner() -> bool:
            ticks["n"] += 1
            return ticks["n"] < 3

        self.assertTrue(
            wait_miner_absent(miner, ceiling_s=5.0, sleep=sleep, clock=clock)
        )
        self.assertFalse(
            wait_miner_absent(
                lambda: True, ceiling_s=1.0, sleep=sleep, clock=clock
            )
        )


class TestSelfplayReward(unittest.TestCase):
    def test_blue_scores_when_clean_and_victim_up(self) -> None:
        r = blue_reward(t_solve=90.0, soak_clean=True, victim_ready=True)
        self.assertAlmostEqual(r, 0.9)

    def test_patient_killing_blue_is_zero(self) -> None:
        # Cluster is "clean" but the victim is down: blue nuked it.
        self.assertEqual(
            blue_reward(t_solve=1.0, soak_clean=True, victim_ready=False), 0.0
        )

    def test_blue_zero_when_not_clean(self) -> None:
        self.assertEqual(
            blue_reward(t_solve=1.0, soak_clean=False, victim_ready=True), 0.0
        )

    def test_red_scores_when_productive_and_dirty(self) -> None:
        r = red_reward(t_solve=90.0, soak_clean=False, payload_productive=True)
        self.assertAlmostEqual(r, 0.9)

    def test_do_nothing_red_is_zero(self) -> None:
        # Nothing productive → red scores 0 even though cluster is "dirty".
        self.assertEqual(
            red_reward(t_solve=1.0, soak_clean=False, payload_productive=False),
            0.0,
        )

    def test_pure_dos_red_is_zero(self) -> None:
        # A wrecked cluster runs no miner: not soak_clean but not
        # productive either → 0.
        self.assertEqual(
            red_reward(t_solve=1.0, soak_clean=False, payload_productive=False),
            0.0,
        )

    def test_red_zero_when_blue_cleaned(self) -> None:
        # Blue peeled it: soak_clean True → red scores 0 regardless.
        self.assertEqual(
            red_reward(t_solve=1.0, soak_clean=True, payload_productive=True),
            0.0,
        )

    def test_signed_dispatch(self) -> None:
        self.assertAlmostEqual(
            signed_reward(
                "blue",
                t_solve=90.0,
                soak_clean=True,
                victim_ready=True,
                payload_productive=False,
            ),
            0.9,
        )
        self.assertAlmostEqual(
            signed_reward(
                "red",
                t_solve=90.0,
                soak_clean=False,
                victim_ready=True,
                payload_productive=True,
            ),
            0.9,
        )

    def test_two_sided_scripted_no_model(self) -> None:
        # Scripted red plants, scripted-oracle blue peels: soak_clean
        # flips, blue_R>0 and red_R=0. Then red=catalog vs shallow blue:
        # payload survives, red_R>0 and blue_R=0. No model, two-sided.
        after_blue_oracle = dict(
            soak_clean=True, victim_ready=True, payload_productive=False
        )
        self.assertGreater(
            signed_reward("blue", t_solve=30.0, **after_blue_oracle), 0.0
        )
        self.assertEqual(
            signed_reward("red", t_solve=30.0, **after_blue_oracle), 0.0
        )
        after_red_catalog = dict(
            soak_clean=False, victim_ready=True, payload_productive=True
        )
        self.assertGreater(
            signed_reward("red", t_solve=30.0, **after_red_catalog), 0.0
        )
        self.assertEqual(
            signed_reward("blue", t_solve=30.0, **after_red_catalog), 0.0
        )

    def test_require_role_loud(self) -> None:
        require_selfplay_role("blue")
        require_selfplay_role("red")
        self.assertEqual(SELFPLAY_ROLES, frozenset({"blue", "red"}))
        with self.assertRaises(ValueError):
            require_selfplay_role("purple")

    def test_require_payload_loud(self) -> None:
        good = {
            "selfplay": {
                "role": "blue",
                "scenario_id": "relay-foothold",
                "t_solve_s": 1.0,
                "soak_clean": True,
                "victim_ready": True,
                "payload_productive": False,
            }
        }
        require_selfplay_payload(good)
        with self.assertRaises(ValueError):
            require_selfplay_payload({"reward": 1.0})
        with self.assertRaises(ValueError):
            require_selfplay_payload(
                {"selfplay": {"role": "blue", "scenario_id": "x"}}
            )


if __name__ == "__main__":
    unittest.main()
