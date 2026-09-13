"""Scripted red <-> blue integration — no model, no KVM.

Proves the self-play game is two-sided and honest with scripted policies
only. A small in-memory `SimCluster` models the relay incident's causal
state (miner present, host reseed chain, victim up). Scripted blue peels
it; scripted red plants and keeps it productive. Both sides are judged by
the *same* `soak_clean` predicate from `soak.py` read off cluster state,
then scored with `signed_reward` — never by any sensor-silence term.

  blue=oracle vs frozen red  -> blue_R > 0, red_R = 0  (blue cleaned it)
  red=catalog vs frozen blue -> red_R  > 0, blue_R = 0 (payload survives)
"""

from __future__ import annotations

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from soak import signed_reward, soak_clean
from tetragon import Event, EventKey


class SimCluster:
    """Deterministic model of the relay incident's cluster state.

    Layers mirror `incidents.Relay`: layer 1 is the visible miner
    Deployment; layers 2/3 are the host reseed chain that re-applies it
    on the next reconcile edge. A fix that does not peel the host chain
    regrows on the soak.
    """

    def __init__(self) -> None:
        self.miner = False  # layer 1 present + Running
        self.host_chain = False  # layers 2/3 (reseed) present
        self.victim_up = True  # legitimate workload Ready
        self.miner_cpu = 0.0  # % CPU the payload burns

    # --- scripted red ---
    def red_plant_catalog(self) -> None:
        self.miner = True
        self.host_chain = True
        self.miner_cpu = 95.0

    def red_noop(self) -> None:
        pass

    # --- scripted blue ---
    def blue_oracle(self) -> None:
        # Full peel: host chain first, then the Deployment.
        self.host_chain = False
        self.miner = False
        self.miner_cpu = 0.0

    def blue_shallow(self) -> None:
        # Layer-1 delete only. The host chain re-applies the miner.
        self.miner = False
        self.miner_cpu = 0.0
        self._reconcile()

    def blue_nuke(self) -> None:
        # Cordon-all / kill the API: miner gone but patient dead.
        self.miner = False
        self.miner_cpu = 0.0
        self.victim_up = False

    def _reconcile(self) -> None:
        # The soak's reconcile edge: the host chain regrows the miner.
        if self.host_chain:
            self.miner = True
            self.miner_cpu = 95.0


class SimProbe:
    """Reads `SimCluster` as the soak predicate + red gate expect."""

    def __init__(self, cluster: SimCluster) -> None:
        self.c = cluster

    def miner_running(self) -> bool:
        # A soak sample also runs a reconcile edge — a shallow fix regrows.
        self.c._reconcile()
        return self.c.miner

    def victim_ready(self) -> bool:
        return self.c.victim_up

    def payload_productive(self) -> bool:
        return self.c.miner and self.c.miner_cpu >= 5.0

    def tetragon_events(self) -> list[Event]:
        if not self.c.miner:
            return []
        return [
            Event(
                key=EventKey(
                    kind="process_kprobe",
                    function="fd_install",
                    policy="k7d",
                    binary="/bin/busybox",
                    path="/tmp/nodecheck",
                ),
                raw={},
            )
        ]


def _judge(cluster: SimCluster, role: str, t_solve: float) -> float:
    probe = SimProbe(cluster)
    clean = soak_clean(
        probe, soak_s=1.0, sleep=lambda _d: None, clock=_ticker()
    )
    return signed_reward(
        role,
        t_solve=t_solve,
        soak_clean=clean,
        victim_ready=probe.victim_ready(),
        payload_productive=probe.payload_productive(),
    )


def _ticker():
    state = {"t": 0.0}

    def clock() -> float:
        state["t"] += 0.5
        return state["t"]

    return clock


class TestScriptedTwoSided(unittest.TestCase):
    def test_blue_oracle_beats_frozen_red(self) -> None:
        # Frozen scripted red already planted (settled state that a
        # blue-on-trial group forks).
        c = SimCluster()
        c.red_plant_catalog()
        # Blue on trial peels fully.
        c.blue_oracle()
        self.assertGreater(_judge(c, "blue", 30.0), 0.0)
        self.assertEqual(_judge(c, "red", 30.0), 0.0)

    def test_blue_shallow_loses_to_frozen_red(self) -> None:
        c = SimCluster()
        c.red_plant_catalog()
        c.blue_shallow()  # regrows on the soak
        self.assertEqual(_judge(c, "blue", 30.0), 0.0)
        # The frozen red's payload survived and is productive.
        self.assertGreater(_judge(c, "red", 30.0), 0.0)

    def test_red_catalog_beats_frozen_blue(self) -> None:
        # Red on trial forks a defended (clean) source, then plants.
        c = SimCluster()  # defended baseline
        c.red_plant_catalog()
        self.assertGreater(_judge(c, "red", 30.0), 0.0)
        self.assertEqual(_judge(c, "blue", 30.0), 0.0)

    def test_red_noop_scores_zero(self) -> None:
        c = SimCluster()
        c.red_noop()  # plants nothing → not productive
        self.assertEqual(_judge(c, "red", 30.0), 0.0)
        # Nothing bad happened, so blue trivially "clean" and victim up.
        self.assertGreater(_judge(c, "blue", 30.0), 0.0)

    def test_patient_killing_blue_scores_zero(self) -> None:
        c = SimCluster()
        c.red_plant_catalog()
        c.blue_nuke()  # miner gone but victim dead
        self.assertEqual(_judge(c, "blue", 30.0), 0.0)


if __name__ == "__main__":
    unittest.main()
