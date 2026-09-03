"""Incident catalog — no KVM."""

from __future__ import annotations

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import incidents  # noqa: E402


class TestIncidents(unittest.TestCase):
    def test_catalog_allowlist(self) -> None:
        self.assertEqual(
            incidents.allowlist(),
            ["cryptominer", "dormant", "hydra", "lateral", "relay", "sleeper"],
        )
        self.assertEqual(incidents.pick(None).id, "relay")
        for fid in incidents.allowlist():
            inc = incidents.get(fid)
            self.assertEqual(inc.id, fid)
            self.assertTrue(inc.yaml)
            self.assertTrue(inc.remediate_cmd())
        hydra = incidents.get("hydra")
        self.assertIn("kind: Deployment", hydra.yaml)
        self.assertIn("kind: CronJob", hydra.yaml)
        self.assertIn("web-cache", hydra.yaml)
        self.assertIn("metrics-sync", hydra.remediate_cmd())
        self.assertIn("cache-health", hydra.remediate_cmd())
        self.assertEqual(hydra.remediate_members(), [0, 1, 2])
        self.assertTrue(callable(hydra.plant_host))
        self.assertNotIn("k7-incident", hydra.yaml)
        sleeper = incidents.get("sleeper")
        self.assertNotIn("kind: CronJob", sleeper.yaml)
        self.assertNotIn("raid-check", sleeper.yaml)
        self.assertNotIn("cache-health", sleeper.yaml)
        self.assertIn(incidents.SLEEPER_CRON, sleeper.remediate_cmd())
        self.assertNotIn("web-cache", incidents._MINER_B64)
        self.assertTrue(callable(sleeper.plant_host))

        relay = incidents.get("relay")
        # Layer 1 is a plain Deployment pinned to the control-plane; no
        # CronJob, SA/Role, preStop, or hostPath that would let a
        # -o yaml / kubectl get sa,role,rolebinding name the reseeder.
        self.assertIn("kind: Deployment", relay.yaml)
        self.assertNotIn("kind: CronJob", relay.yaml)
        self.assertNotIn("preStop", relay.yaml)
        self.assertNotIn("hostPath", relay.yaml)
        self.assertNotIn("ServiceAccount", relay.yaml)
        self.assertIn("node-role.kubernetes.io/control-plane", relay.yaml)
        # The chain that resurrects the miner must not appear in the
        # thing the agent applies or in the manifest the reseeder stashes.
        script = relay.plant_script()
        for tok in relay.next_layer_tokens:
            self.assertNotIn(tok, relay.yaml, f"{tok} leaked into the live spec")
            self.assertIn(tok, script, f"{tok} missing from the plant")
            self.assertIn(tok, relay.remediate_cmd())
        self.assertIn(incidents.RELAY_KUBELET_PODS, script)
        self.assertIn("PathModified=/etc/systemd/system", script)
        self.assertEqual(relay.remediate_members(), [0])
        self.assertTrue(callable(relay.plant_host))

        dormant = incidents.get("dormant")
        # Layer 1 is a plain control-plane Deployment; the resurrect
        # chain never appears in what the agent applies.
        self.assertIn("kind: Deployment", dormant.yaml)
        self.assertNotIn("kind: CronJob", dormant.yaml)
        self.assertNotIn("ServiceAccount", dormant.yaml)
        self.assertIn("node-role.kubernetes.io/control-plane", dormant.yaml)
        script = dormant.plant_script()
        for tok in dormant.next_layer_tokens:
            self.assertNotIn(tok, dormant.yaml, f"{tok} leaked into the live spec")
            self.assertIn(tok, script, f"{tok} missing from the plant")
            self.assertIn(tok, dormant.remediate_cmd())
        # Hidden like relay: .path units, not services/timers/cron, and
        # the guard lives in the vendor dir started-not-enabled.
        self.assertIn(f"{incidents.DORMANT_RESEED_UNIT}.path", script)
        self.assertIn(f"{incidents.DORMANT_GUARD_UNIT}.path", script)
        self.assertIn(f"PathModified={incidents.DORMANT_KUBELET_PODS}", script)
        self.assertIn(f"PathModified={incidents.DORMANT_UNIT_DIR}", script)
        self.assertIn(incidents.DORMANT_GUARD_UNIT_DIR, script)
        # The time gate: each reveal sleeps before it re-acts.
        self.assertIn(f"sleep {incidents.DORMANT_DELAY_SEC}", script)
        # The multi-candidate frontier: an inert decoy cron sits next to
        # the real timer, and it must not carry a miner token.
        self.assertIn(incidents.DORMANT_DECOY_CRON, script)
        self.assertNotIn(incidents.DORMANT_MINER, incidents.DORMANT_DECOY_CRON)
        self.assertEqual(dormant.remediate_members(), [0])
        self.assertTrue(callable(dormant.plant_host))

    def test_unknown_is_loud(self) -> None:
        with self.assertRaises(incidents.UnknownIncident) as ctx:
            incidents.get("not-an-incident")
        self.assertIn("allowlist:", str(ctx.exception))
        self.assertIn("cryptominer", str(ctx.exception))


if __name__ == "__main__":
    unittest.main()
