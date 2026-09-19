"""Sensor install guards — no KVM."""

from __future__ import annotations

import sys
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from sensors import (
    BUSYBOX,
    HELM_BIN,
    HELM_VERSION,
    INJECT_NODE,
    KPROBE_POLICY,
    PATH_PREFIX,
    SRC_PROBE,
    SRC_PROBE_PATH,
    ensure_helm,
    inject_pod_yaml,
    kprobe_policy_yaml,
    pin_api_route,
)


class TestSensors(unittest.TestCase):
    def test_ensure_helm_is_loud_when_missing(self) -> None:
        with patch.object(Path, "is_file", return_value=False):
            with self.assertRaises(RuntimeError) as ctx:
                ensure_helm()
        self.assertIn(HELM_VERSION, str(ctx.exception))
        self.assertIn(str(HELM_BIN), str(ctx.exception))
        self.assertIn("helm-pin", str(ctx.exception))
        self.assertIn("will not guess", str(ctx.exception))

    def test_kprobe_policy_matches_path_prefix(self) -> None:
        yaml = kprobe_policy_yaml()
        self.assertIn(KPROBE_POLICY, yaml)
        self.assertIn("fd_install", yaml)
        self.assertIn(PATH_PREFIX, yaml)
        self.assertIn("cilium.io/v1alpha1", yaml)

    def test_inject_pod_yaml_pins_busybox_to_agent(self) -> None:
        yaml = inject_pod_yaml(SRC_PROBE, SRC_PROBE_PATH)
        self.assertIn(BUSYBOX, yaml)
        self.assertIn(INJECT_NODE, yaml)
        self.assertIn(SRC_PROBE_PATH, yaml)
        self.assertIn("IfNotPresent", yaml)
        self.assertIn("nodeName", yaml)

    def test_pin_api_route_missing_bridge_is_loud(self) -> None:
        with self.assertRaises(RuntimeError) as ctx:
            with pin_api_route("k7-br-does-not-exist"):
                pass
        self.assertIn("no such bridge", str(ctx.exception))
