#!/usr/bin/env python3
"""Fork labels, dilation presets, and the slim metrics path. No k7d."""

from __future__ import annotations

import json
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

from server import (  # noqa: E402
    App,
    dilation_cluster_id,
    fork_labels,
    metric_sig,
    metrics_message,
    nearest_rung,
    perform_action,
    topo_sig,
)
from store import ViewStore  # noqa: E402


def test_fork_labels_are_readable() -> None:
    assert fork_labels(1) == ["child-01"]
    labels = fork_labels(10)
    assert labels[0] == "child-01" and labels[-1] == "child-10"
    assert len(labels) == 10
    try:
        fork_labels(0)
    except ValueError as exc:
        assert "1..=32" in str(exc)
    else:
        raise AssertionError("fork 0 must fail")


def test_cluster_id_and_nearest_rung() -> None:
    assert dilation_cluster_id("tetragon", "root") == "tetragon"
    assert dilation_cluster_id("tetragon", "") == "tetragon"
    assert dilation_cluster_id("tetragon", "child-01-0001") == "tetragon-child-01-0001"
    assert nearest_rung([8, 4, 2, 1], 8) == 8
    assert nearest_rung([8, 4, 2, 1], 3) == 2
    assert nearest_rung([8, 4, 2, 1], 6) == 4
    # tie 3 is equally far from 4 and 2; the lower rung wins
    assert nearest_rung([8, 4, 2, 1], 3) == 2


class FakeClient:
    def __init__(self) -> None:
        self.calls: list[tuple] = []

    def tree_list(self) -> dict:
        return {"trees": [{"tree_id": "tetragon", "kind": "cluster"}]}

    def tree_nodes(self, tree_id: str) -> dict:
        nodes = [{"id": "root", "state": "live", "parent": None, "children": []}]
        if self.calls:
            nodes += [
                {
                    "id": f"child-{i:02d}-0001",
                    "label": f"child-{i:02d}",
                    "state": "live",
                    "parent": "root",
                    "children": [],
                }
                for i in range(1, 11)
            ]
        return {
            "nodes": nodes,
            "usage": {"live_vm_count": len(nodes)},
            "budget": {"max_live_vms": 32},
            "live_dilation": {"root": 1},
            "live_cpu": {"root": [{"member": 0, "vcpus": 1, "cpu_percent": 3.0}]},
            "dilation_ladder": {"root": [8, 4, 2, 1]},
            "dilation_policy": {"root": "fixed"},
            "dilation_trajectory": {},
        }

    def tree_fork_batch(self, tree_id, source_id, labels, timeout=None, dilation=None):
        self.calls.append(("fork", labels))
        return {
            "latency_ns": 4_500_000,
            "forks": [
                {"node_id": f"{label}-0001", "fork_memory_full_copy": [True]}
                for label in labels
            ],
        }

    def set_dilation(self, cluster_id, factor):
        self.calls.append(("set_dilation", cluster_id, factor))
        return {"factor": factor}

    def set_dilation_policy(self, tree_id, mode, ladder, node_id=None):
        self.calls.append(("policy", mode, list(ladder), node_id))
        return {"mode": mode, "ladder": ladder}

    def tree_suspend(self, tree_id, node_id):
        raise RuntimeError("tree suspend(root): node root is in state Suspended, cannot suspend")


def test_fork_ten_records_latency_per_child() -> None:
    app = App(FakeClient(), 50)
    out = perform_action(app, {"op": "fork", "tree_id": "tetragon", "node_id": "root", "n": 10})
    assert out["ok"]
    labels = app.client.calls[0][1]
    assert labels[0] == "child-01" and len(labels) == 10
    lats = app.store.trees["tetragon"]["latencies"]
    assert len(lats) == 10
    assert abs(lats["child-01-0001"]["latency_ms"] - 4.5) < 1e-6


def test_preset_sends_only_a_ladder_and_snaps_off_rung() -> None:
    app = App(FakeClient(), 50)
    app.store.apply_snapshot(
        "tetragon",
        [{"id": "root", "state": "live", "parent": None, "children": []}],
        live_dilation={"root": 3},
    )
    perform_action(
        app,
        {
            "op": "set_dilation_policy",
            "tree_id": "tetragon",
            "preset": "aggressive",
            "adaptive": True,
        },
    )
    kinds = [c[0] for c in app.client.calls]
    assert kinds[0] == "set_dilation"
    # aggressive ladder is 8,4,1 — 3 is closer to 4 than to 1
    assert app.client.calls[0] == ("set_dilation", "tetragon", 4)
    policy = next(c for c in app.client.calls if c[0] == "policy")
    assert policy[1] == "track"
    assert policy[2] == [8, 4, 1]
    assert policy[3] is None


def test_action_error_is_the_daemon_text() -> None:
    app = App(FakeClient(), 50)
    try:
        perform_action(app, {"op": "suspend", "tree_id": "tetragon", "node_id": "root"})
    except RuntimeError as exc:
        assert "Suspended" in str(exc)
        assert "not found" not in str(exc)
    else:
        raise AssertionError("suspend error must surface")


def test_metrics_message_omits_the_event_log() -> None:
    store = ViewStore()
    nodes = [
        {
            "id": "root" if i == 0 else f"child-{i:02d}",
            "state": "live",
            "parent": None if i == 0 else "root",
            "children": [],
            "protected": False,
        }
        for i in range(21)
    ]
    store.apply_snapshot(
        "tetragon",
        nodes,
        live_dilation={"root": 1},
        live_cpu={"root": [{"member": 0, "vcpus": 1, "cpu_percent": 12.5}]},
        dilation_ladder={"root": [8, 4, 2, 1]},
        dilation_policy={"root": "fixed"},
    )
    store.apply_snapshot(
        "miner",
        [{"id": "root", "state": "live", "parent": None, "children": []}],
        live_cpu={"root": [{"member": 0, "vcpus": 1, "cpu_percent": 1.0}]},
    )
    for i in range(200):
        store.ingest(
            {"type": "note", "tree_id": "tetragon", "node_id": "root", "text": f"n{i}"}
        )
    msg = metrics_message(store)
    raw = json.dumps(msg)
    assert msg["kind"] == "metrics"
    assert "events" not in msg
    assert len(msg["trees"]) == 2
    assert msg["trees"]["tetragon"]["live_cpu"]["root"][0]["cpu_percent"] == 12.5
    full = json.dumps(store.snapshot())
    assert len(raw) < len(full) / 5
    before = topo_sig(store)
    store.trees["tetragon"]["live_dilation"] = {"root": 8}
    store.trees["tetragon"]["live_cpu"] = {"root": [{"member": 0, "cpu_percent": 40.0}]}
    assert topo_sig(store) == before
    # Rung history is not painted. It must not wake a metrics frame.
    frozen = metric_sig(store)
    store.trees["tetragon"]["dilation_trajectory"] = {"root": [8, 4, 2, 1]}
    assert metric_sig(store) == frozen
    moved = metric_sig(store)
    store.trees["tetragon"]["live_dilation"] = {"root": 4}
    assert metric_sig(store) != moved
    assert topo_sig(store) == before


if __name__ == "__main__":
    test_fork_labels_are_readable()
    test_cluster_id_and_nearest_rung()
    test_fork_ten_records_latency_per_child()
    test_preset_sends_only_a_ladder_and_snaps_off_rung()
    test_action_error_is_the_daemon_text()
    test_metrics_message_omits_the_event_log()
    print("ok")
