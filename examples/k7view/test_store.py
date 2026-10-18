#!/usr/bin/env python3
"""Unit tests for k7view snapshot diff + ingest. No k7d required."""

from __future__ import annotations

import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

from store import ViewStore, diff_nodes, estimate_usage  # noqa: E402


def _node(nid: str, **kw):
    base = {
        "id": nid,
        "parent": None,
        "children": [],
        "state": "live",
        "dirty_page_count": 0,
        "protected": False,
        "label": nid,
        "vm_count": 3,
        "created_at_unix": 1,
    }
    base.update(kw)
    return base


def test_diff_appear_protect_prune() -> None:
    prev = {"root": _node("root")}
    cur = {
        "root": _node("root", children=["a"], protected=True),
        "a": _node("a", parent="root", dirty_page_count=10),
    }
    ev = diff_nodes("t", prev, cur, 1)
    ops = [e["op"] for e in ev]
    assert "appear" in ops
    assert "protect" in ops
    ev2 = diff_nodes("t", cur, {"root": _node("root", protected=True)}, 2)
    assert [e["op"] for e in ev2] == ["prune"]
    assert ev2[0]["node_id"] == "a"


def test_diff_evict() -> None:
    prev = {"a": _node("a")}
    cur = {"a": _node("a", state="evicted")}
    ev = diff_nodes("t", prev, cur, 1)
    assert ev[0]["op"] == "evict"


def test_usage() -> None:
    nodes = [
        _node("root", dirty_page_count=0, state="live"),
        _node("a", dirty_page_count=4, state="live", vm_count=3),
    ]
    u = estimate_usage(nodes, 256)
    assert u["live_node_count"] == 2
    assert u["live_vm_count"] == 6
    assert u["disk_bytes"] == 4 * 4096
    assert u["live_ram_bytes"] > 0


def test_store_uses_daemon_usage() -> None:
    s = ViewStore()
    usage = {
        "live_vm_count": 3,
        "live_ram_bytes": 99,
        "disk_bytes": 7,
        "total_nodes": 2,
        "live_node_count": 1,
    }
    budget = {"max_live_vms": 8, "max_live_ram_bytes": 1, "max_disk_bytes": 2, "max_chain_depth": 1}
    s.apply_snapshot(
        "t1",
        [_node("root"), _node("a", parent="root", state="suspended")],
        usage=usage,
        budget=budget,
        live_guest_cids={"root": [42], "a": []},
    )
    slot = s.snapshot()["trees"]["t1"]
    assert slot["usage"] == usage
    assert slot["budget"] == budget
    assert slot["members"]["root"] == [42]
    assert slot["members"]["a"] == []


def test_store_prune_tombstones() -> None:
    s = ViewStore()
    s.apply_snapshot("t1", [_node("root"), _node("a", parent="root")])
    s.ingest({"type": "note", "tree_id": "t1", "node_id": "a", "text": "loser"})
    ev = s.apply_snapshot("t1", [_node("root")])
    assert [e["op"] for e in ev] == ["prune"]
    slot = s.snapshot()["trees"]["t1"]
    # The pruned node stays visible as a grey tombstone with its
    # metadata still readable; only the daemon-listed nodes count
    # toward usage.
    assert slot["nodes"]["a"]["state"] == "pruned"
    assert slot["nodes"]["a"]["parent"] == "root"
    assert slot["notes"]["a"] == "loser"
    assert slot["usage"]["total_nodes"] == 1
    # A later snapshot must not re-emit prune for the tombstone.
    ev2 = s.apply_snapshot("t1", [_node("root")])
    assert ev2 == []
    assert s.snapshot()["trees"]["t1"]["nodes"]["a"]["state"] == "pruned"


def test_store_ingest() -> None:
    s = ViewStore()
    s.apply_snapshot("t1", [_node("root")])
    s.ingest({"type": "run", "tree_id": "t1", "phase": "fork", "goal": "demo"})
    s.ingest({"type": "latency", "tree_id": "t1", "node_id": "a", "latency_ms": 12.5})
    s.ingest({"type": "note", "tree_id": "t1", "node_id": "a", "text": "keep"})
    s.ingest(
        {
            "type": "trace",
            "tree_id": "t1",
            "node_id": "a",
            "role": "tool",
            "text": "score",
        }
    )
    s.ingest({"type": "error", "tree_id": "t1", "node_id": "b", "text": "cid missing"})
    s.ingest(
        {
            "type": "trace",
            "tree_id": "t1",
            "node_id": "a",
            "role": "thinking",
            "text": "hel",
        }
    )
    s.ingest(
        {
            "type": "trace",
            "tree_id": "t1",
            "node_id": "a",
            "role": "thinking",
            "text": "hello world",
            "replace": True,
        }
    )
    s.ingest(
        {
            "type": "meta",
            "tree_id": "t1",
            "node_id": "a",
            "action": "protect",
            "text": "lock winner",
        }
    )
    snap = s.snapshot()
    assert snap["run"]["phase"] == "fork"
    assert snap["trees"]["t1"]["latencies"]["a"]["latency_ms"] == 12.5
    assert snap["trees"]["t1"]["notes"]["a"] == "keep"
    assert snap["trees"]["t1"]["traces"]["a"][-1]["role"] == "thinking"
    assert snap["trees"]["t1"]["traces"]["a"][-1]["text"] == "hello world"
    assert snap["trees"]["t1"]["errors"]["b"] == "cid missing"
    assert snap["meta"][-1]["action"] == "protect"
    s.ingest({"type": "tick", "tree_id": "t1", "node_id": "a", "text": "probe 1"})
    snap2 = s.snapshot()
    assert snap2["bus_n"] >= 1
    assert snap2["activity"]["a"] > 0
    assert snap2["last_tick"] == "probe 1"
    assert snap2["events"][-1]["op"] == "tick"
    ops = [e["op"] for e in snap["events"]]
    assert "appear" in ops
    assert "trace" in ops
    assert snap["totals"]["trees"] == 1
    assert snap["totals"]["forks"] == 1


def test_store_totals_multi_tree() -> None:
    s = ViewStore()
    s.apply_snapshot(
        "c1",
        [_node("r", vm_count=3), _node("a", parent="r", vm_count=3)],
        kind="cluster",
        usage={
            "live_vm_count": 6,
            "live_ram_bytes": 1,
            "disk_bytes": 1,
            "total_nodes": 2,
            "live_node_count": 2,
        },
    )
    s.apply_snapshot(
        "v1",
        [_node("r2", vm_count=1, state="live")],
        kind="vm",
        usage={
            "live_vm_count": 1,
            "live_ram_bytes": 1,
            "disk_bytes": 1,
            "total_nodes": 1,
            "live_node_count": 1,
        },
    )
    s.ingest({"type": "latency", "tree_id": "c1", "node_id": "a", "latency_ms": 10})
    s.ingest({"type": "latency", "tree_id": "v1", "node_id": "r2", "latency_ms": 4})
    tot = s.snapshot()["totals"]
    assert tot["trees"] == 2
    assert tot["nodes"] == 3
    assert tot["live_vms"] == 7
    assert tot["forks"] == 2


def test_store_ingest_cmd_verdict_beat() -> None:
    s = ViewStore()
    s.apply_snapshot("t1", [_node("root"), _node("a", parent="root")])
    s.ingest(
        {
            "type": "cmd",
            "tree_id": "t1",
            "node_id": "a",
            "cmd": "kubectl delete pod miner",
            "exit_code": 0,
            "destructive": True,
            "on_source": False,
            "member": 0,
            "stdout": "pod \"miner\" deleted",
        }
    )
    s.ingest(
        {
            "type": "verdict",
            "tree_id": "t1",
            "node_id": "a",
            "clean": False,
            "branch_only": 3,
            "source_only": 0,
            "sample": "process_exec xmrig",
        }
    )
    s.ingest({"type": "beat", "tree_id": "t1", "name": "remediate", "node_id": "a"})
    snap = s.snapshot()
    cmd = snap["trees"]["t1"]["cmds"]["a"]
    assert cmd["cmd"] == "kubectl delete pod miner"
    assert cmd["destructive"] is True
    assert cmd["on_source"] is False
    # per-member drill-down history (drawer "member activity")
    ex = snap["trees"]["t1"]["execs"]["a"]
    assert len(ex) == 1
    assert ex[0]["member"] == 0
    assert ex[0]["stdout"] == 'pod "miner" deleted'
    v = snap["trees"]["t1"]["verdicts"]["a"]
    assert v["clean"] is False
    assert v["branch_only"] == 3
    assert snap["beats"][-1]["name"] == "remediate"
    ops = [e["op"] for e in snap["events"]]
    assert "cmd" in ops
    assert "verdict" in ops
    assert "beat" in ops
    try:
        s.ingest({"type": "beat", "tree_id": "t1"})
        raise AssertionError("beat without name must be loud")
    except ValueError:
        pass


def test_store_normalizes_stub_state() -> None:
    """gym/stub.py reports \"Live\"/\"Cluster\"; the daemon reports lowercase."""
    s = ViewStore()
    s.apply_snapshot("t1", [_node("root", state="Live", kind="Cluster")])
    node = s.snapshot()["trees"]["t1"]["nodes"]["root"]
    assert node["state"] == "live"
    assert node["kind"] == "cluster"


def test_ingest_mcp_bridge() -> None:
    sys.path.insert(0, str(HERE))
    from ingest_mcp import Bridge  # noqa: E402

    b = Bridge()
    fork = b.translate(
        {
            "ts": 1.0,
            "arm": "fork",
            "tool": "fork_batch",
            "args": {"node_id": "root", "n": 2},
            "ok": True,
            "latency_ns": 2_200_000_000,
            "tree_id": "k7mcp-x",
            "result": {
                "forks": [
                    {"node_id": "hyp-1-0", "guest_cids": [3, 4, 5],
                     "fork_memory_full_copy": [False, False, False]},
                    {"node_id": "hyp-1-1", "guest_cids": [6, 7, 8],
                     "fork_memory_full_copy": [False, False, False]},
                ]
            },
        }
    )
    kinds = [p["type"] for p in fork]
    assert kinds[0] == "run"  # first record posts the agent arm phase
    assert kinds.count("latency") == 2
    assert kinds.count("members") == 2
    assert any(p["type"] == "beat" and p["name"] == "fork" for p in fork)
    lat = [p for p in fork if p["type"] == "latency"][0]
    assert lat["latency_ms"] == 2200.0  # batch wall, not invented / n
    assert lat["cow"] == [True, True, True]
    missing = Bridge().translate(
        {
            "tool": "fork_batch",
            "args": {"node_id": "root", "n": 1},
            "ok": True,
            "tree_id": "k7mcp-x",
            "result": {"forks": [{"node_id": "orphan", "guest_cids": [9]}]},
        }
    )
    miss_lat = [p for p in missing if p["type"] == "latency"][0]
    assert miss_lat["latency_ms"] is None
    assert any("latency_ns missing" in (p.get("text") or "") for p in missing)

    ex = b.translate(
        {
            "tool": "branch_exec",
            "args": {"node_id": "root", "member": 0, "cmd": "kubectl delete pod miner"},
            "ok": True,
            "destructive": True,
            "on_source": True,
            "tree_id": "k7mcp-x",
            "result": {"exit_code": 0},
        }
    )
    assert any(p["type"] == "cmd" and p["on_source"] for p in ex)
    assert any(p["type"] == "beat" and p["name"] == "remediate" for p in ex)

    diff = b.translate(
        {
            "tool": "tetragon_diff",
            "args": {"node_id": "hyp-1-0"},
            "ok": True,
            "tree_id": "k7mcp-x",
            "result": {"branch_only": ["x"], "source_only": [], "clean": False},
        }
    )
    v = [p for p in diff if p["type"] == "verdict"][0]
    assert v["clean"] is False
    assert v["branch_only"] == 1
    # pre-fix diff never fires "verified"
    assert not any(p["type"] == "beat" and p["name"] == "verified" for p in diff)

    # post-fix diff with no branch-only events fires "verified"
    post_fix = b.translate(
        {
            "tool": "tetragon_diff",
            "args": {"node_id": "root"},
            "ok": True,
            "tree_id": "k7mcp-x",
            "result": {"branch_only": [], "source_only": ["gone"], "clean": False},
        }
    )
    assert any(p["type"] == "beat" and p["name"] == "verified" for p in post_fix)

    err = b.translate(
        {
            "tool": "prune",
            "args": {"node_id": "nope"},
            "ok": False,
            "error": "no such node: nope",
            "tree_id": "k7mcp-x",
        }
    )
    assert any(p["type"] == "error" for p in err)

    # beats fire once
    again = b.translate(
        {
            "tool": "branch_exec",
            "args": {"node_id": "root", "member": 0, "cmd": "kubectl delete pod x"},
            "ok": True,
            "destructive": True,
            "on_source": True,
            "tree_id": "k7mcp-x",
            "result": {"exit_code": 0},
        }
    )
    assert not any(p["type"] == "beat" for p in again)


def test_llm_extract_json() -> None:
    sys.path.insert(0, str(HERE))
    from llm import extract_json  # noqa: E402

    assert extract_json('{"protect":["a"],"reason":"ok"}')["protect"] == ["a"]
    assert extract_json("sure\n```json\n{\"suspend\":[\"b\"]}\n```")["suspend"] == ["b"]
    assert extract_json("no json here") is None


def test_store_live_dilation_and_guest_clock() -> None:
    s = ViewStore()
    s.apply_snapshot(
        "t1",
        [_node("root"), _node("a", parent="root")],
        live_dilation={"root": 8, "a": 8},
    )
    slot = s.snapshot()["trees"]["t1"]
    assert slot["live_dilation"] == {"root": 8, "a": 8}
    logged = len(s.events)
    s.ingest(
        {
            "type": "guest_clock",
            "tree_id": "t1",
            "node_id": "root",
            "cid": 42,
            "uptime_s": 384.0,
        }
    )
    clock = s.snapshot()["trees"]["t1"]["guest_clock"]
    assert clock["base_uptime_s"] == 384.0
    assert clock["uptime_s"] == 384.0
    assert len(s.events) == logged
    s.ingest(
        {
            "type": "guest_clock",
            "tree_id": "t1",
            "node_id": "root",
            "cid": 42,
            "uptime_s": 392.0,
        }
    )
    clock = s.snapshot()["trees"]["t1"]["guest_clock"]
    assert clock["base_uptime_s"] == 384.0
    assert clock["uptime_s"] == 392.0
    assert len(s.events) == logged
    try:
        s.ingest({"type": "guest_clock", "tree_id": "t1"})
        raise AssertionError("guest_clock without uptime_s must be loud")
    except ValueError:
        pass


def test_rollout_manifest() -> None:
    sys.path.insert(0, str(HERE))
    from dilated import (  # noqa: E402
        DILATED_MAX_LIVE_VMS,
        DILATED_WAVES,
        FORK_SETTLE_WALL_S,
        ROLLOUT_GUEST_TIMEOUT_S,
        ROLLOUT_INITIAL_DELAY_S,
        apply_argv,
        deploy_name,
        dilated_budget,
        dilation_token,
        node_bridge,
        rollout_manifest,
    )

    yaml = rollout_manifest("rancher/mirrored-pause:3.6")
    assert "initialDelaySeconds: 40" in yaml
    assert f"periodSeconds: {10}" in yaml or "periodSeconds: 10" in yaml
    assert "replicas: 2" in yaml
    assert "rancher/mirrored-pause:3.6" in yaml
    assert "/hostbin/true" in yaml
    assert "path: /lib64" in yaml
    assert "/hostbin/sleep" not in yaml
    assert "name: k7-rollout-w1" in rollout_manifest(
        "rancher/mirrored-pause:3.6", "k7-rollout-w1"
    )
    assert deploy_name(0) == "k7-rollout-w0"
    assert deploy_name(2) == "k7-rollout-w2"
    assert node_bridge("k7v-dilated", "root").startswith("k7-br-")
    assert node_bridge("k7v-dilated", "w0-rollout-2-0002") != node_bridge(
        "k7v-dilated", "root"
    )
    try:
        rollout_manifest("no-tag")
        raise AssertionError("image without tag must be loud")
    except ValueError:
        pass
    assert DILATED_WAVES == [6, 4, 4]
    assert ROLLOUT_INITIAL_DELAY_S == 40
    assert ROLLOUT_GUEST_TIMEOUT_S == 120
    assert ROLLOUT_GUEST_TIMEOUT_S > ROLLOUT_INITIAL_DELAY_S
    assert FORK_SETTLE_WALL_S == 2.0
    argv = apply_argv("/tmp/k7-dilated-rollout.yaml")
    assert "--validate=false" in argv
    assert argv[-2:] == ["-f", "/tmp/k7-dilated-rollout.yaml"]
    b = dilated_budget()
    assert b["max_live_vms"] == DILATED_MAX_LIVE_VMS == 24
    assert dilation_token("patched (abi 2, default factor 1)\n") == "patched"
    assert dilation_token("stock (KVM_HAS_DEVICE_ATTR: Inappropriate ioctl for device)") == "stock"
    assert dilation_token("") == ""


def test_wave_sizes() -> None:
    sys.path.insert(0, str(HERE))
    from run_scenario import pressure_budget, wave_sizes  # noqa: E402

    assert wave_sizes("smoke", 4, 3) == [4]
    assert wave_sizes("max", 8, 3) == [8, 4, 4]
    assert wave_sizes("max", 12, 2) == [12, 6]
    assert wave_sizes("ubuntu-dilated", 6, 3) == [6, 4, 4]
    b = pressure_budget(3, 8, 256)
    assert b["max_live_vms"] >= 27
    assert b["max_live_vms"] <= 36
    assert b["max_chain_depth"] >= 4


def main() -> int:
    test_diff_appear_protect_prune()
    test_diff_evict()
    test_usage()
    test_store_uses_daemon_usage()
    test_store_prune_tombstones()
    test_store_ingest()
    test_store_totals_multi_tree()
    test_store_ingest_cmd_verdict_beat()
    test_store_normalizes_stub_state()
    test_ingest_mcp_bridge()
    test_llm_extract_json()
    test_store_live_dilation_and_guest_clock()
    test_rollout_manifest()
    test_wave_sizes()
    print("ok")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
