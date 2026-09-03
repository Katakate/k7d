#!/usr/bin/env python3
"""Offline tests for real-probe formatting (no vsock)."""

from probe import format_probe, live_targets, parse_uptime, root_server_target


def test_live_targets_skips_suspended() -> None:
    trees = {
        "t1": {
            "nodes": {
                "a": {"id": "a", "state": "live"},
                "b": {"id": "b", "state": "suspended"},
            },
            "members": {"a": [42, 43], "b": [99]},
        }
    }
    got = live_targets(trees)
    assert got == [("t1", "a", 42), ("t1", "a", 43)]
    trees_root = {
        "t1": {
            "nodes": {
                "root": {"id": "root", "state": "live", "parent": None},
                "a": {"id": "a", "state": "live", "parent": "root"},
            },
            "members": {"root": [10, 11], "a": [20]},
        }
    }
    assert root_server_target(trees_root) == ("t1", "root", 10)
    assert parse_uptime("12.5 48.0") == 12.5
    assert parse_uptime("") is None
    assert parse_uptime("not-a-number") is None


def test_format_probe_is_measured() -> None:
    text = format_probe(
        {
            "cid": 7,
            "ok": True,
            "ping_ms": 1.23,
            "uptime": "12.5 48.0",
            "loadavg": "0.04 0.01 0.00 1/12 3",
            "exec_ms": 4.5,
            "wrote": True,
            "error": "",
        }
    )
    assert "vsock cid=7" in text
    assert "ping=1.23ms" in text
    assert "uptime=12.5" in text
    assert "load=0.04" in text
    assert "exec=4.5ms" in text
    assert "wrote /tmp/k7view-probe" in text
    fail = format_probe(
        {"cid": 8, "ok": False, "ping_ms": 9.1, "error": "ping-fail"}
    )
    assert "ping-fail" in fail
    assert "uptime=" not in fail


if __name__ == "__main__":
    test_live_targets_skips_suspended()
    test_format_probe_is_measured()
    print("ok")
