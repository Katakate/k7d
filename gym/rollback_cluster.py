#!/usr/bin/env python3
"""35a-inc2: tree_rollback after a dirty Ubuntu child.

Talks to `/run/k7d/k7d.sock`. Imports `Cluster` from fork_under_load;
does not edit that file. Zero new k7d primitives.
"""

from __future__ import annotations

import argparse
import logging
import os
import sys
import time
from pathlib import Path
from typing import Any

HERE = Path(__file__).resolve().parent
REPO = HERE.parent
sys.path.insert(0, str(HERE))
sys.path.insert(0, str(REPO / "examples" / "cluster-tree-search"))

import agent  # noqa: E402
from fork_under_load import (  # noqa: E402
    CHURN_PAUSE,
    Cluster,
    apply_yaml,
    guest_kubectl,
    guest_sh,
)
from host import k7_bridge_name, list_bridges  # noqa: E402
from k7d_client import K7dClient  # noqa: E402

log = logging.getLogger("rb")

PAUSE_YAML = f"""apiVersion: apps/v1
kind: Deployment
metadata:
  name: pause
spec:
  replicas: 1
  selector:
    matchLabels:
      app: pause
  template:
    metadata:
      labels:
        app: pause
    spec:
      containers:
      - name: pause
        image: {CHURN_PAUSE}
        imagePullPolicy: IfNotPresent
"""


def cm_exists(cid: int, name: str) -> bool:
    r = agent.exec_cmd(cid, ["k3s", "kubectl", "get", "cm", name], timeout_s=30)
    return r["exit_code"] == 0


def file_exists(cid: int, path: str) -> bool:
    r = agent.exec_cmd(cid, ["test", "-f", path], timeout_s=10)
    return r["exit_code"] == 0


def replicas(cid: int) -> int:
    out = guest_kubectl(
        cid, ["get", "deploy/pause", "-o", "jsonpath={.spec.replicas}"], timeout_s=30
    ).strip()
    if not out.isdigit():
        raise RuntimeError(f"cid={cid} deploy/pause replicas={out!r}")
    return int(out)


def ready_count(cid: int) -> int:
    out = guest_kubectl(cid, ["get", "nodes", "--no-headers"], timeout_s=60)
    return sum(1 for ln in out.splitlines() if " Ready" in ln)


def wait_ready(cid: int, want: int = 3, ceiling_s: float = 60.0) -> int:
    deadline = time.monotonic() + ceiling_s
    last = ""
    while time.monotonic() < deadline:
        try:
            n = ready_count(cid)
            if n >= want:
                return n
            last = f"{n} Ready"
        except RuntimeError as e:
            last = str(e)
        time.sleep(2)
    raise RuntimeError(f"cid={cid} want {want} Ready nodes: {last}")


def assert_cow(label: str, flags: Any, want_n: int = 3) -> None:
    if not isinstance(flags, list) or len(flags) != want_n or any(flags):
        raise RuntimeError(
            f"{label}: expected CoW {[False] * want_n}, got {flags} "
            "(CHALLENGES #143/#144 silent full copy)"
        )


def attach_fork(
    cluster: Cluster,
    resp: dict[str, Any],
    label: str,
    *,
    ms: float,
    before: set[str],
) -> dict[str, Any]:
    nid = resp["node_id"]
    cids = [int(c) for c in resp.get("guest_cids") or []]
    if len(cids) != 3:
        raise RuntimeError(f"{label} missing 3 guest_cids: {resp}")
    flags = resp.get("fork_memory_full_copy")
    assert_cow(label, flags)
    cluster_id = f"{cluster.tree_id}-{nid}"
    bridge = k7_bridge_name(cluster_id)
    visible = list_bridges()
    if bridge not in visible:
        raise RuntimeError(
            f"{label} bridge {bridge} not on host "
            f"(new={sorted(visible - before)} all={sorted(visible)})"
        )
    for i, cid in enumerate(cids):
        if not agent.ping(cid, timeout_s=8):
            raise RuntimeError(f"{label} member {i} cid={cid} vsock dead")
    wait_ready(cids[0])
    print(
        f"RB_MEASURE fork_{label}_ms={ms:.1f} node={nid} "
        f"bridge={bridge} cids={cids} latency_ns={resp.get('latency_ns')}",
        flush=True,
    )
    return {
        "node_id": nid,
        "guest_cids": cids,
        "bridge": bridge,
        "server_cid": cids[0],
        "fork_ms": ms,
        "full_copy": flags,
        "latency_ns": resp.get("latency_ns"),
    }


def rollback_from_root(cluster: Cluster, label: str) -> dict[str, Any]:
    before = list_bridges()
    t0 = time.perf_counter()
    resp = cluster.client.call(
        {
            "op": "tree_rollback",
            "tree_id": cluster.tree_id,
            "node_id": cluster.root_id,
            "label": label,
        },
        timeout=180,
    )
    ms = (time.perf_counter() - t0) * 1000.0
    if resp.get("status") != "tree_forked":
        raise RuntimeError(f"tree_rollback: {resp}")
    return attach_fork(cluster, resp, label, ms=ms, before=before)


def assert_checkpoint(cid: int, side: str) -> None:
    if not cm_exists(cid, "checkpoint-mark"):
        raise RuntimeError(f"{side}: missing ConfigMap checkpoint-mark")
    if not file_exists(cid, "/var/tmp/checkpoint"):
        raise RuntimeError(f"{side}: missing /var/tmp/checkpoint")
    if cm_exists(cid, "dirty-only"):
        raise RuntimeError(f"{side}: leaked ConfigMap dirty-only (CHALLENGES #143/#144)")
    if file_exists(cid, "/var/tmp/dirty"):
        raise RuntimeError(f"{side}: leaked /var/tmp/dirty")
    got = replicas(cid)
    if got != 1:
        raise RuntimeError(f"{side}: deploy/pause replicas={got}, want 1")
    n = wait_ready(cid)
    if n < 3:
        raise RuntimeError(f"{side}: {n} Ready nodes, want 3")


def assert_dirty(cid: int) -> None:
    if not cm_exists(cid, "dirty-only"):
        raise RuntimeError("dirty: missing ConfigMap dirty-only")
    if not file_exists(cid, "/var/tmp/dirty"):
        raise RuntimeError("dirty: missing /var/tmp/dirty")
    if not cm_exists(cid, "checkpoint-mark"):
        raise RuntimeError("dirty: lost inherited checkpoint-mark")
    got = replicas(cid)
    if got != 3:
        raise RuntimeError(f"dirty: deploy/pause replicas={got}, want 3")
    n = wait_ready(cid)
    if n < 3:
        raise RuntimeError(f"dirty: {n} Ready nodes, want 3")


def run(tree_id: str) -> dict[str, float]:
    client = K7dClient()
    client.ping()
    cluster = Cluster(client, tree_id)
    try:
        cluster.bring_up()
        guest_kubectl(
            cluster.server_cid,
            [
                "create",
                "configmap",
                "checkpoint-mark",
                "--from-literal=mark=checkpoint",
            ],
        )
        guest_sh(cluster.cids[0], "echo checkpoint > /var/tmp/checkpoint")
        apply_yaml(cluster.server_cid, PAUSE_YAML, "pause")
        guest_kubectl(
            cluster.server_cid,
            ["rollout", "status", "deploy/pause", "--timeout=120s"],
        )

        dirty = cluster.fork_one("dirty")
        assert_cow("dirty", dirty.get("full_copy"))
        wait_ready(dirty["server_cid"])
        print(
            f"RB_MEASURE fork_dirty_ms={dirty['fork_ms']:.1f} "
            f"node={dirty['node_id']} bridge={dirty['bridge']}",
            flush=True,
        )

        guest_kubectl(dirty["server_cid"], ["scale", "deploy/pause", "--replicas=3"])
        guest_kubectl(
            dirty["server_cid"],
            ["create", "configmap", "dirty-only", "--from-literal=side=child"],
        )
        guest_sh(dirty["guest_cids"][0], "echo dirty > /var/tmp/dirty")
        assert_dirty(dirty["server_cid"])
        assert_checkpoint(cluster.server_cid, "root-after-mutate")

        undone = rollback_from_root(cluster, "undone")
        assert_checkpoint(undone["server_cid"], "undone")
        assert_dirty(dirty["server_cid"])
        assert_checkpoint(cluster.server_cid, "root-after-rollback")

        print(
            f"RB_MEASURE ok rollback_ms={undone['fork_ms']:.1f} "
            f"dirty_ms={dirty['fork_ms']:.1f} "
            f"rollback_latency_ns={undone.get('latency_ns')} "
            f"dirty_node={dirty['node_id']} undone_node={undone['node_id']}",
            flush=True,
        )
        return {
            "rollback_ms": float(undone["fork_ms"]),
            "dirty_ms": float(dirty["fork_ms"]),
        }
    finally:
        cluster.teardown()


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--tree-id", default="")
    return p.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    ns = parse_args(argv)
    tree_id = ns.tree_id or f"rb-35a-{os.getpid()}"
    if not tree_id.startswith("rb-35a-"):
        raise RuntimeError(f"tree_id must start with rb-35a-, got {tree_id}")
    run(tree_id)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
