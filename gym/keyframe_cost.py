#!/usr/bin/env python3
"""What an incremental keyframe costs at the idle / k8s / kafka divergence levels.

Brings up one Ubuntu 3x2 GiB cluster, then for each of the three
workloads (idle / k8s / kafka):

  1. install that workload on the *source* cluster, the way fork-under-load does --
     a broker deployed fresh inside a fork has to pull its image through
     the fork's NAT and does not come up inside any sane ceiling,
  2. fork a child off the prepared root,
  3. drive the workload's traffic against the child so it diverges,
  4. `tree_prepare_fork_source` the child -- the incremental keyframe,
  5. fork a grandchild off the new keyframe and check it is healthy.

What gets recorded per level is the prepare latency and what the
keyframe physically cost. The daemon reports that cost (`base_disk_bytes`
on the prepare reply) because nothing on the host can measure it after
the fact: a cloned file reports its whole logical length from `stat`,
and `st_blocks` counts extents it only shares, so both would say "6 GiB"
for a keyframe that cost megabytes (CHALLENGES #152). Free-space delta
is recorded alongside as a loose upper bound -- loose because the three
guests keep writing to their own CoW disks throughout.

The baseline to compare against is the root's own keyframe, written by
`tree_adopt_cluster`: root has no ancestor to clone, so all three
members go out in full -- the 7.327 s / 6 GiB we measured.

Talks only to `/run/k7d/k7d.sock`. No new k7d primitives.
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import sys
import threading
import time
import uuid
from pathlib import Path
from typing import Any

HERE = Path(__file__).resolve().parent
REPO = HERE.parent
sys.path.insert(0, str(HERE))
sys.path.insert(0, str(REPO / "examples" / "cluster-tree-search"))

from fork_under_load import (  # noqa: E402
    KAFKA_YAML,
    Cluster,
    apply_yaml,
    deploy_churn,
    guest_kubectl,
    kafka_produce,
    kafka_wait_contains,
    wait_kafka,
)
from k7d_client import K7dClient  # noqa: E402

log = logging.getLogger("keyframe")

PAGE = 4096
TREES_DIR = Path("/var/lib/k7d/trees")


def fs_used_bytes(path: Path) -> int:
    """Bytes in use on the filesystem holding `path`."""
    st = os.statvfs(path)
    return st.f_frsize * (st.f_blocks - st.f_bfree)


def member_span(tree_id: str, node_id: str) -> int:
    """Logical bytes of a node's keyframe -- what a full dump would cost."""
    members = TREES_DIR / tree_id / "nodes" / node_id / "members"
    if not members.is_dir():
        raise RuntimeError(f"no members dir for {node_id} at {members}")
    total = 0
    for member in sorted(members.iterdir()):
        mem = member / "memory.bin"
        if not mem.is_file():
            raise RuntimeError(f"missing keyframe {mem}")
        total += mem.stat().st_size
    if total == 0:
        raise RuntimeError(f"{node_id} keyframe is empty")
    return total


def child_view(cluster: Cluster, fork: dict[str, Any]) -> Cluster:
    """A `Cluster` handle whose root is `fork`, for the workload drivers.

    Only used to reach the fork's own cids and to fork below it. Never
    torn down -- the real cluster owns the VMs and the disks.
    """
    view = Cluster(cluster.client, cluster.tree_id)
    view.root_id = fork["node_id"]
    view.cids = list(fork["guest_cids"])
    view.server_cid = view.cids[0]
    view.bridge = fork["bridge"]
    return view


def install_idle(cluster: Cluster) -> None:
    """The floor needs nothing installed."""


def install_k8s(cluster: Cluster) -> None:
    """k8s level: the churn target lives on the source."""
    deploy_churn(cluster.server_cid)


def install_kafka(cluster: Cluster) -> None:
    """Ceiling: a broker, deployed on the source and forked warm.

    Deployed here rather than in the child because the image pull and
    broker start take longer inside a fresh fork than any ceiling this
    harness is willing to wait; fork-under-load forks a *running* broker too.
    """
    apply_yaml(cluster.server_cid, KAFKA_YAML, "kafka")
    wait_kafka(cluster.server_cid)


def diverge_idle(view: Cluster, seconds: float) -> None:
    """The floor: a k3s control plane doing nothing but being alive."""
    time.sleep(seconds)


def diverge_k8s(view: Cluster, seconds: float) -> None:
    """k8s level: a churning inner control plane."""
    stop = threading.Event()

    def churn() -> None:
        i = 0
        while not stop.is_set():
            try:
                guest_kubectl(
                    view.server_cid,
                    ["create", "configmap", f"kf-churn-{i}", f"--from-literal=n={i}"],
                    timeout_s=20,
                )
                guest_kubectl(
                    view.server_cid,
                    ["scale", "deploy/inner-load", f"--replicas={3 + (i % 3)}"],
                    timeout_s=20,
                )
            except RuntimeError as e:
                if stop.is_set():
                    return
                log.warning("k8s churn step: %s", e)
            i += 1
            time.sleep(0.25)

    t = threading.Thread(target=churn, daemon=True)
    t.start()
    time.sleep(seconds)
    stop.set()
    t.join(timeout=15)


def diverge_kafka(view: Cluster, seconds: float) -> None:
    """Ceiling: keep producing into the forked broker."""
    deadline = time.monotonic() + seconds
    n = 0
    while time.monotonic() < deadline:
        marker = f"KEYFRAME-{n}-{uuid.uuid4().hex[:8]}"
        kafka_produce(view.server_cid, marker)
        kafka_wait_contains(view.server_cid, marker)
        n += 1
    if n == 0:
        raise RuntimeError("kafka divergence produced nothing")


INSTALL = {"idle": install_idle, "k8s": install_k8s, "kafka": install_kafka}
DIVERGE = {"idle": diverge_idle, "k8s": diverge_k8s, "kafka": diverge_kafka}


def measure(cluster: Cluster, workload: str, seconds: float) -> dict[str, Any]:
    client = cluster.client
    INSTALL[workload](cluster)
    fork = cluster.fork_many([f"kf-{workload}"])[0]
    node_id = fork["node_id"]
    view = child_view(cluster, fork)
    try:
        DIVERGE[workload](view, seconds)

        used_before = fs_used_bytes(TREES_DIR)
        t0 = time.perf_counter()
        prep = client.tree_prepare_fork_source(cluster.tree_id, node_id, timeout=600)
        wall_s = time.perf_counter() - t0
        # Loose: the three guests keep writing their own CoW disks in
        # this window, so free space moves for reasons that are not the
        # keyframe. The daemon's own number below is the tight one.
        grew = fs_used_bytes(TREES_DIR) - used_before
        keyframe_bytes = int(prep.get("base_disk_bytes") or 0)
        span = member_span(cluster.tree_id, node_id)

        if not prep.get("wrote_base"):
            raise RuntimeError(f"{workload}: prepare wrote no base: {prep}")
        if not prep.get("wrote_base_incremental"):
            raise RuntimeError(
                f"{workload}: prepare fell back to a full dump -- is the tree root "
                f"on the reflink XFS? {prep}"
            )

        # The keyframe must be usable, not merely cheap: fork off it and
        # ask the inner control plane a question.
        grand = cluster.client.tree_fork_batch(
            cluster.tree_id, node_id, [f"kf-{workload}-gen2"], timeout=300
        )
        gfork = list(grand.get("forks") or [])[0]
        gcid = int(gfork["guest_cids"][0])
        nodes_out = guest_kubectl(gcid, ["get", "nodes", "--no-headers"], timeout_s=120)
        ready = [ln for ln in nodes_out.splitlines() if " Ready" in ln]
        if len(ready) != len(fork["guest_cids"]):
            raise RuntimeError(
                f"{workload}: grandchild of the incremental keyframe has "
                f"{len(ready)}/{len(fork['guest_cids'])} Ready nodes:\n{nodes_out}"
            )
        client.tree_prune(cluster.tree_id, gfork["node_id"])

        rec = {
            "workload": workload,
            "node_id": node_id,
            "dirty_pages": keyframe_bytes // PAGE,
            "prepare_wall_s": round(wall_s, 3),
            "prepare_latency_s": round(int(prep["latency_ns"]) / 1e9, 3),
            "incremental": True,
            "keyframe_span_bytes": span,
            "keyframe_disk_bytes": keyframe_bytes,
            "fs_grew_bytes": grew,
            "disk_share_of_full": round(keyframe_bytes / span, 5) if span else None,
        }
        print("KEYFRAME_MEASURE " + json.dumps(rec, separators=(",", ":")), flush=True)
        return rec
    finally:
        try:
            cluster.prune_child(node_id)
        except RuntimeError as e:
            log.warning("prune %s: %s", node_id, e)


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--out", type=Path, required=True)
    p.add_argument("--tree-id", default=f"kf-{os.getpid()}")
    p.add_argument("--diverge-s", type=float, default=30.0)
    p.add_argument("--workloads", default="idle,k8s,kafka")
    return p.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    logging.basicConfig(
        level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s"
    )
    args.out.mkdir(parents=True, exist_ok=True)

    client = K7dClient()
    client.ping()
    cluster = Cluster(client, args.tree_id)
    rows: list[dict[str, Any]] = []
    try:
        t0 = time.perf_counter()
        used_before = fs_used_bytes(TREES_DIR)
        # `tree_adopt_cluster` inside `bring_up` writes the root
        # keyframe itself, and root has no ancestor to clone, so that
        # call *is* the full-dump baseline. Preparing again afterwards
        # would only measure the idempotent no-op.
        cluster.bring_up(prepare=False)
        span = member_span(args.tree_id, cluster.root_id)
        baseline = {
            "workload": "root-full-dump",
            "prepare_wall_s": round(cluster.adopt_prepare_s, 3),
            "incremental": False,
            "keyframe_span_bytes": span,
            "keyframe_disk_bytes": span,
            "fs_grew_bytes": fs_used_bytes(TREES_DIR) - used_before,
            "bring_up_s": round(time.perf_counter() - t0, 1),
        }
        print(
            "KEYFRAME_MEASURE " + json.dumps(baseline, separators=(",", ":")),
            flush=True,
        )
        rows.append(baseline)
        client.tree_protect(args.tree_id, cluster.root_id)

        for workload in [w for w in args.workloads.split(",") if w]:
            rows.append(measure(cluster, workload, args.diverge_s))
    finally:
        (args.out / "keyframe_cost.json").write_text(json.dumps(rows, indent=2))
        cluster.teardown()
    print("KEYFRAME_MEASURE done", flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
