#!/usr/bin/env python3
"""35a-inc1: dual-child write isolation at Ubuntu cluster fidelity.

One 3-node Ubuntu source, `tree_fork_batch` labels=["alice","bob"], then
exclusive ConfigMaps and /var/tmp mark files on alice / bob / root.
Asserts each side cannot see the other two's objects or files, all three
clusters have 3 Ready nodes, forks are CoW, three distinct bridges.

Talks to `/run/k7d/k7d.sock` only. Imports `Cluster` from
`gym/fork_under_load.py` — do not edit that module.
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import sys
from pathlib import Path
from typing import Any

HERE = Path(__file__).resolve().parent
REPO = HERE.parent
sys.path.insert(0, str(HERE))
sys.path.insert(0, str(REPO / "examples" / "cluster-tree-search"))

from fork_under_load import Cluster, guest_kubectl, guest_sh  # noqa: E402
from k7d_client import K7dClient  # noqa: E402

log = logging.getLogger("dci")


def _cm_names(cid: int) -> set[str]:
    out = guest_kubectl(
        cid, ["get", "cm", "-o", "jsonpath={.items[*].metadata.name}"]
    ).strip()
    return set(out.split()) if out else set()


def _assert_cm_absent(cid: int, name: str, *, side: str) -> None:
    try:
        guest_kubectl(cid, ["get", "cm", name])
    except RuntimeError:
        return
    raise RuntimeError(f"{side}: ConfigMap {name} leaked (visible via kubectl)")


def _assert_cm_present(cid: int, name: str, *, side: str) -> None:
    got = guest_kubectl(
        cid, ["get", "cm", name, "-o", "jsonpath={.metadata.name}"]
    ).strip()
    if got != name:
        raise RuntimeError(f"{side}: missing ConfigMap {name}, got {got!r}")


def _file_exists(cid: int, path: str) -> bool:
    r = guest_sh(
        cid,
        f"if test -f {path}; then echo yes; else echo no; fi",
        timeout_s=15,
    )
    return r["stdout"].strip() == "yes"


def _write_mark(cid: int, mark: str) -> None:
    guest_sh(cid, f"echo {mark} > /var/tmp/{mark}", timeout_s=15)


def _assert_mark(cid: int, mark: str, *, side: str, present: bool) -> None:
    path = f"/var/tmp/{mark}"
    exists = _file_exists(cid, path)
    if present and not exists:
        raise RuntimeError(f"{side}: missing mark file {path}")
    if not present and exists:
        raise RuntimeError(f"{side}: mark file {path} leaked from another cluster")


def _ready_nodes(cid: int, *, side: str) -> None:
    nodes_out = guest_kubectl(cid, ["get", "nodes", "--no-headers"], timeout_s=120)
    ready = [ln for ln in nodes_out.splitlines() if " Ready" in ln]
    if len(ready) != 3:
        raise RuntimeError(
            f"{side}: expected 3 Ready nodes, got {len(ready)}:\n{nodes_out}"
        )


def _assert_cow(forks: list[dict[str, Any]]) -> None:
    for fr in forks:
        full = list(fr.get("full_copy") or [])
        if not full:
            raise RuntimeError(f"fork {fr['node_id']} missing fork_memory_full_copy")
        if any(full):
            raise RuntimeError(
                f"fork {fr['node_id']} expected CoW, got fork_memory_full_copy={full}"
            )


def _assert_side(
    *,
    label: str,
    server_cid: int,
    own_cm: str,
    own_mark: str,
    foreign_cms: tuple[str, ...],
    foreign_marks: tuple[str, ...],
) -> None:
    _assert_cm_present(server_cid, own_cm, side=label)
    for cm in foreign_cms:
        _assert_cm_absent(server_cid, cm, side=label)
    _assert_mark(server_cid, own_mark, side=label, present=True)
    for mark in foreign_marks:
        _assert_mark(server_cid, mark, side=label, present=False)


def run(cluster: Cluster) -> dict[str, Any]:
    forks = cluster.fork_many(["alice", "bob"])
    if len(forks) != 2:
        raise RuntimeError(f"expected 2 forks, got {len(forks)}")
    by_label = {lbl: fr for lbl, fr in zip(("alice", "bob"), forks)}
    alice = by_label["alice"]
    bob = by_label["bob"]
    fork_batch_ms = max(alice["fork_ms"], bob["fork_ms"])
    _assert_cow(forks)

    bridges = {
        "root": cluster.bridge,
        "alice": alice["bridge"],
        "bob": bob["bridge"],
    }
    if len(set(bridges.values())) != 3:
        raise RuntimeError(f"expected 3 distinct bridges, got {bridges}")

    guest_kubectl(
        cluster.server_cid,
        ["create", "configmap", "src-only", "--from-literal=side=source"],
    )
    guest_kubectl(
        alice["server_cid"],
        ["create", "configmap", "alice-only", "--from-literal=side=alice"],
    )
    guest_kubectl(
        bob["server_cid"],
        ["create", "configmap", "bob-only", "--from-literal=side=bob"],
    )
    _write_mark(cluster.server_cid, "src-mark")
    _write_mark(alice["server_cid"], "alice-mark")
    _write_mark(bob["server_cid"], "bob-mark")

    _assert_side(
        label="root",
        server_cid=cluster.server_cid,
        own_cm="src-only",
        own_mark="src-mark",
        foreign_cms=("alice-only", "bob-only"),
        foreign_marks=("alice-mark", "bob-mark"),
    )
    _assert_side(
        label="alice",
        server_cid=alice["server_cid"],
        own_cm="alice-only",
        own_mark="alice-mark",
        foreign_cms=("bob-only", "src-only"),
        foreign_marks=("bob-mark", "src-mark"),
    )
    _assert_side(
        label="bob",
        server_cid=bob["server_cid"],
        own_cm="bob-only",
        own_mark="bob-mark",
        foreign_cms=("alice-only", "src-only"),
        foreign_marks=("alice-mark", "src-mark"),
    )

    for label, bridge in bridges.items():
        cid = (
            cluster.server_cid
            if label == "root"
            else by_label[label]["server_cid"]
        )
        _ready_nodes(cid, side=label)
        cms = _cm_names(cid)
        log.info("%s bridge=%s cms=%s", label, bridge, sorted(cms))

    result = {
        "ok": True,
        "tree_id": cluster.tree_id,
        "fork_batch_ms": round(fork_batch_ms, 1),
        "bridges": bridges,
        "alice_node": alice["node_id"],
        "bob_node": bob["node_id"],
    }
    print(
        f"DCI_MEASURE ok tree={cluster.tree_id} fork_batch_n2_ms={fork_batch_ms:.1f} "
        f"bridges={json.dumps(bridges, separators=(',', ':'))}",
        flush=True,
    )
    return result


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--out", type=Path, default=Path("/tmp/k7-35a-inc1"))
    p.add_argument("--tree-id", default="")
    return p.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    ns = parse_args(argv)
    ns.out.mkdir(parents=True, exist_ok=True)
    tree_id = ns.tree_id or f"dci-35a-{os.getpid()}"
    client = K7dClient()
    client.ping()
    cluster = Cluster(client, tree_id)
    result: dict[str, Any] | None = None
    failed: Exception | None = None
    try:
        cluster.bring_up()
        result = run(cluster)
    except Exception as e:
        failed = e
        log.exception("dual-child harness failed")
    finally:
        cluster.teardown()
    out_json = ns.out / "dual_child.json"
    if result is not None:
        out_json.write_text(json.dumps(result, indent=2) + "\n")
    if failed is not None:
        raise failed
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
