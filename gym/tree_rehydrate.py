#!/usr/bin/env python3
"""35a-inc4: kill -9 k7d mid Ubuntu tree, restart, rehydrate, resume, fork.

Import Cluster. Do not call teardown() before the crash. Talks to
`/run/k7d/k7d.sock`. Do not resurrect live KVM — resume from the
on-disk tree only.
"""

from __future__ import annotations

import argparse
import logging
import os
import subprocess
import sys
import time
from pathlib import Path
from typing import Any

HERE = Path(__file__).resolve().parent
REPO = HERE.parent
sys.path.insert(0, str(HERE))
sys.path.insert(0, str(REPO / "examples" / "cluster-tree-search"))

import agent  # noqa: E402
from fork_under_load import Cluster, guest_kubectl, guest_sh  # noqa: E402
from host import k7_bridge_name, list_bridges, list_taps  # noqa: E402
from k7d_client import K7dClient  # noqa: E402

log = logging.getLogger("rh")

SOCK = Path("/run/k7d/k7d.sock")
TREE_ROOT = Path("/var/lib/k7d/trees")
NET = Path("/sys/class/net")


def stamp_pre_crash_mark(cid: int) -> None:
    guest_kubectl(
        cid,
        [
            "create",
            "configmap",
            "pre-crash-mark",
            "--from-literal=mark=pre-crash",
        ],
    )
    guest_sh(cid, "echo pre-crash > /var/tmp/pre-crash && sync")


def bring_up_with_mark(cluster: Cluster) -> None:
    """Ready 3-node, stamp the mark, then adopt so the checkpoint has it.

    kill -9 cannot resurrect live RAM. The last keyframe is what resume
    maps — write the mark before `tree_adopt_cluster` so `memory.bin`
    contains it (CHALLENGES #205).
    """
    orig = cluster.client.tree_adopt_cluster

    def adopt_after_mark(vm_ids: list[str], **kwargs: Any) -> dict[str, Any]:
        if not cluster.cids:
            raise RuntimeError("adopt_after_mark: no guest CIDs")
        stamp_pre_crash_mark(cluster.cids[0])
        return orig(vm_ids, **kwargs)

    cluster.client.tree_adopt_cluster = adopt_after_mark  # type: ignore[method-assign]
    try:
        cluster.bring_up()
    finally:
        cluster.client.tree_adopt_cluster = orig  # type: ignore[method-assign]


def cm_exists(cid: int, name: str) -> bool:
    r = agent.exec_cmd(cid, ["k3s", "kubectl", "get", "cm", name], timeout_s=30)
    return r["exit_code"] == 0


def file_exists(cid: int, path: str) -> bool:
    r = agent.exec_cmd(cid, ["test", "-f", path], timeout_s=10)
    return r["exit_code"] == 0


def ready_count(cid: int) -> int:
    out = guest_kubectl(cid, ["get", "nodes", "--no-headers"], timeout_s=60)
    return sum(1 for ln in out.splitlines() if " Ready" in ln)


def wait_ready(cid: int, want: int = 3, ceiling_s: float = 90.0) -> int:
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


def wait_sock(ceiling_s: float = 60.0) -> None:
    deadline = time.monotonic() + ceiling_s
    while time.monotonic() < deadline:
        if SOCK.exists():
            try:
                K7dClient(timeout=2).ping()
                return
            except OSError:
                pass
            except RuntimeError:
                pass
        time.sleep(0.2)
    raise RuntimeError(f"{SOCK} did not accept within {ceiling_s}s")


def ensure_k7d_up() -> None:
    subprocess.run(["systemctl", "start", "k7d"], check=False)
    wait_sock()


def kill_k7d() -> None:
    """SIGKILL the daemon without a graceful Drop. Then stop the unit.

    `Restart=on-failure` would otherwise race a new k7d against leftover
    bridges (CHALLENGES #208). `systemctl stop` after the kill prevents
    that restart so this harness can clean *this* tree's leftovers first.
    """
    r = subprocess.run(
        ["systemctl", "kill", "-s", "KILL", "k7d"],
        check=False,
        capture_output=True,
        text=True,
    )
    log.info("systemctl kill KILL k7d: rc=%s %s", r.returncode, r.stderr.strip())
    deadline = time.monotonic() + 5
    while time.monotonic() < deadline:
        if not subprocess.run(["pidof", "k7d"], capture_output=True).stdout.strip():
            break
        time.sleep(0.1)
    subprocess.run(["systemctl", "stop", "k7d"], check=False)
    deadline = time.monotonic() + 8
    while time.monotonic() < deadline:
        st = subprocess.run(
            ["systemctl", "is-active", "k7d"], capture_output=True, text=True
        )
        if st.stdout.strip() != "active":
            return
        time.sleep(0.2)
    raise RuntimeError("k7d still active after kill+stop")


def cleanup_tree_leftovers(tree_id: str, extra: set[str] | None = None) -> list[str]:
    """Delete leftover k7-br-* / TAP slaves that belong to this tree only.

    After kill -9, Drop never ran. The adopt bridge (`k7_bridge_name(tree_id)`)
    stays up with 10.200.0.1/24. Resume creates `{tree_id}-root` — a second
    gateway on the same subnet, and guest traffic blackholes (CHALLENGES #208).
    Never a global `k7-*` wipe.
    """
    names = {k7_bridge_name(tree_id), k7_bridge_name(f"{tree_id}-root")}
    if extra:
        names |= extra
    cleaned: list[str] = []
    for br in sorted(names):
        brif = NET / br / "brif"
        taps: list[str] = []
        if brif.is_dir():
            taps = [p.name for p in brif.iterdir()]
        for tap in taps:
            subprocess.run(
                ["ip", "link", "delete", tap],
                check=False,
                capture_output=True,
            )
        if not (NET / br).exists():
            continue
        subprocess.run(
            ["ip", "link", "set", "dev", br, "down"],
            check=False,
            capture_output=True,
        )
        subprocess.run(
            ["ip", "link", "delete", br, "type", "bridge"],
            check=False,
            capture_output=True,
        )
        cleaned.append(br)
    leftover = names & list_bridges()
    if leftover:
        raise RuntimeError(f"leftover bridges still present after cleanup: {leftover}")
    log.info(
        "cleaned leftover net for %s: bridges=%s taps_now=%s",
        tree_id,
        cleaned,
        sorted(list_taps()),
    )
    return cleaned


def tree_in_list(client: K7dClient, tree_id: str) -> dict[str, Any] | None:
    resp = client.tree_list()
    for t in resp.get("trees") or []:
        if t.get("tree_id") == tree_id:
            return t
    return None


def assert_suspended(client: K7dClient, tree_id: str) -> None:
    nodes = client.tree_nodes(tree_id)
    for n in nodes.get("nodes") or []:
        if n.get("state") != "suspended":
            raise RuntimeError(
                f"open() contract: node {n.get('id')} state={n.get('state')}, "
                f"want suspended"
            )
        live = (nodes.get("live_guest_cids") or {}).get(n.get("id")) or []
        if live:
            raise RuntimeError(
                f"open() contract: node {n.get('id')} still has live CIDs {live}"
            )


def assert_marks(cid: int, side: str) -> None:
    if not cm_exists(cid, "pre-crash-mark"):
        raise RuntimeError(f"{side}: missing ConfigMap pre-crash-mark")
    if not file_exists(cid, "/var/tmp/pre-crash"):
        raise RuntimeError(f"{side}: missing /var/tmp/pre-crash")


def run(tree_id: str) -> dict[str, Any]:
    client = K7dClient()
    client.ping()
    cluster = Cluster(client, tree_id)
    cleaned: list[str] = []
    try:
        bring_up_with_mark(cluster)
        tree_json = TREE_ROOT / tree_id / "tree.json"
        if not tree_json.is_file():
            raise RuntimeError(f"expected {tree_json} after bring_up")
        pre_cids = [int(c) for c in cluster.cids]
        root_id = cluster.root_id
        print(
            f"RH_MEASURE pre_crash tree={tree_id} root={root_id} "
            f"cids={pre_cids} bridge={cluster.bridge} json={tree_json}",
            flush=True,
        )

        kill_k7d()
        cleaned = cleanup_tree_leftovers(tree_id, extra={cluster.bridge} if cluster.bridge else None)
        print(f"RH_MEASURE leftover_bridges_cleaned={cleaned}", flush=True)
        ensure_k7d_up()
        client = K7dClient()
        cluster.client = client

        listed = tree_in_list(client, tree_id)
        opened_via = "startup_scan"
        if listed is None:
            opened = client.tree_open(tree_id)
            if opened.get("status") != "tree_opened":
                raise RuntimeError(f"tree_open: {opened}")
            opened_via = "tree_open"
            listed = tree_in_list(client, tree_id)
            if listed is None:
                raise RuntimeError("tree_open succeeded but tree_list is still empty")
        print(f"RH_MEASURE rehydrate via={opened_via} list={listed}", flush=True)
        assert_suspended(client, tree_id)

        t0 = time.perf_counter()
        resumed = client.tree_resume(tree_id, root_id)
        resume_ms = (time.perf_counter() - t0) * 1000.0
        if resumed.get("status") != "tree_resumed":
            raise RuntimeError(f"tree_resume: {resumed}")
        new_cids = [int(c) for c in resumed.get("guest_cids") or []]
        if len(new_cids) != 3:
            raise RuntimeError(f"resume missing 3 guest_cids: {resumed}")
        if set(new_cids) & set(pre_cids):
            raise RuntimeError(
                f"resume reused pre-crash CIDs: pre={pre_cids} new={new_cids}"
            )
        cluster.cids = new_cids
        cluster.server_cid = new_cids[0]
        cluster.bridge = k7_bridge_name(f"{tree_id}-{root_id}")
        for i, cid in enumerate(new_cids):
            if not agent.ping(cid, timeout_s=12):
                raise RuntimeError(f"resume member {i} cid={cid} vsock dead")
        wait_ready(new_cids[0])
        assert_marks(new_cids[0], "resumed-root")
        print(
            f"RH_MEASURE resume_ms={resume_ms:.1f} new_cids={new_cids} "
            f"bridge={cluster.bridge}",
            flush=True,
        )

        child = cluster.fork_one("child")
        wait_ready(child["server_cid"])
        assert_marks(child["server_cid"], "child")
        guest_kubectl(
            child["server_cid"],
            ["create", "configmap", "child-only", "--from-literal=side=child"],
        )
        if cm_exists(cluster.server_cid, "child-only"):
            raise RuntimeError("root: leaked ConfigMap child-only from child")
        assert_marks(cluster.server_cid, "root-after-fork")

        print(
            f"RH_MEASURE ok via={opened_via} resume_ms={resume_ms:.1f} "
            f"fork_ms={child['fork_ms']:.1f} child={child['node_id']} "
            f"pre_cids={pre_cids} new_cids={new_cids}",
            flush=True,
        )
        return {
            "ok": True,
            "via": opened_via,
            "resume_ms": resume_ms,
            "fork_ms": child["fork_ms"],
            "cleaned_bridges": cleaned,
        }
    finally:
        try:
            cluster.teardown()
        except Exception as e:
            log.warning("teardown: %s", e)
        try:
            cleanup_tree_leftovers(tree_id)
        except Exception as e:
            log.warning("post-teardown leftover cleanup: %s", e)
        try:
            ensure_k7d_up()
        except Exception as e:
            log.error("failed to leave k7d running: %s", e)
            raise


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--tree-id", default="")
    return p.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    ns = parse_args(argv)
    tree_id = ns.tree_id or f"rh-35a-{os.getpid()}"
    if not tree_id.startswith("rh-35a-"):
        raise RuntimeError(f"tree_id must start with rh-35a-, got {tree_id}")
    run(tree_id)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
