#!/usr/bin/env python3
"""RL-shaped cluster tree search over k7d warm forks.

Not a training run. No GPU. Scripted actions + a trivial reward, to make
the unique claim visceral: fork a live multi-VM cluster, try N branches,
keep the winner, drop the losers — and print the fork wall-clock.

Modes:
  busybox   — TreeCreateCluster(3) on the daemon (fast; good for GIFs)
  inner-k3s — adopt the live 3-node inner-k3s pods (headline claim;
              requires RuntimeClass k7 + the pods from test_inner_k3s)

Usage (on a KVM node with k7d running):
  python3 run_demo.py --mode busybox
  python3 run_demo.py --mode inner-k3s --branches 4
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import time
from pathlib import Path

from k7d_client import K7dClient

REPO = Path(__file__).resolve().parents[2]
# Must match INNER3_PODS in crates/k7d/tests/test_inner_k3s.rs
INNER3_PODS = (
    "test-inner-k3s-3n-server",
    "test-inner-k3s-3n-agent-0",
    "test-inner-k3s-3n-agent-1",
)
INNER3_CERTS = Path("/tmp/k7-inner3-demo-certs")


def sh(cmd: list[str], *, check: bool = True, capture: bool = True) -> subprocess.CompletedProcess:
    return subprocess.run(cmd, check=check, capture_output=capture, text=True)


def list_bridges() -> set[str]:
    out = Path("/sys/class/net")
    return {p.name for p in out.iterdir() if p.name.startswith("k7-br-")}


def bridge_port_count(name: str) -> int:
    brif = Path(f"/sys/class/net/{name}/brif")
    if not brif.is_dir():
        return 0
    return sum(1 for _ in brif.iterdir())


def resolve_guest_paths() -> dict[str, str]:
    kernel = os.environ.get("K7D_KERNEL", str(REPO / "guest/kernel/vmlinux"))
    initrd = os.environ.get("K7D_INITRD", str(REPO / "guest/rootfs/initramfs.cpio.gz"))
    if not Path(kernel).is_file():
        raise SystemExit(f"guest kernel missing: {kernel}")
    if not Path(initrd).is_file():
        raise SystemExit(f"guest initrd missing: {initrd}")
    return {"kernel": kernel, "initrd": initrd}


def score_busybox(fork: dict) -> float:
    cids = fork.get("guest_cids") or []
    if len(cids) != 3:
        return 0.0
    if any(fork.get("fork_memory_full_copy") or []):
        return 0.0
    return 1.0


def curl_readyz(bridge: str, guest_ip: str = "10.200.0.2") -> bool:
    try:
        r = sh(
            [
                "curl",
                "-sk",
                "--max-time",
                "3",
                "--interface",
                bridge,
                f"https://{guest_ip}:6443/readyz",
            ],
            check=False,
        )
        return r.returncode == 0 and "ok" in (r.stdout or "")
    except OSError:
        return False


def extract_inner_certs() -> None:
    """Pull client cert/key from the inner server kubeconfig."""
    import base64
    import re

    raw = sh(
        [
            "kubectl",
            "exec",
            INNER3_PODS[0],
            "-c",
            "k3s",
            "--",
            "cat",
            "/etc/rancher/k3s/k3s.yaml",
        ]
    ).stdout
    # kubeconfig embeds base64 PEMs under client-certificate-data / client-key-data
    cert_b64 = re.search(r"client-certificate-data:\s*(\S+)", raw)
    key_b64 = re.search(r"client-key-data:\s*(\S+)", raw)
    if not cert_b64 or not key_b64:
        raise SystemExit("could not parse client cert/key from inner kubeconfig")
    INNER3_CERTS.mkdir(parents=True, exist_ok=True)
    (INNER3_CERTS / "client.pem").write_bytes(base64.b64decode(cert_b64.group(1)))
    (INNER3_CERTS / "client-key.pem").write_bytes(base64.b64decode(key_b64.group(1)))


def curl_inner_load(bridge: str, guest_ip: str = "10.200.0.2") -> bool:
    """inner-load Deployment readyReplicas ≥ 3 via apiserver on bridge."""
    try:
        r = sh(
            [
                "curl",
                "-sSk",
                "--max-time",
                "5",
                "--interface",
                bridge,
                "--cert",
                str(INNER3_CERTS / "client.pem"),
                "--key",
                str(INNER3_CERTS / "client-key.pem"),
                f"https://{guest_ip}:6443/apis/apps/v1/namespaces/default/deployments/inner-load",
            ],
            check=False,
        )
        if r.returncode != 0:
            return False
        body = json.loads(r.stdout or "{}")
        ready = int((body.get("status") or {}).get("readyReplicas") or 0)
        return ready >= 3
    except (OSError, json.JSONDecodeError, ValueError):
        return False


def discover_inner3_vm_ids(client: K7dClient) -> list[str]:
    """Resolve the three inner3 pods to daemon VM ids ordered by vm_index
    (same contract as `test_inner_k3s` / `TreeAdoptCluster`)."""
    indexed: list[tuple[int, str]] = []
    for pod in INNER3_PODS:
        cid = sh(["k3s", "crictl", "pods", "-q", "--name", pod], check=False)
        sandbox_id = (cid.stdout or "").strip().splitlines()
        if not sandbox_id:
            raise SystemExit(
                f"no CRI sandbox for pod {pod} (is it Running?): {cid.stderr}"
            )
        found = client.call({"op": "lookup_sandbox", "sandbox_id": sandbox_id[0]})
        if found.get("status") != "sandbox_found":
            raise SystemExit(f"lookup_sandbox({sandbox_id[0]}): {found}")
        vm_index = found.get("vm_index")
        if vm_index is None:
            raise SystemExit(f"pod {pod}: lookup_sandbox missing vm_index: {found}")
        indexed.append((int(vm_index), found["vm_id"]))
    indexed.sort(key=lambda t: t[0])
    for i, (idx, _) in enumerate(indexed):
        if idx != i:
            raise SystemExit(f"vm_index gap: expected {i}, got {idx} in {indexed}")
    return [vm_id for _, vm_id in indexed]


def ensure_inner3_ready() -> None:
    missing = []
    for pod in INNER3_PODS:
        phase = sh(
            ["kubectl", "get", "pod", pod, "-o", "jsonpath={.status.phase}"],
            check=False,
        )
        if (phase.stdout or "").strip() != "Running":
            missing.append(pod)
    if missing:
        raise SystemExit(
            "inner-k3s pods not Running: "
            f"{missing}. Bring them up (with nginx churn) and leave them:\n"
            "  cd /root/k7d && K7_KEEP_INNER3=1 cargo test -p k7d --test test_inner_k3s \\\n"
            "    test_inner_k3s_cluster_warm_fork_no_restart -- --test-threads=1 --nocapture\n"
            "(or re-run bring_up via that test without KEEP, then re-apply pods)."
        )


def run_busybox(client: K7dClient, branches: int, tree_id: str) -> None:
    paths = resolve_guest_paths()
    # root (3) + branches×3 + one rollback fork (3); leave headroom.
    live_vms = 3 * (branches + 2) + 16
    budget = {
        "max_live_vms": max(64, live_vms),
        "max_live_ram_bytes": 64 * 1024**3,
        "max_disk_bytes": 256 * 1024**3,
        "max_chain_depth": 32,
    }
    print(f"[demo] creating 3-VM cluster tree {tree_id!r} …")
    t0 = time.perf_counter()
    created = client.tree_create_cluster(
        3,
        {
            "kernel": paths["kernel"],
            "initrd": paths["initrd"],
            "memory_mb": 256,
            "vcpus": 1,
            "vsock": True,
        },
        tree_id=tree_id,
        budget=budget,
    )
    create_ms = (time.perf_counter() - t0) * 1000
    root_id = created["root_id"]
    print(
        f"[demo] tree_create_cluster ok in {create_ms:.1f} ms "
        f"(root={root_id}, cids={created.get('guest_cids')})"
    )

    labels = [f"branch-{i}" for i in range(branches)]
    bridges_before = list_bridges()
    print(f"[demo] tree_fork_batch n={branches} from {root_id} …")
    t1 = time.perf_counter()
    batch = client.tree_fork_batch(tree_id, root_id, labels)
    fork_ms = (time.perf_counter() - t1) * 1000
    forks = batch["forks"]
    print(f"[demo] tree_fork_batch wall-clock: {fork_ms:.1f} ms")
    for f in forks:
        full = f.get("fork_memory_full_copy") or []
        print(
            f"       - {f['node_id']}: cids={f.get('guest_cids')} "
            f"full_copy={full}"
        )
        if any(full):
            raise SystemExit("expected CoW forks (fork_memory_full_copy all false)")

    scores = [(score_busybox(f), f) for f in forks]
    scores.sort(key=lambda x: x[0], reverse=True)
    winner_score, winner = scores[0]
    print(f"[demo] winner={winner['node_id']} reward={winner_score}")
    client.tree_protect(tree_id, winner["node_id"])

    # Non-destructive rollback from root (= another fork) as the "continue
    # from checkpoint" RL step.
    rolled = client.tree_rollback(tree_id, root_id, "continue")
    print(f"[demo] rollback(from root) → {rolled['node_id']}")

    for _, f in scores[1:]:
        client.tree_prune(tree_id, f["node_id"])
        print(f"[demo] pruned loser {f['node_id']}")

    new_bridges = [b for b in list_bridges() - bridges_before if bridge_port_count(b) == 3]
    print(f"[demo] new 3-port bridges: {new_bridges}")
    print(f"[demo] DONE — fork batch {fork_ms:.1f} ms for {branches}×3-VM clusters")


def run_inner_k3s(client: K7dClient, branches: int, tree_id: str) -> None:
    ensure_inner3_ready()
    vm_ids = discover_inner3_vm_ids(client)
    print(f"[demo] adopting inner3 vm_ids={vm_ids}")
    source_bridge = "k7-br-inner3"
    if source_bridge not in list_bridges():
        raise SystemExit(f"missing source bridge {source_bridge}")

    live_vms = 3 * (branches + 2) + 16
    budget = {
        "max_live_vms": max(64, live_vms),
        "max_live_ram_bytes": 256 * 1024**3,
        "max_disk_bytes": 512 * 1024**3,
        "max_chain_depth": 32,
    }
    bridges_before = list_bridges()
    adopted = client.tree_adopt_cluster(vm_ids, tree_id=tree_id, budget=budget)
    root_id = adopted["root_id"]
    print(f"[demo] adopted tree={tree_id} root={root_id} cids={adopted.get('guest_cids')}")

    # Wait for source /readyz after prepare.
    deadline = time.time() + 120
    while time.time() < deadline:
        if curl_readyz(source_bridge):
            break
        time.sleep(1)
    else:
        raise SystemExit("source /readyz never recovered after adopt")

    extract_inner_certs()

    labels = [f"cand-{i}" for i in range(branches)]
    print(f"[demo] tree_fork_batch n={branches} (headline path) …")
    t1 = time.perf_counter()
    batch = client.tree_fork_batch(tree_id, root_id, labels)
    fork_ms = (time.perf_counter() - t1) * 1000
    forks = batch["forks"]
    print(f"[demo] tree_fork_batch wall-clock: {fork_ms:.1f} ms  (budget 1000 ms)")
    if fork_ms > 1000:
        print("[demo] WARNING: exceeded 1 s enforced budget (loaded host?)")

    # Map each fork node → its 3-port bridge (appeared during the batch).
    # Reward = readyz + inner-load Deployment still Ready.
    scored: list[tuple[float, dict, str]] = []
    for f in forks:
        if any(f.get("fork_memory_full_copy") or []):
            raise SystemExit(f"{f['node_id']}: expected CoW, got full_copy")
        candidates = [
            b
            for b in list_bridges() - bridges_before
            if bridge_port_count(b) == 3 and all(b != s[2] for s in scored)
        ]
        bridge = candidates[0] if candidates else ""
        ready = bool(bridge) and curl_readyz(bridge)
        load_ok = bool(bridge) and curl_inner_load(bridge)
        reward = (0.5 if ready else 0.0) + (0.5 if load_ok else 0.0)
        print(
            f"       - {f['node_id']}: bridge={bridge or '?'} "
            f"readyz={'ok' if ready else 'FAIL'} inner-load={'ok' if load_ok else 'FAIL'} "
            f"reward={reward}"
        )
        scored.append((reward, f, bridge))

    scored.sort(key=lambda x: x[0], reverse=True)
    winner_score, winner, winner_bridge = scored[0]
    print(f"[demo] winner={winner['node_id']} bridge={winner_bridge} reward={winner_score}")
    client.tree_protect(tree_id, winner["node_id"])
    for _, f, _ in scored[1:]:
        client.tree_prune(tree_id, f["node_id"])
        print(f"[demo] pruned loser {f['node_id']}")

    # Source must still answer (CID-stable prepare, surviving control plane).
    if not curl_readyz(source_bridge):
        raise SystemExit("source cluster /readyz failed after fork batch")
    if not curl_inner_load(source_bridge):
        raise SystemExit("source inner-load Deployment not Ready after fork batch")
    print(f"[demo] source still Ready + inner-load on {source_bridge}")
    print(f"[demo] DONE — inner-k3s fork batch {fork_ms:.1f} ms for {branches} branches")


def raise_nofile(min_fds: int = 65536) -> None:
    """Bump soft RLIMIT_NOFILE for large --branches batches (EMFILE otherwise)."""
    try:
        import resource

        soft, hard = resource.getrlimit(resource.RLIMIT_NOFILE)
        want = min(max(min_fds, soft), hard)
        if want > soft:
            resource.setrlimit(resource.RLIMIT_NOFILE, (want, hard))
            print(f"[demo] raised RLIMIT_NOFILE soft {soft} → {want} (hard={hard})")
    except (ValueError, OSError) as e:
        print(f"[demo] warn: could not raise RLIMIT_NOFILE: {e}", file=sys.stderr)


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument(
        "--mode",
        choices=("busybox", "inner-k3s"),
        default="busybox",
        help="busybox = fast TreeCreateCluster demo; inner-k3s = headline claim",
    )
    ap.add_argument("--branches", type=int, default=4)
    ap.add_argument(
        "--tree-id",
        default=None,
        help="tree id (default: cts-<pid>)",
    )
    ap.add_argument(
        "--keep",
        action="store_true",
        help="do not TreeDrop at the end (inspect with tree_nodes)",
    )
    args = ap.parse_args()
    if args.branches < 1:
        raise SystemExit("--branches must be >= 1")

    tree_id = args.tree_id or f"cts-{os.getpid()}"
    # Daemon already has LimitNOFILE=524288; the demo process itself only
    # holds the control socket — raise anyway so local helpers (bridge
    # enumeration) don't surprise on busy hosts.
    raise_nofile(65536)
    client = K7dClient()
    pong = client.ping()
    print(f"[demo] k7d {pong.get('version')} at {client.path}")

    try:
        if args.mode == "busybox":
            run_busybox(client, args.branches, tree_id)
        else:
            run_inner_k3s(client, args.branches, tree_id)
    finally:
        if not args.keep:
            try:
                client.tree_drop(tree_id)
                print(f"[demo] tree_drop {tree_id}")
            except RuntimeError as e:
                print(f"[demo] tree_drop: {e}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
