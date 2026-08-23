"""Ubuntu 3-node Cilium+Tetragon source. Reuses gym/ubuntu.py; no busybox."""

from __future__ import annotations

import logging
import os
import subprocess
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

log = logging.getLogger("k7d-mcp.cluster")

HERE = Path(__file__).resolve().parent
REPO = HERE.parents[1]

import sys

sys.path.insert(0, str(REPO / "gym"))
sys.path.insert(0, str(REPO / "examples" / "cluster-tree-search"))

import agent  # noqa: E402
import ubuntu as ubuntu_src  # noqa: E402
from budget import tree_budget  # noqa: E402
from host import k7_bridge_name, list_bridges  # noqa: E402
from k7d_client import K7dClient  # noqa: E402

HELM_VERSION = "v3.16.4"
HELM_BIN = Path(f"/usr/local/lib/k7d-helm/{HELM_VERSION}/helm")
CILIUM_CHART = "1.16.10"
TETRAGON_CHART = "1.7.0"
CILIUM_NS = "kube-system"
NATIVE_CIDR = "10.244.0.0/16"
HELM_READY_S = 600
VICTIM_NAME = "k7-victim"

# Source (3) + 6 hypotheses (18) — the demo pressure. Smoke uses n=2.
DEFAULT_BUDGET = tree_budget(
    max_live_vms=24,
    max_live_ram_bytes=64 * 1024**3,
    max_disk_bytes=256 * 1024**3,
    max_chain_depth=32,
)


@dataclass
class Cluster:
    tree_id: str
    root_id: str
    guest_cids: list[int]
    bridge: str
    kubeconfig: Path
    certs_dir: Path
    disks: list[Path]
    vm_ids: list[str]
    server_ip: str
    bring_ms: float = 0.0
    cilium_ms: float = 0.0
    tetragon_ms: float = 0.0
    extra: dict[str, Any] = field(default_factory=dict)


def ensure_helm() -> Path:
    if HELM_BIN.is_file():
        return HELM_BIN
    raise RuntimeError(
        f"pinned helm {HELM_VERSION} missing at {HELM_BIN} "
        "(25a-inc3 installs it at /usr/local/lib/k7d-helm/)"
    )


def kubectl(kube: Path, args: list[str], *, timeout_s: float = 60) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["kubectl", "--kubeconfig", str(kube), *args],
        check=False,
        capture_output=True,
        text=True,
        timeout=timeout_s,
    )


def helm_install_cilium(helm: Path, kube: Path, server_ip: str) -> None:
    ns = kubectl(kube, ["get", "ns", CILIUM_NS, "-o", "jsonpath={.metadata.name}"])
    if (ns.stdout or "").strip() != CILIUM_NS:
        raise RuntimeError(f"kube-system missing before cilium helm: {ns.stderr}")
    already = kubectl(kube, ["-n", CILIUM_NS, "get", "ds", "cilium"])
    if already.returncode == 0:
        log.info("cilium already installed; skipping helm install")
        return
    r = subprocess.run(
        [
            str(helm),
            "install",
            "cilium",
            "cilium",
            "--version",
            CILIUM_CHART,
            "--repo",
            "https://helm.cilium.io/",
            "--namespace",
            CILIUM_NS,
            "--kubeconfig",
            str(kube),
            "--set",
            "operator.replicas=1",
            "--set",
            "routingMode=native",
            "--set",
            f"ipv4NativeRoutingCIDR={NATIVE_CIDR}",
            "--set",
            "autoDirectNodeRoutes=true",
            "--set",
            "kubeProxyReplacement=true",
            "--set",
            "endpointRoutes.enabled=true",
            "--set",
            "bpf.hostLegacyRouting=true",
            "--set",
            "l2NeighDiscovery.enabled=false",
            "--set",
            "ipam.mode=kubernetes",
            "--set",
            "k8s.requireIPv4PodCIDR=true",
            "--set",
            f"k8sServiceHost={server_ip}",
            "--set",
            "k8sServicePort=6443",
        ],
        check=False,
        capture_output=True,
        text=True,
    )
    if r.returncode != 0:
        raise RuntimeError(
            f"helm install cilium {CILIUM_CHART} failed:\n{r.stderr}\n{r.stdout}"
        )
    log.info("helm: installed cilium %s", CILIUM_CHART)


def helm_install_tetragon(helm: Path, kube: Path) -> None:
    already = kubectl(kube, ["-n", CILIUM_NS, "get", "ds", "tetragon"])
    if already.returncode == 0:
        log.info("tetragon already installed; skipping helm install")
        return
    r = subprocess.run(
        [
            str(helm),
            "install",
            "tetragon",
            "tetragon",
            "--version",
            TETRAGON_CHART,
            "--repo",
            "https://helm.cilium.io/",
            "--namespace",
            CILIUM_NS,
            "--kubeconfig",
            str(kube),
            "--set",
            "tetragonOperator.replicas=1",
            "--set",
            "crds.installMethod=helm",
        ],
        check=False,
        capture_output=True,
        text=True,
    )
    if r.returncode != 0:
        raise RuntimeError(
            f"helm install tetragon {TETRAGON_CHART} failed:\n{r.stderr}\n{r.stdout}"
        )
    log.info("helm: installed tetragon %s", TETRAGON_CHART)


def _wait_ready(kube: Path, kind: str, name: str, field: str, want: int, ceiling_s: float) -> float:
    deadline = time.monotonic() + ceiling_s
    last = ""
    t0 = time.perf_counter()
    while time.monotonic() < deadline:
        r = kubectl(
            kube,
            ["-n", CILIUM_NS, "get", kind, name, f"-o=jsonpath={{.status.{field}}}"],
        )
        last = (r.stdout or "").strip()
        try:
            got = int(last)
        except ValueError:
            got = 0
        if got >= want:
            return (time.perf_counter() - t0) * 1000.0
        time.sleep(5)
    raise RuntimeError(
        f"{name} never Ready ({field}={last!r} want>={want}) after {ceiling_s}s"
    )


def wait_cilium_ready(kube: Path, ceiling_s: float = HELM_READY_S) -> float:
    _wait_ready(kube, "ds", "cilium", "numberReady", 3, ceiling_s)
    return _wait_ready(kube, "deploy", "cilium-operator", "readyReplicas", 1, ceiling_s)


def wait_tetragon_ready(kube: Path, ceiling_s: float = HELM_READY_S) -> float:
    _wait_ready(kube, "ds", "tetragon", "numberReady", 3, ceiling_s)
    return _wait_ready(kube, "deploy", "tetragon-operator", "readyReplicas", 1, ceiling_s)


def deploy_victim(kube: Path) -> None:
    yaml = f"""apiVersion: apps/v1
kind: Deployment
metadata:
  name: {VICTIM_NAME}
  namespace: default
spec:
  replicas: 2
  selector:
    matchLabels:
      app: {VICTIM_NAME}
  template:
    metadata:
      labels:
        app: {VICTIM_NAME}
    spec:
      containers:
      - name: victim
        image: docker.io/library/nginx:1.27-alpine
        ports:
        - containerPort: 80
---
apiVersion: v1
kind: Service
metadata:
  name: {VICTIM_NAME}
  namespace: default
spec:
  selector:
    app: {VICTIM_NAME}
  ports:
  - port: 80
    targetPort: 80
"""
    r = subprocess.run(
        ["kubectl", "--kubeconfig", str(kube), "apply", "-f", "-"],
        input=yaml,
        check=False,
        capture_output=True,
        text=True,
    )
    if r.returncode != 0:
        raise RuntimeError(f"victim apply failed: {r.stderr}\n{r.stdout}")
    deadline = time.monotonic() + 180
    while time.monotonic() < deadline:
        s = kubectl(
            kube,
            [
                "-n",
                "default",
                "get",
                "deploy",
                VICTIM_NAME,
                "-o",
                "jsonpath={.status.readyReplicas}",
            ],
        )
        if (s.stdout or "").strip() == "2":
            log.info("victim %s Ready 2/2", VICTIM_NAME)
            return
        time.sleep(3)
    raise RuntimeError(f"victim {VICTIM_NAME} never 2/2 Ready")


def victim_healthy(kube: Path) -> bool:
    s = kubectl(
        kube,
        [
            "-n",
            "default",
            "get",
            "deploy",
            VICTIM_NAME,
            "-o",
            "jsonpath={.status.readyReplicas}",
        ],
        timeout_s=20,
    )
    return (s.stdout or "").strip() == "2"


def bring_up(
    client: K7dClient,
    *,
    tree_id: str,
    repo: Path = REPO,
    budget: dict[str, int] | None = None,
    memory_mb: int = ubuntu_src.NODE_MEMORY_MB,
    install_cni: bool = True,
    install_tetragon: bool = True,
    victim: bool = True,
) -> Cluster:
    """CreateVm × 3 (Ubuntu, k7d.cni=none) + adopt + protect + Cilium + Tetragon.

    Never `tree_create_cluster` and never `K7D_KERNEL`/`K7D_INITRD`.
    """
    t0 = time.perf_counter()
    budget = budget or DEFAULT_BUDGET
    floor = ubuntu_src.memory_floor_error(memory_mb)
    if floor:
        raise RuntimeError(floor)
    manifest = ubuntu_src.build_or_cache_image(repo)
    kernel = Path(str(manifest["kernel"]))
    base = Path(str(manifest["image"]))
    if "initramfs" in str(kernel) or kernel.name == "vmlinux":
        raise RuntimeError(
            f"ubuntu source refused busybox guest path {kernel} "
            "(CHALLENGES #72: never K7D_KERNEL/K7D_INITRD)"
        )
    server_ip = ubuntu_src.guest_ip(0)
    created_ids: list[str] = []
    disks: list[Path] = []
    cids: list[int] = []
    before = list_bridges()
    try:
        for idx, role in enumerate(("server", "agent", "agent")):
            dest = ubuntu_src.DISKS_DIR / (
                f"ubuntu-mcp-{tree_id}-{idx}-{os.getpid()}.img"
            )
            ubuntu_src.reflink_disk(base, dest)
            disks.append(dest)
            ip = ubuntu_src.guest_ip(idx)
            cmdline = ubuntu_src.node_cmdline(
                ip, ubuntu_src.k3s_spec(role, server_ip), cni="none"
            )
            cfg = {
                "kernel": str(kernel),
                "memory_mb": memory_mb,
                "vcpus": ubuntu_src.NODE_VCPUS,
                "vsock": True,
                "cmdline": cmdline,
                "block_devices": [{"host_path": str(dest), "readonly": False}],
                "network": {
                    "cluster_id": tree_id,
                    "vm_index": idx,
                    "pod_netns": None,
                },
            }
            log.info("CreateVm ubuntu %s vm_index=%s ip=%s", role, idx, ip)
            resp = client.create_vm(cfg, timeout=180)
            if resp.get("status") != "vm_created":
                raise RuntimeError(f"create_vm ubuntu {role}/{idx}: {resp}")
            created_ids.append(resp["vm_id"])
            cid = int(resp["guest_cid"])
            cids.append(cid)

            def _dump(c: int = cid) -> str:
                try:
                    return str(client.dump_serial(guest_cid=c).get("console") or "")
                except RuntimeError as e:
                    return f"dump_serial cid={c}: {e}"

            ubuntu_src.wait_agent(cid, ubuntu_src.BOOT_TO_AGENT_S, dump=_dump)
            ubuntu_src.wait_systemd_healthy(cid)
            if idx == 0:
                ubuntu_src.wait_guest_readyz(cid, ubuntu_src.CLUSTER_READY_S)
                dest_dir = ubuntu_src.certs_dir(tree_id)
                ubuntu_src.write_host_kubeconfig(cid, server_ip, dest_dir)
            else:
                ubuntu_src.wait_unit_active(cid, "k3s-agent.service")
        dest_dir = ubuntu_src.certs_dir(tree_id)
        kube = dest_dir / "kubeconfig"
        # cni=none: Ready is a CNI assertion. Register first, Cilium later.
        ubuntu_src.wait_nodes_present(
            kube, ubuntu_src.node_names(server_ip), ubuntu_src.CLUSTER_READY_S
        )
        adopted = client.tree_adopt_cluster(
            created_ids, tree_id=tree_id, budget=budget
        )
        root_id = adopted["root_id"]
        cids = [int(c) for c in adopted.get("guest_cids") or cids]
        after = list_bridges() - before
        expected = k7_bridge_name(tree_id)
        if expected in list_bridges():
            bridge = expected
        elif len(after) == 1:
            bridge = after.pop()
        else:
            raise RuntimeError(f"could not identify source bridge (new={sorted(after)})")
        client.tree_protect(tree_id, root_id)
        for cid in cids:
            r = agent.exec_cmd(cid, ["ip", "link", "set", "eth0", "up"], timeout_s=8)
            if r["exit_code"] != 0:
                raise RuntimeError(f"cid={cid} eth0 up failed: {r}")
        ubuntu_src.persist_meta(
            dest_dir,
            {
                "guest_cids": cids,
                "bridge": bridge,
                "vm_ids": created_ids,
                "disks": [str(p) for p in disks],
            },
        )
        bring_ms = (time.perf_counter() - t0) * 1000.0
        cilium_ms = 0.0
        tetragon_ms = 0.0
        if install_cni:
            helm = ensure_helm()
            t_c = time.perf_counter()
            helm_install_cilium(helm, kube, server_ip)
            wait_cilium_ready(kube)
            ubuntu_src.wait_nodes_ready(
                kube, ubuntu_src.node_names(server_ip), 180
            )
            cilium_ms = (time.perf_counter() - t_c) * 1000.0
            if install_tetragon:
                t_t = time.perf_counter()
                helm_install_tetragon(helm, kube)
                wait_tetragon_ready(kube)
                tetragon_ms = (time.perf_counter() - t_t) * 1000.0
        if victim:
            deploy_victim(kube)
        log.info(
            "ubuntu source ready tree=%s bring=%.0fms cilium=%.0fms tetra=%.0fms",
            tree_id,
            bring_ms,
            cilium_ms,
            tetragon_ms,
        )
        print(
            f"MEASUREMENT ubuntu source bring-up: {bring_ms:.0f} ms "
            f"(cilium {cilium_ms:.0f} ms tetragon {tetragon_ms:.0f} ms)",
            flush=True,
        )
        return Cluster(
            tree_id=tree_id,
            root_id=root_id,
            guest_cids=cids,
            bridge=bridge,
            kubeconfig=kube,
            certs_dir=dest_dir,
            disks=disks,
            vm_ids=created_ids,
            server_ip=server_ip,
            bring_ms=bring_ms,
            cilium_ms=cilium_ms,
            tetragon_ms=tetragon_ms,
        )
    except Exception:
        for vm_id in created_ids:
            try:
                client.stop_vm(vm_id)
            except RuntimeError as e:
                log.warning("teardown stop_vm %s: %s", vm_id, e)
        ubuntu_src.remove_disks(disks)
        raise


def teardown(client: K7dClient, cluster: Cluster) -> dict[str, Any]:
    """Prune root + drop tree + unlink disks. Always run from finally."""
    errors: list[str] = []
    try:
        client.tree_unprotect(cluster.tree_id, cluster.root_id)
    except RuntimeError as e:
        errors.append(f"unprotect: {e}")
    try:
        client.tree_prune(cluster.tree_id, cluster.root_id)
    except RuntimeError as e:
        errors.append(f"prune: {e}")
    try:
        client.tree_drop(cluster.tree_id)
    except RuntimeError as e:
        errors.append(f"drop: {e}")
    ubuntu_src.remove_disks(cluster.disks)
    try:
        import shutil

        shutil.rmtree(cluster.certs_dir, ignore_errors=True)
    except OSError as e:
        errors.append(f"certs: {e}")
    leftover_nodes: list[str] = []
    try:
        leftover_nodes = [
            n["id"] for n in (client.tree_nodes(cluster.tree_id).get("nodes") or [])
        ]
    except RuntimeError:
        leftover_nodes = []
    expected = k7_bridge_name(cluster.tree_id)
    leftover_bridges = [
        b for b in list_bridges() if b in {cluster.bridge, expected}
    ]
    residue = {
        "bridges": leftover_bridges,
        "tree_node_ids": leftover_nodes,
        "errors": errors,
    }
    if leftover_nodes or leftover_bridges or errors:
        log.warning("teardown residue: %s", residue)
    return residue
