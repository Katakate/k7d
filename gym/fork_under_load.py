#!/usr/bin/env python3
"""28a: fork-under-load correctness + usage sampling. Ubuntu only.

Talks to `/run/k7d/k7d.sock`. Never boots Vm in-process, never
tree_create_cluster / INNER3 / K7D_KERNEL. Zero new k7d primitives.
"""

from __future__ import annotations

import argparse
import hashlib
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

import agent  # noqa: E402
import ubuntu as ubuntu_src  # noqa: E402
from host import k7_bridge_name, list_bridges  # noqa: E402
from k7d_client import K7dClient  # noqa: E402
from plots.divergence import (  # noqa: E402
    derive,
    render_sibling_svg,
    render_svg,
    summarize,
    summarize_siblings,
)  # noqa: E402

log = logging.getLogger("ful")

CHURN_PAUSE = "docker.io/rancher/mirrored-pause:3.6"
KAFKA_IMAGE = "docker.io/apache/kafka:3.8.1"
KAFKA_HEAP = "-Xmx256m -Xms256m"
SAMPLE_S_DEFAULT = 30.0
INTERVAL_S_DEFAULT = 2.0
SIBLING_N = 3
PAGE = 4096


def _budget() -> dict[str, int]:
    # 3 source + 3 siblings + 3 probe = 15 live at the densest sample.
    # Headroom so LRU evict cannot suspend a sibling mid-window.
    return {
        "max_live_vms": 24,
        "max_live_ram_bytes": 64 * 1024**3,
        "max_disk_bytes": 64 * 1024**3,
        "max_chain_depth": 8,
    }


def guest_sh(cid: int, script: str, timeout_s: float = 30) -> dict[str, Any]:
    r = agent.exec_cmd(cid, ["sh", "-c", script], timeout_s=timeout_s)
    if r["exit_code"] != 0:
        raise RuntimeError(
            f"cid={cid} exit={r['exit_code']} stderr={r['stderr']!r} "
            f"stdout={r['stdout'][-400:]!r}"
        )
    return r


def guest_kubectl(cid: int, args: list[str], timeout_s: float = 60) -> str:
    r = agent.exec_cmd(cid, ["k3s", "kubectl", *args], timeout_s=timeout_s)
    if r["exit_code"] != 0:
        raise RuntimeError(
            f"kubectl {args} cid={cid} exit={r['exit_code']} "
            f"stderr={r['stderr']!r} stdout={r['stdout'][-400:]!r}"
        )
    return r["stdout"]


def apply_yaml(cid: int, yaml: str, name: str) -> None:
    path = f"/tmp/k7-ful-{name}.yaml"
    agent.write_file(cid, path, yaml.encode())
    guest_kubectl(cid, ["apply", "-f", path], timeout_s=90)


def snapshot_usage(client: K7dClient, tree_id: str) -> dict[str, Any]:
    resp = client.tree_nodes(tree_id)
    usage = resp.get("usage") or {}
    if "live_ram_bytes" not in usage:
        raise RuntimeError(f"tree_nodes missing usage.live_ram_bytes: {resp}")
    derived = derive(usage, ubuntu_src.NODE_MEMORY_MB)
    nodes = []
    for n in resp.get("nodes") or []:
        dirty = int(n.get("dirty_page_count") or 0)
        nodes.append(
            {
                "id": n.get("id"),
                "state": n.get("state"),
                "vm_count": n.get("vm_count"),
                "dirty_page_count": dirty,
                "dirty_bytes_stale": dirty * PAGE,
            }
        )
    return {
        "ts": time.time(),
        "usage": usage,
        "nodes": nodes,
        "live_guest_cids": resp.get("live_guest_cids") or {},
        **derived,
    }


class Cluster:
    """One adopted Ubuntu 3-node tree. Teardown is loud and complete."""

    def __init__(self, client: K7dClient, tree_id: str) -> None:
        self.client = client
        self.tree_id = tree_id
        self.vm_ids: list[str] = []
        self.disks: list[Path] = []
        self.cids: list[int] = []
        self.bridge = ""
        self.root_id = "root"
        self.server_cid = 0
        # Filled in by `bring_up`: the root's own keyframe, which is
        # always a full dump because root has no ancestor to clone.
        self.adopt_prepare_s = 0.0

    def bring_up(self, *, prepare: bool = True) -> None:
        t0 = time.perf_counter()
        manifest = ubuntu_src.build_or_cache_image(REPO)
        kernel = Path(str(manifest["kernel"]))
        base = Path(str(manifest["image"]))
        if "initramfs" in str(kernel) or kernel.name == "vmlinux":
            raise RuntimeError(
                f"refusing busybox guest {kernel} (CHALLENGES #72)"
            )
        server_ip = ubuntu_src.guest_ip(0)
        before = list_bridges()
        try:
            for idx, role in enumerate(("server", "agent", "agent")):
                dest = ubuntu_src.DISKS_DIR / (
                    f"ubuntu-ful-{self.tree_id}-{idx}-{os.getpid()}.img"
                )
                ubuntu_src.reflink_disk(base, dest)
                self.disks.append(dest)
                ip = ubuntu_src.guest_ip(idx)
                cmdline = ubuntu_src.node_cmdline(
                    ip, ubuntu_src.k3s_spec(role, server_ip)
                )
                cfg = {
                    "kernel": str(kernel),
                    "memory_mb": ubuntu_src.NODE_MEMORY_MB,
                    "vcpus": ubuntu_src.NODE_VCPUS,
                    "vsock": True,
                    "cmdline": cmdline,
                    "block_devices": [{"host_path": str(dest), "readonly": False}],
                    "network": {
                        "cluster_id": self.tree_id,
                        "vm_index": idx,
                        "pod_netns": None,
                    },
                }
                log.info("CreateVm %s idx=%s ip=%s", role, idx, ip)
                resp = self.client.create_vm(cfg, timeout=180)
                if resp.get("status") != "vm_created":
                    raise RuntimeError(f"create_vm {role}/{idx}: {resp}")
                self.vm_ids.append(resp["vm_id"])
                cid = int(resp["guest_cid"])
                self.cids.append(cid)

                def _dump(c: int = cid) -> str:
                    try:
                        return str(self.client.dump_serial(guest_cid=c))
                    except RuntimeError as e:
                        return f"dump_serial: {e}"

                ubuntu_src.wait_agent(cid, ubuntu_src.BOOT_TO_AGENT_S, dump=_dump)
                ubuntu_src.wait_systemd_healthy(cid)
                if idx == 0:
                    ubuntu_src.wait_guest_readyz(cid, ubuntu_src.CLUSTER_READY_S)
                    dest_dir = ubuntu_src.certs_dir(self.tree_id)
                    ubuntu_src.write_host_kubeconfig(cid, server_ip, dest_dir)
                else:
                    ubuntu_src.wait_unit_active(cid, "k3s-agent.service")
            names = ubuntu_src.node_names(server_ip)
            kube = ubuntu_src.certs_dir(self.tree_id) / "kubeconfig"
            ubuntu_src.wait_nodes_ready(kube, names, ubuntu_src.CLUSTER_READY_S)
            t_adopt = time.perf_counter()
            adopted = self.client.tree_adopt_cluster(
                self.vm_ids, tree_id=self.tree_id, budget=_budget()
            )
            self.adopt_prepare_s = time.perf_counter() - t_adopt
            print(
                f"FUL_MEASURE adopt_prepare_s={time.perf_counter() - t_adopt:.3f} "
                f"tree={self.tree_id} (new_cluster writes memory.bin)",
                flush=True,
            )
            self.root_id = adopted["root_id"]
            self.cids = [int(c) for c in adopted.get("guest_cids") or self.cids]
            self.server_cid = self.cids[0]
            new = list_bridges() - before
            self.bridge = sorted(new)[0] if new else k7_bridge_name(self.tree_id)
            self.client.tree_protect(self.tree_id, self.root_id)
            if prepare:
                self.client.tree_prepare_fork_source(self.tree_id, self.root_id)
        except Exception:
            self.teardown()
            raise
        log.info(
            "source ready in %.1fs tree=%s bridge=%s cids=%s",
            time.perf_counter() - t0,
            self.tree_id,
            self.bridge,
            self.cids,
        )
        print(
            f"FUL_MEASURE source_bring_up_s={time.perf_counter() - t0:.1f} "
            f"tree={self.tree_id} bridge={self.bridge}",
            flush=True,
        )

    def teardown(self) -> None:
        try:
            self.client.tree_prune(self.tree_id, "root")
        except RuntimeError as e:
            log.warning("prune root: %s", e)
        try:
            self.client.tree_drop(self.tree_id)
        except RuntimeError as e:
            log.warning("drop: %s", e)
        for vm_id in self.vm_ids:
            try:
                self.client.stop_vm(vm_id)
            except RuntimeError as e:
                log.warning("stop_vm %s: %s", vm_id, e)
        ubuntu_src.remove_disks(self.disks)

    def fork_many(
        self, labels: list[str], *, wait_agent: bool = True
    ) -> list[dict[str, Any]]:
        if not labels:
            raise RuntimeError("fork_many: labels must be non-empty")
        before = list_bridges()
        t0 = time.perf_counter()
        batch = self.client.tree_fork_batch(
            self.tree_id, self.root_id, labels, timeout=180
        )
        ms = (time.perf_counter() - t0) * 1000.0
        forks = list(batch.get("forks") or [])
        if len(forks) != len(labels):
            raise RuntimeError(f"expected {len(labels)} forks, got {forks}")
        out: list[dict[str, Any]] = []
        for label, fr in zip(labels, forks):
            nid = fr["node_id"]
            cids = [int(c) for c in fr.get("guest_cids") or []]
            if not cids:
                raise RuntimeError(f"fork {nid} missing guest_cids: {fr}")
            cluster_id = f"{self.tree_id}-{nid}"
            bridge = k7_bridge_name(cluster_id)
            visible = list_bridges()
            if bridge not in visible:
                raise RuntimeError(
                    f"fork bridge {bridge} not on host "
                    f"(new={sorted(visible - before)} all={sorted(visible)})"
                )
            if wait_agent:
                for i, cid in enumerate(cids):
                    if not agent.ping(cid, timeout_s=8):
                        raise RuntimeError(
                            f"fork {nid} member {i} cid={cid} vsock dead"
                        )
            print(
                f"FUL_MEASURE fork_{label}_ms={ms:.1f} node={nid} "
                f"bridge={bridge} cids={cids} latency_ns={fr.get('latency_ns')}",
                flush=True,
            )
            out.append(
                {
                    "node_id": nid,
                    "guest_cids": cids,
                    "bridge": bridge,
                    "server_cid": cids[0],
                    "fork_ms": ms,
                    "full_copy": fr.get("fork_memory_full_copy") or [],
                }
            )
        return out

    def fork_one(self, label: str, *, wait_agent: bool = True) -> dict[str, Any]:
        return self.fork_many([label], wait_agent=wait_agent)[0]

    def prune_child(self, node_id: str) -> None:
        self.client.tree_prune(self.tree_id, node_id)


def sample_window(
    client: K7dClient,
    tree_id: str,
    *,
    workload: str,
    phase: str,
    seconds: float,
    interval: float,
    sink: list[dict[str, Any]],
) -> None:
    deadline = time.monotonic() + seconds
    while True:
        rec = snapshot_usage(client, tree_id)
        rec["workload"] = workload
        rec["phase"] = phase
        sink.append(rec)
        if time.monotonic() >= deadline:
            break
        time.sleep(interval)


def node_dirty_pages(client: K7dClient, tree_id: str, node_id: str) -> int:
    resp = client.tree_nodes(tree_id)
    for n in resp.get("nodes") or []:
        if n.get("id") == node_id:
            return int(n.get("dirty_page_count") or 0)
    raise RuntimeError(f"node {node_id} missing from tree_nodes")


def probe_parent_dirty(cluster: Cluster, label: str) -> tuple[int, str]:
    """Flush the source bitmap via a throwaway fork, then suspend the probe.

    Root is the checkpoint: suspend+resume of root skips `delta.pack`
    (nearest_checkpoint == self) and rewinds to `memory.bin`. A child
    probe is the freeze-legal way to persist the source popcount.
    Do not wait for vsock — suspend does not need the agent, and the
    probe's own brief life would add self-dirt to the sample.
    """
    probe = cluster.fork_one(label, wait_agent=False)
    nid = probe["node_id"]
    try:
        cluster.client.tree_suspend(cluster.tree_id, nid)
        return node_dirty_pages(cluster.client, cluster.tree_id, nid), nid
    finally:
        cluster.prune_child(nid)


def run_sibling_divergence(
    cluster: Cluster,
    samples: list[dict[str, Any]],
    *,
    workload: str,
    sample_s: float,
    exclusive: Any | None = None,
    quiet_child: Any | None = None,
) -> None:
    """Third clock: parent vs child dirty vs the same `memory.bin`.

    One suspend per sibling (resume of a non-checkpoint applies only
    that node's current delta onto the ancestor `memory.bin`; a second
    suspend would persist increment-only dirt and the next resume
    would drop the first generation). A cohort forked together and
    suspended at staggered times is the over-time series.
    """
    labels = [f"{workload}-sib-{i}" for i in range(SIBLING_N)]
    children = cluster.fork_many(labels)
    if quiet_child is not None:
        for ch in children:
            try:
                quiet_child(ch["server_cid"])
            except RuntimeError as e:
                log.warning("quiet child %s: %s", ch["node_id"], e)
    t0 = time.time()
    if SIBLING_N == 1:
        gaps = [0.0]
    else:
        step = sample_s / (SIBLING_N - 1)
        gaps = [i * step for i in range(SIBLING_N)]
    try:
        for i, ch in enumerate(children):
            target = t0 + gaps[i]
            while time.time() < target:
                if exclusive is not None:
                    try:
                        exclusive()
                    except RuntimeError as e:
                        log.warning("exclusive load: %s", e)
                remain = target - time.time()
                if remain > 0:
                    time.sleep(min(1.0, remain))
            parent_pages, probe_id = probe_parent_dirty(
                cluster, f"{workload}-probe-{i}"
            )
            cluster.client.tree_suspend(cluster.tree_id, ch["node_id"])
            child_pages = node_dirty_pages(
                cluster.client, cluster.tree_id, ch["node_id"]
            )
            rec = snapshot_usage(cluster.client, cluster.tree_id)
            rec.update(
                {
                    "workload": workload,
                    "phase": "sibling_div",
                    "parent_dirty_pages": parent_pages,
                    "child_dirty_pages": child_pages,
                    "parent_dirty_bytes": parent_pages * PAGE,
                    "child_dirty_bytes": child_pages * PAGE,
                    "sibling_index": i,
                    "t_after_fork_s": time.time() - t0,
                    "probe_node_id": probe_id,
                    "child_node_id": ch["node_id"],
                }
            )
            samples.append(rec)
            print(
                f"FUL_MEASURE sibling {workload} i={i} "
                f"t={rec['t_after_fork_s']:.1f}s "
                f"parent_mib={parent_pages * PAGE / 1024**2:.1f} "
                f"child_mib={child_pages * PAGE / 1024**2:.1f}",
                flush=True,
            )
    finally:
        for ch in children:
            try:
                cluster.prune_child(ch["node_id"])
            except RuntimeError as e:
                log.warning("prune sibling %s: %s", ch["node_id"], e)


def _vsock_storm(cids: list[int], stop: threading.Event) -> dict[str, int]:
    ok = fail = 0
    while not stop.is_set():
        for cid in cids:
            if agent.ping(cid, timeout_s=1):
                ok += 1
            else:
                fail += 1
    return {"ok": ok, "fail": fail}


def deploy_churn(cid: int) -> None:
    yaml = f"""apiVersion: apps/v1
kind: Deployment
metadata:
  name: inner-load
spec:
  replicas: 3
  selector:
    matchLabels:
      app: inner-load
  template:
    metadata:
      labels:
        app: inner-load
    spec:
      containers:
      - name: pause
        image: {CHURN_PAUSE}
        imagePullPolicy: IfNotPresent
"""
    apply_yaml(cid, yaml, "inner-load")
    guest_kubectl(cid, ["rollout", "status", "deploy/inner-load", "--timeout=180s"])


def k8s_identity(cid: int) -> dict[str, str]:
    marker = guest_kubectl(
        cid, ["get", "cm", "fork-marker", "-o", "jsonpath={.data.nonce}"]
    ).strip()
    repl = guest_kubectl(
        cid, ["get", "deploy", "inner-load", "-o", "jsonpath={.spec.replicas}"]
    ).strip()
    cms = guest_kubectl(
        cid, ["get", "cm", "-o", "jsonpath={.items[*].metadata.name}"]
    ).split()
    return {
        "marker": marker,
        "replicas": repl,
        "configmaps": " ".join(sorted(cms)),
        "cm_set": " ".join(sorted(cms)),
    }


def _cm_names(identity: dict[str, str]) -> set[str]:
    return set((identity.get("cm_set") or identity.get("configmaps") or "").split())


def run_k8s(cluster: Cluster, samples: list[dict[str, Any]], sample_s: float, interval: float) -> dict[str, Any]:
    deploy_churn(cluster.server_cid)
    nonce = uuid.uuid4().hex[:12]
    guest_kubectl(
        cluster.server_cid,
        ["create", "configmap", "fork-marker", f"--from-literal=nonce={nonce}"],
    )
    stop = threading.Event()
    n = {"i": 0}

    def churn() -> None:
        while not stop.is_set():
            i = n["i"]
            n["i"] = i + 1
            try:
                guest_kubectl(
                    cluster.server_cid,
                    [
                        "create",
                        "configmap",
                        f"churn-live-{i}",
                        f"--from-literal=n={i}",
                    ],
                    timeout_s=20,
                )
                guest_kubectl(
                    cluster.server_cid,
                    ["scale", "deploy/inner-load", f"--replicas={3 + (i % 3)}"],
                    timeout_s=20,
                )
            except RuntimeError as e:
                if stop.is_set():
                    return
                log.warning("churn step: %s", e)
            time.sleep(0.25)

    t = threading.Thread(target=churn, daemon=True)
    t.start()
    time.sleep(1.0)
    child = cluster.fork_one("k8s")
    stop.set()
    t.join(timeout=15)
    src = k8s_identity(cluster.server_cid)
    dst = k8s_identity(child["server_cid"])
    # Marker was written before the churn thread; it must match. Replica
    # counts and churn ConfigMaps may differ: an in-flight `k3s kubectl`
    # on the source CID finishes only on the source after resume.
    if src["marker"] != nonce or dst["marker"] != nonce:
        raise RuntimeError(f"k8s marker mismatch src={src} dst={dst} nonce={nonce}")
    guest_kubectl(cluster.server_cid, ["scale", "deploy/inner-load", "--replicas=5"])
    guest_kubectl(child["server_cid"], ["scale", "deploy/inner-load", "--replicas=1"])
    guest_kubectl(
        cluster.server_cid,
        ["create", "configmap", "src-only", "--from-literal=side=source"],
    )
    guest_kubectl(
        child["server_cid"],
        ["create", "configmap", "child-only", "--from-literal=side=child"],
    )
    src2 = k8s_identity(cluster.server_cid)
    dst2 = k8s_identity(child["server_cid"])
    src_cms, dst_cms = _cm_names(src2), _cm_names(dst2)
    if "src-only" not in src_cms or "src-only" in dst_cms:
        raise RuntimeError(f"k8s src-only leaked: src={src2} dst={dst2}")
    if "child-only" not in dst_cms or "child-only" in src_cms:
        raise RuntimeError(f"k8s child-only leaked: src={src2} dst={dst2}")
    if src2["replicas"] == dst2["replicas"]:
        raise RuntimeError(f"k8s replicas did not diverge: {src2} {dst2}")
    sample_window(
        cluster.client,
        cluster.tree_id,
        workload="k8s",
        phase="post_fork",
        seconds=min(4.0, sample_s),
        interval=interval,
        sink=samples,
    )
    cluster.prune_child(child["node_id"])
    n_cm = {"i": 0}

    def exclusive() -> None:
        i = n_cm["i"]
        n_cm["i"] = i + 1
        guest_kubectl(
            cluster.server_cid,
            [
                "create",
                "configmap",
                f"sib-churn-{i}",
                f"--from-literal=n={i}",
            ],
            timeout_s=20,
        )

    def quiet(cid: int) -> None:
        guest_kubectl(
            cid, ["scale", "deploy/inner-load", "--replicas=0"], timeout_s=60
        )

    run_sibling_divergence(
        cluster,
        samples,
        workload="k8s",
        sample_s=sample_s,
        exclusive=exclusive,
        quiet_child=quiet,
    )
    print(
        f"FUL_MEASURE k8s_ok marker={nonce} fork_replicas={src['replicas']} "
        f"src_after={src2['replicas']} child_after={dst2['replicas']}",
        flush=True,
    )
    return {"ok": True, "fork_ms": child["fork_ms"], "identity": src}


KAFKA_YAML = f"""apiVersion: v1
kind: Service
metadata:
  name: kafka
spec:
  selector:
    app: kafka
  ports:
  - port: 9092
    targetPort: 9092
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: kafka
spec:
  replicas: 1
  selector:
    matchLabels:
      app: kafka
  template:
    metadata:
      labels:
        app: kafka
    spec:
      nodeName: k7d-10-200-0-2
      containers:
      - name: kafka
        image: {KAFKA_IMAGE}
        imagePullPolicy: IfNotPresent
        env:
        - name: CLUSTER_ID
          value: "MkU3OEVBNTcwNTJENDM2Qk"
        - name: KAFKA_CLUSTER_ID
          value: "MkU3OEVBNTcwNTJENDM2Qk"
        - name: KAFKA_NODE_ID
          value: "1"
        - name: KAFKA_PROCESS_ROLES
          value: broker,controller
        - name: KAFKA_LISTENERS
          value: PLAINTEXT://0.0.0.0:9092,CONTROLLER://0.0.0.0:9093
        - name: KAFKA_ADVERTISED_LISTENERS
          value: PLAINTEXT://kafka.default.svc.cluster.local:9092
        - name: KAFKA_CONTROLLER_LISTENER_NAMES
          value: CONTROLLER
        - name: KAFKA_LISTENER_SECURITY_PROTOCOL_MAP
          value: CONTROLLER:PLAINTEXT,PLAINTEXT:PLAINTEXT
        - name: KAFKA_CONTROLLER_QUORUM_VOTERS
          value: 1@localhost:9093
        - name: KAFKA_INTER_BROKER_LISTENER_NAME
          value: PLAINTEXT
        - name: KAFKA_OFFSETS_TOPIC_REPLICATION_FACTOR
          value: "1"
        - name: KAFKA_TRANSACTION_STATE_LOG_REPLICATION_FACTOR
          value: "1"
        - name: KAFKA_TRANSACTION_STATE_LOG_MIN_ISR
          value: "1"
        - name: KAFKA_GROUP_INITIAL_REBALANCE_DELAY_MS
          value: "0"
        - name: KAFKA_HEAP_OPTS
          value: "{KAFKA_HEAP}"
        ports:
        - containerPort: 9092
        resources:
          requests:
            memory: 384Mi
          limits:
            memory: 512Mi
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: kstream
spec:
  replicas: 1
  selector:
    matchLabels:
      app: kstream
  template:
    metadata:
      labels:
        app: kstream
    spec:
      nodeName: k7d-10-200-0-3
      containers:
      - name: producer
        image: {KAFKA_IMAGE}
        imagePullPolicy: IfNotPresent
        command: ["/bin/bash", "-c"]
        args:
        - |
          set -e
          for i in $(seq 1 60); do
            /opt/kafka/bin/kafka-topics.sh --bootstrap-server kafka:9092 --create --if-not-exists --topic ful --partitions 1 --replication-factor 1 && break
            sleep 2
          done
          i=0
          while true; do
            echo "msg-$i-$(date +%s%N)"
            i=$((i+1))
            sleep 0.05
          done | /opt/kafka/bin/kafka-console-producer.sh --bootstrap-server kafka:9092 --topic ful
      - name: consumer
        image: {KAFKA_IMAGE}
        imagePullPolicy: IfNotPresent
        command: ["/bin/bash", "-c"]
        args:
        - |
          set -e
          rm -f /tmp/consumed
          touch /tmp/consumed
          /opt/kafka/bin/kafka-console-consumer.sh --bootstrap-server kafka:9092 --topic ful --from-beginning >> /tmp/consumed
"""


def wait_kafka(cid: int, ceiling_s: float = 300) -> None:
    deadline = time.monotonic() + ceiling_s
    last = ""
    while time.monotonic() < deadline:
        try:
            out = guest_kubectl(
                cid,
                ["get", "pods", "-l", "app=kafka", "-o", "jsonpath={.items[0].status.phase}"],
                timeout_s=20,
            ).strip()
            last = out
            if out == "Running":
                guest_kubectl(cid, ["rollout", "status", "deploy/kafka", "--timeout=30s"], timeout_s=40)
                guest_kubectl(cid, ["rollout", "status", "deploy/kstream", "--timeout=30s"], timeout_s=40)
                # Topic exists once the producer loop has succeeded.
                topics = guest_kubectl(
                    cid,
                    [
                        "exec",
                        "deploy/kafka",
                        "--",
                        "/opt/kafka/bin/kafka-topics.sh",
                        "--bootstrap-server",
                        "localhost:9092",
                        "--list",
                    ],
                    timeout_s=30,
                )
                if "ful" in topics:
                    return
                last = f"running, topics={topics!r}"
        except RuntimeError as e:
            last = str(e)[-200:]
        time.sleep(3)
    raise RuntimeError(f"kafka never ready after {ceiling_s}s ({last})")


def kafka_consumed(cid: int) -> str:
    return guest_kubectl(
        cid,
        ["exec", "deploy/kstream", "-c", "consumer", "--", "cat", "/tmp/consumed"],
        timeout_s=30,
    )


def kafka_produce(cid: int, text: str) -> None:
    safe = text.replace("'", "'\\''")
    guest_kubectl(
        cid,
        [
            "exec",
            "deploy/kafka",
            "--",
            "bash",
            "-c",
            f"printf '%s\\n' '{safe}' | /opt/kafka/bin/kafka-console-producer.sh "
            f"--bootstrap-server localhost:9092 --topic ful",
        ],
        timeout_s=30,
    )


def kafka_wait_contains(cid: int, needle: str, ceiling_s: float = 45) -> str:
    deadline = time.monotonic() + ceiling_s
    last = ""
    while time.monotonic() < deadline:
        try:
            last = kafka_consumed(cid)
        except RuntimeError as e:
            last = str(e)
            time.sleep(1)
            continue
        if needle in last:
            return last
        time.sleep(1)
    raise RuntimeError(f"kafka cid={cid} never saw {needle!r} in {ceiling_s}s; tail={last[-200:]!r}")


def run_kafka(cluster: Cluster, samples: list[dict[str, Any]], sample_s: float, interval: float) -> dict[str, Any]:
    apply_yaml(cluster.server_cid, KAFKA_YAML, "kafka")
    wait_kafka(cluster.server_cid)
    marker = f"FORK-MARKER-{uuid.uuid4().hex[:10]}"
    kafka_produce(cluster.server_cid, marker)
    src_pre = kafka_wait_contains(cluster.server_cid, marker)
    stop = threading.Event()
    storm_cids = list(cluster.cids)
    storm: dict[str, int] = {}

    def run_storm() -> None:
        storm.update(_vsock_storm(storm_cids, stop))

    t = threading.Thread(target=run_storm, daemon=True)
    t.start()
    time.sleep(0.4)
    child = cluster.fork_one("kafka")
    stop.set()
    t.join(timeout=8)
    if storm.get("ok", 0) < 1:
        raise RuntimeError(f"vsock storm recorded no successful pings: {storm}")
    dst = kafka_wait_contains(child["server_cid"], marker)
    src_post = kafka_wait_contains(cluster.server_cid, marker)
    src_hash = hashlib.sha256(src_pre.encode()).hexdigest()
    # Child must contain the pre-fork prefix (marker + prior msgs).
    if marker not in dst or marker not in src_post:
        raise RuntimeError("kafka marker missing after fork")
    src_only = f"SRC-ONLY-{uuid.uuid4().hex[:8]}"
    child_only = f"CHILD-ONLY-{uuid.uuid4().hex[:8]}"
    kafka_produce(cluster.server_cid, src_only)
    kafka_produce(child["server_cid"], child_only)
    kafka_wait_contains(cluster.server_cid, src_only)
    kafka_wait_contains(child["server_cid"], child_only)
    src_later = kafka_consumed(cluster.server_cid)
    dst_later = kafka_consumed(child["server_cid"])
    if src_only in dst_later:
        raise RuntimeError("kafka SRC-ONLY leaked onto child")
    if child_only in src_later:
        raise RuntimeError("kafka CHILD-ONLY leaked onto source")
    sample_window(
        cluster.client,
        cluster.tree_id,
        workload="kafka",
        phase="post_fork",
        seconds=min(4.0, sample_s),
        interval=interval,
        sink=samples,
    )
    cluster.prune_child(child["node_id"])

    def quiet(cid: int) -> None:
        guest_kubectl(
            cid, ["scale", "deploy/kstream", "--replicas=0"], timeout_s=60
        )

    run_sibling_divergence(
        cluster,
        samples,
        workload="kafka",
        sample_s=sample_s,
        exclusive=None,
        quiet_child=quiet,
    )
    print(
        f"FUL_MEASURE kafka_ok marker={marker} vsock_storm={storm} "
        f"prefix_sha256={src_hash} fork_ms={child['fork_ms']:.1f}",
        flush=True,
    )
    return {"ok": True, "fork_ms": child["fork_ms"], "vsock_storm": storm}


def run_idle(cluster: Cluster, samples: list[dict[str, Any]], sample_s: float, interval: float) -> dict[str, Any]:
    # Identity: Ready node count + a ConfigMap written just before fork.
    nonce = uuid.uuid4().hex[:12]
    guest_kubectl(
        cluster.server_cid,
        ["create", "configmap", "idle-marker", f"--from-literal=nonce={nonce}"],
    )
    child = cluster.fork_one("idle")
    src = guest_kubectl(
        cluster.server_cid,
        ["get", "cm", "idle-marker", "-o", "jsonpath={.data.nonce}"],
    ).strip()
    dst = guest_kubectl(
        child["server_cid"],
        ["get", "cm", "idle-marker", "-o", "jsonpath={.data.nonce}"],
    ).strip()
    if src != nonce or dst != nonce:
        raise RuntimeError(f"idle marker src={src} dst={dst} nonce={nonce}")
    guest_kubectl(
        cluster.server_cid,
        ["create", "configmap", "idle-src-only", "--from-literal=side=source"],
    )
    guest_kubectl(
        child["server_cid"],
        ["create", "configmap", "idle-child-only", "--from-literal=side=child"],
    )
    src_cms = guest_kubectl(cluster.server_cid, ["get", "cm", "-o", "name"])
    dst_cms = guest_kubectl(child["server_cid"], ["get", "cm", "-o", "name"])
    if "idle-src-only" not in src_cms or "idle-src-only" in dst_cms:
        raise RuntimeError(f"idle src-only leaked:\n{src_cms}\n{dst_cms}")
    if "idle-child-only" not in dst_cms or "idle-child-only" in src_cms:
        raise RuntimeError(f"idle child-only leaked:\n{src_cms}\n{dst_cms}")
    sample_window(
        cluster.client,
        cluster.tree_id,
        workload="idle",
        phase="post_fork",
        seconds=min(4.0, sample_s),
        interval=interval,
        sink=samples,
    )
    cluster.prune_child(child["node_id"])
    run_sibling_divergence(
        cluster,
        samples,
        workload="idle",
        sample_s=sample_s,
    )
    print(f"FUL_MEASURE idle_ok marker={nonce} fork_ms={child['fork_ms']:.1f}", flush=True)
    return {"ok": True, "fork_ms": child["fork_ms"]}


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--out", type=Path, default=Path("/tmp/k7-28a"))
    p.add_argument("--sample-s", type=float, default=SAMPLE_S_DEFAULT)
    p.add_argument("--interval-s", type=float, default=INTERVAL_S_DEFAULT)
    p.add_argument("--tree-id", default="")
    p.add_argument("--skip-kafka", action="store_true")
    return p.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    ns = parse_args(argv)
    ns.out.mkdir(parents=True, exist_ok=True)
    tree_id = ns.tree_id or f"ful-28a-{os.getpid()}"
    client = K7dClient()
    client.ping()
    cluster = Cluster(client, tree_id)
    samples: list[dict[str, Any]] = []
    failed: Exception | None = None
    try:
        cluster.bring_up()
        sample_window(
            client,
            tree_id,
            workload="idle",
            phase="pre_fork",
            seconds=min(6.0, ns.sample_s),
            interval=ns.interval_s,
            sink=samples,
        )
        run_idle(cluster, samples, ns.sample_s, ns.interval_s)
        run_k8s(cluster, samples, ns.sample_s, ns.interval_s)
        if not ns.skip_kafka:
            run_kafka(cluster, samples, ns.sample_s, ns.interval_s)
    except Exception as e:
        failed = e
        log.exception("harness failed")
    finally:
        cluster.teardown()
    jsonl = ns.out / "divergence.jsonl"
    with jsonl.open("w") as f:
        for rec in samples:
            f.write(json.dumps(rec, separators=(",", ":")) + "\n")
    svg = render_svg(samples, ns.out / "divergence.svg")
    sib_svg = render_sibling_svg(samples, ns.out / "sibling_div.svg")
    stats = summarize(samples)
    sib_stats = summarize_siblings(samples)
    (ns.out / "summary.json").write_text(
        json.dumps({"usage": stats, "siblings": sib_stats}, indent=2) + "\n"
    )
    print(
        f"FUL_MEASURE jsonl={jsonl} svg={svg} sibling_svg={sib_svg} "
        f"summary={stats} siblings={sib_stats}",
        flush=True,
    )
    for wl, s in stats.items():
        print(
            f"FUL_MEASURE {wl}_shared_frac_t0={s['shared_frac_t0']:.3f} "
            f"t30={s['shared_frac_t30']:.3f} n={int(s['n_samples'])}",
            flush=True,
        )
        if s["shared_frac_t30"] < 0.20:
            print(
                f"FINDING: {wl} shared_frac at ~30s is {s['shared_frac_t30']:.3f} "
                "(<0.20). CoW collapsed or dirty accounting is lying — "
                "record, do not add a primitive.",
                flush=True,
            )
    if failed is not None:
        raise failed
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
