#!/usr/bin/env python3
"""Held apiserver watch + ClusterIP TCP across Ubuntu TreeFork.

Import Cluster. Do not edit fork_under_load.py. Talks to /run/k7d/k7d.sock.
A *new* curl after the pause is not this assertion (CHALLENGES #42).
"""

from __future__ import annotations

import argparse
import logging
import os
import subprocess
import sys
import threading
import time
from pathlib import Path
from typing import Any

HERE = Path(__file__).resolve().parent
REPO = HERE.parent
sys.path.insert(0, str(HERE))
sys.path.insert(0, str(REPO / "examples" / "cluster-tree-search"))

import ubuntu as ubuntu_src  # noqa: E402
from fork_under_load import Cluster, apply_yaml, guest_kubectl, guest_sh  # noqa: E402
from k7d_client import K7dClient  # noqa: E402
from scoring import curl_readyz  # noqa: E402

log = logging.getLogger("hs")

BUSYBOX = "docker.io/library/busybox:1.36"
LISTEN_PORT = 9376
CHILD_PORT = 9377
GUEST_API = ubuntu_src.guest_ip(0)


class HeldWatch:
    """One host-side TLS watch bound to a single k7 bridge (CHALLENGES #42)."""

    def __init__(
        self, bridge: str, cert: Path, key: Path, ca: Path, guest_ip: str
    ) -> None:
        if not bridge:
            raise RuntimeError("HeldWatch: empty bridge")
        self.bridge = bridge
        cmd = [
            "curl",
            "-sS",
            "-N",
            "-k",
            "--max-time",
            "600",
            "--interface",
            bridge,
            "--cacert",
            str(ca),
            "--cert",
            str(cert),
            "--key",
            str(key),
            f"https://{guest_ip}:6443/api/v1/namespaces/default/configmaps?watch=1",
        ]
        self.proc = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            bufsize=0,
        )
        self._chunks: list[str] = []
        self._lock = threading.Lock()
        self._reader = threading.Thread(target=self._pump, daemon=True)
        self._reader.start()
        time.sleep(0.8)
        if not self.alive():
            raise RuntimeError(
                f"held watch on {bridge} died before connect: {self.stderr()}"
            )

    def _pump(self) -> None:
        assert self.proc.stdout is not None
        while True:
            chunk = self.proc.stdout.read(4096)
            if not chunk:
                break
            with self._lock:
                self._chunks.append(chunk.decode("utf-8", errors="replace"))

    def alive(self) -> bool:
        return self.proc.poll() is None

    def text(self) -> str:
        with self._lock:
            return "".join(self._chunks)

    def saw(self, name: str) -> bool:
        return name in self.text()

    def stderr(self) -> str:
        if self.alive() or self.proc.stderr is None:
            return ""
        return self.proc.stderr.read().decode("utf-8", errors="replace")

    def wait_saw(self, name: str, ceiling_s: float) -> None:
        deadline = time.monotonic() + ceiling_s
        while time.monotonic() < deadline:
            if not self.alive():
                raise RuntimeError(
                    f"held watch on {self.bridge} exited while waiting for "
                    f"{name} (CHALLENGES #29/#42): {self.stderr() or self.text()[-400:]}"
                )
            if self.saw(name):
                return
            time.sleep(0.2)
        raise RuntimeError(
            f"held watch on {self.bridge} never emitted {name} in "
            f"{ceiling_s}s (got {self.text()[-600:]!r})"
        )

    def close(self) -> None:
        if self.alive():
            self.proc.kill()
        try:
            self.proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            self.proc.kill()


def wait_readyz(
    bridge: str, cert: Path, key: Path, ceiling_s: float, label: str
) -> None:
    deadline = time.monotonic() + ceiling_s
    while time.monotonic() < deadline:
        if curl_readyz(bridge, cert=cert, key=key, timeout_s=3):
            return
        time.sleep(0.5)
    raise RuntimeError(
        f"{label} /readyz never recovered after {ceiling_s}s via {bridge} "
        "(wait on host clock, CHALLENGES #202)"
    )


def wait_pod_running(cid: int, name: str, ceiling_s: float = 90) -> None:
    deadline = time.monotonic() + ceiling_s
    last = ""
    while time.monotonic() < deadline:
        try:
            last = guest_kubectl(
                cid,
                ["get", "pod", name, "-o", "jsonpath={.status.phase}"],
                timeout_s=15,
            ).strip()
        except RuntimeError as e:
            last = str(e)
        if last == "Running":
            return
        time.sleep(1)
    desc = ""
    try:
        desc = guest_kubectl(cid, ["describe", "pod", name], timeout_s=20)
    except RuntimeError as e:
        desc = str(e)
    raise RuntimeError(f"pod {name} never Running (last={last!r})\n{desc[-800:]}")


def wait_cluster_ip(cid: int, svc: str, ceiling_s: float = 45) -> str:
    deadline = time.monotonic() + ceiling_s
    last = ""
    while time.monotonic() < deadline:
        last = guest_kubectl(
            cid, ["get", "svc", svc, "-o", "jsonpath={.spec.clusterIP}"], timeout_s=15
        ).strip()
        if last and last != "None":
            try:
                ep = guest_kubectl(
                    cid,
                    [
                        "get",
                        "endpoints",
                        svc,
                        "-o",
                        "jsonpath={.subsets[0].addresses[0].ip}",
                    ],
                    timeout_s=15,
                ).strip()
            except RuntimeError:
                ep = ""
            if ep:
                return last
        time.sleep(0.5)
    raise RuntimeError(f"service {svc} never got ClusterIP+endpoints (last={last!r})")


def pod_file(cid: int, pod: str, path: str) -> str:
    return guest_kubectl(cid, ["exec", pod, "--", "cat", path], timeout_s=20)


def wait_pod_file_contains(
    cid: int, pod: str, path: str, needle: str, ceiling_s: float = 30
) -> str:
    deadline = time.monotonic() + ceiling_s
    last = ""
    while time.monotonic() < deadline:
        try:
            last = pod_file(cid, pod, path)
        except RuntimeError as e:
            last = str(e)
        if needle in last:
            return last
        time.sleep(0.4)
    raise RuntimeError(
        f"{pod}:{path} never contained {needle!r} (last={last[-400:]!r})"
    )


def server_node_name() -> str:
    return "k7d-" + GUEST_API.replace(".", "-")


def listen_yaml(name: str, port: int) -> str:
    return f"""apiVersion: v1
kind: Pod
metadata:
  name: {name}
  labels:
    app: {name}
spec:
  nodeName: {server_node_name()}
  restartPolicy: Never
  containers:
  - name: nc
    image: {BUSYBOX}
    imagePullPolicy: IfNotPresent
    command: ["sh", "-c"]
    args:
    - |
      trap '' HUP
      : > /tmp/tcp-in
      ( sleep 3600 | nc -l -p {port} >> /tmp/tcp-in ) &
      sleep 3600
---
apiVersion: v1
kind: Service
metadata:
  name: {name}
spec:
  selector:
    app: {name}
  ports:
  - port: {port}
    targetPort: {port}
"""


def hold_yaml(name: str, cluster_ip: str, port: int, first_line: str) -> str:
    if not cluster_ip or cluster_ip == "None":
        raise RuntimeError(f"hold_yaml {name}: empty ClusterIP")
    return f"""apiVersion: v1
kind: Pod
metadata:
  name: {name}
spec:
  nodeName: {server_node_name()}
  restartPolicy: Never
  containers:
  - name: nc
    image: {BUSYBOX}
    imagePullPolicy: IfNotPresent
    command: ["sh", "-c"]
    args:
    - |
      trap '' HUP
      rm -f /tmp/hold-in
      mkfifo /tmp/hold-in
      sleep 3600 > /tmp/hold-in &
      ( echo {first_line}; cat /tmp/hold-in ) | nc {cluster_ip} {port}
      sleep 3600
"""


def pull_busybox(cid: int) -> None:
    guest_sh(
        cid,
        f"k3s ctr images pull {BUSYBOX}",
        timeout_s=120,
    )


def start_held_tcp(cid: int, listen: str, hold: str, port: int) -> str:
    apply_yaml(cid, listen_yaml(listen, port), listen)
    wait_pod_running(cid, listen)
    cluster_ip = wait_cluster_ip(cid, listen)
    time.sleep(1)
    apply_yaml(cid, hold_yaml(hold, cluster_ip, port, "before-fork"), hold)
    wait_pod_running(cid, hold)
    wait_pod_file_contains(cid, listen, "/tmp/tcp-in", "before-fork")
    return cluster_ip


def exec_bg(cid: int, pod: str, script: str, token: str) -> str:
    """Start `script` in `pod` without holding the vsock exec pipe (#207)."""
    if not script.strip() or "\nEOS\n" in script or script.startswith("EOS"):
        raise RuntimeError(f"exec_bg {pod}: refused script")
    wrapped = (
        f"cat > /tmp/hs-bg.sh <<'EOS'\n{script.rstrip()}\nEOS\n"
        f"chmod +x /tmp/hs-bg.sh\n"
        f"/tmp/hs-bg.sh </dev/null >/dev/null 2>&1 &\n"
        f"echo {token}\n"
    )
    out = guest_kubectl(cid, ["exec", pod, "--", "sh", "-c", wrapped], timeout_s=30)
    if token not in out:
        raise RuntimeError(f"exec_bg {pod}: missing {token} (out={out!r})")
    return out


def start_new_clusterip_tcp(
    cid: int, listen: str, hold: str, port: int, line: str
) -> None:
    """New ClusterIP session via exec into already-Running pods."""
    exec_bg(
        cid,
        listen,
        f": > /tmp/tcp-{port}\n"
        f"sleep 3600 | nc -l -p {port} >> /tmp/tcp-{port}\n",
        "LISTENING",
    )
    apply_yaml(
        cid,
        f"""apiVersion: v1
kind: Service
metadata:
  name: hs-listen-child
spec:
  selector:
    app: {listen}
  ports:
  - port: {port}
    targetPort: {port}
""",
        "hs-listen-child-svc",
    )
    cluster_ip = wait_cluster_ip(cid, "hs-listen-child")
    time.sleep(1)
    exec_bg(
        cid,
        hold,
        f"( echo {line}; sleep 3600 ) | nc {cluster_ip} {port}\n",
        "CONNECTED",
    )
    wait_pod_file_contains(cid, listen, f"/tmp/tcp-{port}", line)


def write_hold_line(cid: int, hold: str, line: str) -> None:
    guest_kubectl(
        cid,
        ["exec", hold, "--", "sh", "-c", f"echo {line} > /tmp/hold-in"],
        timeout_s=20,
    )


def create_cm(cid: int, name: str) -> None:
    guest_kubectl(
        cid,
        ["create", "configmap", name, f"--from-literal=k={name}"],
        timeout_s=30,
    )


def certs_for(tree_id: str) -> tuple[Path, Path, Path]:
    dest = ubuntu_src.certs_dir(tree_id)
    cert, key, ca = dest / "client.pem", dest / "client-key.pem", dest / "ca.crt"
    for p in (cert, key, ca):
        if not p.is_file():
            raise RuntimeError(f"missing host kube cert {p}")
    return cert, key, ca


def run(cluster: Cluster) -> dict[str, Any]:
    cert, key, ca = certs_for(cluster.tree_id)
    src_bridge = cluster.bridge
    src = cluster.server_cid
    log.info("pull %s on server cid=%s (pods pin nodeName=%s)", BUSYBOX, src, server_node_name())
    pull_busybox(src)

    start_held_tcp(src, "hs-listen", "hs-hold", LISTEN_PORT)
    watch = HeldWatch(src_bridge, cert, key, ca, GUEST_API)
    try:
        if not watch.alive():
            raise RuntimeError("source watch died before tree_fork_batch")
        child = cluster.fork_one("held")
        if not watch.alive():
            raise RuntimeError(
                "source held watch exited during tree_fork_batch "
                "(CHALLENGES #29 TAP-worker pause / #78 cancelled injection): "
                f"{watch.stderr()}"
            )
        wait_readyz(src_bridge, cert, key, 60, "source")
        create_cm(src, "after-fork-src")
        watch.wait_saw("after-fork-src", 20)
        write_hold_line(src, "hs-hold", "after-fork")
        src_tcp = wait_pod_file_contains(src, "hs-listen", "/tmp/tcp-in", "after-fork")
        if "before-fork" not in src_tcp:
            raise RuntimeError(f"source listener lost before-fork: {src_tcp!r}")

        child_cid = int(child["server_cid"])
        child_bridge = str(child["bridge"])
        wait_readyz(child_bridge, cert, key, 60, "child")
        cut = pod_file(child_cid, "hs-listen", "/tmp/tcp-in")
        if "before-fork" not in cut:
            raise RuntimeError(
                f"child listen log at the cut missing before-fork: {cut!r}"
            )
        if "after-fork" in cut:
            raise RuntimeError(
                "child copied listen log already has after-fork — "
                "source write leaked across the cut"
            )

        child_watch = HeldWatch(child_bridge, cert, key, ca, GUEST_API)
        try:
            create_cm(child_cid, "after-fork-child")
            child_watch.wait_saw("after-fork-child", 20)
            time.sleep(2)
            if watch.saw("after-fork-child"):
                raise RuntimeError(
                    "source held watch emitted child-only after-fork-child "
                    "(shared TAP / etcd leak)"
                )
            if child_watch.saw("after-fork-src"):
                raise RuntimeError(
                    "child watch saw source-only after-fork-src"
                )

            # New ClusterIP session on the child — exec into the copied
            # pods (already Running, image present). A fresh Pod stays
            # Pending if it lands on an agent that never pulled busybox.
            start_new_clusterip_tcp(
                child_cid, "hs-listen", "hs-hold", CHILD_PORT, "child-only"
            )
            src_after = pod_file(src, "hs-listen", "/tmp/tcp-in")
            if "child-only" in src_after:
                raise RuntimeError(
                    "source held TCP saw child-only payload: "
                    f"{src_after!r}"
                )
        finally:
            child_watch.close()

        if not watch.alive():
            raise RuntimeError("source watch died after assertions")
        print("HS_MEASURE watch_ok", flush=True)
        print("HS_MEASURE tcp_ok", flush=True)
        print(f"HS_MEASURE fork_ms={child['fork_ms']:.1f}", flush=True)
        print(
            f"HS_MEASURE child={child['node_id']} "
            f"src_bridge={src_bridge} child_bridge={child_bridge} "
            f"watch_pid={watch.proc.pid}",
            flush=True,
        )
        return {
            "ok": True,
            "fork_ms": child["fork_ms"],
            "node_id": child["node_id"],
        }
    finally:
        watch.close()


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--tree-id", default="")
    return p.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    ns = parse_args(argv)
    tree_id = ns.tree_id or f"hs-{os.getpid()}"
    if not tree_id.startswith("hs-"):
        raise RuntimeError(f"tree id must start with hs-, got {tree_id!r}")
    client = K7dClient()
    client.ping()
    cluster = Cluster(client, tree_id)
    failed: Exception | None = None
    try:
        cluster.bring_up()
        run(cluster)
    except Exception as e:
        failed = e
        log.exception("harness failed")
    finally:
        cluster.teardown()
    if failed is not None:
        raise failed
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
