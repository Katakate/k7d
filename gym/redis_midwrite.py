#!/usr/bin/env python3
"""Redis mid-write across Ubuntu TreeFork.

One 3-node Ubuntu source, redis:7-alpine (AOF on) on member 0 plus an
rinc INCR loop on member 1. `tree_fork_batch` n=1 while the loop is
still mutating. Assert GET forkctr matches at the cut, then src-only /
child-only isolation, PING, 3 Ready, CoW.

Talks to `/run/k7d/k7d.sock` only. Imports `Cluster` from
`gym/fork_under_load.py` — do not edit that module.
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import sys
import threading
import time
from pathlib import Path
from typing import Any

HERE = Path(__file__).resolve().parent
REPO = HERE.parent
sys.path.insert(0, str(HERE))
sys.path.insert(0, str(REPO / "examples" / "cluster-tree-search"))

from fork_under_load import Cluster, apply_yaml, guest_kubectl  # noqa: E402
from k7d_client import K7dClient  # noqa: E402

log = logging.getLogger("rd")

REDIS_IMAGE = "docker.io/library/redis:7-alpine"
REDIS_YAML = f"""apiVersion: v1
kind: Service
metadata:
  name: redis
spec:
  selector:
    app: redis
  ports:
  - port: 6379
    targetPort: 6379
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: redis
spec:
  replicas: 1
  selector:
    matchLabels:
      app: redis
  template:
    metadata:
      labels:
        app: redis
    spec:
      nodeName: k7d-10-200-0-2
      containers:
      - name: redis
        image: {REDIS_IMAGE}
        imagePullPolicy: IfNotPresent
        args:
        - --appendonly
        - "yes"
        - --appendfsync
        - everysec
        - --save
        - ""
        ports:
        - containerPort: 6379
        resources:
          limits:
            memory: 128Mi
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: rinc
spec:
  replicas: 1
  selector:
    matchLabels:
      app: rinc
  template:
    metadata:
      labels:
        app: rinc
    spec:
      nodeName: k7d-10-200-0-3
      containers:
      - name: rinc
        image: {REDIS_IMAGE}
        imagePullPolicy: IfNotPresent
        command: ["/bin/sh", "-c"]
        args:
        - |
          while true; do
            redis-cli -h redis INCR forkctr || true
            sleep 0.02
          done
"""


def retry_call(fn, *, ceiling_s: float, label: str):
    deadline = time.monotonic() + ceiling_s
    last = ""
    while time.monotonic() < deadline:
        try:
            return fn()
        except RuntimeError as e:
            last = str(e)
            time.sleep(1)
    raise RuntimeError(f"{label} failed after {ceiling_s}s: {last}")


def redis_cli(cid: int, *args: str, timeout_s: float = 30) -> str:
    return guest_kubectl(
        cid,
        ["exec", "deploy/redis", "--", "redis-cli", "--raw", *args],
        timeout_s=timeout_s,
    ).strip()


def redis_get(cid: int, key: str) -> str | None:
    out = redis_cli(cid, "GET", key)
    if out in ("", "(nil)"):
        return None
    return out.splitlines()[-1]


def redis_get_int(cid: int, key: str) -> int | None:
    out = redis_get(cid, key)
    if out is None:
        return None
    try:
        return int(out)
    except ValueError as e:
        raise RuntimeError(f"GET {key} not int: {out!r}") from e


def ready_count(cid: int) -> int:
    out = guest_kubectl(cid, ["get", "nodes", "--no-headers"], timeout_s=60)
    return sum(1 for ln in out.splitlines() if " Ready" in ln)


def wait_ready(cid: int, *, side: str, want: int = 3, ceiling_s: float = 60.0) -> int:
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
    raise RuntimeError(f"{side}: want {want} Ready nodes: {last}")


def assert_cow(flags: Any) -> None:
    if not isinstance(flags, list) or not flags or any(flags):
        raise RuntimeError(
            f"expected CoW fork_memory_full_copy all-false, got {flags} "
            "(CHALLENGES #43/#79 dirty-log / DMA miss)"
        )


def wait_redis(cid: int, ceiling_s: float = 180) -> None:
    deadline = time.monotonic() + ceiling_s
    last = ""
    while time.monotonic() < deadline:
        try:
            guest_kubectl(
                cid, ["rollout", "status", "deploy/redis", "--timeout=30s"], timeout_s=40
            )
            guest_kubectl(
                cid, ["rollout", "status", "deploy/rinc", "--timeout=30s"], timeout_s=40
            )
            if redis_cli(cid, "PING", timeout_s=20) == "PONG":
                return
            last = "PING not PONG"
        except RuntimeError as e:
            last = str(e)[-240:]
        time.sleep(2)
    raise RuntimeError(f"redis/rinc never ready after {ceiling_s}s ({last})")


def wait_forkctr(cid: int, want: int = 50, ceiling_s: float = 90) -> int:
    deadline = time.monotonic() + ceiling_s
    last: int | None = None
    err = ""
    while time.monotonic() < deadline:
        try:
            last = redis_get_int(cid, "forkctr")
            if last is not None and last >= want:
                return last
            err = f"forkctr={last}"
        except RuntimeError as e:
            err = str(e)[-200:]
        time.sleep(0.4)
    raise RuntimeError(f"forkctr never >= {want} after {ceiling_s}s ({err})")


def get_forkctr_pair(src_cid: int, child_cid: int) -> tuple[int, int]:
    """GET forkctr on both sides at the same wall time.

    Do not CLIENT PAUSE first — the two pauses land tens of ms apart
    and freeze *different* prefixes (CHALLENGES #205). Two live GETs
    from the same snapshotted counter stay within a tick or two.
    """
    box: dict[str, int | Exception] = {}

    def one(key: str, cid: int) -> None:
        try:
            n = redis_get_int(cid, "forkctr")
            if n is None:
                raise RuntimeError(f"{key}: GET forkctr is nil")
            box[key] = n
        except Exception as e:  # noqa: BLE001 — stash for the joiner
            box[key] = e

    ts = [
        threading.Thread(target=one, args=("src", src_cid)),
        threading.Thread(target=one, args=("child", child_cid)),
    ]
    for t in ts:
        t.start()
    for t in ts:
        t.join(timeout=45)
    src = box.get("src")
    child = box.get("child")
    if isinstance(src, Exception):
        raise RuntimeError(f"src GET forkctr: {src}") from src
    if isinstance(child, Exception):
        raise RuntimeError(f"child GET forkctr: {child}") from child
    if not isinstance(src, int) or not isinstance(child, int):
        raise RuntimeError(f"parallel GET incomplete: {box}")
    return src, child


def scale_rinc(cid: int, replicas: int) -> None:
    guest_kubectl(
        cid, ["scale", "deploy/rinc", f"--replicas={replicas}"], timeout_s=60
    )


def wait_rinc_gone(cid: int, ceiling_s: float = 45) -> None:
    deadline = time.monotonic() + ceiling_s
    last = ""
    while time.monotonic() < deadline:
        try:
            out = guest_kubectl(
                cid,
                ["get", "pods", "-l", "app=rinc", "--no-headers"],
                timeout_s=20,
            ).strip()
            if not out:
                return
            last = out.splitlines()[0][:120]
        except RuntimeError as e:
            last = str(e)[-160:]
        time.sleep(1)
    raise RuntimeError(f"child rinc still present after {ceiling_s}s ({last})")


def wait_diverge(
    src_cid: int, child_cid: int, *, ceiling_s: float = 2.0
) -> tuple[int, int]:
    deadline = time.monotonic() + ceiling_s
    last = (None, None)
    while time.monotonic() < deadline:
        src = redis_get_int(src_cid, "forkctr")
        child = redis_get_int(child_cid, "forkctr")
        last = (src, child)
        if src is not None and child is not None and src != child:
            return src, child
        time.sleep(0.2)
    raise RuntimeError(
        f"source and child forkctr did not diverge in {ceiling_s}s: {last}"
    )


def run(cluster: Cluster) -> dict[str, Any]:
    apply_yaml(cluster.server_cid, REDIS_YAML, "redis")
    wait_redis(cluster.server_cid)
    pre = wait_forkctr(cluster.server_cid, 50)
    log.info("source forkctr=%s; forking while rinc runs", pre)

    child = cluster.fork_one("rd")
    assert_cow(child.get("full_copy"))
    src_cid = cluster.server_cid
    child_cid = child["server_cid"]

    def pair() -> tuple[int, int]:
        return get_forkctr_pair(src_cid, child_cid)

    src_cut, child_cut = retry_call(pair, ceiling_s=45, label="GET forkctr at cut")
    cut = min(src_cut, child_cut)
    # Same snapshotted prefix. A 1-tick gap is two kubectl execs racing
    # still-running INCR loops (CHALLENGES #205). Going *backwards*
    # from the pre-fork GET is the torn-AOF class (#43/#79).
    if cut < pre:
        raise RuntimeError(
            f"GET forkctr at cut src={src_cut} child={child_cut} "
            f"< pre-fork {pre} (AOF older than heap — CHALLENGES #43/#79)"
        )
    print(
        f"RD_MEASURE cut={cut} fork_ms={child['fork_ms']:.1f} "
        f"src={src_cut} child={child_cut} pre={pre}",
        flush=True,
    )

    scale_rinc(child_cid, 0)
    wait_rinc_gone(child_cid)

    redis_cli(src_cid, "SET", "src-only", "1")
    redis_cli(child_cid, "SET", "child-only", "1")
    if redis_get(src_cid, "child-only") is not None:
        raise RuntimeError("child-only leaked onto source")
    if redis_get(child_cid, "src-only") is not None:
        raise RuntimeError("src-only leaked onto child")
    if redis_get(src_cid, "src-only") != "1":
        raise RuntimeError("source missing src-only")
    if redis_get(child_cid, "child-only") != "1":
        raise RuntimeError("child missing child-only")

    src_after = redis_get_int(src_cid, "forkctr")
    child_after = redis_get_int(child_cid, "forkctr")
    if src_after is None or child_after is None:
        raise RuntimeError(f"post-stop GET nil src={src_after} child={child_after}")
    if src_after < cut:
        raise RuntimeError(f"source forkctr={src_after} went below cut={cut}")
    if child_after == cut:
        pass
    elif child_after > cut:
        # Child loop ticked once before scale-to-0 landed. Isolation
        # still holds; source and child must then diverge.
        wait_diverge(src_cid, child_cid)
    else:
        raise RuntimeError(
            f"child forkctr={child_after} < cut={cut} "
            "(AOF replay older than the in-memory counter — #43/#79)"
        )

    if redis_cli(src_cid, "PING") != "PONG":
        raise RuntimeError("source PING failed after fork")
    if redis_cli(child_cid, "PING") != "PONG":
        raise RuntimeError("child PING failed after fork (silent AOF replay death)")

    wait_ready(src_cid, side="source")
    wait_ready(child_cid, side="child")

    result = {
        "ok": True,
        "tree_id": cluster.tree_id,
        "cut": cut,
        "fork_ms": round(child["fork_ms"], 1),
        "src_after": src_after,
        "child_after": child_after,
        "full_copy": child.get("full_copy"),
        "child_node": child["node_id"],
    }
    print(
        f"RD_MEASURE ok cut={cut} fork_ms={child['fork_ms']:.1f} "
        f"src_after={src_after} child_after={child_after} "
        f"cow={child.get('full_copy')} node={child['node_id']}",
        flush=True,
    )
    return result


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--out", type=Path, default=Path("/tmp/k7-redis-midwrite"))
    p.add_argument("--tree-id", default="")
    return p.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    ns = parse_args(argv)
    ns.out.mkdir(parents=True, exist_ok=True)
    tree_id = ns.tree_id or f"rd-{os.getpid()}"
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
        log.exception("redis-midwrite harness failed")
    finally:
        cluster.teardown()
    out_json = ns.out / "redis_midwrite.json"
    if result is not None:
        out_json.write_text(json.dumps(result, indent=2) + "\n")
    if failed is not None:
        raise failed
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
