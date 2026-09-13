#!/usr/bin/env python3
"""Paced k7d-view demo: fork clusters (and optional VMs) and annotate them.

Talks to k7d on the unix socket and POSTs notes / traces / latencies to
k7view so the dashboard has something to show besides topology.

Profiles:
  smoke — one 3-VM cluster, one fork_batch (default; good for a quick check)
  max   — multi-wave cluster tree under a tight VM budget, plus a single-VM
          tree. This is the video profile: big git-graph, many clusters,
          many VMs, many forks, pressure bars going hot, then evict.
  ubuntu-dilated — 3-node Ubuntu k3s source at dilation: 8, waves 6+4+4,
          scored by a guest-time Deployment readiness gate.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import threading
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
sys.path.insert(0, str(HERE.parent / "cluster-tree-search"))

from k7d_client import K7dClient  # noqa: E402
import llm as k7view_llm  # noqa: E402
import dilated as dilated_sc  # noqa: E402

USE_LLM = False


def _first_file(paths: list[Path]) -> Path | None:
    for p in paths:
        if p.is_file():
            return p
    return None


def resolve_guest_paths() -> dict[str, str]:
    """Prefer the daemon share dir — rsync excludes workspace guest artifacts."""
    share = Path("/usr/local/share/k7d")
    repo = HERE.parents[1]
    kernel = Path(
        os.environ.get("K7D_KERNEL")
        or _first_file([share / "vmlinux", repo / "guest/kernel/vmlinux"])
        or share / "vmlinux"
    )
    initrd = Path(
        os.environ.get("K7D_INITRD")
        or _first_file(
            [share / "initramfs.cpio.gz", repo / "guest/rootfs/initramfs.cpio.gz"]
        )
        or share / "initramfs.cpio.gz"
    )
    if not kernel.is_file():
        raise SystemExit(f"guest kernel missing: {kernel}")
    if not initrd.is_file():
        raise SystemExit(f"guest initrd missing: {initrd}")
    return {"kernel": str(kernel), "initrd": str(initrd)}


def post(url: str, payload: dict | list) -> None:
    data = json.dumps(payload).encode()
    req = urllib.request.Request(
        url,
        data=data,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=5) as resp:
            resp.read()
    except (urllib.error.URLError, TimeoutError) as exc:
        print(f"[scenario] view ingest failed: {exc}", file=sys.stderr)


def pace(seconds: float) -> None:
    if seconds > 0:
        time.sleep(seconds)


def fetch_state(view: str) -> dict[str, Any]:
    url = view.rstrip("/") + "/api/state"
    with urllib.request.urlopen(url, timeout=5) as resp:
        return json.loads(resp.read().decode())


def llm_watch(ingest: str, view: str, stop: threading.Event) -> None:
    """Stream real OpenRouter comments on the latest measured vsock probe."""
    while not stop.wait(7.0):
        if not (USE_LLM and k7view_llm.configured()):
            continue
        try:
            snap = fetch_state(view)
        except (urllib.error.URLError, TimeoutError, json.JSONDecodeError):
            continue
        last = (snap.get("last_tick") or "").strip()
        totals = snap.get("totals") or {}
        if not last:
            continue
        trees = snap.get("trees") or {}
        node_id = ""
        tree_id = (snap.get("run") or {}).get("tree_id") or ""
        for tid, slot in trees.items():
            traces = slot.get("traces") or {}
            for nid, spans in traces.items():
                if spans and last[:24] in (spans[-1].get("text") or ""):
                    tree_id = tid
                    node_id = nid
                    break
            if node_id:
                break
        if not tree_id:
            continue

        def on_delta(buf: str, _tid: str = tree_id, _nid: str = node_id) -> None:
            meta(ingest, _tid, buf, action="think", node_id=_nid)
            if _nid:
                post(
                    ingest,
                    {
                        "type": "trace",
                        "tree_id": _tid,
                        "node_id": _nid,
                        "role": "thinking",
                        "text": buf,
                        "replace": True,
                    },
                )

        try:
            k7view_llm.collect(
                [
                    {
                        "role": "system",
                        "content": (
                            "You are the k7d tree controller watching real vsock probes. "
                            "Two short sentences. Quote the ping/uptime numbers. No markdown."
                        ),
                    },
                    {
                        "role": "user",
                        "content": (
                            f"latest_probe={last} totals={json.dumps(totals, separators=(',', ':'))}"
                        ),
                    },
                ],
                on_delta=on_delta,
                max_tokens=80,
            )
        except Exception as exc:  # noqa: BLE001
            print(f"[scenario] llm watch: {exc}", file=sys.stderr)


def meta(ingest: str, tree_id: str, text: str, *, action: str = "decide", node_id: str = "") -> None:
    post(
        ingest,
        {
            "type": "meta",
            "tree_id": tree_id,
            "node_id": node_id,
            "action": action,
            "text": text,
        },
    )


def stream_text(
    ingest: str,
    tree_id: str,
    node_id: str,
    text: str,
    *,
    role: str = "thinking",
    chunk: int = 18,
    delay: float = 0.035,
) -> None:
    """Grow one trace span so the tile looks like a token stream."""
    buf = ""
    for i in range(0, len(text), chunk):
        buf += text[i : i + chunk]
        post(
            ingest,
            {
                "type": "trace",
                "tree_id": tree_id,
                "node_id": node_id,
                "role": role,
                "text": buf,
                "replace": True,
            },
        )
        pace(delay)


def chatter(
    ingest: str,
    tree_id: str,
    items: list[tuple[str, str, str]],
    *,
    chunk: int = 16,
    delay: float = 0.025,
) -> None:
    """Interleave streams so many tiles update in the same second."""
    bufs = [""] * len(items)
    done = [False] * len(items)
    while not all(done):
        for i, (node_id, role, text) in enumerate(items):
            if done[i]:
                continue
            nxt = min(len(text), len(bufs[i]) + chunk)
            bufs[i] = text[:nxt]
            post(
                ingest,
                {
                    "type": "trace",
                    "tree_id": tree_id,
                    "node_id": node_id,
                    "role": role,
                    "text": bufs[i],
                    "replace": True,
                },
            )
            if nxt >= len(text):
                done[i] = True
        pace(delay)


def chatter_llm(
    ingest: str,
    tree_id: str,
    items: list[tuple[str, str, str]],
) -> None:
    """Stream one OpenRouter completion per tile, in parallel."""

    def one(node_id: str, role: str, prompt: str) -> None:
        def on_delta(buf: str) -> None:
            post(
                ingest,
                {
                    "type": "trace",
                    "tree_id": tree_id,
                    "node_id": node_id,
                    "role": role,
                    "text": buf,
                    "replace": True,
                },
            )

        try:
            k7view_llm.collect(
                [
                    {
                        "role": "system",
                        "content": (
                            "You are a rollout agent on one k7d cluster-fork branch. "
                            "Speak in 2-3 short sentences as you score CoW, vsock CIDs, "
                            "and whether this branch should live. No markdown."
                        ),
                    },
                    {"role": "user", "content": prompt},
                ],
                on_delta=on_delta,
                max_tokens=90,
            )
        except Exception as exc:  # noqa: BLE001 — demo must keep moving
            print(f"[scenario] llm tile {node_id}: {exc}", file=sys.stderr)
            stream_text(ingest, tree_id, node_id, prompt, role=role, delay=0.02)

    threads = [
        threading.Thread(target=one, args=item, daemon=True) for item in items
    ]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=35)


def chatter_live(
    ingest: str,
    tree_id: str,
    items: list[tuple[str, str, str]],
    *,
    delay: float = 0.025,
) -> None:
    if USE_LLM and k7view_llm.configured():
        chatter_llm(ingest, tree_id, items)
    else:
        chatter(ingest, tree_id, items, delay=delay)


def controller_decide(
    ingest: str,
    tree_id: str,
    scores: list[tuple[float, dict]],
    *,
    budget_note: str,
) -> dict[str, Any]:
    """Stream a meta decision. Returns parsed JSON or empty dict."""
    summary = [
        {
            "id": f.get("node_id"),
            "reward": r,
            "cids": f.get("guest_cids") or [],
            "full_copy": f.get("fork_memory_full_copy") or [],
        }
        for r, f in scores
    ]
    prompt = (
        "You control a k7d snapshot tree. Pick who to protect and who to park.\n"
        f"{budget_note}\n"
        f"branches={json.dumps(summary, separators=(',', ':'))}\n"
        'Reply JSON only: {"protect":["id"],"suspend":["id"],"reason":"one sentence"}'
    )
    text = ""
    if USE_LLM and k7view_llm.configured():
        def on_delta(buf: str) -> None:
            meta(ingest, tree_id, buf, action="think")

        try:
            text = k7view_llm.collect(
                [
                    {
                        "role": "system",
                        "content": (
                            "You are the k7d tree controller. Short. JSON at the end. "
                            "Protect 1-2 clean CoW winners. Suspend losers. "
                            "Never protect every branch."
                        ),
                    },
                    {"role": "user", "content": prompt},
                ],
                on_delta=on_delta,
                max_tokens=180,
            )
        except Exception as exc:  # noqa: BLE001
            print(f"[scenario] llm controller: {exc}", file=sys.stderr)
            text = ""
    decided = k7view_llm.extract_json(text) or {}
    if decided.get("reason"):
        meta(
            ingest,
            tree_id,
            str(decided["reason"]),
            action="decide",
            node_id=(decided.get("protect") or [""])[0] if decided.get("protect") else "",
        )
    return decided


def wave_sizes(profile: str, branches: int, waves: int) -> list[int]:
    if profile == "smoke":
        return [branches]
    if profile == "ubuntu-dilated":
        return list(dilated_sc.DILATED_WAVES)
    sizes = [max(2, branches)]
    nxt = max(3, branches // 2)
    for _ in range(1, max(1, waves)):
        sizes.append(nxt)
    return sizes


def pressure_budget(cluster_vms: int, wave1: int, memory_mb: int) -> dict[str, int]:
    """Tight enough that wave 1 fills ~90% of the VM bar and wave 2 evicts."""
    wave1_live = cluster_vms * (1 + wave1)
    max_vms = max(wave1_live + cluster_vms, int(wave1_live / 0.88))
    return {
        "max_live_vms": max_vms,
        "max_live_ram_bytes": memory_mb * 1024 * 1024 * max(8, max_vms // 2),
        "max_disk_bytes": 64 * 1024**3,
        "max_chain_depth": 8,
    }


def generous_budget(cluster_vms: int, branches: int) -> dict[str, int]:
    live_vms = cluster_vms * (branches + 3)
    return {
        "max_live_vms": max(64, live_vms),
        "max_live_ram_bytes": 64 * 1024**3,
        "max_disk_bytes": 256 * 1024**3,
        "max_chain_depth": 8,
    }


def guest_config(paths: dict[str, str], memory_mb: int) -> dict[str, Any]:
    return {
        "kernel": paths["kernel"],
        "initrd": paths["initrd"],
        "memory_mb": memory_mb,
        "vcpus": 1,
        "vsock": True,
    }


def ingest_members_latency(
    tree_id: str,
    node_id: str,
    parent_id: str | None,
    guest_cids: list,
    latency_ms: float | None,
    cow_full: list | None,
    vm_count: int,
) -> list[dict]:
    cow = [not x for x in cow_full] if cow_full else [True] * vm_count
    items: list[dict] = [
        {
            "type": "members",
            "tree_id": tree_id,
            "node_id": node_id,
            "guest_cids": guest_cids or [],
        },
        {
            "type": "latency",
            "tree_id": tree_id,
            "node_id": node_id,
            "parent_id": parent_id,
            "latency_ms": latency_ms,
            "cow": cow,
        },
    ]
    return items


def fork_wave(
    client: K7dClient,
    ingest: str,
    tree_id: str,
    source_id: str,
    labels: list[str],
    *,
    vm_count: int,
    role: str,
    timeout: float = 180,
) -> tuple[list[dict], float]:
    print(f"[scenario] tree_fork_batch n={len(labels)} from {source_id} ({role}) …")
    t1 = time.perf_counter()
    batch = client.tree_fork_batch(tree_id, source_id, labels, timeout=timeout)
    wall_ms = (time.perf_counter() - t1) * 1000
    forks = batch["forks"]
    daemon_ns = batch.get("latency_ns")
    fork_ms = (daemon_ns / 1e6) if daemon_ns is not None else wall_ms
    print(f"[scenario] fork_batch {fork_ms:.1f} ms (batch wall, n={len(forks)})")
    items: list[dict] = [{"type": "run", "tree_id": tree_id, "phase": "scoring"}]
    for i, f in enumerate(forks):
        cow = f.get("fork_memory_full_copy") or []
        items.extend(
            ingest_members_latency(
                tree_id,
                f["node_id"],
                source_id,
                f.get("guest_cids") or [],
                round(fork_ms, 1),
                cow,
                vm_count,
            )
        )
        items.append(
            {
                "type": "trace",
                "tree_id": tree_id,
                "node_id": f["node_id"],
                "role": "tool",
                "text": f"fork_memory_full_copy={cow} cids={f.get('guest_cids')}",
            }
        )
    post(ingest, items)
    return forks, fork_ms


def score_forks(
    ingest: str,
    tree_id: str,
    forks: list[dict],
    *,
    expect_cids: int,
    pace_s: float,
) -> list[tuple[float, dict]]:
    scores: list[tuple[float, dict]] = []
    lines: list[tuple[str, str, str]] = []
    for f in forks:
        full = f.get("fork_memory_full_copy") or []
        cids = f.get("guest_cids") or []
        reward = 1.0 if (len(cids) == expect_cids and not any(full)) else 0.0
        lines.append(
            (
                f["node_id"],
                "thinking",
                (
                    f"reward={reward:.1f} from this fork: {len(cids)}/{expect_cids} CIDs, "
                    f"fork_memory_full_copy={full}."
                ),
            )
        )
        scores.append((reward, f))
    chatter_live(ingest, tree_id, lines, delay=max(0.02, pace_s * 0.08))
    scores.sort(key=lambda x: x[0], reverse=True)
    return scores


def protect_winner(
    client: K7dClient, ingest: str, tree_id: str, winner: dict, reward: float
) -> None:
    print(f"[scenario] protect {winner['node_id']} reward={reward}")
    client.tree_protect(tree_id, winner["node_id"])
    meta(
        ingest,
        tree_id,
        f"protect {winner['node_id']} — highest reward {reward:.1f}, clean CoW. others may evict.",
        action="protect",
        node_id=winner["node_id"],
    )
    post(
        ingest,
        {
            "type": "note",
            "tree_id": tree_id,
            "node_id": winner["node_id"],
            "text": f"protected — highest reward ({reward:.1f}), clean CoW",
        },
    )


def node_states(client: K7dClient, tree_id: str) -> dict[str, str]:
    nodes = client.tree_nodes(tree_id).get("nodes") or []
    return {n["id"]: (n.get("state") or "") for n in nodes if "id" in n}


def prepare_source(
    client: K7dClient,
    ingest: str,
    tree_id: str,
    node_id: str,
    *,
    timeout: float = 300,
) -> dict[str, Any]:
    """Real k7d checkpoint: snapshot + restore so this node can be forked."""
    print(f"[scenario] tree_prepare_fork_source {node_id} …")
    post(ingest, {"type": "run", "tree_id": tree_id, "phase": "preparing-source"})
    meta(
        ingest,
        tree_id,
        f"prepare_fork_source {node_id} — child has no base.mem until this snapshot.",
        action="prepare",
        node_id=node_id,
    )
    t0 = time.perf_counter()
    resp = client.tree_prepare_fork_source(tree_id, node_id, timeout=timeout)
    ms = (time.perf_counter() - t0) * 1000
    wrote = resp.get("wrote_base")
    print(
        f"[scenario] prepare {node_id} wrote_base={wrote} {ms:.0f} ms "
        f"cids={resp.get('guest_cids')}"
    )
    post(
        ingest,
        {
            "type": "note",
            "tree_id": tree_id,
            "node_id": node_id,
            "text": f"prepare_fork_source wrote_base={wrote} ({ms:.0f} ms)",
        },
    )
    return resp


def print_depths(client: K7dClient, tree_id: str) -> None:
    """Log k7d parent chains so a flat tree cannot hide."""
    resp = client.tree_nodes(tree_id)
    nodes = resp.get("nodes") or []
    by = {n["id"]: n for n in nodes if "id" in n}

    def depth(n: dict) -> int:
        d = 0
        seen: set[str] = set()
        cur = n
        while cur.get("parent") and cur["parent"] in by and cur["id"] not in seen:
            seen.add(cur["id"])
            cur = by[cur["parent"]]
            d += 1
        return d

    max_d = 0
    for n in nodes:
        d = depth(n)
        max_d = max(max_d, d)
        print(
            f"[scenario] depth={d} {n.get('label') or n['id']} "
            f"parent={n.get('parent')} state={n.get('state')} "
            f"base={n.get('has_base_snapshot')}"
        )
    print(f"[scenario] max_depth={max_d} nodes={len(nodes)}")


def run_cluster_tree(
    client: K7dClient,
    ingest: str,
    *,
    tree_id: str,
    paths: dict[str, str],
    cluster_vms: int,
    memory_mb: int,
    sizes: list[int],
    budget: dict[str, int],
    pace_s: float,
    hold_s: float,
    profile: str,
) -> tuple[str, float]:
    post(
        ingest,
        {
            "type": "run",
            "tree_id": tree_id,
            "phase": "booting",
            "goal": (
                "max-load search — many cluster forks under a tight VM budget"
                if profile == "max"
                else "parallel rollouts — keep the healthy CoW winner"
            ),
        },
    )
    post(ingest, {"type": "budget", "tree_id": tree_id, "budget": budget, "memory_mb": memory_mb})

    print(f"[scenario] tree_create_cluster {cluster_vms} …")
    t0 = time.perf_counter()
    created = client.tree_create_cluster(
        cluster_vms,
        guest_config(paths, memory_mb),
        tree_id=tree_id,
        budget=budget,
    )
    create_ms = (time.perf_counter() - t0) * 1000
    root_id = created["root_id"]
    print(
        f"[scenario] created in {create_ms:.0f} ms root={root_id} "
        f"cids={created.get('guest_cids')}"
    )
    post(
        ingest,
        ingest_members_latency(
            tree_id,
            root_id,
            None,
            created.get("guest_cids") or [],
            round(create_ms, 1),
            None,
            cluster_vms,
        )
        + [
            {
                "type": "note",
                "tree_id": tree_id,
                "node_id": root_id,
                "text": f"checkpoint — {cluster_vms}-VM cluster ready ({create_ms:.0f} ms boot)",
            },
            {
                "type": "trace",
                "tree_id": tree_id,
                "node_id": root_id,
                "role": "thinking",
                "text": "checkpoint is live. opening N parallel rollouts from here.",
            },
            {"type": "run", "tree_id": tree_id, "phase": "forking"},
        ],
    )
    pace(hold_s)

    last_fork_ms = 0.0
    winners: list[dict] = []
    all_losers: list[dict] = []
    source = root_id
    fork_timeout = 300 if profile == "max" else 180
    for wave, n in enumerate(sizes):
        if wave > 0:
            # Park live losers first — this is the RL policy of killing
            # branches, and it keeps protect-chain visibility. The daemon
            # now also evicts for incoming VMs inside fork_batch
            # (CHALLENGES #115), so this is no longer *required*
            # for a legal under-budget fork_batch.
            parked = 0
            states = node_states(client, tree_id)
            for f in list(all_losers):
                nid = f["node_id"]
                if states.get(nid) != "live":
                    continue
                print(f"[scenario] suspend loser {nid} (headroom before wave {wave})")
                try:
                    client.tree_suspend(tree_id, nid)
                    post(
                        ingest,
                        {
                            "type": "note",
                            "tree_id": tree_id,
                            "node_id": nid,
                            "text": "suspended — park RAM so the next wave can fork",
                        },
                    )
                    parked += 1
                    meta(
                        ingest,
                        tree_id,
                        f"park {nid} — make headroom before wave {wave} (fork_batch does not evict for incoming).",
                        action="suspend",
                        node_id=nid,
                    )
                except RuntimeError as exc:
                    print(f"[scenario] suspend {nid}: {exc}", file=sys.stderr)
                pace(0.45)
            print(f"[scenario] parked {parked} losers before wave {wave}")
            source = winners[-1]["node_id"] if winners else root_id
            try:
                prepare_source(
                    client, ingest, tree_id, source, timeout=fork_timeout
                )
            except RuntimeError as exc:
                print(
                    f"[scenario] prepare {source} failed (not flattening to root): {exc}",
                    file=sys.stderr,
                )
                continue
        labels = [f"w{wave}-rollout-{i}" for i in range(n)]
        post(ingest, {"type": "run", "tree_id": tree_id, "phase": f"forking-wave-{wave}"})
        meta(
            ingest,
            tree_id,
            f"wave {wave}: fork {n} clusters from {source}. watch VM bar vs budget.",
            action="fork",
            node_id=source,
        )
        try:
            forks, fork_ms = fork_wave(
                client,
                ingest,
                tree_id,
                source,
                labels,
                vm_count=cluster_vms,
                role=f"wave{wave}",
                timeout=fork_timeout,
            )
        except RuntimeError as exc:
            print(
                f"[scenario] fork from {source} failed (not flattening to root): {exc}",
                file=sys.stderr,
            )
            continue
        last_fork_ms = fork_ms
        print_depths(client, tree_id)
        pace(hold_s)
        scores = score_forks(
            ingest,
            tree_id,
            forks,
            expect_cids=cluster_vms,
            pace_s=pace_s * 0.35,
        )
        if not scores:
            continue
        decided = controller_decide(
            ingest,
            tree_id,
            scores,
            budget_note=f"wave={wave} max_live_vms={budget.get('max_live_vms')}",
        )
        by_id = {f["node_id"]: (r, f) for r, f in scores}
        protect_ids = [i for i in (decided.get("protect") or []) if i in by_id][:1]
        if not protect_ids:
            protect_ids = [scores[0][1]["node_id"]]
        for nid in protect_ids:
            reward, winner = by_id[nid]
            try:
                protect_winner(client, ingest, tree_id, winner, reward)
                winners.append(winner)
            except RuntimeError as exc:
                print(f"[scenario] protect {nid}: {exc}", file=sys.stderr)
        protected = set(protect_ids)
        all_losers.extend(f for _, f in scores if f["node_id"] not in protected)
        for nid in decided.get("suspend") or []:
            if nid in protected or nid not in by_id:
                continue
            if node_states(client, tree_id).get(nid) != "live":
                continue
            print(f"[scenario] controller suspend {nid}")
            try:
                client.tree_suspend(tree_id, nid)
                meta(
                    ingest,
                    tree_id,
                    f"controller park {nid}",
                    action="suspend",
                    node_id=nid,
                )
            except RuntimeError as exc:
                print(f"[scenario] suspend {nid}: {exc}", file=sys.stderr)
        if profile == "max" and wave >= 1:
            print("[scenario] tree_auto_evict (budget pressure)")
            try:
                evicted = client.tree_auto_evict(tree_id)
                ids = evicted.get("evicted") or []
                post(
                    ingest,
                    {
                        "type": "note",
                        "tree_id": tree_id,
                        "node_id": source,
                        "text": (
                            f"auto-evict under pressure — {len(ids)} nodes"
                            if ids
                            else "auto-evict — already under budget"
                        ),
                    },
                )
                meta(
                    ingest,
                    tree_id,
                    (
                        f"auto-evict fired — {len(ids)} nodes over budget."
                        if ids
                        else "auto-evict: already under VM/RAM thresholds."
                    ),
                    action="auto_evict",
                    node_id=source,
                )
            except RuntimeError as exc:
                print(f"[scenario] auto_evict: {exc}", file=sys.stderr)
        pace(pace_s)

    if profile == "smoke":
        post(ingest, {"type": "run", "tree_id": tree_id, "phase": "evicting"})
        if all_losers:
            first = all_losers[0]
            print(f"[scenario] suspend {first['node_id']} (park, keep delta)")
            try:
                client.tree_suspend(tree_id, first["node_id"])
                post(
                    ingest,
                    {
                        "type": "note",
                        "tree_id": tree_id,
                        "node_id": first["node_id"],
                        "text": "suspended — park RAM, keep delta in case we rollback",
                    },
                )
            except RuntimeError as exc:
                print(f"[scenario] suspend: {exc}", file=sys.stderr)
            pace(pace_s)
        for f in all_losers[1:]:
            nid = f["node_id"]
            print(f"[scenario] prune loser {nid}")
            try:
                client.tree_prune(tree_id, nid)
            except RuntimeError as exc:
                print(f"[scenario] prune {nid}: {exc}", file=sys.stderr)
                continue
            post(
                ingest,
                {
                    "type": "note",
                    "tree_id": tree_id,
                    "node_id": nid,
                    "text": "pruned — dead rollout, reclaim RAM + disk",
                },
            )
            pace(pace_s * 0.5)
        print("[scenario] rollback from root → continue")
        rolled = client.tree_rollback(tree_id, root_id, "continue")
        post(
            ingest,
            ingest_members_latency(
                tree_id,
                rolled["node_id"],
                root_id,
                rolled.get("guest_cids") or [],
                None,
                rolled.get("fork_memory_full_copy"),
                cluster_vms,
            )
            + [
                {
                    "type": "trace",
                    "tree_id": tree_id,
                    "node_id": rolled["node_id"],
                    "role": "thinking",
                    "text": "new branch from the same checkpoint — continue search.",
                },
                {"type": "run", "tree_id": tree_id, "phase": "idle"},
            ],
        )
    else:
        # Keep the bush for the camera; prune a couple of suspended losers.
        post(ingest, {"type": "run", "tree_id": tree_id, "phase": "evicting"})
        pruned = 0
        for f in all_losers:
            if pruned >= 3:
                break
            nid = f["node_id"]
            print(f"[scenario] prune loser {nid}")
            try:
                client.tree_prune(tree_id, nid)
            except RuntimeError as exc:
                print(f"[scenario] prune {nid}: {exc}", file=sys.stderr)
                continue
            post(
                ingest,
                {
                    "type": "note",
                    "tree_id": tree_id,
                    "node_id": nid,
                    "text": "pruned — dead rollout, reclaim RAM + disk",
                },
            )
            pruned += 1
            pace(max(1.2, pace_s))
        post(ingest, {"type": "run", "tree_id": tree_id, "phase": "idle"})

    winner_id = winners[0]["node_id"] if winners else root_id
    return winner_id, last_fork_ms


def run_vm_tree(
    client: K7dClient,
    ingest: str,
    *,
    tree_id: str,
    paths: dict[str, str],
    memory_mb: int,
    branches: int,
    pace_s: float,
    hold_s: float,
) -> None:
    budget = {
        "max_live_vms": max(8, branches + 1),
        "max_live_ram_bytes": memory_mb * 1024 * 1024 * max(8, branches + 1),
        "max_disk_bytes": 16 * 1024**3,
        "max_chain_depth": 8,
    }
    post(
        ingest,
        {
            "type": "run",
            "tree_id": tree_id,
            "phase": "booting",
            "goal": "single-VM tree — same observer, different payload kind",
        },
    )
    post(ingest, {"type": "budget", "tree_id": tree_id, "budget": budget, "memory_mb": memory_mb})
    print("[scenario] tree_create (single VM) …")
    t0 = time.perf_counter()
    created = client.tree_create(
        guest_config(paths, memory_mb),
        tree_id=tree_id,
        budget=budget,
    )
    create_ms = (time.perf_counter() - t0) * 1000
    root_id = created["root_id"]
    print(f"[scenario] vm tree created in {create_ms:.0f} ms root={root_id}")
    post(
        ingest,
        ingest_members_latency(
            tree_id,
            root_id,
            None,
            created.get("guest_cids") or [],
            round(create_ms, 1),
            None,
            1,
        )
        + [
            {
                "type": "note",
                "tree_id": tree_id,
                "node_id": root_id,
                "text": f"single-VM checkpoint ({create_ms:.0f} ms boot)",
            },
            {"type": "run", "tree_id": tree_id, "phase": "forking"},
        ],
    )
    pace(hold_s)
    n1 = max(2, branches // 2)
    n2 = max(1, branches - n1)
    labels1 = [f"vm-rollout-{i}" for i in range(n1)]
    forks, _ = fork_wave(
        client, ingest, tree_id, root_id, labels1, vm_count=1, role="vm"
    )
    print_depths(client, tree_id)
    pace(hold_s)
    scores = score_forks(
        ingest, tree_id, forks, expect_cids=1, pace_s=pace_s * 0.25
    )
    source = root_id
    if scores:
        protect_winner(client, ingest, tree_id, scores[0][1], scores[0][0])
        source = scores[0][1]["node_id"]
        for _, f in scores[1:]:
            nid = f["node_id"]
            print(f"[scenario] suspend vm loser {nid}")
            try:
                client.tree_suspend(tree_id, nid)
            except RuntimeError as exc:
                print(f"[scenario] suspend {nid}: {exc}", file=sys.stderr)
        try:
            prepare_source(client, ingest, tree_id, source)
            labels2 = [f"vm-g2-{i}" for i in range(n2)]
            fork_wave(
                client, ingest, tree_id, source, labels2, vm_count=1, role="vm-g2"
            )
            print_depths(client, tree_id)
        except RuntimeError as exc:
            print(
                f"[scenario] vm depth-2 from {source} failed (not flattening to root): {exc}",
                file=sys.stderr,
            )
    post(ingest, {"type": "run", "tree_id": tree_id, "phase": "idle"})


def run_ubuntu_dilated_tree(
    client: K7dClient,
    ingest: str,
    *,
    tree_id: str,
    sizes: list[int],
    budget: dict[str, int],
    pace_s: float,
    log: dilated_sc.JsonlLog,
) -> tuple[str, float]:
    """3-wave Ubuntu k3s search at ×8. Tempo comes from guest readiness."""
    post(
        ingest,
        {
            "type": "run",
            "tree_id": tree_id,
            "phase": "booting",
            "goal": "×8 dilated Ubuntu k3s — guest-time rollout search",
        },
    )
    post(
        ingest,
        {
            "type": "budget",
            "tree_id": tree_id,
            "budget": budget,
            "memory_mb": 2048,
        },
    )
    created = dilated_sc.create_ubuntu_source(
        client,
        tree_id=tree_id,
        budget=budget,
        dilation=dilated_sc.DILATION_FACTOR,
        log=log,
    )
    root_id = created["root_id"]
    cluster_vms = 3
    image = created["pause_image"]
    factors = dilated_sc.live_dilation_map(client, tree_id)
    post(
        ingest,
        ingest_members_latency(
            tree_id,
            root_id,
            None,
            created.get("guest_cids") or [],
            round(created["create_ms"], 1),
            None,
            cluster_vms,
        )
        + [
            {
                "type": "note",
                "tree_id": tree_id,
                "node_id": root_id,
                "text": (
                    f"Ubuntu k3s Ready at ×{dilated_sc.DILATION_FACTOR} "
                    f"({created['create_ms']:.0f} ms boot, "
                    f"sleep 8 → {created['sleep8_wall_s']:.2f}s wall)"
                ),
            },
            {
                "type": "beat",
                "tree_id": tree_id,
                "name": "ready",
                "node_id": root_id,
            },
            {"type": "run", "tree_id": tree_id, "phase": "ready"},
        ],
    )
    # Hold Ready so capture.py (--start-phase ready, 1 s poll) and the
    # guest-clock chip can latch before wave 0. Not a rollout pace sleep.
    time.sleep(3.0)
    last_fork_ms = 0.0
    winners: list[dict] = []
    all_losers: list[dict] = []
    source = root_id
    fork_timeout = 300
    for wave, n in enumerate(sizes):
        if wave > 0:
            parked = 0
            states = node_states(client, tree_id)
            for f in list(all_losers):
                nid = f["node_id"]
                if states.get(nid) != "live":
                    continue
                print(f"[scenario] suspend loser {nid} (headroom before wave {wave})")
                try:
                    client.tree_suspend(tree_id, nid)
                    post(
                        ingest,
                        {
                            "type": "note",
                            "tree_id": tree_id,
                            "node_id": nid,
                            "text": "suspended — park RAM so the next wave can fork",
                        },
                    )
                    parked += 1
                    meta(
                        ingest,
                        tree_id,
                        f"park {nid} before wave {wave}",
                        action="suspend",
                        node_id=nid,
                    )
                except RuntimeError as exc:
                    print(f"[scenario] suspend {nid}: {exc}", file=sys.stderr)
            log.write("park", wave=wave, parked=parked)
            source = winners[-1]["node_id"] if winners else root_id
            try:
                prepare_source(client, ingest, tree_id, source, timeout=fork_timeout)
            except RuntimeError as exc:
                print(
                    f"[scenario] prepare {source} failed: {exc}",
                    file=sys.stderr,
                )
                continue
        labels = [f"w{wave}-rollout-{i}" for i in range(n)]
        post(ingest, {"type": "run", "tree_id": tree_id, "phase": f"forking-wave-{wave}"})
        meta(
            ingest,
            tree_id,
            f"wave {wave}: fork {n} clusters from {source} at inherited ×8.",
            action="fork",
            node_id=source,
        )
        try:
            forks, fork_ms = fork_wave(
                client,
                ingest,
                tree_id,
                source,
                labels,
                vm_count=cluster_vms,
                role=f"wave{wave}",
                timeout=fork_timeout,
            )
        except RuntimeError as exc:
            print(f"[scenario] fork from {source} failed: {exc}", file=sys.stderr)
            log.write("fork_error", wave=wave, source=source, error=str(exc))
            continue
        last_fork_ms = fork_ms
        factors = dilated_sc.assert_live_dilation(
            client, tree_id, dilated_sc.DILATION_FACTOR
        )
        log.write(
            "fork",
            wave=wave,
            n=len(forks),
            source=source,
            fork_ms=round(fork_ms, 1),
            live_dilation=factors,
            usage=(client.tree_nodes(tree_id).get("usage") or {}),
        )
        print_depths(client, tree_id)
        post(ingest, {"type": "run", "tree_id": tree_id, "phase": "scoring"})

        def on_line(node_id: str, text: str) -> None:
            post(
                ingest,
                {
                    "type": "trace",
                    "tree_id": tree_id,
                    "node_id": node_id,
                    "role": "tool",
                    "text": text,
                    "replace": True,
                },
            )

        scores = dilated_sc.score_rollouts(
            forks,
            image,
            tree_id=tree_id,
            deploy_name=dilated_sc.deploy_name(wave),
            settle_s=dilated_sc.FORK_SETTLE_WALL_S if wave >= 1 else 0.0,
            on_line=on_line,
        )
        if not any(d.get("ready") for _r, _f, d in scores):
            errors = [
                f"{d.get('node_id')}: {d.get('error') or 'not Ready'}"
                for _r, _f, d in scores
            ]
            raise RuntimeError(
                f"wave {wave}: no branch reached Ready (guest-time rollout). "
                + " | ".join(errors[:4])
            )
        for reward, f, detail in scores:
            log.write("rollout", wave=wave, **detail)
            post(
                ingest,
                {
                    "type": "note",
                    "tree_id": tree_id,
                    "node_id": f["node_id"],
                    "text": (
                        f"rollout reward={reward:.2f} wall={detail.get('wall_s')}s "
                        f"guest={detail.get('guest_s')}s ready={detail.get('ready')}"
                    ),
                },
            )
        if not scores:
            continue
        winner_reward, winner, _wdetail = scores[0]
        try:
            protect_winner(client, ingest, tree_id, winner, winner_reward)
            winners.append(winner)
            log.write("protect", wave=wave, node_id=winner["node_id"], reward=winner_reward)
        except RuntimeError as exc:
            print(f"[scenario] protect {winner['node_id']}: {exc}", file=sys.stderr)
        protected = {winner["node_id"]}
        all_losers.extend(f for _, f, _d in scores if f["node_id"] not in protected)
        if wave >= 1:
            print("[scenario] tree_auto_evict (24-VM budget)")
            try:
                evicted = client.tree_auto_evict(tree_id)
                ids = evicted.get("evicted") or []
                log.write("auto_evict", wave=wave, evicted=ids)
                post(
                    ingest,
                    {
                        "type": "note",
                        "tree_id": tree_id,
                        "node_id": source,
                        "text": (
                            f"auto-evict — {len(ids)} nodes"
                            if ids
                            else "auto-evict — already under budget"
                        ),
                    },
                )
                meta(
                    ingest,
                    tree_id,
                    (
                        f"auto-evict fired — {len(ids)} nodes over budget."
                        if ids
                        else "auto-evict: already under VM/RAM thresholds."
                    ),
                    action="auto_evict",
                    node_id=source,
                )
            except RuntimeError as exc:
                print(f"[scenario] auto_evict: {exc}", file=sys.stderr)
        if pace_s > 0:
            pace(min(pace_s, 0.6))

    post(ingest, {"type": "run", "tree_id": tree_id, "phase": "wave-2-protect"})
    pruned = 0
    for f in all_losers:
        if pruned >= 3:
            break
        nid = f["node_id"]
        print(f"[scenario] prune loser {nid}")
        try:
            client.tree_prune(tree_id, nid)
        except RuntimeError as exc:
            print(f"[scenario] prune {nid}: {exc}", file=sys.stderr)
            continue
        post(
            ingest,
            {
                "type": "note",
                "tree_id": tree_id,
                "node_id": nid,
                "text": "pruned — dead rollout, reclaim RAM + disk",
            },
        )
        pruned += 1
        if pace_s > 0:
            pace(min(pace_s, 0.6))
    post(ingest, {"type": "run", "tree_id": tree_id, "phase": "idle"})
    winner_id = winners[-1]["node_id"] if winners else root_id
    log.write(
        "done",
        winner=winner_id,
        last_fork_ms=round(last_fork_ms, 1),
        live_dilation=dilated_sc.live_dilation_map(client, tree_id),
        usage=(client.tree_nodes(tree_id).get("usage") or {}),
    )
    return winner_id, last_fork_ms


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument(
        "--profile", choices=("smoke", "max", "ubuntu-dilated"), default="smoke"
    )
    ap.add_argument(
        "--video",
        action="store_true",
        help="alias for --profile max (the load-pressure video run)",
    )
    ap.add_argument("--branches", type=int, default=None)
    ap.add_argument("--waves", type=int, default=3)
    ap.add_argument("--cluster-vms", type=int, default=3)
    ap.add_argument("--memory-mb", type=int, default=256)
    ap.add_argument("--tree-id", default=None)
    ap.add_argument("--keep", action="store_true")
    ap.add_argument("--view", default=os.environ.get("K7VIEW_URL", "http://127.0.0.1:7474"))
    ap.add_argument("--pace", type=float, default=None)
    ap.add_argument(
        "--vm-tree",
        action=argparse.BooleanOptionalAction,
        default=None,
        help="also grow a single-VM tree (default on for --profile max)",
    )
    ap.add_argument(
        "--llm",
        action=argparse.BooleanOptionalAction,
        default=None,
        help="stream OpenRouter into tiles + controller (default: on if a key is present)",
    )
    ap.add_argument(
        "--log",
        default=None,
        help="JSONL path (ubuntu-dilated default: k7d-dilated-tree.jsonl)",
    )
    args = ap.parse_args()
    if args.video:
        args.profile = "max"
    if args.branches is None:
        args.branches = (
            6 if args.profile == "ubuntu-dilated" else 8 if args.profile == "max" else 4
        )
    if args.pace is None:
        args.pace = (
            0.35
            if args.profile == "ubuntu-dilated"
            else 0.85 if args.profile == "max" else 1.6
        )
    if args.vm_tree is None:
        args.vm_tree = args.profile == "max"
    if args.profile == "ubuntu-dilated":
        args.memory_mb = 2048
        args.cluster_vms = 3
        args.vm_tree = False
    global USE_LLM
    if args.profile == "ubuntu-dilated":
        USE_LLM = False
    elif args.llm is None:
        USE_LLM = k7view_llm.configured()
    else:
        USE_LLM = bool(args.llm)
    if USE_LLM and not k7view_llm.configured():
        print("[scenario] --llm set but no OPENROUTER_API_KEY; canned streams", file=sys.stderr)
        USE_LLM = False
    if args.branches < 2:
        raise SystemExit("--branches must be >= 2 so a loser can be evicted")
    if args.cluster_vms < 1:
        raise SystemExit("--cluster-vms must be >= 1")

    sizes = wave_sizes(args.profile, args.branches, args.waves)
    tree_id = args.tree_id or f"k7v-{os.getpid()}"
    ingest = args.view.rstrip("/") + "/api/ingest"
    client = K7dClient()
    pong = client.ping()
    log_path = None
    if args.log:
        log_path = Path(args.log)
    elif args.profile == "ubuntu-dilated":
        log_path = Path("k7d-dilated-tree.jsonl")
    log = dilated_sc.JsonlLog(log_path)
    print(
        f"[scenario] k7d {pong.get('version')} tree={tree_id} "
        f"profile={args.profile} waves={sizes} llm={USE_LLM} "
        f"model={k7view_llm.DEFAULT_MODEL if USE_LLM else 'canned'} view={args.view} "
        f"log={log_path}"
    )

    if args.profile == "ubuntu-dilated":
        dilated_sc.require_patched_dilation()
        budget = dilated_sc.dilated_budget()
        winner, fork_ms = run_ubuntu_dilated_tree(
            client,
            ingest,
            tree_id=tree_id,
            sizes=sizes,
            budget=budget,
            pace_s=args.pace,
            log=log,
        )
    else:
        paths = resolve_guest_paths()
        if args.profile == "max":
            budget = pressure_budget(args.cluster_vms, sizes[0], args.memory_mb)
        else:
            budget = generous_budget(args.cluster_vms, args.branches)
        hold = max(args.pace, 2.5 if args.profile == "max" else args.pace)
        winner, fork_ms = _run_trees(
            client,
            ingest,
            tree_id=tree_id,
            paths=paths,
            args=args,
            sizes=sizes,
            budget=budget,
            hold=hold,
        )
    boil = 16.0 if args.profile == "max" else 3.0
    if args.profile == "ubuntu-dilated":
        boil = 4.0
    if args.keep:
        print("[scenario] --keep: trees stay")
        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            print("[scenario] keep stop")
    else:
        print(f"[scenario] hold {boil:.0f}s")
        time.sleep(boil)

    print(f"[scenario] DONE winner={winner} last_fork_batch={fork_ms:.1f} ms")
    if not args.keep:
        client.tree_drop(tree_id)
        print(f"[scenario] tree_drop {tree_id}")
        vm_tree_id = f"{tree_id}-vm"
        try:
            client.tree_drop(vm_tree_id)
            print(f"[scenario] tree_drop {vm_tree_id}")
        except RuntimeError:
            pass
    log.close()
    return 0


def _run_trees(
    client: K7dClient,
    ingest: str,
    *,
    tree_id: str,
    paths: dict[str, str],
    args: argparse.Namespace,
    sizes: list[int],
    budget: dict[str, int],
    hold: float,
) -> tuple[str, float]:
    winner, fork_ms = run_cluster_tree(
        client,
        ingest,
        tree_id=tree_id,
        paths=paths,
        cluster_vms=args.cluster_vms,
        memory_mb=args.memory_mb,
        sizes=sizes,
        budget=budget,
        pace_s=args.pace,
        hold_s=hold,
        profile=args.profile,
    )
    vm_tree_id = None
    if args.vm_tree:
        vm_tree_id = f"{tree_id}-vm"
        run_vm_tree(
            client,
            ingest,
            tree_id=vm_tree_id,
            paths=paths,
            memory_mb=args.memory_mb,
            branches=max(6, args.branches - 2) if args.profile == "max" else 4,
            pace_s=args.pace,
            hold_s=hold,
        )
        post(
            ingest,
            {
                "type": "run",
                "tree_id": tree_id,
                "phase": "idle",
                "goal": "max-load search — cluster tree + VM tree under pressure",
            },
        )
    return winner, fork_ms


if __name__ == "__main__":
    raise SystemExit(main())
