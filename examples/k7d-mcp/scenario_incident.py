#!/usr/bin/env python3
"""Bring up the 25a Ubuntu source, inject an incident, hand control to an agent.

`--policy scripted` is the CI arm: proves everything but the model.
`--no-fork` is the same-model single-world baseline.
`--runs N` repeats both comparison arms.
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import shutil
import sys
import urllib.error
import urllib.request
import uuid
from pathlib import Path
from typing import Any

HERE = Path(__file__).resolve().parent
REPO = HERE.parents[1]
sys.path.insert(0, str(HERE))
sys.path.insert(0, str(REPO / "gym"))
sys.path.insert(0, str(REPO / "examples" / "cluster-tree-search"))

from k7d_client import K7dClient  # noqa: E402
from logutil import JsonlLog  # noqa: E402
from tools import K7dMcp  # noqa: E402

import cluster as cl  # noqa: E402
import incidents  # noqa: E402

log = logging.getLogger("k7d-mcp.scenario")

SYSTEM_PROMPT = (HERE / "SYSTEM_PROMPT.md").read_text()


def ingest(url: str, payload: dict[str, Any]) -> None:
    if not url:
        return
    data = json.dumps(payload).encode()
    req = urllib.request.Request(
        url, data=data, headers={"Content-Type": "application/json"}, method="POST"
    )
    try:
        with urllib.request.urlopen(req, timeout=3) as resp:
            resp.read()
    except (OSError, urllib.error.URLError) as e:
        log.warning("k7view ingest failed: %s", e)


def write_mcp_config(
    dest: Path,
    *,
    socket: str,
    tree_id: str,
    log_path: Path,
    arm: str,
    run_id: str,
    no_fork: bool,
    certs_dir: Path,
) -> Path:
    env = {
        "K7D_SOCKET": socket,
        "K7D_TREE_ID": tree_id,
        "K7D_MCP_LOG": str(log_path),
        "K7D_MCP_ARM": arm,
        "K7D_MCP_RUN_ID": run_id,
        "K7D_SOURCE_NODE": "root",
        "K7D_CERTS_DIR": str(certs_dir),
    }
    if no_fork:
        env["K7D_NO_FORK"] = "1"
    py = "/var/lib/k7d/mcp-venv/bin/python"
    if not Path(py).is_file():
        py = sys.executable
    cfg = {
        "mcpServers": {
            "k7d": {
                "command": py,
                "args": [str(HERE / "server.py")],
                "env": env,
            }
        }
    }
    dest.write_text(json.dumps(cfg, indent=2))
    return dest


def make_tools(
    client: K7dClient,
    *,
    tree_id: str,
    log_path: Path,
    arm: str,
    run_id: str,
    no_fork: bool,
    certs_dir: Path,
) -> K7dMcp:
    return K7dMcp(
        client,
        tree_id=tree_id,
        log=JsonlLog(log_path, arm=arm, run_id=run_id),
        no_fork=no_fork,
        source_node="root",
        certs_dir=certs_dir,
    )


def scripted_fork(mcp: K7dMcp, incident: incidents.Incident) -> None:
    mcp.tree_status()
    batch = mcp.fork_batch("root", 2)
    forks = [f["node_id"] for f in batch["forks"]]
    if len(forks) != 2:
        raise RuntimeError(f"expected 2 forks, got {forks}")
    ns = batch.get("latency_ns")
    if ns is not None:
        print(f"MEASUREMENT fork_batch n=2: {int(ns) / 1e6:.1f} ms", flush=True)
    inspect, try_fix = forks
    mcp.branch_exec(inspect, 0, "k3s kubectl get pods -A --no-headers | head -40")
    mcp.tetragon_diff(inspect)
    for member in incident.remediate_members():
        mcp.branch_exec(try_fix, member, incident.remediate_cmd())
    mcp.tetragon_diff(try_fix)
    mcp.protect(try_fix)
    mcp.prune(inspect)
    for member in incident.remediate_members():
        mcp.branch_exec("root", member, incident.remediate_cmd())
    mcp.tree_status()


def scripted_baseline(mcp: K7dMcp, incident: incidents.Incident) -> None:
    mcp.tree_status()
    mcp.branch_exec("root", 0, "k3s kubectl get pods -A --no-headers | head -40")
    for member in incident.remediate_members():
        mcp.branch_exec("root", member, incident.remediate_cmd())
    mcp.tree_status()


def scripted_smoke(mcp: K7dMcp) -> list[str]:
    """CI smoke: fork n=2, exec, diff, fork-of-fork, prune. Returns ids."""
    mcp.tree_status()
    batch = mcp.fork_batch("root", 2)
    forks = [f["node_id"] for f in batch["forks"]]
    if len(forks) != 2:
        raise RuntimeError(f"expected 2 forks, got {forks}")
    ns = batch.get("latency_ns")
    if ns is not None:
        print(f"MEASUREMENT fork_batch n=2: {int(ns) / 1e6:.1f} ms", flush=True)
    mcp.branch_exec(forks[0], 0, "uname -a")
    mcp.tetragon_diff(forks[0])
    # Fork-of-fork on the adopted-Ubuntu path (CHALLENGES #130): a child
    # must be a fork source too — depth 2 is the tree-search contract.
    deep = mcp.fork_batch(forks[0], 1)
    grand = [f["node_id"] for f in deep["forks"]]
    if len(grand) != 1:
        raise RuntimeError(f"expected 1 fork-of-fork, got {grand}")
    dns = deep.get("latency_ns")
    if dns is not None:
        print(
            f"MEASUREMENT fork_batch from child n=1: {int(dns) / 1e6:.1f} ms",
            flush=True,
        )
    mcp.branch_exec(grand[0], 0, "uname -a")
    mcp.prune(grand[0])
    mcp.prune(forks[0])
    mcp.prune(forks[1])
    mcp.tree_status()
    return forks


def launch_cursor_agent(mcp_config: Path, prompt: str) -> None:
    exe = shutil.which("cursor-agent") or shutil.which("agent")
    if not exe:
        raise RuntimeError(
            "cursor-agent not on PATH; use --policy scripted for CI"
        )
    import subprocess

    r = subprocess.run(
        [exe, "--mcp-config", str(mcp_config), "--print", prompt],
        check=False,
        text=True,
    )
    if r.returncode != 0:
        raise RuntimeError(f"{exe} exited {r.returncode}")


def run_once(ns: argparse.Namespace, *, run_idx: int, no_fork: bool) -> Path:
    arm = "baseline" if no_fork else "fork"
    run_id = f"{ns.run_prefix}-{arm}-{run_idx}-{uuid.uuid4().hex[:8]}"
    tree_id = f"k7mcp-{run_id}"
    log_path = Path(ns.log_dir) / f"{run_id}.jsonl"
    view = (ns.view or "").rstrip("/")
    ingest_url = f"{view}/api/ingest" if view else ""
    client = K7dClient(ns.socket, timeout=ns.k7d_timeout)
    cluster = None
    try:
        ingest(
            ingest_url,
            {
                "type": "run",
                "tree_id": tree_id,
                "phase": "preparing-source",
                "goal": "27a-inc1 incident demo",
            },
        )
        cluster = cl.bring_up(
            client,
            tree_id=tree_id,
            repo=REPO,
            victim=not ns.smoke,
            install_cni=True,
            install_tetragon=True,
        )
        incident = incidents.pick(ns.incident)
        if not ns.smoke:
            incident.inject(cluster.kubeconfig)
            plant = getattr(incident, "plant_host", None)
            if callable(plant):
                plant(cluster.guest_cids)
            ingest(
                ingest_url,
                {
                    "type": "note",
                    "tree_id": tree_id,
                    "text": "incident injected (kind withheld from the agent)",
                },
            )
        cfg_path = Path(ns.log_dir) / f"{run_id}.mcp.json"
        write_mcp_config(
            cfg_path,
            socket=ns.socket,
            tree_id=tree_id,
            log_path=log_path,
            arm=arm,
            run_id=run_id,
            no_fork=no_fork,
            certs_dir=cluster.certs_dir,
        )
        mcp = make_tools(
            client,
            tree_id=tree_id,
            log_path=log_path,
            arm=arm,
            run_id=run_id,
            no_fork=no_fork,
            certs_dir=cluster.certs_dir,
        )
        ingest(
            ingest_url,
            {"type": "run", "tree_id": tree_id, "phase": f"agent-{arm}"},
        )
        prompt = SYSTEM_PROMPT + (
            "\n\nThe live source node_id is `root`. "
            "Diagnose and remediate. Do not ask which incident it is."
        )
        if ns.policy == "scripted":
            if ns.smoke and no_fork:
                mcp.tree_status()
                mcp.branch_exec("root", 0, "uname -a")
                mcp.tree_status()
            elif ns.smoke:
                scripted_smoke(mcp)
            elif no_fork:
                scripted_baseline(mcp, incident)
            else:
                scripted_fork(mcp, incident)
        else:
            launch_cursor_agent(cfg_path, prompt)
        ingest(
            ingest_url,
            {"type": "run", "tree_id": tree_id, "phase": "idle"},
        )
        return log_path
    finally:
        if cluster is not None:
            residue = cl.teardown(client, cluster)
            if residue["tree_node_ids"] or residue["bridges"]:
                raise RuntimeError(f"teardown left residue: {residue}")


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--socket", default=os.environ.get("K7D_SOCKET", "/run/k7d/k7d.sock"))
    p.add_argument("--policy", choices=("scripted", "cursor-agent"), default="scripted")
    p.add_argument("--no-fork", action="store_true", help="baseline arm: source-only")
    p.add_argument("--both-arms", action="store_true", help="run fork then baseline")
    p.add_argument("--runs", type=int, default=1)
    p.add_argument(
        "--incident",
        default="",
        help="relay | dormant | sleeper | hydra | cryptominer | lateral (default: relay)",
    )
    p.add_argument("--smoke", action="store_true", help="skip inject; fork/exec/diff/prune only")
    p.add_argument("--log-dir", default=str(HERE / "logs"))
    p.add_argument("--run-prefix", default="ep")
    p.add_argument("--view", default=os.environ.get("K7VIEW", ""))
    p.add_argument("--k7d-timeout", type=float, default=600)
    return p.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )
    ns = parse_args(argv)
    if ns.runs < 1:
        raise SystemExit(f"--runs must be >= 1, got {ns.runs}")
    Path(ns.log_dir).mkdir(parents=True, exist_ok=True)
    arms = [False, True] if ns.both_arms else [ns.no_fork]
    logs: list[Path] = []
    for i in range(ns.runs):
        for no_fork in arms:
            logs.append(run_once(ns, run_idx=i, no_fork=no_fork))
    print("LOGS " + " ".join(str(p) for p in logs), flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
