#!/usr/bin/env python3
"""Render the five plots from harness JSONL."""

from __future__ import annotations

import argparse
import json
import sys
from collections import defaultdict
from pathlib import Path
from typing import Any

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402

sys.path.insert(0, str(Path(__file__).resolve().parent))
from mutation import looks_destructive  # noqa: E402


PLOTS = (
    "01-tree-utilization.png",
    "02-fork-latency.png",
    "03-hypotheses-wallclock.png",
    "04-remediation-blast-radius.png",
    "05-ram-per-branch.png",
)


def load_jsonl(paths: list[Path]) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for p in paths:
        if not p.is_file():
            raise SystemExit(f"jsonl missing: {p}")
        for i, line in enumerate(p.read_text().splitlines(), 1):
            if not line.strip():
                continue
            try:
                rec = json.loads(line)
            except json.JSONDecodeError as e:
                raise SystemExit(f"{p}:{i}: {e}") from e
            if not isinstance(rec, dict) or "tool" not in rec:
                raise SystemExit(f"{p}:{i}: expected object with tool")
            # Re-score mutating commands with today's classifier so both
            # comparison arms are judged by one rule (see mutation.py).
            if rec.get("tool") == "branch_exec":
                cmd = str((rec.get("args") or {}).get("cmd") or "")
                rec["destructive"] = looks_destructive(cmd)
            rec["_src"] = str(p)
            rows.append(rec)
    if not rows:
        raise SystemExit("no records in jsonl inputs")
    return rows


def _t0(rows: list[dict[str, Any]]) -> float:
    return min(float(r["ts"]) for r in rows)


def plot_utilization(rows: list[dict[str, Any]], dest: Path) -> None:
    t0 = _t0(rows)
    xs, vms, ram, vmax, rmax = [], [], [], [], []
    for r in rows:
        u = r.get("usage") or {}
        b = r.get("budget") or {}
        if not u:
            continue
        xs.append(float(r["ts"]) - t0)
        vms.append(int(u.get("live_vm_count") or 0))
        ram.append(int(u.get("live_ram_bytes") or 0) / 1024**3)
        vmax.append(int(b.get("max_live_vms") or 0))
        rmax.append(int(b.get("max_live_ram_bytes") or 0) / 1024**3)
    fig, ax1 = plt.subplots(figsize=(8, 4.2))
    ax1.plot(xs, vms, color="tab:blue", label="live VMs")
    if any(vmax):
        ax1.axhline(vmax[-1], color="tab:blue", ls="--", alpha=0.5, label="VM budget")
    ax1.set_xlabel("episode time (s)")
    ax1.set_ylabel("live VMs")
    ax2 = ax1.twinx()
    ax2.plot(xs, ram, color="tab:orange", label="live RAM (GiB)")
    if any(rmax):
        ax2.axhline(rmax[-1], color="tab:orange", ls="--", alpha=0.5, label="RAM budget")
    ax2.set_ylabel("live RAM (GiB)")
    h1, l1 = ax1.get_legend_handles_labels()
    h2, l2 = ax2.get_legend_handles_labels()
    ax1.legend(h1 + h2, l1 + l2, loc="upper left")
    ax1.set_title("Tree utilization vs TreeBudget")
    fig.tight_layout()
    fig.savefig(dest, dpi=140)
    plt.close(fig)


def plot_fork_latency(rows: list[dict[str, Any]], dest: Path) -> None:
    ms = []
    for r in rows:
        if r.get("tool") != "fork_batch" or not r.get("ok"):
            continue
        if r.get("latency_ns") is not None:
            ms.append(int(r["latency_ns"]) / 1e6)
        else:
            ms.append(float(r.get("latency_s") or 0) * 1000)
    fig, ax = plt.subplots(figsize=(8, 4.2))
    if ms:
        ax.hist(ms, bins=min(12, max(3, len(ms))), color="tab:green", edgecolor="white")
    ax.set_xlabel("tree_fork_batch latency (ms)")
    ax.set_ylabel("count")
    ax.set_title(f"Fork latency distribution (n={len(ms)})")
    fig.tight_layout()
    fig.savefig(dest, dpi=140)
    plt.close(fig)


def plot_hypotheses(rows: list[dict[str, Any]], dest: Path) -> None:
    by_arm: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for r in rows:
        by_arm[str(r.get("arm") or "fork")].append(r)
    fig, ax = plt.subplots(figsize=(8, 4.2))
    labels, hyps, walls = [], [], []
    for arm, rs in sorted(by_arm.items()):
        t0 = _t0(rs)
        wall = max(float(r["ts"]) for r in rs) - t0
        n = sum(
            len((r.get("result") or {}).get("forks") or [])
            for r in rs
            if r.get("tool") == "fork_batch" and r.get("ok")
        )
        labels.append(arm)
        hyps.append(n)
        walls.append(wall)
    x = range(len(labels))
    ax.bar([i - 0.18 for i in x], hyps, 0.35, label="hypotheses (forks)", color="tab:purple")
    ax2 = ax.twinx()
    ax2.bar([i + 0.18 for i in x], walls, 0.35, label="wall-clock (s)", color="tab:gray")
    ax.set_xticks(list(x), labels)
    ax.set_ylabel("forks")
    ax2.set_ylabel("wall-clock (s)")
    ax.set_title("Hypotheses × wall-clock (fork-tree vs baseline)")
    h1, l1 = ax.get_legend_handles_labels()
    h2, l2 = ax2.get_legend_handles_labels()
    ax.legend(h1 + h2, l1 + l2, loc="upper left")
    fig.tight_layout()
    fig.savefig(dest, dpi=140)
    plt.close(fig)


def plot_blast(rows: list[dict[str, Any]], dest: Path) -> None:
    by_arm: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for r in rows:
        by_arm[str(r.get("arm") or "fork")].append(r)
    fig, ax = plt.subplots(figsize=(8, 4.2))
    labels, ttr, on_src, on_br = [], [], [], []
    for arm, rs in sorted(by_arm.items()):
        dests = [r for r in rs if r.get("destructive") and r.get("ok")]
        t0 = _t0(rs)
        first = min((float(r["ts"]) for r in dests), default=None)
        labels.append(arm)
        ttr.append((first - t0) if first is not None else 0.0)
        on_src.append(sum(1 for r in dests if r.get("on_source")))
        on_br.append(sum(1 for r in dests if not r.get("on_source")))
    x = range(len(labels))
    ax.bar([i - 0.2 for i in x], on_br, 0.2, label="destructive on fork", color="tab:green")
    ax.bar(list(x), on_src, 0.2, label="destructive on source", color="tab:red")
    ax2 = ax.twinx()
    ax2.plot(list(x), ttr, "o-", color="tab:blue", label="time-to-first-remediation (s)")
    ax.set_xticks(list(x), labels)
    ax.set_ylabel("destructive actions")
    ax2.set_ylabel("seconds")
    ax.set_title("Time-to-remediation + blast radius")
    h1, l1 = ax.get_legend_handles_labels()
    h2, l2 = ax2.get_legend_handles_labels()
    ax.legend(h1 + h2, l1 + l2, loc="upper left")
    fig.tight_layout()
    fig.savefig(dest, dpi=140)
    plt.close(fig)


def plot_ram_per_branch(rows: list[dict[str, Any]], dest: Path) -> None:
    t0 = _t0(rows)
    xs, per = [], []
    for r in rows:
        u = r.get("usage") or {}
        live_n = int(u.get("live_node_count") or 0)
        ram = int(u.get("live_ram_bytes") or 0)
        if live_n < 1:
            continue
        xs.append(float(r["ts"]) - t0)
        per.append((ram / live_n) / 1024**3)
    fig, ax = plt.subplots(figsize=(8, 4.2))
    ax.plot(xs, per, color="tab:brown")
    ax.set_xlabel("episode time (s)")
    ax.set_ylabel("RAM per live node (GiB)")
    ax.set_title("RAM per branch over time (CoW sharing)")
    fig.tight_layout()
    fig.savefig(dest, dpi=140)
    plt.close(fig)


def render(rows: list[dict[str, Any]], out: Path) -> list[Path]:
    out.mkdir(parents=True, exist_ok=True)
    writers = (
        plot_utilization,
        plot_fork_latency,
        plot_hypotheses,
        plot_blast,
        plot_ram_per_branch,
    )
    written = []
    for name, fn in zip(PLOTS, writers):
        dest = out / name
        fn(rows, dest)
        written.append(dest)
    return written


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("logs", nargs="*", type=Path, help="JSONL files")
    p.add_argument("--dir", type=Path, help="directory of *.jsonl")
    p.add_argument("--out", type=Path, default=Path(__file__).resolve().parent / "plots")
    return p.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    ns = parse_args(argv)
    paths = list(ns.logs)
    if ns.dir:
        paths.extend(sorted(ns.dir.glob("*.jsonl")))
    if not paths:
        raise SystemExit("pass JSONL files or --dir")
    written = render(load_jsonl(paths), ns.out)
    for p in written:
        print(p)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
