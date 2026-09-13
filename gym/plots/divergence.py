"""Render shared vs diverged RAM from harness JSONL (stdlib SVG).

Each record is one `tree_nodes` sample:

    {ts, workload, phase, usage, configured_ram_bytes,
     diverged_ram_bytes, shared_ram_bytes, shared_frac, ...}

`usage.live_ram_bytes` is the same field k7view's RAM gauge reads.
"""

from __future__ import annotations

import argparse
import json
import sys
from collections import defaultdict
from pathlib import Path
from typing import Any

WORKLOADS = ("idle", "k8s", "kafka")
COLORS = {
    "idle": ("#4c9a4c", "#8fd18f"),
    "k8s": ("#2a6f97", "#89c2d9"),
    "kafka": ("#9b2226", "#e07a5f"),
}


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
            if not isinstance(rec, dict):
                raise SystemExit(f"{p}:{i}: expected object")
            rows.append(rec)
    if not rows:
        raise SystemExit("no records in jsonl inputs")
    return rows


def derive(usage: dict[str, Any], memory_mb: int) -> dict[str, float]:
    """Shared vs diverged from a `TreeUsageInfo` plus known guest size."""
    live_vms = int(usage.get("live_vm_count") or 0)
    diverged = int(usage.get("live_ram_bytes") or 0)
    configured = live_vms * memory_mb * 1024 * 1024
    shared = max(0, configured - diverged)
    frac = (shared / configured) if configured else 0.0
    return {
        "configured_ram_bytes": float(configured),
        "diverged_ram_bytes": float(diverged),
        "shared_ram_bytes": float(shared),
        "shared_frac": frac,
    }


def summarize_siblings(rows: list[dict[str, Any]]) -> dict[str, dict[str, float]]:
    """Per-workload parent vs child dirty bytes at first and last sibling sample."""
    out: dict[str, dict[str, float]] = {}
    by_wl: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for r in rows:
        if r.get("phase") != "sibling_div":
            continue
        wl = str(r.get("workload") or "")
        if wl:
            by_wl[wl].append(r)
    for wl, rs in by_wl.items():
        rs = sorted(rs, key=lambda r: float(r.get("t_after_fork_s") or 0.0))
        out[wl] = {
            "n_samples": float(len(rs)),
            "parent_bytes_t0": float(rs[0]["parent_dirty_bytes"]),
            "child_bytes_t0": float(rs[0]["child_dirty_bytes"]),
            "parent_bytes_last": float(rs[-1]["parent_dirty_bytes"]),
            "child_bytes_last": float(rs[-1]["child_dirty_bytes"]),
            "t_last_s": float(rs[-1].get("t_after_fork_s") or 0.0),
        }
    return out


def summarize(rows: list[dict[str, Any]]) -> dict[str, dict[str, float]]:
    """Per-workload shared_frac at first post-fork sample and at ~30s."""
    out: dict[str, dict[str, float]] = {}
    by_wl: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for r in rows:
        if r.get("phase") != "post_fork":
            continue
        wl = str(r.get("workload") or "")
        if wl:
            by_wl[wl].append(r)
    for wl, rs in by_wl.items():
        rs = sorted(rs, key=lambda r: float(r["ts"]))
        t0 = float(rs[0]["ts"])
        first = float(rs[0]["shared_frac"])
        late = first
        for r in rs:
            if float(r["ts"]) - t0 >= 25:
                late = float(r["shared_frac"])
                break
        else:
            late = float(rs[-1]["shared_frac"])
        out[wl] = {
            "shared_frac_t0": first,
            "shared_frac_t30": late,
            "n_samples": float(len(rs)),
        }
    return out


def _series(rows: list[dict[str, Any]], workload: str) -> tuple[list[float], list[float], list[float]]:
    xs, shared_g, div_g = [], [], []
    picked = [r for r in rows if r.get("workload") == workload and "shared_ram_bytes" in r]
    if not picked:
        return xs, shared_g, div_g
    t0 = min(float(r["ts"]) for r in picked)
    for r in sorted(picked, key=lambda r: float(r["ts"])):
        xs.append(float(r["ts"]) - t0)
        shared_g.append(float(r["shared_ram_bytes"]) / 1024**3)
        div_g.append(float(r["diverged_ram_bytes"]) / 1024**3)
    return xs, shared_g, div_g


def _poly(xs: list[float], ys: list[float], x0: float, y0: float, sx: float, sy: float) -> str:
    if not xs:
        return ""
    pts = " ".join(f"{x0 + x * sx:.1f},{y0 - y * sy:.1f}" for x, y in zip(xs, ys))
    return pts


def _sibling_series(
    rows: list[dict[str, Any]], workload: str
) -> tuple[list[float], list[float], list[float]]:
    picked = [
        r
        for r in rows
        if r.get("workload") == workload
        and r.get("phase") == "sibling_div"
        and "parent_dirty_bytes" in r
        and "child_dirty_bytes" in r
    ]
    if not picked:
        return [], [], []
    xs, parent, child = [], [], []
    for r in sorted(picked, key=lambda r: float(r.get("t_after_fork_s") or 0.0)):
        xs.append(float(r.get("t_after_fork_s") or 0.0))
        parent.append(float(r["parent_dirty_bytes"]) / 1024**3)
        child.append(float(r["child_dirty_bytes"]) / 1024**3)
    return xs, parent, child


def render_sibling_svg(rows: list[dict[str, Any]], dest: Path) -> Path:
    """Three stacked panels: parent vs child dirty vs the same memory.bin."""
    width, panel_h, left, right, top = 860, 180, 64, 24, 36
    height = top + panel_h * 3 + 48
    parts = [
        f'<svg xmlns="http://www.w3.org/2000/svg" width="{width}" height="{height}" '
        f'font-family="ui-sans-serif,system-ui,sans-serif" font-size="12">',
        f'<rect width="{width}" height="{height}" fill="#0f1115"/>',
        '<text x="16" y="22" fill="#e8e8e8" font-size="15">'
        "Sibling dirty after fork (parent vs child popcount vs memory.bin)</text>",
    ]
    plot_w = width - left - right
    plot_h = panel_h - 44
    for i, wl in enumerate(WORKLOADS):
        xs, parent, child = _sibling_series(rows, wl)
        y_base = top + i * panel_h
        xmax = max(xs) if xs else 1.0
        ymax = max([1.0] + parent + child)
        sx = plot_w / xmax if xmax else 1
        sy = plot_h / ymax if ymax else 1
        x0, y0 = left, y_base + 28 + plot_h
        parent_c, child_c = COLORS[wl]
        parts.append(
            f'<text x="{left}" y="{y_base + 16}" fill="#c8c8c8" font-size="13">{wl}</text>'
        )
        parts.append(
            f'<rect x="{left}" y="{y_base + 28}" width="{plot_w}" height="{plot_h}" '
            f'fill="#1a1d24" stroke="#333"/>'
        )
        if xs:
            parts.append(
                f'<polyline fill="none" stroke="{parent_c}" stroke-width="2" '
                f'points="{_poly(xs, parent, x0, y0, sx, sy)}"/>'
            )
            parts.append(
                f'<polyline fill="none" stroke="{child_c}" stroke-width="2" '
                f'stroke-dasharray="5 3" points="{_poly(xs, child, x0, y0, sx, sy)}"/>'
            )
            parts.append(
                f'<text x="{width - right - 8}" y="{y_base + 16}" fill="#aaa" '
                f'text-anchor="end">'
                f"parent {parent[0]:.2f}→{parent[-1]:.2f}  "
                f"child {child[0]:.2f}→{child[-1]:.2f} GiB</text>"
            )
        parts.append(
            f'<text x="{left}" y="{y_base + panel_h - 4}" fill="#888">0s</text>'
        )
        parts.append(
            f'<text x="{left + plot_w}" y="{y_base + panel_h - 4}" fill="#888" '
            f'text-anchor="end">{xmax:.0f}s</text>'
        )
        parts.append(
            f'<text x="8" y="{y_base + 28 + 8}" fill="#888">{ymax:.2f} GiB</text>'
        )
    parts.append(
        f'<text x="{left}" y="{height - 14}" fill="#888">'
        f'<tspan fill="{COLORS["idle"][0]}">━ parent (probe-fork + suspend)</tspan>   '
        f'<tspan fill="{COLORS["idle"][1]}">┄ child (one suspend per sibling)</tspan>   '
        "popcount vs the shared memory.bin — not XOR uniqueness</text>"
    )
    parts.append("</svg>")
    dest.parent.mkdir(parents=True, exist_ok=True)
    dest.write_text("\n".join(parts) + "\n")
    return dest


def render_svg(rows: list[dict[str, Any]], dest: Path) -> Path:
    """Three stacked panels: idle / k8s / kafka, shared vs diverged GiB."""
    width, panel_h, left, right, top = 860, 180, 64, 24, 36
    height = top + panel_h * 3 + 48
    parts = [
        f'<svg xmlns="http://www.w3.org/2000/svg" width="{width}" height="{height}" '
        f'font-family="ui-sans-serif,system-ui,sans-serif" font-size="12">',
        f'<rect width="{width}" height="{height}" fill="#0f1115"/>',
        '<text x="16" y="22" fill="#e8e8e8" font-size="15">'
        "CoW shared vs diverged RAM after fork (tree usage.live_ram_bytes)</text>",
    ]
    plot_w = width - left - right
    plot_h = panel_h - 44
    for i, wl in enumerate(WORKLOADS):
        xs, sh, dv = _series(rows, wl)
        y_base = top + i * panel_h
        xmax = max(xs) if xs else 1.0
        ymax = max([1.0] + sh + dv)
        sx = plot_w / xmax if xmax else 1
        sy = plot_h / ymax if ymax else 1
        x0, y0 = left, y_base + 28 + plot_h
        shared_c, div_c = COLORS[wl]
        parts.append(
            f'<text x="{left}" y="{y_base + 16}" fill="#c8c8c8" font-size="13">{wl}</text>'
        )
        parts.append(
            f'<rect x="{left}" y="{y_base + 28}" width="{plot_w}" height="{plot_h}" '
            f'fill="#1a1d24" stroke="#333"/>'
        )
        if xs:
            parts.append(
                f'<polyline fill="none" stroke="{shared_c}" stroke-width="2" '
                f'points="{_poly(xs, sh, x0, y0, sx, sy)}"/>'
            )
            parts.append(
                f'<polyline fill="none" stroke="{div_c}" stroke-width="2" '
                f'stroke-dasharray="5 3" points="{_poly(xs, dv, x0, y0, sx, sy)}"/>'
            )
            frac0 = sh[0] / (sh[0] + dv[0]) if (sh[0] + dv[0]) else 0
            frac1 = sh[-1] / (sh[-1] + dv[-1]) if (sh[-1] + dv[-1]) else 0
            parts.append(
                f'<text x="{width - right - 8}" y="{y_base + 16}" fill="#aaa" '
                f'text-anchor="end">shared {frac0:.0%} → {frac1:.0%}</text>'
            )
        parts.append(
            f'<text x="{left}" y="{y_base + panel_h - 4}" fill="#888">0s</text>'
        )
        parts.append(
            f'<text x="{left + plot_w}" y="{y_base + panel_h - 4}" fill="#888" '
            f'text-anchor="end">{xmax:.0f}s</text>'
        )
        parts.append(
            f'<text x="8" y="{y_base + 28 + 8}" fill="#888">{ymax:.2f} GiB</text>'
        )
    parts.append(
        f'<text x="{left}" y="{height - 14}" fill="#888">'
        f'<tspan fill="{COLORS["idle"][0]}">━ shared</tspan>   '
        f'<tspan fill="{COLORS["idle"][1]}">┄ diverged (dirty pages)</tspan>   '
        "configured = live_vm_count × 2048 MiB</text>"
    )
    parts.append("</svg>")
    dest.parent.mkdir(parents=True, exist_ok=True)
    dest.write_text("\n".join(parts) + "\n")
    return dest


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("logs", nargs="*", type=Path)
    p.add_argument("--out", type=Path, default=Path(__file__).resolve().parent / "divergence.svg")
    return p.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    ns = parse_args(argv)
    if not ns.logs:
        raise SystemExit("pass JSONL files")
    dest = render_svg(load_jsonl(ns.logs), ns.out)
    print(dest)
    return 0


if __name__ == "__main__":
    sys.exit(main())
