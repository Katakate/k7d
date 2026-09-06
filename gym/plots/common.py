"""JSONL schema + stats for the five 27a-inc2 plots. Stdlib only.

THIS MODULE DOES NOT TRAIN A MODEL.

Default inputs are the synthetic fixture in
`gym/tests/test_plots.py` (`synthetic=true` on every row). Those
rewards, checkpoints, and the "learning curve" are invented so the
renderer and tests have a shape to lock. They are not a GRPO run.

Unlabeled JSONL is rejected. Live trainer logs must set the same
`live_run_id` on every row and must not set `synthetic`. See
`gym/plots/README.md`.
"""

from __future__ import annotations

import json
import math
import statistics
from collections import defaultdict
from pathlib import Path
from typing import Any, Iterable

REQUIRED = (
    "start_mode",
    "checkpoint",
    "fault_id",
    "group_id",
    "member",
    "reward",
)

# Stamped on every synthetic figure. Do not weaken this string.
SYNTHETIC_BANNER = "FIXTURE -- SYNTHETIC, NOT A TRAINED POLICY"

START_MODES = ("fork", "reset")
# €40/month bare-metal box → USD-ish dollars per hour for the cost plot.
# 40 EUR ≈ 44 USD; 730 hours/month.
BOX_USD_PER_MONTH = 44.0
HOURS_PER_MONTH = 730.0
USD_PER_HOUR = BOX_USD_PER_MONTH / HOURS_PER_MONTH


def provenance(eps: list[dict[str, Any]]) -> str:
    """`synthetic` or `live`. Unlabeled or mixed rows fail loud."""
    if not eps:
        raise ValueError("provenance on empty episode list")
    syn = [bool(r.get("synthetic")) for r in eps]
    live_ids = {str(r.get("live_run_id") or "") for r in eps}
    live_ids.discard("")
    if all(syn) and not live_ids:
        return "synthetic"
    if not any(syn) and len(live_ids) == 1 and all(r.get("live_run_id") for r in eps):
        return "live"
    raise ValueError(
        "episode JSONL has no honest provenance: every row needs "
        "synthetic=true (fixture in gym/tests/test_plots.py) XOR the "
        "same live_run_id. Unlabeled rows are rejected so a fixture "
        "cannot be plotted as a training result. See gym/plots/README.md"
    )


def eval_kind(eps: list[dict[str, Any]]) -> str:
    """How the live rows were produced. Fixture rows are `fixture`."""
    if provenance(eps) == "synthetic":
        return "fixture"
    kinds = {str(r.get("eval_kind") or "") for r in eps}
    kinds.discard("")
    if kinds == {"gym-scripted"}:
        return "gym-scripted"
    if kinds == {"grpo"}:
        return "grpo"
    raise ValueError(
        "live JSONL needs eval_kind=gym-scripted (no GPU, scripted "
        f"noop/oracle) or eval_kind=grpo (k7rl). got {sorted(kinds)}"
    )


def live_run_id(eps: list[dict[str, Any]]) -> str | None:
    kind = provenance(eps)
    if kind != "live":
        return None
    return str(eps[0]["live_run_id"])


def figure_title(
    kind: str,
    caption: str,
    *,
    live_run_id: str | None = None,
    eval_kind: str = "grpo",
) -> str:
    """Two-line title. Synthetic / gym-scripted banners stay red."""
    if kind == "synthetic":
        return f"{SYNTHETIC_BANNER}\n{caption}"
    if kind == "live":
        if not live_run_id:
            raise ValueError("live figure_title needs live_run_id")
        if eval_kind == "gym-scripted":
            return (
                f"LIVE GYM EVAL {live_run_id} -- NOT A TRAINED POLICY\n"
                f"{caption}"
            )
        if eval_kind == "grpo":
            return f"LIVE GRPO {live_run_id}\n{caption}"
        raise ValueError(f"unknown eval_kind {eval_kind!r}")
    raise ValueError(f"unknown provenance {kind!r}")


PLOT_STEMS = (
    "headline-reward-std",
    "noise-floor",
    "learning-curve",
    "throughput-cost",
    "score-drift",
)


def plot_filenames(
    kind: str, *, skip: tuple[str, ...] = ()
) -> tuple[str, ...]:
    """On-disk names include FIXTURE or LIVE so a file pick is honest."""
    if kind == "synthetic":
        tag = "FIXTURE"
    elif kind == "live":
        tag = "LIVE"
    else:
        raise ValueError(f"unknown provenance {kind!r}")
    out = []
    for i, stem in enumerate(PLOT_STEMS, 1):
        if stem in skip:
            continue
        out.append(f"{i:02d}-{tag}-{stem}.png")
    return tuple(out)


def load_jsonl(paths: Iterable[Path]) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for p in paths:
        if not p.is_file():
            raise ValueError(f"jsonl missing: {p}")
        for i, line in enumerate(p.read_text().splitlines(), 1):
            if not line.strip():
                continue
            try:
                rec = json.loads(line)
            except json.JSONDecodeError as e:
                raise ValueError(f"{p}:{i}: {e}") from e
            if not isinstance(rec, dict):
                raise ValueError(f"{p}:{i}: expected object")
            rec["_src"] = str(p)
            rows.append(rec)
    if not rows:
        raise ValueError("no records in jsonl inputs")
    return rows


def playbook_rows(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Playbook exam rows. Missing playbook payload is loud."""
    from playbook import require_playbook_payload

    out = []
    for r in rows:
        if r.get("scoreboard") != "playbook":
            continue
        require_playbook_payload(r)
        if "reward" not in r or "start_mode" not in r:
            raise ValueError(f"playbook row missing reward/start_mode: {r!r}"[:240])
        out.append(r)
    return out


def incident_rows(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Incident harvest rows. Missing incident payload is loud."""
    from soak import require_incident_payload

    out = []
    for r in rows:
        if r.get("scoreboard") != "incident":
            continue
        require_incident_payload(r)
        if "reward" not in r or "start_mode" not in r:
            raise ValueError(
                f"incident row missing reward/start_mode: {r!r}"[:240]
            )
        out.append(r)
    return out


def std_solve_vs_turn(eps: list[dict[str, Any]]) -> dict[str, Any]:
    """Within-group std of t_solve. Unsolved members count as T_BUDGET_S."""
    from soak import T_BUDGET_S

    def pick(r: dict[str, Any]) -> float:
        inc = r["incident"]
        if inc.get("soak_clean") and inc.get("t_solve_s") is not None:
            return float(inc["t_solve_s"])
        return float(T_BUDGET_S)

    return _std_vs_turn(eps, pick)


def selfplay_rows(
    rows: list[dict[str, Any]], role: str | None = None
) -> list[dict[str, Any]]:
    """Self-play harvest rows (26a-inc11). Missing selfplay payload is
    loud. Filter by role when given (advantage is within-role)."""
    from soak import require_selfplay_payload, require_selfplay_role

    if role is not None:
        require_selfplay_role(role)
    out = []
    for r in rows:
        if r.get("scoreboard") != "selfplay":
            continue
        sp = require_selfplay_payload(r)
        if "reward" not in r or "start_mode" not in r:
            raise ValueError(
                f"selfplay row missing reward/start_mode: {r!r}"[:240]
            )
        if role is not None and str(sp["role"]) != role:
            continue
        out.append(r)
    return out


def selfplay_std_vs_turn(
    eps: list[dict[str, Any]], role: str
) -> dict[str, Any]:
    """Within-group std(R) vs turn for one role, fork vs reset, equal n."""
    picked = selfplay_rows(eps, role)
    if not picked:
        raise ValueError(f"no selfplay rows for role={role!r}")
    return _std_vs_turn(picked, lambda r: float(r["reward"]))


def std_vs_turn(eps: list[dict[str, Any]]) -> dict[str, Any]:
    """Within-group reward std at each turn. Equal n or loud.

    Reward is passed/t, so one miss shrinks as 1/t. For the undiluted
    count see `std_passed_vs_turn`.
    """
    return _std_vs_turn(eps, lambda r: float(r["reward"]))


def std_passed_vs_turn(eps: list[dict[str, Any]]) -> dict[str, Any]:
    """Within-group std of pages passed (not divided by t)."""
    return _std_vs_turn(eps, lambda r: float(r["playbook"]["passed"]))


def _std_vs_turn(
    eps: list[dict[str, Any]], pick
) -> dict[str, Any]:
    if not eps:
        raise ValueError("std vs turn on empty playbook rows")
    by_turn: dict[int, list[dict[str, Any]]] = defaultdict(list)
    for r in eps:
        turn = int(r.get("turn") if r.get("turn") is not None else r.get("step") or 0)
        if turn < 1:
            raise ValueError(f"playbook row needs turn>=1: {r!r}"[:200])
        by_turn[turn].append(r)
    ns: set[int] = set()
    series: dict[str, list[tuple[int, float]]] = {"fork": [], "reset": []}
    for turn in sorted(by_turn):
        slice_ = by_turn[turn]
        n = require_equal_group_n(slice_)
        ns.add(n)
        stds = _group_stds(slice_, pick)
        for mode in START_MODES:
            vals = []
            for (m, _ckpt), xs in stds.items():
                if m == mode:
                    vals.extend(xs)
            if not vals:
                raise ValueError(f"turn {turn}: missing {mode} arm")
            mu, _ = mean_std(vals)
            series[mode].append((turn, mu))
    if len(ns) != 1:
        raise ValueError(
            f"std-vs-turn n changed across turns: {sorted(ns)} "
            "(do not mix harvests)"
        )
    return {"n": next(iter(ns)), "series": series}


def episodes(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Rows that carry a per-member reward (trainer or gym eval)."""
    out = []
    for r in rows:
        if r.get("kind") not in (None, "", "episode"):
            if "reward" not in r:
                continue
        missing = [k for k in REQUIRED if k not in r]
        if missing:
            raise ValueError(f"episode missing {missing}: {r!r}"[:240])
        if r["start_mode"] not in START_MODES:
            raise ValueError(f"start_mode must be fork|reset, got {r['start_mode']!r}")
        if r.get("scoreboard") in ("playbook", "incident"):
            continue
        out.append(r)
    if not out:
        raise ValueError("no episode rows (need start_mode/checkpoint/reward)")
    provenance(out)  # unlabeled JSONL is a hard error
    return out


def group_ns(eps: list[dict[str, Any]]) -> dict[tuple[str, str, str], int]:
    """Member count per (start_mode, checkpoint, group_id)."""
    buckets: dict[tuple[str, str, str], int] = defaultdict(int)
    for r in eps:
        key = (str(r["start_mode"]), str(r["checkpoint"]), str(r["group_id"]))
        buckets[key] += 1
    return dict(buckets)


def min_group_n(eps: list[dict[str, Any]]) -> int:
    sizes = list(group_ns(eps).values())
    if not sizes:
        raise ValueError("min_group_n on empty episode list")
    return min(sizes)


def require_equal_group_n(eps: list[dict[str, Any]]) -> int:
    """Headline/noise-floor refuse n=8 vs n=2. Harvest the same n."""
    sizes = set(group_ns(eps).values())
    if not sizes:
        raise ValueError("require_equal_group_n on empty episode list")
    if len(sizes) != 1:
        raise ValueError(
            f"headline/noise-floor need the same n on every group, "
            f"got {sorted(sizes)}. Sequential reset at --reset-n="
            f"--fork-n; do not subsample (|Δ|√((n-1)/n²) is not a result)"
        )
    n = next(iter(sizes))
    if n < 2:
        raise ValueError(f"within-group std needs n>=2, got {n}")
    return n


def match_group_n(
    eps: list[dict[str, Any]], n: int | None = None
) -> list[dict[str, Any]]:
    """Keep members 0..n-1. History/tests only — plots must not use this.
    """
    if n is None:
        n = min_group_n(eps)
    if n < 2:
        raise ValueError(f"match_group_n needs n>=2, got {n}")
    small = [k for k, v in group_ns(eps).items() if v < n]
    if small:
        raise ValueError(f"group smaller than n={n}: {small}")
    out = []
    for r in eps:
        try:
            idx = int(r["member"])
        except (KeyError, TypeError, ValueError) as e:
            raise ValueError(f"episode missing integer member: {r!r}"[:200]) from e
        if idx < n:
            out.append(r)
    for k, v in group_ns(out).items():
        if v != n:
            raise ValueError(
                f"match_group_n: {k} has {v} members after keeping "
                f"member<{n} (indexes must be 0..n_orig-1)"
            )
    return out


def group_stds(eps: list[dict[str, Any]]) -> dict[tuple[str, str], list[float]]:
    """Within-group reward std, keyed by (start_mode, checkpoint)."""
    return _group_stds(eps, lambda r: float(r["reward"]))


def _group_stds(eps: list[dict[str, Any]], pick) -> dict[tuple[str, str], list[float]]:
    buckets: dict[tuple[str, str, str], list[float]] = defaultdict(list)
    for r in eps:
        key = (str(r["start_mode"]), str(r["checkpoint"]), str(r["group_id"]))
        buckets[key].append(float(pick(r)))
    out: dict[tuple[str, str], list[float]] = defaultdict(list)
    for (mode, ckpt, _gid), vals in buckets.items():
        if len(vals) < 2:
            raise ValueError(
                f"group {mode}/{ckpt} has n={len(vals)}; within-group std "
                "needs ≥2 members (do not silently drop)"
            )
        out[(mode, ckpt)].append(statistics.pstdev(vals))
    return dict(out)


def mean_std(xs: list[float]) -> tuple[float, float]:
    if not xs:
        raise ValueError("mean_std on empty")
    if len(xs) == 1:
        return xs[0], 0.0
    return statistics.mean(xs), statistics.pstdev(xs)


def learning_series(
    eps: list[dict[str, Any]],
) -> dict[tuple[str, str], list[tuple[int, float, float]]]:
    """(step, mean_reward, group_std) per (start_mode, fault_id)."""
    by: dict[tuple[str, str, int], list[float]] = defaultdict(list)
    for r in eps:
        step = int(r.get("step") if r.get("step") is not None else r.get("steps") or 0)
        key = (str(r["start_mode"]), str(r["fault_id"]), step)
        by[key].append(float(r["reward"]))
    series: dict[tuple[str, str], list[tuple[int, float, float]]] = defaultdict(list)
    for (mode, fault, step), rewards in sorted(by.items()):
        mu, sd = mean_std(rewards)
        series[(mode, fault)].append((step, mu, sd))
    return dict(series)


def throughput(eps: list[dict[str, Any]]) -> dict[str, dict[str, float]]:
    """episodes/min and $/1k-episodes per start_mode."""
    by: dict[str, list[float]] = defaultdict(list)
    for r in eps:
        wall = r.get("wall_s")
        if wall is None:
            wall = r.get("episode_s")
        if wall is None:
            raise ValueError(f"episode missing wall_s: {r.get('group_id')}")
        by[str(r["start_mode"])].append(float(wall))
    out: dict[str, dict[str, float]] = {}
    for mode, walls in by.items():
        mean_s = statistics.mean(walls)
        if mean_s <= 0:
            raise ValueError(f"{mode}: mean wall_s={mean_s} (must be > 0)")
        epm = 60.0 / mean_s
        per_1k_hours = (1000.0 / epm) / 60.0
        out[mode] = {
            "n": float(len(walls)),
            "mean_wall_s": mean_s,
            "episodes_per_min": epm,
            "usd_per_1k_episodes": per_1k_hours * USD_PER_HOUR,
            "usd_per_hour": USD_PER_HOUR,
        }
    return out


def score_values(
    eps: list[dict[str, Any]], *, phase: str
) -> dict[str, list[float]]:
    """Reward distributions for a named checkpoint/phase."""
    out: dict[str, list[float]] = defaultdict(list)
    for r in eps:
        p = str(r.get("phase") or r.get("checkpoint") or "")
        if p != phase:
            continue
        out[str(r["start_mode"])].append(float(r["reward"]))
    return dict(out)


def drift_phases(
    eps: list[dict[str, Any]],
) -> tuple[str, str, dict[str, list[float]], dict[str, list[float]]]:
    """Prefer scripted noop/oracle; fall back to untrained/final."""
    for a, b in (("noop", "oracle"), ("untrained", "final")):
        early = score_values(eps, phase=a)
        late = score_values(eps, phase=b)
        if early and late:
            return a, b, early, late
    raise ValueError(
        "score-drift needs checkpoint=noop+oracle (gym-scripted) or "
        "untrained+final (trained). Do not invent a learning curve."
    )


def headline_claim(stds: dict[tuple[str, str], list[float]]) -> dict[str, Any]:
    """fork-group std vs reset-group std on shared checkpoints."""
    ckpts = sorted({c for (_m, c) in stds})
    rows = []
    for c in ckpts:
        f = stds.get(("fork", c))
        r = stds.get(("reset", c))
        if not f or not r:
            raise ValueError(
                f"checkpoint {c!r} missing an arm "
                f"(fork={f is not None} reset={r is not None}) — "
                "serialize: train once, eval both modes"
            )
        fm, fs = mean_std(f)
        rm, rs = mean_std(r)
        rows.append(
            {
                "checkpoint": c,
                "fork_std_mean": fm,
                "reset_std_mean": rm,
                "ratio": (fm / rm) if rm else math.inf,
            }
        )
    return {"checkpoints": rows}
