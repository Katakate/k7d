#!/usr/bin/env python3
"""Render the five GRPO plots from episode JSONL.

*****************************************************************************
FAKE BY DEFAULT. THIS SCRIPT DOES NOT TRAIN ANYTHING.

The JSONL that `gym/tests/test_plots.py` feeds this renderer is a
SYNTHETIC FIXTURE. Rewards, "untrained/mid/final" checkpoints, and
the learning-curve walk are invented to lock the plot schema. No
GRPO run, no LoRA, no k7rl checkpoint exists in this repo.

Every synthetic figure is stamped:

    FIXTURE -- SYNTHETIC, NOT A TRAINED POLICY

in the title, in the filename (`*-FIXTURE-*.png`), and in
`gym/plots/README.md`. Unlabeled JSONL is rejected so a fixture
cannot be exported as a training result.

Live trainer logs (when they exist) must set the same `live_run_id`
on every row and must not set `synthetic`. Those files are tagged
LIVE. Until k7rl writes that JSONL, treat every plot from this
folder as fake.

Read `gym/plots/README.md` before you put one of these figures
anywhere a stranger will see it.
*****************************************************************************

Headline: within-group reward std, fork vs reset, same checkpoints.
matplotlib when installed; SVG fallback so `make gym-test` stays
stdlib-only on the gym process itself.
"""

from __future__ import annotations

import argparse
import html
import sys
from pathlib import Path
from typing import Any

_GYM = Path(__file__).resolve().parents[1]
if str(_GYM) not in sys.path:
    sys.path.insert(0, str(_GYM))

from plots.common import (  # noqa: E402
    PLOT_STEMS,
    SYNTHETIC_BANNER,
    USD_PER_HOUR,
    drift_phases,
    episodes,
    eval_kind as jsonl_eval_kind,
    figure_title,
    group_stds,
    headline_claim,
    incident_rows,
    playbook_rows,
    require_equal_group_n,
    learning_series,
    live_run_id,
    load_jsonl,
    plot_filenames,
    provenance,
    selfplay_std_vs_turn,
    std_passed_vs_turn,
    std_solve_vs_turn,
    std_vs_turn,
    throughput,
)


def _try_mpl():
    try:
        import matplotlib

        matplotlib.use("Agg")
        import matplotlib.pyplot as plt

        return plt
    except ImportError:
        return None


def _kind(eps: list[dict[str, Any]]) -> tuple[str, str | None, str]:
    return provenance(eps), live_run_id(eps), jsonl_eval_kind(eps)


def _title(kind: str, caption: str, run_id: str | None, ekind: str) -> str:
    return figure_title(kind, caption, live_run_id=run_id, eval_kind=ekind)


def _stamp_mpl(
    fig: Any,
    ax: Any,
    kind: str,
    caption: str,
    run_id: str | None,
    ekind: str,
) -> None:
    banner, sub = _title(kind, caption, run_id, ekind).split("\n", 1)
    # gym-scripted is live measurements, not a trained policy.
    color = "tab:red" if kind == "synthetic" or ekind == "gym-scripted" else "darkgreen"
    fig.suptitle(banner, color=color, fontweight="bold", fontsize=11)
    ax.set_title(sub)
    footer = "Do not publish as a training result."
    if kind == "live" and ekind == "grpo":
        footer = f"live_run_id={run_id}"
    elif kind == "live":
        footer = f"live_run_id={run_id} eval_kind={ekind} -- not GRPO"
    fig.text(0.5, 0.01, footer, ha="center", fontsize=8, color=color)


def _svg(path: Path, title: str, bars: list[tuple[str, float]], ylabel: str) -> None:
    w, h = 720, 400
    mx = max((v for _n, v in bars), default=1.0) or 1.0
    left, bottom, rw, rh = 70, 50, 600, 240
    fake = SYNTHETIC_BANNER in title
    fill = "#b71c1c" if fake else "#1b5e20"
    parts = [
        f'<svg xmlns="http://www.w3.org/2000/svg" width="{w}" height="{h}">',
        f'<rect x="0" y="0" width="{w}" height="44" fill="{fill}"/>',
        f'<text x="12" y="20" font-size="13" fill="#fff">{html.escape(title.splitlines()[0])}</text>',
        f'<text x="12" y="38" font-size="12" fill="#fff">{html.escape(title.splitlines()[-1] if chr(10) in title else "")}</text>',
        f'<text x="12" y="200" font-size="11" transform="rotate(-90 12 200)">{html.escape(ylabel)}</text>',
    ]
    bw = rw / max(len(bars), 1) * 0.7
    for i, (name, val) in enumerate(bars):
        x = left + i * (rw / max(len(bars), 1)) + 8
        bh = (val / mx) * rh
        y = bottom + (rh - bh)
        parts.append(
            f'<rect x="{x:.1f}" y="{y:.1f}" width="{bw:.1f}" height="{bh:.1f}" fill="#4c78a8"/>'
        )
        parts.append(
            f'<text x="{x:.1f}" y="{bottom + rh + 16}" font-size="10">{html.escape(name)}</text>'
        )
        parts.append(
            f'<text x="{x:.1f}" y="{y - 4:.1f}" font-size="10">{val:.4g}</text>'
        )
    parts.append("</svg>")
    dest = path.with_suffix(".svg") if path.suffix == ".png" else path
    dest.write_text("\n".join(parts))


def plot_headline(eps: list[dict[str, Any]], dest: Path) -> dict[str, Any]:
    kind, run_id, ekind = _kind(eps)
    n = require_equal_group_n(eps)
    stds = group_stds(eps)
    claim = headline_claim(stds)
    claim["n"] = n
    plt = _try_mpl()
    labels, fork_y, reset_y = [], [], []
    for row in claim["checkpoints"]:
        labels.append(row["checkpoint"])
        fork_y.append(row["fork_std_mean"])
        reset_y.append(row["reset_std_mean"])
    caption = (
        f"Headline: fork vs reset reward std (same checkpoints, n={n})"
        if ekind != "gym-scripted"
        else (
            "Headline: fork vs reset reward std; "
            f"n={n} both arms; "
            f"{eps[0].get('scoreboard', 'health')} scoreboard; "
            "noop+oracle (no GPU, not GRPO)"
        )
    )
    if plt is None:
        bars = []
        for lab, f, r in zip(labels, fork_y, reset_y):
            bars.append((f"{lab}/fork", f))
            bars.append((f"{lab}/reset", r))
        _svg(dest, _title(kind, caption, run_id, ekind), bars, "std")
        return claim
    fig, ax = plt.subplots(figsize=(8, 4.6))
    x = range(len(labels))
    ax.bar([i - 0.18 for i in x], fork_y, 0.35, label="fork", color="tab:green")
    ax.bar([i + 0.18 for i in x], reset_y, 0.35, label="reset", color="tab:red")
    ax.set_xticks(list(x), labels)
    ax.set_ylabel("within-group reward std")
    _stamp_mpl(fig, ax, kind, caption, run_id, ekind)
    ax.legend()
    fig.tight_layout(rect=(0, 0.04, 1, 0.90))
    fig.savefig(dest, dpi=140)
    plt.close(fig)
    return claim


def plot_noise_floor(eps: list[dict[str, Any]], dest: Path) -> dict[str, Any]:
    kind, run_id, ekind = _kind(eps)
    noop = [r for r in eps if str(r["checkpoint"]) == "noop"]
    if not noop:
        raise ValueError("noise-floor plot needs checkpoint=noop episodes")
    n = require_equal_group_n(noop)
    stds = group_stds(noop)
    claim = headline_claim(stds)
    claim["n"] = n
    plt = _try_mpl()
    f = claim["checkpoints"][0]["fork_std_mean"]
    r = claim["checkpoints"][0]["reset_std_mean"]
    caption = f"Noise-floor ablation (identical no-op policies, n={n} both arms)"
    if plt is None:
        _svg(
            dest,
            _title(kind, caption, run_id, ekind),
            [("fork", f), ("reset", r)],
            "std",
        )
        return claim
    fig, ax = plt.subplots(figsize=(8, 4.6))
    ax.bar(["fork", "reset"], [f, r], color=["tab:green", "tab:red"])
    ax.set_ylabel("within-group reward std")
    _stamp_mpl(fig, ax, kind, caption, run_id, ekind)
    fig.tight_layout(rect=(0, 0.04, 1, 0.90))
    fig.savefig(dest, dpi=140)
    plt.close(fig)
    return claim


def plot_learning(eps: list[dict[str, Any]], dest: Path) -> dict[str, Any]:
    kind, run_id, ekind = _kind(eps)
    series = learning_series(eps)
    plt = _try_mpl()
    caption = (
        "Invented reward walk, not a trained learning curve"
        if kind == "synthetic"
        else "Learning curve (group-std band)"
    )
    if plt is None:
        bars = []
        for (mode, fault), pts in sorted(series.items()):
            if pts:
                bars.append((f"{mode}/{fault}/last", pts[-1][1]))
        _svg(dest, _title(kind, caption, run_id, ekind), bars, "reward")
        return {"series_keys": [f"{m}/{f}" for m, f in series]}
    fig, ax = plt.subplots(figsize=(8, 4.6))
    for (mode, fault), pts in sorted(series.items()):
        xs = [p[0] for p in pts]
        ys = [p[1] for p in pts]
        band = [p[2] for p in pts]
        ax.plot(xs, ys, label=f"{mode}/{fault}")
        lo = [y - b for y, b in zip(ys, band)]
        hi = [y + b for y, b in zip(ys, band)]
        ax.fill_between(xs, lo, hi, alpha=0.15)
    ax.set_xlabel(
        "training steps (fixture schedule)"
        if kind == "synthetic"
        else "training steps"
    )
    ax.set_ylabel(
        "mean containment reward (invented)"
        if kind == "synthetic"
        else "mean containment reward"
    )
    _stamp_mpl(fig, ax, kind, caption, run_id, ekind)
    ax.legend()
    fig.tight_layout(rect=(0, 0.04, 1, 0.90))
    fig.savefig(dest, dpi=140)
    plt.close(fig)
    return {"series_keys": [f"{m}/{f}" for m, f in series]}


def plot_throughput(eps: list[dict[str, Any]], dest: Path) -> dict[str, Any]:
    kind, run_id, ekind = _kind(eps)
    tput = throughput(eps)
    plt = _try_mpl()
    modes = sorted(tput)
    epm = [tput[m]["episodes_per_min"] for m in modes]
    cost = [tput[m]["usd_per_1k_episodes"] for m in modes]
    caption = (
        f"Throughput + cost (€40/mo box ≈ ${USD_PER_HOUR:.3f}/h); "
        "fixture walls, not a training bill"
        if kind == "synthetic"
        else (
            f"Throughput + cost (€40/mo box ≈ ${USD_PER_HOUR:.3f}/h); "
            "lease-to-score wall"
            + (", no GPU" if ekind == "gym-scripted" else "")
        )
    )
    if plt is None:
        bars = [(f"{m} epm", tput[m]["episodes_per_min"]) for m in modes]
        bars += [(f"{m} $/1k", tput[m]["usd_per_1k_episodes"]) for m in modes]
        _svg(dest, _title(kind, caption, run_id, ekind), bars, "value")
        return tput
    fig, ax = plt.subplots(figsize=(8, 4.6))
    x = range(len(modes))
    ax.bar([i - 0.18 for i in x], epm, 0.35, label="episodes/min", color="tab:blue")
    ax2 = ax.twinx()
    ax2.bar([i + 0.18 for i in x], cost, 0.35, label="$/1k episodes", color="tab:orange")
    ax.set_xticks(list(x), modes)
    ax.set_ylabel("episodes/min")
    ax2.set_ylabel("USD per 1k episodes")
    _stamp_mpl(fig, ax, kind, caption, run_id, ekind)
    h1, l1 = ax.get_legend_handles_labels()
    h2, l2 = ax2.get_legend_handles_labels()
    ax.legend(h1 + h2, l1 + l2, loc="upper left")
    fig.tight_layout(rect=(0, 0.04, 1, 0.90))
    fig.savefig(dest, dpi=140)
    plt.close(fig)
    return tput


def plot_std_vs_turn(rows: list[dict[str, Any]], dest: Path) -> dict[str, Any]:
    """Within-group reward std versus playbook turn. Not GRPO."""
    pb = playbook_rows(rows)
    if not pb:
        raise ValueError("std-vs-turn needs scoreboard=playbook rows")
    kind, run_id, ekind = _kind(pb)
    claim = std_vs_turn(pb)
    n = claim["n"]
    caption = (
        f"Playbook std vs turn (same exam, n={n} both arms, not GRPO)"
    )
    fork = claim["series"]["fork"]
    reset = claim["series"]["reset"]
    plt = _try_mpl()
    if plt is None:
        bars = [(f"t{t}/fork", s) for t, s in fork]
        bars += [(f"t{t}/reset", s) for t, s in reset]
        _svg(dest, _title(kind, caption, run_id, ekind), bars, "std")
        return claim
    fig, ax = plt.subplots(figsize=(8, 4.6))
    ax.plot([t for t, _ in fork], [s for _, s in fork], "o-", label="fork", color="tab:green")
    ax.plot(
        [t for t, _ in reset], [s for _, s in reset], "o-", label="reset", color="tab:red"
    )
    ax.set_xlabel("turn (page)")
    ax.set_ylabel("within-group reward std")
    ax.set_xticks([t for t, _ in fork])
    _stamp_mpl(fig, ax, kind, caption, run_id, ekind)
    ax.legend()
    fig.tight_layout(rect=(0, 0.04, 1, 0.90))
    out = dest if dest.suffix else dest.with_suffix(".png")
    fig.savefig(out, dpi=140)
    plt.close(fig)
    return claim


def plot_std_passed_vs_turn(rows: list[dict[str, Any]], dest: Path) -> dict[str, Any]:
    """Within-group std of pages passed (not passed/t). Not GRPO."""
    pb = playbook_rows(rows)
    if not pb:
        raise ValueError("std-passed-vs-turn needs scoreboard=playbook rows")
    kind, run_id, ekind = _kind(pb)
    claim = std_passed_vs_turn(pb)
    n = claim["n"]
    caption = (
        f"Playbook std of pages passed vs turn "
        f"(not divided by t, n={n} both arms, not GRPO)"
    )
    fork = claim["series"]["fork"]
    reset = claim["series"]["reset"]
    plt = _try_mpl()
    if plt is None:
        bars = [(f"t{t}/fork", s) for t, s in fork]
        bars += [(f"t{t}/reset", s) for t, s in reset]
        _svg(dest, _title(kind, caption, run_id, ekind), bars, "std(pages passed)")
        return claim
    fig, ax = plt.subplots(figsize=(8, 4.6))
    ax.plot([t for t, _ in fork], [s for _, s in fork], "o-", label="fork", color="tab:green")
    ax.plot(
        [t for t, _ in reset], [s for _, s in reset], "o-", label="reset", color="tab:red"
    )
    ax.set_xlabel("turn (page)")
    ax.set_ylabel("within-group std of pages passed")
    ax.set_xticks([t for t, _ in fork])
    _stamp_mpl(fig, ax, kind, caption, run_id, ekind)
    ax.legend()
    fig.tight_layout(rect=(0, 0.04, 1, 0.90))
    out = dest if dest.suffix else dest.with_suffix(".png")
    fig.savefig(out, dpi=140)
    plt.close(fig)
    return claim


def plot_incident_std_vs_turn(
    rows: list[dict[str, Any]], dest: Path
) -> dict[str, Any]:
    """Within-group std(R) versus incident turn. Not GRPO. Not pages/t."""
    inc = incident_rows(rows)
    if not inc:
        raise ValueError("std-r-vs-turn needs scoreboard=incident rows")
    kind, run_id, ekind = _kind(inc)
    claim = std_vs_turn(inc)
    n = claim["n"]
    caption = (
        f"Incident std(R) vs turn (relay soak, n={n} both arms, not GRPO)"
    )
    fork = claim["series"]["fork"]
    reset = claim["series"]["reset"]
    plt = _try_mpl()
    if plt is None:
        bars = [(f"t{t}/fork", s) for t, s in fork]
        bars += [(f"t{t}/reset", s) for t, s in reset]
        _svg(dest, _title(kind, caption, run_id, ekind), bars, "std(R)")
        return claim
    fig, ax = plt.subplots(figsize=(8, 4.6))
    ax.plot([t for t, _ in fork], [s for _, s in fork], "o-", label="fork", color="tab:green")
    ax.plot(
        [t for t, _ in reset], [s for _, s in reset], "o-", label="reset", color="tab:red"
    )
    ax.set_xlabel("turn")
    ax.set_ylabel("within-group std(R)")
    ax.set_xticks([t for t, _ in fork])
    _stamp_mpl(fig, ax, kind, caption, run_id, ekind)
    ax.legend()
    fig.tight_layout(rect=(0, 0.04, 1, 0.90))
    out = dest if dest.suffix else dest.with_suffix(".png")
    fig.savefig(out, dpi=140)
    plt.close(fig)
    return claim


def plot_incident_solve_std_vs_turn(
    rows: list[dict[str, Any]], dest: Path
) -> dict[str, Any]:
    """Within-group std of t_solve versus turn. Unsolved = T_BUDGET_S."""
    inc = incident_rows(rows)
    if not inc:
        raise ValueError("std-solve-vs-turn needs scoreboard=incident rows")
    kind, run_id, ekind = _kind(inc)
    claim = std_solve_vs_turn(inc)
    n = claim["n"]
    caption = (
        f"Incident std(t_solve) vs turn (n={n} both arms, not GRPO)"
    )
    fork = claim["series"]["fork"]
    reset = claim["series"]["reset"]
    plt = _try_mpl()
    if plt is None:
        bars = [(f"t{t}/fork", s) for t, s in fork]
        bars += [(f"t{t}/reset", s) for t, s in reset]
        _svg(dest, _title(kind, caption, run_id, ekind), bars, "std(t_solve s)")
        return claim
    fig, ax = plt.subplots(figsize=(8, 4.6))
    ax.plot([t for t, _ in fork], [s for _, s in fork], "o-", label="fork", color="tab:green")
    ax.plot(
        [t for t, _ in reset], [s for _, s in reset], "o-", label="reset", color="tab:red"
    )
    ax.set_xlabel("turn")
    ax.set_ylabel("within-group std(t_solve) seconds")
    ax.set_xticks([t for t, _ in fork])
    _stamp_mpl(fig, ax, kind, caption, run_id, ekind)
    ax.legend()
    fig.tight_layout(rect=(0, 0.04, 1, 0.90))
    out = dest if dest.suffix else dest.with_suffix(".png")
    fig.savefig(out, dpi=140)
    plt.close(fig)
    return claim


def plot_selfplay_std_vs_turn(
    rows: list[dict[str, Any]], dest: Path, *, role: str
) -> dict[str, Any]:
    """Within-group std(R) vs turn for one self-play role, fork vs reset,
    equal n. Not GRPO. Signed reward (blue = R(soak_clean),
    red = R(not soak_clean)), same soak judge."""
    sp = selfplay_std_vs_turn(rows, role)
    n = sp["n"]
    kind, run_id, ekind = _kind(selfplay_role_rows(rows, role))
    caption = (
        f"Self-play std(R) vs turn — role={role} (n={n} both arms, not GRPO)"
    )
    fork = sp["series"]["fork"]
    reset = sp["series"]["reset"]
    plt = _try_mpl()
    if plt is None:
        bars = [(f"t{t}/fork", s) for t, s in fork]
        bars += [(f"t{t}/reset", s) for t, s in reset]
        _svg(dest, _title(kind, caption, run_id, ekind), bars, "std(R)")
        return sp
    fig, ax = plt.subplots(figsize=(8, 4.6))
    ax.plot([t for t, _ in fork], [s for _, s in fork], "o-", label="fork", color="tab:green")
    ax.plot(
        [t for t, _ in reset], [s for _, s in reset], "o-", label="reset", color="tab:red"
    )
    ax.set_xlabel("turn")
    ax.set_ylabel(f"within-group std(R) [{role}]")
    ax.set_xticks([t for t, _ in fork])
    _stamp_mpl(fig, ax, kind, caption, run_id, ekind)
    ax.legend()
    fig.tight_layout(rect=(0, 0.04, 1, 0.90))
    out = dest if dest.suffix else dest.with_suffix(".png")
    fig.savefig(out, dpi=140)
    plt.close(fig)
    return sp


def selfplay_role_rows(
    rows: list[dict[str, Any]], role: str
) -> list[dict[str, Any]]:
    from plots.common import selfplay_rows as _sp

    return _sp(rows, role)


def plot_drift(eps: list[dict[str, Any]], dest: Path) -> dict[str, Any]:
    kind, run_id, ekind = _kind(eps)
    early_n, late_n, early, late = drift_phases(eps)
    plt = _try_mpl()
    summary = {
        early_n: {k: sum(v) / len(v) for k, v in early.items() if v},
        late_n: {k: sum(v) / len(v) for k, v in late.items() if v},
    }
    if kind == "synthetic":
        caption = "Score drift early vs late (invented checkpoint rewards)"
    elif ekind == "gym-scripted":
        caption = (
            f"Score drift {early_n} vs {late_n}; "
            f"{eps[0].get('scoreboard', 'health')} scoreboard "
            "(scripted, no GPU, not Tetragon-trained)"
        )
    else:
        caption = f"Score drift {early_n} vs {late_n} (trained policy)"
    if plt is None:
        bars = [(f"{early_n}/{k}", mu) for k, mu in summary[early_n].items()]
        bars += [(f"{late_n}/{k}", mu) for k, mu in summary[late_n].items()]
        _svg(
            dest,
            _title(kind, caption, run_id, ekind),
            bars,
            "mean reward",
        )
        return summary
    fig, ax = plt.subplots(figsize=(8, 4.6))
    data, labels = [], []
    for phase, bag in ((early_n, early), (late_n, late)):
        for mode in sorted(bag):
            data.append(bag[mode])
            labels.append(f"{phase}/{mode}")
    ax.violinplot(data, showmeans=True)
    ax.set_xticks(list(range(1, len(labels) + 1)), labels, rotation=15)
    ax.set_ylabel(
        "containment reward (invented)"
        if kind == "synthetic"
        else "containment reward"
    )
    _stamp_mpl(fig, ax, kind, caption, run_id, ekind)
    fig.tight_layout(rect=(0, 0.04, 1, 0.90))
    fig.savefig(dest, dpi=140)
    plt.close(fig)
    return summary


_WRITERS = {
    "headline-reward-std": plot_headline,
    "noise-floor": plot_noise_floor,
    "learning-curve": plot_learning,
    "throughput-cost": plot_throughput,
    "score-drift": plot_drift,
}


def render(
    rows: list[dict[str, Any]],
    out: Path,
    *,
    skip: tuple[str, ...] = (),
) -> list[Path]:
    out.mkdir(parents=True, exist_ok=True)
    eps = episodes(rows)
    kind, _run_id, ekind = _kind(eps)
    skip_stems = list(skip)
    if ekind == "gym-scripted" and "learning-curve" not in skip_stems:
        skip_stems.append("learning-curve")
    if (
        "noise-floor" not in skip_stems
        and not any(str(r.get("checkpoint")) == "noop" for r in eps)
    ):
        skip_stems.append("noise-floor")
    written = []
    names = plot_filenames(kind, skip=tuple(skip_stems))
    stems = [s for s in PLOT_STEMS if s not in skip_stems]
    for name, stem in zip(names, stems):
        dest = out / name
        _WRITERS[stem](eps, dest)
        if dest.is_file():
            written.append(dest)
        else:
            alt = dest.with_suffix(".svg")
            if not alt.is_file():
                raise RuntimeError(f"plot writer produced neither {dest} nor {alt}")
            written.append(alt)
    return written


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("logs", nargs="*", type=Path)
    p.add_argument("--dir", type=Path)
    p.add_argument("--out", type=Path, default=Path(__file__).resolve().parent / "out")
    return p.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    ns = parse_args(argv)
    paths = list(ns.logs)
    if ns.dir:
        paths.extend(sorted(ns.dir.glob("*.jsonl")))
    if not paths:
        raise SystemExit("pass JSONL files or --dir")
    for p in render(load_jsonl(paths), ns.out):
        print(p)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
