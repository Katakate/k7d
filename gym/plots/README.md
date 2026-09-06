# THESE GRPO PLOTS ARE FAKE UNTIL k7rl LOGS SAY OTHERWISE

**No model has been trained in this repository.**

This warning is about the five **GRPO** figures
(`render.py` / `common.py` / `test_plots.py`). It is not about the
dirty-page SVGs (`divergence.py`), which render harness JSONL
(shared vs diverged RAM), not rewards.

`gym/plots/` GRPO scripts are a renderer and a schema lock. They are
not a training-results folder. The figures you get from
`gym/tests/test_plots.py` are a **synthetic fixture**: hand-chosen
means and spreads so the five scripts have something to draw and so
`make gym-test` can assert "fork std << reset std" as a *shape*, not
as a measured GRPO outcome.

If you saw a "learning curve" from this folder, that curve was
**invented**. There is no LoRA, no GRPO step, no checkpoint, no
GPU run behind it. Publishing that figure as a training result is
a lie.

## What is invented vs what is reused

| Number on a fixture plot | Honest status |
|---|---|
| Rewards, `untrained` / `mid` / `final` / `noop` walk | **Invented** in `fixture_rows()` |
| Within-group stds derived from those rewards | **Invented** (arithmetic on invented rewards) |
| Learning-curve x-axis "training steps" | **Invented schedule** (0 / 50 / 100) |
| `wall_s=1.17` (fork) and `wall_s=48.2` (reset) | **Reused** from measured cluster bring-up / fork walls — real seconds, paired here with fake rewards |
| `$ / 1k episodes` | **Arithmetic** on those reused walls, not an invoice from a training job |

## How we keep this from looking real

1. Every fixture row sets `synthetic=true`.
2. Unlabeled JSONL is a hard error (`provenance()` in `common.py`).
3. Every synthetic figure title starts with
   `FIXTURE -- SYNTHETIC, NOT A TRAINED POLICY`.
4. Filenames contain `FIXTURE` (`01-FIXTURE-headline-reward-std.png`,
   …). A live trainer dump, when it exists, must set one
   `live_run_id` on every row and gets `LIVE` in the filename instead.
5. This README sits next to the scripts on purpose.

## Live gym-scripted eval (no GPU)

`gym/plots/harvest.py` leases real Ubuntu groups, scores them, and
writes `eval_kind=gym-scripted` JSONL. Policies are **noop** and
**oracle** (`good_fix_hint`). That is enough for four of the five
figures:

| Figure | Real without GRPO? |
|---|---|
| Headline fork vs reset std | Yes (same scripted policy on both arms). Renderer **refuses** unequal n (do not compare n=8 fork to n=2 reset). Harvest `--reset-n` sequentially to match `--fork-n`. |
| Noise floor | Yes (noop only) |
| Throughput + cost | Yes (lease-to-score wall) |
| Score drift | Yes (noop vs oracle). Title must not say "trained". |
| Learning curve | **No.** Harvest refuses to draw one. |
| Playbook std vs turn | Yes (`--scoreboard playbook --turns 20`). Same exam on every member. Not GRPO. |

Banners say `LIVE GYM EVAL -- NOT A TRAINED POLICY`. Default
scoreboard is `health`. `--scoreboard tetragon` installs Cilium +
Tetragon on the Ubuntu gym source and scores the
event-diff. Missing helm or missing Tetragon pods are loud — never
a silent health score labeled Tetragon.

The first measured set is `testdata/gym-20260823-eval3.jsonl`
(40 rows, Ubuntu `kill-member-0`, health scoreboard) rendered as
`testdata/live-eval3/0{1,2,4,5}-LIVE-*.png`. Tetragon
`testdata/gym-20260823-tetra3.jsonl` (40 rows, fork+reset, real
`fd_install`) is rendered as `testdata/live-tetra3/0{1,2,4,5}-LIVE-*.svg`.
Both arms show the same 0.8/1.0 split — not CoW noise, not GRPO.
Raw fork std 0.066 vs reset 0.100 is n=8 vs n=2 on that bit
(`|Δ|√((n-1)/n²)`). Those JSONLs no longer render a headline.
Fair harvest is n=8 both arms (`tetra-churn`, sequential reset):
`testdata/gym-20260824-churn8.jsonl` (64 rows) rendered as
`testdata/live-churn8/0{1,2,4,5}-LIVE-*.svg`. Headline is
0.066 = 0.066 on the same 0.8/1.0 bit. Do not train.
The 20-page exam is the playbook scoreboard
(`--scoreboard playbook`). Live JSONL
`testdata/gym-20260824-turns20.jsonl` (640 rows) and
`testdata/live-turns20/std-vs-turn.svg` (passed/t) and
`std-passed-vs-turn.svg` (raw pages passed, not divided by t).
Turn-20 std 0.0108 / 0.0373; undiluted count 0.217 / 0.745
(fork / reset, n=8). Those numbers stay with the playbook harvest,
separate from tetra3/churn8. Still not a trained policy.
The relay soak harvest is
`--scoreboard incident --fault-id relay`. Live JSONL
`testdata/gym-20260827-relaysoak.jsonl` (192 rows) and
`testdata/live-relaysoak/std-r-vs-turn.svg` plus
`std-solve-vs-turn.svg`. Oracle 48/48 soak-clean both arms,
shallow 0/48, turn-3 std(R) is a tie. Do not train. Do not quote
as tetra3 / churn8 / turns20.

## Live GRPO data (sibling repo, not this folder)

A trained learning curve belongs in `k7rl` (`k7-slime` is retired).
Those rows need `live_run_id` plus `eval_kind=grpo` and must **not**
set `synthetic`. Only then may a figure omit the FIXTURE / gym-eval
banner.

The first trained dump is historical `k7-slime`
`live/grpo-20260823T181800Z/` (`eval-both.jsonl`, n=8 fork+reset).
New dumps live in k7rl. Render the historical one from this repo:

```
python3 gym/plots/render.py \
  /path/to/k7-slime-dev/live/grpo-20260823T181800Z/eval-both.jsonl \
  --out /path/to/k7-slime-dev/live/grpo-20260823T181800Z/plots
```

Do not copy trainer JSONL into `gym/plots/`. Filenames use `LIVE`,
not `FIXTURE`.

Do not treat any figure in this folder as a trained policy
unless the JSONL sets `eval_kind=grpo` and a `live_run_id`.
