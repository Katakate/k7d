"""27a-inc2 plot stats + render from SYNTHETIC fixture JSONL. No KVM.

These rows are invented. They are not a GRPO run. See gym/plots/README.md.
"""

from __future__ import annotations

import json
import statistics
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from plots.common import (
    SYNTHETIC_BANNER,
    episodes,
    eval_kind,
    figure_title,
    group_stds,
    headline_claim,
    load_jsonl,
    match_group_n,
    min_group_n,
    plot_filenames,
    provenance,
    std_vs_turn,
    throughput,
)
from plots.harvest import parse_args as harvest_args
from plots.render import plot_headline, render


def _ep(**kw):
    row = {
        "kind": "episode",
        "start_mode": "fork",
        "checkpoint": "untrained",
        "fault_id": "kill-member-0",
        "group_id": "g0",
        "member": 0,
        "reward": 0.4,
        "wall_s": 1.17,
        "step": 0,
        "synthetic": True,
        "terms": {
            "liveness": 1.0,
            "workload_ready": 1.0,
            "source_intact": 1.0,
            "contained": 0.0,
            "restored": 0.0,
        },
    }
    row.update(kw)
    return row


def _group(mode: str, ckpt: str, gid: str, rewards: list[float], **kw) -> list[dict]:
    wall = 1.17 if mode == "fork" else 48.2
    return [
        _ep(
            start_mode=mode,
            checkpoint=ckpt,
            group_id=gid,
            member=i,
            reward=r,
            wall_s=wall,
            **kw,
        )
        for i, r in enumerate(rewards)
    ]


def fixture_rows() -> list[dict]:
    """Invented rewards. Same checkpoints across arms. Fork std << reset std.

    Not a trained policy. `synthetic=true` is mandatory provenance.
    """
    rows: list[dict] = []
    # untrained / mid / final / noop × fork + reset, two groups of n=8.
    cells = {
        ("fork", "untrained"): (0.40, 0.01),
        ("reset", "untrained"): (0.40, 0.12),
        ("fork", "mid"): (0.62, 0.02),
        ("reset", "mid"): (0.58, 0.14),
        ("fork", "final"): (0.80, 0.015),
        ("reset", "final"): (0.74, 0.13),
        ("fork", "noop"): (0.80, 0.008),
        ("reset", "noop"): (0.80, 0.11),
    }
    for (mode, ckpt), (mu, spread) in cells.items():
        for g in range(2):
            rewards = [mu + spread * ((i - 3.5) / 3.5) for i in range(8)]
            step = {"untrained": 0, "mid": 50, "final": 100, "noop": 0}[ckpt]
            rows.extend(
                _group(mode, ckpt, f"{mode}-{ckpt}-g{g}", rewards, step=step)
            )
    return rows


class TestPlotStats(unittest.TestCase):
    def test_headline_fork_std_below_reset(self) -> None:
        eps = episodes(fixture_rows())
        claim = headline_claim(group_stds(eps))
        self.assertGreaterEqual(len(claim["checkpoints"]), 4)
        for row in claim["checkpoints"]:
            self.assertLess(
                row["fork_std_mean"],
                row["reset_std_mean"],
                msg=row,
            )

    def test_throughput_reset_is_slower(self) -> None:
        t = throughput(episodes(fixture_rows()))
        self.assertGreater(t["fork"]["episodes_per_min"], 40.0)
        self.assertLess(t["reset"]["episodes_per_min"], 2.0)
        self.assertGreater(
            t["reset"]["usd_per_1k_episodes"],
            t["fork"]["usd_per_1k_episodes"],
        )

    def test_missing_arm_is_loud(self) -> None:
        only_fork = [r for r in fixture_rows() if r["start_mode"] == "fork"]
        with self.assertRaises(ValueError) as ctx:
            headline_claim(group_stds(episodes(only_fork)))
        self.assertIn("missing an arm", str(ctx.exception))

    def test_unlabeled_jsonl_is_loud(self) -> None:
        rows = fixture_rows()
        for r in rows:
            del r["synthetic"]
        with self.assertRaises(ValueError) as ctx:
            episodes(rows)
        self.assertIn("provenance", str(ctx.exception))

    def test_mixed_synthetic_and_live_is_loud(self) -> None:
        rows = fixture_rows()
        rows[0]["synthetic"] = False
        rows[0]["live_run_id"] = "run-1"
        with self.assertRaises(ValueError) as ctx:
            provenance(rows)
        self.assertIn("provenance", str(ctx.exception))

    def test_figure_title_stamps_fixture_banner(self) -> None:
        title = figure_title("synthetic", "Headline: fork vs reset")
        self.assertTrue(title.startswith(SYNTHETIC_BANNER))
        self.assertIn("NOT A TRAINED POLICY", title)

    def test_figure_title_gym_scripted_is_not_grpo(self) -> None:
        title = figure_title(
            "live",
            "Headline",
            live_run_id="gym-1",
            eval_kind="gym-scripted",
        )
        self.assertIn("NOT A TRAINED POLICY", title)
        self.assertNotIn("k7-slime", title)
        self.assertNotIn("k7rl", title)
        self.assertNotIn("LIVE GRPO", title)

    def test_figure_title_grpo_is_repo_neutral(self) -> None:
        title = figure_title(
            "live",
            "Headline",
            live_run_id="grpo-1",
            eval_kind="grpo",
        )
        self.assertTrue(title.startswith("LIVE GRPO grpo-1"))
        self.assertNotIn("k7-slime", title)
        self.assertNotIn("k7rl", title)


class TestRender(unittest.TestCase):
    def test_five_plots_from_jsonl(self) -> None:
        rows = fixture_rows()
        with tempfile.TemporaryDirectory() as td:
            src = Path(td) / "eval.jsonl"
            src.write_text("\n".join(json.dumps(r) for r in rows) + "\n")
            out = Path(td) / "plots"
            written = render(load_jsonl([src]), out)
            self.assertEqual(len(written), 5)
            names = {p.name for p in written}
            # png if matplotlib, svg fallback otherwise
            want = {
                n.replace(".png", p.suffix)
                for n, p in zip(plot_filenames("synthetic"), written)
            }
            self.assertEqual(names, want)
            for p in written:
                self.assertGreater(p.stat().st_size, 80)
                self.assertIn("FIXTURE", p.name)

    def test_readme_says_fake(self) -> None:
        readme = Path(__file__).resolve().parents[1] / "plots" / "README.md"
        text = readme.read_text()
        self.assertIn("THESE GRPO PLOTS ARE FAKE", text)
        self.assertIn("NOT A TRAINED POLICY", text)
        self.assertIn("invented", text.lower())

    def test_gym_scripted_skips_learning_curve(self) -> None:
        rows = []
        for mode, n in (("fork", 4), ("reset", 4)):
            for ckpt, mu in (("noop", 0.4), ("oracle", 0.7)):
                for g in range(2):
                    spread = 0.02 if mode == "fork" else 0.12
                    for i in range(n):
                        rows.append(
                            {
                                "kind": "episode",
                                "eval_kind": "gym-scripted",
                                "live_run_id": "gym-unit",
                                "start_mode": mode,
                                "checkpoint": ckpt,
                                "fault_id": "kill-member-0",
                                "group_id": f"{mode}-{ckpt}-g{g}",
                                "member": i,
                                "reward": mu + spread * ((i - (n - 1) / 2) / max(n - 1, 1)),
                                "wall_s": 1.2 if mode == "fork" else 48.0,
                                "step": 0,
                                "scoreboard": "health",
                            }
                        )
        with tempfile.TemporaryDirectory() as td:
            written = render(rows, Path(td))
            names = {p.name for p in written}
            self.assertTrue(any("LIVE" in n and "headline" in n for n in names))
            self.assertFalse(any("learning-curve" in n for n in names))
            self.assertEqual(len(written), 4)

    def test_grpo_live_filenames_use_live_tag(self) -> None:
        rows = []
        for mode in ("fork", "reset"):
            for ckpt, step, mu in (
                ("untrained", 0, 0.8),
                ("mid", 3, 0.9),
                ("final", 5, 1.0),
            ):
                for g in range(2):
                    for i in range(2):
                        rows.append(
                            {
                                "kind": "episode",
                                "eval_kind": "grpo",
                                "live_run_id": "grpo-unit",
                                "start_mode": mode,
                                "checkpoint": ckpt,
                                "phase": ckpt,
                                "fault_id": "kill-member-0",
                                "group_id": f"{mode}-{ckpt}-g{g}",
                                "member": i,
                                "reward": mu,
                                "wall_s": 1.2 if mode == "fork" else 48.0,
                                "step": step,
                            }
                        )
        eps = episodes(rows)
        self.assertEqual(provenance(eps), "live")
        self.assertEqual(eval_kind(eps), "grpo")
        with tempfile.TemporaryDirectory() as td:
            written = render(eps, Path(td))
            names = {p.name for p in written}
            self.assertEqual(len(written), 4)
            self.assertTrue(all("LIVE" in n for n in names))
            self.assertFalse(any("FIXTURE" in n for n in names))
            self.assertTrue(any("learning-curve" in n for n in names))
            self.assertFalse(any("noise-floor" in n for n in names))

    def test_live_eval3_jsonl_renders_four_not_five(self) -> None:
        src = (
            Path(__file__).resolve().parents[1]
            / "plots"
            / "testdata"
            / "gym-20260823-eval3.jsonl"
        )
        rows = load_jsonl([src])
        self.assertEqual(len(episodes(rows)), 40)
        self.assertEqual(provenance(episodes(rows)), "live")
        self.assertEqual(eval_kind(episodes(rows)), "gym-scripted")
        stds = group_stds(episodes(rows))
        fork_noop = statistics.mean(stds[("fork", "noop")])
        reset_noop = statistics.mean(stds[("reset", "noop")])
        # Raw n=8 vs n=2 on the same 0.4/0.8 bit — not a fair headline.
        self.assertAlmostEqual(fork_noop, 0.132287, places=4)
        self.assertAlmostEqual(reset_noop, 0.200000, places=4)
        matched = match_group_n(episodes(rows), min_group_n(episodes(rows)))
        mstds = group_stds(matched)
        self.assertAlmostEqual(statistics.mean(mstds[("fork", "noop")]), 0.2000, places=4)
        self.assertAlmostEqual(statistics.mean(mstds[("reset", "noop")]), 0.2000, places=4)
        from plots.common import require_equal_group_n

        with self.assertRaises(ValueError) as ctx:
            require_equal_group_n(episodes(rows))
        self.assertIn("same n", str(ctx.exception))
        with tempfile.TemporaryDirectory() as td:
            with self.assertRaises(ValueError):
                render(rows, Path(td))

    def test_live_tetra3_fork_has_kprobe(self) -> None:
        src = (
            Path(__file__).resolve().parents[1]
            / "plots"
            / "testdata"
            / "gym-20260823-tetra3.jsonl"
        )
        rows = load_jsonl([src])
        eps = episodes(rows)
        self.assertEqual(len(eps), 40)
        self.assertEqual({r["scoreboard"] for r in eps}, {"tetragon"})
        self.assertEqual({r["start_mode"] for r in eps}, {"fork", "reset"})
        self.assertEqual(eval_kind(eps), "gym-scripted")
        self.assertTrue(all("event_diff" in r for r in eps))
        m0 = next(
            r
            for r in eps
            if r["start_mode"] == "fork"
            and r["checkpoint"] == "noop"
            and r["member"] == 0
        )
        kinds = {e["kind"] for e in m0["event_diff"]["branch_only"]}
        self.assertIn("process_kprobe", kinds)
        self.assertEqual(m0["reward"], 0.8)
        sib = next(
            r
            for r in eps
            if r["start_mode"] == "fork"
            and r["checkpoint"] == "noop"
            and r["member"] == 1
        )
        self.assertEqual(sib["event_diff"]["branch_only"], [])
        self.assertEqual(sib["reward"], 1.0)
        rm0 = next(
            r
            for r in eps
            if r["start_mode"] == "reset"
            and r["checkpoint"] == "noop"
            and r["member"] == 0
        )
        self.assertIn(
            "process_kprobe",
            {e["kind"] for e in rm0["event_diff"]["branch_only"]},
        )
        self.assertEqual(rm0["reward"], 0.8)
        stds = group_stds(eps)
        # Raw: n=8 fork vs n=2 reset on the same 0.8/1.0 bit.
        self.assertAlmostEqual(statistics.mean(stds[("fork", "noop")]), 0.0661, places=3)
        self.assertAlmostEqual(statistics.mean(stds[("reset", "noop")]), 0.1000, places=3)
        from plots.common import require_equal_group_n

        with self.assertRaises(ValueError) as ctx:
            require_equal_group_n(eps)
        self.assertIn("same n", str(ctx.exception))

    def test_headline_plot_refuses_unequal_n(self) -> None:
        src = (
            Path(__file__).resolve().parents[1]
            / "plots"
            / "testdata"
            / "gym-20260823-tetra3.jsonl"
        )
        eps = episodes(load_jsonl([src]))
        with tempfile.TemporaryDirectory() as td:
            with self.assertRaises(ValueError) as ctx:
                plot_headline(eps, Path(td) / "01-LIVE-headline-reward-std.png")
        self.assertIn("same n", str(ctx.exception))

    def test_live_churn8_equal_n_is_a_tie(self) -> None:
        src = (
            Path(__file__).resolve().parents[1]
            / "plots"
            / "testdata"
            / "gym-20260824-churn8.jsonl"
        )
        from plots.common import require_equal_group_n

        eps = episodes(load_jsonl([src]))
        self.assertEqual(len(eps), 64)
        self.assertEqual({r["fault_id"] for r in eps}, {"tetra-churn"})
        self.assertEqual(require_equal_group_n(eps), 8)
        stds = group_stds(eps)
        self.assertAlmostEqual(statistics.mean(stds[("fork", "noop")]), 0.0661, places=3)
        self.assertAlmostEqual(statistics.mean(stds[("reset", "noop")]), 0.0661, places=3)
        with tempfile.TemporaryDirectory() as td:
            written = render(eps, Path(td))
            names = {p.name for p in written}
            self.assertTrue(any("LIVE" in n and "headline" in n for n in names))
            self.assertFalse(any("learning-curve" in n for n in names))
            self.assertEqual(len(written), 4)

    def test_should_reap_mcp_smoke_leftover(self) -> None:
        from plots.harvest import should_reap_tree

        self.assertTrue(should_reap_tree("gym-src-eval-tetra3"))
        self.assertTrue(should_reap_tree("gym-rst-x"))
        self.assertTrue(should_reap_tree("k7mcp-smoke-13509"))
        self.assertFalse(should_reap_tree("keep-me"))

    def test_reap_leftover_gym_disks(self) -> None:
        from plots.harvest import reap_leftover_gym_disks

        with tempfile.TemporaryDirectory() as td:
            d = Path(td)
            keep = d / "base.img"
            keep.write_bytes(b"x")
            gone = d / "ubuntu-gym-rst-1.img"
            gone.write_bytes(b"y")
            self.assertEqual(reap_leftover_gym_disks(d), 1)
            self.assertTrue(keep.is_file())
            self.assertFalse(gone.exists())

    def test_reset_tetragon_group_is_sequential_n1(self) -> None:
        from plots.harvest import one_reset_tetragon_group

        calls: list[tuple[int, str]] = []

        def fake_group(**kw):
            calls.append((kw["n"], kw["fault_id"]))
            return [
                {
                    "group_id": kw["group_id"],
                    "member": 0,
                    "fault_id": kw["fault_id"],
                    "reward": 1.0,
                }
            ]

        with mock.patch("plots.harvest.one_group", fake_group):
            rows = one_reset_tetragon_group(
                base="http://127.0.0.1:1",
                checkpoint="noop",
                n=2,
                group_id="g",
                fault_id="kill-member-0",
                live_run_id="r",
                ttl_s=10,
            )
        self.assertEqual(calls, [(1, "kill-member-0"), (1, "none")])
        self.assertEqual([r["member"] for r in rows], [0, 1])
        self.assertEqual({r["group_id"] for r in rows}, {"g"})
        self.assertEqual({r["fault_id"] for r in rows}, {"kill-member-0"})

    def test_harvest_gym_env_pins_scoreboard(self) -> None:
        from plots.harvest import gym_env

        env = gym_env(18080, "fork", "gym-src-x", "tetragon")
        self.assertEqual(env["GYM_SCOREBOARD"], "tetragon")
        self.assertEqual(env["GYM_START_MODE"], "fork")

    def test_harvest_accepts_tetragon_and_needs_helm(self) -> None:
        ns = harvest_args(
            ["--out", "/tmp/k7-harvest-test", "--scoreboard", "tetragon"]
        )
        self.assertEqual(ns.scoreboard, "tetragon")
        self.assertEqual(ns.fork_n, 8)
        self.assertEqual(ns.reset_n, 8)

    def test_harvest_playbook_turns_and_ready_gate(self) -> None:
        from plots.harvest import gym_env

        ns = harvest_args(
            [
                "--out",
                "/tmp/k7-harvest-playbook",
                "--scoreboard",
                "playbook",
                "--fault-id",
                "none",
                "--turns",
                "20",
                "--fork-n",
                "8",
                "--reset-n",
                "8",
            ]
        )
        self.assertEqual(ns.scoreboard, "playbook")
        self.assertEqual(ns.turns, 20)
        self.assertEqual(ns.fault_id, "none")
        env = gym_env(18080, "fork", "gym-src-x", "playbook")
        self.assertEqual(env["GYM_SCOREBOARD"], "playbook")
        self.assertEqual(env["GYM_READY_GATE"], "api")

    def test_harvest_incident_turns_and_ready_gate(self) -> None:
        from plots.harvest import gym_env

        ns = harvest_args(
            [
                "--out",
                "/tmp/k7-harvest-incident",
                "--scoreboard",
                "incident",
                "--fault-id",
                "relay",
                "--turns",
                "3",
                "--fork-n",
                "8",
                "--reset-n",
                "8",
            ]
        )
        self.assertEqual(ns.scoreboard, "incident")
        self.assertEqual(ns.turns, 3)
        self.assertEqual(ns.fault_id, "relay")
        env = gym_env(18080, "fork", "gym-src-x", "incident")
        self.assertEqual(env["GYM_SCOREBOARD"], "incident")
        self.assertEqual(env["GYM_READY_GATE"], "api")

    def test_harvest_incident_refuses_wrong_fault(self) -> None:
        from plots import harvest as harvest_mod

        with self.assertRaises((SystemExit, ValueError)) as ctx:
            harvest_mod.main(
                [
                    "--out",
                    "/tmp/k7-harvest-incident-bad",
                    "--scoreboard",
                    "incident",
                    "--fault-id",
                    "kill-member-0",
                    "--turns",
                    "3",
                ]
            )
        self.assertIn("relay", str(ctx.exception))

    def test_harvest_incident_refuses_unequal_n(self) -> None:
        from plots import harvest as harvest_mod

        with self.assertRaises(SystemExit) as ctx:
            harvest_mod.main(
                [
                    "--out",
                    "/tmp/k7-harvest-incident-unequal",
                    "--scoreboard",
                    "incident",
                    "--fault-id",
                    "relay",
                    "--turns",
                    "3",
                    "--fork-n",
                    "8",
                    "--reset-n",
                    "2",
                ]
            )
        self.assertIn("fork-n", str(ctx.exception).lower())

    def test_incident_std_vs_turn_equal_n(self) -> None:
        from plots.common import require_equal_group_n, std_solve_vs_turn, std_vs_turn
        from plots.render import (
            plot_incident_solve_std_vs_turn,
            plot_incident_std_vs_turn,
        )

        rows = []
        for mode, t_spread in (("fork", 0.2), ("reset", 2.0)):
            for ckpt, clean in (("oracle", True), ("shallow", False)):
                for g in range(2):
                    for turn in range(1, 4):
                        for i in range(8):
                            t_solve = 4.0 + t_spread * i
                            r = (1.0 - t_solve / 900.0) if clean else 0.0
                            rows.append(
                                {
                                    "kind": "episode",
                                    "eval_kind": "gym-scripted",
                                    "live_run_id": "gym-unit-relaysoak",
                                    "start_mode": mode,
                                    "checkpoint": ckpt,
                                    "fault_id": "relay",
                                    "group_id": f"{mode}-{ckpt}-g{g}",
                                    "member": i,
                                    "reward": r,
                                    "wall_s": 1.0,
                                    "step": turn,
                                    "turn": turn,
                                    "scoreboard": "incident",
                                    "incident": {
                                        "turn": turn,
                                        "t_solve_s": t_solve,
                                        "soak_clean": clean,
                                        "layer_gates": {},
                                    },
                                }
                            )
        t1 = [r for r in rows if r["turn"] == 1]
        self.assertEqual(require_equal_group_n(t1), 8)
        claim = std_vs_turn(rows)
        self.assertEqual(claim["n"], 8)
        solve = std_solve_vs_turn(rows)
        self.assertEqual(solve["n"], 8)
        fork_r = next(s for t, s in claim["series"]["fork"] if t == 3)
        reset_r = next(s for t, s in claim["series"]["reset"] if t == 3)
        self.assertGreater(reset_r, fork_r)
        with tempfile.TemporaryDirectory() as td:
            dest = Path(td) / "std-r-vs-turn.svg"
            plot_incident_std_vs_turn(rows, dest)
            self.assertTrue(dest.is_file() or dest.with_suffix(".png").is_file())
            dest_s = Path(td) / "std-solve-vs-turn.svg"
            plot_incident_solve_std_vs_turn(rows, dest_s)
            self.assertTrue(
                dest_s.is_file() or dest_s.with_suffix(".png").is_file()
            )

    def test_harvest_playbook_refuses_inject(self) -> None:
        from plots import harvest as harvest_mod

        with self.assertRaises((SystemExit, ValueError)) as ctx:
            harvest_mod.main(
                [
                    "--out",
                    "/tmp/k7-harvest-playbook-inject",
                    "--scoreboard",
                    "playbook",
                    "--fault-id",
                    "kill-member-0",
                    "--turns",
                    "20",
                ]
            )
        self.assertIn("inject", str(ctx.exception).lower())

    def test_playbook_std_vs_turn_equal_n(self) -> None:
        from plots.render import plot_std_vs_turn

        rows = []
        for mode, spread in (("fork", 0.01), ("reset", 0.12)):
            for g in range(2):
                for turn in range(1, 6):
                    for i in range(8):
                        passed = 5 if mode == "fork" else max(1, 5 - (i % 3))
                        rows.append(
                            {
                                "kind": "episode",
                                "eval_kind": "gym-scripted",
                                "live_run_id": "gym-unit-turns",
                                "start_mode": mode,
                                "checkpoint": "playbook",
                                "fault_id": "none",
                                "group_id": f"{mode}-playbook-g{g}",
                                "member": i,
                                "reward": (passed + spread * i) / turn,
                                "wall_s": 1.0,
                                "step": turn,
                                "turn": turn,
                                "scoreboard": "playbook",
                                "playbook": {
                                    "turn": turn,
                                    "passed": passed,
                                    "total": turn,
                                    "steps": [True] * min(passed, turn)
                                    + [False] * max(0, turn - passed),
                                    "step_s": [0.1] * turn,
                                },
                            }
                        )
        from plots.common import require_equal_group_n, std_vs_turn

        t1 = [r for r in rows if r["turn"] == 1]
        self.assertEqual(require_equal_group_n(t1), 8)
        claim = std_vs_turn(rows)
        self.assertEqual(claim["n"], 8)
        with tempfile.TemporaryDirectory() as td:
            dest = Path(td) / "std-vs-turn.svg"
            plot_std_vs_turn(rows, dest)
            self.assertTrue(dest.is_file() or dest.with_suffix(".png").is_file())

    def test_playbook_std_passed_vs_turn_not_diluted_by_t(self) -> None:
        from plots.common import std_passed_vs_turn, std_vs_turn
        from plots.render import plot_std_passed_vs_turn

        rows = []
        for mode, passed in (("fork", 4), ("reset", 2)):
            for g in range(2):
                for turn in range(1, 6):
                    for i in range(8):
                        if mode == "fork":
                            got = passed if i < 6 else passed - 1
                        else:
                            got = passed if i < 4 else max(0, passed - 2)
                        rows.append(
                            {
                                "kind": "episode",
                                "eval_kind": "gym-scripted",
                                "live_run_id": "gym-unit-passed",
                                "start_mode": mode,
                                "checkpoint": "playbook",
                                "fault_id": "none",
                                "group_id": f"{mode}-playbook-g{g}",
                                "member": i,
                                "reward": got / turn,
                                "wall_s": 1.0,
                                "step": turn,
                                "turn": turn,
                                "scoreboard": "playbook",
                                "playbook": {
                                    "turn": turn,
                                    "passed": got,
                                    "total": turn,
                                    "steps": [True] * min(got, turn)
                                    + [False] * max(0, turn - got),
                                    "step_s": [0.1] * turn,
                                },
                            }
                        )
        frac = std_vs_turn(rows)
        count = std_passed_vs_turn(rows)
        self.assertEqual(count["n"], 8)
        t1_frac = next(s for t, s in frac["series"]["fork"] if t == 1)
        t5_frac = next(s for t, s in frac["series"]["fork"] if t == 5)
        t1_cnt = next(s for t, s in count["series"]["fork"] if t == 1)
        t5_cnt = next(s for t, s in count["series"]["fork"] if t == 5)
        self.assertGreater(t1_frac, t5_frac)
        self.assertAlmostEqual(t1_cnt, t5_cnt)
        self.assertGreater(
            next(s for t, s in count["series"]["reset"] if t == 5),
            t5_cnt,
        )
        with tempfile.TemporaryDirectory() as td:
            dest = Path(td) / "std-passed-vs-turn.svg"
            plot_std_passed_vs_turn(rows, dest)
            self.assertTrue(dest.is_file() or dest.with_suffix(".png").is_file())

    def test_existing_plots_ignore_playbook_rows(self) -> None:
        rows = fixture_rows()
        pb = {
            "kind": "episode",
            "eval_kind": "gym-scripted",
            "live_run_id": "gym-mix",
            "start_mode": "fork",
            "checkpoint": "playbook",
            "fault_id": "none",
            "group_id": "playbook-g0",
            "member": 0,
            "reward": 0.5,
            "wall_s": 1.0,
            "step": 1,
            "turn": 1,
            "scoreboard": "playbook",
            "playbook": {
                "turn": 1,
                "passed": 1,
                "total": 1,
                "steps": [True],
                "step_s": [0.1],
            },
            "synthetic": True,
        }
        inc = {
            "kind": "episode",
            "eval_kind": "gym-scripted",
            "live_run_id": "gym-mix",
            "start_mode": "fork",
            "checkpoint": "oracle",
            "fault_id": "relay",
            "group_id": "incident-g0",
            "member": 0,
            "reward": 0.9,
            "wall_s": 1.0,
            "step": 1,
            "turn": 1,
            "scoreboard": "incident",
            "incident": {
                "turn": 1,
                "t_solve_s": 5.0,
                "soak_clean": True,
                "layer_gates": {},
            },
            "synthetic": True,
        }
        mixed = rows + [pb, inc]
        # playbook/incident rows must not break the fixture renderer
        eps = episodes(mixed)
        self.assertTrue(all(r.get("scoreboard") != "playbook" for r in eps))
        self.assertTrue(all(r.get("scoreboard") != "incident" for r in eps))
        self.assertGreaterEqual(len(eps), 8)

    def test_harvest_refuses_unequal_n(self) -> None:
        from plots import harvest as harvest_mod

        with self.assertRaises(SystemExit) as ctx:
            harvest_mod.main(
                [
                    "--out",
                    "/tmp/k7-harvest-unequal",
                    "--fork-n",
                    "8",
                    "--reset-n",
                    "2",
                ]
            )
        self.assertIn("fork-n", str(ctx.exception).lower())
        from plots import harvest as harvest_mod
        from sensors import HELM_BIN

        if HELM_BIN.is_file():
            return
        with self.assertRaises(RuntimeError) as ctx:
            harvest_mod.main(
                ["--out", "/tmp/k7-harvest-test", "--scoreboard", "tetragon"]
            )
        self.assertIn("helm", str(ctx.exception).lower())


if __name__ == "__main__":
    unittest.main()
