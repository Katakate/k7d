"""28a plot/derive unit tests — no KVM."""

from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from plots.divergence import (
    derive,
    load_jsonl,
    render_sibling_svg,
    render_svg,
    summarize,
    summarize_siblings,
)


class TestDerive(unittest.TestCase):
    def test_shared_is_configured_minus_dirty(self) -> None:
        # 6 live VMs × 2048 MiB; 1 GiB dirtied.
        usage = {"live_vm_count": 6, "live_ram_bytes": 1024**3}
        d = derive(usage, 2048)
        self.assertEqual(d["configured_ram_bytes"], 6 * 2048 * 1024 * 1024)
        self.assertEqual(d["diverged_ram_bytes"], 1024**3)
        self.assertEqual(d["shared_ram_bytes"], d["configured_ram_bytes"] - 1024**3)
        self.assertGreater(d["shared_frac"], 0.9)
        self.assertLess(d["shared_frac"], 1.0)

    def test_zero_vms_is_loud_zero_not_nan(self) -> None:
        d = derive({"live_vm_count": 0, "live_ram_bytes": 0}, 2048)
        self.assertEqual(d["shared_frac"], 0.0)
        self.assertEqual(d["configured_ram_bytes"], 0.0)

    def test_missing_usage_keys_default_to_zero(self) -> None:
        d = derive({}, 2048)
        self.assertEqual(d["diverged_ram_bytes"], 0.0)

    def test_src_only_is_not_a_substring_of_idle_src_only(self) -> None:
        names = {"idle-src-only", "fork-marker", "kube-root-ca.crt"}
        self.assertNotIn("src-only", names)
        names.add("src-only")
        self.assertIn("src-only", names)


class TestSummarizeAndSvg(unittest.TestCase):
    def _rows(self) -> list[dict]:
        t0 = 1_700_000_000.0
        rows = []
        for wl, start_frac, end_frac in (
            ("idle", 0.95, 0.93),
            ("k8s", 0.90, 0.80),
            ("kafka", 0.88, 0.70),
        ):
            configured = 6 * 2048 * 1024 * 1024
            for i, frac in enumerate((start_frac, (start_frac + end_frac) / 2, end_frac)):
                shared = configured * frac
                diverged = configured - shared
                rows.append(
                    {
                        "ts": t0 + i * 15,
                        "workload": wl,
                        "phase": "post_fork",
                        "usage": {
                            "live_vm_count": 6,
                            "live_ram_bytes": int(diverged),
                        },
                        "configured_ram_bytes": configured,
                        "diverged_ram_bytes": diverged,
                        "shared_ram_bytes": shared,
                        "shared_frac": frac,
                    }
                )
        return rows

    def test_summarize_t0_and_t30(self) -> None:
        s = summarize(self._rows())
        self.assertAlmostEqual(s["idle"]["shared_frac_t0"], 0.95)
        self.assertAlmostEqual(s["idle"]["shared_frac_t30"], 0.93)
        self.assertAlmostEqual(s["kafka"]["shared_frac_t30"], 0.70)
        self.assertEqual(s["k8s"]["n_samples"], 3.0)

    def test_render_svg_from_jsonl(self) -> None:
        rows = self._rows()
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "d.jsonl"
            p.write_text("".join(json.dumps(r) + "\n" for r in rows))
            loaded = load_jsonl([p])
            self.assertEqual(len(loaded), 9)
            dest = Path(td) / "divergence.svg"
            render_svg(loaded, dest)
            svg = dest.read_text()
            self.assertIn("<svg", svg)
            self.assertIn("idle", svg)
            self.assertIn("k8s", svg)
            self.assertIn("kafka", svg)
            self.assertIn("shared", svg)


class TestSiblingDivergence(unittest.TestCase):
    def _rows(self) -> list[dict]:
        rows = []
        for wl, p0, c0, p1, c1 in (
            ("idle", 0.80 * 1024**3, 0.79 * 1024**3, 0.85 * 1024**3, 0.84 * 1024**3),
            ("k8s", 1.40 * 1024**3, 1.38 * 1024**3, 1.90 * 1024**3, 1.42 * 1024**3),
            ("kafka", 3.00 * 1024**3, 2.95 * 1024**3, 3.80 * 1024**3, 3.05 * 1024**3),
        ):
            for i, (pb, cb) in enumerate(((p0, c0), ((p0 + p1) / 2, (c0 + c1) / 2), (p1, c1))):
                rows.append(
                    {
                        "ts": 1_700_000_000.0 + i * 10,
                        "workload": wl,
                        "phase": "sibling_div",
                        "t_after_fork_s": float(i * 15),
                        "parent_dirty_bytes": pb,
                        "child_dirty_bytes": cb,
                        "usage": {"live_vm_count": 6, "live_ram_bytes": int(pb + cb)},
                    }
                )
        return rows

    def test_summarize_siblings_parent_grows_faster_under_load(self) -> None:
        s = summarize_siblings(self._rows())
        self.assertEqual(s["k8s"]["n_samples"], 3.0)
        self.assertGreater(s["k8s"]["parent_bytes_last"], s["k8s"]["child_bytes_last"])
        self.assertGreater(s["kafka"]["parent_bytes_last"], s["kafka"]["child_bytes_last"])
        idle_gap = abs(s["idle"]["parent_bytes_last"] - s["idle"]["child_bytes_last"])
        k8s_gap = s["k8s"]["parent_bytes_last"] - s["k8s"]["child_bytes_last"]
        self.assertGreater(k8s_gap, idle_gap)

    def test_render_sibling_svg(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            dest = Path(td) / "sibling_div.svg"
            render_sibling_svg(self._rows(), dest)
            svg = dest.read_text()
            self.assertIn("<svg", svg)
            self.assertIn("parent", svg)
            self.assertIn("child", svg)
            self.assertIn("idle", svg)
            self.assertIn("kafka", svg)


if __name__ == "__main__":
    unittest.main()
