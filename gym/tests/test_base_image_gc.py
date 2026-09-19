"""Base-image GC in build-node-image.sh — no KVM, no full image build."""

from __future__ import annotations

import os
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parents[1]
REPO = HERE.parent
SCRIPT = REPO / "guest" / "ubuntu" / "build-node-image.sh"


def _plant_set(d: Path, key: str, payload: bytes, *, mtime: float | None = None) -> None:
    for ext in (".img", ".initrd", ".vmlinuz", ".json"):
        p = d / f"ubuntu-24.04-{key}{ext}"
        p.write_bytes(payload)
        if mtime is not None:
            os.utime(p, (mtime, mtime))


def _gc(d: Path, *, keep: str = "1", extra_env: dict[str, str] | None = None) -> subprocess.CompletedProcess[str]:
    env = os.environ.copy()
    env["OUT_DIR"] = str(d)
    env["K7D_KEEP_BASE_IMAGES"] = keep
    if extra_env:
        env.update(extra_env)
    return subprocess.run(
        ["bash", str(SCRIPT), "--gc-only"],
        check=False,
        capture_output=True,
        text=True,
        env=env,
        cwd=str(REPO),
    )


class TestBaseImageGc(unittest.TestCase):
    def test_keep_1_removes_all_four_files_of_old_set(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            d = Path(td)
            now = time.time()
            _plant_set(d, "oldkey", b"old", mtime=now - 3600)
            _plant_set(d, "newkey", b"new", mtime=now)
            r = _gc(d, keep="1")
            self.assertEqual(r.returncode, 0, r.stderr)
            for ext in (".img", ".initrd", ".vmlinuz", ".json"):
                self.assertFalse(
                    (d / f"ubuntu-24.04-oldkey{ext}").exists(),
                    f"old set {ext} must be gone: {r.stderr}",
                )
                self.assertTrue(
                    (d / f"ubuntu-24.04-newkey{ext}").is_file(),
                    f"new set {ext} must remain",
                )
            self.assertIn("deleting set", r.stderr)

    def test_gc_skips_held_open_img(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            d = Path(td)
            now = time.time()
            _plant_set(d, "oldkey", b"old", mtime=now - 3600)
            _plant_set(d, "newkey", b"new", mtime=now)
            img = d / "ubuntu-24.04-oldkey.img"
            fd = os.open(img, os.O_RDONLY)
            try:
                r = _gc(d, keep="1")
            finally:
                os.close(fd)
            self.assertEqual(r.returncode, 0, r.stderr)
            self.assertTrue(img.is_file(), "held-open .img must not be deleted")
            for ext in (".initrd", ".vmlinuz", ".json"):
                self.assertTrue(
                    (d / f"ubuntu-24.04-oldkey{ext}").is_file(),
                    f"held-open set {ext} must remain with the .img",
                )
            self.assertIn("skip", r.stderr)
            self.assertIn("open", r.stderr)

    def test_cache_hit_deletes_nothing(self) -> None:
        """A cache hit must stay a read-only fast path.

        Plant two sets plus a complete current KEY set, invoke the
        script's cache-hit path (no --gc-only), assert the old set
        survives. `--print-key` needs AGENT_BIN; point it at this
        file so the hash is stable without a musl agent.
        """
        agent = REPO / "target" / "x86_64-unknown-linux-musl" / "release" / "k7-agent"
        if not agent.is_file():
            agent = Path(sys.executable)
        with tempfile.TemporaryDirectory() as td:
            d = Path(td)
            env = os.environ.copy()
            env["OUT_DIR"] = str(d)
            env["AGENT_BIN"] = str(agent)
            env["K7D_KEEP_BASE_IMAGES"] = "1"
            key = subprocess.run(
                ["bash", str(SCRIPT), "--print-key"],
                check=True,
                capture_output=True,
                text=True,
                env=env,
                cwd=str(REPO),
            ).stdout.strip()
            self.assertRegex(key, r"^[0-9a-f]{16}$", key)
            _plant_set(d, "oldkey", b"old")
            time.sleep(0.05)
            _plant_set(d, key, b"current")
            # Cache-hit path still requires root (the real builder does).
            # If we are not root, assert the source order instead: GC is
            # after the cache-hit `exit 0`.
            src = SCRIPT.read_text()
            hit = src.index("==> cache hit")
            last_gc = src.rindex("gc_old_base_images")
            self.assertLess(hit, last_gc, "cache hit must exit before the miss-path GC call")
            r = subprocess.run(
                ["bash", str(SCRIPT)],
                check=False,
                capture_output=True,
                text=True,
                env=env,
                cwd=str(REPO),
            )
            if os.geteuid() != 0 and r.returncode != 0:
                self.assertIn("must run as root", r.stderr)
                for ext in (".img", ".initrd", ".vmlinuz", ".json"):
                    self.assertTrue((d / f"ubuntu-24.04-oldkey{ext}").is_file())
                return
            self.assertEqual(r.returncode, 0, r.stderr + r.stdout)
            self.assertIn("cache hit", r.stdout)
            for ext in (".img", ".initrd", ".vmlinuz", ".json"):
                self.assertTrue(
                    (d / f"ubuntu-24.04-oldkey{ext}").is_file(),
                    f"cache hit deleted old set {ext}",
                )
                self.assertTrue((d / f"ubuntu-24.04-{key}{ext}").is_file())


if __name__ == "__main__":
    unittest.main()
