#!/usr/bin/env python3
"""Reap marked stale test trees. Same rules as sweep_trees: marker,
STALE_AGE, zero live VMs (or unknown). Never touches unmarked dirs.
"""

from __future__ import annotations

import os
import shutil
import sys
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
REPO = HERE.parent
sys.path.insert(0, str(REPO / "examples" / "cluster-tree-search"))

from k7d_client import TEST_TREE_MARKER, K7dClient  # noqa: E402

DISKS_DIR = Path(os.environ.get("DISKS_DIR", "/var/lib/k7d/disks"))
TREES_DIR = DISKS_DIR / "trees"
# crates/k7d/tests/common/mod.rs STALE_AGE
STALE_AGE_S = 30 * 60


def _live_vm_counts(client: K7dClient | None) -> dict[str, int]:
    if client is None:
        return {}
    try:
        listing = client.tree_list()
    except (RuntimeError, OSError):
        return {}
    out: dict[str, int] = {}
    for t in listing.get("trees") or []:
        tid = t.get("tree_id") or ""
        if not tid:
            continue
        usage = t.get("usage") or {}
        out[tid] = int(usage.get("live_vm_count") or 0)
    return out


def main() -> int:
    if not TREES_DIR.is_dir():
        print(f"reclaim-test-trees: {TREES_DIR} missing — nothing to reap")
        return 0
    client: K7dClient | None
    try:
        client = K7dClient()
        client.ping()
    except (RuntimeError, OSError) as e:
        print(f"reclaim-test-trees: daemon unreachable ({e}); unknown trees still reap")
        client = None
    live = _live_vm_counts(client)
    now = time.time()
    reaped = 0
    for entry in sorted(TREES_DIR.iterdir()):
        if not entry.is_dir():
            continue
        marker = entry / TEST_TREE_MARKER
        if not marker.is_file():
            continue
        try:
            age = now - marker.stat().st_mtime
        except OSError as e:
            print(f"reclaim-test-trees: cannot age {marker}: {e} — leaving it")
            continue
        if age < STALE_AGE_S:
            continue
        tree_id = entry.name
        if live.get(tree_id, 0) > 0:
            continue
        if client is not None:
            try:
                client.tree_drop(tree_id)
            except RuntimeError as e:
                # "no such tree" is the unknown-to-the-daemon case.
                print(f"reclaim-test-trees: tree_drop({tree_id}): {e}")
        try:
            shutil.rmtree(entry)
        except OSError as e:
            print(f"reclaim-test-trees: failed to remove {entry}: {e}", file=sys.stderr)
            continue
        print(f"sweep: reaped tree {tree_id}")
        reaped += 1
    print(f"reclaim-test-trees: reaped {reaped} marked stale tree(s)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
