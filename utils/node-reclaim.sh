#!/usr/bin/env bash
# Reclaim disk-tier leftovers the test-suite sweep and image GC define:
# marked stale test trees, and all-but-K7D_KEEP_BASE_IMAGES base-image
# sets. No extra powers — unmarked trees are never touched.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$REPO_ROOT"

DISKS_DIR="${DISKS_DIR:-/var/lib/k7d/disks}"

echo "==> df before"
df -h "$DISKS_DIR" || df -h "$(dirname "$DISKS_DIR")"

python3 utils/reclaim-test-trees.py
bash guest/ubuntu/build-node-image.sh --gc-only

echo "==> df after"
df -h "$DISKS_DIR" || df -h "$(dirname "$DISKS_DIR")"
