#!/usr/bin/env bash
# Mount the reflink XFS loop image at /var/lib/k7d/disks in the *host*
# mount namespace. Invoked from k7d.service ExecStartPre=+ (the `+`
# prefix is load-bearing: without it ProtectSystem=strict would hide
# the mount from the host and from every integration test). Also called
# by your node provisioning so a reset node and the unit share
# one script.
#
# Mirrors crates/k7d/src/disks.rs ensure_loopback_xfs (96 GiB sparse,
# mkfs.xfs -m reflink=1, grow an older smaller image).
set -euo pipefail

DISKS_IMG=/var/lib/k7d/disks.img
DISKS_MNT=/var/lib/k7d/disks
# crates/k7d/src/disks.rs DISKS_IMAGE_SIZE
SIZE_BYTES=$((96 * 1024 * 1024 * 1024))

mkdir -p "$DISKS_MNT"

if [[ ! -f "$DISKS_IMG" ]]; then
  truncate -s "$SIZE_BYTES" "$DISKS_IMG"
  mkfs.xfs -q -m reflink=1 "$DISKS_IMG"
fi

if ! grep -qF "$DISKS_IMG" /etc/fstab; then
  echo "$DISKS_IMG $DISKS_MNT xfs loop,nofail 0 0" >>/etc/fstab
fi

if ! mountpoint -q "$DISKS_MNT"; then
  mount "$DISKS_MNT" 2>/dev/null || mount -o loop "$DISKS_IMG" "$DISKS_MNT"
fi

current=$(stat -c%s "$DISKS_IMG")
if (( current < SIZE_BYTES )); then
  truncate -s "$SIZE_BYTES" "$DISKS_IMG"
  dev=$(losetup -j "$DISKS_IMG" | head -1 | cut -d: -f1)
  if [[ -z "$dev" ]]; then
    echo "k7d-mount-disks: no loop device backs $DISKS_IMG" >&2
    exit 1
  fi
  losetup -c "$dev"
  xfs_growfs "$DISKS_MNT" >/dev/null
fi

# The mount root itself is the VM broker's working directory, not just a
# parent of one: `fork.rs` puts each fork's `.k7d-blk-fork-<pid>-<n>`
# reflink dir *beside* the image it clones, and `disks.rs` writes its
# reflink probe there. Both run as uid `k7d` under privilege separation, and a
# freshly `mkfs`'d XFS has a root-owned 0755 root, so without this the
# first fork fails with a bare `Permission denied` (CHALLENGES #250).
# Mode stays 0755: a jailed Firecracker runs as a per-VM lease uid that
# is in no group of ours and still has to traverse this to reach its
# chroot under `disks/fc`.
#
# Here rather than only in `k7d_own_state_dirs` because this script is
# what runs after every mount, including the one that follows the `mkfs`
# above. Provisioning may not have happened yet on a fresh node, which is
# the one case where the account is legitimately absent — say so instead
# of chowning to a uid that does not exist.
if getent passwd k7d >/dev/null; then
  chown k7d:k7d "$DISKS_MNT"
  chmod 0755 "$DISKS_MNT"
else
  echo "k7d-mount-disks: no k7d account yet — $DISKS_MNT stays root-owned; \
packaging/k7d-account.sh has not run" >&2
fi

# Per-pid names, as crates/k7d/src/disks.rs already uses: this script is
# the unit's ExecStartPre *and* what the test suite calls directly, so
# two copies run concurrently every time a test restarts the daemon. With
# one fixed name the first copy's `rm -f` deletes the second's file
# between its `echo` and its `cp`, and the failure reads as "the
# filesystem is not reflink-capable" (CHALLENGES #254).
probe_src="$DISKS_MNT/.reflink-probe-src-$$"
probe_dst="$DISKS_MNT/.reflink-probe-dst-$$"
echo probe >"$probe_src"
cp --reflink=always "$probe_src" "$probe_dst" || {
  echo "k7d-mount-disks: $DISKS_MNT is not reflink-capable" >&2
  exit 1
}
rm -f "$probe_src" "$probe_dst"
