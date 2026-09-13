#!/usr/bin/env bash
# Rsync the workspace to the bare-metal node, then bump the mtime of every
# file the transfer actually wrote.
#
# Why the touch: `rsync -a` preserves the *workspace's* mtime. If a file
# on the node is ever newer than the copy rsync writes over it (someone
# edited or restored it on the node), the source's mtime moves
# *backwards*. Cargo's freshness check is "is any source newer than the
# artifact", so a source dated before the artifact is fresh by
# definition: cargo skips the rebuild and the suite tests a binary built
# from source that exists nowhere. That reports a false PASS as readily
# as a false failure. See CHALLENGES.md #64.
#
# Only transferred files are touched, so cargo's incremental build still
# works. That requires `--checksum`: with rsync's default size+mtime
# quick check, the files we touched last time look changed on the next
# run and every sync would re-touch (and so rebuild) the whole tree.
# Comparing content makes "transferred" mean "really different", which
# is exactly the set whose mtime must move forward. The synced tree is
# ~6 MB, so checksumming it costs well under a second.
set -euo pipefail

cd "$(git -C "$(dirname "$0")" rev-parse --show-toplevel)"
source utils/ssh-setup.sh

RAW_LIST="$(mktemp)"
cleanup() {
    rm -f "$RAW_LIST"
    [[ -n "${_SSH_TMPDIR:-}" ]] && rm -rf "$_SSH_TMPDIR"
    return 0
}
trap cleanup EXIT

REMOTE_DIR="${K7_REMOTE_DIR:-/root/k7d}"

echo "==> Rsyncing to $NODE:$REMOTE_DIR"
rsync_rc=0
rsync -azc --delete \
    --exclude target --exclude .git --exclude reference \
    --exclude tmp --exclude dist \
    --exclude "examples/k7d-mcp/logs*" \
    --exclude "guest/kernel/linux-*" --exclude "guest/kernel/vmlinux" \
    --exclude "guest/rootfs/initramfs.cpio.gz" \
    --exclude "guest/rootfs/runc.amd64" \
    --exclude "guest/docker/payload" \
    --exclude "guest/docker/.cache" \
    --exclude "verif/.lake" --exclude "verif/build" \
    --out-format='%n' \
    -e "ssh ${SSH_OPTS[*]}" \
    ./ "$NODE:$REMOTE_DIR/" >"$RAW_LIST" || rsync_rc=$?
if [[ "$rsync_rc" -ne 0 ]]; then
    echo "==> rsync to $NODE failed (exit $rsync_rc)" >&2
    exit "$rsync_rc"
fi

# Drop directories ("foo/") and deletions ("deleting foo") — only real
# files transferred in this run need their mtime moved forward.
FILES="$(awk '!/\/$/ && !/^deleting /' "$RAW_LIST")"
if [[ -n "$FILES" ]]; then
    echo "==> Bumping mtime of $(wc -l <<<"$FILES") transferred file(s) on the node"
    printf '%s\n' "$FILES" | tr '\n' '\0' |
        ssh "${SSH_OPTS[@]}" "$NODE" \
            "cd '$REMOTE_DIR' && xargs -0 -r touch -h --"
fi
# Cloud-agent git snapshots often ship epoch mtimes. rsync -a keeps them,
# so a file we did not re-transfer stays dated 1970 and cargo treats the
# newer artifact as fresh (CHALLENGES #64). Bump anything still in 1970.
ssh "${SSH_OPTS[@]}" "$NODE" \
    "find '$REMOTE_DIR/crates' '$REMOTE_DIR/gym' '$REMOTE_DIR/examples' \
     -type f ! -newermt '1980-01-01' -exec touch -- {} +"
