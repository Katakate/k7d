#!/usr/bin/env bash
# Build the k7d guest rootfs (initramfs) containing busybox and k7-agent.
# Requires: Docker, and k7-agent must be cross-compiled first (`make build-agent`).
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
AGENT_BIN="${REPO_ROOT}/target/x86_64-unknown-linux-musl/release/k7-agent"

[[ -f "$AGENT_BIN" ]] || {
    echo "k7-agent binary not found at $AGENT_BIN" >&2
    echo "Run 'make build-agent' first." >&2
    exit 1
}

WORK_DIR=$(mktemp -d)
cleanup() { rm -rf "$WORK_DIR"; }
trap cleanup EXIT

echo "==> Preparing initramfs tree"
ROOTFS="$WORK_DIR/rootfs"
mkdir -p "$ROOTFS"/{bin,sbin,usr/local/bin,proc,sys,dev,tmp,run,etc,mnt/state}
mkdir -p "$ROOTFS"/sys/fs/cgroup

# Install busybox (static)
cp /bin/busybox "$ROOTFS/bin/busybox" 2>/dev/null || {
    # Fallback: download static busybox
    curl -fsSL "https://busybox.net/downloads/binaries/1.35.0-x86_64-linux-musl/busybox" \
        -o "$ROOTFS/bin/busybox"
}
chmod +x "$ROOTFS/bin/busybox"

# Create busybox symlinks (core + networking)
for cmd in sh cat echo ls mkdir mount umount sleep grep wc head tail stty \
           ifconfig ping route ip dmesg hostname uname mknod vi \
           ps kill env rm cp mv chmod chown ln basename dirname nc mkfifo; do
    ln -sf busybox "$ROOTFS/bin/$cmd"
done
for cmd in ifconfig route; do
    ln -sf ../bin/busybox "$ROOTFS/sbin/$cmd"
done

# iproute2 (`ip` with vxlan link types, `tc`) is NOT in the initramfs
# either, for the same reason as runc below and with a measurement to
# back it: alpine's iproute2-minimal + iproute2-tc plus the musl loader
# and libelf/libzstd they link against is 2.4 MB uncompressed, which
# took the gzipped initramfs from 1.6 MB to 3.0 MB and boot-to-agent
# from ~205 ms to ~221 ms — a third of the runs then missed the 250 ms
# VM_BOOT_TO_AGENT budget. Every k7d VM would pay that so that one test
# could run `tc`. The Dockerfile here defines the image, and
# crates/k7d/tests/test_kernel_features.rs hands it to its guest over
# virtiofs. The node rootfs is where this userspace belongs for
# real.
#
# runc is NOT included in the initramfs — it's loaded via virtiofs
# at /mnt/state/bin/runc to keep initramfs small (<2MB) for fast boot.
# The shim/daemon is responsible for placing the runc binary on the
# host virtiofs share before starting containers.
# Download it here so it's available for the host side.
RUNC_VERSION="1.2.5"
RUNC_STATIC="${REPO_ROOT}/guest/rootfs/runc.amd64"
if [[ ! -f "$RUNC_STATIC" ]]; then
    echo "==> Downloading static runc v${RUNC_VERSION}"
    curl -fsSL "https://github.com/opencontainers/runc/releases/download/v${RUNC_VERSION}/runc.amd64" \
        -o "$RUNC_STATIC"
    chmod +x "$RUNC_STATIC"
fi

# Install k7-agent
cp "$AGENT_BIN" "$ROOTFS/usr/local/bin/k7-agent"
chmod +x "$ROOTFS/usr/local/bin/k7-agent"

# Install init script
cp "$SCRIPT_DIR/init.sh" "$ROOTFS/init"
chmod +x "$ROOTFS/init"

echo "==> Creating cpio archive"
cd "$ROOTFS"
find . -print0 | cpio --null -o --format=newc 2>/dev/null | gzip > "$SCRIPT_DIR/initramfs.cpio.gz"

echo "==> Guest rootfs built: ${SCRIPT_DIR}/initramfs.cpio.gz ($(du -h "$SCRIPT_DIR/initramfs.cpio.gz" | cut -f1))"
