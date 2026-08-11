#!/usr/bin/env bash
# Build a minimal guest kernel for k7d.
# Must run on a Linux x86 host (not macOS).
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
KERNEL_VERSION="6.12.10"
KERNEL_URL="https://cdn.kernel.org/pub/linux/kernel/v6.x/linux-${KERNEL_VERSION}.tar.xz"
BUILD_DIR="${SCRIPT_DIR}/linux-${KERNEL_VERSION}"
CONFIG_FILE="${SCRIPT_DIR}/config-minimal"

[[ -f "$CONFIG_FILE" ]] || {
    echo "Missing kernel config: $CONFIG_FILE" >&2
    exit 1
}

if [[ ! -d "$BUILD_DIR" ]]; then
    echo "==> Downloading Linux ${KERNEL_VERSION}"
    curl -fSL "$KERNEL_URL" | tar -xJ -C "$SCRIPT_DIR"
fi

echo "==> Applying minimal config"
cp "$CONFIG_FILE" "${BUILD_DIR}/.config"
cd "$BUILD_DIR"
make olddefconfig

echo "==> Building vmlinux"
make -j"$(nproc)" vmlinux

cp vmlinux "$SCRIPT_DIR/vmlinux"
strip --strip-all "$SCRIPT_DIR/vmlinux" 2>/dev/null || true
echo "==> Guest kernel built: ${SCRIPT_DIR}/vmlinux ($(du -h "$SCRIPT_DIR/vmlinux" | cut -f1))"
