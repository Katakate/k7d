#!/usr/bin/env bash
# Five-minute try path.
#
# Doctor-checks /dev/kvm, /dev/vhost-vsock, /dev/net/tun, and cgroup v2;
# fetches the release tarball + guest artifacts if they are not already
# on this box; starts k7d if needed; boots a busybox 3-node tree; forks
# 4 branches; prints wall-clocks next to the two-clocks table.
#
# Usage (from a clone, or after curling this script):
#   sudo ./scripts/quickstart.sh
#
# Overrides:
#   K7D_RELEASE_URL   tarball URL (default: latest Katakate/k7d x86_64)
#   K7D_PREFIX        install prefix (default: /usr/local)
#   K7D_SOCKET        control socket (default: /run/k7d/k7d.sock)
set -euo pipefail

PREFIX="${K7D_PREFIX:-/usr/local}"
SOCKET="${K7D_SOCKET:-/run/k7d/k7d.sock}"
REPO_OWNER="${K7D_RELEASE_OWNER:-Katakate}"
REPO_NAME="${K7D_RELEASE_REPO:-k7d}"
WORKDIR="${K7D_QUICKSTART_DIR:-/tmp/k7d-quickstart}"

# The script lives in the clone when present (`$HERE/../guest/...`).
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$HERE/.." && pwd)"

die() { echo "quickstart: $*" >&2; exit 1; }

require_root() {
    if [[ "$(id -u)" -ne 0 ]]; then
        die "must run as root (KVM + /run/k7d + /usr/local)"
    fi
}

# Same four checks as `k7d doctor`, so this script works *before* the
# binary is installed.
doctor_bash() {
    local fail=0
    for p in /dev/kvm /dev/vhost-vsock /dev/net/tun; do
        if [[ -c "$p" ]]; then
            echo "ok    ${p##*/}  $p"
        else
            echo "FAIL  ${p##*/}  $p missing or not a character device"
            fail=1
        fi
    done
    if [[ -f /sys/fs/cgroup/cgroup.controllers ]] && grep -q '^0::' /proc/self/cgroup; then
        echo "ok    cgroup_v2  /sys/fs/cgroup (unified) + /proc/self/cgroup 0::"
    else
        echo "FAIL  cgroup_v2  host is not cgroup v2"
        fail=1
    fi
    if [[ "$fail" -ne 0 ]]; then
        die "doctor FAIL — need KVM, vhost-vsock, TUN, and cgroup v2"
    fi
    echo "doctor: ok — host can run k7d"
}

have_guests() {
    [[ -f "${K7D_KERNEL:-}" && -f "${K7D_INITRD:-}" ]]
}

resolve_local_guests() {
    if have_guests; then
        return 0
    fi
    local candidates=(
        "$PREFIX/share/k7d"
        "$REPO_ROOT/guest"
        "$WORKDIR/extract"
    )
    local dir kernel initrd
    for dir in "${candidates[@]}"; do
        if [[ -d "$dir/kernel" ]]; then
            kernel="$dir/kernel/vmlinux"
            initrd="$dir/rootfs/initramfs.cpio.gz"
        else
            kernel="$dir/vmlinux"
            initrd="$dir/initramfs.cpio.gz"
        fi
        if [[ -f "$kernel" && -f "$initrd" ]]; then
            export K7D_KERNEL="$kernel"
            export K7D_INITRD="$initrd"
            return 0
        fi
    done
    return 1
}

find_k7d() {
    if command -v k7d >/dev/null 2>&1; then
        command -v k7d
        return 0
    fi
    if [[ -x "$PREFIX/bin/k7d" ]]; then
        echo "$PREFIX/bin/k7d"
        return 0
    fi
    if [[ -x "$REPO_ROOT/target/release/k7d" ]]; then
        echo "$REPO_ROOT/target/release/k7d"
        return 0
    fi
    if [[ -x "$WORKDIR/extract/k7d" ]]; then
        echo "$WORKDIR/extract/k7d"
        return 0
    fi
    return 1
}

latest_tarball_url() {
    if [[ -n "${K7D_RELEASE_URL:-}" ]]; then
        echo "$K7D_RELEASE_URL"
        return 0
    fi
    local api="https://api.github.com/repos/${REPO_OWNER}/${REPO_NAME}/releases/latest"
    local url
    url="$(curl -fsSL "$api" | python3 -c '
import json, sys
data = json.load(sys.stdin)
for a in data.get("assets") or []:
    name = a.get("name") or ""
    if name.endswith("x86_64-linux.tar.gz"):
        print(a["browser_download_url"])
        sys.exit(0)
sys.exit(1)
')" || return 1
    echo "$url"
}

fetch_release() {
    mkdir -p "$WORKDIR"
    local url tarball
    url="$(latest_tarball_url)" || die \
        "could not resolve a release tarball (set K7D_RELEASE_URL, or clone the repo and build)"
    tarball="$WORKDIR/k7d-x86_64-linux.tar.gz"
    echo "==> fetching $url"
    curl -fL --retry 3 -o "$tarball" "$url" || die "download failed: $url"
    rm -rf "$WORKDIR/extract"
    mkdir -p "$WORKDIR/extract"
    tar -xzf "$tarball" -C "$WORKDIR/extract" --strip-components=1
    [[ -x "$WORKDIR/extract/k7d" ]] || die "tarball missing k7d"
    [[ -f "$WORKDIR/extract/vmlinux" ]] || die "tarball missing vmlinux"
    [[ -f "$WORKDIR/extract/initramfs.cpio.gz" ]] || die "tarball missing initramfs.cpio.gz"
    export K7D_KERNEL="$WORKDIR/extract/vmlinux"
    export K7D_INITRD="$WORKDIR/extract/initramfs.cpio.gz"
}

ensure_daemon() {
    local bin="$1"
    if [[ -S "$SOCKET" ]]; then
        if "$bin" doctor >/dev/null && python3 -c "
import socket, sys
s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
s.settimeout(2)
s.connect('$SOCKET')
s.sendall(b'{\"op\":\"ping\"}\\n')
print(s.recv(4096).decode())
" >/dev/null 2>&1; then
            echo "==> k7d already running at $SOCKET"
            return 0
        fi
    fi
    echo "==> starting $bin"
    mkdir -p "$(dirname "$SOCKET")"
    # Foreground child; we wait for the socket then leave it running.
    K7D_KERNEL="${K7D_KERNEL:?}" K7D_INITRD="${K7D_INITRD:?}" \
        RUST_LOG="${RUST_LOG:-info}" \
        "$bin" --socket "$SOCKET" >/tmp/k7d-quickstart-daemon.log 2>&1 &
    local deadline=$((SECONDS + 15))
    while [[ ! -S "$SOCKET" ]]; do
        if (( SECONDS >= deadline )); then
            die "socket $SOCKET did not appear — see /tmp/k7d-quickstart-daemon.log"
        fi
        sleep 0.2
    done
    echo "==> k7d listening on $SOCKET"
}

main() {
    require_root
    [[ "$(uname -m)" == "x86_64" ]] || die "amd64/x86_64 host required (no arm64 build yet)"
    doctor_bash

    if ! resolve_local_guests; then
        echo "==> no guest artifacts on this box — fetching the release tarball"
        fetch_release
    else
        echo "==> guests: K7D_KERNEL=$K7D_KERNEL"
        echo "==> guests: K7D_INITRD=$K7D_INITRD"
    fi

    local bin
    if ! bin="$(find_k7d)"; then
        echo "==> k7d binary not on PATH — fetching the release tarball"
        fetch_release
        bin="$(find_k7d)" || die "k7d still missing after fetch"
    fi
    echo "==> using $bin"

    # Prefer the new binary's doctor verb when it exists.
    if "$bin" doctor >/dev/null 2>&1; then
        "$bin" doctor
    fi

    ensure_daemon "$bin"
    echo "==> k7d quickstart (busybox 3-node + 4 forks)"
    if "$bin" --help 2>/dev/null | grep -q quickstart; then
        exec "$bin" --socket "$SOCKET" quickstart
    fi
    # Older release tarballs predate the verb. The clone still has the
    # Python demo — same 3-node + 4-fork, same clocks.
    local demo="$REPO_ROOT/examples/cluster-tree-search/run_demo.py"
    if [[ -f "$demo" ]]; then
        echo "==> $bin has no quickstart verb — using $demo"
        exec python3 "$demo" --mode busybox --branches 4
    fi
    die "$bin has no quickstart verb and $demo is missing — build k7d from this repo"
}

main "$@"
