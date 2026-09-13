#!/usr/bin/env bash
# Print "patched" or "stock" for the KVM modules currently loaded, and exit
# 0 / 1 respectively.  Every arm of the dilation bench asserts this before it runs.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WORK="${K7_DILATION_WORK:-/root/kvm-dilation}"
BIN="$WORK/kvm-dilation-probe"

mkdir -p "$WORK"
if [[ ! -x "$BIN" || "$HERE/probe.c" -nt "$BIN" ]]; then
    gcc -O1 -Wall -Werror -o "$BIN" "$HERE/probe.c"
fi
exec "$BIN"
