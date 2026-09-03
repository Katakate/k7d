#!/usr/bin/env bash
# Swap the running host onto the patched KVM modules.
#
# The stock modules are never deleted: revert.sh puts them back with modprobe,
# and so does a reboot.  If the patched pair fails to load, the stock pair goes
# back before this script returns — a host left with no kvm.ko at all is a
# worse outcome than a failed install.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WORK="${K7_DILATION_WORK:-/root/kvm-dilation}"
OUT="$WORK/modules"

if grep -q "^vendor_id.*AuthenticAMD" /proc/cpuinfo; then
    VENDOR=kvm_amd
else
    VENDOR=kvm_intel
fi
MOD="${VENDOR/_/-}.ko"

# Rebuild unless the modules on disk were built from *this* patch. Keying the
# skip on "a kvm.ko exists" is how an edited patch gets installed as the
# previous one: the host reports itself patched and the new behaviour is simply
# absent, which reads as a bug in the new code.
PATCH_SHA="$(sha256sum "$HERE/0001-kvm-x86-per-VM-continuous-time-dilation.patch" | cut -d' ' -f1)"
if [[ ! -f "$OUT/kvm.ko" || ! -f "$OUT/$MOD" ]] ||
   [[ "$(cat "$OUT/patch.sha256" 2>/dev/null)" != "$PATCH_SHA" ]]; then
    bash "$HERE/build.sh"
fi

start_k7d() {
    if systemctl is-enabled --quiet k7d; then systemctl start k7d; fi
}

if systemctl is-active --quiet k7d; then
    echo "== stopping k7d (it holds /dev/kvm)"
    systemctl stop k7d
fi

# `modprobe -r` is the interlock: it fails with EBUSY while a VM holds the
# module, which is exactly the condition that must stop us. Name the
# holder (a Kata/firecracker pod pinned kvm_amd on a node for weeks,
# CHALLENGES #197) and give k7d back — a node left with the daemon down
# fails every other agent's probe for no reason.
if [[ -d /sys/module/kvm ]] && ! modprobe -r "$VENDOR" kvm; then
    echo "== $VENDOR is pinned by a VM outside k7d; not swapping modules. Holders:" >&2
    for p in /proc/[0-9]*; do
        if ls -l "$p/fd" 2>/dev/null | grep -q "anon_inode:kvm-vm"; then
            echo "   pid ${p#/proc/} $(cat "$p/comm") $(tr '\0' ' ' <"$p/cmdline" | cut -c1-120)" >&2
        fi
    done
    start_k7d
    exit 1
fi

restore_stock() {
    echo "== patched modules did not load; going back to stock" >&2
    modprobe -r "$VENDOR" kvm 2>/dev/null || true
    modprobe kvm && modprobe "$VENDOR"
    start_k7d
}
trap restore_stock ERR

# insmod resolves nothing, so the exporters the two modules import from —
# irqbypass for kvm, ccp's sev_* for kvm-amd — have to be up first.
modprobe -a irqbypass ccp 2>/dev/null || true

insmod "$OUT/kvm.ko"
insmod "$OUT/$MOD"
bash "$HERE/state.sh"
trap - ERR

start_k7d
