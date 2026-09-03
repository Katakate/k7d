#!/usr/bin/env bash
# Put the host back on the distribution's KVM modules.  Every other spec's
# `make remote-check` runs on stock, so this is not optional after a bench run.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

if grep -q "^vendor_id.*AuthenticAMD" /proc/cpuinfo; then
    VENDOR=kvm_amd
else
    VENDOR=kvm_intel
fi

if systemctl is-active --quiet k7d; then
    echo "== stopping k7d (it holds /dev/kvm)"
    systemctl stop k7d
fi

# Fails with EBUSY while a VM is alive, which is the right answer.
[[ -d /sys/module/kvm ]] && modprobe -r "$VENDOR" kvm
modprobe kvm
modprobe "$VENDOR"

state="$(bash "$HERE/state.sh" || true)"
echo "$state"
[[ "$state" == stock* ]] || { echo "still not on stock modules" >&2; exit 1; }

if systemctl is-enabled --quiet k7d; then
    systemctl start k7d
fi
