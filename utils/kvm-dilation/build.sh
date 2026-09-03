#!/usr/bin/env bash
# Build patched kvm.ko / kvm-amd.ko / kvm-intel.ko for the running kernel.
#
# Out-of-tree is not an option: arch/x86/kvm's private headers are not in the
# linux-headers package, so the modules are built inside a full source tree of
# the exact ABI the node runs, with the headers package's Module.symvers
# supplying the CRCs of everything the module imports.
#
# Everything lives under $WORK (default /root/kvm-dilation); nothing outside it
# is touched, and no module is loaded — that is install.sh's job.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WORK="${K7_DILATION_WORK:-/root/kvm-dilation}"
KREL="$(uname -r)"

# The ABI (e.g. 6.8.0-137.137) the modules must match, pinned to what is
# running.  A mismatch here is the whole failure mode this script exists to
# avoid, so it is read from the running kernel, never guessed.
ABI="$(dpkg-query -W -f='${Version}' "linux-modules-${KREL}")"
SRCVER="${ABI%%-*}"            # 6.8.0
LP="https://launchpad.net/ubuntu/+archive/primary/+files"

echo "== kernel ${KREL}, ABI ${ABI}"

DEPS=(build-essential flex bison bc libelf-dev libssl-dev dwarves)
missing=()
for p in "${DEPS[@]}"; do
    dpkg-query -W -f='${Status}' "$p" 2>/dev/null | grep -q "^install ok installed$" || missing+=("$p")
done
if ((${#missing[@]})); then
    echo "== installing build deps: ${missing[*]}"
    DEBIAN_FRONTEND=noninteractive apt-get install -y -qq "${missing[@]}" >/dev/null
fi

mkdir -p "$WORK/debs" "$WORK/src"
cd "$WORK/debs"
for f in "linux-source-${SRCVER}_${ABI}_all.deb" \
         "linux-headers-${KREL}_${ABI}_amd64.deb"; do
    [[ -f "$f" ]] || curl -fsSL -o "$f" "$LP/$f"
done

EXTRACT="$WORK/extract"
[[ -d "$EXTRACT/usr/src/linux-headers-${KREL}" ]] || {
    mkdir -p "$EXTRACT"
    for f in *.deb; do dpkg-deb -x "$f" "$EXTRACT"; done
}

PATCH="$HERE/0001-kvm-x86-per-VM-continuous-time-dilation.patch"
# The stamp is the patch's own hash, not a bare "applied" flag. A flag makes an
# *edited* patch silently build the previous one: the tree is already patched,
# the modules are already there, and the only symptom is the new behaviour
# missing from a host that reports itself patched.
PATCH_SHA="$(sha256sum "$PATCH" | cut -d' ' -f1)"
STAMP=.k7-dilation-applied
TREE="$WORK/src/linux-source-${SRCVER}"

# The stamp is the only evidence this tree is in a known state, so a tree
# without one is not pristine — it is a tree whose `patch` run died partway,
# and re-applying over it fails on the hunks that did land.
if [[ -d "$TREE" && "$(cat "$TREE/$STAMP" 2>/dev/null)" != "$PATCH_SHA" ]]; then
    echo "== the tree does not hold this patch; re-extracting"
    rm -rf "$TREE"
fi
[[ -d "$TREE" ]] || tar -C "$WORK/src" -xf "$EXTRACT/usr/src/linux-source-${SRCVER}.tar.bz2"

cd "$TREE"
if [[ -f "$STAMP" ]]; then
    echo "== patch already applied ($PATCH_SHA)"
else
    # No --forward: "previously applied, skipping" on a freshly extracted tree
    # would mean the patch is wrong, and skipping it builds stock modules that
    # call themselves patched.
    patch -p1 < "$PATCH"
    echo "$PATCH_SHA" > "$STAMP"
fi

cp "/boot/config-${KREL}" .config
# CONFIG_DEBUG_INFO_BTF_MODULES stays on even though we cannot generate BTF
# without a vmlinux (modfinal skips it with a warning): it is #ifdef'd into
# struct module, and turning it off makes every module here load with
# "section size must match the kernel's built struct module size".
# The trusted-key blobs are not shipped in the source package.
scripts/config --disable MODULE_SIG_ALL \
               --set-str SYSTEM_TRUSTED_KEYS "" \
               --set-str SYSTEM_REVOCATION_KEYS ""
make olddefconfig KERNELRELEASE="$KREL" >/dev/null
make -j"$(nproc)" modules_prepare KERNELRELEASE="$KREL" >/dev/null
# The running kernel's own symbol CRCs, so the modules link against the ABI
# that is actually loaded rather than one we recomputed.
cp "$EXTRACT/usr/src/linux-headers-${KREL}/Module.symvers" Module.symvers
make -j"$(nproc)" KERNELRELEASE="$KREL" M=arch/x86/kvm modules

OUT="$WORK/modules"
# Whatever is in here is from the previous patch until this build replaces it,
# and a half-replaced set is worse than an empty one.
rm -rf "$OUT"
mkdir -p "$OUT"
for m in kvm kvm-amd kvm-intel; do
    [[ -f "arch/x86/kvm/$m.ko" ]] && cp "arch/x86/kvm/$m.ko" "$OUT/"
done
# What install.sh checks before deciding it can skip this script.
echo "$PATCH_SHA" > "$OUT/patch.sha256"

for m in "$OUT"/*.ko; do
    got="$(modinfo -F vermagic "$m")"
    [[ "$got" == "$KREL "* ]] || { echo "vermagic mismatch: $m is '$got', kernel is $KREL" >&2; exit 1; }
    echo "== built $(basename "$m"): $got"
done
