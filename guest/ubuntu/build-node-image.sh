#!/usr/bin/env bash
# Build an Ubuntu 24.04 node image for a bare k7d `create_vm` VM: a
# sparse ext4 root disk on the reflink XFS, the stock
# Ubuntu kernel packaged with it, the static-musl k7-agent as a systemd
# unit, and static networking driven off the kernel command line.
#
# This is tooling, not runtime code: crates/k7d/src knows nothing about
# Ubuntu. Callers: `crates/k7d/tests/test_ubuntu_guest.rs`,
# `crates/k7d/tests/test_ubuntu_k3s.rs`, and
# `crates/k7d/tests/test_ubuntu_cilium.rs`. The content key
# already hashes k7d-k3sconfig; the CNI suite adds no new builder input.
#
# Output (in $OUT_DIR, all named by the same content key):
#   ubuntu-24.04-<key>.img       ext4 root disk, sparse, pristine
#                                (tests reflink a per-VM copy)
#   ubuntu-24.04-<key>.vmlinuz   the bzImage copied out of that disk
#   ubuntu-24.04-<key>.initrd    the stock initramfs, copied out for the
#                                record; the guest boots WITHOUT it (see
#                                the manifest's `boots_without_initrd`)
#   ubuntu-24.04-<key>.json      manifest: digests, kernel version,
#                                masked units and why, config findings
#
# Content-cached like `cached_erofs_image`: the key is a digest of this
# script, the helper scripts and units, the pinned rootfs tarball digest,
# the agent binary, the apt package list, and the pinned k3s artifacts,
# so an unchanged input set never rebuilds and any change to any of them
# produces a new image rather than a stale hit.
#
# Requires root (loop mount + chroot), network (apt), and $OUT_DIR on a
# reflink-capable filesystem.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"

# --- Pinned inputs (never "latest") ---------------------------------
UBUNTU_RELEASE="24.04"
UBUNTU_BUILD="release-20260814"
ROOTFS_TARBALL="ubuntu-${UBUNTU_RELEASE}-server-cloudimg-amd64-root.tar.xz"
ROOTFS_URL="https://cloud-images.ubuntu.com/releases/${UBUNTU_RELEASE}/${UBUNTU_BUILD}/${ROOTFS_TARBALL}"
ROOTFS_SHA256="6d20ae2cf2692719c40b2d8cf316b7629237431a16dc95464eec88256739b751"
# linux-image-virtual is the flavour this ladder targets. In 24.04 it is
# a meta-package over the *generic* kernel binary with only the base
# module set, which is why the flavour check in test_ubuntu_guest.rs
# asserts against the modules actually present in the image rather than
# against the config alone.
#
# linux-image-extra-virtual (i.e. linux-modules-extra) is here because of
# a measured gap, not for completeness: `cpuidle-haltpoll.ko` — the idle
# driver we picked so an idle vCPU costs neither a host core
# nor a 0.5 ms vmexit per wakeup — ships in *extra*, and with only the
# base set the guest falls back to the `menu` governor with no haltpoll
# at all. It also removes the same class of surprise for the later suites
# (Cilium's tunnels and qdiscs, Longhorn's dm targets). The cost is
# recorded in the manifest as `rootfs_used_kb`.
#
# open-iscsi and nfs-common are Longhorn's two userspace prerequisites:
# `iscsiadm` + a running `iscsid` for a V1 volume's attach path,
# `mount.nfs` for an RWX share. Both are documented
# requirements of the CSI driver, so they belong in the node image
# rather than in a DaemonSet that installs packages at runtime.
#
# rdma-core + ibverbs-utils are Soft-RoCE userspace.
# The kernel module (`rdma_rxe`) already ships in linux-image-extra-virtual;
# `rdma` already ships in iproute2. Ubuntu splits `ibv_devinfo` into
# ibverbs-utils (source package rdma-core) — the binary `rdma-core`
# package is udev rules, not the tool (CHALLENGES #150). Do not add
# perftest / infiniband-diags / ib_send_bw.
APT_PACKAGES="linux-image-virtual linux-image-extra-virtual iproute2 ca-certificates curl kmod iptables conntrack open-iscsi nfs-common rdma-core ibverbs-utils apparmor"

# Units whose only unmet dependency is `network-online.target`, which
# this image cannot reach (`systemd-networkd-wait-online` is masked and
# k7d-net.service owns eth0 — CHALLENGES #108). The drop-in clears that
# ordering instead of masking the unit, because `iscsid` itself must be
# running for Longhorn to attach a volume.
NO_NETWORK_ONLINE_UNITS="iscsid.service rpc-statd.service nfs-idmapd.service"

# k3s is baked offline: the binary plus its airgap image
# tarball, digest-pinned like the cloud-image tarball. Units ship
# *disabled*; k7d-k3s.service reads k7d.k3s= at boot and starts the
# matching one. Version matches the inner-k3s fixture's rancher/k3s
# tag (v1.32.5-k3s1) so the two substrates are comparable.
K3S_VERSION="v1.32.5+k3s1"
K3S_VERSION_URL="v1.32.5%2Bk3s1"
K3S_URL="https://github.com/k3s-io/k3s/releases/download/${K3S_VERSION_URL}/k3s"
K3S_SHA256="9624ef0534b1be432b4ce8dd94dcd7241ed02451d970a4d38943baccf5c60dce"
K3S_AIRGAP="k3s-airgap-images-amd64.tar.zst"
K3S_AIRGAP_URL="https://github.com/k3s-io/k3s/releases/download/${K3S_VERSION_URL}/${K3S_AIRGAP}"
K3S_AIRGAP_SHA256="ac1f278f1b006851d95cd3236e9b909264872e9f6b5ffcf90d28198c6f2e913c"
K3S_IMAGES_TXT_URL="https://github.com/k3s-io/k3s/releases/download/${K3S_VERSION_URL}/k3s-images.txt"
K3S_IMAGES_TXT_SHA256="aa8e10337aef453cb17e6408dbaec9eb2da409ca6ba1f8bc7332fcef97fdaf3a"

# A subdirectory of the reflink XFS, not its root: FICLONE needs the same
# filesystem as the per-VM clones, but everything directly under
# /var/lib/k7d/disks is by contract a per-VM image, and the test suite's
# hygiene sweep deletes every *.img there that no live VM holds open
# (`sweep_disks` in tests/common). A cached base image left in that
# directory is therefore reaped at the start of the next test binary and
# silently rebuilt, minutes at a time. The sweep does not recurse.
OUT_DIR="${OUT_DIR:-/var/lib/k7d/disks/base-images}"
CACHE_DIR="${CACHE_DIR:-/var/cache/k7d-ubuntu}"
AGENT_BIN="${AGENT_BIN:-${REPO_ROOT}/target/x86_64-unknown-linux-musl/release/k7-agent}"
# 16 GiB sparse: the rootfs plus a kernel is ~2.4 GiB used, k3s's airgap
# images are ~1 GiB more, and a CSI stack (Longhorn's
# manager, engine, instance-manager, share-manager and CSI sidecars) is
# several GiB of unpacked images per node on top of Cilium. At 6 GiB the
# kubelet hit its `nodefs` eviction threshold and evicted the very
# DaemonSet that was pulling — which reads as a Longhorn failure, not as
# the node running out of root disk. Sparse, so the headroom costs only
# what a node actually writes.
IMAGE_SIZE="${IMAGE_SIZE:-17179869184}"

# Units masked in the image. Each line is `unit<TAB>reason` and lands in
# the manifest verbatim: masking is a recorded decision, not a tidy-up.
# Anything time-triggered matters twice over — a warm fork resumes with
# the source's uptime, so a timer that fires on resume would show up as
# a newly-failed unit on the child.
MASKED_UNITS=$(cat <<'UNITS'
snapd.service	snap has no role in a VM node image; its seeding costs seconds of boot
snapd.socket	same, and the socket would re-activate the service
snapd.seeded.service	waits for a seeding that never happens
cloud-init.service	no cloud-init datasource: the k7d cmdline is the only config channel
cloud-init-local.service	same, and it blocks boot waiting for metadata
cloud-config.service	same
cloud-final.service	same
apt-daily.service	apt over the network on a timer; a fork would resume into it
apt-daily.timer	the timer that starts it
apt-daily-upgrade.service	unattended upgrades must never run under a test
apt-daily-upgrade.timer	the timer that starts it
systemd-tmpfiles-clean.timer	fires on resume after a fork with the source's uptime
motd-news.service	fetches a news blob over the network at login
motd-news.timer	the timer that starts it
man-db.timer	rebuilds a man cache nobody reads in a VM
dpkg-db-backup.timer	backs up dpkg's db on a disk that is reflinked away
e2scrub_all.timer	online fsck of an ext4 image the host owns
e2scrub_reap.service	same
fstrim.timer	discard on a sparse image behind a loop device
systemd-networkd.service	k7d-net.service owns eth0; networkd would race it with DHCP
systemd-networkd.socket	same
systemd-networkd-wait-online.service	would block boot waiting for a link networkd never configures
systemd-resolved.service	/etc/resolv.conf is a real file here; resolved would replace it with a stub pointing at itself
systemd-timesyncd.service	k7d owns the guest clock: an in-guest NTP client reaches ntp.ubuntu.com through the bridge's MASQUERADE and steps CLOCK_REALTIME back to true time within seconds, silently undoing a warp
systemd-time-wait-sync.service	the barrier timesyncd satisfies; with timesyncd masked it would block time-sync.target forever
apport.service	crash reporting has no upload path from a VM
unattended-upgrades.service	same reason as apt-daily-upgrade
nm-cloud-setup.service	NetworkManager cloud-setup waits for metadata that a k7d VM does not have
nm-cloud-setup.timer	the timer that starts it
open-iscsi.service	logs into remembered iSCSI targets after network-online.target, which this image cannot reach (CHALLENGES #108); Longhorn does its own iscsiadm logins and only needs iscsid
iwpmd.service	iWARP port mapper from rdma-core; no iWARP hardware on virtio-mmio
rdma-ndd.service	rdma-core node-description daemon; wants dmidecode, which --no-install-recommends omits
UNITS
)

die() { echo "build-node-image: $*" >&2; exit 1; }

# True if any process holds `img` open. A FICLONE clone does not pin
# its source; anything booted directly off the base would.
img_is_open() {
    local want target fd
    want=$(readlink -f "$1" 2>/dev/null) || return 1
    for fd in /proc/[0-9]*/fd/*; do
        target=$(readlink "$fd" 2>/dev/null) || continue
        if [[ "$target" == "$want" ]]; then
            return 0
        fi
    done
    return 1
}

# Evict old content-keyed sets from OUT_DIR. Keep K7D_KEEP_BASE_IMAGES
# (default 2) most recently modified sets. Skip a set whose .img is
# open rather than deleting it. Deletes all four files of each evicted
# set (.img, .initrd, .vmlinuz, .json).
gc_old_base_images() {
    local out_dir="${1:-$OUT_DIR}"
    local keep="${K7D_KEEP_BASE_IMAGES:-2}"
    [[ "$keep" =~ ^[0-9]+$ ]] || die "K7D_KEEP_BASE_IMAGES must be an integer, got ${keep}"
    (( keep >= 1 )) || die "K7D_KEEP_BASE_IMAGES must be >= 1, got ${keep}"
    [[ -d "$out_dir" ]] || return 0

    local -a sets=()
    local img
    shopt -s nullglob
    for img in "$out_dir"/ubuntu-*.img; do
        sets+=("${img%.img}")
    done
    shopt -u nullglob
    ((${#sets[@]})) || return 0

    local sorted base i=0
    # GNU `stat %N` is the quoted filename, not nanoseconds. Same-second
    # mtimes then sort by path and can evict the set just built. `%T@`
    # is seconds with a fractional part.
    sorted=$(
        for base in "${sets[@]}"; do
            printf '%s\t%s\n' "$(find "${base}.img" -maxdepth 0 -printf '%T@')" "$base"
        done | sort -nr | cut -f2-
    )
    while IFS= read -r base; do
        [[ -n "$base" ]] || continue
        i=$((i + 1))
        if (( i <= keep )); then
            continue
        fi
        if [[ -e "${base}.img" ]] && img_is_open "${base}.img"; then
            echo "gc-base-images: skip ${base}.img (.img is open)" >&2
            continue
        fi
        echo "gc-base-images: deleting set $(basename "$base")" >&2
        rm -f "${base}.img" "${base}.initrd" "${base}.vmlinuz" "${base}.json"
    done <<< "$sorted"
}

if [[ "${1:-}" == --gc-only ]]; then
    gc_old_base_images "$OUT_DIR"
    exit 0
fi

PRINT_KEY=0
[[ "${1:-}" == --print-key ]] && PRINT_KEY=1

if [[ $PRINT_KEY -eq 0 ]]; then
    [[ $EUID -eq 0 ]] || die "must run as root (loop mount + chroot)"
fi
[[ -f "$AGENT_BIN" ]] || die "k7-agent not found at $AGENT_BIN — run 'make build-agent'"
if [[ $PRINT_KEY -eq 0 ]]; then
    for tool in mkfs.ext4 tar curl chroot sha256sum; do
        command -v "$tool" >/dev/null || die "missing required tool: $tool"
    done
else
    command -v sha256sum >/dev/null || die "missing required tool: sha256sum"
fi

# --- Content key ----------------------------------------------------
KEY=$(
    {
        sha256sum "$0" "$AGENT_BIN" \
            "$SCRIPT_DIR/k7d-netconfig" \
            "$SCRIPT_DIR/k7d-k3sconfig" \
            "$SCRIPT_DIR/units/k7-agent.service" \
            "$SCRIPT_DIR/units/k7d-net.service" \
            "$SCRIPT_DIR/units/k7d-k3s.service" \
            "$SCRIPT_DIR/units/k3s.service" \
            "$SCRIPT_DIR/units/k3s-agent.service" \
            "$SCRIPT_DIR/units/k7d-no-network-online.conf" \
            "$SCRIPT_DIR/apparmor/k7-agent" \
            "$SCRIPT_DIR/apparmor/k7-deny-vsock" \
            "$SCRIPT_DIR/k7d-vsock-apparmor-check" \
            "$SCRIPT_DIR/containerd/config-v3.toml.tmpl"
        echo "$ROOTFS_SHA256 $APT_PACKAGES $IMAGE_SIZE $NO_NETWORK_ONLINE_UNITS"
        echo "$MASKED_UNITS"
        echo "$K3S_VERSION $K3S_SHA256 $K3S_AIRGAP_SHA256 $K3S_IMAGES_TXT_SHA256"
    } | sha256sum | cut -c1-16
)
BASE="ubuntu-${UBUNTU_RELEASE}-${KEY}"
IMG="${OUT_DIR}/${BASE}.img"
KERNEL_OUT="${OUT_DIR}/${BASE}.vmlinuz"
INITRD_OUT="${OUT_DIR}/${BASE}.initrd"
MANIFEST="${OUT_DIR}/${BASE}.json"

if [[ "${1:-}" == --print-key ]]; then
    echo "$KEY"
    exit 0
fi

mkdir -p "$OUT_DIR" "$CACHE_DIR"

# The manifest is written last, so its presence is what proves the whole
# build finished. A half-built image with no manifest is rebuilt.
# A cache hit is a read-only fast path: do not GC here.
if [[ -f "$MANIFEST" && -f "$IMG" && -f "$KERNEL_OUT" && -f "$INITRD_OUT" ]]; then
    echo "==> cache hit: $IMG"
    cat "$MANIFEST"
    exit 0
fi

# --- Fetch the pinned rootfs ----------------------------------------
TARBALL="${CACHE_DIR}/${UBUNTU_BUILD}-${ROOTFS_TARBALL}"
if [[ -f "$TARBALL" ]] && echo "${ROOTFS_SHA256}  ${TARBALL}" | sha256sum -c - >/dev/null 2>&1; then
    echo "==> using cached $TARBALL"
else
    echo "==> downloading $ROOTFS_URL"
    curl -fsSL -o "${TARBALL}.part" "$ROOTFS_URL"
    echo "${ROOTFS_SHA256}  ${TARBALL}.part" | sha256sum -c - \
        || die "rootfs tarball digest mismatch — refusing an unpinned image"
    mv "${TARBALL}.part" "$TARBALL"
fi

fetch_pinned() {
    local url=$1 dest=$2 expect=$3
    if [[ -f "$dest" ]] && echo "${expect}  ${dest}" | sha256sum -c - >/dev/null 2>&1; then
        echo "==> using cached $dest"
        return
    fi
    echo "==> downloading $url"
    curl -fsSL -o "${dest}.part" "$url"
    echo "${expect}  ${dest}.part" | sha256sum -c - \
        || die "digest mismatch for $dest — refusing an unpinned artifact"
    mv "${dest}.part" "$dest"
}

K3S_BIN="${CACHE_DIR}/k3s-${K3S_VERSION}"
K3S_AIRGAP_FILE="${CACHE_DIR}/${K3S_VERSION}-${K3S_AIRGAP}"
K3S_IMAGES_TXT="${CACHE_DIR}/${K3S_VERSION}-k3s-images.txt"
fetch_pinned "$K3S_URL" "$K3S_BIN" "$K3S_SHA256"
fetch_pinned "$K3S_AIRGAP_URL" "$K3S_AIRGAP_FILE" "$K3S_AIRGAP_SHA256"
fetch_pinned "$K3S_IMAGES_TXT_URL" "$K3S_IMAGES_TXT" "$K3S_IMAGES_TXT_SHA256"
chmod 0755 "$K3S_BIN"

# --- Build ----------------------------------------------------------
MNT=$(mktemp -d)
BUILD_IMG="${IMG}.building"
cleanup() {
    local rc=$?
    for d in dev/pts dev proc sys; do
        mountpoint -q "$MNT/$d" && umount -l "$MNT/$d" || true
    done
    mountpoint -q "$MNT" && umount "$MNT" || true
    rmdir "$MNT" 2>/dev/null || true
    if [[ $rc -ne 0 ]]; then
        rm -f "$BUILD_IMG"
    fi
}
trap cleanup EXIT

rm -f "$BUILD_IMG"
truncate -s "$IMAGE_SIZE" "$BUILD_IMG"
# `-O ^has_journal` is deliberately NOT used: systemd's writes want a
# journalled fs, and a fork's reflinked copy must be recoverable.
mkfs.ext4 -F -q -L k7d-root "$BUILD_IMG"
mount -o loop "$BUILD_IMG" "$MNT"

echo "==> unpacking $ROOTFS_TARBALL"
tar -xpf "$TARBALL" -C "$MNT" --numeric-owner --xattrs-include='*'

# resolv.conf as a real file, not a symlink into resolved's stub dir:
# systemd-resolved is masked below, and a dangling symlink is how a
# guest ends up with working NAT and no DNS.
rm -f "$MNT/etc/resolv.conf"
printf 'nameserver 1.1.1.1\nnameserver 8.8.8.8\n' > "$MNT/etc/resolv.conf"

for d in dev dev/pts proc sys; do
    mkdir -p "$MNT/$d"
done
mount --bind /dev "$MNT/dev"
mount -t devpts devpts "$MNT/dev/pts"
mount -t proc proc "$MNT/proc"
mount -t sysfs sysfs "$MNT/sys"

in_chroot() { chroot "$MNT" /usr/bin/env DEBIAN_FRONTEND=noninteractive "$@"; }

echo "==> installing $APT_PACKAGES"
in_chroot apt-get -qq update
# shellcheck disable=SC2086 # word splitting of the package list is wanted
in_chroot apt-get -qq install -y --no-install-recommends $APT_PACKAGES
# vsock is the door; sshd would be a second one with a password database
# behind it. Purge rather than mask so the binary is not even present.
in_chroot apt-get -qq purge -y openssh-server >/dev/null 2>&1 || true
in_chroot apt-get -qq clean

KVER=$(ls "$MNT"/boot/vmlinuz-* | sed 's|.*/vmlinuz-||' | sort -V | tail -1)
[[ -n "$KVER" ]] || die "no kernel installed in the image"
KPKG_VERSION=$(in_chroot dpkg-query -W -f '${Version}' "linux-image-${KVER}")
[[ -f "$MNT/boot/initrd.img-${KVER}" ]] || die "no initramfs for ${KVER}"
[[ -f "$MNT/boot/config-${KVER}" ]] || die "no kernel config for ${KVER}"

echo "==> installing the k7-agent and its units"
install -D -m 0755 "$AGENT_BIN" "$MNT/usr/local/bin/k7-agent"
install -D -m 0755 "$SCRIPT_DIR/k7d-netconfig" "$MNT/usr/local/sbin/k7d-netconfig"
install -D -m 0755 "$SCRIPT_DIR/k7d-k3sconfig" "$MNT/usr/local/sbin/k7d-k3sconfig"
install -D -m 0644 "$SCRIPT_DIR/units/k7-agent.service" \
    "$MNT/etc/systemd/system/k7-agent.service"
install -D -m 0644 "$SCRIPT_DIR/units/k7d-net.service" \
    "$MNT/etc/systemd/system/k7d-net.service"
install -D -m 0644 "$SCRIPT_DIR/units/k7d-k3s.service" \
    "$MNT/etc/systemd/system/k7d-k3s.service"
install -D -m 0644 "$SCRIPT_DIR/units/k3s.service" \
    "$MNT/etc/systemd/system/k3s.service"
install -D -m 0644 "$SCRIPT_DIR/units/k3s-agent.service" \
    "$MNT/etc/systemd/system/k3s-agent.service"
# AppArmor vsock jail. Profiles load via apparmor.service
# at boot; the agent unit refuses to start if they are not enforcing.
install -D -m 0644 "$SCRIPT_DIR/apparmor/k7-agent" \
    "$MNT/etc/apparmor.d/k7-agent"
install -D -m 0644 "$SCRIPT_DIR/apparmor/k7-deny-vsock" \
    "$MNT/etc/apparmor.d/k7-deny-vsock"
install -D -m 0755 "$SCRIPT_DIR/k7d-vsock-apparmor-check" \
    "$MNT/usr/local/sbin/k7d-vsock-apparmor-check"
# Compile-check only (`-Q` skips the kernel load). `-p` is preprocess
# and does not catch conflicting x modifiers (CHALLENGES #161).
in_chroot apparmor_parser -Q /etc/apparmor.d/k7-deny-vsock \
    || die "AppArmor profile k7-deny-vsock failed to compile"
in_chroot apparmor_parser -Q /etc/apparmor.d/k7-deny-vsock \
    /etc/apparmor.d/k7-agent \
    || die "AppArmor profile k7-agent failed to compile"

echo "==> clearing network-online.target ordering from $NO_NETWORK_ONLINE_UNITS"
for unit in $NO_NETWORK_ONLINE_UNITS; do
    install -D -m 0644 "$SCRIPT_DIR/units/k7d-no-network-online.conf" \
        "$MNT/etc/systemd/system/${unit}.d/k7d-no-network-online.conf"
done

# Longhorn's V1 attach path needs `iscsiadm` and a running `iscsid`, and
# an RWX share needs `mount.nfs`. A package that installed but left one
# of these missing would surface as an unschedulable CSI plugin minutes
# later, so check inside the image instead.
for tool in /usr/sbin/iscsiadm /usr/sbin/iscsid /usr/sbin/mount.nfs /usr/bin/ibv_devinfo; do
    [[ -e "$MNT$tool" ]] || die "$tool missing from the image — check APT_PACKAGES"
done
in_chroot systemctl enable iscsid.service >/dev/null 2>&1 || {
    mkdir -p "$MNT/etc/systemd/system/sysinit.target.wants"
    ln -sf /usr/lib/systemd/system/iscsid.service \
        "$MNT/etc/systemd/system/sysinit.target.wants/iscsid.service"
}

echo "==> installing digest-pinned k3s ${K3S_VERSION} (units stay disabled)"
install -D -m 0755 "$K3S_BIN" "$MNT/usr/local/bin/k3s"
ln -sfn k3s "$MNT/usr/local/bin/kubectl"
ln -sfn k3s "$MNT/usr/local/bin/crictl"
ln -sfn k3s "$MNT/usr/local/bin/ctr"
mkdir -p "$MNT/var/lib/rancher/k3s/agent/images" \
    "$MNT/var/lib/rancher/k3s/agent/etc/containerd"
install -D -m 0644 "$SCRIPT_DIR/containerd/config-v3.toml.tmpl" \
    "$MNT/var/lib/rancher/k3s/agent/etc/containerd/config-v3.toml.tmpl"
install -D -m 0644 "$K3S_AIRGAP_FILE" \
    "$MNT/var/lib/rancher/k3s/agent/images/${K3S_AIRGAP}"
install -D -m 0644 "$K3S_IMAGES_TXT" "$MNT/usr/local/share/k7d/k3s-images.txt"
# k3s/k3s-agent are present so k7d-k3sconfig can start them, but they
# must not come up on a node that has no k7d.k3s= (a bare boot VM).
in_chroot systemctl disable k3s.service k3s-agent.service >/dev/null 2>&1 || true
rm -f "$MNT/etc/systemd/system/multi-user.target.wants/k3s.service" \
    "$MNT/etc/systemd/system/multi-user.target.wants/k3s-agent.service"

in_chroot systemctl enable k7-agent.service k7d-net.service k7d-k3s.service >/dev/null 2>&1 || {
    # `systemctl enable` in a chroot is only symlink-writing, but if it
    # refuses (no /run/systemd, dbus-activated variants) the enablement
    # must still happen — a disabled agent unit is a VM that never
    # answers, and the failure would surface as a connect timeout.
    mkdir -p "$MNT/etc/systemd/system/multi-user.target.wants"
    for unit in k7-agent.service k7d-net.service k7d-k3s.service; do
        ln -sf "/etc/systemd/system/$unit" \
            "$MNT/etc/systemd/system/multi-user.target.wants/$unit"
    done
}

# vsock and the haltpoll idle driver are modules in this flavour
# (CONFIG_VSOCKETS=m, CONFIG_VIRTIO_VSOCKETS=m, CONFIG_HALTPOLL_CPUIDLE=m),
# and nothing on a virtio-mmio bus triggers their autoload — no bus to
# enumerate, the devices are created from the kernel command line. Load
# them explicitly. `cpuidle_haltpoll.force=1` on the cmdline still
# applies: modprobe reads /proc/cmdline for module parameters.
cat > "$MNT/etc/modules-load.d/k7d.conf" <<'MODULES'
# k7d: both are modules in linux-image-virtual and
# neither has an autoload trigger on a virtio-mmio-only machine.
vmw_vsock_virtio_transport
cpuidle_haltpoll
# k3s' containerd snapshotter and kube-proxy.
overlay
br_netfilter
MODULES

# Root on virtio-blk. `nofail` is deliberately absent: a root that did
# not mount must stop the boot loudly, not continue into a broken guest.
cat > "$MNT/etc/fstab" <<'FSTAB'
LABEL=k7d-root / ext4 defaults 0 1
FSTAB

# A fixed machine-id: an empty one puts systemd into first-boot mode
# (preset-all, extra units, a slower and noisier boot) on every VM, and
# a fork would inherit whatever the source generated anyway.
echo "k7d0000000000000000000000000000a5" > "$MNT/etc/machine-id"
echo "k7d-node" > "$MNT/etc/hostname"
printf '127.0.0.1 localhost\n127.0.1.1 k7d-node\n' > "$MNT/etc/hosts"
# No password logins at all: the console is a debugging tap, vsock is
# the interface.
in_chroot passwd -l root >/dev/null

echo "==> masking units"
MASKED_ENTRIES=()
while IFS=$'\t' read -r unit reason; do
    [[ -n "$unit" ]] || continue
    # A unit absent from this image is masked anyway (a symlink to
    # /dev/null), so a later `apt install` cannot resurrect it.
    in_chroot systemctl mask "$unit" >/dev/null 2>&1 || \
        ln -sf /dev/null "$MNT/etc/systemd/system/$unit"
    MASKED_ENTRIES+=("{\"unit\":\"${unit}\",\"reason\":\"${reason}\"}")
done <<< "$MASKED_UNITS"
MASKED_JSON="[$(IFS=,; echo "${MASKED_ENTRIES[*]}")]"

# Unmount the pseudo-filesystems before measuring anything: `du` over a
# bind-mounted /proc walks live host process directories and fails on
# whatever exited mid-walk.
umount -l "$MNT/dev/pts"
umount -l "$MNT/dev"
umount -l "$MNT/proc"
umount -l "$MNT/sys"

echo "==> copying the kernel out"
cp "$MNT/boot/vmlinuz-${KVER}" "${KERNEL_OUT}.building"
cp "$MNT/boot/initrd.img-${KVER}" "${INITRD_OUT}.building"
CONFIG_SHA=$(sha256sum "$MNT/boot/config-${KVER}" | cut -d' ' -f1)
# The three built-ins that decide whether the stock initrd is needed at
# all. All three are =y in this flavour, so `root=/dev/vda` mounts with
# no initramfs — recorded here, asserted in the test.
BOOTS_WITHOUT_INITRD=true
for cfg in CONFIG_VIRTIO_MMIO CONFIG_VIRTIO_MMIO_CMDLINE_DEVICES CONFIG_VIRTIO_BLK CONFIG_EXT4_FS; do
    grep -q "^${cfg}=y" "$MNT/boot/config-${KVER}" || BOOTS_WITHOUT_INITRD=false
done
MODULE_COUNT=$(find "$MNT/lib/modules/${KVER}" -name '*.ko*' | wc -l)
ROOTFS_USED_KB=$(du -sk --one-file-system "$MNT" | cut -f1)

umount "$MNT"

mv "${KERNEL_OUT}.building" "$KERNEL_OUT"
mv "${INITRD_OUT}.building" "$INITRD_OUT"
mv "$BUILD_IMG" "$IMG"

cat > "$MANIFEST" <<JSON
{
  "key": "${KEY}",
  "ubuntu_release": "${UBUNTU_RELEASE}",
  "cloud_image_build": "${UBUNTU_BUILD}",
  "cloud_image_tarball": "${ROOTFS_TARBALL}",
  "cloud_image_sha256": "${ROOTFS_SHA256}",
  "apt_packages": "${APT_PACKAGES}",
  "kernel_version": "${KVER}",
  "kernel_package_version": "${KPKG_VERSION}",
  "kernel_config_sha256": "${CONFIG_SHA}",
  "kernel_module_count": ${MODULE_COUNT},
  "boots_without_initrd": ${BOOTS_WITHOUT_INITRD},
  "image": "${IMG}",
  "image_size_bytes": ${IMAGE_SIZE},
  "rootfs_used_kb": ${ROOTFS_USED_KB},
  "kernel": "${KERNEL_OUT}",
  "initrd": "${INITRD_OUT}",
  "agent_sha256": "$(sha256sum "$AGENT_BIN" | cut -d' ' -f1)",
  "k3s_version": "${K3S_VERSION}",
  "k3s_sha256": "${K3S_SHA256}",
  "k3s_airgap": "${K3S_AIRGAP}",
  "k3s_airgap_sha256": "${K3S_AIRGAP_SHA256}",
  "k3s_images_txt_sha256": "${K3S_IMAGES_TXT_SHA256}",
  "k3s_units_disabled": ["k3s.service", "k3s-agent.service"],
  "no_network_online_units": "${NO_NETWORK_ONLINE_UNITS}",
  "masked_units": ${MASKED_JSON}
}
JSON

echo "==> built $IMG"
cat "$MANIFEST"
gc_old_base_images "$OUT_DIR"
