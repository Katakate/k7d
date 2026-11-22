#!/usr/bin/env bash
# Privilege separation — the VM broker's identity, the udev rule that carries
# /dev/vhost-vsock to it, and the ownership of the state it writes.
#
# Sourced, not executed: `packaging/install.sh` (release install) and
# `your node provisioning` (fresh bare-metal node) both need exactly
# this, and a second copy would be a second thing to forget. The grep test
# in crates/k7d/tests/test_hardening.rs asserts both callers use it.
#
# The VM broker's account, udev rule, and state-directory ownership.

# The account the VM broker runs as. System user, no shell, no login; its
# home is the state directory it owns. Group `kvm` is what makes /dev/kvm
# and (with the rule below) /dev/vhost-vsock openable without a capability.
k7d_create_account() {
    # CoreOS (RHCOS, SCOS) keeps `kvm` in /usr/lib/group behind
    # nss-altfiles; getent sees it, useradd/usermod only read /etc/group.
    if ! grep -q '^kvm:' /etc/group; then
        getent group kvm >>/etc/group
    fi
    getent group k7d >/dev/null || groupadd --system k7d
    getent passwd k7d >/dev/null || useradd --system --gid k7d --groups kvm \
        --home-dir /var/lib/k7d --no-create-home --shell /usr/sbin/nologin k7d
    # Idempotent, and the migration path for an account created by an
    # older install that predates the kvm membership.
    usermod -aG kvm k7d
}

# /dev/vhost-vsock is root:root 0600 on Ubuntu. Loud on failure: a rule
# that did not apply means the split daemon cannot boot a VM at all, and
# discovering that at the first create_vm instead of at install time is
# the difference between a packaging error and an outage.
k7d_install_udev_rule() {
    local rules_src="$1"
    install -m 0644 "$rules_src" /etc/udev/rules.d/60-k7d.rules
    echo vhost_vsock >/etc/modules-load.d/k7d.conf
    modprobe vhost_vsock
    udevadm control --reload
    udevadm trigger --name-match=vhost-vsock --settle
    local got
    got="$(stat -c '%G %a' /dev/vhost-vsock)"
    if [[ "$got" != "kvm 660" ]]; then
        echo "60-k7d.rules did not apply: /dev/vhost-vsock is '$got', want 'kvm 660'" >&2
        return 1
    fi
}

# State the VM broker writes as uid k7d. The Firecracker chroot base and
# the jailer's cgroup root stay root-owned 0700 — they are the node
# broker's, and §10.4's fuzz precondition asserts uid k7d cannot enter
# them. `disks/{trees,data}` live on the loop-mounted XFS, so this has to
# run after k7d-mount-disks; both callers do.
# `mkdir -p` + `chown`/`chmod` rather than `install -d`, because
# /var/lib/k7d/trees and /var/lib/k7d/fc are symlinks onto the loop-mounted
# XFS (your node provisioning, k7d::disks::ensure_reflink_*): the
# ownership has to land on the target, which is what following the link
# does and what `install -d` would fight about. `chown -R` is also the
# migration for a node upgraded in place, whose tree and sandbox files are
# root-owned from before the split — without it the first VM broker fails
# on its own state dir.
k7d_own_state_dirs() {
    local dir owner
    for dir in /var/lib/k7d/trees /var/lib/k7d/sandboxes /var/lib/k7d/stage \
        /var/lib/k7d/disks/trees /var/lib/k7d/disks/data; do
        owner="$(stat -c '%U' "$dir" 2>/dev/null || true)"
        mkdir -p "$dir"
        chmod 0750 "$dir"
        # The recursive pass is the in-place migration and nothing else.
        # Repeating it is a full walk of every tree's snapshot files on a
        # node the suite reprovisions before each test binary, which the
        # latency budgets would notice; the directory's own owner is the
        # marker for whether it has already happened.
        [[ "$owner" == k7d ]] || chown -R k7d:k7d "$dir"
    done
    # The XFS mount root is the VM broker's too — a fork's reflink dir is
    # a sibling of the image it clones, so it lands here (CHALLENGES
    # #250). Non-recursive on purpose: `base-images` is tens of GiB of
    # root-owned bits the VM broker only reads, and `fc` below must stay
    # root's. 0755, not 0750: a jailed Firecracker's lease uid is in no
    # group of ours and traverses this to reach its chroot.
    chown k7d:k7d /var/lib/k7d/disks
    chmod 0755 /var/lib/k7d/disks
    # The Firecracker jails and the jailer's cgroup root stay the node
    # broker's. §10.4's fuzz precondition asserts uid k7d cannot enter
    # either, so this line is load-bearing rather than tidy.
    mkdir -p /var/lib/k7d/fc
    chown root:root /var/lib/k7d/fc
    chmod 0700 /var/lib/k7d/fc
}

# All three, in the only order that works.
k7d_provision_vm_broker_identity() {
    k7d_create_account
    k7d_install_udev_rule "$1"
    k7d_own_state_dirs
}
