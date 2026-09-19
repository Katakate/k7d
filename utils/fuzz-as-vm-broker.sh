#!/usr/bin/env bash
# Run every fuzz target with the VM broker's privileges, not root's.
#
# Privilege separation moved every parser a guest or a shim can reach
# into a process that is uid k7d with an empty capability set. A fuzz
# run as root measures a process that no longer exists: a bug that
# libFuzzer finds while it can mount, make a TAP and write another
# uid's cgroup is a different bug from the same input hitting the real
# VM broker.
#
# So this script does two things, in this order:
#
#  1. Asserts the sandbox is real. Four probes, each of
#     which must *fail* under `setpriv`: TUNSETIFF, a mkdir in the
#     jailer's root-only cgroup tree, a bind mount, and a non-empty
#     bounding set. A probe that unexpectedly succeeds means the run
#     would have been measuring root, so it is fatal — not a warning.
#  2. Builds each target as root (cargo needs the target dir) and runs
#     it under `setpriv` as k7d.
#
# Usage: utils/fuzz-as-vm-broker.sh <seconds-per-target> <target>...

set -euo pipefail

SECONDS_PER_TARGET="${1:?usage: $0 <seconds-per-target> <target>...}"
shift
TARGETS=("$@")
[[ ${#TARGETS[@]} -gt 0 ]] || {
    echo "no fuzz targets given" >&2
    exit 1
}

BROKER_USER="k7d"
FUZZ_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../fuzz" && pwd)"

[[ $(id -u) -eq 0 ]] || {
    echo "must start as root: the point is to drop to $BROKER_USER" >&2
    exit 1
}
id "$BROKER_USER" >/dev/null 2>&1 || {
    echo "no $BROKER_USER account — run packaging/install.sh or your node provisioning" >&2
    exit 1
}

# `--clear-groups` and not `--groups kvm`: a fuzz target opens no device,
# and running with fewer privileges than the real VM broker is the safe
# direction for a sandbox assertion.
as_broker() {
    setpriv --reuid "$BROKER_USER" --regid "$BROKER_USER" --clear-groups \
        --no-new-privs --inh-caps=-all --bounding-set=-all -- "$@"
}

# --- 1. the sandbox precondition ---------------------------------------

refuse() {
    local what="$1"
    shift
    if as_broker "$@" >/dev/null 2>&1; then
        echo "FATAL: uid $BROKER_USER could $what — this fuzz run would be measuring root" >&2
        exit 1
    fi
    echo "  refused as expected: $what"
}

echo "==> sandbox precondition for uid $BROKER_USER"
# TUNSETIFF: /dev/net/tun is 0666, so the open succeeds and the ioctl is
# what CAP_NET_ADMIN gates. `ip tuntap add` is that ioctl.
refuse "create a TAP (TUNSETIFF)" ip tuntap add dev k7fuzzprobe0 mode tap
# The jailer's parent cgroup is root-only and deliberately never
# delegated, unlike the VM broker service.
mkdir -p /sys/fs/cgroup/k7d
refuse "mkdir under /sys/fs/cgroup/k7d" mkdir /sys/fs/cgroup/k7d/fuzz-probe
refuse "bind-mount /tmp" mount --bind /tmp /tmp
bnd="$(as_broker cat /proc/self/status | awk '/^CapBnd:/ {print $2}')"
if [[ "${bnd//0/}" != "" ]]; then
    echo "FATAL: CapBnd is $bnd, want all zeroes" >&2
    exit 1
fi
echo "  CapBnd is $bnd"

# libFuzzer writes its corpus and crash artifacts relative to the cwd,
# which root owns. Give the unprivileged run somewhere it can write, or a
# crash is reported as a failure to save the reproducer.
WORK="$(mktemp -d /tmp/k7d-fuzz-XXXXXX)"
chown "$BROKER_USER:$BROKER_USER" "$WORK"
trap 'rm -rf "$WORK"' EXIT

# --- 2. build as root, run as k7d -----------------------------------

cd "$FUZZ_DIR"
for target in "${TARGETS[@]}"; do
    echo "==> building $target"
    cargo +nightly fuzz build "$target"
    # `cargo fuzz build` puts the binary under the fuzz target dir, under
    # whatever the host triple is; there is exactly one.
    bin="$(find target -maxdepth 3 -type f -name "$target" -perm -u+x | head -1)"
    [[ -n "$bin" ]] || {
        echo "built $target but found no binary under $FUZZ_DIR/target" >&2
        exit 1
    }
    corpus="$WORK/corpus/$target"
    mkdir -p "$corpus"
    chown -R "$BROKER_USER:$BROKER_USER" "$WORK"
    echo "==> fuzzing $target for ${SECONDS_PER_TARGET}s as $BROKER_USER"
    as_broker "$(pwd)/$bin" "$corpus" \
        -max_total_time="$SECONDS_PER_TARGET" \
        -artifact_prefix="$WORK/" \
        -print_final_stats=1
done

echo "==> all ${#TARGETS[@]} target(s) clean as uid $BROKER_USER"
