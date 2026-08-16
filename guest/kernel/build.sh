#!/usr/bin/env bash
# Build a minimal guest kernel for k7d.
# Must run on a Linux x86 host (not macOS).
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
KERNEL_VERSION="6.12.10"
KERNEL_URL="https://cdn.kernel.org/pub/linux/kernel/v6.x/linux-${KERNEL_VERSION}.tar.xz"
BUILD_DIR="${SCRIPT_DIR}/linux-${KERNEL_VERSION}"
CONFIG_FILE="${SCRIPT_DIR}/config-minimal"
DRIFT_FILE="${SCRIPT_DIR}/config-drift-allowed"

for f in "$CONFIG_FILE" "$DRIFT_FILE"; do
    [[ -f "$f" ]] || {
        echo "Missing $f" >&2
        exit 1
    }
done

# `make olddefconfig` answers the requests it can and drops the rest
# without a word — an option whose dependency is unmet reads exactly
# like an option nobody asked for. That silence once shipped a guest
# whose nf_tables had no address families at all (CONFIG_NF_TABLES_INET
# depends on IPV6, which was off then), and the only symptom was nested
# dockerd dying on "TABLE_ADD failed (Not supported): table nat" weeks
# later. So: compare what kconfig answered against what config-minimal
# asked for, and refuse to build anything else. Symbols kconfig will
# never answer as asked are listed, with a reason each, in
# config-drift-allowed.
assert_config_survived() {
    local answered="$1"
    local sym want got drifted=0

    while IFS= read -r line; do
        if [[ "$line" =~ ^(CONFIG_[A-Za-z0-9_]+)=(.*)$ ]]; then
            sym="${BASH_REMATCH[1]}"
            want="${BASH_REMATCH[2]}"
        elif [[ "$line" =~ ^#[[:space:]](CONFIG_[A-Za-z0-9_]+)[[:space:]]is[[:space:]]not[[:space:]]set$ ]]; then
            sym="${BASH_REMATCH[1]}"
            want=""
        else
            continue
        fi
        grep -qE "^${sym}([[:space:]]|$)" "$DRIFT_FILE" && continue

        # A symbol kconfig turned off is absent from the answer, not
        # written out as "is not set", so a missing line reads as off.
        got="$(sed -n "s/^${sym}=//p" "$answered")"
        [[ "$got" == "$want" ]] && continue

        ((drifted == 0)) && echo "==> kconfig did not honour config-minimal:" >&2
        printf '      %-38s asked %-12s got %s\n' \
            "$sym" "${want:-off}" "${got:-off}" >&2
        drifted=$((drifted + 1))
    done <"$CONFIG_FILE"

    ((drifted == 0)) && return 0

    cat >&2 <<EOF

$drifted option(s) did not survive 'make olddefconfig'. A guest built
from this config would not be the guest config-minimal describes.
Satisfy the dependency kconfig is missing, ask for the value it
enforces, or — if it is one kconfig will never honour — record it in
$(basename "$DRIFT_FILE") with the reason.
EOF
    exit 1
}

if [[ ! -d "$BUILD_DIR" ]]; then
    echo "==> Downloading Linux ${KERNEL_VERSION}"
    curl -fSL "$KERNEL_URL" | tar -xJ -C "$SCRIPT_DIR"
fi

echo "==> Applying haltpoll warm-pool patches"
python3 - "$BUILD_DIR/drivers/cpuidle/governors/haltpoll.c" <<'PY'
import sys
from pathlib import Path
p = Path(sys.argv[1])
t = p.read_text()
orig = t
if "dev->poll_limit_ns = 0;" in t:
    t = t.replace(
        "\tdev->poll_limit_ns = 0;",
        "\t/* k7d: seed the configured window; vanilla starts at 0. */\n"
        "\tdev->poll_limit_ns = guest_halt_poll_ns;",
        1,
    )
t = t.replace(
    "\t\t*stop_tick = false;\n\t\t/* Otherwise, poll again */",
    "\t\t/* Otherwise, poll again. k7d: leave stop_tick true — poll uses\n"
    "\t\t * local_clock, not the scheduler tick. */",
    1,
)
t = t.replace(
    "\t*stop_tick = false;\n\t/* Last state was halt: poll */",
    "\t/* Last state was halt: poll. k7d: leave stop_tick true. */",
    1,
)
if "dev->poll_limit_ns = guest_halt_poll_ns" not in t:
    sys.exit("haltpoll seed did not take")
select = t.split("haltpoll_select", 1)[1].split("haltpoll_reflect", 1)[0]
if select.count("*stop_tick = false;") != 1:
    sys.exit(f"haltpoll_select stop_tick=false count={select.count('*stop_tick = false;')} want 1 (latency_req==0 only)")
if t != orig:
    p.write_text(t)
    print("    patched", p)
else:
    print("    already applied")
PY

echo "==> Applying minimal config"
cp "$CONFIG_FILE" "${BUILD_DIR}/.config"
cd "$BUILD_DIR"
make olddefconfig

echo "==> Checking the config kconfig answered against the one we asked for"
assert_config_survived "${BUILD_DIR}/.config"

echo "==> Building vmlinux"
make -j"$(nproc)" vmlinux

cp vmlinux "$SCRIPT_DIR/vmlinux"
strip --strip-all "$SCRIPT_DIR/vmlinux" 2>/dev/null || true
echo "==> Guest kernel built: ${SCRIPT_DIR}/vmlinux ($(du -h "$SCRIPT_DIR/vmlinux" | cut -f1))"
