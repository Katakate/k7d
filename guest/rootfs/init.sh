#!/bin/sh
export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
mount -t proc proc /proc
mount -t sysfs sysfs /sys
mount -t tmpfs tmpfs /tmp
mount -t tmpfs tmpfs /run
mount -t devtmpfs devtmpfs /dev 2>/dev/null || true

# PTYs for interactive exec (kubectl exec -it). The agent
# allocates masters from /dev/ptmx, which resolves through this mount.
mkdir -p /dev/pts
mount -t devpts -o mode=620,ptmxmode=666 devpts /dev/pts 2>/dev/null || true

# Mount cgroup2 for runc container lifecycle (per-container
# memory/cpu limits need memory + cpu controllers delegated so
# guest runc can write memory.max / cpu.max).
mkdir -p /sys/fs/cgroup
mount -t cgroup2 none /sys/fs/cgroup 2>/dev/null || true

# No-internal-process constraint: a cgroup cannot both host processes
# and enable domain controllers in subtree_control. Move this shell
# (and the agent we exec next) into a leaf, then delegate ALL
# available controllers on the root (dind-style): namespaced
# nested daemons (k3s needs cpuset) can only enable controllers their
# ancestors delegated, so partial delegation here starves them.
if [ -f /sys/fs/cgroup/cgroup.controllers ]; then
    mkdir -p /sys/fs/cgroup/init
    echo $$ > /sys/fs/cgroup/init/cgroup.procs
    # Fail loud: without these, linux.resources limits are silently
    # unenforceable (no memory.max / cpu.max in child cgroups).
    sed -e 's/ / +/g' -e 's/^/+/' < /sys/fs/cgroup/cgroup.controllers \
        > /sys/fs/cgroup/cgroup.subtree_control \
        || { echo "k7-init: failed to enable cgroup controllers" >&2; exit 1; }
fi

# Nothing here sets the clock. The kernel has no RTC driver, but it does
# have kvmclock, which hands it the host's wall clock through the
# `MSR_KVM_WALL_CLOCK_NEW` page before userspace exists — earlier and
# more precisely than the `k7d.now=<unix-seconds>` cmdline seed this
# used to parse, and unlike that seed it also survives restore and fork,
# where the host re-bases the clock with `KVM_SET_CLOCK`.

# Configure COM2 for agent: disable echo, raw mode
stty -F /dev/ttyS1 raw -echo -echoe -echok 115200

exec /usr/local/bin/k7-agent
