# Guest userspace tools that are too big for the initramfs.
#
# `build.sh` assembles the initramfs (host busybox + the k7-agent this
# workspace built + init.sh) and deliberately keeps it under 2 MB: every
# byte is decompressed on the boot path of every VM, and the
# VM_BOOT_TO_AGENT budget is 250 ms against a ~205 ms baseline. So this
# image is not part of the initramfs — it is handed to a guest over
# virtiofs by whoever needs it, the same arrangement runc has.
#
# This file once described the whole rootfs and
# nothing built it: an out-of-date copy of a build nobody ran.
#
# iproute2-minimal ships `ip`, iproute2-tc ships `tc` — alpine splits
# them, and iproute2-minimal alone gets you no `tc` at all. Busybox has
# neither: no `tc` binary, and its `ip link add` knows only a handful of
# link types, not vxlan. Cilium's datapath needs both a clsact qdisc and
# (in tunnel mode) a vxlan device, which is what
# crates/k7d/tests/test_kernel_features.rs probes for inside a booted
# guest.
FROM alpine:3.20
RUN apk add --no-cache iproute2-minimal iproute2-tc
