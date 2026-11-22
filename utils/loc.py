#!/usr/bin/env python3
"""Count k7d's Rust code by design bucket.

A line counts when it is non-blank, not a comment, and outside a
`#[cfg(test)] mod` / `#[cfg(kani)] mod` block. Brace matching for those
blocks is textual (it does not parse string literals), so treat the
numbers as +/- a few lines, not exact.

Every `.rs` under `crates/*/src` must be in exactly one bucket: a new
file that is not listed fails the run instead of being silently
dropped from a total.

    python3 utils/loc.py                 # table
    python3 utils/loc.py --max-core 7000 # also fail if "core" exceeds it
    python3 utils/loc.py --firecracker reference/firecracker
                                         # same rules on Firecracker

"core" is the machine Firecracker also has: vCPU / KVM / boot, virtio
MMIO and PCI transports + blk / net / vsock, memory layout, snapshot. "vmm" adds what only
k7d's VMM does: live CoW fork, the clock owner (warp, dilation) and
virtio-fs. Everything else is host plumbing, control plane or tooling.
"""

import argparse
import pathlib
import subprocess
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent

# (bucket, group, description, [paths relative to ROOT, dirs end with /])
BUCKETS = [
    ("core", "vmm", "Machine: vCPU, KVM, boot, virtio-mmio/pci blk/net/vsock, snapshot", [
        "crates/k7d/src/vm/mod.rs",
        "crates/k7d/src/pci.rs",
        "crates/k7d/src/bls.rs",
        "crates/k7d/src/virtio_mmio.rs",
        "crates/k7d/src/block.rs",
        "crates/k7d/src/vsock.rs",
        "crates/k7d/src/network/virtio_net.rs",
        "crates/k7d/src/mptable.rs",
        "crates/k7d/src/devices.rs",
        "crates/k7d/src/mem_layout.rs",
        "crates/k7d/src/snapshot.rs",
        "crates/k7d/src/fdutil.rs",
    ]),
    ("fork", "vmm", "Live CoW fork: fork source, keyframes, dirty bitmap", [
        "crates/k7d/src/fork.rs",
        "crates/k7d/src/vm/fork_ops.rs",
    ]),
    ("clock", "vmm", "Clock owner: timer survey, warp, dilation", [
        "crates/k7d/src/vm/clock.rs",
        "crates/k7d/src/autowarp.rs",
        "crates/k7d/src/dilation.rs",
        "crates/k7d/src/cpu_sample.rs",
    ]),
    ("virtiofs", "vmm", "virtio-fs device + virtiofsd lifecycle", [
        "crates/k7d/src/virtiofs.rs",
    ]),
    ("tree", "daemon", "Snapshot tree, cluster tree, budget model, warm pool", [
        "crates/k7d/src/tree.rs",
        "crates/k7d/src/cluster_tree.rs",
        "crates/k7d/src/tree_model.rs",
        "crates/k7d/src/pool.rs",
    ]),
    ("host-net", "daemon", "Host networking: TAP, bridges, netns, iptables", [
        "crates/k7d/src/network/mod.rs",
        "crates/k7d/src/netns.rs",
    ]),
    ("host-storage", "daemon", "Disks, volumes, erofs images", [
        "crates/k7d/src/disks.rs",
        "crates/k7d/src/volumes.rs",
        "crates/k7d/src/volumes_blk.rs",
        "crates/k7d/src/erofs.rs",
    ]),
    ("control", "daemon", "Control socket, API, config, daemon main", [
        "crates/k7d/src/control.rs",
        "crates/k7d/src/api.rs",
        "crates/k7d/src/config.rs",
        "crates/k7d/src/main.rs",
        "crates/k7d/src/lib.rs",
        "crates/k7d/src/latency.rs",
        "crates/k7d/src/guest.rs",
    ]),
    ("security", "daemon", "Privsep brokers, spawner, seccomp, netjail, cgroup, KSM", [
        "crates/k7d/src/broker/",
        "crates/k7d/src/seqmsg.rs",
        "crates/k7d/src/spawner.rs",
        "crates/k7d/src/seccomp.rs",
        "crates/k7d/src/netjail.rs",
        "crates/k7d/src/cgroup.rs",
        "crates/k7d/src/ksm.rs",
    ]),
    ("firecracker", "daemon", "Firecracker backend (stock FC + jailer)", [
        "crates/k7d/src/fc/",
    ]),
    ("ops", "daemon", "doctor, quickstart", [
        "crates/k7d/src/doctor.rs",
        "crates/k7d/src/quickstart.rs",
    ]),
    ("shim", "shim", "containerd-shim-k7-v1", ["crates/shim/src/"]),
    ("agent", "guest", "In-guest agent", ["crates/agent/src/"]),
    ("replicate", "tools", "replicate (stub)", ["crates/replicate/src/"]),
]


# Firecracker's counterpart of "core", under src/vmm/src: same machine
# surface (x86_64, virtio-MMIO and PCI transports, blk / net / vsock,
# legacy devices, vCPU / VM state, builder, snapshot). Generated bindings,
# test helpers, aarch64, the io_uring engine and the PCIe-only pieces
# (MSI-X, PCIe capability, root port) are excluded: k7d's PCI bus is
# legacy INTx, and the rest has no k7d equivalent.
FC_CORE = [
    "devices/virtio/block/", "devices/virtio/net/", "devices/virtio/vsock/",
    "devices/virtio/queue.rs", "devices/virtio/iovec.rs", "devices/virtio/iov_deque.rs",
    "devices/virtio/mod.rs", "devices/virtio/device.rs", "devices/virtio/persist.rs",
    "devices/virtio/transport/mmio.rs", "devices/virtio/transport/mod.rs",
    "devices/virtio/transport/pci/", "pci/", "devices/pci/", "device_manager/pci_mngr.rs",
    "devices/legacy/", "arch/x86_64/", "arch/mod.rs", "vstate/",
    "builder.rs", "persist.rs", "snapshot/", "lib.rs",
    "device_manager/mod.rs", "device_manager/mmio.rs",
    "device_manager/persist.rs", "device_manager/legacy.rs",
]
FC_EXCLUDE = ("generated", "test_utils", "/tests/", "/benches/", "aarch64", "io_uring",
              "msix.rs", "pcie_cap.rs", "root_port.rs")
# Userspace vsock: k7d uses the kernel's vhost-vsock instead, so this is
# reported separately rather than silently dropped.
FC_VSOCK = "devices/virtio/vsock/"


def firecracker(fc_root):
    vmm = fc_root / "src/vmm/src"
    if not vmm.is_dir():
        sys.exit(f"loc.py: {vmm} not found (run `make reference`)")
    files = sorted(p.relative_to(vmm).as_posix() for p in vmm.rglob("*.rs"))
    files = [f for f in files if not any(e in "/" + f for e in FC_EXCLUDE)]
    for p in FC_CORE:
        if not any(f == p or (p.endswith("/") and f.startswith(p)) for f in files):
            sys.exit(f"loc.py: Firecracker layout changed, {p} not under {vmm}")
    core = [f for f in files if any(f == p or (p.endswith("/") and f.startswith(p)) for p in FC_CORE)]
    total = sum(count(p) for p in (fc_root / "src").rglob("*.rs")
                if not any(e in p.as_posix() for e in ("/tests/", "/benches/")))
    n_core = sum(count(vmm / f) for f in core)
    n_vsock = sum(count(vmm / f) for f in core if f.startswith(FC_VSOCK))
    rev = subprocess.run(["git", "-C", str(fc_root), "log", "-1", "--format=%h %cs"],
                         capture_output=True, text=True, check=True).stdout.strip()
    print(f"Firecracker {rev}")
    print(f"   core: {n_core:>6}  (of which userspace vsock {n_vsock})")
    print(f"    all: {total:>6}  (every crate under src/, tests and benches excluded)")


def gated_mod(lines, i):
    s = lines[i].strip()
    if s not in ("#[cfg(test)]", "#[cfg(kani)]") or i + 1 >= len(lines):
        return False
    nxt = lines[i + 1].strip()
    return nxt.startswith(("mod ", "pub mod ")) and nxt.endswith("{")


def count(path):
    lines = path.read_text().split("\n")
    code = i = 0
    while i < len(lines):
        if gated_mod(lines, i):
            depth, i = 0, i + 1
            while i < len(lines):
                depth += lines[i].count("{") - lines[i].count("}")
                i += 1
                if depth <= 0:
                    break
            continue
        s = lines[i].strip()
        if s and not s.startswith(("//", "/*", "*")):
            code += 1
        i += 1
    return code


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--max-core", type=int, help="fail if the core bucket exceeds this")
    ap.add_argument("--firecracker", type=pathlib.Path, metavar="DIR",
                    help="count a Firecracker checkout's matching core instead")
    args = ap.parse_args()
    if args.firecracker:
        firecracker(args.firecracker.resolve())
        return

    files = sorted(p.relative_to(ROOT).as_posix() for p in ROOT.glob("crates/*/src/**/*.rs"))
    owner = {}
    for bucket, _, _, paths in BUCKETS:
        for f in files:
            if any(f == p or (p.endswith("/") and f.startswith(p)) for p in paths):
                if f in owner:
                    sys.exit(f"loc.py: {f} is in both {owner[f]} and {bucket}")
                owner[f] = bucket
        for p in paths:
            if not any(f == p or (p.endswith("/") and f.startswith(p)) for f in files):
                sys.exit(f"loc.py: bucket {bucket} lists {p}, which does not exist")
    missing = [f for f in files if f not in owner]
    if missing:
        sys.exit("loc.py: not in any bucket (add them to BUCKETS):\n  " + "\n  ".join(missing))

    totals = {}
    for f in files:
        totals[owner[f]] = totals.get(owner[f], 0) + count(ROOT / f)

    print(f"| {'bucket':<13} | {'group':<6} | {'lines':>6} | what |")
    print(f"|{'-' * 15}|{'-' * 8}|{'-' * 7}:|------|")
    groups = {}
    for bucket, group, desc, _ in BUCKETS:
        groups[group] = groups.get(group, 0) + totals[bucket]
        print(f"| {bucket:<13} | {group:<6} | {totals[bucket]:>6} | {desc} |")
    print()
    for group, n in groups.items():
        print(f"{group:>7}: {n:>6}")
    print(f"{'all':>7}: {sum(groups.values()):>6}")

    if args.max_core is not None and totals["core"] > args.max_core:
        sys.exit(f"loc.py: core is {totals['core']} lines, over --max-core {args.max_core}")


if __name__ == "__main__":
    main()
