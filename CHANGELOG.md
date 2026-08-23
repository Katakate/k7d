# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.3.0] — 2026-08-23

Ubuntu 24.04 is now a first-class guest: a three-node k3s cluster boots
on bare VMs, takes Cilium, Tetragon, and Longhorn, and still warm-forks.
A gym leases those nodes, a tree jailer contains them, and an MCP demo
plus live viewer show a cluster-fork incident end to end.

### Added

- Ubuntu 24.04 guests on `create_vm`, then k3s on those nodes and a warm
  fork of the running cluster.
- Cilium 1.16.10 and Tetragon 1.7.0 on the Ubuntu cluster, with
  fork-and-diff of Tetragon events.
- Longhorn on Ubuntu nodes, plus persistent data disks that survive a
  warm fork as reflink-CoW copies.
- Single-node gym: lease, act, score, TTL reap; a v0 fault catalog
  (inject / contain / restore); a gym router with sticky groups and
  drain; Tetragon scoreboard and reset arm.
- k7d MCP server and an incident demo (fork, inspect, remediate), with
  k7view as a live observer for cluster-fork trees.
- Tree jailer: virtiofsd sandbox, nft net jail, per-tree cgroup, and
  daemon seccomp (enforce by default).
- Checkpoint policy: restore-chain cap, incoming eviction, disk guard.
- Fork-under-load correctness checks and dirty-page divergence plots.

### Fixed

- Guest NAT egress collapsing to ~50 KB/s.
- vhost-vsock ring pages were missing from the warm-fork dirty set, so
  a child could boot from a stale `used.idx`.

### Changed

- Ubuntu bare-VM is the exclusive gym / GRPO substrate. The tiny
  busybox guest and nested-runc inner-k3s stay in CI.

## [0.2.2] — 2026-08-19

Inner-cluster fidelity and guest-kernel work. Add-ons survive a warm fork,
Cilium can replace kube-proxy inside the guest cluster, and the guest grows
iSCSI/NFS plus eBPF plumbing.

### Added

- CoreDNS, ServiceLB + Traefik, local-path PVCs, metrics-server, and
  NetworkPolicy proven across a warm fork on inner-k3s.
- HPA scale-up with post-fork divergence, an etcd datastore profile, and
  ArgoCD GitOps on a forked cluster, plus an add-on support matrix.
- Guest kernel: Cilium eBPF datapath and Longhorn v1 iSCSI/NFS, with BTF.
- iSCSI + NFSv4 guest userspace, checked against a real target.
- Cilium as the inner CNI (kube-proxy replaced), riding a warm fork.
- Guest-kernel hooks for kprobes, ftrace, and BPF LSM.

### Fixed

- A ~1% unreachable warm fork (`vcpu_events` + net TX kick) and an fd leak.
- Shared-cluster integration tests no longer collide; stranded host
  resources are swept.
- The test suite runs one VM-booting binary at a time so a failure names
  the binary.

### Changed

- The VMM+shim size claim is now ≤30k LOC (was ≤25k).

## [0.2.1] — 2026-08-16

Patch release. `k7d --version` on a machine with a running daemon no longer
takes down that daemon's control socket.

### Fixed

- **`k7d --version` used to start a second daemon that stole the live
  control socket and deleted it on exit.** `main()` parsed only `--socket`
  and fell through to the serve path for everything else, and `serve()`
  opened by unconditionally unlinking whatever sat at the socket path — so
  an informational flag displaced the running daemon's socket and left a
  unit that reported `active` with no socket for any shim to reach.
  `--version`/`-V`/`--help`/`-h` now answer and exit before anything else,
  and `serve()` probes the path with a connect first: a live listener is
  `AddrInUse` and a refusal to start, not a silent displacement.
- The test suite runs one integration-test binary at a time (enumerated
  from `cargo metadata`), so a failure names the binary and VM-booting
  tests no longer compete across binaries.

## [0.2.0] — 2026-08-16

Second release. Bigger guests boot, container writes land on a real disk
instead of guest RAM, a restored guest knows what time it is, and an idle
vCPU costs ~1% of a core rather than 100%.

### Added

- **Writable storage on a host disk (`k7d.katakate.org/scratch-size`).** A
  container's overlay upper now lives on a sparse ext4 image attached as a
  read-write virtio-blk device (default 8 GiB) instead of a RAM-backed
  layer. Writable capacity is no longer tied to the pod's memory limit, and
  filling it gives the writer `ENOSPC` instead of guest-wide memory
  pressure. A warm fork gets a reflink-CoW copy, isolated from parent and
  siblings; the image is unlinked with the VM.
- **Per-container ephemeral-storage limits
  (`k7d.katakate.org/container-scratch-size`).** A `name=size` list over
  Kubernetes container names, e.g. `builder=2Gi,logger=64Mi`, gives each
  named container its own image so an overrun stays that container's
  problem. Opt-in: each image spends one of the VM's virtio-MMIO device
  slots, and a pod using it is served by fork rather than the warm pool.
- Guest ephemeral-storage usage accounting over the agent protocol.
- `packaging/install.sh` for installing the daemon, shim, and guest
  artifacts from a release tarball.

### Fixed

- **Guests of 4 GiB and larger now boot.** Guest RAM is split across the
  32-bit MMIO hole instead of overlapping the device window.
- **A restored guest knows the wall clock.** The guest is given kvmclock and
  the host a way to re-base it, so a VM resumed from a snapshot hours later
  no longer reports a date from 1999 — which broke TLS certificate
  validation for anything the guest fetched.
- **An idle vCPU no longer costs a full host core.** The guest uses the
  haltpoll cpuidle governor with a 200 µs window, bringing an idle vCPU to
  roughly 1% of a core.
- The daemon alone chooses which guest kernel and initramfs a VM boots, and
  refuses to create a VM without them rather than guessing.
- OCI cgroup mounts are translated to guest cgroup2 with Kata-like
  namespace nesting, and guest IPv6 is enabled.
- Pause/resume, fork-source adoption, teardown, and stats fixes found while
  integrating the k7 backend.

## [0.1.0] — 2026-08-11

First public release.

### Added

- k7d daemon: KVM microVM runtime with CoW warm fork (~5 ms single-VM)
- Live multi-VM Kubernetes cluster fork (~105 ms for the 3-node CI fixture)
- Snapshot trees: `tree_create` / `tree_fork_batch` / `tree_protect` /
  `tree_prune` / `tree_rollback` / `tree_auto_evict` over `/run/k7d/k7d.sock`
- `containerd-shim-k7-v1` and `runtimeClassName: k7` (logs, exec/PTY,
  volumes, multi-container, init containers, multi-vCPU)
- Guest agent, kernel, and initramfs build pipeline
- Release tarball + `packaging/install.sh` (`make release`, optional `--with-k3s`)
- Kani proofs on selected unsafe / arithmetic paths; Aeneas→Lean proofs
  for the tree budget / eviction model
- `examples/cluster-tree-search` GRPO-shaped demo client

### Known limitations

- Config file (`/etc/k7d/config.toml`) not yet shipped
- Cross-node fork not supported (host-local trees)
- Sibling-fork isolation is weaker than one-jailed-process-per-VM models —
  see `SECURITY.md`
- No formal security audit yet
