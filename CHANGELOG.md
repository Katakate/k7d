# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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
