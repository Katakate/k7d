# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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
