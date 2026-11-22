# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.10.0] — 2026-11-22

k7d runs on OpenShift. The shim is a CRI-O `vm` runtime, a guest's
virtio devices can sit on a PCI bus, and a single-node OKD 4.22 boots
inside a k7d VM from its installed disk.

### Added

- CRI-O support: `packaging/install.sh --with-crio` registers `k7` and
  `k7-fc` as CRI-O `vm` runtimes (`/etc/crio/crio.conf.d/50-k7.conf`)
  and installs the shim a second time as `containerd-shim-k7-v2`, the
  name CRI-O 1.32–1.36 require. On OpenShift the shim drops SELinux
  labels (the guest has no LSM), refuses non-zero `hugepageLimits`, and
  joins a delegated `crio-<id>.scope` so `cpuset` stays enabled on the
  QoS slice. Proven on single-node OKD 4.22 (CRI-O 1.35.5) for both
  `k7` and `k7-fc`.
- `VmConfig.transport`: `mmio` (default) or `pci`, k7d's own legacy PCI
  bus with one virtio-pci function per device, for guest kernels built
  without `CONFIG_VIRTIO_MMIO` (RHCOS, CentOS Stream CoreOS). Native
  backend only; `k7d-fc` refuses it. k7d can boot a `coreos-installer`
  disk from the disk itself by reading its GRUB/BLS entries
  (`k7d::bls`), without firmware or a GRUB binary. On that path a
  single-node OKD 4.22 installs itself and reaches node `Ready`.
- `tree_resume` takes `clock`: `wall` (default) wakes the guest at real
  now, `frozen` leaves out the time the snapshot spent at rest. The
  response reports `at_rest_ms`, and a `wall` resume after more than
  about a day logs that cluster certificates may have expired.

### Changed

- The root README is a short, neutral project overview.
- The size claim is measured, not estimated: `make loc` counts code per
  design bucket from a manifest that fails on unlisted files, and
  `make loc-firecracker` applies the same rules to Firecracker. The
  README's "under 30k lines for the VMM and shim" becomes ~8k for the
  machine and ~13k with live fork and the clock owner.
- `vm.rs` and `network.rs` are split by concern (`vm/{mod,clock,fork_ops}.rs`,
  `network/{mod,virtio_net}.rs`). Pure moves; module paths are unchanged.

## [0.9.0] — 2026-10-07

Warm-forked pod sandboxes keep their network. Every host-bridge
network gets its own network namespace, so a fork and its live source
have egress at the same time.

### Fixed

- Warm forks of pod-backed sandboxes (k7d and k7d-fc) lost their
  network: the fork's NIC was missing (native) or sat outside the fork
  pod's netns (Firecracker), which could also bypass the pod's network
  policy. `fork_vm` takes the fork pod's netns from the shim and gives
  the fork its own bridge with a TAP at the source's `vm_index`, attached
  into the fork pod netns with NAT. A pod-backed fork with no netns
  fails loudly (CHALLENGES #283).
- A second `tree_suspend` on a parked node returns `BadState` instead of
  "node not found" (CHALLENGES #286).
- `set_dilation` matches the longest tree id, then the single guest of a
  one-VM tree (CHALLENGES #287).
- Per-VM CPU samples read the vCPU thread's own task stat instead of the
  whole process, which clamped every node to 100% (CHALLENGES #293).

### Changed

- One network namespace per host-bridge network. Each
  `k7-br-<id>` bridge moves into `/run/netns/k7-br-<id>` behind a `/30`
  uplink veth from `198.18.0.0/15`; guests keep `10.200.0.0/24`. Two
  networks with the same guest IP (a fork and its source) both have
  egress. Pod-backed sandboxes never build the netns. Startup and the
  orphan sweep reap stale `k7-br-*` netns (CHALLENGES #283, #284).

### Added

- `set_dilation_policy` and a per-VM CPU tick sample for the k7view
  observer (fork N children, dilation ladder presets, live CPU).

## [0.8.0] — 2026-09-28

Cluster keyframes pause for the residual, not the guest's RAM. A tree
can opt into a dilation policy and into KSM. The fake-GPU fixture
grows a count, per-GPU DCGM series, device IDs, and Kueue flavors.

### Added

- Coordinated cluster keyframe: `tree_adopt_cluster`,
  `tree_create_cluster`, and in-tree children cut every native member
  at one instant. Live pre-copy writes RAM while the guest runs, so
  the pause is the residual rather than guest RAM. An adopted root
  keyframe can be refreshed into a new generation. `TreeCreated`
  reports `pause_ns` and `max_pause_ns`.
- Opt-in per-tree dilation policy (`fixed` / `down` / `track`) with
  caller knobs for window, saturated, quiet, cadence, and ladder.
  The default stays `fixed` and starts no loop. Intel live
  `SetDilation` re-arms in-flight LAPIC timers (VMX preemption timer).
- Opt-in per-tree KSM (`ksm: true` on `tree_create_cluster` /
  `tree_adopt_cluster`, off by default, inherited by forks). Guest
  RAM is marked mergeable after the guest is running. Same-tenant
  hosts only; k7d does not start `ksmd`.
- Resume applies the checkpoint's own dirty delta.
- Fake GPU fixture: `FAKE_GPU_COUNT` (default 2), `Allocate` sets
  `NVIDIA_VISIBLE_DEVICES` to the kubelet-assigned `fake-gpu-N` IDs,
  one DCGM series per device, product and topology labels with Kueue
  flavors `fake-h100` / `fake-l40s`, and a RayJob on digest-pinned
  `rayproject/ray:2.47.1-py311`. Mock only.
- `tree_drop` tears a tree down. `list_vms` / `vm_status` stay the
  sandbox registry; adopted members are reached through
  `tree_nodes.live_guest_cids`.

### Fixed

- Close log-bridge FIFOs so a fork source can tear down.
- `stop_vm` on an id adopted into a tree errors and does not free
  tree disks. `tree_prune` of the root and `tree_drop` release the
  broker pins for those ids.

## [0.7.0] — 2026-09-19

Privilege separation: a node broker (root) and a VM broker (uid `k7d`).
Intel warm-fork carries CET/XSS. Firecracker jail integrity and disk
reclaim.

### Added

- Privilege separation: node broker (root) / VM broker (uid `k7d`);
  `net.*`, `virtiofsd.spawn`, pinned-descriptor, and `fc.*` verbs;
  `K7D_PRIVSEP` on by default.
- Exec helpers from a pre-seccomp spawner; smaller daemon seccomp filter.
- Measured capability bounding set and `ProtectSystem=strict`.
- Standalone Firecracker pods survive a VM-broker restart
  (`K7D_VM_BROKER_RESTART`).
- README k7d vs k7d-fc comparison table.

### Fixed

- Intel hosts: carry IA32_XSS / CET / SSP across warm fork; auto-warp
  on lapic-deadline guests.
- `k7d.service` 226/NAMESPACE on join nodes before kubelet exists.
- Firecracker jail integrity: CLOEXEC fds, `0700` staging, `O_PATH`
  hostPath, k7d-fc resume→exec.
- Reclaim the disk tier: sweep test trees, GC base images, fail loud
  on ENOSPC.

## [0.6.0] — 2026-09-12

A second VMM: stock Firecracker under the jailer (`k7-fc`), plus
dockerd as an agent-supervised guest service. Shim and guest
confinement tighten; forks refuse a missed virtio park.

### Added

- Firecracker engine: boot the k7d guest on stock Firecracker + jailer,
  CRI pods on RuntimeClass `k7-fc` (ConfigPath, PodOverhead), Diff
  snapshot → reflinked base → LoadSnapshot fork, cluster fork,
  suspend/resume, warm pool, and CRI exec / kube Ready.
- `dockerd` as an agent-supervised guest service (overlay2 on a
  per-sandbox virtio-blk disk; forkable). The release tarball ships
  the payload under `docker/` (`install.sh` → `/usr/local/share/k7d/docker`).

### Fixed

- Pass OCI confinement through to guest runc; do not follow symlinks
  under virtiofs hostPath shares; data-disk exclusivity, socket mode,
  and bounded agent lines.
- Validate virtqueue geometry at the guest→host boundary; refuse a
  fork when a virtio worker misses the 200ms park.
- `Kill(SIGTERM)` reports the real exit code.
- Pool `compatible()` sees dilation and `data_disks`; `create_vm`
  fails when a requested CNI attach cannot complete; Firecracker live
  lookups cover data disks, serial dump, and tree members;
  `evict_subtree` reaps parked disk clones.

## [0.5.0] — 2026-09-06

The public tree now ships the gym and the carried KVM dilation patch.
Ubuntu TreeFork hunts stay up across a daemon crash, a held apiserver
session, and a Redis write in flight. Scenario packs get a scripted
runtime.

### Added

- Public publish tree includes `gym/` and `utils/kvm-dilation/` (carried
  KVM continuous ×N dilation patch plus install/revert).
- `make helm-pin` installs the pinned helm v3.16.4 used by Ubuntu
  Cilium/Tetragon bring-up.
- Scenario pack format and a scripted gym runtime.
- Held Ubuntu apiserver watch and ClusterIP TCP across TreeFork.
- Rehydrate an Ubuntu tree after `k7d` is killed with SIGKILL.
- Redis mid-write Ubuntu TreeFork hunt.

## [0.4.0] — 2026-09-03

Guest time warp sits next to warm fork: a cluster can jump idle wall
clock, dilate KVM time, and still snapshot and fork. Mid-tree forks
take O(divergence) reflink keyframes. A host-enforced network jail
contains a rogue agent, and the gym can fork, prepare, and score a
live red-vs-blue lease.

### Added

- Guest time warp: lockstep forward jump (`WarpClock`), auto-warp of
  idle wall time, continuous KVM dilation (validated at N=8),
  bidirectional N, adaptive N on a paused cluster, snapshot/fork of a
  dilated VM, and fork at a different N than the source.
- Two-arm time-warp benchmark: 1.83× wall-clock at zero fidelity delta;
  dilation-N sweep as a fidelity-cost curve; ×8 dilated fork-tree clip.
- Reflink keyframes: O(divergence) fork points down the tree; inherit
  an ancestor keyframe so a mid-tree prepare is not required.
- Gym: `POST /env/{id}/fork`, `POST /env/{id}/prepare` (memory.bin, no
  new VM), AutoWarp jump | micro | dilate on `POST /lease`,
  `GYM_SCOREBOARD=grpo`, live red-vs-blue self-play, relay soak harvest.
- Dual-child Ubuntu cluster write isolation, and rollback after a dirty
  child.
- Rogue-agent network jail: egress policy, host lockdown, per-TAP
  anti-spoof, conntrack/rate caps, AppArmor deny `AF_VSOCK`.
- Fake GPU + DCGM fixture on Ubuntu k3s, then JobSet, TrainJob /
  Kubeflow Trainer, Kueue, KubeRay, and Soft-RoCE — each then forked.
- `k7d doctor` (CLI + `{"op":"doctor"}`): `/dev/kvm`,
  `/dev/vhost-vsock`, `/dev/net/tun`, cgroup v2.
- `k7d quickstart`: busybox 3-node tree, 4 forks, both fork clocks
  (~105 ms CI guest / ~1.1 s Ubuntu k3s+Cilium+Tetragon).
- k7view fork-tree videos with a real no-fork baseline; blog #7.

### Fixed

- Unprivileged Ubuntu pod exec under `k7-deny-vsock`.
- Host rpcbind/NFS listening on `0.0.0.0:111` (Portmapper reports).
- Gym returning 502 on a downed Tetragon API instead of scoring it.
- Live mid-tree `/fork` documented as 23 s; measured 0.51 s.

### Changed

- README: Mermaid diagrams, time-warp section, both fork clocks in the
  hero table; asciinema hero GIF dropped.
- TreeFork budgets asserted on daemon `latency_ns`.
- Public sanitizer widened; public markdown no longer carries spec ids
  or leftover HN wording.
- Fixture plots stamped synthetic, not trained.

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
