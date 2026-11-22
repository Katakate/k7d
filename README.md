# k7d

Fork a live Kubernetes cluster. A copy-on-write fork of a running 3-node k3s cluster takes about 105 ms on the minimal CI guest and about 1.1 s on Ubuntu k3s with Cilium and Tetragon. Nothing inside reboots. Fifty forks share one machine's RAM until they diverge.

[![docs](https://img.shields.io/badge/docs-docs.katakate.org-blue)](https://docs.katakate.org/k7d)
[![release](https://img.shields.io/github/v/release/Katakate/k7d)](https://github.com/Katakate/k7d/releases)
[![license](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](LICENSE)
[![verification](https://img.shields.io/badge/verified-Kani%20%2F%20Aeneas-informational.svg)](#verification)

k7d is a small Rust VMM (about 8k lines for the machine, 13k with live fork and the clock owner; see [Size](#size)) with one primitive: pause a set of KVM guests, map their memory copy-on-write, give the copy its own L2 bridge with the same addresses, and resume both. Applied to a whole cluster, that primitive gives you many byte-identical copies of a running Kubernetes system, each on its own bridge, each paying only for the pages it changes.

Every latency figure in this repository is an integration-test assertion, not a benchmark paste. See [LATENCY_BUDGETS.md](LATENCY_BUDGETS.md) and the [benchmark write-up](docs/blog/2026-08-07-k7d-cluster-fork-benchmark.md).

## What it is for

Any workflow that needs many copies of a running system that start from exactly the same state.

- **RL environments and agent evaluation.** GRPO and other group-relative methods compare rewards within a group; forks give every member the same etcd revision, the same caches, the same half-finished reconcile loop. The daemon manages forks as a tree under a RAM and disk budget: `fork_batch`, `rollback`, `protect`, `prune`, `auto_evict`. A minimal trainer-side client is in [`examples/cluster-tree-search/`](examples/cluster-tree-search/); the gym and MCP server are in [`gym/`](gym/) and [`examples/k7d-mcp/`](examples/k7d-mcp/).
- **Runtime security testing.** Run the same attack in N copies and compare what Tetragon or a network policy reports in each. The Ubuntu guest ships Cilium and Tetragon; `test_ubuntu_tetragon_fork_event_diff` is the proving test.
- **Platform and scheduler testing.** Fork a cluster with mock GPUs (device plugin, per-pod DCGM, flavors and topology), Kueue, JobSet, KubeRay, RayJob or Kubeflow Trainer installed, and replay job storms against the copy. See the `test_ubuntu_ml_*` suites under [`crates/k7d/tests/`](crates/k7d/tests/).
- **Agent sandboxes.** The same engine warm-forks a single VM in about 5 ms, and pods can run as k7d VMs through `runtimeClassName: k7` or `k7-fc`. For Kubernetes-orchestrated sandboxes with a Python SDK, see [Katakate k7](https://github.com/Katakate/k7).

k7d also owns the guest clock. Episodes that are mostly waiting (probe periods, backoffs, reconcile ticks) can be compressed: lockstep clock jumps with no fidelity cost (1.83x on a 3-node k3s episode), or continuous dilation at up to 8x wall time with a carried KVM patch. Compute is never compressed, only waiting. Details on the [docs site](https://docs.katakate.org/k7d).

## Quickstart

Requirements: Linux x86_64 with KVM (`/dev/kvm`), `/dev/vhost-vsock`, `/dev/net/tun`, cgroup v2. No arm64 build yet.

```bash
git clone https://github.com/Katakate/k7d && cd k7d
sudo ./scripts/quickstart.sh
```

This checks the host, fetches the release tarball and guest images, starts the daemon, boots a 3-node busybox cluster, forks it four times, and prints the measured clocks.

```bash
k7d doctor       # host checks, no daemon
k7d quickstart   # 3-node cluster + 4 forks against a running daemon
```

To build from source: Rust and Docker, then `make release`. To run Kubernetes pods as k7d VMs, see [HACKING.md](HACKING.md).

## How it works

A fork is a short critical section on the source: pause every vCPU, drain in-flight virtio I/O, read the dirty bitmap (KVM dirty log plus device-written pages), map the child's RAM as a copy-on-write view of the parent and copy only the dirty pages, create a new bridge replaying the source's IPs and MACs, restore vCPUs and timers with `KVM_SET_CLOCK`, resume. From inside the guest nothing moved: same addresses, same TLS, same TCP.

The non-obvious parts, and the roughly 200 bugs that had to be fixed to make "byte-identical" true, are in [CHALLENGES.md](CHALLENGES.md). Architecture and concepts are on the [docs site](https://docs.katakate.org/k7d).

## Measured

One bare-metal box: Ryzen 5 3600, 6 cores, 64 GiB, NVMe.

| Guest | Fork | Source bring-up |
|---|---|---|
| Minimal CI guest (busybox / inner k3s) | ~105 ms | warm |
| Ubuntu k3s + Cilium + Tetragon | ~1.1 s | 48 s |
| Warm single-VM fork | ~5 ms | |
| 50 x 3-VM cluster forks, shared pause | ~4.1 s | warm |

## Supported

Inside a forked cluster: k3s control plane with N nodes, Flannel or Cilium, CoreDNS, Ingress, PVCs, NetworkPolicy, HPA, embedded etcd, ArgoCD, Longhorn, Tetragon, and an ML platform fixture with mock GPUs, Kueue, JobSet, KubeRay, RayJob, Kubeflow Trainer and soft-RoCE. Each row has a proving integration test in [`crates/k7d/tests/`](crates/k7d/tests/).

Two VMM backends: native (in-process, ~5 ms single-VM fork, time warp, virtiofs) and Firecracker (stock jailer, for multi-tenant or hostile guests). One daemon, chosen per VM. See [Backends](https://docs.katakate.org/k7d/concepts/backends).

Not supported today: nested `hostNetwork` pods, cross-node fork, non-x86_64 hosts.

## Verification

Selected critical paths are machine-checked: Kani bounded proofs over `unsafe` and address-arithmetic harnesses, and an Aeneas-to-Lean proof of the snapshot-tree budget and eviction model. This is not a claim that the runtime is proven.

```bash
make kani
make verif-gen verif-build
```

## Size

Counted by `make loc`: non-blank, non-comment lines outside test and Kani modules, grouped by an explicit file manifest that fails on any file it does not list.

| | Lines |
|---|---:|
| Machine: vCPU, KVM, boot, virtio-MMIO and PCI transports, blk / net / vsock, memory layout, snapshot | ~7.8k |
| Live copy-on-write fork | ~2.5k |
| Clock owner (warp, dilation) and virtio-fs | ~2.6k |
| **VMM** | **~12.9k** |
| Daemon: snapshot tree, control plane, privilege separation, Firecracker backend, host networking and storage | ~26k |
| Shim and guest agent | ~6.4k |

For scale, `make loc-firecracker` applies the same rules to Firecracker's matching machine (x86_64, virtio-MMIO and PCI transports, blk / net / vsock, legacy devices, vCPU and VM state, builder, snapshot): about 30k lines, roughly 3.8 times k7d's machine, out of about 71k in the whole tree (`cc88013`, November 2026). Part of the difference is scope rather than economy. k7d uses the kernel's vhost-vsock where Firecracker has a 2.3k-line userspace device (without it the ratio is about 3.5); k7d's PCI bus is legacy INTx with no MSI-X or PCIe (those Firecracker files are left out of the count); and k7d has no ACPI, balloon, rate limiter, device metrics or aarch64. Firecracker is independently audited; k7d is not.

## Security

Native and Firecracker backends have different isolation stories; native is for fleets you control, Firecracker for guests that may try to escape. Single host, x86_64 Linux with KVM, no external security audit yet. See [SECURITY.md](SECURITY.md).

## Learn more

- Documentation: [docs.katakate.org/k7d](https://docs.katakate.org/k7d)
- Demos and recordings: [docs/demo/](docs/demo/README.md)
- Design notes on building k7d: [beci.me/blog](https://beci.me/blog)
- Contributing: [CONTRIBUTING.md](CONTRIBUTING.md)

## License

Apache-2.0. See [LICENSE](LICENSE).
