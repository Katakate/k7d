# k7d cluster-fork benchmarks (2026-08-07)

Reproducible numbers for the claim: **warm-fork a live multi-VM
Kubernetes cluster in well under a second**, with TLS sessions surviving
and the source cluster still answering.

This post follows the same methodology shape as CubeSandbox’s BMI5
benchmark write-up (named hardware, exact commands, P50/typical +
enforced budget). Source of truth for budgets is
[`LATENCY_BUDGETS.md`](../../LATENCY_BUDGETS.md) /
[`crates/k7d/src/latency.rs`](../../crates/k7d/src/latency.rs) - every
row below is enforced by an integration test. If a number here drifts
from those files, **trust the tests**.

## Hardware

Pinned bare-metal provider bare-metal node used for all figures below
(prefer sync/rebuild over wipe when ready - see `editor-config/rules/contributor hygiene.mdc`):

| | |
|---|---|
| CPU | AMD Ryzen 5 3600 (6c/12t, up to ~4.2 GHz) |
| RAM | 64 GiB |
| Storage | 2× Samsung 512 GB NVMe |
| OS | Ubuntu 26.04 LTS, Linux KVM |
| Devices | `/dev/kvm`, `/dev/vhost-vsock`, `/dev/net/tun`, virtiofsd |
| Runtime | k3s + RuntimeClass `k7` + `k7d.service` |

> Note: `LATENCY_BUDGETS.md` still mentions an older Intel i7-6700
> description from an earlier node generation. The measured inner-k3s
> number below was taken on the Ryzen 5 3600 host on 2026-08-07.

## Reproduce

On the node (or via `make remote-*` from a laptop with `K7_SSH_KEY` set):

```bash
# Full enforced suite (fmt + deny + clippy + all tests, --test-threads=1):
make remote-check

# Headline path only:
ssh root@$K7_NODE_IP 'cd /root/k7d && source ~/.cargo/env && \
  cargo test -p k7d --test test_inner_k3s \
    test_inner_k3s_cluster_warm_fork_no_restart \
    -- --test-threads=1 --nocapture'

# Packaging demo (busybox, fast):
ssh root@$K7_NODE_IP 'cd /root/k7d/examples/cluster-tree-search && \
  python3 run_demo.py --mode busybox --branches 4'

# Scale check - shared-pause batch of 50× 3-VM clusters:
ssh root@$K7_NODE_IP 'cd /root/k7d && source ~/.cargo/env && \
  cargo test -p k7d --test test_cluster_tree \
    test_cluster_tree_fork_batch_50 -- --test-threads=1 --nocapture'
# or: python3 examples/cluster-tree-search/run_demo.py --mode busybox --branches 50
```

The inner-k3s test prints a line like:

```
TreeFork node=warm-0000 cids=[…] elapsed=105.062575ms budget=1s
daemon: fork_cluster_warm '…': 3 VMs in 69.703248ms
```

## Results (enforced + measured)

| Operation | Enforced budget | Typical / measured | Test |
|---|---|---|---|
| Warm single-VM fork (`<25%` dirty) | 50 ms | ~5 ms | `test_fork_warm_under_50ms` |
| 10× warm fork batch | 200 ms | ~15 ms | `test_fork_warm_batch_10` |
| On-host 3-VM cluster warm fork (busybox) | 150 ms | ~25-40 ms quiet / ~70-100 ms loaded | `test_cluster_fork_warm_3vm_under_50ms` |
| Cluster-tree fork (busybox, 3 VMs) | 750 ms | ~75 ms quiet | `test_cluster_tree_fork_under_75ms` |
| Cluster warm fork batch (8× 3 VMs) | 2 s | shared pause; beats 8× single ceiling | `test_cluster_fork_warm_batch_8` |
| Cluster-tree fork batch (50× 3 VMs) | 20 s | **~4.1 s** (~82 ms/cluster) shared pause + parallel materialise | `test_cluster_tree_fork_batch_50` |
| **Inner-k3s cluster-tree fork (3 VMs)** | **1 s** | **~104 ms** under churn (pause Deployment + API storm); CoW (~70 ms on-host `fork_cluster_warm`) | `test_inner_k3s_cluster_warm_fork_no_restart` |

### What changed on 2026-08-07

Before: cluster pods carried a virtiofs share for the k3s airgap
hostPath → every fork was a full memfd copy of 3 × ~3.2 GiB → ~2 s
typical / 15 s budget.

After: RO hostPath mounts pack into cached erofs images on virtio-blk
(zero virtiofs shares) → every member forks `MAP_PRIVATE(base.mem)` +
dirty-page CoW → **~105 ms** / **1 s** budget. Share-less
`prepare_fork_source` also preserves the vsock CID so kubectl exec
against the source still works after adopt/fork.

## Comparison (honest)

| Operation | kind | vcluster | CubeSandbox-style sandbox clone | **k7d** |
|---|---|---|---|---|
| Fresh isolated Kubernetes | ~30-60 s cold | ~20 s | n/a (not a cluster) | **warm fork of a live 3-node cluster (~105 ms typical)** |
| Unit of fork | n/a | n/a | one microVM / process sandbox | **the whole cluster** (control plane + workers) |
| Surviving TLS across fork | n/a | n/a | no (new sandbox) | **yes** (held `?watch=true` stream survives - Inc 4/5 proof) |
| Source still answers after fork | n/a | n/a | n/a | **yes** (CID-stable prepare) |

k7d is complementary to E2B / CubeSandbox: they fork a **sandbox**;
k7d forks the **cluster**. This repo is **not** E2B API compatible on
purpose - different unit of isolation.

### What we are *not* claiming

- Firecracker-beating cold boot (we boot once, then fork).
- “&lt;5 MB per instance” density (our guests run kubelet; CubeSandbox’s
  own amortized density table is already ~21-26 MB).
- That the virtiofs era (~2 s full-copy) was the intended steady state - 
  that was the pre-14a slow path, now the explicit fallback for RW
  hostPath only.

## Demo

```bash
cd examples/cluster-tree-search
python3 run_demo.py --mode busybox --branches 4
```

See [`examples/cluster-tree-search/README.md`](../../examples/cluster-tree-search/README.md)
and the root README GIF.
