# cluster-tree-search — RL-shaped demo of k7d cluster fork

**What this is:** a scripted “tree search” over warm-forked multi-VM
clusters. Not SWE-bench. Not a training run. No GPU.

**What it shows:** fork N branches from a live checkpoint, score a
trivial reward, protect the winner, prune the losers — and print the
fork wall-clock. This is the packaging surface for the unique claim:
k7d forks a *whole Kubernetes cluster*, not a process sandbox.

## Modes

| Mode | Command | What it does | Wall-clock focus |
|---|---|---|---|
| `busybox` (default) | `python3 run_demo.py --mode busybox` | `TreeCreateCluster(3)` + `tree_fork_batch` | Fast. Measured **~262 ms** for a 4×3-VM CoW batch on the pinned node (2026-08-07). |
| `inner-k3s` | `python3 run_demo.py --mode inner-k3s` | Adopt the live 3-node inner-k3s pods (pause Deployment + API churn) + batch-fork; reward = `/readyz` + `inner-load` Ready | Headline path (~104 ms under churn, 1 s budget). |

## Prerequisites

On a Linux KVM host with k7d already installed (the pinned bare-metal node
is fine):

```bash
test -S /run/k7d/k7d.sock && systemctl is-active k7d
ls /dev/kvm /dev/vhost-vsock
# guest kernel + initramfs (busybox mode):
ls guest/kernel/vmlinux guest/rootfs/initramfs.cpio.gz
```

For `--mode inner-k3s`, bring up the dirtier fixture and **leave the
pods running** (`K7_KEEP_INNER3=1` skips the usual pod delete):

```bash
K7_KEEP_INNER3=1 cargo test -p k7d --test test_inner_k3s \
  test_inner_k3s_cluster_warm_fork_no_restart -- --test-threads=1 --nocapture
```

That joins 3 Ready nodes, deploys `Deployment/inner-load` (pause×3),
churns scale/ConfigMaps/pause pods, warm-forks once (asserts CoW +
`inner-load` Ready on both bridges), then leaves the outer pods up.

## Run

```bash
cd examples/cluster-tree-search
python3 run_demo.py --mode busybox --branches 4
# Headline path (pods must already be Running):
python3 run_demo.py --mode inner-k3s --branches 4
```

Flags:

- `--keep` — leave the tree around for `tree_nodes` inspection
- `--tree-id NAME` — stable tree id (default `cts-<pid>`)
- `K7D_SOCKET` — override control socket (default `/run/k7d/k7d.sock`)

## Layout

| File | Role |
|---|---|
| `k7d_client.py` | Thin JSON-lines client (`tree_fork_batch` / `tree_rollback` / `tree_protect` / …). Not a product SDK. |
| `run_demo.py` | The demo driver |
| `../docs/assets/cluster-fork-demo.gif` | Captured busybox demo for the root README |

## Numbers

Budgets and measured values live in [`LATENCY_BUDGETS.md`](../../LATENCY_BUDGETS.md)
and are enforced by integration tests — this demo *prints* the wall-clock;
it does not redefine the budget. See also the benchmark post:
[`docs/blog/2026-08-07-k7d-cluster-fork-benchmark.md`](../../docs/blog/2026-08-07-k7d-cluster-fork-benchmark.md).
