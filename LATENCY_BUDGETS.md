# Latency Budgets

Every operation below is enforced by an integration test in
[`crates/k7d/tests/test_latency.rs`](crates/k7d/tests/test_latency.rs).
The budget constants live in
[`crates/k7d/src/latency.rs`](crates/k7d/src/latency.rs) - 
that file is the single source of truth imported by the tests.

Budgets are set at roughly 2× the typical observed value on the bare-metal
bare-metal node (currently AMD Ryzen 5 3600, 64 GB, NVMe - see
`docs/blog/2026-08-07-k7d-cluster-fork-benchmark.md`).

Cluster-tree `TreeFork` rows are enforced on the daemon's `latency_ns`
(CHALLENGES #156), not the client `Instant` around the
Unix-socket call. Tests print the client RTT; if it exceeds the budget
while the daemon stays under, that is a FINDING, not a failure. Do not
widen `FORK_INNER_K3S_CLUSTER_3VM` to absorb suite-tail queueing.

| Operation | Budget | Typical | Test |
|---|---|---|---|
| VM build (KVM + memfd + virtiofsd) | 150 ms | ~62 ms | `test_latency_vm_build` |
| VM boot → agent ready | 250 ms | ~194-205 ms (was ~225-235 ms; the kvmclock kernel rebuild took ~18 ms off it) | `test_latency_vm_boot_to_agent` |
| Agent ping RTT | 1 ms | ~0.2 ms | `test_latency_agent_ping` |
| Agent exec RTT | 2 ms | ~0.5 ms | `test_latency_agent_exec` |
| 5× sequential exec | 5 ms | ~2 ms | `test_latency_exec_sequential_5x` |
| Virtiofs read | 2 ms | ~1 ms | `test_latency_virtiofs_read` |
| Virtiofs write | 2 ms | ~1.14 ms mean / 1.26 ms max with guest haltpoll 200 µs window (`cpuidle_haltpoll.force=1`, 50 ms settle + 2 warmups); was ~1.16 ms / 1.23 ms at a 2 ms window, ~1.2 ms under `idle=poll`, ~1.7 ms (2 of 10 over budget) with plain HLT | `test_latency_virtiofs_write` |
| Snapshot 256 MB VM | 500 ms | ~228 ms | `test_latency_snapshot_256mb` |
| CoW restore from snapshot | 10 ms | ~3 ms | `test_latency_restore_cow` |
| Agent reconnect after restore | 5000 ms | ~500 ms | `test_latency_restore_agent_reconnect` |
| Fork (cold source) | 600 ms | ~250 ms | `test_latency_fork_cold` |
| Warm fork (part 1) - `<25%` dirty | 50 ms | ~5 ms | `test_fork_warm_under_50ms` |
| Warm fork of a 2-vCPU source | 75 ms | TBD (start generous, tighten after measuring) | `test_fork_warm_multi_vcpu` |
| CoW restore of a 2-vCPU snapshot | 35 ms | TBD | `test_multi_vcpu_snapshot_restore_roundtrip` |
| 10× warm fork batch | 200 ms | ~15 ms | `test_fork_warm_batch_10` |
| Cluster warm fork - 3 VMs | 150 ms | ~25-40 ms quiet / ~70-100 ms loaded bare-metal | `test_cluster_fork_warm_3vm_under_50ms` |
| Cluster-tree fork - 3 VMs | 750 ms | ~75 ms quiet host; 188 ms with the tree jail on vs 176 ms with it off, k7-node-02, 2026-08-21 | `test_cluster_tree_fork_under_75ms` |
| Cluster warm fork batch - 8× 3 VMs | 2 s | shared pause; must beat 8×150 ms | `test_cluster_fork_warm_batch_8` |
| Cluster-tree fork batch - 50× 3 VMs | 20 s | ~3.85 s (~77 ms/cluster) shared pause + parallel materialise; must beat 50×750 ms. Re-baselined after reflink keyframes + the net jail (k7-node-02, 2026-08-24): 2.44 s / 48.8 ms per cluster on main with `K7D_NET_JAIL=off`, 3.74 s / 74.9 ms on main with the tree jail on, 3.85 s / 77.0 ms with the full net jail (egress+input chains + per-TAP anti-spoof) - the full jail costs ~2 ms/cluster because the fork path pins all member TAPs in ONE `nft` transaction (`add_taps_at`); one `nft` process per TAP instead measured 12.7 s / 254 ms per cluster. (pre-reflink-keyframe figures: 4.10 s jail-on / 2.63 s off, 2026-08-21 — no longer the baseline) | `test_cluster_tree_fork_batch_50` |
| Inner-k3s cluster-tree fork - 3 VMs + load churn | 1 s | ~104 ms with dirtier fixture (pause Deployment scale + ConfigMap/pause-pod storm, 2026-08-08); CoW path (~70 ms on-host `fork_cluster_warm`) | `test_inner_k3s_cluster_warm_fork_no_restart` |
| Inner-k3s cluster-tree fork - 3 VMs + CoreDNS + load churn | 1 s | ~175 ms (2026-08-17, quiet/targeted host; CoreDNS Ready + 3 DNS-probe pods + load churn); on-host `fork_cluster_warm` ~68 ms; 494 ms re-measured with the tree jail on (k7-node-02, 2026-08-22), of which ~18 ms is the jail: 12 ms `nft -f` + 5.6 ms cgroup enrolment, the rest being `save_metadata` (131 ms), dirty-tracking re-enable (100 ms) and post-fork eviction; reuse `FORK_INNER_K3S_CLUSTER_3VM` | `test_inner_k3s_coredns_dns_fork` |
| Inner-k3s cluster-tree fork - 3 VMs + ServiceLB + Traefik + load churn | 1 s | ~206 ms (2026-08-17, targeted host; Traefik Ready + HTTP Ingress + load churn); on-host `fork_cluster_warm` ~96 ms; reuse `FORK_INNER_K3S_CLUSTER_3VM` | `test_inner_k3s_ingress_fork` |
| Inner-k3s cluster-tree fork - 3 VMs + local-path PVC + load churn | 1 s | ~200 ms (2026-08-17, targeted host; local-path-provisioner Ready + PVC writer + load churn); on-host `fork_cluster_warm` ~79 ms; reuse `FORK_INNER_K3S_CLUSTER_3VM` | `test_inner_k3s_local_path_pvc_fork` |
| Inner-k3s cluster-tree fork - 3 VMs + metrics-server + load churn | 1 s | ~196 ms (2026-08-17, targeted host; metrics-server Ready + `metrics.k8s.io` Available + load churn); on-host `fork_cluster_warm` ~79 ms; reuse `FORK_INNER_K3S_CLUSTER_3VM` | `test_inner_k3s_metrics_server_fork` |
| Inner-k3s cluster-tree fork - 3 VMs + NetworkPolicy + load churn | 1 s | ~195 ms (2026-08-17, targeted host; netpol controller live, default-deny + allow policies enforced + load churn); on-host `fork_cluster_warm` not recorded for this profile — follow-up; reuse `FORK_INNER_K3S_CLUSTER_3VM` | `test_inner_k3s_network_policy_fork` |
| Inner-k3s cluster-tree fork - 3 VMs + metrics + HPA + CPU-burn load | 1 s | ~200 ms (2026-08-17, targeted host; HPA scaled 1→3 from CPU metrics + load churn); on-host `fork_cluster_warm` ~85 ms; reuse `FORK_INNER_K3S_CLUSTER_3VM` | `test_inner_k3s_hpa_scale_fork` |
| Inner-k3s cluster-tree fork - 3 VMs + etcd datastore + load churn | 1 s | ~200 ms (2026-08-17, targeted host; embedded etcd + load churn); on-host `fork_cluster_warm` ~90 ms; reuse `FORK_INNER_K3S_CLUSTER_3VM` | `test_inner_k3s_etcd_datastore_fork` |
| Inner-k3s cluster-tree fork - 3 VMs + ArgoCD core + git server | 2 s | ~203-213 ms (2026-08-18, targeted host; ArgoCD core + git + Synced Application); on-host `fork_cluster_warm` ~87-96 ms; new `FORK_INNER_K3S_CLUSTER_3VM_ARGOCD` - do not widen the shared 1 s `FORK_INNER_K3S_CLUSTER_3VM` | `test_inner_k3s_argocd_gitops_fork` |
| Cluster-tree suspend - 3 VMs | 750 ms | ~25 ms quiet host | (asserted via `SUSPEND_CLUSTER_TREE_3VM`) |
| Cluster-tree resume - 3 VMs | 750 ms | ~40 ms quiet host | (asserted via `RESUME_CLUSTER_TREE_3VM`) |
| Lockstep guest-clock warp - 3 VMs | 250 ms | ~0.4 ms for the ioctls alone (2-VM busybox cluster, daemon `latency_ns`); 3-node Ubuntu figure recorded by the test | `test_warp_clock_moves_a_live_cluster_in_lockstep` |
| Fork agent reconnect | 5000 ms | ~500 ms | `test_latency_fork_agent_reconnect` |
| VM shutdown | 5 ms | ~0.05 ms | `test_latency_vm_shutdown` |
| Pool acquire - pooled `create_vm` round trip | 100 ms | ~50 ms (dominated by the control listener's 50 ms accept poll, not the pool) | `test_pool_fills_and_acquire_is_fast` |
| Pod network ready | 50 ms | ~5-10 ms over `VM_BOOT_TO_AGENT` | (asserted via `POD_NETWORK_READY`) |
| Pod volumes setup - per-pod kubelet-volume bind tree | 250 ms | ~25-40 ms on bare-metal (3-6 volumes) | `test_latency_pod_volumes_setup` |
| Virtiofsd socket appear - ceiling, multi-share spawn | 15 s | sub-second | (asserted via `VIRTIOFSD_SOCKET_APPEAR`) |

## Inner-k3s add-on fork cost

TreeFork elapsed on the 3-VM inner-k3s fixture. Every typical is the
value the merged increment wrote into the table above - this unit
does not re-measure. Deltas subtract the lean baseline (~104 ms,
2026-08-08). inc2-inc5 profiles also enable CoreDNS, so those deltas
include CoreDNS's share; isolated add-on cost (profile minus the
CoreDNS-only row) was not a required recording.

| Profile | Typical fork | Delta vs baseline (~104 ms) |
|---|---|---|
| baseline (add-ons off, load churn) | ~104 ms | - |
| + CoreDNS | ~175 ms | +71 ms |
| + ServiceLB/Traefik | ~206 ms | +102 ms |
| + local-path (PVC workload) | ~200 ms | +96 ms |
| + metrics-server | ~196 ms | +92 ms |
| + NetworkPolicy | ~195 ms | +91 ms |

On-host `fork_cluster_warm` (the CoW memcpy path inside TreeFork),
same sources: baseline ~70 ms; CoreDNS ~68 ms; ServiceLB/Traefik
~96 ms; local-path ~79 ms; metrics-server ~79 ms; NetworkPolicy
not recorded for the NetworkPolicy profile — follow-up. A single
profile with every add-on on at once was not recorded.

The three cluster-tree budgets are intentionally generous (750 ms vs.
the ~75 ms / ~25 ms / ~40 ms the design projects on a quiet host). On the bare-metal node the actual on-host operations
take well under those projections in isolation, but `make remote-check`
runs the full integration suite serially with KVM state shared across
tests, and `test_cluster_fork_warm_3vm_under_50ms` already swings up to
~500 ms in that mode (vs. ~25 ms run alone). Tightening the budgets
back to the projected numbers is a follow-up once `remote-check`
enforces a clean inter-test KVM/bridge state.

## Ubuntu bare-VM node substrate

A different guest, so a different substrate: stock Ubuntu 24.04 rootfs
on ext4/virtio-blk with systemd as PID 1 and a distro `-virtual`
kernel, booted by `create_vm` with no initramfs. These numbers are
**not** comparable to the minimal-guest rows above and do not replace
them. Both guests
run through the same VMM, and the delta is entirely userspace: systemd
plus a full distro rootfs instead of a busybox initramfs.

Measured on the bare-metal node (2026-08-18), one VM at 2 GB / 2 vCPU,
`crates/k7d/tests/test_ubuntu_guest.rs`:

| Operation | Ceiling asserted | Typical | Test |
|---|---|---|---|
| Ubuntu boot → agent on vsock | 120 s | ~3.20 s (3.30 s on a shared host) | `test_ubuntu_guest_boots_to_agent_with_systemd_network_and_clock` |
| Ubuntu boot → systemd `running` | 180 s | ~3.49 s (~0.30 s after the agent answers) | same |
| Ubuntu warm fork (1 VM, 2048 MB) | 250 ms (`FORK_UBUNTU_NODE_1VM`) | ~112 ms (~118 ms on a shared host) | `test_ubuntu_guest_warm_fork` |
| Forked child → systemd `running` | 180 s | ~7.5 ms (state resumed, not re-reached) | same |

The two boot ceilings are deliberately loose rather than 2× typical:
they are there to fail a hang (the `console=ttyS0` + serial-marker trap,
which manifests as an infinite wait at `connect_agent`),
not to police distro boot time. Tightening them is a follow-up once a
second measurement on a quiet host exists - as written, a regression
that doubles Ubuntu boot time passes. Boot time is also not yet
optimised beyond masking obviously VM-useless units (25 of them, each
recorded with a reason in the image manifest).

The fork number is the interesting one: warm-forking a 2 GB Ubuntu node
costs ~112 ms, in the same range as the 3-VM inner-k3s cluster forks
above, and it gets its own budget (`FORK_UBUNTU_NODE_1VM`, 250 ms - 2×
the measurement) rather than borrowing the minimal guest's `FORK_WARM`.
The child's root disk is a `FICLONE` reflink of the source's (1773
shared extents), so the fork is CoW on both memory and disk.

## Ubuntu bare-VM k3s cluster

Same Ubuntu substrate as the section above, now with a 3-node k3s
cluster (1 server + 2 agents, k3s' own containerd, default flannel).
New constants only - [`FORK_UBUNTU_NODE_1VM`] and every minimal-guest
budget are untouched.

Measured on an exclusive bare-metal node (2026-08-19, `<node-ip>`),
three VMs at 2 GB / 2 vCPU, k3s `v1.32.5+k3s1` baked offline:

| Operation | Ceiling asserted | Typical | Test |
|---|---|---|---|
| Ubuntu k3s boot → 3 nodes Ready | 600 s (`BOOT_UBUNTU_K3S_CLUSTER_3NODE`) | **39.0 s** (deliveries) / **41.8 s** (fork+churn) | `test_ubuntu_k3s_three_node_cluster_deliveries` |
| Ubuntu k3s cluster warm fork (3 × 2048 MB) | 1000 ms (`FORK_UBUNTU_K3S_CLUSTER_3VM`) | **488 ms** (under the 1 s target) | `test_ubuntu_k3s_cluster_warm_fork_no_restart` |
| Host RAM per node (MemAvailable Δ / 3) | recorded finding | **~1.33-1.37 GiB** | both |
| Node image (sparse 6 GiB logical) | recorded finding | **~3.30 GiB** on disk; rootfs used 2 402 352 KiB | `test_ubuntu_k3s_three_node_cluster_deliveries` |
| Post-fork shared extents (child vs source root) | recorded finding | **2481** | `test_ubuntu_k3s_cluster_warm_fork_no_restart` |

The 600 s boot ceiling is hang detection: three systemd+k3s boots plus
airgap import are a different measurement from the single-VM 3.3 s.
The fork ceiling is ~2× the 488 ms exclusive measurement and is also
the sub-second target; missing that target is a recorded finding, not
a silent pass. `FORK_UBUNTU_NODE_1VM` (250 ms) and every minimal-guest
budget are untouched.

## Ubuntu bare-VM Cilium cluster

Same 3-node Ubuntu k3s substrate as the section above, with
`k7d.cni=none` (flannel and kube-proxy off) and Cilium 1.16.10
installed by host Helm. **No new constant** - 
`FORK_UBUNTU_K3S_CLUSTER_3VM` is reused. `FORK_UBUNTU_NODE_1VM`
and every minimal-guest budget are untouched.

Measured on an exclusive bare-metal node (2026-08-19, `<node-ip>`),
three VMs at 2 GB / 2 vCPU, Helm v3.16.4, chart 1.16.10:

| Operation | Ceiling asserted | Typical | Test |
|---|---|---|---|
| Ubuntu k3s boot → 3 nodes registered (`cni=none`) | 600 s (`BOOT_UBUNTU_K3S_CLUSTER_3NODE`) | **41.1 s** | `test_ubuntu_cilium_datapath_fork` |
| host Helm apply | recorded finding | **4.35 s** | same |
| Cilium image-pull → 3/3 Ready | 600 s wait in the test | **190 s** after helm (events **171 s**); first-run cold pull **206 s** / **352 s** boot-to-Ready | same |
| Ubuntu Cilium cluster warm fork (3 × 2048 MB) | 1000 ms (`FORK_UBUNTU_K3S_CLUSTER_3VM`) | **416 ms** (under the 1 s target) | same |
| Host RAM per node (MemAvailable Δ / 3) | recorded finding | **~1.13 GiB** | same |

The pull is the long pole, not the fork. Reused
`FORK_UBUNTU_K3S_CLUSTER_3VM` rather than adding a Cilium-specific
ceiling; missing the sub-second target is a recorded finding, not a
silent pass. `FORK_UBUNTU_NODE_1VM` (250 ms) and every minimal-guest
budget are untouched.

## Ubuntu bare-VM Tetragon cluster

Same 3-node Ubuntu Cilium cluster as the section above, with
Tetragon 1.7.0 installed by host Helm. **No new constant** - 
`FORK_UBUNTU_K3S_CLUSTER_3VM` is reused. `FORK_UBUNTU_NODE_1VM`
and every minimal-guest budget are untouched.

Measured on an exclusive bare-metal node (2026-08-19, `<node-ip>`),
three VMs at 2 GB / 2 vCPU, Helm v3.16.4, Cilium chart 1.16.10,
Tetragon chart 1.7.0:

| Operation | Ceiling asserted | Typical | Test |
|---|---|---|---|
| Ubuntu k3s boot → Tetragon Ready (3/3 + operator) | hang-detect in the test (600 s) | **266-269 s** (helm-apply **3.6-3.8 s** + pull/ready **56-61 s**) | `test_ubuntu_tetragon_fork_event_diff` |
| event-to-inject (source kprobe+LSM) | recorded finding | **2.7-3.1 s** | same |
| event-to-inject (child, after fork) | recorded finding | **455 ms** | same |
| Ubuntu Tetragon cluster warm fork (3 × 2048 MB) | 1000 ms (`FORK_UBUNTU_K3S_CLUSTER_3VM`) | **453 ms** (full suite) / **551 ms** (isolated); under the 1 s target | same |
| Host RAM per node (MemAvailable Δ / 3) | recorded finding | **~1.13 GiB** | same |

The fork is the product, not the pull. Reused
`FORK_UBUNTU_K3S_CLUSTER_3VM` rather than adding a Tetragon-specific
ceiling; missing the sub-second target is a recorded finding, not a
silent pass. `FORK_UBUNTU_NODE_1VM` and every minimal-guest budget
are untouched.

## Ubuntu bare-VM Longhorn cluster

Same 3-node Ubuntu Cilium cluster, plus a persistent data
disk per node at `/var/lib/longhorn` and Longhorn 1.12.1 installed by
host Helm. **No new constant** - `FORK_UBUNTU_K3S_CLUSTER_3VM` is
reused. `FORK_UBUNTU_NODE_1VM` and every minimal-guest budget are
untouched.

Longhorn is the one workload on this ladder that does not run at
the default Ubuntu node size: it asks for 4 vCPU / 4 GB per storage node
(CHALLENGES #120), so this test passes a `NodeSize` and every other
Ubuntu test keeps 2 vCPU / 2 GB and the numbers above.

Measured on an exclusive bare-metal node (2026-08-19, `<node-ip>`),
three VMs at 4 GB / 4 vCPU with a 16 GiB data disk each, Helm v3.16.4,
Cilium chart 1.16.10, Longhorn chart 1.12.1:

| Operation | Ceiling asserted | Typical | Test |
|---|---|---|---|
| Ubuntu k3s boot → 3 nodes registered (`cni=none`) | 600 s (`BOOT_UBUNTU_K3S_CLUSTER_3NODE`) | **39.0 s** | `test_ubuntu_longhorn_fork_volumes` |
| host Helm apply (Longhorn) | recorded finding | **3.1 s** | same |
| Longhorn image-pull → manager 3/3, CSI 3/3, instance-managers 3/3, StorageClass | 900 s wait in the test | **350-364 s** after helm (**543-661 s** boot-to-Ready, Cilium's pull included) | same |
| RWO PVC bound | recorded finding | **3.6 s** | same |
| RWX PVC bound | recorded finding | **3.6 s** | same |
| Ubuntu Longhorn cluster warm fork (3 × 4096 MB, 3 root + 3 data disks) | 1000 ms (`FORK_UBUNTU_K3S_CLUSTER_3VM`) | **538 ms** / **696 ms** (under the 1 s target); **541 ms** with the tree jail on, k7-node-02, 2026-08-22 - but **1139 ms** when the same test runs last in a 66-minute `make check`, so this one is load-sensitive, not jail-sensitive | same |
| Post-fork shared extents (child vs source data disk) | recorded finding | **100-110** per node | same |
| Host RAM per node (MemAvailable Δ / 3) | recorded finding | **~1.39 GiB** | same |

Six CoW disks instead of three, and twice the guest RAM, still fork
inside the same 1 s ceiling the 2 GB clusters were measured against - 
the fork cost tracks the number of devices and page tables, not the
volume of storage behind them. The pull is the long pole again.

## Incremental reflink keyframes

`prepare_fork_source` on a tree *child* clones the nearest ancestor's
`memory.bin` with `FICLONE` and overwrites only the pages that node has
dirtied since it was forked, so a fork point below the root costs
O(divergence) rather than O(guest RAM). Root, virtiofs payloads, and
any tree whose root is not on a reflink filesystem keep the full dump —
loudly, with `wrote_base_incremental == false` on the wire.

New constant: `PREPARE_KEYFRAME_INCREMENTAL_CLUSTER_3VM` = **4.5 s**,
~2× the worst measured level. Measured on the Ubuntu 3 × 2 GiB cluster
at the measured divergence levels with 30 s of divergence each
(`gym/keyframe_cost.py`, 2026-08-23, `<node-ip>`):

| Operation | Ceiling asserted | Typical | Test |
|---|---|---|---|
| Root keyframe (full dump, 3 × 2 GiB) | recorded finding | **7.79 s** / 6.00 GiB | `test_keyframe_cost_ubuntu_divergence_levels` |
| Child keyframe — idle | 4.5 s | **0.78 s** / 1.18 GiB (19.6 % of the full dump) | same |
| Child keyframe — k8s churn | 4.5 s | **0.84 s** / 1.66 GiB (27.8 %) | same |
| Child keyframe — kafka | 4.5 s | **1.14 s** / 3.06 GiB (51.0 %) | same |

Two things worth knowing before reading these numbers:

- **The disk figure is the workload's, not the clone's.** `FICLONE`
  itself is ~100 µs; what a keyframe costs is exactly the node's dirty
  set, and three k3s nodes dirty a fifth of guest RAM in 30 s of doing
  nothing (page-cache churn). Nothing in this path can make a busy
  node's keyframe small.
- **The keyframe is not fsynced**, and neither is the full dump it
  replaces. Syncing a patched reflinked file cost 2–5 s per member —
  more than everything else on the path combined — because each
  written page breaks a shared extent (CHALLENGES #154).

The disk column is the daemon's own `base_disk_bytes`, reported on the
prepare reply and counted by the tree's disk budget. Do not measure a
reflinked keyframe with `du` or `stat`: both report a shared extent as
if the child owned it (CHALLENGES #152).

## Ubuntu bare-VM ML-mock cluster

Same 3-node Ubuntu k3s Flannel substrate as the first Ubuntu
section, plus a fake kubelet device plugin (`nvidia.com/gpu`
count=2) and a dcgm-exporter-shaped scrape. **No new constant** —
`FORK_UBUNTU_K3S_CLUSTER_3VM` is reused. `FORK_UBUNTU_NODE_1VM`
and every minimal-guest budget are untouched.

Measured on an exclusive bare-metal node (2026-08-23, `<node-ip>`),
three VMs at 2 GB / 2 vCPU, isolated
`test_ubuntu_ml_mocks_gpu_dcgm_fork`:

| Operation | Ceiling asserted | Typical | Test |
|---|---|---|---|
| fake GPU + DCGM Ready (Capacity=2/node) | 180 s wait in the test | **9.4 s** after apply | `test_ubuntu_ml_mocks_gpu_dcgm_fork` |
| `gpu-pause` Running (`nvidia.com/gpu: 1`) | 180 s wait in the test | **4.3 s** | same |
| Ubuntu ML-mock cluster warm fork (3 × 2048 MB) | 1000 ms (`FORK_UBUNTU_K3S_CLUSTER_3VM`) | **458 ms** (under the 1 s target) | same |

The fork is the product, not the fixture pull. Reused
`FORK_UBUNTU_K3S_CLUSTER_3VM` rather than adding an ML-mock-specific
ceiling. `FORK_UBUNTU_NODE_1VM` and every minimal-guest budget are
untouched.

## Ubuntu bare-VM JobSet on mock GPUs

Same 3-node Ubuntu k3s Flannel + GPU/DCGM fixture, plus
digest-pinned JobSet v0.12.0. **No new constant** —
`FORK_UBUNTU_K3S_CLUSTER_3VM` is reused. `FORK_UBUNTU_NODE_1VM`
and every minimal-guest budget are untouched.

Measured on an exclusive bare-metal node (2026-08-24, `<node-ip>`),
three VMs at 2 GB / 2 vCPU, isolated
`test_ubuntu_ml_jobset_gpu_fork`:

| Operation | Ceiling asserted | Typical | Test |
|---|---|---|---|
| fake GPU + DCGM Ready (Capacity=2/node) | 180 s wait in the test | **3.2 s** after apply | `test_ubuntu_ml_jobset_gpu_fork` |
| JobSet v0.12.0 controller Ready | 300 s wait in the test | **28 s** | same |
| 2-worker JobSet Complete (`nvidia.com/gpu: 1` each, CPU/Gloo DNS) | 300 s wait in the test | **12.5 s** after apply | same |
| Ubuntu JobSet cluster warm fork (3 × 2048 MB) | 1000 ms (`FORK_UBUNTU_K3S_CLUSTER_3VM`) | **298 ms** (under the 1 s target) | same |

The fork is the product, not the JobSet image pull. Reused
`FORK_UBUNTU_K3S_CLUSTER_3VM` rather than adding a JobSet-specific
ceiling. `FORK_UBUNTU_NODE_1VM` and every minimal-guest budget are
untouched.

## Ubuntu bare-VM Soft-RoCE

Same 3-node Ubuntu k3s Flannel substrate as the first Ubuntu
section, plus Soft-RoCE (`rdma_rxe`) on guest `eth0`. **No new
constant** — `FORK_UBUNTU_K3S_CLUSTER_3VM` is reused.
`FORK_UBUNTU_NODE_1VM` and every minimal-guest budget are
untouched.

Measured on an exclusive bare-metal node (2026-08-24, `<node-ip>`),
three VMs at 2 GB / 2 vCPU, isolated
`test_ubuntu_ml_rdma_soft_roce_fork`:

| Operation | Ceiling asserted | Typical | Test |
|---|---|---|---|
| Ubuntu Soft-RoCE cluster warm fork (3 × 2048 MB) | 1000 ms (`FORK_UBUNTU_K3S_CLUSTER_3VM`) | **540 ms** typical / **974 ms** first run after clippy (under the 1 s target) | same |

The fork is the product, not an NCCL run. Reused
`FORK_UBUNTU_K3S_CLUSTER_3VM` rather than adding a Soft-RoCE-specific
ceiling. `FORK_UBUNTU_NODE_1VM` and every minimal-guest budget are
untouched.

## Ubuntu bare-VM KubeRay on mock GPUs

Same 3-node Ubuntu k3s Flannel + GPU/DCGM fixture, plus
digest-pinned KubeRay v1.7.0. **No new constant** —
`FORK_UBUNTU_K3S_CLUSTER_3VM` is reused. `FORK_UBUNTU_NODE_1VM`
and every minimal-guest budget are untouched.

Measured on an exclusive bare-metal node (2026-08-24, `<node-ip>`),
three VMs at 2 GB / 2 vCPU, isolated
`test_ubuntu_ml_kuberay_gpu_fork`:

| Operation | Ceiling asserted | Typical | Test |
|---|---|---|---|
| fake GPU + DCGM Ready (Capacity=2/node) | 180 s wait in the test | **9.4 s** after apply | `test_ubuntu_ml_kuberay_gpu_fork` |
| KubeRay v1.7.0 operator Ready | 300 s wait in the test | **24.6 s** | same |
| CPU head + GPU worker Running (`nvidia.com/gpu: 1`) | 180 s wait in the test | **3.2 s** after apply | same |
| Ubuntu KubeRay cluster warm fork (3 × 2048 MB) | 1000 ms (`FORK_UBUNTU_K3S_CLUSTER_3VM`) | **580 ms** (under the 1 s target) | same |

The fork is the product, not a Ray image pull. Reused
`FORK_UBUNTU_K3S_CLUSTER_3VM` rather than adding a KubeRay-specific
ceiling. `FORK_UBUNTU_NODE_1VM` and every minimal-guest budget are
untouched.

## Ubuntu Redis mid-write fork 

Same 3-node Ubuntu k3s substrate, with `redis:7-alpine` (AOF on,
128 MiB, pinned to `k7d-10-200-0-2`) and an `rinc` INCR loop on a
different node. **No new constant** —
`FORK_UBUNTU_K3S_CLUSTER_3VM` is reused. `FORK_UBUNTU_NODE_1VM`
and every minimal-guest budget are untouched.

Measured on an exclusive bare-metal node (2026-09-03, `<node-ip>`),
cache-hit Ubuntu image:

| Operation | Ceiling asserted | Typical | Test |
|---|---|---|---|
| Ubuntu k3s boot → 3 nodes Ready + adopt | 600 s (`BOOT_UBUNTU_K3S_CLUSTER_3NODE`) | **40.8 s** | `test_redis_midwrite_ubuntu_fork` |
| Redis AOF + rinc Ready, `forkctr` ≥ 50 | 180 s wait in the harness | **~6 s** after source Ready | same |
| Ubuntu Redis mid-write warm fork (3 × 2048 MB) | 1000 ms (`FORK_UBUNTU_K3S_CLUSTER_3VM`) | **575 ms** client / **568 ms** daemon (under the 1 s target) | same |
| Harness wall (cache-hit) | 180 s | **84 s** harness / **99 s** cargo-test | same |

The fork is the product, not a Redis image pull. Reused
`FORK_UBUNTU_K3S_CLUSTER_3VM` rather than adding a Redis-specific
ceiling. `FORK_UBUNTU_NODE_1VM` and every minimal-guest budget are
untouched.
