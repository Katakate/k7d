# Latency Budgets

Every operation below is enforced by an integration test in
[`crates/k7d/tests/test_latency.rs`](crates/k7d/tests/test_latency.rs).
The budget constants live in
[`crates/k7d/src/latency.rs`](crates/k7d/src/latency.rs) —
that file is the single source of truth imported by the tests.

Budgets are set at roughly 2× the typical observed value on the bare-metal
bare-metal node (currently AMD Ryzen 5 3600, 64 GB, NVMe — see
`docs/blog/2026-08-07-k7d-cluster-fork-benchmark.md`).

| Operation | Budget | Typical | Test |
|---|---|---|---|
| VM build (KVM + memfd + virtiofsd) | 150 ms | ~62 ms | `test_latency_vm_build` |
| VM boot → agent ready | 250 ms | ~194–205 ms (was ~225–235 ms; the kvmclock kernel rebuild in 19f took ~18 ms off it) | `test_latency_vm_boot_to_agent` |
| Agent ping RTT | 1 ms | ~0.2 ms | `test_latency_agent_ping` |
| Agent exec RTT | 2 ms | ~0.5 ms | `test_latency_agent_exec` |
| 5× sequential exec | 5 ms | ~2 ms | `test_latency_exec_sequential_5x` |
| Virtiofs read | 2 ms | ~1 ms | `test_latency_virtiofs_read` |
| Virtiofs write | 2 ms | ~1.14 ms mean / 1.26 ms max with guest haltpoll 200 µs window (`cpuidle_haltpoll.force=1`, 50 ms settle + 2 warmups); was ~1.16 ms / 1.23 ms at a 2 ms window, ~1.2 ms under `idle=poll`, ~1.7 ms (2 of 10 over budget) with plain HLT | `test_latency_virtiofs_write` |
| Snapshot 256 MB VM | 500 ms | ~228 ms | `test_latency_snapshot_256mb` |
| CoW restore from snapshot | 10 ms | ~3 ms | `test_latency_restore_cow` |
| Agent reconnect after restore | 5000 ms | ~500 ms | `test_latency_restore_agent_reconnect` |
| Fork (cold source) | 600 ms | ~250 ms | `test_latency_fork_cold` |
| Warm fork (part 1) — `<25%` dirty | 50 ms | ~5 ms | `test_fork_warm_under_50ms` |
| Warm fork of a 2-vCPU source | 75 ms | TBD (start generous, tighten after measuring) | `test_fork_warm_multi_vcpu` |
| CoW restore of a 2-vCPU snapshot | 35 ms | TBD | `test_multi_vcpu_snapshot_restore_roundtrip` |
| 10× warm fork batch | 200 ms | ~15 ms | `test_fork_warm_batch_10` |
| Cluster warm fork — 3 VMs | 150 ms | ~25–40 ms quiet / ~70–100 ms loaded bare-metal | `test_cluster_fork_warm_3vm_under_50ms` |
| Cluster-tree fork — 3 VMs | 750 ms | ~75 ms quiet host | `test_cluster_tree_fork_under_75ms` |
| Cluster warm fork batch — 8× 3 VMs | 2 s | shared pause; must beat 8×150 ms | `test_cluster_fork_warm_batch_8` |
| Cluster-tree fork batch — 50× 3 VMs | 20 s | ~4.1 s (~82 ms/cluster) shared pause + parallel materialise; must beat 50×750 ms | `test_cluster_tree_fork_batch_50` |
| Inner-k3s cluster-tree fork — 3 VMs + load churn | 1 s | ~104 ms with dirtier fixture (pause Deployment scale + ConfigMap/pause-pod storm, 2026-08-08); CoW path (~70 ms on-host `fork_cluster_warm`) | `test_inner_k3s_cluster_warm_fork_no_restart` |
| Inner-k3s cluster-tree fork — 3 VMs + CoreDNS + load churn | 1 s | ~175 ms (22a-inc1, 2026-08-17, quiet/targeted host; CoreDNS Ready + 3 DNS-probe pods + load churn); on-host `fork_cluster_warm` ~68 ms; reuse `FORK_INNER_K3S_CLUSTER_3VM` | `test_inner_k3s_coredns_dns_fork` |
| Inner-k3s cluster-tree fork — 3 VMs + ServiceLB + Traefik + load churn | 1 s | ~206 ms (22a-inc2, 2026-08-17, targeted host; Traefik Ready + HTTP Ingress + load churn); on-host `fork_cluster_warm` ~96 ms; reuse `FORK_INNER_K3S_CLUSTER_3VM` | `test_inner_k3s_ingress_fork` |
| Inner-k3s cluster-tree fork — 3 VMs + local-path PVC + load churn | 1 s | ~200 ms (22a-inc3, 2026-08-17, targeted host; local-path-provisioner Ready + PVC writer + load churn); on-host `fork_cluster_warm` ~79 ms; reuse `FORK_INNER_K3S_CLUSTER_3VM` | `test_inner_k3s_local_path_pvc_fork` |
| Inner-k3s cluster-tree fork — 3 VMs + metrics-server + load churn | 1 s | ~196 ms (22a-inc4, 2026-08-17, targeted host; metrics-server Ready + `metrics.k8s.io` Available + load churn); on-host `fork_cluster_warm` ~79 ms; reuse `FORK_INNER_K3S_CLUSTER_3VM` | `test_inner_k3s_metrics_server_fork` |
| Inner-k3s cluster-tree fork — 3 VMs + NetworkPolicy + load churn | 1 s | ~195 ms (22a-inc5, 2026-08-17, targeted host; netpol controller live, default-deny + allow policies enforced + load churn); on-host `fork_cluster_warm` not recorded by 22a-inc5 — follow-up; reuse `FORK_INNER_K3S_CLUSTER_3VM` | `test_inner_k3s_network_policy_fork` |
| Inner-k3s cluster-tree fork — 3 VMs + metrics + HPA + CPU-burn load | 1 s | ~200 ms (23a-inc1, 2026-08-17, targeted host; HPA scaled 1→3 from CPU metrics + load churn); on-host `fork_cluster_warm` ~85 ms; reuse `FORK_INNER_K3S_CLUSTER_3VM` | `test_inner_k3s_hpa_scale_fork` |
| Inner-k3s cluster-tree fork — 3 VMs + etcd datastore + load churn | 1 s | ~200 ms (23a-inc2, 2026-08-17, targeted host; embedded etcd + load churn); on-host `fork_cluster_warm` ~90 ms; reuse `FORK_INNER_K3S_CLUSTER_3VM` | `test_inner_k3s_etcd_datastore_fork` |
| Inner-k3s cluster-tree fork — 3 VMs + ArgoCD core + git server | 2 s | ~203–213 ms (23a-inc3, 2026-08-18, targeted host; ArgoCD core + git + Synced Application); on-host `fork_cluster_warm` ~87–96 ms; new `FORK_INNER_K3S_CLUSTER_3VM_ARGOCD` — do not widen the shared 1 s `FORK_INNER_K3S_CLUSTER_3VM` | `test_inner_k3s_argocd_gitops_fork` |
| Cluster-tree suspend — 3 VMs | 750 ms | ~25 ms quiet host | (asserted via `SUSPEND_CLUSTER_TREE_3VM`) |
| Cluster-tree resume — 3 VMs | 750 ms | ~40 ms quiet host | (asserted via `RESUME_CLUSTER_TREE_3VM`) |
| Fork agent reconnect | 5000 ms | ~500 ms | `test_latency_fork_agent_reconnect` |
| VM shutdown | 5 ms | ~0.05 ms | `test_latency_vm_shutdown` |
| Pool acquire — pooled `create_vm` round trip | 100 ms | ~50 ms (dominated by the control listener's 50 ms accept poll, not the pool) | `test_pool_fills_and_acquire_is_fast` |
| Pod network ready | 50 ms | ~5–10 ms over `VM_BOOT_TO_AGENT` | (asserted via `POD_NETWORK_READY`) |
| Pod volumes setup — per-pod kubelet-volume bind tree | 250 ms | ~25–40 ms on bare-metal (3–6 volumes) | `test_latency_pod_volumes_setup` |
| Virtiofsd socket appear — ceiling, multi-share spawn | 15 s | sub-second | (asserted via `VIRTIOFSD_SOCKET_APPEAR`) |

## Inner-k3s add-on fork cost (epic w3 / the referenced work)

TreeFork elapsed on the 3-VM inner-k3s fixture. Every typical is the
value the merged increment wrote into the table above — this unit
does not re-measure. Deltas subtract the lean baseline (~104 ms,
2026-08-08). inc2–inc5 profiles also enable CoreDNS, so those deltas
include CoreDNS's share; isolated add-on cost (profile minus the
CoreDNS-only row) was not a required recording.

| Profile | Typical fork | Delta vs baseline (~104 ms) |
|---|---|---|
| baseline (add-ons off, load churn) | ~104 ms | — |
| + CoreDNS | ~175 ms | +71 ms |
| + ServiceLB/Traefik | ~206 ms | +102 ms |
| + local-path (PVC workload) | ~200 ms | +96 ms |
| + metrics-server | ~196 ms | +92 ms |
| + NetworkPolicy | ~195 ms | +91 ms |

On-host `fork_cluster_warm` (the CoW memcpy path inside TreeFork),
same sources: baseline ~70 ms; CoreDNS ~68 ms; ServiceLB/Traefik
~96 ms; local-path ~79 ms; metrics-server ~79 ms; NetworkPolicy
not recorded by 22a-inc5 — follow-up. A single profile with every
add-on on at once was not recorded by 22a.

The three cluster-tree budgets are intentionally generous (750 ms vs.
the ~75 ms / ~25 ms / ~40 ms the design projects on a quiet host). On the bare-metal node the actual on-host operations
take well under those projections in isolation, but `make remote-check`
runs the full integration suite serially with KVM state shared across
tests, and `test_cluster_fork_warm_3vm_under_50ms` already swings up to
~500 ms in that mode (vs. ~25 ms run alone). Tightening the budgets
back to the projected numbers is a follow-up once `remote-check`
enforces a clean inter-test KVM/bridge state.
