# gym — per-node lease service over k7d cluster fork

HTTP sidecar for one k7d daemon. A trainer leases N sibling clusters
forked from one live checkpoint, acts, scores, and releases. The gym
owns cleanup: a client that dies costs nothing after the lease TTL.

This is **not** the trainer. No GPU, no torch, Python stdlib only.

## Run it (< 5 min on a KVM box)

```bash
test -S /run/k7d/k7d.sock && systemctl is-active k7d
ls /dev/kvm guest/kernel/vmlinux guest/rootfs/initramfs.cpio.gz

# create mode: gym cold-boots a 3-VM busybox source once, then forks
python3 gym/server.py --source-mode create --port 8080
# other terminal:
curl -sS http://127.0.0.1:8080/healthz
curl -sS -X POST http://127.0.0.1:8080/lease \
  -H 'Content-Type: application/json' \
  -d '{"fault_id":"none","n":4,"group_id":"g1","ttl_s":120}'
```

`adopt` mode takes the live `INNER3_PODS` (`K7_KEEP_INNER3=1`) instead
of a busybox source. Failures from `tree_adopt_cluster` are returned
verbatim — the gym never falls back to `create`.

**Trainer substrate is `ubuntu`**. The first HTTP contract froze on
busybox; that exception is closed. Ubuntu mode boots a 3-node k3s
cluster through `/run/k7d/k7d.sock` (`CreateVm` × 3 with the Ubuntu
bzImage + root disk + `k7d.k3s=`, then `tree_adopt_cluster` +
`tree_protect`). It never calls `tree_create_cluster` and never
adopts `k7-br-inner3`.

```bash
# requires the Ubuntu node image (content-keyed cache under
# /var/lib/k7d/disks/base-images) and GYM_MEMORY_MB >= 2048
# Cilium/Tetragon scoreboards also need: make helm-pin
GYM_SOURCE_MODE=ubuntu GYM_MEMORY_MB=2048 python3 gym/server.py --port 8080
```

`GYM_MEMORY_MB < 2048` is a loud startup error (the 256 MiB create-mode
default is a leftover). Admission uses 2048 MiB/VM; a 3-node Ubuntu
source measured ~1.35 GiB host RAM/node. A lease that cannot fit `1 source + n forks`
is **400** with the arithmetic — never a silent drop to busybox.

## HTTP contract

Every JSON object includes `node_id` (hostname, or `GYM_NODE_ID`) so a
router can be a dumb proxy. `group_id` is echoed, never interpreted.
Errors carry the k7d message verbatim. No retries that would mask
`BudgetExhausted` or an adopt precondition.

`POST /lease` is the **only** fork. Siblings are created together
(`tree_fork_batch`) or not at all; a partial batch is pruned before
the response returns.

Auth: if `GYM_TOKEN` is set, every request must send
`X-Gym-Token: <token>`. Unset means no check. The gym-router
(`gym/router.py`) forwards the same header.

| Method + path | Body → response |
|---|---|
| `GET /healthz` | → `{ok, node_id, k7d: "ready", free_ram_bytes, leases_in_flight, max_leases}`. **503** with `ok:false` if `/run/k7d/k7d.sock` is absent or `ping` fails — never `ok` on a dead daemon. |
| `POST /lease` | `{fault_id, n, group_id, ttl_s}` → `{lease_id, node_id, tree_id, source_node_id, group_id, fault_id, good_fix_hint, inject_ms, envs: [{env_id, branch_node_id, index, bridge, guest_ips}]}`. `fault_id` selects an injector from `gym/faults/` (`none`, `kill-member-0`, `partition-member-0`). Unknown id is **400** with the allowlist in `error` — never a silent `none`. Inject runs **after** `tree_fork_batch`. `health` / `tetragon` plant env index 0 only; `incident` / `grpo` plant **every** env. A failed inject tears the lease down before the response returns. A group that cannot fit `GYM_MAX_LIVE_VMS` / `GYM_MAX_LIVE_RAM_BYTES` is **400** with the arithmetic in `error` (e.g. `need 27 live VMs (source=3 + already_leased=0 + n=8 * vms_per_branch=3) > max_live_vms=8`). Nothing is forked. |
| `POST /env/{env_id}/act` | `{action, args, timeout_s}` → `{ok, stdout, stderr, exit_code, elapsed_ms, node_id}`. Verbs: `exec` (vsock agent, create-mode / busybox) and `kubectl` (inner apiserver via `curl --interface <bridge>` — kubectl itself cannot pick a bridge). A non-zero guest/API exit is HTTP 200 with `ok:false`. |
| `POST /env/{env_id}/obs` | → `{observation, truncated_bytes, byte_count, node_id}`. create: per-member `uname` + cids. adopt / ubuntu: `GET /api/v1/nodes`, `GET /api/v1/pods`, `/readyz`. Ubuntu also adds `services{"k3s.service"}` + `links{"eth0"}` from one vsock exec on `guest_cids[0]`; exec failure sets `services_error` and omits those keys — never fabricates `active`. Observation packing is the original HTTP contract; `truncated_bytes` is 0 today. |
| `POST /lease/{lease_id}/score` | → `{scores: [{env_id, reward, terms: {liveness, workload_ready, source_intact, contained, restored}}], node_id}` in `envs` order. Terms are always all five keys; never defaulted. `health`: `contained` is 1.0 iff the fault is isolated to env 0 (visible there or already restored; source + other siblings clean); `restored` is 1.0 iff env 0 matches the injector's healthy predicate. `GYM_SCOREBOARD=grpo` scores each env on **its own** readyz / nodes_ready / contained / restored (`source_intact` is shared); a member whose vsock/API probe raises is zeros + `unreachable: true` (HTTP 200, never 502 the group). `reward` is the mean of the five. `GYM_SCOREBOARD=tetragon` keeps those five keys; `contained` is the source-vs-branch event-diff and each row also carries `event_diff`. `GYM_SCOREBOARD=playbook` takes `{turn}` and returns graded `reward=passed/t` plus a `playbook` payload; missing `playbook` is loud. The five terms stay diagnostics. |
| `POST /lease/{lease_id}/release` | → `{released: true, pruned: [...], residue: {bridges, taps, tree_node_ids, errors}, node_id}`. Prunes each branch node (disk included). Does **not** drop the source tree — `tree_fork_batch` is intra-tree; dropping the tree would destroy the warm checkpoint. Residue is reported, not hidden. |
| `GET /lease/{lease_id}` | → lease record + `expires_at` (unix seconds). |

`kubectl` args are kubectl-shaped. The first surface maps:

- `get nodes` / `get pods` / `get pods -A` / `get deploy NAME` / `get ns`
- `delete pod NAME`
- `scale deploy NAME --replicas=N`
- `--raw=/path` or a leading `/api/...` path

Anything else is a loud 400. Traffic is `curl --interface <env.bridge>`
because source and fork clusters share guest IPs (`10.200.0.2`…).
Reset n=8 bring-up pins `10.200.0.2/32` via that member's
`k7-br-*` around host `kubectl` / Helm (`pin_guest_route`) so
`wait_nodes_ready` does not hit a sibling apiserver.

## Config

| Env / flag | Default | Meaning |
|---|---|---|
| `GYM_SOURCE_MODE` / `--source-mode` | `create` | `create`, `adopt`, or `ubuntu`. Unknown values are loud. No implicit fallback. |
| `GYM_START_MODE` / `--start-mode` | `fork` | `fork` (training) or `reset` (measurement-only fresh bring-up per member). `reset` requires `GYM_SOURCE_MODE=ubuntu` and `GYM_RESET_MEASUREMENT=1`. Admission is `n × 3 × 2048 MiB` — not CoW. A fork-sized budget (`max_live_vms=8`, or RAM sized on ~0.6 GiB RSS/fork) is a loud 400. Do not train on reset. |
| `GYM_SCOREBOARD` / `--scoreboard` | `health` | `health` (catalog contain/restore, flannel, env-0 inject), `tetragon` (Cilium+Tetragon on the Ubuntu source, then source-vs-branch event-stream diff + cluster health), `playbook` (same 20-page SRE exam on every member, reward = passed/t, `ready_gate=api`), `incident` / `selfplay` (catalog relays), or `grpo` (`kill-member-0` / `partition-member-0` / `none` on **every** member, per-member five-term mean; `relay` stays on incident/selfplay). `tetragon` requires `ubuntu` and pinned helm v3.16.4. `playbook` requires `ubuntu`, `fault_id=none`, and does not wait `CLUSTER_READY_S` nodes Ready. `grpo` requires `ubuntu`. Loud with inject faults on playbook; loud with `relay` on grpo. Member API down → HTTP 200 + reward terms 0, not 502. API up but no Tetragon pods → 502, never a silent health score. Bring-up installs Cilium+Tetragon on the guest bridge when `tetragon` (not host kubectl / flannel Ready-wait). |
| `GYM_READY_GATE` / `--ready-gate` | `nodes` | `nodes` (wait three Ready) or `api` (lease after `/readyz`). `playbook` forces `api`. Do not change the health/tetragon default. |
| `GYM_RESET_MEASUREMENT` / `--reset-measurement` | unset | Required acknowledgement that reset is measurement-only. |
| `GYM_SOURCE_TREE_ID` / `--source-tree-id` | `gym-src-<pid>` | Source tree id. Prefix `gym-src-` exempts it from the startup sweep. |
| `GYM_BIND` / `--bind` | `127.0.0.1` | Listen address. |
| `GYM_PORT` / `--port` | `8080` | Listen port (`0` = ephemeral). |
| `GYM_NODE_ID` / `--node-id` | hostname | Echoed on every response. |
| `GYM_MAX_LEASES` | `4` | In-flight lease cap. |
| `GYM_MAX_LIVE_VMS` | `64` | Admission + the `TreeBudget` passed at source create/adopt. **Not** the daemon default of 8. |
| `GYM_MAX_LIVE_RAM_BYTES` | 64 GiB | Same, for RAM. |
| `GYM_VM_COUNT` | `3` | Members per cluster (create mode). |
| `GYM_MEMORY_MB` | `256` | Guest RAM per VM. create-mode leftover default. **ubuntu mode refuses to start below 2048** (`NODE_MEMORY_MB`). |
| `GYM_REAPER_INTERVAL_S` | `1` | Must be well under the shortest TTL. |
| `GYM_TOKEN` | unset | Shared-secret header. |
| `K7D_SOCKET` | `/run/k7d/k7d.sock` | Daemon control socket. |
| `K7D_KERNEL` / `K7D_INITRD` | workspace guest | create-mode busybox source only. Ubuntu `CreateVm` passes explicit bzImage + disk paths and never reads these (CHALLENGES #72). |

## Lifecycle

1. **Startup sweep.** `tree_list` vs the empty lease table: prune stray
   children on `gym-src-*` trees; prune-then-drop any other `gym-*`
   tree. A gym restart must not orphan a tree forever.
2. **Source.** `create`: `tree_create_cluster` (busybox). `adopt`:
   `tree_adopt_cluster` over `INNER3_PODS`. `ubuntu`: `CreateVm` × 3
   (Ubuntu bzImage, no initrd, `root=/dev/vda`, `k7d.k3s=`) then
   `tree_adopt_cluster` + `tree_protect`. Create-mode also
   `ip link set eth0 up` on every source member so forks inherit a live
   link (`partition-member-0` takes it down on env 0 only); Ubuntu
   `eth0` is already UP (`k7d-net.service`). Two independent guards
   (prefix + protect) so auto-evict cannot take the checkpoint every
   future group forks from. The gym never cold-boots inside
   `POST /lease`.
3. **Lease.** Budget check → one `tree_fork_batch` → inject on env 0 → envs.
4. **Release / TTL.** Same path: prune each branch. The reaper logs
   `lease_id`, age, and the client that never came back.
5. **`tree_drop` keeps disk.** Release therefore prunes (subtree delete
   includes disk) and leaves the source tree in place. A reaper that
   only dropped would fill the disk and look like a k7d leak.

## Router

`gym/router.py` sits in front of **≥2** gym processes. It is a dumb
proxy: same paths, same JSON, plus `node_id`. It never opens
`/run/k7d/k7d.sock` and never forks. One GRPO group still lives on
one node.

```bash
# two gyms (each owns its own k7d + Ubuntu source), then:
GYM_UPSTREAMS=http://127.0.0.1:8081,http://127.0.0.1:8082 \
GYM_MEMORY_MB=2048 python3 gym/router.py --port 8080
```

- **Sticky `group_id`.** The first successful `POST /lease` pins the
  group to that gym. Later leases with the same id go there while the
  gym is up. A drained gym is **not** migrated — the trainer requeues.
- **Drain.** `GET /healthz` 503 or unreachable → stop placing **new**
  groups there. In-flight `/env/…/act` against that gym fails loud
  (HTTP 502). Unknown `lease_id` / `env_id` is **404**, not a broadcast.
- **Admission.** `GYM_MEMORY_MB < 2048` is a loud startup error.
  A lease that cannot fit is **400** with
  `2048 MiB × 3 × (1+n)` spelled in `error` (1 source + n forks,
  3 VMs/branch, 2048 MiB/VM). Do not admit on k7d VmRSS (~0.6 GiB
  per 3-node fork) — that undercounts guest RAM.

`GYM_TOKEN` is checked on the router and forwarded as `X-Gym-Token`.
`gym/stub.py` is the no-k7d gym used by router tests.

## Layout

| File | Role |
|---|---|
| `server.py` | `http.server`; one process per node |
| `router.py` | Sticky-group proxy + Ubuntu RAM admission + drain |
| `stub.py` | Fake gym for router tests (no k7d) |
| `lease.py` | Lease state machine + table |
| `budget.py` | `TreeBudget` arithmetic |
| `scoring.py` | Contain/restore reward + kubectl→API map |
| `tetragon.py` | Tetragon event-diff scoreboard: parse export-stdout, baseline-diff, `score_tetragon`; dead API is a scored 0. Cilium+Tetragon install lives in `sensors.py` (bridge, only when `GYM_SCOREBOARD=tetragon`). |
| `playbook.py` | 20-page SRE exam. `GYM_SCOREBOARD=playbook`, reward = passed/t, pinned in-guest image, poll ceilings. Not Tetragon. |
| `plots/` | GRPO figure **scripts** (fixture JSONL is SYNTHETIC -- `gym/plots/README.md`). `plots/harvest.py` produces four *gym-scripted* LIVE figures (noop/oracle, no GPU, no learning curve) plus playbook std-vs-turn. Dirty-page SVGs are a separate pipeline. |
| `faults/` | Named injectors (`none`, `kill-member-0`, `partition-member-0`). Ubuntu kill stops `k3s.service` on member 0 — never `kill -9 1`. `GYM_SCOREBOARD=tetragon` keeps the apiserver and injects via a pinned busybox pod (CHALLENGES #146 / #147). |
| `ubuntu.py` | Ubuntu node image / cmdline / Ready wait for `GYM_SOURCE_MODE=ubuntu` |
| `agent.py` | Vsock agent client (port 1024) |
| `host.py` | `k7-br-*` / TAP / MemAvailable |
| `tests/` | Pure-Python unit tests (`make gym-test`) |

The JSON-lines client lives at
`examples/cluster-tree-search/k7d_client.py` and is imported from
there. Do not copy it.

## Host deps (Ubuntu / Cilium / Tetragon)

```bash
make helm-pin          # helm v3.16.4 → /usr/local/lib/k7d-helm/ (root)
# Ubuntu node image (first build is long; later runs are cache hits):
#   guest/ubuntu/build-node-image.sh
```

`GYM_SCOREBOARD=tetragon` and `examples/k7d-mcp/scenario_incident.py`
refuse any other helm. Bind stays `127.0.0.1`.

## Tests

```bash
make gym-test          # no KVM
# full suite, including crates/k7d/tests/test_gym.rs:
make remote-check
```
