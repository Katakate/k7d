# Challenges & solutions log

Tracking non-obvious bugs and which reference projects helped solve them.

## 1. Guest CPU immediately triple-faults (Milestone 1)

**Symptom:** `VcpuExit::Shutdown` after 1 exit. CPU registers reset to `rip=0xfff0, cr0=0x10` (BIOS reset vector). No kernel output at all.

**Root cause:** Missing `set_cpuid2()`. On AMD SVM, KVM requires CPUID entries to be explicitly set for the guest vCPU. Without them, the CPU can't execute the first instruction — it triple-faults immediately because the guest CPU doesn't know what features it supports.

**Fix:** Call `kvm.get_supported_cpuid()` then `vcpu_fd.set_cpuid2()` before running.

**Reference:** Firecracker (`arch/x86_64/vcpu.rs`) — sets CPUID for every vCPU.

**Time lost:** ~4 hours debugging. The symptoms gave no hint that CPUID was the cause.

---

## 2. vhost-vsock EFAULT on SET_RUNNING (Milestone 1.5)

**Symptom:** All vhost ioctls succeed (SET_OWNER, SET_FEATURES, SET_MEM_TABLE, SET_GUEST_CID, SET_VRING_NUM/BASE/ADDR/KICK/CALL) but `VHOST_VSOCK_SET_RUNNING` returns EFAULT. The kernel's `vhost_vq_access_ok()` fails.

**Root cause:** `VIRTIO_F_ACCESS_PLATFORM` (bit 33) was set in vhost features. When passed to `SET_FEATURES`, the kernel enables IOTLB mode — vring addresses in `SET_VRING_ADDR` are interpreted as IOVAs (guest physical addresses) instead of host user-space virtual addresses. Since we pass HVAs, the kernel can't access them.

**Fix:** Clear bit 33 before calling `VHOST_SET_FEATURES`:
```rust
let features = vhost_features & !(1u64 << 33);
```

**Reference:** crosvm (`devices/src/virtio/vhost/worker.rs` lines 85-91) — explicitly clears `VIRTIO_F_ACCESS_PLATFORM`.

**Why we needed crosvm:** Firecracker and Cloud Hypervisor implement vsock in userspace — they don't use `/dev/vhost-vsock` at all. crosvm is the only Rust VMM in our references that uses the kernel vhost-vsock path.

**Time lost:** ~6 hours. Same ioctls worked in standalone Rust/Python test binaries (because they used all vhost features including ACCESS_PLATFORM, but with nregions=0 which skipped the address validation).

---

## 3. Guest doesn't see virtio-MMIO device (Milestone 1.5)

**Symptom:** Kernel cmdline has `virtio_mmio.device=4K@0xc000000:5` but no device probe in kernel log.

**Root cause (a):** `CONFIG_VIRTIO_MMIO_CMDLINE_DEVICES` was not set in the guest kernel config. The kernel has the virtio-mmio driver but doesn't parse the cmdline parameter without this option.

**Root cause (b):** MMIO device was placed at `0xc000000` (192MB) which is WITHIN the guest RAM region (0-256MB). KVM maps this as regular memory, so accesses don't generate MMIO exits — they just read/write RAM.

**Fix:** (a) Add `CONFIG_VIRTIO_MMIO_CMDLINE_DEVICES=y` to kernel config. (b) Place MMIO devices above guest RAM: `base = mem_size + 0x1000`.

**Reference:** Firecracker kernel configs + MMIO device placement logic.

---

## 4. Interrupt delivery for vhost devices (Milestone 1.5 → 2)

**Symptom:** vhost-vsock activated, guest agent listens on AF_VSOCK, but host `connect()` times out. The guest never processes incoming vsock packets.

**Root cause:** Two-part issue:
1. The vhost call eventfd fires the KVM irqfd (delivering IRQ 5 to the guest), but the virtio-MMIO `INTERRUPT_STATUS` register (offset 0x60) never has the `INT_VRING` bit set. The guest driver reads interrupt_status, sees 0, and dismisses the interrupt.
2. The `QUEUE_NOTIFY` MMIO writes from the guest weren't being forwarded to the vhost kick eventfds, so the host-side vhost kernel never processed guest-submitted buffers.

**Fix:** 
- Firecracker pattern for vhost interrupt status: `is_vhost` flag makes `interrupt_status` always return `INT_VRING` for vhost devices (since the vhost kernel manages its own state).
- Forward `QUEUE_NOTIFY` writes to the vhost kick eventfds via `VirtioBackend::queue_notify()`.

**Reference:** Firecracker (`transport/mmio.rs` lines 260-279) — for vhost-user devices, always returns `VIRTIO_MMIO_INT_VRING` from interrupt status read.

---

## 5. Serial FIFO overflow on large payloads (Milestone 3)

**Symptom:** Agent never responds to `write_file` commands. The file transfer protocol sends base64-encoded data as a single JSON line, but lines >64 bytes get silently truncated by the serial FIFO.

**Root cause:** vm-superio's serial FIFO is 64 bytes. `enqueue_raw_bytes()` silently drops bytes when the FIFO is full.

**Fix:** Send data in 32-byte chunks with 1ms inter-chunk delays to let the guest drain the FIFO.

**Reference:** None — discovered empirically.

---

## 6. Initrd not detected by kernel (Milestone 2)

**Symptom:** Kernel boots but doesn't unpack initramfs. No "Unpacking initramfs" message. Kernel panics with "VFS: Unable to mount root fs."

**Root cause:** Two issues:
1. `boot_params.hdr.version` not set — the kernel checks the protocol version to determine which header fields are valid. Without it, `ramdisk_image`/`ramdisk_size` are ignored.
2. Initrd address not page-aligned — kernel expects the initrd at a 4K-aligned address.

**Fix:** Set `params.hdr.version = 0x020e` (protocol 2.14). Align initrd address: `(mem_size - initrd_size) & !0xFFF`.

**Reference:** Firecracker boot params setup in `arch/x86_64/mod.rs`.

---

## 7. Shim dies at startup on containerd 2.x: `Protobuf(WireError(IncorrectTag(46)))`

**Symptom:** On k3s v1.36 (containerd 2.3), every k7 pod fails at sandbox creation. containerd logs show the shim's `start` command exiting with `Protobuf(Error(WireError(IncorrectTag(46))))` before our code ever runs. The same shim binary worked on k3s v1.32 (containerd 1.7).

**Root cause:** containerd 2.x writes a *bootstrap protobuf* (not `Any`-wrapped) to the shim `start` command's **stdin**. The `containerd-shim` Rust crate (0.10 and 0.11 alike) later re-reads stdin inside `spawn()` and tries to parse it as an `Any`-wrapped runc `Options` message to extract a `ShimCgroup`. Tag byte 46 is ASCII `.` — it was parsing a path string as a protobuf tag. Diagnosed by temporarily replacing `/usr/local/bin/containerd-shim-k7-v1` with a shell wrapper that dumped argv, env, and stdin to a file.

**Fix:** Drain stdin to EOF at the top of `start_shim()` before calling `shim::asynchronous::spawn()` — the crate's parse sees an empty stream and skips cgroup placement (which we don't use). No dependency bump needed; we stayed on `containerd-shim` 0.10 and Rust 1.85 (0.11 drags in zbus 5 → Rust 1.87 → a clippy-lint cascade, for zero functional gain).

**Reference:** `containerd-shim` crate source (`asynchronous/mod.rs` stdin read path); containerd 2.x `cmd/containerd-shim-runc-v2` bootstrap protocol.

**Time lost:** ~5 hours. The error surfaces from inside the library before any of our logging, and the ASCII-as-tag detail ("what is tag 46?") is the key clue.

---

## 8. One k7 pod start breaks *every* ClusterIP on the node

**Symptom:** `test_cni` Flow 4 (VM → Service IP `10.43.0.10:53`) times out, while VM → CoreDNS *pod IP* works, VM → host gateway works, VM → internet works. Weirder: after any k7 pod has run, even a plain **runc** busybox pod can no longer reach any Service IP.

**Root cause:** `ClusterNetwork::create()` wrote `0` to `/proc/sys/net/bridge/bridge-nf-call-iptables`, assuming it was scoped to our bridge. It is **global to the root network namespace** — it disables iptables processing for bridged frames on *all* bridges, including flannel's `cni0`. kube-proxy's ClusterIP DNAT happens on the routed path, but a same-node backend's *reply* crosses `cni0` as a pure L2 frame; with bridge-nf off it skips conntrack un-DNAT, so the client receives a reply from the pod IP instead of the Service IP and drops it. Classic Kubernetes same-node-hairpin failure — self-inflicted.

**Fix:** Write `1` instead. The original motivation ("k8s FORWARD DROP policy blocks bridge traffic") is already handled by the explicit `-I FORWARD/-I INPUT/-I OUTPUT ... -j ACCEPT` rules for the k7 bridge. The `bridge-nf-call-iptables=0` *inside the pod netns* (`netns.rs`) is unchanged — that one really is scoped, because sysctls under `net.bridge` are per-netns.

**Reference:** kubernetes/kubernetes docs on `bridge-nf-call-iptables` prerequisite; confirmed empirically by toggling the sysctl and watching a runc probe pod flip between SVC_OK/SVC_FAIL.

**Time lost:** ~4 hours, spread over two debugging sessions — the first session wrongly wrote it off as a fresh-node k3s/flannel environment quirk because the failure also reproduced with runc pods (which *looked* like "not our code" but was actually the smoking gun: our sysctl write had already poisoned the node).

---

## 9. Shared cluster bridge: per-pod shims collide and race on teardown

**Symptom:** Two k7 pods in the same cluster both got `vm_index` 0 (duplicate guest IP `10.200.0.2` and MAC — an L2 identity collision). Separately, deleting the *first* pod destroyed the shared `k7-br-*` bridge under the surviving pod's VM.

**Root cause:** The bridge and `vm_index` allocator lived in per-shim process memory (`ClusterNetwork` in `SandboxState`). Every shim process independently "created" the bridge (idempotent), started counting indices from 0, and dropped the bridge on its own sandbox Delete. No cross-process coordination existed.

**Fix:** This was a main driver for the daemon architecture. The k7d daemon holds one refcounted `BridgeEntry` per `cluster_id`: first `create_vm` creates the bridge, later VMs join and get unique indices, `stop_vm` frees the index (`ClusterNetwork::remove_entry`) and destroys the bridge only when the refcount hits zero.

**Reference:** None — architectural. The lesson: any resource shared across pods (bridges, warm pools, snapshot trees) cannot be owned by a per-pod process.

---

## 10. Test infra papercuts that masked real results (node re-setup)

Three small ones, recorded because each burned real time:

- **Stale daemon binary:** `ensure_k7d_daemon_running()` skipped `cargo build` when `target/release/k7d` merely *existed*, so a source fix was "tested" against the previous binary and looked like it didn't work. Fix: always run `cargo build` (a no-op takes ~1s when fresh) and install via copy-to-temp + rename (avoids ETXTBSY on the running daemon).
- **Hostname case:** k3s lowercases node names, but the bare-metal rescue image's hostname was mixed-case (`Ubuntu-resolute-...zst`). Tests pinning pods via `kubernetes.io/hostname: $(hostname)` scheduled nowhere and sat in `Pending`. Fix: lowercase in `common::current_hostname()`; never hardcode node names (`k7-node-01`) in test YAML.
- **cargo-deny vs CVSS 4.0:** RustSec advisories started shipping CVSS 4.0 vectors, which cargo-deny 0.18 fails to parse — `cargo deny check` errors out before checking anything. Fix: pin cargo-deny ≥ 0.20.2 in node setup.
- **Stale shim binary (encore):** the same skip-build-if-exists bug bit `ensure_shim_installed()` during increment 4 — the crash-recovery hooks were "tested" against the increment-3 shim and looked like dead code. Fix: always `cargo build` (a fresh no-op takes ~1s), same as the daemon helper.

---

## 11. Killing a shim does NOT make containerd respawn it

**Symptom:** The crash-recovery plan assumed `pkill -9` of a pod's shim → containerd respawns the shim → new shim calls `Connect` and reattaches to the running VM. Empirically: no shim respawn ever happened. Instead kubelet reported the sandbox dead, tore it down, and recreated the pod under a **new** sandbox id, while the original VM stayed orphaned in the k7d daemon.

**Root cause:** The shim-v2 contract on containerd 2.x (k3s): when a shim's ttrpc socket dies, containerd does not restart the process. It invokes the shim *binary* with the `delete` subcommand against the dead bundle (cleanup hook), and kubelet's PLEG marks the sandbox NotReady → `RunPodSandbox` with a fresh id. `Connect`-reattach is only exercised when **containerd itself** restarts (the shim survives and containerd re-dials).

**Fix:** Implement both surfaces. (a) Orphan reaping: shim `delete` subcommand (`delete_shim`) and the foreign-id `Delete`/`Shutdown` Task paths call `lookup_sandbox` on the daemon, `stop_vm` the orphan, lazily unmount + remove the dead shim's state dir. (b) Keep `Connect` reattach (`reattach_sandbox` + agent ping) for the containerd-restart case. The kubectl test asserts pod recovery under a new sandbox id and that the old VM/record is reaped — not shim resurrection.

**Reference:** containerd shim-v2 lifecycle (`cmd/containerd-shim-runc-v2` delete flow); kata-containers handles cleanup in the same subcommand.

**Time lost:** ~3 hours, including a controlled kill experiment with `crictl`/`journalctl` to establish the real lifecycle before rewriting the test's expectations.

---

## 12. One virtiofsd socket path per *process* breaks the second VM

**Symptom:** After a shim kill, kubelet's replacement sandboxes failed forever: `virtiofsd socket did not appear within 15s`, virtiofsd logging "Resource temporarily unavailable". The retry storm (new sandbox every few seconds, each leaking a virtiofsd) drove node load past 4 and nearly wedged SSH.

**Root cause:** The virtiofsd socket dir was `/tmp/k7d-virtiofs-{pid}` — keyed on process id only. In the shim-per-pod era every pod had its own pid, so it was accidentally unique. With the single k7d daemon spawning *all* VMs, the second VM's virtiofsd bound the same socket path as the first (still-running) one. Masked as a crash-recovery bug because it only surfaced when a second VM started while the first was orphaned.

**Fix:** Per-VM unique dir via an atomic counter: `k7d-virtiofs-{pid}-{seq}` (`vm.rs`), and `VirtiofsdProcess::drop` removes the socket's parent dir. Lesson: any "per-process" resource naming from the per-pod-shim era is a latent collision in the daemon era — audit for others (same class as challenge 9).

**Time lost:** ~2 hours, mostly spent suspecting the new reattach logic instead of the socket path.

---

## 13. Dashboard `K7_NODE_IP` secret points at a foreign node

**Symptom:** Every `ssh` / `make remote-*` from a Cloud agent failed with `Permission denied (publickey)` even though `K7_SSH_KEY` reconstructed to a valid ED25519 key (`ssh-keygen -y` succeeded) and the key was offered (`ssh -v`: "Offering public key ... explicit").

**Root cause:** The CI remote dashboard's `K7_NODE_IP` env var was set to a node from the `K7_NODE_IPS` fleet list where our key is **not** authorized — not the pinned primary `<node-ip>`. `utils/ssh-setup.sh` honors the env var over its own default, so everything silently targeted the wrong machine. <!-- pragma: allowlist secret -->

**Fix:** `export K7_NODE_IP=<node-ip>` explicitly in the session before any `make remote-*` target (kickoff specs now say so). Diagnosis shortcut for next time: valid key + key offered + still denied ⇒ suspect the *host*, not the key. <!-- pragma: allowlist secret -->

**Time lost:** ~15 minutes.

---

## 14. Pooled `create_vm` round trip is ~50 ms — the control socket's accept poll, not the pool

**Symptom:** `test_pool_fills_and_acquire_is_fast` measured ~50 ms for a pooled `create_vm` where the daemon-side work (pop idle VM + registry insert + sandbox-record write) is ~1 ms. Uncomfortably close to the 100 ms `POOL_ACQUIRE` ceiling for no obvious reason.

**Root cause:** `control::serve` uses a non-blocking listener polled every **50 ms** (so the signal handler can break the loop). Each test opens a *fresh* connection per request, and the connect waits out the tail of the current sleep before `accept` runs. Long-lived clients (the shim keeps its connection) never see this; per-call-connection clients pay up to 50 ms once per connection.

**Fix:** None needed for the budget (50 ms accept + ~1 ms work < 100 ms). Documented in `LATENCY_BUDGETS.md`. If a future increment needs snappier per-connection latency, replace the sleep-poll with a blocking `accept` on a listener + self-pipe/eventfd for shutdown wakeup.

**Time lost:** ~30 minutes (rerunning with `--nocapture` on the node to see where the time went).

---

## 15. Aeneas "Could not match the contexts" on borrows held across branches

**Symptom:** After the `HashMap → Vec<NodeInfo>` rewrite of `tree_model.rs`, `cargo build` and `cargo test` were green but `make remote-verif` failed in Aeneas's symbolic-execution phase with `Could not match the contexts` for `usage`, `lru_live_victim`, and `lru_evictable_leaf_subtree` — functions whose loops read several fields off `&t.nodes[i]` inside `if` branches and short-circuit `&&` chains.

**Root cause:** Aeneas's borrow-tracking symbolic execution must *join* the environments of the two arms at every branch point. A shared borrow like `let n = &t.nodes[i]` that is still live across the arms (or a `&&`-chain where each conjunct re-borrows `prot`/`exempt`) produces arm environments the join cannot reconcile, and translation aborts — even though rustc's borrow checker is perfectly happy.

**Fix:** In the loop bodies, eagerly copy the scalar fields to locals *before* any branching (`let id = t.nodes[i].id; let state = t.nodes[i].state; …`) and evaluate the eligibility conjuncts into `bool` locals before the single `if a && !b && !c`. Purely mechanical, no semantic change; the Lean mirrors mirror the rewritten form. Rule of thumb for future `tree_model.rs` edits: no reference may live across an `if`/`match` arm boundary, and no `&&`/`||` operand may call a borrowing helper.

**Reference:** Aeneas (AeneasVerif/aeneas) — known limitation of the join on region abstractions.

**Time lost:** ~1.5 hours (three translate–rewrite–retranslate cycles).

---

## 16. `install-aeneas.sh` bit-rot: aeneas `main` grew an OCaml dep and moved to a newer Lean

**Symptom:** The pinned node had been reset, so the Aeneas toolchain had to be reinstalled. `make remote-install-verif` failed mid-build with `Error: Library "ppx_deriving_yojson" not found`. After fixing that and regenerating, `lake build` then died inside the *proofwidgets* dependency with `Unknown constant 'Lake.Hash.ofHashable'`.

**Root cause:** Two facets of the same drift: `verif/lakefile.toml` pins `aeneas` at `rev = "main"`, so every fresh install tracks upstream HEAD. (a) Upstream added a `ppx_deriving_yojson` dependency that our opam install list in `utils/install-aeneas.sh` predates. (b) Upstream bumped `backends/lean/lean-toolchain` from `v4.28.0-rc1` to `v4.31.0`; the node's checkout was regenerated against 4.31.0, but the repo's committed `verif/lean-toolchain` still said 4.28.0-rc1 — the next `make rsync` overwrote the node's toolchain file and made Lake elaborate 4.31-built package lakefiles with a 4.28 toolchain.

**Fix:** Added `ppx_deriving_yojson` to the opam install list in `utils/install-aeneas.sh` and bumped `verif/lean-toolchain` to `leanprover/lean4:v4.31.0` in the repo (the lakefile comment already documents that the two must move together). Longer-term: pin `rev` in `verif/lakefile.toml` to a specific aeneas commit instead of `main` next time drift bites.

**Reference:** AeneasVerif/aeneas `backends/lean/lean-toolchain` history.

**Time lost:** ~2 hours wall-clock (most of it the ~40 min OCaml/opam rebuild after each fix, plus diagnosing the proofwidgets error back to the toolchain overwrite).

---

## 17. `rsync --delete` silently deletes node-side generated files that are gitignored locally

**Symptom:** Directly after a successful baseline `lake build` on the node, running `make rsync` from the sandbox broke the next build in confusing ways (see challenge 16's proofwidgets error; `verif/lake-manifest.json` would also have been re-resolved against upstream `main`).

**Root cause:** `make rsync` uses `--delete` and doesn't read `.gitignore`. Files that exist only on the node (regenerated `verif/lean-toolchain` state, `verif/lake-manifest.json`) or exist locally with stale content get clobbered by whatever the sandbox has. `verif/.lake/` was already excluded, but the manifest and toolchain files sit outside it.

**Fix:** Copied the node's `lake-manifest.json` into the local tree before rsyncing (kept gitignored), and committed the correct `lean-toolchain`. When touching the verif toolchain, treat `verif/lean-toolchain` + `verif/lakefile.toml` `rev` + the node's `~/aeneas` checkout as one unit that must be updated together.

**Reference:** none.

**Time lost:** ~30 minutes.

---

## 18. Foreground `runc exec` without `-t` gives the container pipes, not our PTY

**Symptom:** The agent allocated a PTY pair, spawned `runc exec` with the slave as stdio (plus `setsid` + `TIOCSCTTY` in `pre_exec`), and the guest-side shell still saw `stty: standard input: Inappropriate ioctl for device` — stdin inside the container was a pipe.

**Root cause:** Foreground non-terminal `runc exec` inserts *pipes* between the runc process and the container process; the fds we so carefully made a controlling terminal only reach runc itself. The exec'd process's stdio is created inside the container by runc.

**Fix:** `runc exec -t`: runc allocates the container-side PTY from the container's own devpts, makes it the controlling terminal, proxies it to runc's stdio (our slave), performs the initial resize from our slave's winsize, and forwards SIGWINCH — a double-PTY chain that behaves exactly like ssh-in-ssh. Two follow-on requirements: the container's OCI bundle needs a `devpts` mount at `/dev/pts` (runc creates the `/dev/ptmx → pts/ptmx` symlink itself when it owns `/dev` as tmpfs; the CRI's generated config always has devpts, but hand-rolled test bundles did not), and the guest kernel/init need devpts (`CONFIG_UNIX98_PTYS=y`, `mount -t devpts` in `init.sh`).

**Reference:** runc `libcontainer/console_linux.go`, `tty.go`.

**Time lost:** ~1 hour (two VM-boot test cycles + a host-side Python repro harness that isolated runc behaviour from the VM stack).

---

## 19. containerd's CRI never tells the runtime that a *tty* exec client detached

**Symptom:** `kubectl exec -it pod -- sh -c 'exec sleep 31337'`, SIGKILL the kubectl client → the exec process lives forever inside the guest. The shim's two detach detectors — stdin-FIFO EOF and the `CloseIO` ttrpc — never fired. Protocol-level detach (vsock `eof`) worked fine.

**Root cause:** Two independent containerd behaviours, verified on a live k3s node: (a) the CRI plugin holds the exec stdin FIFO open **read-write** itself (`lsof` shows `109u` + `111w` fds on it), so our read side never sees EOF no matter who disconnects; (b) in `internal/cri/io/exec_io.go` the stdin-copy goroutine only calls `CloseStdin()` (→ `CloseIO` ttrpc) when `stdinOnce && !tty` — for terminal execs it just logs `Container exec "…" stdin closed` and drops the streams. Detach for tty execs is by-design invisible to the runtime (this is the upstream "kubectl exec processes leak" behaviour).

**Fix:** The one observable signal: at detach the CRI closes its *read* end of the stdout FIFO (its log even shows `Failed to pipe "stdout" … file already closed`). After that, the shim's write end polls `POLLERR` (no readers left). Added a detach watchdog thread to the shim's PTY bridge: `poll(stdout_fd, events=0, 500ms)` → on `POLLERR`, send `eof` to the agent, which SIGHUPs the PTY's foreground process group (SIGKILL fallback after 2 s). Also treat `EPIPE` on a stdout write the same way.

**Reference:** containerd `internal/cri/io/exec_io.go`; kubernetes/kubernetes#25355-family issues.

**Time lost:** ~2 hours (log-correlating one detach across kubectl → apiserver → kubelet → CRI → shim, plus an `lsof`/FIFO-holder audit to rule out FIFO EOF).

---

## 20. Initial PTY window size races the first command through the double-PTY chain

**Symptom:** Protocol test sent `stty size` immediately after the PTY handshake and got `0 0`-flavoured failure output (busybox dies with errno-less `stty: standard input` when `TIOCGWINSZ` returns rows=0), even though the same session resized correctly moments later. A host-side runc repro with a 1 s warm-up worked every time.

**Root cause:** `runc exec -t` copies the winsize from its stdio onto the container-side PTY *once*, right after its console proxy comes up (`tty.resize()` in the signal-forwarding loop). A command typed at handshake time is buffered by the line discipline and can execute before that initial resize lands. No winsize *update* is ever lost — SIGWINCH after console setup and pre-console winch values are both absorbed by the initial copy — only an early one-shot *query* can observe 0×0. Real terminal clients redraw on SIGWINCH, so users never see this.

**Fix:** Made the tests poll (`pty_expect` re-sends `stty size` until the expected `R C` appears) instead of send-once. No product change — the race window is inherent to runc's console lifecycle and harmless in practice.

**Time lost:** ~45 minutes.

---

## 21. `test_cni` "regression" that was actually node contamination — and a `LeakGuard` that kills live VMs

**Symptom:** During final `make remote-check`, `test_cni` failed Flow 2 (host → pod-IP curl timeout) — reproducibly, in isolation, *and on unmodified `main`*. The pod showed `RESTARTS 1` with kubelet `SandboxChanged` events; host ARP for the pod IP sat in `FAILED`; attaching tcpdump to `cni0` (promiscuous mode) made the very same curl succeed.

**Root cause(s):** Layered node contamination, not code: ~700 leaked mounts under `/var/lib/k7d/pods` (149 stale pod dirs), 16 orphaned kubelet pod dirs with EBUSY `etc-hosts` bind-mount sources, and a leftover `test-cni-nginx` pod crash-looping from the previous failed run — kubelet kept recreating its sandbox while the new test ran, and `common::cleanup_k7_runtime_leaks()`'s `systemctl try-restart k7d` at test start/end drops *every* VM the daemon owns, including the sandbox of any still-running pod (that's where the `SandboxChanged` + exit-255 noise came from). After a full cleanup (unmount + rm stale k7d pod dirs, delete leftover pods, restart k3s), the plain create/curl loop passed 8/8 and the whole suite went green on both `main` and the branch.

**Fix:** Manual node hygiene this time. Two standing lessons: (a) when a kubectl-suite failure looks like a networking regression, check `mount | grep -c k7d` and `kubectl get pods` for crash-looping leftovers *before* debugging code; (b) `cleanup_k7_runtime_leaks`'s daemon restart is safe only when no k7 pod is supposed to survive the test file — leftover pods from a *previous* aborted run violate that assumption and poison the next one.

**Reference:** none.

**Time lost:** ~3 hours (the ARP/promisc red herring ate most of it).

---

## 22. Sharing one cargo `target/` between two worktrees bakes the wrong `CARGO_MANIFEST_DIR` into installed binaries

**Symptom:** After comparing the branch against a `main` checkout on the node (`/root/k7d-main` with `target` symlinked to `/root/k7d/target` to reuse the build cache), the next `make remote-check` first failed to *compile* (shim resolving `k7d::api` against `/root/k7d-main/crates/k7d/src/api.rs`), then — after a package-level `cargo clean` — every k7 pod failed with `k7d create_vm: … failed to open kernel file`. The freshness check in `ensure_k7d_daemon_running` (size + mtime) considered the installed daemon current, so it never reinstalled.

**Root cause:** The `main` build wrote its artifacts into the shared `target/`, so `/root/k7d/target/release/k7d` silently *became* a main-code binary with `default_guest_paths()`' compile-time `CARGO_MANIFEST_DIR` pointing at `/root/k7d-main/guest/…` — a directory I deleted right afterwards. Package-level `cargo clean -p` didn't purge enough metadata to force a coherent rebuild.

**Fix:** `rm -rf target/release`, rebuild from `/root/k7d`, force-reinstall both binaries (unlink + copy), restart k7d and k3s. Standing rule: never share a target dir across checkouts on the node — a full from-scratch build costs ~2 minutes and the "savings" cost an hour of unwinding.

**Reference:** none.

**Time lost:** ~1 hour.

---

## 23. Every pod teardown was a silent containerd deadlock — the shim never closed its stdio FIFOs on task exit

**Symptom:** `test_pod_cpu_limit_caps_host_usage` failed only its final assertion: the per-VM CPU cgroup was not removed within 15 s of `kubectl delete pod`. Manual probing made it worse: a capped pod hung in `Terminating` for 15+ minutes, kubelet logged `StopContainer … DeadlineExceeded`, and — the key control experiment — an *uncapped* pod hung exactly the same way, exonerating the new cgroup code.

**Root cause:** A latent contract violation that had been present since the io bridge was written. Containerd's client-side `task.Delete` (invoked by the CRI's `handleContainerExit`) runs `t.io.Wait()` — which blocks until the *shim* closes the write end of the container's stdout/stderr FIFOs ("these should be closed on the shim's side", client/task.go) — *before* it sends the Delete RPC. Our `OutputBridge` held those FIFOs open until… the Delete RPC. Deadlock by construction, on **every single pod stop**. Teardown only ever "worked" through a cascade of failures: `handleContainerExit` wedged at `io.Wait()` → 10 s event-handler ctx expired → a late ttrpc response hit the canceled stream → containerd logged `ttrpc: received message on inactive stream` and hard-closed the shim connection → "cleaning up dead shim" force-cleanup finally ran the shim's `delete` subcommand, which stopped the VM. That cascade cost 30 s–15 min per pod depending on which layer timed out first, and the containerd log had been quietly full of `failed to delete shim: close wait error` the whole time. The new 15 s cgroup-teardown assertion was simply the first test strict enough to notice. A second latent bug found en route: the agent vsock socket is blocking with no `SO_RCVTIMEO`, so the "30 s" deadline in `read_response_line` could never fire once a `read()` had started.

**Fix:** Drop the container's `OutputBridge` (closing the FIFO write ends) in the shim's `Kill` handler at the moment the exit code is set (all bridges for the sandbox branch); `delete()` keeps its existing removal as a backstop. Set `SO_RCVTIMEO(1 s)` on agent vsock sockets so blocking reads wake periodically and request deadlines actually enforce (PTY sessions already treat `AgentError::Timeout` as a retry). Pod deletion went from a 2-minute-to-15-minute wedge to **2 seconds**, and `test_shim.rs` dropped from ~5 min to 74 s.

**Debugging path worth remembering:** shim stderr surfaces in `/var/lib/rancher/k3s/agent/containerd/containerd.log` (containerd relays it) — that log interleaved with containerd's own messages gave the exact RPC sequence (`Kill(15)` → exit event → `Kill(9)`+`Wait` → silence). `k3s ctr -n k8s.io tasks ls` showing the task `STOPPED` while `crictl ps` said `Running` proved the exit never reached the CRI store. Reading the *exact* containerd version's source (`v2.3.2`, clone + grep beats memory) pinpointed `io.Wait()` before the Delete RPC.

**Reference:** containerd `client/task.go` `Delete()` + `client/task_opts.go` `WithProcessKill`, `internal/cri/server/events.go` `handleContainerExit`.

**Time lost:** ~4 hours.

---

## 24. Aeneas axiomatizes `u64::saturating_mul` and derived `Option::clone` — equivalence proofs hit opaque constants

**Symptom:** The `ram_soft_limit` equivalence proof stalled on `core.num.U64.saturating_mul`, and the `auto_evict_ram` prologue (`self.clone()`) stalled on the `Clone` instance for `Option<u64>` — both were `axiom`s in the generated Lean, so no tactic could reduce them and "never panics" was unprovable.

**Root cause:** Aeneas's Lean stdlib models `saturating_add` but not `saturating_mul`, and the *derived* `Clone` for a struct containing `Option<u64>` goes through `Option::clone`, which the extraction leaves abstract. Anything the generated code touches through an axiom is a hole in an equivalence proof.

**Fix:** Semantics-preserving Rust rewrites, verified by the equivalence theorems themselves: `ram_soft_limit` now uses an explicit overflow guard (`if pct != 0 && bytes > u64::MAX / pct { u64::MAX } else { bytes * pct } / 100`) instead of `saturating_mul`, and `NodeInfo` got a manual field-wise `impl Clone` (copying `Option<u64>` by value) instead of `#[derive(Clone)]`. Standing rule: before writing equivalence proofs, grep the generated file for `axiom` — each hit needs a Rust-side refactor or an honest documented assumption. **Now automated**: `utils/check-verif-axioms.sh` diffs generated axioms against `verif/axiom-allowlist.txt` inside `make verif-gen` / `make remote-verif`.

**Reference:** Aeneas `backends/lean/Aeneas/Std/Scalar` (which ops have models).

**Time lost:** ~1 hour.

---

## 25. `@[simp]` bridges from Aeneas scalar bounds to mirror constants poison `scalar_tac`

**Symptom:** Mid-way through the rebuild-loop proofs, `scalar_tac` started failing on plain goals like `(↑t.nodes).length ≤ Usize.max` that it normally discharges instantly.

**Root cause:** The abstraction layer had `@[simp]` lemmas rewriting `Usize.max`/`U64.max` to the mirror constants `Tree.USIZE_MAX`/`Tree.U64_MAX`. Any `simp` sweep before a `scalar_tac` call rewrote the goal into the mirror vocabulary, and `scalar_tac`'s preprocessing no longer recognized the scalar-bound facts it needed.

**Fix:** Dropped `@[simp]` from the bridge lemmas (`u64_max_eq`, `usize_max_eq`, `core_u64_max_val`) and applied them by explicit `rw` only at the endgame of each proof, keeping the generated vocabulary intact wherever `scalar_tac`/`omega` still has work to do.

**Reference:** none.

**Time lost:** ~45 minutes.

---

## 26. `split`/`simp` choke on Aeneas match-in-do goals once the postcondition is rewritten — `show` with the reduced block is the reliable escape

**Symptom:** In the LRU loop proofs (`lru_live_victim_loop`, `lru_evictable_leaf_subtree_loop`, `auto_evict_ram_loop`), `split` failed on the generated `match best with | none => … | some (la, id) => …` accumulator step with "target expression is not type-correct under the `instances` transparency level", and `simp` refused to make progress on the surrounding `do` block.

**Root cause:** The postcondition in `⦃ r => P r ⦄` goals is a `Post`-typed coercion. Rewriting *inside* it early (e.g. `rw [hdrop]`/`rw [hstep]` to unfold the mirror's list step) produced a motive that Lean's `split` could no longer typecheck against the still-unreduced generated `match`; the failure surfaces far from the rewrite that caused it.

**Fix:** Two-part pattern used throughout `Equiv/Lru.lean` and `Equiv/Evict.lean`: (a) keep the postcondition untouched until each branch's endgame — do all `hdrop`/`hstep` rewrites last; (b) where the generated code pattern-matches the accumulator, `rcases` on it *in the proof* and use `show (do …) ⦃ r => … ⦄` to restate the goal with the match already reduced to that branch's `do` block, which typechecks by `whnf` and lets `bind_tc_ok`/`step` proceed. Mechanical once known, invisible from error messages until then.

**Reference:** Aeneas `backends/lean` test suite (`progress`-tactic loop proofs) for the general loop-proof shape; the `show`-reduction trick is not in the test suite.

**Time lost:** ~2.5 hours (spread across the three loop families).

---

## 27. TapNetBackend restart at virtqueue idx 0 hangs eth0 after prepare/warm-fork

**Symptom:** After `prepare_fork_source` on a VM that had already driven eth0 traffic, vsock agent reconnect succeeded but the next guest command that used eth0 (ping/nc) hung forever. internal notes

**Root cause:** The userspace `TapNetBackend` worker keeps `last_avail` / `last_used` in host memory, starting at 0 on cold activate. Restore/warm-fork reattach a new backend while guest rings already have non-zero `used.idx`. Restarting at 0 re-processes already-serviced descriptors and writes stale used-ring entries; the guest networking softirq backs off and stops making progress. Vsock avoids the same bug via `VHOST_SET_VRING_BASE` kernel-side.

**Fix:** `TapNetBackend::seed_indices_from_guest` reads guest `used.idx` for RX/TX and seeds both `last_avail` and `last_used` before the worker starts. Called from `restore_vm_inner` and `build_vm_from_state_and_mem_inner`. Covered by `test_cluster_fork_warm_source_tcp_undisturbed` and `test_cluster_fork_warm_fork_tcp_works`. Also added `nc`/`mkfifo` busybox symlinks to the guest initramfs.

**Reference:** Firecracker userspace virtio-net / vhost `VHOST_SET_VRING_BASE`; `editor-config/rules/rust-src.mdc` "userspace virtio worker counters".

**Time lost:** ~2 hours (prior 9d deferral) + implementation.

---

## 28. Busybox `nc -l </dev/null` tears down held TCP immediately

**Symptom:** Held eth0 TCP looked dead before `fork_cluster_warm` — `/proc/net/tcp` empty, client `nc` gone — even though `before-fork` bytes had already landed in the server's file.

**Root cause:** Listen scripts launched `nc -l` with stdin redirected from `/dev/null`. Busybox nc treats stdin EOF as "close the connection", so the session died right after the first payload. One-shot `echo | nc` tests still passed.

**Fix:** Hold stdin open with `sleep 3600 | nc -l -p PORT >> file` for long-lived listeners.

**Reference:** none (busybox nc stdin semantics).

**Time lost:** ~1 hour.

---

## 29. TapNetBackend workers keep running during Vm::pause and kill source TCP across warm fork

**Symptom:** After `fork_cluster_warm`, a held eth0 TCP session on the *source* cluster was gone (`/proc/net/tcp` empty, busybox `nc` exited) even though ping/new TCP worked after `prepare_fork_source` (seed fix alone).

**Root cause:** `Vm::pause` stopped only the vCPU thread. Userspace `TapNetBackend` workers kept polling TAP and mutating guest virtqueues while both cluster members' vCPUs were frozen for dirty-page capture. That desynchronized the guest TCP stacks from the rings; on resume the held sockets aborted.

**Fix:** `VirtioBackend::set_paused` + `TapNetBackend` pause flag; `Vm::pause` freezes workers before joining the vCPU, `Vm::resume` restarts the vCPU then clears the flag. Workers skip TAP/ring processing while paused (frames stay in the kernel TAP buffer).

**Reference:** none (k7d-specific userspace virtio pause gap).

**Time lost:** ~1.5 hours.

---

## 30. Lean elaboration recurses once per numeral unit on `Array U8 4096#usize` — `maxRecDepth` blowup far from the actual proof

**Symptom:** Group E equivalence work stalled with `maximum recursion depth has been reached` — not in a tactic, but while *elaborating* statements mentioning `Array Std.U8 4096#usize`/`4100#usize` (a bare `example … := by sorry` already failed), and again later when `spec_imp_exists` was applied to those theorems in `Transfer.lean`. The generated `K7d.lean`'s own `set_option maxRecDepth 2048` was not inherited (set_option is file-scoped) and raising to 4096 merely moved the failure.

**Root cause:** Somewhere in unification/defeq checking of the fixed-size-array type index, Lean recurses once per numeral unit of the size literal. Small arrays (`28#usize`) fit inside the default 512; page-sized ones need depth proportional to 4096+.

**Fix:** `set_option maxRecDepth 1000000` at the top of `Verif/Equiv/K7dl.lean` and `Verif/Equiv/Transfer.lean`. Cost is nil in practice (build times unchanged); the option only bounds recursion, it doesn't allocate.

**Reference:** none.

**Time lost:** ~1 hour (the failure points at the theorem statement, not the numeral).

---

## 31. `simp` loops on `BitVec.toLEBytes`' own recursion; unfold byte lists element-wise instead

**Symptom:** Bridging Aeneas's `to_le_bytes` model (`BitVec.toLEBytes`) to the mirror's `extractLsb'` byte lists via `simp [BitVec.toLEBytes]` hit `maximum recursion depth` — the definition unfolds by peeling one byte and recursing on the shifted value, and `simp` re-fires on the recursive call forever.

**Root cause:** `toLEBytes` is structurally recursive on the *width*, and its equation lemma's RHS contains another `toLEBytes` application that matches the same simp rule.

**Fix:** Never unfold it. Prove `toLEBytes_getElem! : n.toLEBytes[i]! = n.extractLsb' (8*i) 8` once via `BitVec.getElem!_toLEBytes` (bit-level, no recursion), then convert fixed-length lists with `list_eq_four`/`list_eq_eight` (a length-`k` list is the literal list of its `k` elements) and rewrite element-wise. Same trick closed `u32ToLe`, `u64ToLe`, and both `fromLEBytes` bridges (those needed `norm_num` to concretize `8 * (l.length)` widths before `bv_decide` would accept the goal).

**Reference:** Aeneas `backends/lean/Aeneas/Std` BitVec byte lemmas.

**Time lost:** ~1.5 hours.

---

## 32. `rw` cannot rewrite across `BitVec ty.numBits` vs `BitVec 32` type indices — chain `Eq.trans`/`congrArg` term proofs instead

**Symptom:** In `k7dl_parse_header_equiv`'s version check, every attempt to `rw` the hypothesis `version.bv = u32FromLe …` into the `if` condition failed with motive-is-not-type-correct, even though both sides printed identically. The scalar lives at `BitVec ty.numBits` (from the generic `UScalar` structure), the mirror at `BitVec 32` — definitionally equal, syntactically different indices.

**Root cause:** `rw` builds a motive by abstracting the pattern; abstracting a term whose *type* mentions the term being rewritten (dependent type index) produces an ill-typed motive. Standard Lean limitation, but invisible in the pretty-printer.

**Fix:** Skip `rw` for those steps and discharge the `if` conditions with defeq-tolerant *term* proofs: `if_neg (fun h => hvne ((uscalar_eq_iff_bv _ _).mpr (hversion.trans (h.trans k7dl_version_bv.symm))))` and `if_pos (hversion.symm.trans ((congrArg UScalar.bv hveq).trans k7dl_version_bv))`. `Eq.trans` type-checks up to defeq, so the mismatched indices unify where `rw`'s motive could not.

**Reference:** none.

**Time lost:** ~45 minutes.

---

## 33. Inc 1's `ctr version` check was a false positive — no `set -e` and a "Client:"-satisfied assertion

**Symptom:** `test_sidecar_containerd_socket_via_emptydir` was green while manual reproductions of the exact same pod showed the sidecar containerd crash-looping at startup. The "pass" looked nondeterministic until the assertion was read closely.

**Root cause:** The main container's script had no `set -e`; `ctr --address /cri/containerd.sock version` prints its `Client:` section *before* attempting to connect, so on connect failure the partial output still landed in `/cri/ctr-version.txt`, the script continued and wrote `CTR_OK`, and the test's assertion accepted `Client:` as one of four alternatives. containerd had in fact never served a request (see #34, #35).

**Fix:** `set -e` in the entrypoint and the assertion now requires the `Server:` section, which only prints after a successful round-trip over the socket.

**Reference:** none (test-harness bug).

**Time lost:** ~2 hours chasing "nondeterministic" containerd startup that was in fact deterministic.

---

## 34. bolt/sqlite-WAL cannot live on virtiofs with `--cache never` — mmap(MAP_SHARED) fails with ENODEV

**Symptom:** The sidecar containerd died at plugin init with `failed to create new snapshotter: failed to restore remote snapshot: failed to open database file: no such device` when its `--root` was on the container rootfs (virtiofs).

**Root cause:** k7d spawns virtiofsd with `--cache never`, which sets `FOPEN_DIRECT_IO` on every file; the guest FUSE layer then rejects shared writable mmap with ENODEV. containerd's bolt databases (stargz metadata first, `meta.db` next) and kine's sqlite in WAL mode (mmaps the `-shm` file) all require shared mmap, so no containerd/k3s state can live on any virtiofs mount — rootfs and emptyDirs alike.

**Fix:** The inner-k3s test mounts in-guest tmpfs over `/var/lib/containerd`, `/run/containerd`, `/var/lib/rancher` and `/var/lib/kubelet` before starting containerd / `k3s server`. The `/cri` emptyDir stays on virtiofs (unix sockets and plain files are fine).

**Reference:** virtiofsd `--cache never` semantics (FUSE direct-io forbids shared mmap).

**Time lost:** ~1.5 hours (compounded by #33 masking it).

---

## 35. virtiofsd `--announce-submounts` (default since 1.13) gives each container its own superblock for the same emptyDir — cross-container unix sockets ECONNREFUSED

**Symptom:** With containerd serving on `/cri/containerd.sock`, `ctr`/k3s in the *other* container of the same pod got `connect: connection refused` forever, while the same command inside the sidecar container worked. Files written to the emptyDir were visible both ways; `ls -i` showed identical inode numbers.

**Root cause:** internal notes's volume plumbing bind-mounts every kubelet volume into the per-pod `volumes-rw` scratch tree, so each volume is a host *mount point* inside the virtiofsd share. virtiofsd ≥ 1.13 defaults to `--announce-submounts`, making the guest kernel expose each of those as a FUSE submount that is automounted lazily — and each container's runc traversal instantiated its *own* submount superblock (`/proc/self/mountinfo` showed `virtiofs none` device 0:29 in one container, 0:38 in the other). Unix-socket `connect()` resolves to the in-kernel inode object, which differs across superblocks, so the listener is never found. Regular file I/O goes through virtiofsd and works, which is why internal notes's file-sharing tests never caught it.

**Fix:** Pass `--no-announce-submounts` in `VirtiofsdProcess::spawn_with_options`. The whole share is then one superblock and every container binds subdirs of it (`mountinfo` now shows `virtiofs k7fs2 /emptydir-cri`), restoring kubelet-like emptyDir semantics for sockets.

**Reference:** virtiofsd 1.13 changelog (announce-submounts default flip); FUSE submount automount semantics.

**Time lost:** ~2 hours.

---

## 36. Stripping `linux.resources` from the guest OCI spec re-enables runc's default device filter — kubelet dies on `/dev/kmsg`

**Symptom:** kubelet inside the k3s container failed with `open /dev/kmsg: operation not permitted` even though the entrypoint had successfully `mknod`ed the node and the container is privileged in the pod spec.

**Root cause:** The shim's `fix_and_write_oci_config` removes `linux.resources` wholesale. With no `devices` rules at all, runc installs its restrictive default eBPF device-cgroup program, which allows only the standard tty/null/zero/random set — privileged-ness from the outer pod spec never reaches the guest runc.

**Fix:** After stripping `resources`, the shim now writes back `{"devices":[{"allow":true,"access":"rwm"}]}`. The VM is the security boundary and host devices never enter the guest, so unrestricted in-guest device access matches the runtime's threat model.

**Reference:** runc libcontainer cgroup v2 default device filter.

**Time lost:** ~45 minutes.

---

## 37. kubelet-in-guest kernel/runtime gaps: `lo` down, missing cpuset + keys, 1999 clock

**Symptom:** Serial fatals while bringing up `k3s server` in a k7 pod: containerd's CRI stream server `listen tcp 127.0.0.1:0: cannot assign requested address`; then k3s `failed to find cpuset cgroup (v2)`; then kubelet `open /proc/sys/kernel/keys/root_maxkeys: no such file or directory`. Also every guest log timestamp is 1999-11-30.

**Root cause:** The guest brings up `eth0` but never `lo`, and the minimal kernel config had no `CONFIG_CPUSETS` (cgroup.controllers lacked `cpuset`, which k3s hard-requires on cgroup v2) and no `CONFIG_KEYS` (kubelet writes the keyring sysctls at startup, fail-fatal). The clock is a separate cosmetic issue (no RTC/kvmclock wall-time seed) that is harmless here because all TLS validation happens against the same in-guest clock.

**Fix:** `ip link set lo up` in both container entrypoints (plus tmpfs/cgroup2/kmsg prep, see the test's doc comment); `CONFIG_CPUSETS=y` and `CONFIG_KEYS=y` added to `guest/kernel/config-minimal` and the guest kernel rebuilt. Guest wall-clock seeding is left for a future increment.

**Reference:** k3s `pkg/cgroups` cgroup v2 validation; kubelet `setupKernelTunables`.

**Time lost:** ~1.5 hours across three iteration loops (each needing a kernel or daemon redeploy).

---

## 38. Empty shim `grouping` collapsed every concurrent k7 pod onto one shim process — `SandboxState` silently overwritten

**Symptom:** First multi-pod test (3 outer k7 pods for the inner 3-node cluster): the 2nd and 3rd pods flapped between `Running` and `Completed`, `kubectl exec` into any of them hung until the kubelet timeout, and deleting one pod sometimes tore down a sibling's VM. `crictl` exec directly against containerd worked, single-pod tests (Incs 1–2) never showed any of this.

**Root cause:** `start_shim` called `shim::asynchronous::spawn(opts, "", ...)` with an empty `grouping`. The containerd-shim crate derives the shim socket path from `(namespace, grouping)`, so every k7 pod in `k8s.io` mapped to the *same* socket — containerd routed the 2nd pod's sandbox `Create` at the 1st pod's shim process, whose singleton `SandboxState` (`vm_id`, `guest_cid`, `sandbox_id`) was silently overwritten. Execs then dialed the wrong VM's agent (hang), teardowns stopped sibling VMs, and container status queries answered for the wrong pod (the spurious `Completed`). Every earlier increment only ever ran one kubectl pod at a time, so the collision was invisible.

**Fix:** Group per pod like the upstream runc shim: the grouping key is the sandbox id — `opts.id` for a sandbox bundle, the `io.kubernetes.cri.sandbox-id` annotation for workload containers (routing them to their pod's existing shim). One shim process (and socket) per pod.

**Reference:** containerd `runtime/v2/shim` grouping semantics; the Go runc shim uses the sandbox id as its group label.

**Time lost:** ~2 hours — the hang pointed at kubelet exec proxying and inner-guest networking first; only tracing which shim PID served which pod's ttrpc socket exposed the collision.

---

## 39. After `prepare_fork_source`, every in-guest exec hangs — restore drops virtiofs, and `runc` lives on it

**Symptom:** Post-`TreeAdoptCluster`, any `container_exec` against the adopted VMs' agents never completed — the test's `ContainerWaitExec` poll spun forever. Even a trivial `runc exec test -f …` never spawned a runc process in the guest; a host-level agent `ls /mnt/state/bin` timed out too.

**Root cause:** The restore path (`restore_vm_with_tap` / warm-fork rebuild) **intentionally does not respawn virtiofsd or re-register virtio-fs MMIO devices** (documented in `fork.rs` since pre-10b). After `prepare_fork_source_in` swaps the source for a restored copy, every virtiofs mount in the guest is a dead FUSE session: requests queue forever. The agent's `runc_path()` stats `/mnt/state/bin/runc` (virtiofs) before spawning, so the exec thread blocks before `runc` even starts — and the entire container rootfs is virtiofs-backed anyway. Running processes (k3s, containerd) survive only on their resident page cache. Additionally, anonymous host `curl /readyz` is rejected (401) — probes need the kubeconfig client cert.

**Fix (two-sided):** (a) `prepare_fork_source` no longer swaps virtiofs-backed VMs for a restored copy at all — vhost-user needs fd-backed shared memory that `MAP_PRIVATE` CoW cannot provide, so such sources now just snapshot + enable dirty tracking and keep running (virtiofsd, FUSE sessions, and even the vsock CID stay intact). (b) Forks of virtiofs VMs get a full memfd copy plus fresh virtiofsd sessions (see #41 for the remaining stale-handle limitation). Test-side, probes/assertions run from the host over the bridges: authenticated `curl --interface <bridge>` against `https://10.200.0.2:6443` — `--interface` is load-bearing because source and fork carry the same guest IPs on two bridges; a held `?watch=true` stream provides the single TCP/TLS session that must survive the fork.

**Reference:** `fork.rs` restore comment ("Restore intentionally does NOT re-spawn virtiofsd"); cloud-hypervisor's equivalent restriction on vhost-user device snapshot/restore.

**Time lost:** ~2 hours (agent-side vsock probing to localize the hang to virtiofs).

**Resolved for share-less sources:** the residual trap here — the prepare swap restoring a *block-only* source on a NEW vsock CID while the pod's shim keeps dialing the cached one — is fixed by preserving the CID across the in-place restore: `prepare_fork_source_in` shuts the source down and drops its device registry **first** (closing the vhost-vsock fd releases the CID to the kernel; claiming it while the old fd is open would `EADDRINUSE`), then restores via `restore_vm_preserving_cid`. Agent connections still die (fresh vsock backend) but the shim dials the CID fresh per exec, so kubectl exec/logs against adopted cluster members keep working.

---

## 40. Restored VMs get a fresh unprogrammed PIT — no IRQ0 ever again, k3s parks and CLOCK_REALTIME freezes

**Symptom:** After adopt (= prepare/restore), the source inner-k3s guests looked half-alive: ping and agent exec fine, TCP connect to `:6443` accepted, but the API server never answered a TLS ClientHello. k3s and containerd consumed **zero CPU**; `date +%s` was frozen while `/proc/uptime` advanced; `/proc/interrupts` showed IRQ0 (PIT timer) stuck at its pre-restore count while vsock interrupts flowed.

**Root cause:** The guest kernel (`pci=off`, PIC-only, LOC=0) takes its tick from the i8254 PIT, which the guest programs **exactly once at boot**. Restore calls `KVM_CREATE_PIT2` — a fresh, unprogrammed PIT — and never restored the saved channel state, so the restored guest never receives another timer interrupt: every timer-driven wakeup (Go runtimes, sleep, schedulers' tick) parks forever, and kernel timekeeping stops being updated (CLOCK_REALTIME freezes once past the TSC `max_idle_ns` clamp). Interrupt-driven paths (vsock agent, ICMP, TCP handshakes) keep working, which is why every busybox-guest restore test passed for months — busybox guests have no timer-driven workload that a test asserted on.

**Fix:** Snapshot the PIT via `KVM_GET_PIT2` into `IrqChipState.pit` (raw `kvm_pit_state2` bytes, like the PIC blobs) and apply `KVM_SET_PIT2` in `restore_cpu_state` right after the PIC restore — KVM reloads the channel counters and re-arms its in-kernel hrtimer.

**Reference:** QEMU's kvm-pit migration (`KVM_GET_PIT2`/`KVM_SET_PIT2` in its `kvm_pit_get/put`); KVM API docs.

**Time lost:** ~1.5 hours — the freeze was three layers away from the visible symptom (probe start "hang" → exec hang → dead virtiofs (#39) → and *then* the separate zero-CPU/frozen-clock trail to IRQ0).

---

## 41. Warm-forked guests SIGBUS on binaries mmap'd from virtiofs — fresh FUSE session EBADFs stale file handles

**Symptom:** After the first successful warm fork of the inner-k3s cluster (6.4 s, virtiofs rebuilt, network answering), the fork's API server sent RSTs: the fork's `k3s` process had died with a Go runtime fatal dump; `ls /mnt/state/bin` in the fork returned `Bad file descriptor` (an error, not a hang — the fresh virtiofsd was answering).

**Root cause:** The fork's virtio-fs devices get a *fresh* virtiofsd (same host dirs, new FUSE session — see #39). The cloned guest kernel still holds FUSE nodeids and file handles issued by the *old* session; the new daemon EBADFs them. Path lookups recover (`--cache never` re-lookups from the always-valid root nodeid), but **mmap'd executables never re-open their file handle**: the first page fault on a non-resident page of the 250 MB `k3s` binary (mapped from the virtiofs-backed container rootfs) does `FUSE_READ` with the stale handle → `EBADF` → `SIGBUS` → Go runtime fatal. Everything infra-level (memfd full copy, vring-base seeding, IRQ0, TCP) was already working — the guest was killed by its own binary's backing store.

**Fix (fixture-level):** The pod entrypoints copy the long-running binaries to in-guest tmpfs and exec from there (`k3s` in the main container; the sidecar copies `k3s` once + `containerd-shim-runc-v2` and re-creates `containerd` as a symlink — in the k3s image `/bin/containerd` is an argv0-dispatch symlink into the 184 MB multicall `k3s` binary, so a naive `cp` dereferences it and blows the tmpfs; `PATH=/tmpbin:` makes containerd resolve its shim from tmpfs). Inner-pod binaries already run from tmpfs (#34), so this closes the last mmap-from-virtiofs dependency for running processes. Post-fork, *new* file opens work (fresh lookups); only stale handles/mmaps were fatal. The architectural fix — carrying the FUSE session across the fork via virtiofsd's vhost-user device-state migration (`VHOST_USER_SET_DEVICE_STATE_FD`) — is future work.

**Reference:** virtiofsd internal-migration support; FUSE `nodeid`/`fh` session semantics.

**Time lost:** ~1 hour (live agent inspection of the crashed fork; the Go traceback in the captured container stderr was the tell).

---

## 42. Continuous `/readyz` sampling flakes during the warm-fork source pause

**Symptom:** `test_inner_k3s_cluster_warm_fork_no_restart` occasionally failed with `source inner API /readyz failed during fork (1 failures / N samples)` (later: `never succeeded after resume` with `samples=[true, true, true, false]`) even when the held `?watch=true` TLS session survived and both clusters came up Ready.

**Root cause:** The background sampler opens a *new* TLS connection every ~200 ms. During the ~8 s source pause (3× full memfd copy) a handshake that races the freeze can fail. With only one in-flight curl across the pause, that failure was often the sole "post-fork" sample when `stop()` joined — so even a softened "any post-resume success" check still flaked. New-connection success across the pause is a different property from the 9d headline (one held TCP/TLS session must survive).

**Fix:** Drop the continuous sampler. Assert the held watch survives; poll `/readyz` explicitly after resume (plus the existing pre-fork wait and `assert_three_ready_nodes_via`).

**Reference:** `test_cluster_fork_warm_source_tcp_undisturbed` (held session only).

**Time lost:** ~40 minutes (two `make remote-check` flakes + assertion redesign).

---

## 43. In-process virtio-blk DMA is invisible to KVM dirty logging — warm forks would ship stale device-written pages

**Symptom:** (Caught at design time, not debugged live — recorded because the final diff makes it look optional.) A warm fork copies `base.mem` + the KVM dirty bitmap. The new userspace virtio-blk worker writes guest RAM directly through k7d's own mapping (`pread` completions, used-ring entries, status bytes). KVM's dirty log only records **vCPU** writes, so none of those device writes are in the bitmap — a fork taken after block I/O would resurrect pre-I/O bytes on exactly those pages: silent data corruption, the in-process cousin of #39's virtiofsd problem (which forced virtiofs VMs onto the full-memfd path).

**Root cause:** Dirty tracking is per-writer. vhost devices (vsock) have the kernel writing and KVM cannot see it either, but their rings are re-seeded on fork; virtiofsd forced full copies; an in-process device is the first writer we fully control.

**Fix:** Because the worker is in-process we can do what virtiofsd could not: `BlockBackend` keeps a per-device page bitmap (`Arc<Vec<AtomicU64>>`), every guest-memory store marks it (`mark_dirty` covers data buffers, status bytes, used-ring slots + idx), and `Vm::get_and_accumulate_dirty` merges it via the new `VirtioBackend::merge_dirty_pages`. Pause ordering matters too: on `set_paused` the worker first **drains** every pending request (used == avail), then parks; `Vm::pause` blocks on the new `wait_quiescent` before the bitmap is read, so no DMA lands after the merge. Same discipline as the net worker's pause (#29) plus the bitmap.

**Reference:** #27 (ring seeding), #29 (pause-before-fork), #39 (why virtiofs forks are full-copy); `crates/k7d/src/block.rs`.

**Time lost:** none at runtime (design-time catch); `test_block_device_warm_fork_ro` locks the invariant in.

---

## 44. Kani proof of the parallel-copy chunking OOM'd CBMC — symbolic-capacity `Vec`

**Symptom:** `verify_copy_chunk_ranges_cover_disjoint` (chunk work list for the multi-threaded memfd copy) failed `make remote-kani` with `CBMC appears to have run out of memory` during propositional reduction — no counterexample, 2306 VCCs after simplification.

**Root cause:** The helper returned `Vec<(u64, u64)>` built with `Vec::with_capacity(max_chunks)` where `max_chunks` was a symbolic `usize` (assumed 1..=8). A heap allocation whose *size* is symbolic forces CBMC to model the allocator paths (`raw_vec` grow/deallocate) for every candidate capacity on top of the 12-iteration unwind — the SAT problem exploded even though the arithmetic itself is trivial.

**Fix:** Refactor to a pure `copy_chunk_size(mem_size, max_chunks) -> u64` and drive the spawn loop directly off `offset`/`len` (no `Vec` at runtime either). The proof walks the same loop with plain `u64` arithmetic and verifies in seconds (33 checks).

**Reference:** none (Kani docs recommend stubbing/avoiding heap in harnesses).

**Time lost:** ~30 minutes (one remote-kani round trip + refactor).

---

## 45. Shared-node measurement invalidated mid-run — another agent's rsync reverted `/root/k7d`

**Symptom:** Right after `make remote-check` showed the parallel cluster fork at ~1.3 s (daemon journal: three interleaved ~1.07 s copies), a standalone rerun of `test_inner_k3s_cluster_warm_fork_no_restart` measured `TreeFork elapsed=7.98s` with strictly sequential ~2.5 s copies and none of the new log lines — as if the change had never landed.

**Root cause:** The bare-metal node is shared. Between my check and the rerun, another agent's `make remote-check` rsynced *its* (older) tree over `/root/k7d`. My rerun's `ensure_k7d_daemon_running` then dutifully rebuilt and reinstalled the daemon **from that reverted source** (`strings /usr/local/bin/k7d` no longer contained the new log strings). The test binary itself was also rebuilt old, which is why the journalctl scrape printed nothing.

**Fix:** Wait for the other run to finish (`ps aux | grep cargo` on the node), `make rsync` again, rerun — 1.31 s end-to-end. When a remote measurement contradicts a change you *know* executed minutes earlier, first verify the node's source/binary provenance (`grep` the source, `strings` the installed binary, `systemctl show -p ExecMainStartTimestamp`) before doubting the change.

**Reference:** none.

**Time lost:** ~45 minutes (stale measurement, binary forensics, waiting out the other run).

---

## 46. FICLONE probe reported `EBADF` on a genuinely reflink-capable XFS — source fd opened write-only

**Symptom:** `test_writable_image_on_loopback_xfs_reflink_fork` failed with `NoReflink { dir: "/var/lib/k7d/disks", probe: "Bad file descriptor (os error 9)" }` — on the freshly provisioned loopback XFS with `reflink=1`, where `cp --reflink=always` works fine. The fail-loud probe was itself the bug.

**Root cause:** `assert_reflink_capable` created the probe *source* file with `File::create` (write-only) and passed its fd as the `FICLONE` source argument. The kernel requires the clone source fd to be open **for reading** and returns `EBADF` otherwise (`ioctl_ficlone(2)`), so the probe failed on every filesystem regardless of reflink support — indistinguishable from "not reflink-capable" in the error string.

**Fix:** Write the probe content, then reopen the source with `File::open` (read-only) before the ioctl — mirroring `fork::reflink_file`, which already did this correctly. Lesson: an `EBADF`/`EINVAL` from `FICLONE` is about fd modes/flags, not filesystem capability; only `EOPNOTSUPP`/`EXDEV` mean "can't reflink here".

**Reference:** `ioctl_ficlone(2)` man page; `fork.rs::reflink_file`.

**Time lost:** ~20 minutes (one full remote-check round trip).

---

## 47. Deferred-VM sandboxes died in a kubelet recreate loop — Connect's reattach gate keyed on `vm_id == None`

**Symptom:** With the block-path shim (VM creation deferred from sandbox `Create` to the first workload `Create` because virtio-blk cannot hotplug), every kubectl pod looped `FailedCreatePodSandBox: failed to get task pid: sandbox <id>: reattach failed: no such sandbox` — hundreds of sandboxes created and killed per minute, pod never got an IP. `test_cni_pod_traffic_flows` timed out. The shim log showed each sandbox `Create` succeeding ("VM deferred to first workload Create") immediately followed by a failing `Connect`.

**Root cause:** The spec-11a shim-restart recovery path in `connect()` treated `state.vm_id.is_none()` as "this shim never saw a Create — rebuild state from the daemon". That invariant broke the moment `Create` stopped calling `CreateVm`: a healthy just-created deferred sandbox also has `vm_id == None`, and the daemon genuinely has no VM for it yet, so the reattach lookup failed and `Connect` answered NotFound. Containerd's task-start needs `Connect` for the shim pid, so the freshly created sandbox was torn down and recreated forever.

**Fix:** Gate the reattach on "this shim has truly never seen this id": also require `pending_vm.is_none()`, `sandbox_id != req.id`, and `!containers.contains_key(&req.id)` before attempting daemon reattach. Lesson: any state-recovery heuristic keyed on "field not yet set" must be revisited whenever the lifecycle that sets the field moves later.

**Reference:** none (own shim, internal notes).

**Time lost:** ~30 minutes (one full remote-check round trip + node log archaeology).

---

## 48. Block-path pods boot fast enough to land inside k3s' post-restart convergence window — host→pod TCP times out while the pod is fine

**Symptom:** `test_cni_pod_traffic_flows` failed Flow 2 (`curl http://<pod_ip>/` → timeout) on every full `make remote-check`, yet passed 5/5 standalone. During the broken window: pod Running with IP, guest agent answering on vsock, nginx listening, `ping` netns→guest fine, `curl http://10.200.0.2/` (guest IP, direct) → 200 — only host→pod-IP TCP dead. The same sandbox served 200 minutes later with zero intervention. Two red herrings burned time: guest `lo` being DOWN (it always is; in-guest loopback tests never worked on this design) and a mystery mid-test k7d restart (that was `LeakGuard::drop` → `systemctl try-restart k7d` running during the panic *unwind*, i.e. post-failure noise that then churned the sandbox and changed the pod IP under the debugger).

**Root cause:** Full-suite runs rsync + rebuild the shim, so `ensure_shim_installed` reinstalls it and `systemctl restart k3s` right before the first kubectl test. Flannel/kube-proxy take tens of seconds to reprogram the host dataplane after that restart. The old virtiofs path spent seconds spawning three virtiofsd processes and waiting for mounts, absorbing the window by accident; the block path reaches Running fast enough that the single-shot 5 s curl landed inside it. Standalone reruns don't reinstall (mtimes match) → no k3s restart → no window. The same churn plausibly explains the one-off vsock reconnect timeouts seen in `test_tree_protection` / `test_cluster_fork_warm_3vm_under_50ms` during other rounds (each passed standalone and in other full rounds).

**Fix:** `common::wait_for_k3s_ready()` after every `systemctl restart k3s` in the test helpers — polls apiserver `/readyz` AND CoreDNS pod Ready. CoreDNS Ready is the precise signal: kubelet's readiness probe is an HTTP GET from the host netns to the pod IP, i.e. exactly the path that is broken during convergence. Flow 2 also polls (90 s) instead of a single 5 s curl, per the send-once-is-a-bug pattern (#14).

**Reference:** none (k3s restart semantics + own test harness).

**Time lost:** ~2 hours (four full remote-check round trips, tcpdump in the pod netns, journal archaeology).

---

## 49. 50×3-VM shared-pause batch died with EMFILE — soft `RLIMIT_NOFILE` stayed at 1024

**Symptom:** `test_cluster_tree_fork_batch_50` panicked mid-materialise with `Fork(Restore(Io(... Too many open files)))` after the shared-pause batch path was wired up. The 8× bare batch test passed.

**Root cause:** Each live VM holds on the order of tens of fds (KVM, vCPU, TAP, vsock, eventfds, serial pipes, memfd). 50 forks × 3 members + the source ≈ 153 VMs → well over the default soft `ulimit -n` of 1024. Systemd reports `LimitNOFILE=524288` as the *hard* ceiling by default; without an explicit `LimitNOFILE=` in `k7d.service` the running daemon still had soft=1024. In-process tests and the daemon both hit `EMFILE` on `/dev/vhost-vsock`.

**Fix:** (1) `ensure_nofile_headroom` / `fork_cluster_warm_batch` raise the soft limit from hard-limit headroom; (2) daemon `main` raises to 262144 at startup; (3) `ensure_k7d_daemon_running` writes `LimitNOFILE=524288` into the unit and restarts when missing.

**Reference:** none (rlimit vs KVM fd fan-out).

**Time lost:** ~20 minutes (one remote-check to the failure + ulimit probe).

---

## 50. Nested hostNetwork www/nginx fails — etc-hosts bind

**Symptom:** internal notes`hostNetwork` nginx DaemonSet inside the 3-VM inner-k3s cluster. Nginx CrashLooped on kubelet `etc-hosts` bind (`…/etc/hosts: not a directory`). CrashLoops stressed the sidecar containerd tmpfs; outer pods went `Error`.

**Root cause:** Nested kubelet/hostNetwork path mounts `etc-hosts` into a layout the guest runc/k3s container does not provide as a real directory.

**Fix:** Do not use hostNetwork www images in this fixture. Dirtier workload = ordinary (non-hostNetwork) pause Deployment + API churn; score via apiserver `readyReplicas` on each bridge. See also #51.

**Reference:** none (nested CRI quirk of this fixture).

**Time lost:** ~20 minutes.

---

## 51. Guest kernel missing CFS_BANDWIDTH — nested runc can't open `cpu.max`

**Symptom:** Inner pause pods (Inc 3 and `Deployment/inner-load`) failed with `openat2 …/cpu.max: no such file or directory` even though `cpu` was listed in `cgroup.controllers`. Cgroup dirs showed `cpu.weight` / `cpu.stat` but never `cpu.max`. Sandbox pause tasks sometimes stayed Running (no CFS write), while the app container Create always failed.

**Root cause:** `guest/kernel/config-minimal` had `CONFIG_CGROUP_SCHED=y` but not `CONFIG_CFS_BANDWIDTH`. Without CFS bandwidth, cgroup v2 never creates `cpu.max`; runc 1.2.x in the nested k3s containerd still tries to open it when applying CPU config.

**Fix:** Enable `CONFIG_FAIR_GROUP_SCHED=y` and `CONFIG_CFS_BANDWIDTH=y`, rebuild the guest kernel on the node (`cd guest/kernel && ./build.sh`), re-run inner-k3s tests against the new `vmlinux`.

**Reference:** Linux `kernel/sched/core.c` CFS bandwidth; runc `libcontainer/cgroups/fs2/cpu.go`.

**Time lost:** ~40 minutes (misattributed to "hostNetwork-only" in #50 before checking `cpu.max` on a bare pause pod).

---

## 52. `copy_file_range` EXDEV — cross-filesystem copies got un-supported again in Linux 5.19

**Symptom:** First run of `test_kubectl_pod_two_images` / `test_image_slot_exhaustion_fails_loud`: every image-slot fill failed with `copy_file_range /var/lib/k7d/images/….erofs -> /tmp/k7d-shim-…/image-slots/slot-0.img: Invalid cross-device link (os error 18)` — even though the FICLONE→`copy_file_range` fallback chain looked textbook.

**Root cause:** Linux 5.3 allowed cross-filesystem `copy_file_range`, but 5.19 reverted it (dedup/CoW corruption bugs) — it now returns `EXDEV` whenever src and dst superblocks differ. The erofs cache (`/var/lib/k7d/images`, root ext4) and the slot backing file (`/tmp/k7d-shim-*`) are practically always on different filesystems, so the "fallback" was dead code that failed 100% of the time on modern kernels.

**Fix:** Three-step chain in `clone_or_copy_into` (`crates/shim/src/task.rs`): FICLONE → `copy_file_range` → plain `std::io::copy` read/write loop on `EXDEV`/`EINVAL`/`ENOSYS`/`EOPNOTSUPP`.

**Reference:** Linux commit `868f9f2f8e00` ("vfs: fix copy_file_range() regression in cross-fs copies", 5.19).

**Time lost:** ~30 minutes (one full remote-check cycle).

---

## 53. Guest `lo` was never brought up — pod-local 127.0.0.1 hung with a timeout, not ECONNREFUSED

**Symptom:** In the two-image pod test, nginx reached Running and exec/logs worked, but `wget http://127.0.0.1/` from inside the *same* container timed out (`Operation timed out`, not `Connection refused` — which is what made it look like an nginx or netns problem rather than an interface problem).

**Root cause:** Nothing in the guest (initramfs init or k7-agent) ever ran `ip link set lo up`. Loopback is not auto-upped by the kernel. Every prior test exercised eth0 (configured by the shim/daemon) or vsock; no workload had ever connected to localhost inside the guest. Since the shim strips the OCI network namespace, all pod containers share the guest root netns — so a down `lo` breaks both in-container localhost and the pod-semantic cross-container localhost.

**Fix:** `bring_lo_up()` in the agent's boot path (`crates/agent/src/main.rs`), before block/virtiofs mounts. Test asserts localhost from both the nginx container and the busybox sidecar.

**Reference:** none (guest-init gap).

**Time lost:** ~25 minutes (one remote-check cycle + a wrong first guess at runc netns handling).

---

## 54. Preserving `linux.resources` resurfaced CRI `memory.swap.max` on a no-swap guest

**Symptom:** After `fix_oci_config` stopped stripping `linux.resources`, every kubectl pod (including BestEffort nginx with no memory limit) CrashLoopBackOff'd at Start with `unable to set unified resource "memory.swap.max": … no such file or directory`. CNI / shim tests that previously passed started failing immediately.

**Root cause:** containerd CRI stamps `linux.resources.unified["memory.swap.max"]="0"` on essentially every container. The guest kernel is built with `CONFIG_SWAP` unset, so cgroup v2 never creates `memory.swap.max`. internal notes`resources` object (then writing back devices allow-all only). Restoring structured memory/cpu for Inc 4 re-exposed the unified swap key.

**Fix:** In `fix_oci_config`, keep memory/cpu (and other) resource fields, force devices allow-all, drop structured `memory.swap` and swap/zswap unified keys the guest cannot honour. Also drop `memory.oom.group` until Inc 2 exit observation lands — with `oom.group=1` an over-limit `kubectl exec` kills the whole container cgroup and, without an exit event, kubelet never restarts it (breaks internal notes's "pod survives guest OOM" check). Process-level OOM still enforces `memory.max`; Inc 4's main-process hog covers whole-container OOMKilled. Delegate `+cpu +memory +pids` from guest `init.sh` after moving the agent into a `/sys/fs/cgroup/init` leaf. Rebuild guest kernel on the Inc 4 node for `CONFIG_CFS_BANDWIDTH` (CHALLENGES #51).

**Reference:** runc `libcontainer/cgroups/fs2` unified key writer; Linux `CONFIG_SWAP` / memcg swap files.

**Time lost:** ~1.5 hours (CNI looked like networking; then 10c survival raced/broke on oom.group).

---

## 55. Parallel agents clobber `/root/k7d` on a shared bare-metal node

**Symptom:** `make remote-check` on the Inc 5 node flipped between green clippy on
mainline sources and hard failures compiling Inc 2 symbols
(`container_wait_poll`, `clippy::single_match_else` in an exit-watcher loop)
that are not on this branch. Mid-suite, `test_shim.rs` lost
`test_multi_image_pod_warm_fork_cow` (grep count went 1 → 0) while
`auth.log` showed several distinct cloud-agent SSH sources rsyncing the
same `/root/k7d` tree.

**Root cause:** Multiple increments were pointed at one node and all used the
default `REMOTE_DIR=/root/k7d`. `rsync --delete` from any agent silently
replaces the working tree under the other agent's build/test.

**Fix:** Run Inc 5 against an isolated tree:
`make remote-check REMOTE_DIR=/root/k7d-inc5` (copy guest
`vmlinux` / initramfs / `runc.amd64` into that tree once — rsync excludes
them). Keep claiming the assigned `K7_NODE_IP`; do not fight over
`/root/k7d` when another increment is active.

**Reference:** none (agent hygiene / node multiplexing).

**Time lost:** ~25 minutes (two aborted remote-check cycles + diagnosis).

---

## 56. Console with a no-op IRQ trigger wedges the agent's vsock accept loop after ~4 KiB of logging

**Symptom:** The spec-15b "dirtier" inner-k3s warm-fork tests failed on `main`
and every 16a-inc2 attempt (this is what sank PR71): after the churn workload,
`kubectl exec` into the fixture pods timed out forever (`exit status 124`)
while the guests stayed provably healthy — inner apiserver answered on
`:6443`, kubelet ports open, ping fine. Direct vsock probes showed a
distinctive progression per guest: agent answers → connects succeed but
requests time out → `ECONNRESET` on connect. Under a 1/s external probe,
agents "died" 30–70 s after boot; without probes, only the exec-heavy server
pod died. Post-adopt serial consoles were completely empty, so the guest
looked like a black box.

**Root cause:** COM1 was created with `SerialTrigger::noop()` — the console
device could never raise an interrupt. Kernel printk polls LSR and never
noticed, but guest *userspace* writes to `/dev/console` drain through the
8250 tty path, which parks the writer until a THRE interrupt refills the
4 KiB xmit buffer. The k7-agent (guest PID 1) `eprintln!`s two lines per
vsock connection from its accept loop; after ~60–70 connections (≈4 KiB) the
next `write(2)` blocked forever and took the accept loop with it. The vsock
backlog then explains both probe signatures: pending connects still complete
their handshake into the accept queue (request then times out — no handler),
and once the backlog fills the guest RSTs new connects
(`virtio_transport_recv_listen` → `sk_acceptq_is_full` → reset). The 30–70 s
window under 1/s probing is just 4096 bytes ÷ ~65 bytes per probe. internal notes's
churn (~30 extra execs against the server pod) pushed it over the edge, which
is why lighter suites (and the Inc 5 adopt test) never caught it.

**Fix:** Wire COM1 like COM2 already was: eventfd + `register_irqfd(GSI 4)`
and `SerialDevice::with_trigger` at all three creation sites (cold boot and
both restore paths). Also added a `DumpSerial` control verb (by `vm_id` or
`guest_cid`, including live tree members) so the next black-box guest can be
inspected through the daemon's in-memory console buffer.

**Dead end worth recording:** before finding the console trigger, the prime
suspect was vhost-vsock snapshot tearing — the kernel vhost worker keeps
DMA-ing into guest RAM during the multi-second `memory.bin` dump (only
vCPUs and in-process net/blk workers are paused), so a busy guest's memory
image can in principle disagree with the ring state that restore re-seeds
`SET_VRING_BASE` from. A hardening toggle (`VhostVsockBackend::set_paused`
→ `VHOST_VSOCK_SET_RUNNING` 0/1 across `Vm::pause`/`resume`) was
implemented — and **reverted**: it made
`test_cluster_fork_warm_source_tcp_undisturbed` /
`test_cluster_fork_warm_fork_tcp_works` fail with source-agent reconnect
timeouts in full-suite runs (green with the toggle disabled, and the suite
ran 2× faster). The stop/start cycle is not transparent to live guests the
way QEMU's managed stop (GET_VRING_BASE + re-negotiation) is. The tearing
hazard remains theoretical — no observed failure is attributable to it —
but if one ever appears, the fix must snapshot ring state via
`GET_VRING_BASE` semantics rather than toggling RUNNING around the dump.

**Reference:** Linux `drivers/tty/serial/8250` (uart_write parks on full
xmit buffer awaiting THRI), `net/vmw_vsock/virtio_transport_common.c`
(backlog-full reset). vm-superio raises THR-empty only through the trigger.

**Time lost:** ~2 days across two agent threads (PR71's unexplained wedge +
this thread's full re-diagnosis: node-health red herrings, snapshot-tearing
theory, live guest triage via bridge networking, then the 30–70 s ÷ probe
rate arithmetic).

---

## 57. Virtio worker threads inherit the vCPU thread's cgroup *and* comm — the "exactly 2 TIDs" cgroup test was doubly wrong

**Symptom:** `test_multi_vcpu_all_tids_in_cgroup` found **10** TIDs in the
2-vCPU pod's `cgroup.threads` instead of 2. The panic leaked the pod, whose
per-VM cgroup then cascaded `vm_cpu_cgroups().len() == 1` failures through
the rest of `test_resources.rs` (each later test also restarts k7d with the
fresh binary, killing the leaked pod's VM — kubelet's `SandboxChanged`
recreation loop made the leftovers look like a multi-vCPU boot crash).

**Root cause:** Two cgroup-v2 threaded-mode inheritance rules meeting one
naive assertion. (1) A thread cloned by a member of a threaded cgroup starts
*in that cgroup* — virtio-net/virtio-blk workers are spawned by the vCPU
thread that handles the guest's device-activation MMIO exit, so after
`apply_cpu_cap` moved the vCPU TIDs, every device worker landed in the VM
cgroup too. This is *correct* behaviour (device work is VM work; the pod
quota must cap it), so the test had to identify vCPU threads instead of
counting. (2) The first fix — name the vCPU threads `vcpu{i}` and match
`/proc/<tid>/comm` — still failed: `comm` is also inherited on clone, so the
unnamed workers all reported `vcpu0`.

**Fix:** Name the vCPU run-loop threads (`vcpu0`, `vcpu1`, …) *and* the
virtio worker threads (`virtio-net`, `virtio-blk`) at spawn; the test asserts
the set of `vcpu*`-named TIDs in `cgroup.threads` is exactly
`{vcpu0, vcpu1}`. Added a `PodGuard` (drop-deletes the pod) to the internal notes
kubectl tests so one panic can no longer cascade into later tests.

**Reference:** Linux `Documentation/admin-guide/cgroup-v2.rst` (threaded
controllers, thread placement on clone); `prctl(PR_SET_NAME)` comm
inheritance.

**Time lost:** ~1 hour (one full remote-check cycle per wrong assertion,
plus untangling the leaked-pod cascade from a suspected boot regression).

---

## 58. Restored SMP guests hang intermittently — `KVM_GET_LAPIC` does not carry the TSC-deadline timer arm

**Symptom:** `test_multi_vcpu_snapshot_restore_roundtrip` failed
intermittently after restore, and the failing step *moved between runs*:
one run timed out on `dmesg`, the next on `date`, another passed all the
way. Everything before the hang worked — the restored guest reported 2
CPUs, both counters advanced, earlier execs succeeded.

**Root cause:** The per-vCPU LAPIC is captured via `KVM_GET_LAPIC`, but
the one-shot **TSC-deadline timer arm lives in the `IA32_TSC_DEADLINE`
MSR (0x6E0)**, not in the LAPIC register page — and our minimal
`MSR_INDICES` list didn't include it. After restore, a vCPU whose LAPIC
tick was armed at capture time never received that timer interrupt
again. On a 1-vCPU guest this is masked: the PIT tick (restored since
CHALLENGES #40) keeps CPU 0's timekeeping alive. On SMP, the AP has no
PIT — whatever the guest scheduler queued on CPU 1 hung until something
else (a wakeup IPI re-arming the timer) happened to rescue it, which is
why the failure was intermittent and moved around.

**Fix:** Add `0x6E0` to the captured MSR list. Restore order matters
for free: the MSR loop runs *after* `KVM_SET_LAPIC`, so the deadline
write re-arms KVM's software timer against the restored TSC (a deadline
already in the past injects the interrupt immediately — also correct).
Three consecutive green runs after a 100% repro-within-3-runs before.

**Reference:** Firecracker sidesteps this by capturing the *full*
`KVM_GET_MSR_INDEX_LIST` rather than a hand-picked set; KVM's
`kvm_set_lapic_tscdeadline_msr` → `start_apic_timer` is the re-arm path.

**Time lost:** ~1.5 hours (chasing the moving timeout through three test
hardening rounds — stdio-held pipes and a missing busybox `date` symlink
were real but unrelated test bugs found on the way).

---

## 59. Tree fork children are not prepared as fork sources

**Symptom:** `test_cluster_annotation_mixed_vcpus` got the annotation
adopt+fork to Running, then
`TreeFork { source_id: warm, label: probe }` failed with
`VM not prepared as fork source — call prepare_fork_source() first`
(reflink copy path).

**Root cause:** `TreeAdoptCluster` / `TreeCreate*` run
`prepare_fork_source` on the **root** payload. A subsequent `TreeFork`
produces a live child that is *not* automatically re-prepared — only
the root (or an explicitly prepared node) can be forked again. The
test assumed the annotation-created `warm` node was a ready source.

**Fix (test-side):** assert the `warm` node exists via `TreeNodes`,
then probe-fork from `root` to obtain guest CIDs and check per-member
`nproc`. That still proves the adopted kubectl mixed-vCPU cluster
preserved counts; the annotation fork itself is covered by the
trigger pod reaching Running.

**Reference:** none (daemon invariant; same as library `fork_warm`
requiring `prepare_fork_source` first).

**Time lost:** ~20 minutes.

---

## Reference projects and what each taught us

| Project | What we learned |
|---------|----------------|
| **Firecracker** | MMIO register layout, boot params fields, GDT/segment setup, page table identity mapping, E820 memory map, interrupt_status pattern for vhost devices, ioeventfd for QUEUE_NOTIFY |
| **crosvm** | `VIRTIO_F_ACCESS_PLATFORM` must be cleared for vhost backends, vhost ioctl ordering (features → mem_table → vring setup → cid → start) |
| **Cloud Hypervisor** | Kernel loading via linux-loader, virtio-fs device tree setup, vhost-user connection pattern |
| **Linux kernel source** | vhost-vsock queue count (2 not 3), `vhost_vq_access_ok()` validation path, ENOBUFS meaning (`idx >= dev->nvqs`) |
