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

**Fix:** This was a main driver for the daemon architecture . The k7d daemon holds one refcounted `BridgeEntry` per `cluster_id`: first `create_vm` creates the bridge, later VMs join and get unique indices, `stop_vm` frees the index (`ClusterNetwork::remove_entry`) and destroys the bridge only when the refcount hits zero.

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

**Fix:** Semantics-preserving Rust rewrites, verified by the equivalence theorems themselves: `ram_soft_limit` now uses an explicit overflow guard (`if pct != 0 && bytes > u64::MAX / pct { u64::MAX } else { bytes * pct } / 100`) instead of `saturating_mul`, and `NodeInfo` got a manual field-wise `impl Clone` (copying `Option<u64>` by value) instead of `#[derive(Clone)]`. Standing rule: before writing equivalence proofs, grep the generated file for `axiom` — each hit needs a Rust-side refactor or an honest documented assumption. **Now automated** : `utils/check-verif-axioms.sh` diffs generated axioms against `verif/axiom-allowlist.txt` inside `make verif-gen` / `make remote-verif`.

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

**Symptom:** After `prepare_fork_source` on a VM that had already driven eth0 traffic, vsock agent reconnect succeeded but the next guest command that used eth0 (ping/nc) hung forever. the referenced work therefore deferred its TCP-survival tests.

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

**Root cause:** the referenced work's volume plumbing bind-mounts every kubelet volume into the per-pod `volumes-rw` scratch tree, so each volume is a host *mount point* inside the virtiofsd share. virtiofsd ≥ 1.13 defaults to `--announce-submounts`, making the guest kernel expose each of those as a FUSE submount that is automounted lazily — and each container's runc traversal instantiated its *own* submount superblock (`/proc/self/mountinfo` showed `virtiofs none` device 0:29 in one container, 0:38 in the other). Unix-socket `connect()` resolves to the in-kernel inode object, which differs across superblocks, so the listener is never found. Regular file I/O goes through virtiofsd and works, which is why the referenced work's file-sharing tests never caught it.

**Fix:** Pass `--no-announce-submounts` in `VirtiofsdProcess::spawn_with_options`. The whole share is then one superblock and every container binds subdirs of it (`mountinfo` now shows `virtiofs k7fs2 /emptydir-cri`), restoring kubelet-like emptyDir semantics for sockets.

**Reference:** virtiofsd 1.13 changelog (announce-submounts default flip); FUSE submount automount semantics.

**Time lost:** ~2 hours.

---

## 36. Stripping `linux.resources` from the guest OCI spec re-enables runc's default device filter — kubelet dies on `/dev/kmsg` 

**Symptom:** kubelet inside the k3s container failed with `open /dev/kmsg: operation not permitted` even though the entrypoint had successfully `mknod`ed the node and the container is privileged in the pod spec.

**Root cause:** The shim's `fix_and_write_oci_config` removes `linux.resources` wholesale . With no `devices` rules at all, runc installs its restrictive default eBPF device-cgroup program, which allows only the standard tty/null/zero/random set — privileged-ness from the outer pod spec never reaches the guest runc.

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

**Resolved for share-less sources :** the residual trap here — the prepare swap restoring a *block-only* source on a NEW vsock CID while the pod's shim keeps dialing the cached one — is fixed by preserving the CID across the in-place restore: `prepare_fork_source_in` shuts the source down and drops its device registry **first** (closing the vhost-vsock fd releases the CID to the kernel; claiming it while the old fd is open would `EADDRINUSE`), then restores via `restore_vm_preserving_cid`. Agent connections still die (fresh vsock backend) but the shim dials the CID fresh per exec, so kubectl exec/logs against adopted cluster members keep working.

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

**Reference:** none (own shim, the referenced work Inc 4 recovery path vs the referenced work Inc 4 deferred boot).

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

**Symptom:** the referenced work tried a `hostNetwork` nginx DaemonSet inside the 3-VM inner-k3s cluster. Nginx CrashLooped on kubelet `etc-hosts` bind (`…/etc/hosts: not a directory`). CrashLoops stressed the sidecar containerd tmpfs; outer pods went `Error`.

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

**Root cause:** containerd CRI stamps `linux.resources.unified["memory.swap.max"]="0"` on essentially every container. The guest kernel is built with `CONFIG_SWAP` unset, so cgroup v2 never creates `memory.swap.max`. the referenced work had been hiding this by deleting the entire `resources` object (then writing back devices allow-all only). Restoring structured memory/cpu for Inc 4 re-exposed the unified swap key.

**Fix:** In `fix_oci_config`, keep memory/cpu (and other) resource fields, force devices allow-all, drop structured `memory.swap` and swap/zswap unified keys the guest cannot honour. Also drop `memory.oom.group` until Inc 2 exit observation lands — with `oom.group=1` an over-limit `kubectl exec` kills the whole container cgroup and, without an exit event, kubelet never restarts it (breaks the referenced work's "pod survives guest OOM" check). Process-level OOM still enforces `memory.max`; Inc 4's main-process hog covers whole-container OOMKilled. Delegate `+cpu +memory +pids` from guest `init.sh` after moving the agent into a `/sys/fs/cgroup/init` leaf. Rebuild guest kernel on the Inc 4 node for `CONFIG_CFS_BANDWIDTH` (CHALLENGES #51).

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
window under 1/s probing is just 4096 bytes ÷ ~65 bytes per probe. the referenced work's
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
`{vcpu0, vcpu1}`. Added a `PodGuard` (drop-deletes the pod) to the the referenced work
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

## 60. Fork-source pods can never terminate — Kill blocks on the dead pre-swap agent connection while holding the state lock 

**Symptom:** After `k7 fork` (spec-17d `fork-source-*` annotations →
`ForkVm`), the *source* pod wedges in `Terminating` forever; kubelet
spams `ExecSync ... context canceled` (readiness probes), and dozens of
test namespaces pile up behind the stuck pod. All lifecycle tests pass —
the wedge only shows at pod deletion.

**Root cause:** the first `ForkVm` against a share-less source runs
`prepare_fork_source`, which swaps the source VM for a restored copy on
the SAME vsock CID. The source shim's **cached** `state.agent` connection
still points at the torn-down backend: reads/writes just stall until the
30s request deadline. `Kill` called `agent.container_signal` through that
cached connection **while holding the shim state lock** — containerd's
own Kill deadline is shorter than 30s, so every StopContainer attempt
timed out, kubelet retried, and each retry blocked the lock again (which
is also why the probes' Exec RPCs all hung). Exec never showed the bug
because the exec bridges dial a *fresh* vsock connection per exec.

**Fix:** `Kill` and workload `Delete` now dial a fresh
`AgentClient::connect_vsock(cid, 2s)` for the best-effort
`container_signal` / `container_stop` instead of trusting the cached
connection — same pattern the exec/output bridges already use. A live
guest answers in ms; a half-dead one costs at most 2s. Source pods now
terminate in ~4s.

**Reference:** the referenced work Inc 5 (CID-stable prepare swap), CHALLENGES #39.

**Time lost:** ~1 hour (the smoking gun was `/proc/<shim>/task/*/wchan`
showing the shim idle — not deadlocked — combined with `Kill: signal=9`
arriving in the shim log while `crictl stop` still hit DeadlineExceeded).

---

## 61. Empty shim `Stats` response poisons node-wide kubelet stats (and blocks namespace deletion)

**Symptom:** With any `runtimeClassName: k7` pod running, k3s logs
`ListContainerStats failed ... failed to decode container metrics ...
type with url : not found` for the k7d container; kubelet's summary API
loses ALL container stats, metrics-server goes permanently NotReady
("no metrics to serve"), and — the truly evil part — every namespace
deletion on the node wedges with `stale GroupVersion discovery:
metrics.k8s.io/v1beta1` because the namespace controller cannot finish
discovery against the dead aggregated API.

**Root cause:** the shim's `stats()` returned a bare
`api::StatsResponse::new()` — no `stats` `Any` payload at all.
containerd's CRI plugin fails the *aggregate* ListContainerStats call
when any single container's metrics blob has an empty type URL, so one
k7d pod takes down stats for every container on the node.

**Fix:** return a valid empty
`containerd_shim_protos::cgroups::metrics::Metrics` converted with
`convert_to_any` (type URL `io.containerd.cgroups.v1.Metrics`). Real
per-container accounting inside the guest is future work; the VM-level
numbers live in the k7d daemon's per-VM CPU cgroup.

**Reference:** containerd `cri/server/container_stats_list.go`
(decode-all-or-fail), kata shim returns proper cgroup metrics.

**Time lost:** ~45 min (surfaced as "why do test namespaces never
finish deleting" three layers above the actual bug).

---

## 62. Guests ≥ ~4 GiB never booted: 32-bit `ramdisk_image`, and a "working" band that silently aliased RAM over the IOAPIC

**Symptom:** any pod with `memory: 4Gi` or more stuck in ContainerCreating,
the shim giving up with `agent connect failed: Connection timed out`
(sometimes `No such device` from the vsock connect). `3.5Gi` worked. The
obvious suspect — and the one the spec had already written down as the
"smoking gun" — was that `vm.rs` placed the virtio-mmio windows at
`mem_size + MMIO_GAP + idx*0x1000`, so at 4 GiB the vsock window jumped
from `0xc4001000` to `0x104001000`, past the 32-bit boundary.

**Root cause:** the MMIO jump was a red herring. `virtio_mmio.device=`
addresses are parsed as 64-bit, the kernel maps them fine, and a guest
booted with a window above 4 GiB talks to the device happily. The real
defects were two, both invisible from the shim side:

1. **`boot_params.hdr.ramdisk_image` is 32 bits wide.** We loaded the
   initrd at the top of guest RAM and wrote that address into the header
   without using the 64-bit `ext_ramdisk_image` extension, so past 4 GiB
   the address silently truncated. The guest kernel then found no
   initramfs, panicked in `prepare_namespace` with `VFS: Unable to mount
   root fs`, and never started `k7-agent` — hence a connect timeout
   rather than any memory-shaped error.
2. **RAM aliased fixed platform MMIO.** Sizes in the narrow ~4076–4097
   MiB band *did* connect, which is what made the ceiling look fuzzy.
   Those guests had RAM mapped over the in-kernel IOAPIC (`0xfec00000`),
   the LAPIC (`0xfee00000`) and KVM's TSS + identity-map pages: writes
   landed on device registers, corruption was quiet, and the "max working
   `memory_mb`" answer was meaningless because the boundary was two
   unrelated bugs interleaved.

**Fix:** give the guest the layout a real PC has. `crates/k7d/src/mem_layout.rs`
splits RAM into a low region ending at `MMIO_HOLE_START` (`0xfe000000`)
and, for bigger guests, a high region starting at 4 GiB, registered as
two KVM slots. The hole stays unmapped so accesses reach devices, and
virtio-mmio windows now sit at a *fixed* base inside it instead of
floating above RAM. The initrd goes at the top of low RAM, which is
always addressable in 32 bits — with a loud error if it ever fails to
fit rather than a truncating cast. The host mapping stays linear
(`hva == base + gpa`, the hole left as untouched sparse memfd pages) so
every virtio backend keeps translating with a single addition; snapshots,
deltas and dirty bitmaps switched from RAM size to the guest physical
*span* (`Vm::mem_span()`), since the hole is inside the range they index.

**Debugging note:** the guest panic was only visible on the serial
console of a directly-built `Vm`. Going through kubectl, every failure
mode — panic, corruption, agent crash — presents identically as a
connect timeout, so binary-searching `memory_mb` through pods produced
nothing but a confusing "sometimes 4076 works" signal. A throwaway
integration test that built VMs at chosen sizes and dumped serial output
found it in one run.

**Reference:** Firecracker `arch::x86_64::layout` (`MMIO_MEM_START`,
`FIRST_ADDR_PAST_32BITS`) and Cloud Hypervisor's `MemoryManager` both use
the same low/high split; Linux `Documentation/arch/x86/boot.rst` for the
`ramdisk_image` / `ext_ramdisk_image` field widths.

**Time lost:** ~3 hours, most of it trusting the MMIO hypothesis the spec
handed us before checking the serial log.

---

## 63. `prepare_fork_source`'s husk unlinks the live guest's scratch image — and `Path::exists()` cannot tell a mount from a mountpoint 

**Symptom:** two traps found while giving each sandbox a host-backed
virtio-blk scratch disk (`disks::ScratchDisk`, an RAII handle whose
`Drop` unlinks the image).

1. With the handle owned by the `Vm`, `prepare_fork_source` silently
   deleted the image of a *running* guest. Nothing broke at that moment:
   the block backend still holds the fd, so the parent kept reading and
   writing happily. The damage only surfaced later and elsewhere — the
   next `fork_warm` failed its `FICLONE` with `ENOENT` on a file the
   guest was actively using, which reads like a reflink/XFS problem
   rather than a lifetime problem.
2. The obvious way to write the agent's fail-loud check for "scratch was
   promised but did not mount" — `Path::new(SCRATCH_MOUNT).exists()` —
   cannot fail. `mount_one_blk` does `fs::create_dir_all(&spec.mount)`
   before mounting and only *logs* a mount failure, so an unformatted or
   absent device leaves an empty *directory* at the mount point and the
   check passes. The container would then run with its overlay upper on
   the initramfs tmpfs — exactly the RAM-backed writable layer the referenced work
   exists to abolish, now with a log line claiming it was on a disk.

**Root cause:** (1) `Vm::prepare_fork_source_in` snapshots the source,
builds a restored VM, and `std::mem::swap`s it into `self`; the
swapped-out husk is dropped at end of scope. Every resource the live
guest still needs has to be moved across *before* the swap — the TAP
device already was, and the scratch handle is the same class of thing.
(2) A mountpoint's existence says nothing about what, if anything, is
mounted on it.

**Fix:** (1) `restored.scratch_disk = self.scratch_disk.take();` before
the swap, with the reason in a comment next to the TAP handover so the
next resource added to `Vm` finds the precedent. (2) Check the
*filesystem type* of the mount the path lives on
(`mount_fstype_of` over `/proc/self/mountinfo`, already present for the
erofs rootfs detection) and require `ext4`; an unmounted mountpoint
reports `rootfs`/`tmpfs` and fails the container start with an error
naming the mount point.

Both are covered by assertions rather than left to inspection:
`test_warm_fork_scratch_is_cow_and_isolated` asserts the source image
still exists after `prepare_fork_source` (reverting the handover makes it
fail immediately), and `test_promised_but_missing_scratch_fails_loud`
boots a guest with a deliberately unformatted image at the scratch mount
point.

**Reference:** none — both are local invariants. The reflink-CoW
inheritance decision follows `reference/cubesandbox/` (cubecow).

**Time lost:** ~1 hour, most of it on trap 1: the parent guest showing no
symptom at all made "the image is gone" the last hypothesis rather than
the first.

---

## 64. A node-side edit makes every later `make remote-check` test stale code — rsync rolls the source's mtime *backwards* and cargo calls it fresh

**Symptom:** `test_warm_fork_scratch_is_cow_and_isolated` failed in
`make remote-check` with the exact assertion that a five-minute-earlier
standalone `cargo test --test test_scratch` had passed, and that the code
on the node plainly satisfied — `grep` found the required line in
`crates/k7d/src/vm.rs` on the node, and the test still failed. Two
consecutive full-suite runs tested a binary built from source that
existed nowhere: not in the repo, not on the node.

**Root cause:** an experiment had temporarily edited `vm.rs` *on the
node* (to confirm that removing the scratch-disk handover really does
break the fork test) and rebuilt. That build's fingerprint recorded the
edited file's mtime — call it 07:10. Restoring the file and re-running
`make rsync` then wrote the **workspace** copy back with the
**workspace's** mtime, 07:05, because `rsync -a` preserves times. Cargo's
freshness check is "is any source newer than the output": a source dated
*before* the artifact is fresh by definition, so cargo skipped the
rebuild and every later test linked the experimental library. `rsync`
without `-c`/`--checksum` also has nothing to say here — it compares size
and mtime, and both matched what it had already sent.

The dangerous direction is the other one. This can just as easily hide a
node-side hack that makes a test *pass*, and `make remote-check` would
report green for code that was never in the repo.

**Fix:** never leave a node-side source edit behind — restore from git
(`git -C /root/k7d checkout -- <file>` is not available since the node
copy is not a checkout, so `cp` from a backup *and then* force a
rebuild). After any rsync that follows a node-side edit, bump the source
mtimes so cargo cannot mistake old-but-different for unchanged:

```bash
ssh $NODE 'cd /root/k7d && find crates -name "*.rs" -newermt "1970-01-01" -exec touch {} +'
```

Better: do experiments the same way as any other change — edit locally,
rsync, run — so the node's tree is only ever written by rsync and its
mtimes only ever move forward.

**Reference:** none. Related to #17 (`rsync --delete` removing node-side
generated files) and #45 / #55 (a second writer to `/root/k7d`): the
common theme is that the node's tree is shared mutable state and rsync is
not a synchronisation primitive.

**Time lost:** ~40 minutes, and one wasted 25-minute full-suite run. The
tell was "the assertion contradicts the source on the node" — at that
point stop debugging the code and start doubting the artifact.

---

## 65. The per-container memory-limit test was really a tmpfs-accounting test, and the referenced work broke it by working

**Symptom:** `test_kubectl_pod_per_container_memory_limits` (the referenced work
Inc 4, untouched for months) failed on the 19b branch with
`40Mi write in 32Mi cgroup must fail, got: Ok("")`. Nothing in the diff
went near cgroups, runc, or `linux.resources`.

**Root cause:** the test proved "each container's memory limit is
enforced independently" by writing a 40 MiB file to `/tmp` inside a
32Mi-limited container and asserting the exec got OOM-killed. `/tmp` is
part of the container rootfs, i.e. the overlay *upper* — which before
19b was a guest tmpfs. Tmpfs pages are charged to the writing cgroup and
are not reclaimable without swap, so the write did OOM, and the test
passed for a reason it never stated. the referenced work moves the upper onto a
host-backed ext4 image on virtio-blk, where the same write is ordinary
reclaimable page cache: the kernel writes back and reclaims instead of
OOM-killing, the write succeeds, and the assertion fails. The test was
right to fail — the behaviour it encoded is exactly the coupling 19b
exists to remove.

**Fix:** probe the limit with memory instead of with a file:
`dd if=/dev/zero of=/dev/null bs=40M count=1`, whose 40 MiB I/O buffer is
anonymous and fully faulted in by the read. OOM-kills at 32Mi, succeeds
at 256Mi, and no longer depends on where the writable layer lives. The
test comment now says which property it is measuring and why it is not a
file write.

**Reference:** none. `Documentation/admin-guide/cgroup-v2.rst` on why
tmpfs pages count as unreclaimable file memory is the underlying reason.

**Time lost:** ~20 minutes. Worth generalising: any test that reaches a
resource limit *indirectly* silently depends on which subsystem backs the
resource. Grep for the rest of them before changing a backing store.

---

## 66. Making the remote loop survive a dropped SSH: three ways the detached run was still fragile

**Symptom:** hardening `make remote-check` against the two failure modes
in #64 (a wedged connection with no keepalive, and rsync rolling a
source's mtime backwards) produced three follow-on bugs that each look
like the mechanism works when it does not.

1. **The detached run never came up.** `nohup setsid bash run.sh >log &`
   from an `ssh` command line raced its own session teardown: the whole
   `&&` chain was backgrounded, so the setup and the `setsid` ran after
   the remote shell had already been told to exit. The run *did* start
   often enough to look correct, and the log even had output in it, but
   the pid file was written by a process that was gone by the time the
   local side polled for it.
2. **Reattaching duplicated every line.** The local viewer is
   `ssh … tail -f | tee -a <local log>`, and the local log's *size* is
   the byte offset a reattach resumes from. `SIGKILL`ing the wrapper
   (a dying agent, a closed laptop — the exact case reattach exists for)
   leaves the ssh orphaned and still appending, so the new viewer and
   the old one both write and the log gets each subsequent line twice.
   Reattach then resumes from a doubled offset.
3. **Touching rsynced files made every sync a full sync.** The #64 fix
   is "bump the mtime of what rsync wrote". With rsync's default
   size+mtime quick check, those touched files look changed on the next
   run, so rsync re-transfers and re-touches the whole tree every time —
   and a whole tree of fresh mtimes means cargo rebuilds everything on
   every `make remote-check`.

**Root cause:** (1) `setsid` only forks when it is already a process
group leader, and a non-interactive shell does not put background jobs
in their own group — so plain `setsid` blocked instead of detaching, and
the surrounding subshell was racing SIGHUP. (2) A process's death does
not reap its children, and the resume offset was derived from state a
dead process could still be mutating. (3) mtime is both the thing being
repaired and the thing rsync uses to decide what to send.

**Fix:** (1) `nohup setsid --fork`, run synchronously (no `&`), with the
wrapper recording its own `$$` and writing its exit code from an `EXIT`
trap so a run can never finish without a status. (2) Reap any ssh
carrying this run's viewer marker before attaching — matching on the
marker *and* on `comm == ssh`, so a process that merely mentions the
path is never signalled. (3) `rsync --checksum`: "transferred" then
means "content really differs", which is exactly the set whose mtime
must move forward, and the sync is idempotent again (~1.8 s for this
tree, versus a full rebuild).

**Testing note worth reusing:** three separate test scripts killed
*themselves*, because `pkill -f <pattern>` matches the command line of
the shell running the pkill. Put this kind of test in a file rather than
an inline `bash -c`, or the harness fails in a way that looks like the
thing under test. A wedged connection also cannot be faithfully
simulated by `SIGSTOP`ing the node's sshd — the client did not time out
in 150 s. A local TCP proxy that keeps both sockets open and delivers
nothing does reproduce it exactly: 71 s to fail with the keepalives,
still hanging at 120 s without them.

**Reference:** none. `setsid(1)`'s `--fork` note and `tail --pid` are the
only upstream behaviours involved.

**Time lost:** ~1.5 hours, most of it on (1) — "the run produced output
but reports as never started" reads like a state-machine bug, not a
shell-detachment one.

---

## 67. Per-container writable images: the mount that must not nest, and a `statfs` that answers for the wrong filesystem 

**Symptom:** giving a container its own ext4 image  looked like
a one-line variation on 19b's shared scratch — same `create_ext4_volume`,
same `k7d.blk=` plumbing, same agent mount. The first shape of it broke
two things that have nothing to do with each other: container teardown
started failing on `Device or resource busy`, and the usage number
reported for a container sharing the pod scratch was the *pod's* usage,
identical for every container in it.

**Root cause:** both come from a per-container mount being a mount and
not a directory.

1. The obvious place to put it is
   `/run/k7d/scratch/<name>` — right where 19b already puts a
   container's `upper`/`work`. But that path is a plain directory the
   agent creates on the shared image and reclaims with
   `remove_dir_all` when the container goes away, so mounting a device
   there means teardown tries to delete a live mount point. The mount
   also shadows what is underneath it, so a `statfs` meant for the
   shared disk answers for whichever nested image happened to be
   mounted at the path it was given.
2. `statfs` reports the *filesystem*, and for a shared-scratch container
   the filesystem is the whole pod's disk. Used-blocks minus free-blocks
   is a correct number for a dedicated image, where nobody else writes,
   and a meaningless one per container on the shared image. The two
   shapes need genuinely different measurements, not one with a
   correction factor.

**Fix:** per-container images mount at their own root,
`/run/k7d/cscratch/<name>` (`disks::CONTAINER_SCRATCH_GUEST_ROOT`),
deliberately not under the shared mount, with the reason written at the
constant. `OverlayMounts` carries a `dedicated` flag that then decides
both behaviours: teardown empties a dedicated mount instead of removing
it, and `usage` returns `statfs` for a dedicated image but walks the
container's `upper` tree for a shared one — which is also what makes a
delete lower the reported number, since neither `statfs` on the shared
disk nor the host's allocated block count ever goes down.

**Testing notes worth reusing:**

- Asserting "this container's writes land on its own device" by checking
  the filesystem type at the container's own `/` finds `overlay`, always.
  The ext4 is the overlay's `upperdir`; assert on that (and on the
  `upperdir=` option naming the expected mount) instead.
- `kubectl exec … dd` hitting `ENOSPC` looked like an empty failure:
  the interesting text is on the command's stderr and the non-zero exit
  makes the client discard it. Appending `; echo rc=$?` and matching on
  the combined output turns "the exec failed" into "the write failed
  with No space left on device", which is the difference between a
  passing test and a debugging session.

**Reference:** none.

**Time lost:** ~1 hour, mostly on the busy-teardown, which surfaced as a
container `Delete` failing long after the mount decision that caused it.

---

## 68. Teaching k7d to find installed guest artifacts made the test suite boot yesterday's guest

**Symptom:** rebasing the release-packaging branch onto main turned the
three per-container ephemeral-storage tests red, and only those. They
failed as `agent not ready within timeout` and
`container_usage(...): Timeout` — the signature of a hang, on a node
where every other VM-booting test in the suite passed.

**Root cause:** the branch taught `default_guest_paths()` to resolve
`/usr/local/share/k7d/{vmlinux,initramfs.cpio.gz}` before the workspace,
so an installed k7d could find its own guest. This node both builds and
runs k7d, so it has both copies — and the installed one was from the
previous day. `make test` rebuilds the agent and initramfs before every
run precisely so the suite cannot test a stale guest (entry 64 is the
same hazard by a different route), and this quietly undid that: the
tests booted an initramfs whose agent predated the feature they were
testing, so the call they waited on was never going to be answered.
Nothing was flaky and nothing timed out for the reason it claimed.

**Fix:** the workspace outranks the install. An installed binary has no
workspace — the path is baked from `CARGO_MANIFEST_DIR` at compile time
and belongs to whatever host compiled it — so it still resolves to the
share dir, and installs from the tarball never depend on either, because
`install.sh`'s systemd unit sets `K7D_KERNEL`/`K7D_INITRD` outright.

The tell, for next time: a timeout that only hits the newest tests in a
suite is more likely to be a stale guest than a slow one. `md5sum` the
initramfs the VM actually booted against the one the build just wrote.

**Reference:** none.

**Time lost:** ~45 minutes.

---

## 69. The publish scrubber cut an em dash in half and shipped Rust that would not compile

**Symptom:** the sanitized public tree looked right in `git diff` and
passed every grep-gate, but 17 of its files — 15 of them `.rs` — were no
longer valid UTF-8.

**Root cause:** the scrubber rewrites internal spec references with a
character class that itself contains multi-byte characters
(`[0-9A-Za-z_.§ –-]`). Perl defaults to byte semantics, so `§` and `–`
enter the class as their individual bytes, and a match can end partway
through a *different* multi-byte character that happens to share a
prefix — here the `—` in `the referenced work — pod annotation ...`, whose first
two bytes were consumed and whose third was left stranded. Rust source
must be valid UTF-8, so the public tree would not have built. Every gate
was a `rg` for forbidden *strings*; none of them asked whether the file
was still a well-formed file.

**Fix:** run the rewrites with `perl -CSD -Mutf8` so the patterns and
the input are both characters, and validate the encoding of every file
the sweep touched before the grep-gates run. A rewriting step needs a
gate on the shape of its output, not only on the content it was aiming
to remove.

Two smaller traps in the same script, both found by finally running it
end to end: `CHALLENGES.md`'s exemption from the spec-label scrub was an
early `return`, which also skipped the redaction below it and leaked the
node IP; and the curated copy list named a top-level `tests/` that has
never existed, so a real run aborted before reaching any gate.

**Reference:** perlrun `-C`, perlunicode.

**Time lost:** ~40 minutes.

---

## 70. `Load key: invalid format` meant a missing newline, not a bad key

**Symptom:** every `make remote-*` target failed to authenticate against
a node that was up and healthy, with
`Load key "/tmp/.../id_key": invalid format`.

**Root cause:** `utils/ssh-setup.sh` reconstructs the PEM when the
secret arrives with spaces instead of newlines, and that path appends a
trailing newline. A key stored with real newlines skips the
reconstruction and is written out verbatim — so a secret saved without a
trailing newline produced a file OpenSSH refuses to parse. It reports
that as `invalid format`, which reads like a corrupt or wrong-type key
rather than a missing byte.

**Fix:** terminate the file on both paths. Worth remembering that
OpenSSH will not accept an unterminated key file at all, and says so in
terms that point away from the cause.

**Reference:** none.

**Time lost:** ~15 minutes.

---

## 71. Deleting spec references by regex broke five things a diff review would not catch

**Symptom:** a mechanical pass that stripped internal spec references
from ~100 files left the tree looking plausible in review but wrong in
five distinct ways, only two of which any compiler or linter noticed.

**Root cause:** every reference sat inside prose, and deleting a span of
prose is not a local edit. The failure classes were: (1) a reference that
opened a parenthesis closed on a later line, leaving `... at boot (` with
the close paren orphaned two lines down; (2) a reference that began a
sentence, leaving a comment whose first character is `.` or `,`;
(3) `// the referenced work/19c:` where only the first id matched, turning `//` into
`///` — a doc comment in the middle of an expression, which does not
compile; (4) a tidy-up step that rewrote leading whitespace, silently
de-indenting doc-list continuation lines until clippy's
`doc_lazy_continuation` rejected them; (5) an identifier, `debug_log_10a`,
that encoded a spec id and had callers in two other modules, so a
file-scoped rename left dangling references.

The deeper trap: searching for the leftovers by grepping for spec
keywords finds nothing, because the keyword is exactly what was removed.
The damage has to be searched for by *shape* — comments starting with
punctuation, comment lines ending in an unclosed paren, indentation that
changed on a `///` line — and each shape needs its own pattern.

**Fix:** repair each site by hand against the pre-edit text from git,
then verify by shape rather than by keyword, and finish with a real
compile. `cargo fmt` will not flag any of this; clippy catches only the
doc-comment classes. The rewrites now live in the source, so the publish
scrubber's spec-rewriting block is gone and its grep-gate is what keeps
the tree clean — a new reference gets reworded at the source instead of
machine-mangled at publish time (which is what produced text like
"for internal notes's k3s-agent sidecar").

**Reference:** none.

**Time lost:** ~3 hours, most of it discovering damage classes one at a
time.

---

## 72. Nested dockerd died on a NAT write because the shim booted a guest nobody deployed

**Symptom:** stock docker-in-docker sidecars CrashLooped on one node of
a three-node k7 lab, on `--backend k7d`:

```text
failed to create NAT chain DOCKER: iptables --wait -t nat -N DOCKER:
iptables v1.8.11 (nf_tables): TABLE_ADD failed (Not supported): table nat
```

Everything a triage would check said the opposite of broken. Host NAT
was healthy, `iptables-save -t nat` non-empty, `/proc/net/ip_tables_names`
listed `nat`. The other two nodes ran the same image fine, and k7d's own
stock-dind e2e test was green on the node it runs on.

**Root cause:** two silences that only meet on a node that both builds
and runs k7d.

*Which guest booted.* The shim resolved the guest kernel and initramfs
itself and sent them to the daemon, which honours an explicit path over
its own `K7D_KERNEL`/`K7D_INITRD`. containerd spawns a shim with no
environment, so that resolution always fell through to the workspace
path baked in at compile time. `/root/k7d/guest/kernel/vmlinux` exists
on a build node and holds whatever was last built there — rsync
excludes both artifacts on purpose — so pods booted that, and the
deployed `/usr/local/share/k7d/vmlinux` was never opened. Nothing
logged which of the two won. Entry #68 had made the workspace outrank
the install a day earlier, reasoning that "an installed binary has no
workspace": true of a binary built elsewhere, false of the shim here.

*What was in it.* That stale kernel predated the config fix in 18a. Its
config asked for `CONFIG_NF_TABLES_INET` and nothing else in the
family; `NF_TABLES_INET` depends on `IPV6`, which was off then, so
`make olddefconfig` dropped it — in silence, because a request kconfig
cannot honour is simply absent from the answer. The result is a kernel
where `CONFIG_NF_TABLES=y` and `nft_supported_family()` is false for
every family. Measured on a kernel rebuilt that way on purpose:

| In the guest | Result |
|---|---|
| `iptables -t nat -L -n` | rc=0, prints PREROUTING/INPUT/OUTPUT/POSTROUTING |
| `iptables -t nat -N PROBE` | rc=4, `TABLE_ADD failed (Not supported): table nat` |

The read succeeds because iptables-nft synthesizes a missing table's
built-in chains, so the table looks present right up until something
writes. `nf_tables_newtable()` returns `-EOPNOTSUPP` before it looks at
anything else, and dockerd's first act is that write.

**Fix:** one per silence.

- The shim sends no guest paths at all; the daemon resolves them, logs
  what it resolved and where the answer came from, and `vm_status`
  reports the kernel each VM booted.
- `guest/kernel/build.sh` diffs the config kconfig answered against
  `config-minimal` and refuses to build a kernel that is not the one
  described. Twelve symbols kconfig will never answer as asked are
  listed in `config-drift-allowed` with the Kconfig rule behind each.
- `CONFIG_IKCONFIG_PROC` puts the answered config in the guest at
  `/proc/config.gz`, so a running VM can be asked what it is instead of
  inferred from the tree that maybe built it.
- The suite installs the guest it built into `/usr/local/share/k7d` and
  points `k7d.service` there, which is both how a k7 node runs and the
  only arrangement where the daemon's path differs from the shim's
  compile-time one — so the assertion that a pod booted the daemon's
  kernel has teeth. It reads the effective environment from `systemctl
  show`, not the unit file it just wrote, because a drop-in overriding
  `K7D_KERNEL` looks identical to everything working.

**What would have found it faster:** asking the VM, not the host. Every
host-side check passes in this failure, and the guest's own
`/proc/config.gz` and the daemon's resolved kernel path each answer it
outright. A green e2e suite is not evidence when the suite and the
failing pod boot different artifacts — the first question about any
"works here, not there" bug should be whether both sides are running
the same bytes.

**Reference:** linux 6.12 `net/netfilter/nf_tables_api.c`
(`nft_supported_family`, `nf_tables_newtable`).

**Time lost:** ~3 hours, most of it establishing that the host was
innocent and that two nodes differed only in a file nobody deploys.

---

## 73. Four things stood between `CONFIG_KVM_GUEST=y` and a guest that knows what time it is 

**Symptom:** `config-minimal` had asked for `CONFIG_KVM_GUEST=y` and
`CONFIG_PARAVIRT=y` since the first guest kernel, and no guest had ever
had either — both live under `if HYPERVISOR_GUEST`, which was never set,
so `olddefconfig` dropped them in silence (#72's new check is what
finally said so). Setting `CONFIG_HYPERVISOR_GUEST=y` and rebuilding
changed nothing observable: the guest still logged

```text
Booting paravirtualized kernel on bare hardware
clocksource: Switched to clocksource tsc-early
```

and `/sys/.../current_clocksource` still read `tsc`.

**Root cause:** three more layers, each of which looks like the whole
problem while you are on it.

*The hypervisor bit.* `KVM_GET_SUPPORTED_CPUID` returns KVM's signature
leaves — `0x4000_0000` spells `KVMKVMKVM`, `0x4000_0001` lists the
paravirt features — but leaves `CPUID.1:ECX[31]` clear, because whether
to tell the guest it is virtualized is the VMM's call. The guest gates
its entire paravirt path on that one bit: `init_hypervisor_platform`
never runs, so nothing ever looks at the signature leaves and
`kvmclock_init` returns before it registers anything. A VMM that copies
supported CPUID through verbatim gets a guest that cannot see the
hypervisor it is asking about.

*The TSC wins on merit.* With the bit set the guest registers kvmclock
and then declines to use it. On a host with an invariant TSC the guest
rates kvm-clock 299 and tsc 300, reasoning that a counter which never
stops needs no paravirt help. Sound for a VM that runs to completion,
wrong for one that is snapshotted: a restored guest's TSC resumes at the
value it was captured with, and there is no ioctl that re-bases it.
`clocksource=kvm-clock` on the cmdline settles it.

*Nothing was moving the clock.* `KVM_KVMCLOCK_CTRL` was already called
after restore, which reads like the clock being handled. It is not — it
sets the "guest stopped" flag in the pvclock page so the guest touches
its watchdogs instead of reporting a soft lockup across the jump. No
part of it changes a clock's value. kvmclock counts nanoseconds from the
creation of the VM fd; a restore makes a new fd, so the restored guest's
clock starts near zero while its timekeeping core still holds the value
from before the capture. The restore has to hand the value back with
`KVM_SET_CLOCK`, and hand back the captured reading **plus the wall time
the snapshot spent at rest** — otherwise the clock is monotonic and
wrong, which is the harder bug to see.

**Measured before any of it:** a VM restored across a 5-second gap read
7 seconds behind the host. The error is however long the snapshot sat
there, so a warm-pool template forked hours after it was minted hands
its sandbox a clock hours behind — with no RTC to correct it, and TLS
certificate validation downstream. Nothing in the suite had ever asked a
restored guest what time it was. After: 0s across cold boot, restore,
cold fork, prepared source and warm fork.

**Fix:** `CONFIG_HYPERVISOR_GUEST=y`; `CPUID.1:ECX[31]` set in
`vm::patch_cpuid_for_kvm_guest` on both the boot and restore paths;
`clocksource=kvm-clock`; `KVM_GET_CLOCK` into the snapshot next to a
host `CLOCK_REALTIME` reading, and `KVM_SET_CLOCK` on restore
(`fork::restore_kvmclock`). `k7d.now=` and the `init.sh` block that
parsed it are gone — kvmclock delivers the wall clock through
`MSR_KVM_WALL_CLOCK_NEW` before userspace exists, and survives the
transitions a cmdline is never re-read across.

**Two traps worth naming.** Advertising a paravirt feature in CPUID is a
promise to snapshot it: async page faults, steal time and PV EOI each
publish a guest physical address through a per-vCPU MSR, and a restore
that drops the MSR leaves the guest reading a page the host has stopped
writing. Leaf `0x4000_0001` is narrowed to the two kvmclock bits for
that reason. And the MSR save list's "kvmclock" entries were half wrong:
`0x4b564d03`/`04` are steal time and PV EOI, not the wall-clock pair —
harmless while the guest had no kvmclock at all, which is exactly how a
mislabel like that survives.

**Unrelated finding, kept because it was measured:** `idle=poll` came in
as the other half of `mitigations=off` for a VERW fault that
`CONFIG_CPU_MITIGATIONS=n` has since fixed, so removing it looked free —
boot-to-agent did not move. It is not free: the virtiofs write path went
from a 1.20 ms mean to 1.7 ms and broke its 2 ms budget in 2 of 10 runs,
because a halted guest has to be woken by an interrupt for every host
round trip. It stays, with the price written down (100% of a host core
per idle vCPU against 1%) and the way out specced in 19g.

**Reference:** linux 6.12 `arch/x86/kernel/kvmclock.c`
(`kvmclock_init`, the 299/300 ratings), `arch/x86/kernel/cpu/hypervisor.c`
(`init_hypervisor_platform`), `Documentation/virt/kvm/api.rst`
(`KVM_KVMCLOCK_CTRL`, `KVM_GET_CLOCK`/`KVM_SET_CLOCK`),
`arch/x86/include/uapi/asm/kvm_para.h` (the MSR numbering).

**Time lost:** ~4 hours, most of it on the two layers that fail quietly:
a guest that logs "bare hardware" while running under KVM, and a
restored clock that is monotonic, plausible and hours wrong.

---

## 74. Guest haltpoll starts at zero, shrinks to zero, and re-arms the PIT 

**Symptom:** dropping `idle=poll` (100% of a host core per idle vCPU)
pushed `test_latency_virtiofs_write` from a 1.20 ms mean to 1.7 ms and
broke its 2 ms budget in 2 of 10 runs. Host `kvm.halt_poll_ns` — already
on at 200 µs, and still 2 of 10 over budget when bumped to 2 ms — does
not close the gap: it keeps the host thread from scheduling out after a
vmexit, it does not remove the vmexit.

**Root cause:** four layers, each of which looks like a working haltpoll
governor until the next one is measured.

1. **The driver does not install.** `cpuidle-haltpoll.c` only loads if
   `KVM_HINTS_REALTIME` is advertised or `cpuidle_haltpoll.force=1` is
   on the cmdline, and it refuses to load if any `idle=` override is
   present. `patch_cpuid_for_kvm_guest` zeroes the EDX that hint lives
   in on purpose (advertising a dedicated-host-CPU claim that is not
   true). `force=1` is the gate; the hint stays off.
2. **Vanilla `poll_limit_ns` starts at 0 and shrinks after a long idle.**
   A warm-pool VM never sees a short idle, so the next request is a
   plain HLT. Widening `guest_halt_poll_ns` does nothing until the
   governor has grown to it.
3. **`haltpoll_select` sets `stop_tick=false` on POLL**, re-arming the
   PIT for the next scheduler tick. Each tick ends the poll, so a 2 ms
   window is charged once per tick instead of once per real wakeup.
4. **Even after leaving `stop_tick` true, leftover PIT IRQs at ~43 Hz
   remain** (`noapic` → 8254, oneshot stop is weak). Idle cost ≈
   43 Hz × 2 ms ≈ 8.6% of a host core — under the 10% budget, not the
   ~1% of plain HLT.
5. **The virtiofs write test's 1 s settle is many governor cycles past
   the poll window.** Haltpoll only helps a request that arrives
   *during* the poll after the previous wakeup. After 1 s the guest has
   HLTed; a warmup then a timed write is the HLT+vmexit path (~1.9 ms,
   flaky against 2 ms). 50 ms settle + two warmups puts the timed write
   in the window and recovers the 1.16 ms idle=poll number.

**Fix:** `CONFIG_CPU_IDLE` + haltpoll governor; `idle=poll` off;
`cpuidle_haltpoll.force=1`; pin 2 ms and `allow_shrink=0`; seed
`poll_limit_ns` at `guest_halt_poll_ns` and leave `stop_tick` true
(`guest/kernel/build.sh` patches `haltpoll.c`); 50 ms settle + two
warmups in `test_latency_virtiofs_write`. `test_idle_vcpu_is_cheap`
asserts the vCPU thread stays under 10% of a host core over 5 s.

**Reference:** linux 6.12 `drivers/cpuidle/cpuidle-haltpoll.c`
(`haltpoll_want`), `drivers/cpuidle/governors/haltpoll.c`
(`haltpoll_select`, `haltpoll_enable_device`).

**Time lost:** ~4 hours, most of it on (2) and (5) looking like a
window-size problem when the guest had already HLTed. A sixth layer
showed up only in `make check`: `test_cluster_fork_warm_fork_tcp_works`
timed out on `nc -w 5` when run after `test_cluster_fork_warm_batch_8`,
and passed in isolation. The fork test never warmed ARP on the *fork*
bridge (the source ping is a different L2 domain), so the first SYN
paid neighbour discovery; haltpoll HLTs between execs and busybox nc
burns its whole timeout on that SYN. Same trap `start_held_tcp_session`
already documented. Fix: ping both ways on the forks, and keep stdin
open on `nc -l` (CHALLENGES #28).

---

## 75. The workspace lock a dropped connection must not release, and the holder that read its own script from `/dev/null`

**Symptom:** two remote runs against one node interleave — one rsyncs into
`/root/k7d` while the other is compiling it — and the result is a suite that
fails in a different place each time. It reads as flakiness, so it gets
retried rather than fixed. `remote-run.sh` already serialised runs of the
*same* name (reattach instead of restart); nothing serialised two runs of
different names, and the scheduler's node lease is advisory — the launched
job still takes its node IP from its own environment, so the interlock has
to be on the node.

**Root cause:** two, one after the other.

1. **The lock cannot be held by the ssh session.** That is the whole design
   of this script: a dropped connection is a viewer problem, not a run
   problem. A lock held by the connection would release mid-build on exactly
   the network blip the detach exists to survive. It also cannot be held by
   the run process alone, because the rsync that must be excluded happens
   *before* the run exists.
2. **A detached process cannot be fed on stdin.** The holder was launched as
   `nohup setsid --fork bash -s ... </dev/null` with the script on a
   heredoc. `</dev/null` is what detaches it from the connection, and it is
   the same stdin the script arrives on — so `bash -s` read the script from
   `/dev/null`, did nothing and exited 0. Nothing failed. The lock was never
   taken, and the waiter sat in its poll loop for the full 45-minute timeout
   because "holder never launched" and "lock is busy" look identical from
   the client.

**Fix:** a detached node-side holder process owns the lock for the whole
rsync+build window — written to a file first, then launched, the same
two-step the run wrapper already used. The kernel releases the flock if that
process dies, so a killed client cannot wedge the node. The holder exits when
the run records an exit code, after a start grace if the run never appears,
and after a hard maximum so a hung build cannot own the node forever. Giving
up before the run starts (a failed rsync) releases immediately instead of
waiting out the grace. And the holder touches a marker *before* blocking on
the lock, so a launch failure is reported in seconds rather than looking like
a busy node — the second bug was only cheap to find because the first
symptom was a wait, not an error.

**Reference:** none upstream; `flock(2)` releases on process death, which is
the property the whole design rests on.

**Time lost:** ~25 minutes, almost all of it on the `</dev/null`
interaction, which produced no error on either side.

---

## 76. `--test-threads=1` does not serialize the test suite, only each binary

**Symptom:** cutting 0.2.0, two of three full `make remote-check` runs failed
exactly one test each with the same shape — a fork whose VM never answers:
`Agent(Io(Os { code: 110, TimedOut }))` on the vsock connect. It was a
*different* test each time (`test_fork_warm_under_50ms`, then
`test_emptydir_tmpfs_shared_and_survives_fork`), the middle run was green at
268/268, and each failing test binary passed on its own immediately after.
The first failure looked like a fork regression: it reported the fork itself
at 1.88 ms and then failed on reachability.

**Root cause:** `--test-threads=1` bounds parallelism *within* one test
binary. Cargo still runs different test *binaries* concurrently, and this
suite has many, each booting VMs and claiming vsock CIDs. So the invariant
we thought we had — one VM at a time on the node — never held across
binaries, and a fork that lands while another binary is saturating the host
can miss its agent-connect deadline. It reads as a fork regression because
the failing assertion is in the fork test.

**Fix:** none in this release — 0.2.0 ships on a green run, and every test in
the suite passed. But at two failures in three runs this is not a rare flake
to re-run past; it makes `remote-check` unreliable as a gate, which is worse
than a slower gate. The fix is to stop relying on a flag that cannot express
what we want: drive one test binary at a time (a `--test` target per `cargo
test` invocation, serially, each still `--test-threads=1`), or take a
node-side lock around VM-booting tests the way the workspace lock in #75
serializes whole runs. Until that lands, a lone fork/vsock timeout in an
otherwise green run should be re-run before it is believed — and if it moves
to a different test on the re-run, it is this.

**Update (serialization landed, and the diagnosis above was wrong):** the
`test` target now runs unit tests in one pass and then every integration
test binary alone (enumerated from `cargo metadata`, each still
`--test-threads=1`), and a failure names the binary. That part worked. The
flake rate did not move: 6 fully-serialized suite runs across two nodes,
both after `cargo clean` full rebuilds, produced **2 green** — the same
one-in-three the parallel suite produced. Every failure is the same shape
(warm fork or snapshot-restore, then vsock connect `ETIMEDOUT` or a first
ping between forks failing): `test_tree_auto_evict_lru`,
`test_cluster_fork_warm_fork_tcp_works`, `test_fork_warm_under_50ms`,
`test_cluster_fork_warm_source_tcp_undisturbed`. And it reproduces in
*isolation*: `test_cluster_fork` alone on an otherwise idle node failed 2
of 10 consecutive runs (`test_tree` alone was 10/10 green). So cross-binary
parallelism was never the cause — the middle green run that exonerated the
product in this entry was luck. The residual is an intra-binary,
per-fork-operation (~1%) reachability race in warm fork / restore, and it
needs its own investigation (the follow-up spec exists; fork/vsock code was
explicitly out of scope for the serialization change). The serialization
stays: it is what made the failures attributable enough to measure this.

**Reference:** none upstream — this is cargo's documented behaviour
(`--test-threads` is passed to the libtest harness, which only ever sees one
binary), just not the behaviour the flag's use here assumed.

**Time lost:** ~10 minutes, and it would have been much more if the
re-run had also failed and sent us into fork's agent-connect path.

---

## 77. `k7d --version` took down the node's runtime

**Symptom:** while verifying the 0.2.0 release tarball, running
`./k7d --version` on the node hung instead of printing a version. It had
started a *second* daemon. Killing it left the systemd unit `active` with
`MainPID` intact but `/run/k7d/k7d.sock` gone, so every shim on the node
would have failed to reach a daemon that believed it was serving. This is the
second time it happened — the first cost a live node earlier in the same
release.

**Root cause:** two bugs that compose into a foot-gun.

`main()` parsed only `--socket` and fell through to the serve path for
everything else, so an informational flag *is* a daemon start. And `serve`
opened with an unconditional `remove_file` on the socket path, commented as
clearing a stale socket from a previous run — but existence cannot
distinguish a stale socket from a live one. So the second daemon unlinked the
first's socket and bound its own at the same path: the first kept accepting on
an inode no client could open, and whichever process exited first deleted the
other's socket.

**Fix:** answer `--version` / `-V` / `--help` / `-h` before anything else and
exit. In `serve`, probe the path with `UnixStream::connect` before removing
it: a successful connect means a live daemon owns it, which is now
`AddrInUse` and a refusal to start, rather than a silent displacement. Only a
connect failure — nobody listening — is treated as leftover and unlinked.
Two tests cover it: informational flags exit 0 without serving, and a second
daemon on a live socket fails while the first stays reachable.

**Reference:** none upstream; this is the standard Unix-socket daemon
question ("is this socket stale?") answered by connecting, the way
`systemd`'s socket activation and most PID-file-free daemons do.

**Time lost:** ~20 minutes across two incidents, plus the cost of doubting a
release artifact.

---

## 78. The pause signal can cancel an interrupt KVM already ACKed — and restore dropped it 

**Symptom:** ~1% of warm forks / snapshot-restores produced a VM that was
alive but unreachable: vsock connect `ETIMEDOUT` for the full 30 s, or the
fork's first ICMP echo unanswered. Reproduced on an idle node, one binary,
`--test-threads=1`, freshly rebuilt tree, on two machines (see #76). A
repro loop (warm fork + 3 s vsock probe, `examples/fork_repro.rs`) failed
18/300 iterations and produced the evidence in one shot.

**Root cause:** `Vm::pause` signals the vCPU thread to kick it out of
`KVM_RUN`. That signal can land *between* KVM staging an event injection
and the VM entry that would deliver it: KVM cancels the injection and
reports it in `KVM_GET_VCPU_EVENTS` as `interrupt.injected=1` (the failing
capture showed `nr=53` — the vsock IRQ as an 8259 ExtINT vector; this
guest boots `noapic`). By that point the PIC has already ACKed the vector:
its in-service bit is set and nothing will ever re-send it. The restore
path deliberately skipped `KVM_SET_VCPU_EVENTS` (an old AMD `#BR`
workaround for stale *exception* state), so the interrupt evaporated while
the restored PIC state — carried over verbatim — kept waiting for an EOI
from a handler that never ran. An 8259 in-service bit gates that IRQ and
everything at lower priority, so the guest was permanently deaf on
vsock/net while running normally otherwise (HLTed, sane RIP, empty LAPIC).
The deaf fork's dump matched exactly: captured `interrupt(injected=1
nr=53)`, restored VM idle with the injection gone.

**Fix:** `restore_cpu_state` step 5b now restores the asynchronous,
non-regenerating slice of `vcpu_events` — the in-flight external
interrupt, NMI state, and interrupt-shadow window — and still zeroes all
exception state (exceptions are synchronous: re-executing the faulting
instruction regenerates them; restoring them is what caused `#BR` on
AMD Zen 4). The repro loop then ran 1000+ iterations clean, including
captures with `interrupt.injected=1` that were re-queued and delivered.
Regression coverage: `test_fork_requeues_interrupted_injection` (forces
`interrupt.injected=1 nr=0x35` into a captured state and asserts the
restored vCPU reports it queued before its first `KVM_RUN`) and
`test_fork_warm_repeated_reachable` (100 warm forks with agent traffic
right before each pause — the window the flake lives in — each probed
over vsock; pre-fix ~6% per-fork failure, post-fix deterministic).

The repro loop also exposed an unrelated leak on the same path:
`PipeSerialDevice` (COM2 agent serial, one per fork) held its pipe pair
as raw fds with no `Drop`, so every dropped VM leaked 2 fds and a
fork-heavy process hit `EMFILE` after ~500 forks. Both ends now close on
drop.

**Reference:** Linux KVM `vcpu_enter_guest` — on a pre-entry bail (signal
pending) it calls `kvm_x86_ops.cancel_injection`, leaving the ACKed
interrupt only in `vcpu->arch.interrupt` (surfaced via
`KVM_GET_VCPU_EVENTS`); Firecracker/QEMU restore `vcpu_events` wholesale
for this reason. The 8259 in-service semantics are the standard
"blocked until EOI" behaviour from the Intel 8259A datasheet.

**Time lost:** ~3 hours across the referenced work/22c, most of it before this
increment: the failure moved between tests and read as a harness
concurrency problem (#76) until the serialized runs proved it was
per-fork. With the repro loop dumping captured state, the actual root
cause fell out of the first failing iteration.

---

## 79. A warm fork inherits the guest's TX ring but not the guest's kick 

**Symptom:** after fixing #78, `test_cluster_fork_warm_fork_tcp_works`
still flaked: the fork0→fork1 ping got no reply (~13% of iterations in
a dedicated repro loop, `examples/cluster_ping_repro.rs`). The deaf
fork looked healthy — vsock agent fine, RX counters climbing — but its
eth0 TX was dead: host-side, the fork's TAP had **zero** frames written
by the VMM; guest-side, `NETDEV WATCHDOG: transmit queue 0 timed out`
in dmesg and the tx-error counter matched the watchdog fire count.

**Root cause (three stacked holes in `TapNetBackend`, all in the fork
window):**

1. **The guest's TX kick does not survive the fork.** The guest posts
   TX descriptors, then notifies via an MMIO write that lands in the
   *source's* `tx_kick` eventfd. If the fork captures memory before the
   source worker drains the ring, the fork sees `avail.idx > used.idx`
   — but its freshly created eventfd is silent, and virtio drivers
   never re-notify for descriptors already made available. The fork's
   worker (which only touches the TX ring on a kick) waits forever;
   the guest's TX queue stays stopped waiting for completions and the
   watchdog fires. RX kept working because the RX path is driven by
   TAP `POLLIN`, not guest kicks — which is exactly why the failure
   read as "one direction dead".
2. **No device-DMA dirty tracking.** Warm forks copy `base.mem` plus
   KVM's dirty-page delta, and KVM's log only sees vCPU writes. The
   net worker writes guest memory from userspace (RX payloads,
   used-ring entries, `used.idx`) and, unlike `BlockBackend`, reported
   none of it — so any net traffic between the last capture and the
   pause handed forks a used ring older than the guest driver's own
   (vCPU-written, hence fresh) bookkeeping. The reseeded worker then
   re-completed descriptors the guest had already recycled.
3. **No pause quiescence.** `set_paused(true)` was a bare atomic store;
   `wait_quiescent` was the trait's no-op default. The fork memcpy
   could race a mid-flight `put_used_desc` and capture a torn ring
   (entry written, idx not, or vice versa) — the guest driver reacts
   to a bogus used id by marking the vq broken, permanently.

**Fix:** mirror the `BlockBackend` discipline in `TapNetBackend` — a
`parked` flag the worker raises before sleeping (with `wait_quiescent`
polling it, and `set_paused` kicking the worker out of its poll in both
directions), a per-page device-DMA dirty bitmap marked on every RX
payload copy and used-ring write and merged via `merge_dirty_pages` —
and, for hole 1, a single self-kick at the end of `activate` (both net
and blk) so a restored worker drains whatever was captured
avail-but-unprocessed. Cold boots are unaffected (the ring is empty).
Repro: 13/60 failures before, 0/60 after each of two rounds.

**Reference:** firecracker persists `avail.idx` progress inside device
state and re-processes the queue on restore for the same reason
(`src/vmm/src/devices/virtio/net/persist.rs`); the eventfd-kick
lifetime issue is unique to fork-style restore where the guest is never
told anything happened.

**Time lost:** ~2 hours, mostly spent on hypothesis 2/3 (dirty
tracking + quiescence, which were real but not the dominant failure)
before the host-side TAP counters — zero frames ever written by the
fork's VMM — pointed at the kick path. The lesson generalises: **every
piece of virtio progress state must either live in guest memory or be
explicitly reconstructed on restore.** Kicks live in host eventfds;
they must be reconstructed.

---

## 80. The "ghost dispatcher": a hardcoded default node made cross-run interference untraceable 

**Symptom:** while verifying the referenced work with five consecutive `make
remote-check` runs, `make check` jobs kept appearing on k7-node-03 —
surviving process kills and even a provider hardware reset — and their
inner-k3s pods (fixed names, `runtimeClassName: k7`, scheduled across
all three outer nodes) collided with the verification runs on
k7-node-02 (`kubectl apply` nodeSelector conflicts, `TUNSETIFF: Device
or resource busy` from daemon-created TAPs). It read as "another agent"
but the agent listing showed only one running agent.

**Root cause:** `utils/ssh-setup.sh` had `NODE_IP="${K7_NODE_IP:-<node-ip>}"`
— a silent default fallback (the exact pattern this repo bans in code,
hiding in the tooling). Any dispatcher holding the shared `K7_SSH_KEY`
but running *without* `K7_NODE_IP` in its environment — an automation
or stale session with an old checkout — silently landed its 25-minute
suites on node-03. Nothing recorded who dispatched a run: auth.log
showed only rotating AWS NAT egress IPs (indistinguishable between
agents), and every one of 613 logins used the same shared key.

**Fix:** `ssh-setup.sh` now fails loud when `K7_NODE_IP` is unset, and
`remote-run.sh` stamps `$RUN_DIR/origin` (host, `CURSOR_CONVERSATION_ID`,
user, timestamp) on every dispatched run. the referenced work adds the broader
test-isolation work (per-run resource names, stranded-resource sweep).

**Reference:** none.

**Time lost:** ~1.5 hours of kill/reset/re-verify whack-a-mole across
two turns before the fallback line was found.

---

## 81. `let FOO = unique_name(FOO)` does not shadow a `const FOO`

**Symptom:** `test_cni` failed to compile on remote-check:
`expected String, found &str` / "`POD_NAME` is interpreted as a
constant, not a new binding".

**Root cause:** Rust does not let a `let` bind the same identifier as
an in-scope `const`. `let POD_NAME = common::unique_name(POD_NAME)`
is a type error, not a shadow. The same pattern was about to hit
every `test_volumes` const.

**Fix:** bind a distinct snake_case local (`let pod_name =
common::unique_name(POD_NAME)`) and use that at apply/wait/delete
sites. Constants stay as the unsuffixed base name.

**Reference:** none.

**Time lost:** one remote-check cycle (~3 min to the first kubectl
binary after the boot/fork suites).

---

## 82. `k7-test-run` YAML label decoded as a number

**Symptom:** After the referenced work isolation, `test_exec_pty_*` failed with
`unable to decode "STDIN": json: cannot unmarshal number into Go
struct field ObjectMeta.metadata.labels of type string`. Other tests
that used the same `stamp_test_labels` helper passed.

**Root cause:** `run_id()` is 6 hex chars. When all six happen to be
digits (`123456`), unquoted YAML `k7-test-run: 123456` is a number,
and kubectl's YAML decoder rejects it for `metadata.labels` (string
map). Hex-with-a-letter run ids never hit this.

**Fix:** Always quote the label value: `k7-test-run: "{rid}"`.

**Reference:** Kubernetes `ObjectMeta.labels` is `map[string]string`.

**Time lost:** ~15 min

---

## 83. Unique inner3 cluster-id left warm-fork tests looking for `k7-br-inner3`

**Symptom:** `test_inner_k3s_cluster_warm_fork_no_restart` and
`…_via_annotation` panicked `inner3 bridge missing: ["k7-br-i33fadb0"]`
after the per-run isolation rename. The three-node ready test passed.

**Root cause:** pods already used `inner3_cluster_id()` (`i3` + 6 hex,
to stay ≤ 9 chars for `k7-br-{id}` / IFNAMSIZ). The two warm-fork
tests still hardcoded `source_bridge = "k7-br-inner3"`.

**Fix:** `inner3_bridge()` derived from `inner3_cluster_id()`.

**Reference:** none.

**Time lost:** one remote-check cycle through the inner-k3s binary.

---

## 84. `unique_name` left `test_shim` passing `String` where `&str` is required

**Symptom:** first compile of `test_shim` after the isolation rename
failed with 18 `E0308` errors (`expected &str, found String`) at
`wait_for_pod_ready`, `pod_vm_id`, `pod_jsonpath`, and `kubectl`
argv sites. Earlier remote-check rounds never reached this binary.

**Root cause:** `let pod = unique_name(...)` is `String`; helpers
still take `&str`. Most call sites were already borrowed; the
fork-source / stats / scratch tests were not.

**Fix:** borrow at those sites (`&src`, `&fork`, `&pod`, …).

**Reference:** none.

**Time lost:** one remote-check cycle to `test_shim`.

---

## 85. `make test` wiped the shared cluster at the start of every suite

**Symptom:** launching two `make check` runs at once (the the referenced work
criterion) had both nodes execute
`kubectl delete pod -l '!component' -A --force`. That deleted
cilium/coredns/k7-agent/Longhorn and would also delete the other
run's live `test-*` pods (they carry `k7-test-run`, not `component`).

**Root cause:** leftover pretest hygiene from before per-run names.
Unique names + a 30-minute label sweep already cover crashed-run
residue; the Makefile wipe was the remaining cross-run collision.

**Fix:** drop the cluster-wide delete. Keep node-local pkill/umount
cleanup. Stale cluster objects stay the sweep's job.

**Reference:** `internal notes` had already
narrowed a similar delete to `-n default`.

**Time lost:** noticed at the start of the two-node concurrent run.

---

## 86. k3s starts before the sidecar finishes airgap import — CoreDNS ImagePullBackOff 

**Symptom:** `test_inner_k3s_coredns_dns_fork` saw `kube-system/coredns`
exist with `readyReplicas=0` for the full 300 s poll. Pause pods in the
same fixture (applied after nodes Ready) had always worked.

**Root cause:** the sidecar imports every `/airgap/*.tar` *after*
containerd's socket appears, then touches `/cri/pause-imported`. The
k3s container only waited for the socket, then `exec`'d. k3s applies
bundled manifests (CoreDNS) immediately; kubelet raced the import and
tried to pull `rancher/mirrored-coredns-coredns:1.12.1` on an isolated
bridge with no registry. `imagePullPolicy: IfNotPresent` does not help
when the image is not there yet. The default profile never hit this:
its inner pause pods are applied only after the 3-node Ready loop,
which is well after import.

**Fix:** the k3s entrypoint waits for `/cri/pause-imported` before
`exec /bin/k3s`. One marker, no second disable-string path.

**Reference:** none — fixture-local race.

**Time lost:** one full `make remote-check` (~19 min of inner-k3s) to
see `readyReplicas=0` with no pod dump.

---

## 87. CoreDNS CrashLoop: optional `/etc/coredns/custom` mkdir on a RO rootfs 

**Symptom:** after the airgap-import race (#86) was fixed, kubelet
reported the CoreDNS image `already present on machine` but the pod
stayed `CrashLoopBackOff` / `StartError`.

**Root cause:** k3s's bundled CoreDNS container sets
`readOnlyRootFilesystem: true` and mounts an *optional*
`coredns-custom` ConfigMap at `/etc/coredns/custom`. The image has
`/etc/coredns` but not `custom/`. Nested runc tries to `mkdirat` the
mountpoint on the already-RO rootfs:

`create mountpoint for /etc/coredns/custom mount: mkdirat
…/rootfs/etc/coredns/custom: read-only file system`

Host k3s never hits this (different runc/snapshotter ordering). The
default Corefile does not need the custom dir.

**Fix:** after the Deployment appears, copy `Corefile` + `NodeHosts`
from the ConfigMap onto the shared `/cri` emptyDir **on every member**
and JSON-patch the Deployment to (1) drop the custom volumeMount, (2)
replace the ConfigMap volume with `hostPath: /cri/coredns-config` so
sidecar runc sees regular files, (3) clear `readOnlyRootFilesystem`,
(4) pin `nodeSelector` to `inner-server`. Staging only the server is
not enough: k3s topologySpread lands CoreDNS on an agent and kubelet
then fails `hostPath type check: /cri/coredns-config is not a
directory`. Not a second `--disable` path.

**Reference:** none — nested runc + upstream manifest.

**Time lost:** three 8-minute bring-ups; custom mkdir, then empty
Corefile, then agent-scheduled hostPath miss.

---

## 88. CoreDNS CrashLoop: projected SA token empty to sidecar runc 

**Symptom:** after the Corefile hostPath (#87) CoreDNS scheduled on
`inner-server` and started, then exited immediately:

`plugin/kubernetes: open /var/run/secrets/kubernetes.io/serviceaccount/token: no such file or directory`

**Root cause:** kubelet injects a projected `kube-api-access-*` volume
in the k3s container's mount ns. Sidecar runc sees an empty bind — the
same nested-runc hole as CHALLENGES #50 (why inner pause/DNS-probe
pods set `automountServiceAccountToken: false`). CoreDNS's kubernetes
plugin cannot run without that token.

**Fix:** mint a 2h bound token (`kubectl create token coredns`) plus
`kube-root-ca.crt` onto `/cri/coredns-sa` on every member; JSON-patch
`automountServiceAccountToken: false` and mount that hostPath at the
SA path. Not a second `--disable` path.

**Reference:** CHALLENGES #50, #87.

**Time lost:** one 8-minute bring-up after the hostPath pin.

---

## 89. Ingress-profile airgap import ENOSPC on the sidecar containerd tmpfs 

**Symptom:** `test_inner_k3s_ingress_fork` never reached Running. The k3s
container timed out on `/cri/pause-imported`; sidecar containerd exited
during `ctr images import /airgap/traefik.tar`:

`write …/overlayfs/snapshots/…/usr/local/bin/traefik: no space left on device`

**Root cause:** the sidecar mounts a **512 Mi** tmpfs on
`/var/lib/containerd` (sized for pause + CoreDNS + busybox). This
profile also stages Traefik (~56 Mi compressed, much larger extracted)
and `klipper-helm`. Extracted layers overflowed 512 Mi. The 180 s
import-wait then failed loud as "airgap images not imported".

**Fix:** derive the containerd tmpfs from the profile's
`sidecar_memory_mb` (limit − 128 Mi, so the default profile stays
512 Mi). `ingress_3node()` sets `sidecar_memory_mb = 1536` (1408 Mi
tmpfs). Also **wipe** `/tmp/k7-inner3-airgap` at the start of each
stage: the sidecar imports every `*.tar`, so a leftover `traefik.tar`
from this profile poisoned later default-profile tests with the same
ENOSPC.

**Reference:** none — fixture-local disk budget.

**Time lost:** one full `test_inner_k3s` binary (~15 min) to see the
import fail after helm/traefik tars were added.

---

## 90. Helm-install etc-hosts is a file to kubelet and a directory to sidecar runc 

**Symptom:** `helm-install-traefik` / `helm-install-traefik-crd` pods
(ordinary, not hostNetwork) stayed `CrashLoopBackOff` with

`error mounting "…/etc-hosts" to rootfs at "/etc/hosts": create
mountpoint for /etc/hosts mount: cannot create subdirectories in
"…/rootfs/etc/hosts": not a directory`

CoreDNS started after the #87/#88 hostPath patch. A one-line flattener
in the k3s `args: |` block also made `kubectl apply` fail
(`yaml: line 140: could not find expected ':'`).

**Root cause:** kubelet writes `pods/<uid>/etc-hosts` as a regular file
on its `/var/lib/kubelet` tmpfs. The sidecar bind-mounts
`/cri/kubelet-pods` and sees an empty *directory* at the same relative
path (device 34 vs 17 in the same k3s container). runc therefore treats
the source as a directory and tries to mkdir the image's `/etc/hosts`
file. An earlier flatten that `umount`ed rshared projected volumes
detached `/var/lib/kubelet/pods` from `/cri`, which is how the two
views diverged. Putting that flatten in the k3s `|` block as a
one-liner with `:` / `$(…)` was also enough to break YAML parse.

**Fix:** point both containers' `/var/lib/kubelet/pods` at `/cri`
with a symlink (k3s also bind-mounts `/cri/kubelet-pods` onto itself
and marks it rshared) so kubelet file writes are the sidecar's runc
sources — no copy race. A `/cri/flatten-vols.sh` heredoc still copies
any leftover file-vs-dir mismatches. Do **not** umount kubelet volume
trees (that was detaching the old bind). Client `kubectl apply
--dry-run` pins the ingress pod YAML.

After the symlink, helm *starts* but `helm ls` talks to
`localhost:8080` (projected SA empty inside the container — #88) and
`helm install` of the bundled chart fails
`x509: certificate signed by unknown authority`. Job `spec.template` is
immutable and helm-controller objectset-applies the stock Job, so
delete/recreate never wins. The test copies the klipper-helm binary
onto `/cri` (ctr run as uid 0 into a sidecar tmpdir — the image USER
cannot write `/cri`) and `helm upgrade --install`s the bundled chart
tarballs with the k3s admin kubeconfig, then patches Job status
`SuccessCriteriaMet` + `Complete` (k8s 1.32 rejects `completionTime`
without both).

**Reference:** CHALLENGES #50, #87, #88. helm-controller Jobs are not
hostNetwork (`dnsPolicy: ClusterFirst`); the etc-hosts hole is the
nested two-container CRI, not hostNetwork.

**Time lost:** two inner-cluster bring-ups plus a 14 s YAML-parse miss.

---

## 91. local-path hostPath is the sidecar's path, and the provisioner ConfigMap is empty to runc 

**Symptom:** enabling k3s `local-storage` in the inner cluster is not
enough for a PVC to `Bound`. The provisioner CrashLoops on a missing
SA token / empty `/etc/config`, and helper pods that do start mkdir
a directory the consumer pod cannot see.

**Root cause (two nested-runc holes, same family as #87/#88/#90):**

1. **hostPath is resolved in the sidecar containerd mount ns, not
   k3s's.** The bundled default root is `/var/lib/rancher/k3s/storage`,
   which the k3s container mounts as guest tmpfs. Sidecar runc sees a
   different (empty) path at that name. Helper `mkdir` and the PVC
   consumer's hostPath therefore do not share files unless both
   containers bind the same `/cri/k3s-storage` directory there.
2. **ConfigMap + projected SA are empty to sidecar runc** — the
   provisioner needs `local-path-config` (`config.json`, setup/teardown,
   `helperPod.yaml`) and an API token. Same fix as CoreDNS: copy the
   files onto `/cri`, mint `kubectl create token
   local-path-provisioner-service-account`, JSON-patch the Deployment
   to those hostPaths, `automountServiceAccountToken: false`, pin to
   `inner-server`. Helper pods get `automountServiceAccountToken:
   false` in the staged `helperPod.yaml` so they do not inherit the
   projected-token hole.

The PVC bytes then live on `/cri` emptyDir (guest RAM), which is why
a CoW warm fork preserves them and why they are not durable across a
VM restart. Unpinned reader/writer pods hang `Pending`: local-path
PVs are node-affine (`WaitForFirstConsumer`); pin to the original
writer's `kubernetes.io/hostname`.

A first run Bound the PVC and the original writer could `cat` its
marker, but a REST-created reader on the **source** (not even the
fork) exited 1: `/data/marker` was missing. `find` on
`/cri/k3s-storage/pvc-…` showed the directory and **zero files**.
The writer had been writing into kubelet's per-pod volume dir in the
sidecar ns, not into the PV: kubelet (k3s mount ns) bind-mounts the
local path onto `/var/lib/kubelet/pods/<uid>/volumes/…`, and that
bind does not propagate into sidecar runc unless `/cri/kubelet-pods`
is itself a rshared bind in **both** containers (k3s already did
this for #90; the sidecar only had `rshared /cri`). Rewrite
`config.json` to `paths: ["/cri/k3s-storage"]` and rshared-bind
`/cri/kubelet-pods` in the sidecar so the local-volume bind is the
PV for every subsequent pod.

**Fix:** rewrite the provisioner config onto `/cri/k3s-storage`;
`patch_local_path_for_nested_runc`; after the PVC is Bound, mount that
provisioned path as **hostPath** in writer/reader pods. A PVC volume
mount is kubelet's local-volume bind and is empty to sidecar runc —
the same class of hole as #87/#88. REST POST/DELETE of node-pinned
busybox pods through `--interface` after the fork.

**Reference:** CHALLENGES #50, #87, #88, #90. k3s
`manifests/local-storage.yaml` (v1.32.5).

**Time lost:** preempted from the CoreDNS/Traefik series; recorded so
the next add-on does not rediscover the sidecar hostPath split.

---

## 92. The bundled add-on's image ref is not greppable in the k3s binary — and the kernel gap metrics-server was supposed to need does not exist 

**Symptom:** two dead ends before a line of the metrics-server profile
was written.

1. Pinning the add-on image needs the exact ref the *pinned* k3s image
   deploys, so `ctr run --rm $K3S_IMAGE … grep -ao
   "mirrored-metrics-server:[A-Za-z0-9._-]*" /bin/k3s` — the obvious
   move, since the manifests live inside that binary. It matched
   nothing, after 40 s of image pull and container start.
2. The spec expected a guest-kernel stats gap ("candidates in the
   cgroup-stats family, e.g. PSI or additional cgroup accounting") and
   a `config-minimal` edit plus an on-node `./build.sh`.

**Root cause:**

1. k3s embeds `manifests/` **gzip-compressed** (`pkg/deploy`
   bindata), so no image ref appears as plain text in `/bin/k3s`. The
   host node's `/var/lib/rancher/k3s/server/manifests/` is the wrong
   answer too — it belongs to the *host's* k3s (v1.36.3 →
   metrics-server v0.9.0), not the inner cluster's pinned v1.32.5
   (→ v0.7.2). Reading the host's copy would have pinned an image the
   inner cluster never asks for, and the failure would have surfaced
   as `ErrImageNeverPull` two bring-ups later.
2. Nothing was missing. `CONFIG_MEMCG` + `CONFIG_CGROUP_CPUACCT` +
   `CONFIG_CFS_BANDWIDTH` (the block CHALLENGES #51 landed) already
   satisfy what kubelet's cAdvisor reads for `/metrics/resource`, and
   node-level CPU/memory come from `/proc/stat` and `/proc/meminfo`,
   which need no config at all. The first bring-up served numeric
   `kubectl top nodes` for all three members.

**Fix:** read the ref from the upstream tag that matches the pinned
image —
`raw.githubusercontent.com/k3s-io/k3s/v1.32.5+k3s1/manifests/metrics-server/metrics-server-deployment.yaml`
— then resolve `:v0.7.2` to a digest against the registry and pin
both. For the kernel: no edit, no rebuild. The generalisable rule is
the one #72 already states from the other direction — **measure the
guest before editing `config-minimal`**; a spec's suspicion is a
hypothesis, and here the anticipated symbol list would have added
unused options behind a `config-drift-allowed` entry nothing needed.

The only real nested-runc hole was the familiar one: metrics-server
uses its projected SA token both to reach the apiserver *and* to
authenticate to every kubelet and verify their serving certs against
the same `ca.crt`, so the empty-projected-volume hole (#88) takes out
the whole scrape path at once. The `tmp-dir` emptyDir needed nothing:
kubelet creates emptyDir directories mode 0777 under
`/var/lib/kubelet/pods`, which both containers symlink into `/cri`
(#90), so `--cert-dir=/tmp` is writable by uid 1000 under sidecar runc.

**Reference:** CHALLENGES #51, #72, #88, #90. k3s
`manifests/metrics-server/` (v1.32.5), metrics-server v0.7.2.

**Time lost:** ~15 minutes of probing (a 40 s `ctr run` grep plus the
host-manifest false lead); the kernel rebuild the spec budgeted for
was never needed.

---

## 93. NetworkPolicy in the guest was three kernel gaps deep — and the third hid behind the iptables backend 

**Symptom:** with `--disable-network-policy` dropped, the connectivity
baseline passed but a default-deny-ingress policy never denied
anything. Three distinct failures, one per guest-kernel rebuild:

1. `level=warning msg="Skipping network policy controller start, ipset
   save failed: ipset v7.16: Kernel error received: Invalid argument"`
   — the controller never starts, and it's a *warning*, so the cluster
   looks healthy while policies are silently decorative.
2. With ipset in: the controller starts, programs its chains, then
   every sync dies with `Aborting sync. Failed to run iptables-restore:
   exit status 4 (Warning: Extension NFLOG revision 0 not supported …
   Warning: Extension limit revision 0 not supported … RULE_APPEND
   failed (No such file or directory): rule in chain KUBE-POD-FW-…)`.
3. With `CONFIG_NETFILTER_XT_TARGET_NFLOG` + `CONFIG_NETFILTER_XT_MATCH_LIMIT`
   in and verified via `/proc/config.gz`: the xt revision warnings
   disappear but the *same* `RULE_APPEND failed (No such file or
   directory)` remains, still on the per-pod chain's NFLOG rule.

**Root cause:** k3s's embedded netpol controller (kube-router lib
v2.2.1) needs, in the guest kernel: the ipset netlink subsystem
(`ipset save` is its startup probe; sets are `hash:ip` for pod
selectors, `hash:net` for ipBlocks) plus the `xt_set` match — and a
kernel implementation for the rate-limited NFLOG rule its per-pod
firewall chains end with. The trap in layer 3: k3s's
`iptables-restore` is v1.8.9 **(nf_tables)**, and the nft backend does
not use `xt_NFLOG`/`xt_limit` for those rules — it translates them to
the *native* `nft_log` / `nft_limit` expressions, so the xt modules
the layer-2 warnings named are necessary for the revision probe but
not sufficient for the rule. ENOENT on RULE_APPEND = missing nft
expression module, and nothing in the error says which (the same
class as #72's "kernel lies on read", one level up: the *userspace
tool* names the xt extension while actually needing the nft one).

**Fix:** `guest/kernel/config-minimal` grew, in one measured pass per
layer: `CONFIG_IP_SET`, `CONFIG_IP_SET_HASH_IP`,
`CONFIG_IP_SET_HASH_NET`, `CONFIG_NETFILTER_XT_SET`; then
`CONFIG_NETFILTER_XT_MATCH_LIMIT`, `CONFIG_NETFILTER_XT_TARGET_NFLOG`
(+ `CONFIG_NF_CT_NETLINK` for the `Failed to list conntrack entries:
invalid argument` kube-proxy/netpol conntrack cleanup spam — without
it stale-flow flushing after a policy change is a silent no-op); then
`CONFIG_NFT_LOG`, `CONFIG_NFT_LIMIT`. Rebuilt on the node per #51,
verified via `/proc/config.gz` in a booted guest per #72. With all
three layers in, enforcement flips in under a second of a policy
apply, and `test_inner_k3s_network_policy_fork` proves
deny/allow/deny-again pre-fork and on both bridges post-fork.

**Reference:** kube-router `network_policy_controller.go` (vendored in
k3s v1.32.5); iptables nft translations (`extensions/libxt_NFLOG.c`
`xlate` → `log group N`). CHALLENGES #51, #72, #92.

**Time lost:** ~1.5 h (three kernel rebuild + bring-up cycles; the
nft-vs-xt indirection in layer 3 is the part a future reader would
not guess from the final config diff).

---

## 94. `alpine/git` has no `git-daemon` 

**Symptom:** `test_inner_k3s_argocd_gitops_fork` brought the 3-node
profile up and applied an `alpine/git` Deployment as the in-cluster
`git://` server. `argocd/git` stayed `readyReplicas=0` for 180 s.
The pod got a ClusterIP, so this was not ImagePull / scheduling.
CrashLoop logs:

```
Initialized empty Git repository in /git/managed.git/
git: 'daemon' is not a git command. See 'git --help'.
```

A first misdiagnosis treated this as `git daemon` refusing uid 0
and added `adduser` + `--user=git`. That is still required once the
binary exists, but it was not why the pod died.

**Root cause:** `docker.io/alpine/git` is a **client-only** image.
`/usr/libexec/git-core` ships `git-upload-pack` and credential
helpers, not `git-daemon`. Dumb HTTP from the same image is also a
dead end (no `git-http-backend` / CGI). The guests are airgapped, so
`apk add git-daemon` at container start cannot work.

**Fix:** stay on spec candidate 1 (`git daemon` / `git://` via
ClusterIP). During airgap staging, Docker-build
`FROM alpine:3.20.3@<digest>` + `apk add git git-daemon` on the
node, import/export the result as `docker.io/k7d/git-daemon:local`,
and run the git Deployment from that image (`imagePullPolicy:
Never`). `alpine/git` stays the seed / fork-commit **client**.
`--user=git` is kept. No dumb-HTTP / Gitea fallback.

**Reference:** Alpine package `git-daemon`; the referenced work transport
order (git daemon → dumb HTTP → Gitea).

**Time lost:** one full `test_inner_k3s` binary (~43 min) plus a
targeted rerun, because libtest buffers the panic until the binary
ends and the first fix chased the wrong error.

---

## 95. Minimal ArgoCD CRD dropped Application status 

**Symptom:** repo-server cloned `git://` and the application-controller
logged `Updated sync status: → Synced` / `Updated health status: →
Healthy`, but `GET …/applications/gitops-demo` via the bridge had
**no `status` object**. The test waited 300 s on empty
`status.sync.status`.

**Root cause:** our CRD set `subresources.status: {}`. Upstream
Argo CD v2.14.11's Application CRD is `subresources: {}` — the
controller writes `status` with a regular Update, not `/status`.
With the status subresource enabled, the apiserver **strips**
status from those Updates. The controller's informer still shows
Synced/Healthy; etcd (and every GET) does not.

Declaring `properties.status` alone does not fix that.

**Fix:** drop `subresources.status` so the CRD matches upstream
(`subresources: {}`). Keep `properties.spec` / `properties.status`
+ preserve-unknown-fields. `applications/status` RBAC is harmless.

**Reference:** `argoproj/argo-cd` v2.14.11
`manifests/crds/application-crd.yaml` (`subresources: {}`).

**Time lost:** two targeted runs (~8 min after cluster up each).

---

## 96. Argo CD application-controller has no leader-election Lease

**Symptom:** after Application reached `Synced/Healthy` with a real
revision, `GET /apis/coordination.k8s.io/v1/namespaces/argocd/leases`
stayed `items: []` for 120 s. The controller was clearly looping
(it created the busybox Deployment).

**Root cause:** the referenced work assumed the application-controller
holds a `coordination.k8s.io` Lease the way kube-controller-manager
does. Upstream never shipped that. Replicas share work by **cluster
sharding** (`ARGOCD_CONTROLLER_REPLICAS`); issue argoproj/argo-cd#3073
proposed `--leader-elect` and did not land on this component. The
ApplicationSet controller *does* take a Lease, but ApplicationSet is
out of scope for this increment.

**Fix:** prove the loop is live via `Application.status.reconciledAt`
advancing across two reads ~30 s apart on each bridge. Drive the
interval with `ARGOCD_RECONCILIATION_TIMEOUT=15s` on the controller
(the `argocd-cm` `timeout.reconciliation` key is not what this
binary reads; default is 180 s). That stamp is what the controller
actually writes every reconcile — stronger than a lock it does not
hold. Documented here and in the PR; the shared Lease assertion
vocabulary from 23a-inc2 (etcd) is unchanged.

**Reference:** argoproj/argo-cd#3073; official
`argocd-application-controller` StatefulSet (no leader-elect flags).

**Time lost:** one targeted run (~2 min after Synced).

---

## 97. `test_fork_requeues_interrupted_injection` is flaky, and the guest kernel was not why 

**Symptom:** while measuring the 24a-inc1 guest kernel, the the referenced work
regression test `test_fork_requeues_interrupted_injection` produced a
fork that was permanently deaf on vsock — exactly the #78 failure it
exists to guard against. First samples read as a regression the new
kernel had introduced: 0 failures in 10 runs on the old `vmlinux`,
4 in 20 on the new one.

**Root cause:** not the kernel. A 40-iteration arm on each `vmlinux`
(`examples/inject_repro.rs`, the only variable being which kernel the
guest boots) came back **9/40 failures on the old kernel and 4/40 on
the new** — pre-existing, and if anything less frequent after this
increment. The initial 0/10 was a small sample of a ~10-25% flake.

What the loop does pin down is that the flake belongs to the test's
*forcing*, not to the fork path:

- vector `0` (no forced injection, otherwise identical) — 0 failures
  in 150 iterations, matching `fork_repro`'s clean runs
- any non-zero vector reproduces, so it is not the `0x35` the test picks

That points at the forced state being one KVM never produces. A real
cancelled injection (#78) was staged by KVM only because the guest was
interruptible at that instant and the 8259 had ACKed the vector, so the
capture carries a matching in-service bit. The test synthesises neither:
it sets `interrupt.injected=1` on a capture taken at an arbitrary pause
point. `KVM_SET_VCPU_EVENTS` then *pre-stages* that injection, so it is
delivered at the fork's next VM entry regardless of `IF`, interrupt
shadow, or what the guest was in the middle of — the interruptibility
check already happened, in the natural case, before staging.

So the fork enters a vector its controller never ACKed at a point the
guest never agreed to be interrupted. Two downstream mechanisms fit and
this increment did not separate them: the handler re-entering a driver
whose lock the interrupted code holds (permanently deaf vsock, VM
otherwise healthy — the observed symptom), or the handler EOIing an
interrupt that is not in service, which on an 8259 clears the
highest-priority in-service bit instead and strands a *different* IRQ.
The second explains the vector-independence more comfortably. Either
way it is #78's end state reached through the test's own input, not
through a fork-path bug. Not confirmed by reading back PIC state on a
failing iteration — that is the next step for whoever takes it.

**Fix:** none applied — deliberately out of scope for a guest-kernel
increment, since any fix is a change to `k7d`'s restore path or to what
the test forces. Reported rather than absorbed, and not worked around
with a retry or `#[ignore]` (`editor-config/rules/k7d-workflow.mdc`). The
assertions the test exists for — that restore re-queues the injection
and zeroes exception state — pass every iteration; it is only the
post-`start` vsock probe that flakes. Whoever picks this up should
decide whether the test should force a *self-consistent* capture (set
the PIC in-service bit alongside the injection) or whether restore
should reconcile the two; `inject_repro.rs` and its vector-`0` control
arm are the measurement rig.

**Reference:** builds on #78 (cancelled-injection deafness) and its
8259 in-service semantics; no upstream issue.

**Time lost:** ~1.5 hours, most of it spent believing a 10-run sample.
The lesson is the cheap one: before attributing a flake to the change
under test, run the control arm at the same sample size — the old
kernel was worse.

---

## 98. `VM_BOOT_TO_AGENT` is a bare-VM budget, and a networked VM already spends most of it 

**Symptom:** the new `test_nodeusr_image_does_not_regress_boot` asserted
what the spec's hygiene checkbox asks — that a guest with the erofs
userspace attached still reaches the agent inside `VM_BOOT_TO_AGENT` —
and failed at 256 ms against the 250 ms budget, on both of its first
two runs. The obvious reading is that a second virtio-blk device and a
60 MB image cost 6 ms too much.

**Root cause:** the obvious reading is wrong, and the test was asking
the wrong question. `latency::VM_BOOT_TO_AGENT` is calibrated on the
shape `test_latency::test_latency_vm_boot_to_agent` boots: 256 MB, one
virtiofs share, **no network**. Five runs of it on the node measured
225–245 ms, so that shape already sits within ~5 ms of its own ceiling.
The storage test's VM is a different shape — it needs a TAP to reach
`10.200.0.1` at all — and a TAP-equipped VM with no block device at all
measured 235 ms (best of 5). The erofs image itself costs ~11 ms on top
(246 ms best of 5): one more virtio-mmio device to probe and one more
`mount` before the agent listens, which is the price the design
deliberately pays instead of the initramfs's per-VM decompression.

So an absolute assertion in this test would have made it own the cost
of virtio-net, and gone red for a change to networking that had nothing
to do with storage.

A delta assertion at 15 ms then failed too, at 20 ms — and *that* is
where the second, more useful thing turned up. Printing every sample
instead of the minimum showed the measurements are not continuous:

```
without the image: 236.0 235.9 236.2 235.9 236.0 235.9 245.8 236.6 236.1
with the image:    255.8 256.5 256.7 256.4 256.0 246.4 256.0 256.4 256.3
```

Every value sits on ~226, ~236, ~246 or ~256 and nothing lands between.
`Vm::connect_agent` polls the serial buffer for the agent's listen
marker every 10 ms (`vm.rs`, `thread::sleep(Duration::from_millis(10))`),
so **boot-to-agent is quantized to 10 ms by the instrument**. A cost
smaller than one step reads as either 0 or 10 ms depending on where in
the poll interval it falls, which is exactly what three consecutive
runs produced: minimum deltas of 0.3 ms, 10 ms and 10.5 ms for the same
unchanged image.

**Fix:** measure the same VM twice, with and without the image,
**interleaved** (a node that gets busy halfway through would otherwise
land entirely on whichever arm ran second and read as that arm's cost),
and assert on the difference between the two minima with a 20 ms
allowance — two of the instrument's steps, documented as such at the
constant. Every sample is printed on every run. The budget itself was
not touched; 24a-inc1's precedent is that a budget regression is a
finding to report, so here are both findings:

- **A k7d VM with a TAP boots to agent in ~236 ms, leaving ~14 ms of
  the 250 ms budget**, and anything attaching a device to a networked
  VM is spending from that margin. `VM_BOOT_TO_AGENT` is calibrated on
  a shape with no network. Whoever needs headroom should split the
  budget by VM shape or go after what virtio-net adds, not raise the
  number.
- **`VM_BOOT_TO_AGENT` cannot be measured more finely than 10 ms**
  while `connect_agent` polls at that interval. Every boot-latency
  number in this repo carries that resolution, and no experiment that
  compares two configurations differing by less than a step can
  conclude anything from a single sample. Making the poll adaptive
  (or having the agent's readiness signal wake the waiter) would buy
  real resolution back for cheap.

**Reference:** 24a-inc1 finding 1 (iproute2 in the initramfs, ~16 ms)
measured the same class of cost on the other delivery mechanism; no
upstream issue.

**Time lost:** ~45 minutes across four measurement runs. The cheap
lesson is the second one: when a latency delta refuses to settle, print
the raw samples before touching the threshold — the distribution said
"instrument resolution" in one glance, and no amount of re-running the
minimum was ever going to.

---

## 99. The packaged `tgt.service` squats `0.0.0.0:3260`, and `tgtadm --control-port` is not a port 

**Symptom:** three separate stumbles standing up a host-side iSCSI
target for `test_iscsi_nfs.rs`, none of which the spec named:

1. `apt-get install tgt` starts `tgt.service` immediately, and its
   `ExecStart=/usr/sbin/tgtd -f` binds `0.0.0.0:3260`. A test daemon
   binding `10.200.0.1:3260` then fails with `EADDRINUSE`.
2. `tgtadm --control-port 33261` exits with
   `-C argument value '33261' out of range`.
3. A probe script's `pkill -f "portal=127.0.0.1:33260"` killed the SSH
   session running it.

**Root cause:** (1) is the shared-node hazard the spec's trap 5 warns
about, arriving from a direction it did not name — not "don't run the
node's services into the ground" but "installing the package *is*
running a service", and on a public bare-metal node that service is an
unauthenticated iSCSI target reachable from the internet. (2) the
`--control-port` is an *index* into tgt's abstract-namespace mgmt socket
(`tgtd.ipc_abstract_namespace.N`), not a TCP port, and `tgtadm` range-
checks it against roughly 0–1023; the name invites the wrong value.
(3) `pkill -f` matches the whole command line of *every* process,
including the `bash -c` that ssh runs — which contains the pattern.

**Fix:** `your node provisioning` installs `tgt` for its
binaries and then `systemctl disable --now tgt`, with the reasoning
inline; the test runs its own `tgtd` bound to the bridge gateway and
kills it by `Child` pid in a `Drop` guard, never by pattern. The
control-port index is derived as `100 + pid % 900` so two suites on one
node cannot share a mgmt channel. `nfs-kernel-server` gets the opposite
treatment and stays enabled, because `nfsd` cannot be scoped by address
at all — only by export ACL, which is why the export is created with
`exportfs -o … 10.200.0.0/24:<dir>` and `/etc/exports` is never touched.

**Reference:** `tgt` 1.0.85, `/usr/lib/systemd/system/tgt.service`; no
upstream issue.

**Time lost:** ~20 minutes across three probe cycles, which is the
argument for probing host-side plumbing by hand before wrapping it in
Rust.

---

## 100. Cilium's agent dies on two files a minimal kernel does not have, and neither is about eBPF 

**Symptom:** every `cilium-agent` in the inner cluster went
`CrashLoopBackOff` with the whole datapath never loading, twice in a row
for two unrelated reasons — and both times the *cluster* symptom was the
one 24a-inc1 warned about (nodes `NotReady`, no CNI), which points at the
datapath and the eBPF config, neither of which was the problem:

```
level=fatal msg="failed to start: ... kernel-modules-manager:
  failed to retrieve loaded modules names: failed to open loaded modules
  information at /proc/modules: no such file or directory"
```

then, after that was fixed:

```
level=fatal msg="failed to start: daemon creation failed: error while
  initializing daemon: failed while reinitializing datapath: failed to
  delete xfrm policies on node configuration changed: protocol not
  supported"
```

**Root cause:** `config-minimal` was built for a guest that will never
load a module and does not do IPsec, so it had `# CONFIG_MODULES is not
set` (with an explicit "No modules" comment defending it) and no `XFRM`
at all. Both are correct statements about the guest and wrong statements
about what Cilium's *startup* touches:

- `/proc/modules` only exists if `CONFIG_MODULES=y`. Cilium's
  kernel-modules-manager reads the loaded-module list before any
  datapath work, from a `Start` hook that is fatal on error. It does not
  care that the list is empty — it cares that the file opens. Every real
  node has it.
- Clearing xfrm policies is unconditional in datapath
  (re)initialisation, encryption enabled or not, and it needs a
  `NETLINK_XFRM` socket. `CONFIG_XFRM` is a non-prompting symbol nothing
  else in this config selected, so `socket(AF_NETLINK, …,
  NETLINK_XFRM)` returned `EPROTONOSUPPORT` — which surfaces as
  "protocol not supported" inside a message about xfrm policies, and
  reads like an IPsec misconfiguration rather than a missing kernel
  option.

**Fix:** `CONFIG_MODULES=y` (with `MODULE_UNLOAD`/`MODULE_SIG`/
`MODULE_COMPRESS` left off — the loader is there for `/proc/modules`,
not to load anything) and `CONFIG_XFRM_USER=y`, which selects
`XFRM_ALGO` and thus `XFRM`. Both are in `REQUIRED_CONFIGS` in
`test_kernel_features.rs` and both got a functional probe in a booted
guest next to the existing ones: `/proc/modules` exists and is empty,
and `ip xfrm policy show` succeeds — that command opens exactly the
socket Cilium needs, so it fails where it is cheap to read instead of
inside a CrashLoopBackOff four layers down.

**Reference:** Cilium 1.16.10 `pkg/datapath/linux/modules` and
`pkg/datapath/linux/node_config`; neither option appears in Cilium's own
[system requirements](https://docs.cilium.io/en/v1.16/operations/system_requirements/),
which lists the eBPF and tc options and assumes a distro kernel for
everything else. That assumption is the trap: the published list is
necessary and not sufficient for a purpose-built kernel.

**Time lost:** ~35 minutes, almost all of it in two ~15-minute
kernel-rebuild cycles. The lesson is where to look, not what to set:
when a CNI DaemonSet crashloops on a k7d guest, read the agent's
**last fatal log line** before reading the eBPF config — twice in a row
the answer was a `/proc` or netlink surface the guest simply lacked, and
neither would ever have been found by re-reading the datapath options.

---

## Reference projects and what each taught us

| Project | What we learned |
|---------|----------------|
| **Firecracker** | MMIO register layout, boot params fields, GDT/segment setup, page table identity mapping, E820 memory map, interrupt_status pattern for vhost devices, ioeventfd for QUEUE_NOTIFY |
| **crosvm** | `VIRTIO_F_ACCESS_PLATFORM` must be cleared for vhost backends, vhost ioctl ordering (features → mem_table → vring setup → cid → start) |
| **Cloud Hypervisor** | Kernel loading via linux-loader, virtio-fs device tree setup, vhost-user connection pattern |
| **Linux kernel source** | vhost-vsock queue count (2 not 3), `vhost_vq_access_ok()` validation path, ENOBUFS meaning (`idx >= dev->nvqs`) |
