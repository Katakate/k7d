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

**Follow-up:** `SnapshotTree::fork_batch` / `ClusterSnapshotTree::fork_batch`
now call `prepare_fork_source` on the source when members have no
`fork_source_base_path` (same policy as daemon `fork_vm`). Control op
`tree_prepare_fork_source` exposes that checkpoint as its own step.
Parent ids stay k7d's — a child fork is a real depth-2 node, not a
flattened retry from root.

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

## 101. vhost-vsock's kernel DMA was the one device write nobody reported to the warm-fork dirty delta (PR 118 salvage)

**Symptom:** none observed — this is the hazard #56 left open, closed
deliberately rather than after a failure. It was found while reviewing an
abandoned branch (PR 118) that had been written against the same the referenced work
symptom #78/#79 turned out to explain.

**Root cause:** a warm fork copies `base.mem` plus the pages
`KVM_GET_DIRTY_LOG` reports, and that log only sees vCPU writes. #79 gave
the userspace virtio-net and virtio-blk workers their own device-DMA
bitmaps for exactly this reason, but vhost-vsock has no userspace worker to
carry one: the kernel module DMA-writes the used ring and RX payloads
directly. `VirtioBackend::merge_dirty_pages` defaulted to a no-op and its
doc comment claimed vhost devices take the full-memfd fork path — vsock-only
VMs do not (`test_emptydir_tmpfs_shared_and_survives_fork` asserts the CoW
path). A fork whose vsock rings moved after `prepare_fork_source` therefore
inherited them as of `base.mem`, and `activate_with_bases` programmed
`VHOST_SET_VRING_BASE` from that stale `used.idx`. The `.cursor` rule
saying vsock "side-steps the worker-counter bug kernel-side via
`VHOST_SET_VRING_BASE`" holds only if the ring pages themselves are fresh.

Why it never showed up as a failure: an idle guest's rings do not move in
the fork window, and a vCPU write sharing the ring page copies the right
bytes by accident. The Ubuntu bare-VM guests of the referenced work are busier, which
is what made closing it now worth the churn.

**Fix:** `MmioDevice::merge_dirty_pages` marks every ready vsock virtqueue's
descriptor table, avail ring, and used ring, and walks the descriptors to
mark the buffers they point at (RX payloads vhost writes). Bounded to vsock
on purpose: its queues are 256 descriptors of at most a page, while a net or
blk `len` is legitimately megabytes — PR 118 walked every device first and
pushed `test_inner_k3s_cluster_warm_fork_no_restart` over its 1 s `TreeFork`
budget (1.031 s), which it then proposed to widen to 2 s. Indirect
descriptors and any buffer outside `mem_span` are skipped.

**Deliberately not taken from PR 118:** freezing the kernel worker
(`SET_RUNNING` 0 + `GET_VRING_BASE`) around the multi-second `memory.bin`
dump and persisting those bases in `devices.json`. That is the remedy #56
prescribes for dump-window tearing, it is a real remaining gap, and it is
also the ioctl pair #56 already reverted once for breaking live sources —
so it wants the repro loop and its own increment, not a drive-by. Spec
26a-inc1 carries it.

**Reference:** CHALLENGES #27, #56, #79; Linux `drivers/vhost/vsock.c`
(used-ring updates outside KVM's view); PR 118 (closed unmerged).

**Time lost:** none on the bug; the cost was reviewing a stale 16-commit
branch against a `main` that had already fixed the symptom differently.

---

## 102. Leftover Cilium dataplane kills standalone k3s, then SSH 

**Symptom:** `make remote-check` died in `test_cni` because `systemctl
restart k3s` had no `k3s.service` — the node was a `k3s-agent` joined to
another cluster. After uninstalling the agent and installing a
standalone k3s server, flannel immediately exited:

```
failed to set interface flannel.1 to UP state: address already in use
```

UDP 8472 was held by leftover `cilium_vxlan`. After deleting
`cilium_vxlan` / `cilium_host` / `cilium_net` *and* the maps under
`/sys/fs/bpf/tc/globals/cilium*`, SSH still accepted TCP/22 but reset
during kex (`kex_exchange_identification: Connection reset by peer`).
The node was not wiped — just unreachable.

**Root cause:** a k3s-agent + Cilium join leaves a host dataplane
(vxlan on 8472, `05-cilium.conflist`, tc/BPF on the physical NIC) that
survives `k3s-agent-uninstall.sh`. Flannel and Cilium cannot share 8472.
Deleting the BPF maps while programs are still attached to `enp9s0`
breaks the host path SSH needs after the TCP handshake. A hw reset
clears the attached programs; the on-disk CNI conflist does not.

**Fix:** provider hardware reset of *this node only* (`K7_SERVERS=3040440` /
`<node-ip>`). Then `rm` leftover `/etc/cni/net.d/05-cilium.conflist`,
seed `/var/lib/rancher/k3s/agent/etc/containerd/config-v3.toml.tmpl`
with the k7 runtime (fresh k3s only writes `config.toml`), apply
RuntimeClass `k7`. Do not delete Cilium BPF maps as a first cleanup
step — take the vxlan iface and the conflist, or reboot.

**Reference:** none (host leftover from a previous agent join).

**Time lost:** ~45 minutes, most of it waiting on a node whose SSH was
half-dead after the BPF-map delete.

A second trap on the same node: after the hw reset, the share-dir
guest (`/usr/local/share/k7d/vmlinux`, 20 MiB, no `CONFIG_MODULES`)
was copied into the rsync-excluded `guest/kernel/vmlinux` so the
workspace had *a* kernel. `make check` then ran `test_inner_k3s`
against that pre-#100 image — Cilium CrashLoopBackOff on
`/proc/modules` missing, and NetworkPolicy `ipset` EINVAL. Rebuild
from `config-minimal` (needs `dwarves`/`pahole`, `flex`, `bison`,
`libelf-dev` — this node did not have them) and install the 25 MiB
result into the share dir before re-running the suite. The same reset
also left `tgt` / `nfs-kernel-server` uninstalled, so
`test_iscsi_nfs` failed loud (as designed) until
`setup-node-after-reset.sh`'s package list was applied.

---

## 103. `linux-image-virtual` has no haltpoll module, and a missing cpuidle driver looks like a config gap 

**Symptom:** the Ubuntu node booted, systemd came up clean, the clock was
exact — and the 19g idle probe failed on the first thing it reads:

```
assertion `left == right` failed: boot: cpuidle driver is "none", not haltpoll
```

Everything the minimal guest needs for haltpoll was in place:
`cpuidle_haltpoll.force=1` on the cmdline,
`haltpoll.guest_halt_poll_ns=200000`, `cpuidle_haltpoll` listed in
`/etc/modules-load.d`, and `CONFIG_ACPI_PROCESSOR_IDLE`/`CONFIG_HALTPOLL_CPUIDLE=m`
in the flavour's `/boot/config-6.8.0-138-generic`. The config said the
driver existed and the driver was not there.

**Root cause:** `cpuidle-haltpoll.ko` ships in `linux-modules-extra-*`,
not in the `linux-modules-*` set that `linux-image-virtual` pulls in.
`systemd-modules-load.service` therefore failed to load a module that
was never on the disk, and the kernel fell back to no cpuidle driver at
all. The config check could not catch this: a distro `=m` means "this
module was built", not "this module is in the package you installed" —
two different questions that look identical in `config-*`.

**Fix:** add `linux-image-extra-virtual` to the image's package list.
The test's flavour check now asserts, for every `=m` option it accepts,
that the matching `.ko` is actually present under `/lib/modules` — so
the next instance of this fails on the specific missing module instead
of on a downstream functional probe. The diagnosis came from making the
failure talk: the probe now dumps `/proc/cmdline`, `lsmod`, an explicit
`modprobe -v cpuidle_haltpoll`, the `dmesg` cpuidle/kvm lines and
`systemctl status systemd-modules-load` before it panics, and
`modprobe -v`'s "module not found" was the whole answer.

**Reference:** Ubuntu kernel packaging — `linux-image-virtual` →
`linux-modules-<ver>-virtual` (the trimmed VM set),
`linux-image-extra-virtual` → `linux-modules-extra-<ver>-generic`.
This is the same shape as the Cilium/Longhorn module question in
inc3-inc5, which is why the extra set is installed rather than
`modprobe`-ing one module by hand.

**Time lost:** ~25 minutes, most of it spent re-reading the kernel
config on the assumption that a `-virtual` flavour had dropped
haltpoll. On a distro guest, "is the option set" and "is the module
installed" are separate checks; ask the second one first.

---

## 104. `du` over a chroot that still has `/proc` bind-mounted 

**Symptom:** the Ubuntu image builder failed at the very end, after the
expensive `apt` work had already succeeded, with a burst of:

```
du: cannot read directory '/tmp/tmp.MzvpNNwvsy/proc/1234/task/...': No such file or directory
```

**Root cause:** the builder measures the finished rootfs with
`du -sk "$MNT"` for the manifest, and at that point `/proc`, `/sys`,
`/dev` and `/dev/pts` were still bind-mounted into the chroot from the
host. So `du` was not walking the image — it was walking the host's live
process tree, and racing every process that exited mid-walk. The failure
is timing-dependent, which is worse than deterministic: the same builder
can pass on a quiet host and fail on a busy one.

**Fix:** unmount the four pseudo-filesystems *before* measuring anything,
and pass `--one-file-system` to `du` so a future bind mount cannot
silently inflate `rootfs_used_kb` either. Same reasoning for the module
count, which globs `/lib/modules` in the image.

**Reference:** none — generic chroot hygiene.

**Time lost:** ~10 minutes. Worth writing down only because of where it
struck: a manifest-measuring step at the end of a multi-minute build,
which is exactly where a cheap ordering bug is most expensive to hit.

---

## 105. A bzImage needs its own setup header and a different entry point than the ELF path 

**Symptom / trap:** the ELF path builds a `boot_params` zero page from a
hand-written `setup_header` (boot protocol version, magic, cmdline
pointer, E820 map) and starts the BSP at the address the loader
reports. Reusing either of those for a bzImage produces no error and no
serial output — the decompressor either jumps somewhere unmapped or
decompresses over itself, and the VM sits there until the test's boot
ceiling expires.

**Root cause:** two differences the ELF path gets away with not knowing.
First, a bzImage's decompressor reads `setup_sects`, `init_size`,
`pref_address`, `relocatable_kernel` and the `LOADED_HIGH` bit in
`loadflags` back out of the zero page — values that describe *that
image*, so `linux-loader`'s `BzImage::load` hands its parsed
`setup_header` back and the zero page must carry it verbatim rather than
carrying a hand-built one. Second, the 64-bit entry point is
`kernel_load + 0x200` (`startup_64`, with the CPU already in long mode),
not the entry the header advertises, which is the 32-bit/real-mode one.

Also, `setup_header` is `#[repr(packed)]`, so any expression that takes
a *reference* to one of its fields is UB. `log::info!` format args and
`assert_eq!` both take references, so the natural way to log or assert
on these fields does not compile (`error[E0793]: reference to packed
field is unaligned`) — a real error worth keeping rather than papering
over with `addr_of!`: the fields are copied out by value into locals
first.

**Fix:** `load_kernel_image` selects the loader by magic bytes
(`\x7fELF` at 0, `HdrS` at 0x202) and returns `(entry, Option<setup_header>)`;
`configure_boot_params` overlays the image's header when it got one and
keeps the hand-built header otherwise. Neither is trusted to be right by
inspection: a unit test asserts on the bytes actually written to guest
memory that the bzImage zero page carries the image's header and that no
bzImage-only field (`init_size`) leaks into the ELF one, and a third
test asserts an unrecognised file (a shell script) fails loudly instead
of being handed to a loader on spec.

**Reference:** the x86 [boot protocol](https://www.kernel.org/doc/html/latest/arch/x86/boot.html)
(`init_size`, `pref_address`, `LOADED_HIGH`, the 64-bit entry at
`+0x200`); `linux-loader`'s `loader::bzimage`; cloud-hypervisor's
`vmm/src/vm.rs` bzImage path in `reference/`.

**Time lost:** ~15 minutes, all of it reading the boot protocol before
writing the code rather than debugging a silent hang after. Recorded
because the failure mode carries no diagnostic at all: get either half
wrong and the guest is simply mute.

---

## 106. The suite's own hygiene sweep eats a multi-minute cached artifact 

**Symptom:** the Ubuntu base image kept disappearing from
`/var/lib/k7d/disks` between test binaries, leaving its manifest,
kernel and initrd behind. Every suite run then rebuilt a several-minute
image that was supposed to be content-cached and built once per node.
Nothing failed, which is why it was easy to miss — the cost showed up
only as a suite that had quietly got slower.

**Root cause:** `sweep_disks` in `tests/common` deletes every `*.img`
directly under `/var/lib/k7d/disks` that no live VM holds open, and
`maybe_hygiene_once()` runs it at the start of each test binary. That is
the correct contract for the directory: per-VM images there are garbage
the moment their VM is gone, and a test that dies mid-run must not strand
one. A cached *base* image is the one thing in that directory that is
not per-VM state, and it looked exactly like a stranded image.

**Fix:** build the base image into a `base-images/` subdirectory of the
same reflink XFS. `FICLONE` needs the same filesystem, not the same
directory, so per-VM clones still reflink, and `sweep_disks` does not
recurse. The alternative — teaching the sweep to recognise base images —
was rejected: "anything unrecognised directly under the disks dir is
garbage" is a stronger invariant than a list of exceptions.

Worth noting the near miss: the builder's cache check requires the image
file itself and not just the manifest it writes last, so a swept image
rebuilt instead of handing a test a path to a file that no longer
existed. Had the check trusted the manifest alone, this would have
surfaced as a reflink failure in an unrelated test.

**Reference:** none — the interaction is between this repo's own
`cached_erofs_image` caching pattern and its spec-22d sweep.

**Time lost:** ~15 minutes, all of it after noticing that a manifest
pointed at a nonexistent `.img`. Two correct local decisions (cache the
artifact on the reflink filesystem; reap unknown images there) composed
into a wrong global one.

---

## 107. The node's workspace lock does not stop an interactive session, and the damage looks like a flaky budget 

**Symptom:** `test_inner_k3s_argocd_gitops_fork` failed inside an
otherwise green `make remote-check`, on a test whose budget
(`FORK_INNER_K3S_CLUSTER_3VM_ARGOCD`, 2 s) had been comfortable for days.
The obvious readings — a real regression from the branch, or CHALLENGES
#97's known fork flake — were both wrong.

**Root cause:** another agent was on the same bare-metal node, running
`examples/k7view/run_scenario.py --keep --branches 4` in a detached tmux
session, in the *same* `/root/k7d` workspace, at the same moment. It
created a 3-VM cluster and forked four branches on the same KVM host
while the suite was measuring a cluster fork.

`utils/remote-run.sh` takes an `flock` on
`/run/k7d-remote/workspace.lock` precisely to stop this (CHALLENGES #64's
neighbour), and it worked as designed: it serialises *remote-run
invocations*. A human or agent typing `python3 …` into a tmux session on
the node never touches that lock. The interlock is not a mutex on the
node, only on one way of using it.

**Fix (operational, not code):** confirm exclusivity before trusting a
timing failure. `tmux ls`, `who`, `ps` for foreign `cargo`/`python`, and
`ls /run/k7d-remote/*/pid` for live runs answer it in one round trip; the
scenario's own leftovers (`--keep` leaves `k7v-*` trees in
`/var/lib/k7d/trees`) are the fingerprint afterwards. The failing test
was then re-run on a quiet node and passed.

Recording it because the diagnosis order matters: when a *budget* test
fails and the code under it did not change, ask "was the machine mine?"
before reading the fork path. Kept measurements are only as good as the
host's exclusivity — the numbers in `LATENCY_BUDGETS.md` are all 2x
ceilings for exactly this reason.

**Reference:** none — this repo's `utils/remote-run.sh` lock and the
ops-side node lease, which is advisory: a launched agent still reads
`K7_NODE_IP` from its own environment.

**Time lost:** ~20 minutes, most of it spent about to re-run a suite on
the assumption the failure was mine.

---

## 108. k3s `After=network-online.target` hangs forever when wait-online is masked 

**Symptom:** a Ubuntu node with `k7d.k3s=server,…` on the cmdline
reaches the vsock agent and `k7d-net.service` is active, but
`k3s.service` never leaves `activating` and `/readyz` is never
reachable. `systemctl start k3s` from the oneshot times out at 180 s.
`journalctl -u k3s` is empty — the binary has not run.

**Root cause:** the stock k3s unit (and every copy of it online) has
`After=network-online.target` / `Wants=network-online.target`. inc1's
image masks `systemd-networkd-wait-online.service` because
`k7d-net.service` already configured eth0 from `k7d.ip=`, and a
wait-online that never sees a DHCP lease is a boot hang. Masking the
waiter does not satisfy `network-online.target`; it leaves the target
unreached. systemd then holds every unit that `After=`s it, including
k3s, for the start timeout — which with `TimeoutStartSec=0` is
forever.

This is the same class of trap as inc1's masked-unit list: a target
that is correct on a cloud VM is a silent deadlock on a k7d node
that does its own net config.

**Fix:** ship `k3s.service` / `k3s-agent.service` with
`After=k7d-net.service` / `Wants=k7d-net.service` and no mention of
`network-online.target`. `k7d-net.service` is the unit that actually
makes eth0 usable; waiting on it is both sufficient and terminating.
Named in `guest/ubuntu/units/k3s.service` so a future refresh of the
upstream unit file cannot silently put the After= back.

**Reference:** systemd `network-online.target` +
`systemd-networkd-wait-online.service`; k3s packaging
(`k3s.service` in the k3s-io/k3s install script). inc1's masked-unit
list in `guest/ubuntu/build-node-image.sh`.

**Time lost:** ~15 minutes (caught in the unit file before the first
cluster bring-up, from reading the masked-unit list against the
upstream k3s unit — a future reader who copies the stock unit will
lose a boot-to-Ready hang cycle).

---

## 109. Gym lease 404 ≠ residue gone 

**Symptom:** `test_gym` TTL path saw `GET /lease/{id}` return 404 while
`tree_nodes` still listed a branch and a `k7-br-*` + its TAP slaves
were still up. Explicit `/release` was clean because the HTTP call
blocked on prune.

**Root cause:** `mark_released` popped the in-memory row *before*
`tree_prune`. The reaper logged the reap, the test treated 404 as
"done", and asserted the pre-lease snapshot against a half-torn-down
group. A second flake: a global `k7-br-*` diff also fired on
`k7-br-3vm-*` bridges minted by other work on the shared node — those
are not this lease.

**Fix:** `begin_release` keeps the row visible until prune returns, then
`mark_released`. Residue assertions are scoped to the lease's own
`branch_node_id`s / `bridge`s / TAP slaves, not every `k7-br-*` on the
box. `GET` staying 200 through teardown is load-bearing for a trainer
that polls.

**Reference:** none (gym-side lifecycle, not a k7d bug).

**Time lost:** ~25 minutes (two red `test_gym` runs).

---

## 110. Busybox gym is a frozen contract, not the trainer substrate (2026-08-19)

**Symptom:** After 26a-inc0 (and the inc1 catalog) it was still
reasonable to write the next gym spec against create-mode busybox
or `K7_KEEP_INNER3` — the 26a substrate note explicitly allowed
that "while 25a climbs". Gym-router as inc2 would have encoded
tiny-guest RAM (~23 MiB k7d VmRSS/fork, 256 MiB guests) into fleet
admission. Fault injectors on that guest also fight PID 1 =
`k7-agent`, ash hex arithmetic, and `eth0` starting DOWN.

**Root cause:** The 2026-08-18 25a decision parked nested-runc and
`config-minimal` feature work but left a gym exception so the HTTP
contract could freeze first. "Park" was also easy to read as
"delete the tiny kernel" or "keep using it until Ubuntu is
perfect". Neither is the intent. GRPO on realistic k3s +
Cilium/Tetragon needs systemd + a distro kernel, not another
busybox workaround.

**Fix:** Exclusive policy in `internal notes` and
`internal notes`. Next gym increment is
`internal notes`. Gym-router moved to parked
`internal notes`. Always-apply rule
`editor-config/rules/ubuntu-substrate.mdc`. Minimal guest +
`test_inner_k3s.rs` stay green CI — not deleted.

**Reference:** `internal notes` (decision
record).

**Time lost:** none this change (policy lock). The cost avoided is
another busybox gym increment.

---

## 111. Gym fault catalog: PID 1, zombies, ash hex, and eth0 never up 

**Symptom:** `kill-member-0` inject "did not take"; the scripted restore
hung `POST /act` for 15 s; `partition-member-0` scored `contained=0`
with `source_intact=1`.

**Root cause:** four independent create-mode traps, all on the busybox
guest (`guest/rootfs/init.sh` `exec`s `k7-agent` as PID 1):

1. `kill -9 1` kills the vsock agent. There is no scripted restore.
2. After SIGKILL of a canary, `kill -0 $pid` stays true on the zombie
   until PID 1 reaps, so a "process is gone" verifier fails.
3. A good-fix of `sleep 86400 &` never returns: busybox ash waits on
   the leftover job and `Command::output()` (the agent exec path)
   blocks until `timeout_s`.
4. Create-mode guests only `ip link set lo up`. `eth0` exists and is
   DOWN on the source and every fork. Taking it down on one sibling
   is indistinguishable from the rest, so `contained` is 0. A first
   attempt to read `/sys/class/net/eth0/flags` as hex made it worse:
   busybox ash evaluates `$((0x1003 & 1))` as 0 (stops at `x`), so
   every NIC looked DOWN.

**Fix:** `kill-member-0` SIGKILLs a planted canary and scores on
`/tmp/k7-fault-kill` / `/tmp/k7-fault-restored` (the good fix is a
marker write, not a background sleep). `partition-member-0` matches
`,UP`/`<UP` on `ip link show eth0`. The gym brings `eth0` up on the
source after create so forks inherit a live link. Unknown `fault_id`
stays 400 with the allowlist; a failed inject still tears the lease
down.

**Reference:** none (guest userspace + ash, not a k7d/KVM bug).

**Time lost:** ~40 minutes (four red `test_gym` inject/score runs).

---

## 112. Cilium's conflist is not always under k3s' CNI dir 

**Symptom:** `test_ubuntu_cilium_datapath_fork` brought Cilium 1.16.10
to DaemonSet 3/3 + operator Available, every node had `cilium_host` /
`cilium_net`, and the three nodes were Ready — then panicked:

```
server: Cilium never wrote its conflist:
---
ls: cannot access '/run/flannel': No such file or directory
```

A first reading treated this as "Cilium did not install its CNI
config". The datapath was already programmed.

**Root cause:** the assertion was copied from inner-k3s
(`test_inner_k3s.rs`), which lists only
`/var/lib/rancher/k3s/agent/etc/cni/net.d` for a file named
`05-cilium.conflist`. Cilium's Helm chart default is `/etc/cni/net.d`,
and the filename is any `*cilium*.conflist`. The first `ls` printed
nothing (empty or missing k3s dir; stderr discarded); the second
`ls /run/flannel` error was concatenated into the same string. A
follow-on `contains("flannel")` check would also have failed on that
error text even after the conflist was found.

**Fix:** `find` both the k3s CNI dir and `/etc/cni/net.d` for
`*cilium*.conflist`; look for `*flannel*` files in those dirs
separately; assert `/run/flannel` is absent without grepping its
`ls` error. Do not require the inner-k3s filename or path.

**Reference:** Cilium Helm `cni.confPath` default (`/etc/cni/net.d`);
k3s kubelet `--cni-conf-dir=/var/lib/rancher/k3s/agent/etc/cni/net.d`.

**Time lost:** one full Ubuntu Cilium bring-up (~6 min) plus resuming
the sequential suite around it.

---

## 113. Cluster-tree fork bridges were named `ctree-{pid}`, so gym kubectl bound the wrong `k7-br-*` 

**Symptom:** Ubuntu gym source bring-up succeeded (~113 s, 3 Ready).
`POST /lease` n=1 `none` forked in ~626 ms. `act` `kubectl get nodes`
then returned HTTP 200 with `ok: false`:

```
curl: (45) Couldn't bind to 'k7-br-gym-8fa62'
```

`obs` also 200 — it swallows the same bind failure into
`nodes_error` / `readyz=false`.

**Root cause:** `ClusterSnapshotTree::new_cluster` invented
`tree_id = format!("ctree-{}", pid)` and `fork_batch` named the new
bridge from `{that}-{node_id}`. The gym recomputes
`k7_bridge_name(f"{registry_tree_id}-{node_id}")` from the id
`tree_adopt_cluster` returned (`gym-src-test-ubuntu-…`). Those
hashes diverge. Busybox gym never hit this: create-mode used vsock
`exec`, adopt used the short `k7-br-inner3`. First hashed long
tree id + `--interface` path.

**Fix:** `new_cluster` takes the last component of `root_dir` as
`tree_id` (callers already do `tree_root_dir().join(&tree_id)`).
Gym fails loud if the computed fork bridge is not on the host.

**Reference:** none (k7d `ClusterNetwork::create` / `bridge_short_tag`).

**Time lost:** one full Ubuntu source bring-up plus diagnosing curl 45
as a name mismatch rather than a down interface.

---

## 114. A foreign rsync can replace `/root/k7d` on an "exclusive" node 

**Symptom:** After a green `test_gym_ubuntu` on <node-ip>, a
`--nocapture` re-run hung in the 600 s healthz wait. The gym log was
one line: `GYM_SOURCE_MODE must be create|adopt, got 'ubuntu'`.

**Root cause:** `/root/k7d/gym/server.py` on the node was an older
tree (no `ubuntu` mode). `utils/rsync-to-node.sh` / `remote-run.sh`
use `K7_NODE_IP` (or the first of `K7_NODE_IPS`). The cloud env
still lists all three nodes in `K7_NODE_IPS`. Another agent that
does not `unset K7_NODE_IPS` can rsync *its* workspace onto this
node even when the increment said "TOUCH ONLY 135". Same class as
CHALLENGES #107 (workspace lock is not a node mutex).

**Fix (operational):** `export K7_NODE_IP=…; unset K7_NODE_IPS`
before every `make rsync` / `remote-check`. If gym/daemon sources
on the node do not match the branch, re-rsync before believing a
hang. Do not provider-reset.

**Reference:** none.

**Time lost:** one 600 s healthz wait plus diagnosing a "missing
mode" as a hung Ready.

---

## 115. Cluster `fork_batch` does not evict for *incoming* VMs (k7view max-load)

**Symptom:** `run_scenario.py --profile max` created a 3-VM root, forked
8 cluster branches (27 live VMs, budget 30), then hung for ~180 s on
the second wave and died. The tree never grew past wave 0. k7d logged
nothing after the first `fork_cluster_warm_batch: 8 clusters / 24 VMs`.

**Root cause:** `ClusterSnapshotTree::fork_batch` calls
`auto_evict_if_over(source)` which is `evict_for_incoming_inner(source, 0)`.
It only suspends when the tree is *already* over budget, not when the
batch about to start would push `live_vm_count + incoming` over
`max_live_vms`. Wave 1 wanted 12 more VMs at 27/30. The client sat on
the control socket until `tree_fork_batch`'s 180 s timeout.

Single-VM `SnapshotTree` has the same `incoming=0` helper for
`fork_batch`; the cluster path is the one the video demo hits because
each node is 3 VMs.

**Fix (demo-side, not a daemon change):** park unprotected losers
*before* the next wave so there is real headroom, and use a 300 s
timeout on the max profile. Do not retry a failed child fork from
root — that flattens the tree to depth 1. A daemon fix would pass
`incoming = labels.len() * vm_count` into `evict_for_incoming_inner`
— that is a separate increment.

**Reference:** none — `crates/k7d/src/cluster_tree.rs` `fork_batch` /
`auto_evict_if_over`.

**Time lost:** ~15 minutes (one hung wave, then the headroom-before-wave
retry).

**Resolution :** both `fork_batch` paths now call
`evict_for_incoming(source, labels.len() × vm_count)` and fail loud with
`BudgetExhausted` when everything else is protected. Note the semantic
shift: a fork that previously *overshot* `max_live_vms` silently (source
and forks exempt from `evict_post_fork`, warning only) now refuses
up-front — `test_tree_protection` relied on the overshoot with
`max_live_vms: 1` and had to move to a budget of 2 where its intent
(protected nodes are never suspended) is expressible without overshoot.

---

## 116. `remote-run.sh` reattach dies on a fresh checkout (`.remote-runs/<run>.log` missing)

**Symptom:** `make remote-check` from a fresh clone, while a previous
agent's run of the same name was still in flight on the node, printed
`line 92: /workspace/.remote-runs/check.log: No such file or directory`
and exited 1 — looking like a failed check when the node-side run was
fine.

**Root cause:** the reattach path never creates the local log — only
`start_run` truncates it (`: >"$LOCAL_LOG"`). `local_log_size` reads the
file via input redirection (`wc -c <"$LOCAL_LOG"`); with `set -e` the
failed redirect aborts the script before the viewer even attaches. Any
fresh checkout reattaching to an in-flight run hits it (cloud agents
always start from fresh clones).

**Fix:** create the file if missing right after the `mkdir -p` — resume
offset 0 is exactly right for a viewer that has no local copy yet.

**Reference:** none — `utils/remote-run.sh`, builds on #64.

**Time lost:** ~10 minutes (plus one 45-minute lock wait behind another
agent's suite that the failure obscured).

---

## 117. `test_ubuntu_cilium_datapath_fork` fails: guest pulls from quay.io at ~50 KB/s (pre-existing, node-side)

**Symptom:** during the 9g-inc1 `make remote-check`,
`test_ubuntu_cilium_datapath_fork` timed out with `Cilium never Ready
in 600s (agents=0/3 operator=1)`. Reproduced identically in isolation.
An *independent* agent's suite on different sources failed on the same
test earlier the same day — this is not a regression of the branch
under test (which touches only tree eviction/checkpoint policy).

**Root cause:** userspace virtio-net advertised TSO and enabled TAP
`TUNSETOFFLOAD CSUM+TSO`, so the kernel delivered 16–64 KiB GRO
aggregates on RX — but the RX path always stamped `num_buffers=1` and
wrote into a single descriptor chain, silently truncating the rest.
Guest TCP saw chopped segments and collapsed to ~50 KB/s. The kubelet
event log had the number: `Successfully pulled image
"quay.io/cilium/operator-generic:v1.16.10@…" in 9m15.047s … Image
size: 29153610 bytes` — 29 MB in 9¼ minutes. At that rate the ~200 MB
`cilium` and ~150 MB `cilium-envoy` images cannot finish inside the
test's 600 s ceiling.

Not quay throttling the node IP: a `k3s crictl pull` of the same repo
**on the host** is full speed. Single-guest `curl -o /dev/null -w
'%{speed_download}'` of that quay blob vs GitHub `runc.amd64`: host
~15–35 MB/s quay / ~19–26 MB/s GitHub; guest with the truncate bug
matches the 50 KB/s kubelet number; guest after the MRG_RXBUF split
is line-rate on both URLs. Conntrack was 1399/393216. No IFB, no
leftover `tbf`/`htb`/`netem`/`ingress` on the WAN. `speed.hetzner.de`
does not resolve here.

Bisect traps (each tried, each loud):
- `TUNSETOFFLOAD CSUM+TSO` + `ethtool -K gro off` on the TAP
  reproduced 29 MB in 9m22s exactly.
- TAP CSUM-only (TSO off) made NAT egress fast — kernel no longer
  GRO'd into userspace — but the guest still TSO'd. `write(2)` of a
  GSO frame to a CSUM-only TAP returns `EINVAL` (ignored), so
  guest-to-guest Cilium native-routing hung (`cil-allow` wget).
- Advertising TSO to the guest while the TAP was CSUM-only is the
  same mismatch. TCPMSS on the bridge FORWARD path was not the
  cause (still hung after it was scoped to WAN, then removed).

**Fix:** two stacked bugs.

1. NAT collapse: TAP `TUNSETOFFLOAD CSUM+TSO` plus RX `num_buffers=1`
   silently truncated GRO aggregates. TAP is CSUM-only (fail loud);
   RX splits across MRG_RXBUF and publishes `used.idx` once. Single-guest
   curl on <node-ip>: host quay ~22–35 MB/s / github ~26–28 MB/s;
   guest quay ~26–38 MB/s / github ~41–45 MB/s. Conntrack 1.5k/393216;
   no IFB; WAN qdisc is fq_codel. `speed.hetzner.de` does not resolve.
   `ClusterNetwork::create` fails on leftover IFB/tc shaping.
2. Cross-node pod SYN-ACK dest MAC is the **k7 bridge / default-gateway
   MAC**, not the peer node. Cilium native routing sends that frame to
   `10.200.0.1`; the host had no `10.42.0.0/16` route and dropped it.
   Host-ns replies stay on-link (node MAC → node MAC) and never hit
   this hop. `ensure_host_pod_routes` installs each node's `podCIDR`
   via its InternalIP on the k7 bridge (and `10.43.0.0/16` via the
   first node so a ClusterIP that misses kube-proxy replacement is
   not dropped on the gateway). Unlabelled `cil-preadmit` then
   finishes in ~4–6 s. Do not log/rewrite every gateway-dest frame
   — that stalls the virtio thread (Cilium Ready 0/3).
3. After NetworkPolicy, labeled `cil-allow` got `Connection refused`
   for minutes while Cilium ipcache/identity were correct and the
   BPF allow map stayed at 0 packets. k3s's embedded kube-router
   netpol controller installs `KUBE-POD-FW-*` `REJECT … icmp-port-unreachable`
   unless mark `0x10000`. Cilium never sees the skb. `k7d.cni=none`
   now writes `disable-network-policy: true` (same requirement as
   the inner-k3s Cilium profile).
4. Even with kube-router off, labeled wget timed out: server TAP
   saw `10.200.0.1 → pod:8080` and Cilium logged `identity world`
   deny. Host `bridge-nf-call-iptables=1` (required for host
   kube-proxy) plus host flannel `MASQUERADE 10.42.0.0/16` SNATed
   *bridged* guest SYNs to the k7 gateway. Per-bridge
   `nf_call_iptables=0` does **not** override the global hook.
   `ClusterNetwork::create` INSERTs
   `nat POSTROUTING -s 10.42/16 -d 10.42/16 -m physdev --physdev-is-bridged -j RETURN`
   so those frames skip host flannel MASQ. Live proof: TAP SYNs
   kept the pod IP and HTTP 200 followed immediately.
5. `ensure_host_pod_routes` originally did `ip route replace
   10.42.{n}.0/24 via 10.200.0.{n+2}` **in the main table**. Guest
   node 0's podCIDR is the same prefix as host k3s `cni0`
   (`10.42.0.0/24`). The replace stole kubelet's connected route;
   `ClusterNetwork::Drop` then deleted the bridge and the via-route
   vanished with it — main had **no** `10.42.0.0/24`. Host CoreDNS
   readiness probes (`http://10.42.0.11:8181/ready`) timed out and
   `test_cni_pod_traffic_flows` failed with `k3s did not converge
   within 180s (coredns ready=false)`. Overlay routes now live in
   table 200, selected only by `iif k7-br-* to 10.42/16|10.43/16`.
   `destroy` / `cleanup_stale_k7_bridges` / `wait_for_k3s_ready`
   restore `cni0`'s connected route if it is missing. Tetragon's
   operator is a regular pod on a worker (`10.42.1.x`); without
   these overlay routes it never reaches the API, never binds
   `:8081`, and dies on liveness. `test_ubuntu_tetragon` now
   installs the same table-200 routes as the Cilium datapath test.

`test_ubuntu_guest_egress_throughput` floors guest downloads at 1 MB/s;
`test_ubuntu_guest_bridge_tcp` covers L2.

**Reference:** `crates/k7d/src/network.rs` (`rx_deliver_merged`,
`TUNSETOFFLOAD`); `crates/k7d/tests/test_ubuntu_guest.rs`; spec
25a-inc3b.

**Time lost:** ~1 hour on the original report, plus a day of TAP
offload / GRO / TCPMSS bisect before the truncate was named.

---

## 118. `cases` on an `Option` loop argument fails dependent elimination inside a WP spec goal (Aeneas Equiv proofs)

**Symptom:** the new `Verif/Equiv/Chain.lean` loop-equivalence proof
for `restore_chain_depth` — written by copying `Anc.lean`'s
`ancestor_ids_loop_equiv` skeleton — died on its `cases cur with`
step with `Dependent elimination failed: Failed to solve equation
cur = none`, even though the goal state (dumped with `trace_state`)
was exactly the expected `⦃…⦄`-wrapped `match cur with …` and no
hypothesis mentioned `cur`. The same `cases cur with` idiom compiles
fine in `Anc.lean` against the same Aeneas/Lean toolchain.

**Root cause:** not fully diagnosed (the generated
`restore_chain_depth_loop` differs from `ancestor_ids_loop` only in
arm shapes — scalar accumulator and early `ok none` returns instead of
a `Vec` push), but the failure is in `cases`' structured-`with` mode
building the dependent motive over the spec-triple goal.

**Fix:** use `rcases cur with _ | c` instead of
`cases cur with | none => … | some c => …`. `rcases` clears the
elimination without any other change; the rest of the `Anc.lean`
skeleton (fuel recursion, `find_index_equiv`, `step as`,
`termination_by fuel.val`) transfers as-is. Also handy from the same
session: after `step as ⟨ni, hni⟩` on the `Vec.index` read,
`rw [hwalk, hlook, ← hni]` rewrites the *mirror* side's indexed
element into `ni` so both sides of the goal speak the same node — no
per-field `have`s needed.

**Reference:** `verif/Verif/Equiv/Chain.lean` vs
`verif/Verif/Equiv/Anc.lean`; Lean 4 `cases` dependent-elimination
notes.

**Time lost:** ~30 minutes (one failed lake build, one `trace_state`
round-trip, one variant experiment).

---

## 116. Child Tetragon inject stays Pending unless it lands on the node that already pulled busybox 

**Symptom:** `test_ubuntu_tetragon_fork_event_diff` installed Tetragon
1.7.0 via Helm, fired kprobe + BPF-LSM on the source (`touch
/tmp/k7d-tetra-src-*` in ~3 s), warm-forked three 2 GB nodes in 453 ms
with zero restarts — then panicked:

```
default/tetra-child-inject: never Succeeded via k7-br-ubtetf after 180s
```

The child's API was fine (`/readyz`, node Ready, pod snapshot via
`curl --interface`). The POST created the pod. It never left Pending.

**Root cause:** the source inject had no `nodeName`, so busybox landed
on whichever node the scheduler picked. The child inject was also
unpinned. After the fork it scheduled onto a node whose containerd
had never pulled `docker.io/library/busybox:1.36.1`. A post-fork
image pull through that node's bridge did not finish in 180 s (and
looked like a Tetragon / fork bug). The child's kubelet was not
wedged: pinning both injects to agent-1 — the containerd that already
had the image — made the child Succeed in 16 s, and the event-stream
diff landed 455 ms later.

**Fix:** pin `tetra-src-probe` and `tetra-child-inject` to
`k7d-10-200-0-3`. Keep `imagePullPolicy: IfNotPresent`. Dump phase
and default-namespace events if a later inject still sticks.

**Reference:** none (test fixture, not a Tetragon or VMM bug).

**Time lost:** one full Ubuntu Tetragon bring-up (~8 min) plus the
pinned re-run.

---

## 117. k3s `helm-install-traefik` Jobs are not long-lived pods 

**Symptom:** A full `make remote-check` that had already passed
`test_ubuntu_k3s` on the previous exclusive run panicked later in the
same PR:

```
source: kube-system/helm-install-traefik-76vbs/helm restartCount 0 → 1
(must stay zero-delta across the convergence wait, not merely at the end)
```

Fork latency was 870 ms (under the 1 s ceiling, high vs the 488 ms
typical). Nodes were Ready; no other pod restarted.

**Root cause:** `snapshot_pods_json` is documented as tracking
*long-lived* pods, but it still indexed k3s' `helm-install-traefik*`
Job pods. Those Jobs retry by design. A retry during the converge
wait is not a cluster restart and is not a regression of the 13a/22a
zero-restart matrix.

**Fix:** skip `helm-install-*` in the snapshot the same way the
fixture already skips `churn-pause-` / `cil-allow-` / `tetra-`.

**Reference:** none (test fixture).

**Time lost:** one 70-minute remote-check that died on the last Ubuntu
binaries.

---

## 118. Deleting leftover cluster trees evicts the Ubuntu image from page cache 

**Symptom:** After a green Tetragon isolated run (453–551 ms cluster
fork) and a first `make remote-check` that died on `test_inner_k3s`
TreeFork budgets (1.033 s / 1.118 s), leftover `i3*` trees totaled
~82 GiB. Soft-cleaning those trees on an exclusive node
(`tmux`/`who`/live `/run/k7d-remote/*/pid` all empty, load 0.2)
dropped `buff/cache` 54 GiB → 31 GiB. The next exclusive
`test_ubuntu_k3s_cluster_warm_fork_no_restart` then missed
`FORK_UBUNTU_K3S_CLUSTER_3VM` at **1.613 s** and **1.999 s**. The
code under the test had not changed; `FORK_UBUNTU_NODE_1VM` was
untouched.

**Root cause:** the 6 GiB Ubuntu node image lives on the loopback XFS
at `/var/lib/k7d/disks/base-images/`. A bulk `rm -rf` of tens of
gigabytes of dead trees evicts that image (and the live guest RAM
backing) from the host page cache. The 1 s Ubuntu cluster ceiling
is a 2× of a *hot* measurement (~416–551 ms). A cold-cache fork
looks like a regression. CHALLENGES #107's exclusivity check is
necessary but not sufficient — the machine can be yours and still
cold.

The same suite's `test_inner_k3s_etcd_datastore_fork` passed on the
exclusive re-run; `test_inner_k3s_ingress_fork` missed again
(2.52 s, warm-0 materialise 2.16 s) with those 13 GiB leftover
trees still on disk. That test was not edited.

**Fix (operational, not a widened budget):** confirm exclusivity
(#107), then check whether the 6 GiB image is still in cache
(`free`, or a `dd` of the current `ubuntu-24.04-*.img` into
`/dev/null`). Re-run the Ubuntu budget tests after a cache warm —
do **not** raise `FORK_UBUNTU_K3S_CLUSTER_3VM`. After warming,
`test_ubuntu_k3s` (176 s) and `test_ubuntu_tetragon_fork_event_diff`
(359 s) passed on `<node-ip>`.

**Reference:** CHALLENGES #107 (exclusivity), #106 (do not put the
cached artifact where the sweep deletes `*.img`).

**Time lost:** two exclusive Ubuntu re-runs (~6 min) plus diagnosing
a "real" 2 s miss that was a cold cache.

**Seen again, and now easier to hit :** a full
`make remote-check` that spends two hours in `test_shim` /
`test_inner_k3s` before it reaches `test_ubuntu_k3s` leaves the same
cold cache behind, and
`test_ubuntu_k3s_cluster_warm_fork_no_restart` missed at **1.200 s**.
`dd`-ing the current base image to `/dev/null` on the idle node and
re-running gave **462 ms** — with `test_ubuntu_tetragon` at 423 ms and
`test_ubuntu_longhorn` at 538 ms in the same pass. inc5 doubled the
node root to 16 GiB, so there is more image to fall out of cache;
warm before trusting a miss at the tail of a full suite.

**Seen again :** back-to-back full
`make remote-check` runs plus **65 GiB** of leftover `gym-src-test-*`
trees produced inner-k3s TreeFork misses at 1.17–1.42 s (three
different profiles across two runs — never the same test twice, a
flake signature, and the daemon-side materialise was 17–50 ms every
time) and `test_ubuntu_longhorn_fork_volumes` at 2.09 s in-suite and
2.72 s isolated. A `dd` of the base image alone was **not** enough for
Longhorn — that fork's cost is dominated by the *guests'* dirty memory
under churn, which only warms by actually running the cluster. After
soft-cleaning the leftover trees and one warm-up cluster run, inner-k3s
went green and the Longhorn fork measured **802 ms** on the same code.
Note `main` cannot cross-check this node: without this branch's
virtio-net fixes (#117) Cilium agents never come up there, so
attribution has to come from the materialise-time breakdown, not an
A/B run.

---

## 119. The guest cluster reused the host cluster's pod CIDR, so the host masqueraded guest pod-to-pod traffic 

**Symptom:** Longhorn 1.12.1 installed cleanly on the Ubuntu 3-node
Cilium cluster and then never became Ready inside 900 s. What varied
run to run was *which* component looked broken: `longhorn-manager` on
the k3s server node exited 1 in a crash loop after two minutes of
`Failed to check endpoint
https://longhorn-admission-webhook.longhorn-system.svc:9502/v1/healthz:
context deadline exceeded`, occasionally with `lookup ... on
10.43.0.10:53: i/o timeout`; `longhorn-driver-deployer` sat at
`Init:0/1`; `longhorn-csi-plugin` hung at 2/3; readiness probes
flapped 3/3 → 2/3 → 3/3. When a volume did get far enough to attach,
CSI reported only `DeadlineExceeded` and the instance-manager log said
`iscsiadm: cannot make connection to <pod ip>: Connection timed out`.
Cilium itself reported `Cluster health: 3/3 reachable`, no policy
drops in `cilium-dbg monitor --type drop`, correct
`autoDirectNodeRoutes` routes on every node, and matching podCIDRs in
both `nodes` and `ciliumnodes`.

**Root cause:** the guest k3s cluster ran on k3s' default
`10.42.0.0/16` pod CIDR and `10.43.0.0/16` service CIDR — and the
bare-metal host these VMs run on is *itself* a k3s node whose cluster
uses exactly those ranges (`k7-node-01` = `10.42.0.0/24`,
`k7-node-03` = `10.42.1.0/24`, `k7-node-02` = `10.42.2.0/24`, kube-dns
`10.43.0.10`). The host has `net.bridge.bridge-nf-call-iptables=1`, so
guest frames crossing `k7-br-*` traverse the host's `nat` table, where
the host's own Cilium has:

```
-A CILIUM_POST_nat -s 10.42.0.0/24 ! -d 10.42.0.0/24 ! -o cilium_+ -j MASQUERADE
```

A guest pod on the server node (`10.42.0.x`) talking to a pod on
another guest node (`10.42.1.x`) matches that rule exactly, so the
*host* SNATs it. The asymmetry this produces is what made every
component look individually broken: same-node pod-to-pod worked
(never leaves the VM), `10.42.1.x → 10.42.0.x` worked (wrong `-s`),
and everything a `10.42.0.x` pod sent off-node — cluster DNS, its own
`ClusterIP` webhook, another node's pod, even a node IP — was lost.
Zeroing the chain and re-probing from a guest pod showed 11 packets on
that MASQUERADE rule; that is the whole diagnosis.

**Fix:** move the guest cluster off the host's ranges in
`guest/ubuntu/k7d-k3sconfig` — `cluster-cidr: 10.244.0.0/16`,
`service-cidr: 10.245.0.0/16`, `cluster-dns: 10.245.0.10` — with
`POD_CIDR` / `SERVICE_CIDR` in `common/ubuntu_k3s.rs` as the single
place the fixtures and Cilium's `ipv4NativeRoutingCIDR` read them
from. k7d's guest subnet (10.200.0.0/24) already dodged this
collision for node IPs; the cluster's own CIDRs had never been moved
because nothing before Longhorn needed cross-node pod-to-pod or
in-cluster DNS. Longhorn Ready went from "never" to 364 s on the
first try.

**A measurement trap met along the way:** `curl -m 5
telnet://<ip>:3260` exits 28 both when the SYN is dropped and when the
connection is fine but `tgtd` says nothing until an initiator speaks
iSCSI. An "unreachable" verdict built on that timeout string is
measuring nothing; only `curl -v`'s `Connected to <ip>` line
distinguishes the two. #121 is a *second*, independent cause that this
same probe found once it could tell them apart.

**Reference:** none upstream — this is a host/guest CIDR collision
specific to running guest clusters on a machine that is itself a k3s
node. Cilium's masquerade rule is doing exactly what it is supposed
to.

**Time lost:** ~5 twenty-minute cluster runs chasing NetworkPolicies,
node memory, and vCPU count before probing the host's nat counters.

---

## 120. Longhorn needs a bigger node root, a bigger reflink XFS, and more than 2 GB 

**Symptom:** Longhorn pods were evicted with `DiskPressure`, managers
and CSI sidecars were `OOMKilled`, and `ensure_loopback_xfs` ran out
of space at 25 GiB used of 32 GiB while three clusters' base-image
copies were live.

**Root cause:** three separate ceilings sized for k3s alone. inc2's
6 GiB node root cannot hold Ubuntu + the k3s airgap images + Cilium +
ten Longhorn images (~1.1 GiB of layers before unpacking), so the
kubelet crosses its `nodefs` eviction threshold. inc2's 2 GB per node
is under Longhorn's documented 4 GB floor. And `DISKS_IMAGE_SIZE`
(32 GiB) is the sum of every base image and every live clone, so a
bigger root multiplies through it.

**Fix:** node image 6 GiB → 16 GiB, `DISKS_IMAGE_SIZE` 32 GiB →
96 GiB with `ensure_loopback_xfs` growing an existing image in place
(`truncate` + `losetup -c` + `xfs_growfs`) rather than demanding a
wiped node, and a `NodeSize` the cluster fixture takes so Longhorn
asks for 4 vCPU / 4 GB while every other Ubuntu test keeps inc2's
2 vCPU / 2 GB and its budgets. Sizing was the fix for these three;
it was *not* the fix for the connectivity failure in #119, which
survived every one of them.

**Reference:** Longhorn's documented node requirements.

**Time lost:** ~2 runs, plus a manual sweep of stale images.

---

## 121. Longhorn's own NetworkPolicies deny its loopback iSCSI attach under Cilium, because the initiator is `world` 

**Symptom:** with the CIDR collision in #119 fixed, Longhorn reached
Ready in 293 s and then the first RWO attach still failed: the pod sat
in `ContainerCreating` behind `AttachVolume.Attach failed … rpc error:
code = DeadlineExceeded`, and the node's host namespace could not open
TCP to its *own* instance-manager pod on 3260 — while a plain busybox
pod on that same node, on that same port, answered fine.

**Root cause:** Longhorn 1.12's chart ships ingress-only
NetworkPolicies for its own components, and
`networkPolicies.restrictInternalTraffic` defaults to **true** even
when `networkPolicies.enabled` is false. Every `from:` in the
`instance-manager` policy is a `podSelector`. But Longhorn's V1 attach
is a host-to-pod loopback iSCSI session: the engine creates a tgt
target inside the instance-manager pod's namespace and then runs
`iscsiadm` in the *host* namespace against that pod's own IP. Under
Cilium that connection arrives sourced from the node's `cilium_host`
router IP and is classified as identity `world` — not `host`, so
`allow-localhost` does not cover it — and the policy denies it:

```
xx drop (Policy denied) to endpoint 1036, file bpf_lxc.c:2067,
   identity world->40615: 10.244.1.132:38992 -> 10.244.1.226:3260 tcp SYN
```

**Fix:** `--set networkPolicies.restrictInternalTraffic=false` on the
Helm install — the chart's own switch for managing that traffic
yourself. `test_ubuntu_longhorn_fork_volumes` asserts the loopback
connect against the real instance-manager (not just a plain pod)
before it creates a PVC, so this failure names itself in seconds
instead of arriving seven minutes later as a CSI deadline.

**Reference:** Longhorn chart `networkPolicies.restrictInternalTraffic`;
Cilium identity `world` vs `host` for `cilium_host`-sourced traffic.

**Time lost:** one 9-minute run to confirm the flag is load-bearing
after #119 was fixed (the two causes were entangled: with #119 in
place, this one could not be seen).

---

## 122. Longhorn's share-manager pod legitimately disappears across the fork's no-restart check 

**Symptom:** a full `make remote-check` that had already survived the
fork budget died in `test_ubuntu_longhorn_fork_volumes` at
`assert_no_restarts`: `source-longhorn: pod
longhorn-system/share-manager-pvc-… disappeared after the fork`. The
same test had passed twice on identical code.

**Root cause:** `share-manager-*` is Longhorn's RWX NFS server pod.
It exists only while a workload has the RWX volume attached; once the
test's `lh-rwx-write`/`lh-rwx-read` probe pods reach `Succeeded`,
Longhorn detaches the volume and deletes the share-manager
*asynchronously*. Whether that deletion lands before the pre-fork
snapshot or between snapshot and post-fork check is a race the test
does not control — the pod's disappearance is volume lifecycle, not a
restart.

**Fix:** add `share-manager-` to the ephemeral-pod skip list in
`snapshot_pods_json` (`tests/common/ubuntu_k3s.rs`), next to
`churn-pause-` / `helm-install-` which exist for the same reason.

**Reference:** Longhorn share-manager lifecycle (created on RWX
attach, deleted on detach).

**Time lost:** one ~60-minute remote-check that failed at the last
binary.

---

## 123. `k7d.cni=none` nodes stay NotReady until Cilium — do not wait Ready first 

**Symptom:** the MCP Ubuntu smoke hung 600 s in `wait_nodes_ready` after
CreateVm × 3 with `k7d.cni=none`. kubectl showed all three nodes
registered as `NotReady` for the whole ceiling.

**Root cause:** once flannel and kube-proxy are off, Ready *is* a CNI
assertion (25a-inc3). `bring_up_cluster_ex(UbuntuCni::None)` only waits
for nodes to be *present*; Cilium install is what makes them Ready.
`gym/ubuntu.py` only had `wait_nodes_ready`, and `cluster.py` called it
before Helm.

**Fix:** add `wait_nodes_present` (same helper as the Rust fixture),
adopt+protect on a registered-but-NotReady cluster, install Cilium,
then wait Ready.

**Reference:** `crates/k7d/tests/common/ubuntu_k3s.rs` `UbuntuCni::None`
arm of `bring_up_cluster_ex`.

**Time lost:** one ~11-minute smoke run.

---

## 124. `import faults` in examples/k7d-mcp binds gym/faults 

**Symptom:** `scenario_incident.py --both-arms` brought the Ubuntu
Cilium+Tetragon source up (44.6 s + 59 s Cilium + 28 s Tetragon) and
then died: `AttributeError: module 'faults' has no attribute 'pick'`.

**Root cause:** the harness does `sys.path.insert(0, gym)` *after*
inserting `examples/k7d-mcp`, so gym wins. `import faults` loaded
`gym/faults/__init__.py` (kill-member-0 catalog) instead of the
cryptominer/lateral catalog.

**Fix:** rename the catalog to `incidents.py`. Do not share a module
name with `gym/`.

**Reference:** none.

**Time lost:** one ~2.5-minute bring-up.

---

## 125. Codex CLI as MCP agent: three config walls 

**Symptom:** replacing the hand-rolled LLM loop with OpenAI Codex CLI
0.149 hit three sequential failures before the first successful tool
call: (1) `wire_api = "chat"` rejected at config load; (2) MCP
handshake "connection closed: initialize response"; (3) every tool
call denied with "MCP tool call requires approval, but approval
policy is never".

**Root cause:** (1) Codex ≥0.148 removed the chat-completions wire
API — Responses only (OpenRouter added `/v1/responses`, so this
works). (2) Codex spawns MCP servers from its *own* workdir, so
relative `args`/env paths in the server config silently break.
(3) In a `read-only` sandbox, MCP tools without `readOnlyHint`
annotations are treated as consequential; with `approval_policy =
"never"` they are denied rather than run — `default_tools_approval_mode`
has no "never-ask-and-run" variant.

**Fix:** `wire_api = "responses"`; absolute paths everywhere in the
generated config (`agent_codex.py` resolves `K7D_MCP_LOG` against the
harness cwd); `sandbox_mode = "danger-full-access"` — the documented
mode for externally-sandboxed automation, which the gym node is.

**Reference:** openai/codex discussion #7782 (chat wire removal);
binary strings of codex-cli 0.149 for the config key surface.

**Time lost:** ~45 minutes across three probe runs.

---

## 126. Codex tempdir ate the run's JSONL; stale k7view served old ingest 

**Symptom:** first recorded Codex agent run looked perfect in the
transcript, but the k7view tiles/verdicts/beats never rendered
(bridge logged `HTTP 400` on every post), and after the run the
harness JSONL — the plots input — was gone.

**Root cause:** two independent bugs. (a) `K7D_MCP_LOG` was a
relative path; Codex ran `server.py` from its ephemeral
`CODEX_HOME/work`, so the JSONL landed inside the tempdir that
`agent_codex.py` deletes on exit. (b) Port 7474 was still held by a
k7view server from a previous session (started from another cwd, so
the `pkill -f "^python3 examples/k7view"` pattern missed it); the
fresh code never bound — `EADDRINUSE` sat unnoticed in the log — and
the stale server predated the `cmd`/`verdict`/`beat`/`latency`
ingest kinds, hence the 400s. Killing it mid-run reset the UI state
and orphaned the capture.

**Fix:** absolutize `K7D_MCP_LOG` in the generated Codex config;
kill by listener (`ss -tlnp` → pid) not by command pattern before
starting the server; re-run the take. The video is take 2.

**Reference:** none.

**Time lost:** one full ~10-minute episode (bring-up + agent run) and
the take-1 recording.

---

## 127. Two latency-budget guards flake marginally under full-suite load (finding, 2026-08-20)

**Symptom:** two consecutive `make remote-check` runs on k7-node-01
each failed exactly one latency-budget test, a different one each
time: `test_nodeusr_image_does_not_regress_boot` (median pair-delta
**20.066 ms** vs the 20 ms allowance) and
`test_ubuntu_longhorn_fork_volumes` (3-VM cluster warm fork
**1.559 s** vs the 1 s `FORK_UBUNTU_K3S_CLUSTER_3VM` budget). Both
pass immediately when rerun in isolation (20.07→ok, 1.56 s→ok).

**Root cause:** these guards measure wall-clock against tight budgets
on a node that, during a full suite run, has residual page-cache and
I/O pressure from the preceding ~35 test binaries (and, in run 1,
concurrent rsyncs). The failures are load noise at the budget edge,
not regressions — the diff under test contained no Rust.

**Fix:** none to the budgets — both tests explicitly say "report as a
finding rather than raising the allowance", so this entry is that
finding. Operationally: do not rsync to the node mid-suite, and when
one of these two trips at the margin, rerun the single test binary
before suspecting the change.

*(2026-08-21: a third member of the class —
`test_ubuntu_k3s_cluster_warm_fork_no_restart` at 1.38 s vs the 1 s
budget mid-suite, 786 ms in isolation.)*

*(2026-08-22, the referenced work on <node-ip> / k7-node-01: the nodeusr
guard is no longer only a mid-suite flake. `make remote-check` failed
at median pair-delta **20.096 ms** after `test_inner_k3s`; an isolated
rerun failed at **20.453 ms**; three more isolated `--exact` runs
were 20.137 / **19.992** / 20.167 — one pass by 8 µs. The common
pair is 236→256 ms, i.e. two `connect_agent` 10 ms poll ticks, plus
sub-ms clock noise. `delta <= 20ms` at nanosecond resolution treats
that pair as a miss most of the time. The allowance constant stays
20 ms; the assertion now compares `as_millis()` so 20.45 ms is still
two ticks and a third tick (30 ms) still fails. 28a did not touch
`crates/k7d/src`.)*

**Reference:** none.

**Time lost:** two full-suite runs (~85 min each) to isolate; ~20 min
on 2026-08-22 to see the isolated miss was the same pair.

---

## 128. Fork chips showed `1.00s` because we invented per-child time 

**Symptom:** every latency chip on a 4-way `fork_batch` read `1.00s`,
which looks like a silent default. The daemon measured **4.01 s** for
that one batch (`latency_ns` 4_013_455_285).

**Root cause:** `ingest_mcp.py` (and `run_scenario.py`) divided the
single batch wall by `n` and painted that onto every child. The
daemon does not report per-child fork time — only one
`tree_fork_batch` `latency_ns`. Equal slices of 4.01 / 4 rounded to
two decimal seconds.

**Fix:** chips show the measured batch wall (4.01 s on each edge of
that batch). Missing `latency_ns` omits the number (`latency_ns
missing` in the feed) — no invented 1000 ms.

**Reference:** none.

**Time lost:** the recorded take looks fake until you read the JSONL.

---

## 129. Ubuntu gym-path cannot fork a fork (depth stays 1)

**Symptom:** after a successful `fork_batch` from `root`, every
`fork_batch` / `rollback` from the child returns
`IO error: No such file or directory`. The agent in the depth>=4
prompt did the right thing (protect keeper, prune loser, fork from
the child) and could not grow the tree.

**Root cause:** the first diagnosis here ("adopted children are not
preparable") was wrong — see **#130** for the real one: preparing a
fork child as a fork source *deleted the child's reflinked RW root
disk* (husk `Drop` owned it), so the grandchild's FICLONE hit ENOENT.
Deterministic on any VM with a RW block device; nothing about adopt.

**Fix:** superseded by #130 (fixed in the same PR after all — the bug
was a disk-ownership hole in `prepare_fork_source_in`, well inside
"keep the core primitives correct").

**Reference:** #130 below.

**Time lost:** one ~6-minute agent episode (bring-up + failed deepen).

---

## 130. Vm::Drop deleted the fork child's RW disk under a successor

**Symptom:** fork-of-fork fails with `fork error: IO error: No such
file or directory (os error 2)` for any VM with a **read-write block
device** — reproduced with a 2-line script against a fresh adopted
Ubuntu cluster tree (fork root→child OK; fork child→grandchild fails
every time). Meanwhile `test_cluster_tree_fork_from_child` was green,
hiding the hole: busybox members have no disks.

**Root cause:** a forked VM runs on FICLONE-reflinked RW images in a
`.k7d-blk-fork-*` dir it owns (`fork_state_dir`, removed on
`Vm::Drop`). Three code paths dropped a `Vm` whose images a successor
still needed:

1. `prepare_fork_source_in` (share-less path) swaps in a restored copy
   whose block backends **reopen the same files**, then drops the old
   husk — husk `Drop` deleted the images. The live guest kept running
   on the open (unlinked) fds, *silently*; the next fork's
   `capture_vm_state` recorded the dead path and the reflink ENOENT'd.
   Root never hit it (its images sit unowned in `/var/lib/k7d/disks`),
   so every tree with RW disks was silently capped at depth 1.
2. `suspend` (both trees) dropped the payload — same deletion, so
   resume's reflink from `vm_state.json`'s recorded path ENOENT'd.
3. prune of a node suspended under the new scheme must reap the parked
   images or they leak.

Writing the regression tests flushed out two more members of the same
family:

4. the reflink clone dir was created next to the source image
   (`host_path.parent()`), so a fork-of-fork's images **nested inside
   the parent fork's owned dir** — reaping the outer dir recursively
   deleted the inner fork's disks (first seen as resume reaping its own
   fresh clones);
5. `dump_memory` opened `memory.bin` with `File::create` (O_TRUNC) —
   preparing a node that had been *resumed from that same checkpoint*
   truncated the live guest's `MAP_PRIVATE` RAM backing: EFAULT on the
   vCPU, SIGBUS on the host-side dump.

**Fix:** ownership transfer, not copies: `prepare_fork_source_in`
moves `fork_state_dir` husk→restored (exactly like the `scratch_disk`
handle two lines above it — the same class of bug, fixed for scratch
in #39 territory but missed for fork clones). `suspend` takes the dir
out of each member (`Vm::take_fork_state_dir`) and parks it on the
node record (`NodeInfo::parked_disk_dirs`, serde-persisted); `resume`
reflinks from it then reaps it; `prune` reaps it for suspended nodes.
For (4), the clone-dir builder walks up past any `.k7d-blk-fork-*`
ancestors so every fork's dir sits directly in the stable disks dir
(same filesystem, FICLONE still valid). For (5), dump to
`memory.bin.tmp` + rename — the old inode stays alive under any
existing mapping. Verified end-to-end on the daemon socket: adopted
Ubuntu root → child → grandchild → great-grandchild (depth 3, 3-VM
clusters each), clean teardown.
Regression tests: `test_cluster_tree_fork_of_fork_with_rw_disks`,
`test_tree_fork_of_fork_with_rw_disk`,
`test_ubuntu_guest_fork_of_fork`, and a fork-from-child step in the
MCP smoke.

**Reference:** POSIX unlink-vs-open-fd semantics made the deletion
invisible until the next path-based operation — the textbook way a
"loud errors" repo gets a silent one anyway.

**Time lost:** ~2 h (plus the mis-diagnosis in #129).

---

## 131. A depth quota is theatre; a competent agent fans out complete theories

**Symptom:** Take 2's README video was a depth-4 gold spine. Every
keeper was child `-0` (1/16 if each wave flipped a coin). The user
called it.

**Root cause:** `scenario_incident.py` appended "Grow a winning
lineage to depth >= 4 before replaying anything on root." Labels were
`hyp-{ts}-{i}`, so `-0` was an accidental favorite cue. Layout pinned
`children[0]` to the parent lane. The catalog miner was a lone Pod —
one delete ended it, so extra depth had nothing to do.

**Fix:** Delete the quota. Default incident is `hydra` (Deployment +
in-cluster reseed + node-local `cache-health.service`). Prompt may
say "use the 24-VM budget, fork at least 3, soak, don't crown the
first node_id" — compute / experimental-design constraints, not a
scripted spine. Labels are unordered `hyp-<hex>`. Layout continues
the middle sibling by id. Take 4: Codex + grok-4.6 inspected k8s and
host systemd *before* forking, then one n=3 wave (k8s-only /
host-only / combined). H1 respawned and was pruned; H3 (third child)
was protected and replayed. Depth stayed 1 because the model already
had the full picture. Handicapping inspect to force depth would be
theatre of another kind.

**Reference:** none

**Time lost:** one prompted take + the conversation that named it.

---

## 132. Depth comes from a causal chain, not a quota — and a lateral fix can still short-circuit it 

**Symptom:** the `relay` incident's first shape produced grok-4.6 depth
2, peak 9 — the agent solved it in one wave. A later kimi-k3 (medium)
run also stalled at depth 2, three separate times, each via a different
in-cluster shortcut.

**Root cause:** three "fixes" that were never removing the persistence
but still looked clean on a soak:
1. `kubectl scale --replicas=0` — the reconcile only checked that the
   Deployment *existed*, so a 0-replica deploy passed.
2. `kubectl patch` the container command to benign — the reconcile
   only re-applied when the deploy was *missing*, never when its spec
   drifted.
3. a node **taint** — the miner had no broad tolerations, so
   `NoSchedule` kept the respawned pod Pending forever without touching
   the host chain.
   Each let a weaker model declare victory (Tetragon quiet, victim
   Ready) at depth 2, before ever discovering layer 2/3.

**Fix:** make layer 2 *continuously enforce* the malicious desired
state — `k3s kubectl apply -f <stashed manifest>` on **every** kubelet
pod edge (not conditional on absence), and give the miner
`tolerations: [{operator: Exists}]`. Now delete / scale-0 / patch /
taint all revert within one pod edge; the only durable stop is removing
the host reseed chain, which forces the layer-2→layer-3 discovery that
creates depth. Also throttle the miner (`sha256sum` its own binary +
`sleep 0.02`) so N concurrent always-on forks do not saturate the host
(a prior n=4 wave with an unkillable 100%-CPU miner drove load to 63 on
12 cores and wedged the fork guests). Locked in by three new asserts in
`test_ubuntu_incident.rs` (scale-0 self-heal, patch revert, taint
tolerance). Grok-4.6 then peeled the host chain to **depth 3, peak 21**.

**But** kimi-k3 (medium) still landed at depth 2 by a *legitimate*
lateral fix: a CEL `ValidatingAdmissionPolicy` that denies
`CREATE/UPDATE` of the `node-agent` Deployment, so the reconcile's
`apply` is rejected at the API — one move neutralises the whole host
chain, so the sequential layer discovery (the thing that makes depth)
is never needed. Blocking that would mean defeating a standard admission
control, i.e. CTF-adjacent, which the referenced work forbids. Takeaway:
a causal chain reliably forces depth against a model that *peels* it,
but you cannot force a given model away from a shorter legitimate fix
without handicapping the environment — depth is a property of the
model's chosen path, and the asset gate (depth ≥ 3) is honest about it.

**Flagship pick (2026-08-21):** the user chose the kimi-k3 depth-2
capture as the README hero anyway (`docs/assets/k7d-mcp-demo.{mp4,gif}`).
The depth-3 grok-4.6 run remains the spec-bar proof; the flagship is
the more watchable tree (wave-2 / 21-of-24 budget pressure).

**Also (self-inflicted):** the mid-session tolerations edit corrupted
the `yaml` f-string indentation (`template`/`spec` slid under
`selector`), which kubectl rejected with `unknown field
spec.selector.template`. Validate rendered manifests with PyYAML, not
by eye. And a `pkill` over the SSH control session returned exit 255
without killing the target; the orphaned Codex agent kept forking VMs
and starved the next run — verify `pgrep` is empty after a kill, do not
trust the exit code.

**Reference:** none

**Time lost:** several full node runs (~20 min each) chasing shortcuts
and one orphaned-agent contention stall.

---

## 133. A per-tree `memory.max` cannot exist in a one-process VMM 

**Symptom:** the tree jailer was specced as "a per-tree parent cgroup
with `memory.max` and `pids.max` from `TreeBudget`". The obvious
implementation — extend `VmCpuCgroup`'s threaded `vm-<id>` pattern to a
threaded `tree-<id>` and add `memory.max` — cannot work, and the way it
fails is quiet: the `memory.max` file simply does not appear in the new
directory, so a naive implementation writes nothing and reports a jail
that isn't there.

**Root cause:** two cgroup v2 rules meeting k7d's architecture. (1)
Memory is charged per *process*, and every tree's VMs are threads of the
single k7d process, so all trees charge the same cgroup no matter how
the threads are grouped. (2) A threaded subtree may only enable
*threaded* controllers — `cpu`, `cpuset`, `pids`, `perf_event`. `memory`
is domain-only, and `VmCpuCgroup` has already converted the daemon's own
cgroup into a domain-threaded root, so no domain child can be created
under it either. Process-per-tree would fix both and is exactly what
must not be done: warm fork is an in-process `MAP_PRIVATE` CoW of the
source's memory mapping, so a tree in its own process could not be
forked from at all.

**Fix:** split the jail in two and be explicit about what each half can
enforce. `pids.max` on a threaded `tree-<id>` under the daemon's cgroup
bounds the tree's own threads (enrolment past the cap fails with
`EAGAIN`, which is the enforcement). `memory.max` goes on a *domain*
cgroup at `/sys/fs/cgroup/k7d-jail/tree-<id>` holding the tree's
virtiofsd helper **processes** — which are the part of a tree that
parses guest-controlled input anyway. Both limits derive from the
existing `TreeBudget`, so `tree_model.rs` and its Lean proofs stay shut.

**Reference:** kernel `Documentation/admin-guide/cgroup-v2.rst`,
"Threads" — the list of threaded controllers is the whole argument.

**Time lost:** ~1 h, most of it spent confirming that the limitation is
real rather than a delegation misconfiguration on the node.

---

## 134. `make check` fails on a Python suite that never ran your code 

**Symptom:** first full `make check` after the tree jailer landed died in
`k7d-mcp-test` with `tree_fork_batch: fork error: IO error: No such file
or directory (os error 2)`. Read as "the jail broke deep forks", which
is a plausible story: the fork path touches virtiofsd (now chrooted) and
the tree cgroup.

**Root cause:** the Python MCP suite talks to the **live daemon** on
`/run/k7d/k7d.sock`, i.e. `/usr/local/bin/k7d`, and `make check` runs it
*before* the Rust integration tests that install a freshly built daemon.
The binary serving it was two days old and predated every line under
test; the ENOENT came from its own stale `/var/lib/k7d/trees` state.
Nothing in the failure output says which binary answered.

**Fix:** install the build under test (`systemctl stop k7d`, copy,
`systemctl start k7d` — plain `cp` over a running binary gets `Text file
busy`) before trusting any daemon-mediated suite. The same suite passed
immediately afterwards, all the way through a 3-VM Ubuntu k3s cluster
with Cilium and Tetragon plus a deep fork. When a daemon-mediated test
fails, check `md5sum /usr/local/bin/k7d` against `target/release/k7d`
before debugging anything else.

**Reference:** none.

**Time lost:** ~30 min, plus one 3-minute suite re-run.

---

## 135. Every cluster lives on 10.200.0.0/24, so a leftover cluster answers for the new one 

**Symptom:** `make check` died in the Ubuntu smoke with
`['k7d-10-200-0-2', ...] never present after 600s` followed by
`Unable to connect to the server: tls: failed to verify certificate:
x509: certificate signed by unknown authority`. The obvious reading,
right after landing a network jail, is that the jail broke the cluster.
The same test passed standalone in 156 s minutes later.

**Root cause:** not the jail — the jail's `drop` counters were both
zero, i.e. it never dropped a packet. Every k7d cluster bridge carries
the *same* `10.200.0.0/24`, and the host holds one route per bridge. A
cluster left running by an earlier test (in this case the inner-k3s
fixture from a profiling run) still owned a guest at `10.200.0.2`, so
the host's `kubectl --server https://10.200.0.2:6443` reached **the
older cluster's** API server. Its certificate is signed by that
cluster's CA, not by the CA in the kubeconfig the test had just read
out of its own server guest — hence "unknown authority", and hence
nodes that were never "present" because the test was asking the wrong
cluster. `make check` runs `gym-test` before the Rust suite, so a
residue-producing earlier run poisons the *first* thing the next run
does.

**Fix:** none in code for now — clean residue (`systemctl restart k7d`
drops every VM; `ip link del k7-br-*`; the the referenced work stale-jail reaper
takes the tables with it) before a full run, and read an
"unknown authority" from a freshly built cluster as *"I am talking to
somebody else's cluster"*, never as a certificate bug. The real fix is
a per-cluster subnet instead of one shared `10.200.0.0/24`; that is a
network-layout change, not a jail change, and it is the natural
follow-up to this spec.

**Reference:** none.

**Time lost:** ~1 h, most of it re-running a 40-minute suite.

---

## 136. Attribute the fork budget before you blame the newest layer 

**Symptom:** the first full run with the tree jailer blew two 1 s
inner-k3s fork budgets (1.43 s CoreDNS, 1.27 s metrics-server) against
a historical ~175-200 ms. A jail had just been added to the fork path,
so the jail was the suspect.

**Root cause:** the daemon already logged
`fork_cluster_warm_batch: 1 clusters / 3 VMs in 153ms`, which said the
CoW primitive was fine, but nothing measured the ~1.2 s *around* it.
Temporary `Instant` probes on each phase of
`ClusterSnapshotTree::fork_batch` gave the answer in one run: of a
494 ms fork, the jail is ~18 ms (one 12 ms `nft -f` plus 5.6 ms of
`cgroup.threads` writes), while `save_metadata` alone is 131 ms and
re-enabling dirty tracking on the first member is 100 ms. The 1.4 s
outliers were the same fork on a host loaded by twenty minutes of
preceding suite, not a jail cost.

**Fix:** measure phase by phase before optimising or reverting. The one
probe worth keeping is in `netjail.rs`, which now logs how long its
`nft -f` took, so the jail's whole per-fork cost is visible in the
daemon log without a rebuild.

The same trap fired a second time at the other end of the suite:
`test_ubuntu_longhorn_fork_volumes` blew its 1 s fork budget at
1.139 s as the last binary of a 66-minute run, and measured **541 ms**
standalone on the same build with the jail on — against 538/696 ms
recorded before the jail existed. Two of the three fork budgets this
spec appeared to break were the host, not the code. Standalone re-run
first; it costs six minutes and it is the difference between a fix and
a revert.

**Reference:** none.

**Time lost:** ~45 min.

---

## 137. Baseline the branch you are blaming 

**Symptom:** three consecutive full `make check` runs on the tree-jailer
branch ended red, each on a *different* test: two inner-k3s fork
budgets at ~1.1-1.4 s, then `test_ubuntu_longhorn_fork_volumes` at
1.139 s, then two more inner-k3s budgets. Every one of them passes
standalone with the jail on, at or below its pre-jail number
(CoreDNS 494 ms, HPA 786 ms, Longhorn 541 ms). Three red runs still
look like a regression that only shows up under load.

**Root cause:** the node. `origin/main`, checked out into a second
worktree on the same node and run the same way, is **also** red — on
`test_fork_requeues_interrupted_injection`, a vsock timeout that has
nothing to do with any of this. The suite is ~66 minutes of sustained
KVM, k3s and container-pull load on one box, and its tightest budgets
(1 s cluster forks) do not survive that load reliably on this host.

A later run made it sharper still: the branch failed
`test_fork_requeues_interrupted_injection` at exactly the point main
did, ten minutes into `make check` — and that whole binary passes
standalone in 21 s (12/12) right afterwards. Inside the suite it runs
after `gym-test`, which leaves a live 3-node Ubuntu cluster's worth of
VMs and vsock CIDs behind; the same test then waits 52 s instead of 21 s
and times out on the agent. `make check` is ordered `lint gym-test test`,
so the Rust suite always starts on a host the Python suite just loaded.

**Fix:** when a long suite goes red on a branch, run the *base* branch
the same way before spending hours on your own diff. It costs one suite
run and it is the only thing that separates "my change broke it" from
"this node cannot hold this suite green right now". Copy the untracked
guest artifacts (`guest/kernel/vmlinux`, `guest/rootfs/initramfs.cpio.gz`,
`guest/rootfs/runc.amd64`) into the baseline worktree first — the rsync
excludes them, so a fresh tree fails instantly on a missing kernel and
tells you nothing.

**Reference:** none.

**Time lost:** ~3 h across four suite runs.

---

## 138. `kani::assume` is checked arithmetic too 

**Symptom:** `make remote-kani` on a node where Kani had to be
installed first failed one of fourteen harnesses:
`verify_initrd_placement_within_bounds`, "attempt to add with overflow"
at the *assumption*, not at anything it asserts.

**Root cause:** the harness read

```rust
let initrd_size: u64 = kani::any();
kani::assume(initrd_size > 0 && initrd_size + HIMEM_START < layout.low_size);
```

`kani::any()` ranges over all of `u64`, and the `+ HIMEM_START` inside
the assumption is ordinary checked arithmetic that Kani verifies like
any other line. For `initrd_size` near `u64::MAX` it overflows before
the assumption can rule that value out.

**Fix:** bound the value in one assumption, then use it in the next:

```rust
kani::assume(initrd_size > 0 && initrd_size < layout.low_size);
kani::assume(initrd_size + HIMEM_START < layout.low_size);
```

14/14 harnesses pass after that. Two node-setup traps came with it:
Kani is not part of `setup-node-after-reset.sh`, and
`cargo install kani-verifier` fails against this repo's pinned rustc
1.85 because its dependencies want 1.88 — install a side toolchain
(`rustup toolchain install 1.88.0 --profile minimal;
cargo +1.88.0 install --locked kani-verifier; cargo kani setup`), which
leaves the repo's pin alone.

**Reference:** Kani docs, "assumptions are verified code".

**Time lost:** ~20 min.

---

## 139. `journalctl -k | grep -i seccomp` misses the audit lines 

**Symptom:** a full `make remote-check` in `K7D_SECCOMP=log` looked
clean under the spec's prescribed grep (`journalctl -k | grep -i
seccomp` produced only the unit-test `getcpu` probe). Flipping the
default to `enforce` then killed the daemon with
`status=31/SYS` the first time `test_cni` created a TAP: `k7d.service:
Main process exited, code=dumped, status=31/SYS`.

**Root cause:** the kernel's seccomp audit line is
`audit: type=1326 audit(...): ... syscall=N ...`. It does **not**
contain the word `seccomp`. `journalctl -k | grep -i seccomp` therefore
only hits systemd's own `+SECCOMP` feature string and the unit-test
probe (whose `comm=` happens to be `seccomp::tests:`). The real
mismatches — `ip`/`k7d` `ioctl` (syscall 16) whose type byte is not
KVM/vhost/TUN (`FICLONE` is `0x94`), and iptables `alarm` (syscall 37)
— were sitting in `dmesg` the whole time, 162 of them.

**Fix:** collect evidence with `dmesg | grep 'type=1326'` (or
`journalctl -k | grep type=1326`), not `grep -i seccomp`. Added
`SYS_alarm` to `HELPER_SYSCALLS` and the missing ioctl type bytes
(`0x94` FICLONE, `0x89` SIOC, `0x12` BLK, `0x4C` LOOP, `0x58` XFS,
`0x53` CDROM, `0x02` floppy) to `IOCTL_TYPES`.

**Reference:** none.

**Time lost:** ~45 min, plus one enforce-mode suite that died at
`test_cni`.

---

## 140. virtiofsd's vring worker speaks `pwritev2` 

**Symptom:** after the ioctl/`alarm` allowlist landed, enforce-mode
`test_volumes` died with
`comm="vring_worker" exe="/usr/libexec/virtiofsd" sig=31 syscall=328`.
The earlier log-mode `dmesg` tally had never shown virtiofsd.

**Root cause:** syscall 328 is `pwritev2` (327 is `preadv2`). virtiofsd
uses the `v`2 variants for its FUSE/vhost-user I/O. The first log-mode
audit harvest rotated those lines out of `dmesg` before we counted, so
the allowlist shipped `preadv`/`pwritev` only.

**Fix:** add `SYS_preadv2` and `SYS_pwritev2` next to the existing
`preadv`/`pwritev` entries in `DAEMON_SYSCALLS`. The same worker then
tripped `syncfs` (syscall 306); `SYS_sync` / `SYS_syncfs` went in
beside `fsync`/`fdatasync`.

**Reference:** none.

**Time lost:** ~20 min.

---

## 140. 0.2.2 publish grep-gate: spec rewriting had to come back

**Symptom:** `utils/publish-to-public.sh` failed the public grep-gate
on the tagged 0.2.2 tree. Hits were `internal notes` paths in
`CHALLENGES.md` (exempt from spec-*refs* but not from the path
pattern), dozens of `the referenced work` / `the referenced work` comments in Rust and
utils, and `provider hardware reset` in a war story.

**Root cause:** #71 removed the publish-time spec rewriter on purpose
— source was supposed to stay clean. Later increments wrote the ids
back into comments and `CHALLENGES.md`. By the time the release was
tagged, rewriting forty files at the source would have needed a new
bump. The gate still forbids the strings, so the only legal fix is
the curation script.

**Fix:** restore a narrower sanitizer: drop ``-style
parentheticals first, then replace leftover `spec[s]? NNa(-inc…)`
with `the referenced work`, `internal notes` with `internal notes`,
and `provider hardware reset` / leftover `a provider` with provider
wording. `perl -CSD` and the UTF-8 gate from #69 stay. `cargo fmt`
still runs on scrubbed Rust. Landed on private `main` after the
`v0.2.2` tag so the next release does not hit the same wall.

**Reference:** none (release curation; #69 and #71).

**Time lost:** ~25 minutes.

---

## 141. `usage.live_ram_bytes` is live to the bitmap, not to KVM 

**Symptom:** after `tree_fork_batch`, sampling `tree_nodes` every 2 s
for 30 s produced a **perfectly flat** shared-vs-diverged trace. Idle
stayed 0.875024159749349, k8s 0.7764511108398438, kafka
0.5303999582926432 — same float, 16 samples, no drift.

**Root cause:** `ClusterPayload::est_ram_bytes` (the number k7view's
RAM gauge reads) is `accumulated_dirty_pages() * 4096`. That bitmap
is only merged from `KVM_GET_DIRTY_LOG` and the device-DMA maps at
fork / suspend / prepare. Between those ops the popcount cannot
grow, so a post-fork sample window is a hold of the fork-time
delta, not a live CoW clock. `NodeInfo.dirty_page_count` is even
staler (written once into `tree.json`).

This is the same class as #101 (vhost-vsock DMA invisible to KVM's
log): the gauge only sees what someone remembered to merge. 28a
forked under a Kafka producer+consumer plus a vsock ping storm
(1001 ok / 1 fail through the pause) and the branches stayed
byte-identical at the marker and independently consistent after —
#101 did not fire — but the "over time" plot cannot move without a
new merge on the `tree_nodes` path.

**Fix:** none in `crates/k7d/src` (27a freeze). Record the
cross-workload *levels* as the claim (idle 87.5% shared, k8s 77.6%,
kafka 53.0% of 6 live × 2048 MiB). Do not add a refresh primitive
because "the line should slope."

**Reference:** CHALLENGES #101, #43, #79; `vm.rs`
`accumulated_dirty_pages`; `cluster_tree.rs` `usage()`.

**Time lost:** one 28a run to notice the identical floats; not a
debug chase.

---

## 142. Cloud-agent git snapshots ship epoch mtimes and cargo skips the rebuild 

**Symptom:** `cargo test -p k7d --test test_data_disk` on a freshly
rsync'd node failed with `GUEST_OVERLAY_TABLE` / `DataDisk` "not
found in `k7d::network`" / `k7d::disks`, even though those items
were in the synced `src`. Clippy had just compiled the same crate.

**Root cause:** the CI remote checkout timestamps every file at
`1970-01-01`. `rsync -a --checksum` preserves that. After a
checksum no-op (content already on the node) the transferred-file
touch in `rsync-to-node.sh` does not run, so sources stay dated
1970 and cargo's incremental debug lib — built from an older
revision, artifact mtime 2026 — is "newer than" the source.
Tests that changed get rebuilt; the lib does not. Same trap as
#64, different carrier (epoch mtime instead of a backwards
source mtime).

**Fix:** after every sync, `find crates gym examples -type f !
-newermt 1980-01-01 -exec touch`. Plus a one-shot `cargo clean -p
k7d` on the node that already had the stale fingerprint.

**Reference:** CHALLENGES #64.

**Time lost:** one full `make check` (~15 min) plus the misread
that the node's src had drifted.

---

## 143. Sibling dirty after fork cannot use suspend+resume on the same node 

**Symptom:** the third clock in `internal notes` is
"after fork, parent vs child over time." `tree_nodes` does not
merge the dirty bitmap (#141). A live per-branch walk is a new
primitive (27a freeze). The existing merge ops are fork /
suspend / prepare.

**Root cause:** none of those ops give a repeating *cumulative*
sample on both sides of one live pair.

- `tree_suspend` of `root` writes `dirty_page_count`, but
  `resume` of a checkpoint skips `delta.pack`
  (`nearest_checkpoint == self`) and remaps from `memory.bin`
  only — it rewinds the source to prepare time.
- `tree_suspend` of a child is honest: `write_delta` of the
  full accumulated bitmap (seeded B0 ∪ new). `resume` applies
  that delta onto the ancestor `memory.bin` and is correct
  *once*. After resume, dirty tracking starts empty. A second
  suspend persists increment-only dirt; the next resume applies
  that small delta onto bare `memory.bin` and **drops** the
  first generation.
- `tree_fork_batch` on a child first `prepare_fork_source`s it
  (new `memory.bin`, zeroed bitmap), so a grandchild no longer
  measures dirt vs the original base.
- `prepare` on the source is a no-op after adopt (`wrote_base=
  false`) and does not refresh `NodeInfo.dirty_page_count`.

**Fix:** none in `crates/k7d/src`. Sample with a *cohort*: fork
n=3 siblings at one instant, suspend sibling *i* once at
t=0 / T/2 / T (leave suspended, then prune). Parent popcount
comes from a throwaway probe-fork + immediate suspend + prune
— that child is seeded with the source's just-merged
accumulated bitmap, which is still vs the original
`memory.bin`. Plot is independent popcounts, not XOR
uniqueness. CHALLENGES #141.

**Reference:** `cluster_tree.rs` `suspend` / `resume` /
`fork_batch`; `vm.rs` `seed_accumulated_dirty`.

**Time lost:** reading resume vs checkpoint before writing the
harness; did not burn a node run on a rewind.

---

## 144. Ubuntu gym Ready-wait via host kubectl hits the wrong 10.200.0.2

**Symptom:** `GYM_START_MODE=reset` n=2 (or a reset harvest after a
fork source was left up) hangs in `wait_nodes_ready` for 600s,
then fails with `x509: certificate signed by unknown authority`.
CreateVm of all three guests succeeded.

**Root cause:** every Ubuntu gym cluster uses guest IPs
`10.200.0.2/3/4`. `wait_nodes_ready` ran host `kubectl` against
`https://10.200.0.2:6443`. The host route lands on whichever TAP
was installed first — the leftover fork source, or reset member
0 — not the cluster that just booted. The new kubeconfig's
client cert does not match that API.

**Fix:** wait Ready with `curl --interface <k7-br-*>` and the
new cluster's client cert (`wait_nodes_ready_on_bridge`), the
same path scoring already uses. Do not fall back to host
kubectl.

**Reference:** none (gym guest-IP reuse + `--interface`).

**Time lost:** two harvest runs (~25 min) before the TLS error
made the collision obvious.

A killed harvest can also leave *orphan* `create_vm` guests
(`tree_list` empty, `list_vms` still running, TAP still on
`k7-br-gym-*`). `make check`'s MCP Ubuntu smoke then waits 600s
and dies the same x509 way. `harvest.drop_eval_trees` now stops
those orphans when no trees remain.

---

## 145. Fork Tetragon score saw empty curl as JSON

**Symptom:** First `GYM_SCOREBOARD=tetragon` harvest installed
Cilium+Tetragon on the source (103 s) and leased n=8. Score
returned 502: `tetragon pod list json via k7-br-gym-*: Expecting
value: line 1 column 1`.

**Root cause:** right after `tree_fork_batch` the child apiserver
can refuse. `curl_api` then returns `(7, "", "Failed to connect")`.
`tetragon_pod_names` treated any `code < 400` as JSON, including
an empty body.

**Fix:** require HTTP 2xx and a non-empty body; retry the list
for ~40 s. Do not `json.loads("")`.

**Reference:** none (fork API settle + `--interface`).

**Time lost:** one harvest (~3 min source + first lease).

---

## 146. Tetragon score cannot collect after stop k3s.service

**Symptom:** retrying the child API for 40 s still failed:
`curl: (7) Failed to connect to 10.200.0.2 port 6443 after 0 ms`.

**Root cause:** Ubuntu `kill-member-0` stops `k3s.service` on
member 0. That guest *is* the apiserver Tetragon collection uses
(`https://10.200.0.2:6443` via the fork bridge). Health scoring
does not need the API; Tetragon does.

**Fix:** when `GYM_SCOREBOARD=tetragon`, inject only the
`/tmp/k7d-tetra-*` marker and leave k3s up. Health path still
stops the unit.

**Reference:** none (scoreboard vs control-plane inject).

**Time lost:** second harvest (~3 min).

---

## 147. Host `touch` is invisible to Tetragon

**Symptom:** First tetragon harvest after #146 returned HTTP 200.
Every row had `event_diff.baseline_size=0`, `branch_size=0`,
`branch_only=[]`. Member 0 scored 0.6 (contained=0 because
injected-and-no-events); siblings scored 1.0. Same shape as the
health split, not a kprobe.

**Root cause:** Ubuntu `kill-member-0` ran `touch /tmp/k7d-tetra-*`
via vsock on the guest host. Tetragon's 25a-inc4 `fd_install`
policy fires on a **pinned busybox pod**
(`test_ubuntu_tetragon.rs` `inject_via_bridge`). Host touch is not
exported. `collect_events` also treated HTTP 200 empty log bodies
as success, so parse saw zero events instead of 502.

**Fix:** pre-pull busybox on `k7d-10-200-0-3` during sensor
install (`tetra-src-probe`); tetragon inject POSTs
`k7-kill-member-0` and waits for the kprobe. Empty log bodies are
not chunks. Score 502 if the injected unrestored member has no
branch-only events.

**Reference:** `crates/k7d/tests/test_ubuntu_tetragon.rs` inject
pod / CHALLENGES #146.

**Time lost:** one fork arm (~4 min) plus a reset arm that was
killed mid-bring-up.

---

## 148. Reset Cilium hung because the fork source still owned 10.200.0.2

**Symptom:** tetra3 fork arm scored real kprobe `branch_only` events
(32 rows). Reset lease 502 after 600s:
`cilium never Ready (numberReady='0' want>=3)`.

**Root cause:** `Gym.shutdown` keeps the source so the next gym
start can reuse it. Harvest then starts a reset gym with the same
`source_tree_id`. `startup_sweep` sees that id and keeps the fork
source. Reset `CreateVm` guests also use `10.200.0.2`. Helm
installs Cilium on the new bridge pin, but the leftover TAP wins
the collision and the new DS stays at numberReady=0.

**Fix:** reset-mode sweep drops leftover `gym-src-*` trees.
Harvest also `drop_eval_trees()` between the fork and reset arms.

**Reference:** CHALLENGES #144 (same IP, different TAP).

**Time lost:** one 600s Cilium wait.

---

## 149. Two live reset clusters cannot both Ready Cilium

**Symptom:** After #148, reset member 0 Cilium Ready in 51 s.
Member 1 of the same n=2 lease: helm install, then 600 s
`numberReady=0`.

**Root cause:** every Ubuntu cluster uses guest IPs
`10.200.0.2/3/4` and gateway `10.200.0.1` on its own bridge
(`crates/k7d/src/network.rs`). Two live reset members both claim
`10.200.0.1`. Member 0 (flannel health) can Ready that way
because images are on disk. Cilium must pull through the gateway;
the second cluster's pull never finishes.

**Fix:** tetragon reset harvest brings up one cluster at a time
(`n=1` lease, inject on member 0, `fault_id=none` on siblings)
and stitches them into one group_id. Health reset n=2 is
unchanged. Unique subnets per cluster would be a k7d change.

**Reference:** CHALLENGES #144 / #148 (same /24).

**Time lost:** second 600 s Cilium wait.

---

## 150. Solo reset Cilium also stuck in ContainerCreating

**Symptom:** After sequential n=1 reset (no overlapping 10.200.0.1),
four members Ready in ~50 s, then later solo clusters hung 600 s
with cilium/cilium-envoy `ContainerCreating` / `Init:0/6`. A fresh
harvest then failed on the *first* member the same way.

**Root cause:** not fully isolated. Quay is reachable from the
host. Guest image pull uses `10.200.0.1` egress; FORWARD is DROP
plus host Cilium chains. A failed MCP Ubuntu smoke
(`test_fork_exec_diff_prune_zero_residue`) left
`k7mcp-smoke-*` **protected**, `live_ram_bytes=0`, and
`k7-br-k7m-*` still holding `10.200.0.1/24`. A later gym cluster
then has no working gateway. `drop_eval_trees` only reaps
`gym-src-eval-` / `gym-rst-`. A vsock `ping 8.8.8.8` before helm
is now loud so the next hang is "no egress" vs "registry".

**Fix:** `assert_guest_egress` before `install_cilium_tetragon`.
Reset harvest + four LIVE plots remain 26a-inc6.

**Reference:** CHALLENGES #149.

**Time lost:** two more 600 s waits.

---

## 151. Reset Cilium pull EIO: leftover gym disks filled the 96G XFS

**Symptom:** After leftover MCP bridges were gone, a tetragon reset
member failed in ~40 s (not 600 s) on
`crictl pull quay.io/cilium/cilium:v1.16.10`:
`failed to extract layer ... mkdir .../LC_MESSAGES: input/output error`.
Host quay.io was fine. Guest ping and DNS worked.

**Root cause:** `/var/lib/k7d/disks` (96 GiB loopback XFS, CHALLENGES
#120) was 98% full / 2.1 GiB free. Reset `/release` dropped the tree
but never unlinked `ubuntu-gym-*.img`. Killed harvests left ~30
reflink clones whose unique CoW (Cilium layers, k3s) ate the XFS.
Guest virtio-blk writes then return EIO; kubelet retries look like
`ContainerCreating` for 600 s.

**Fix:** record disk paths on the reset `Env`, unlink on release and
on failed bring-up. Harvest `drop_eval_trees` also reaps leftover
`ubuntu-gym-*.img` and refuses to start below 12 GiB free.

**Reference:** CHALLENGES #120 / #150.

**Time lost:** one loud pull (the 600 s waits in #150 were this).

---

## 152. `delta.pack` names no base, and a resumed checkpoint forgets it is one 

**Symptom:** none yet — found by reading during the 30a persist
investigation, not by a failing test. The reachable sequence:
prepare a node (base v1) → fork a child → suspend the child (pack
is complete vs v1) → suspend the checkpoint node → resume it →
`fork_batch` from it again. That last fork re-prepares and writes
base v2 into the *same* node dir. Resuming the suspended child now
applies its vs-v1 pack onto v2: every page the checkpoint dirtied
after its resume that is not in the child's pack leaks into the
child silently.

**Root cause:** two halves. (1) `prepare_fork_source` (both trees)
is idempotent per **live `Vm` handle** (`fork_source_base_path`,
`tree.rs` ~:452), but `fork.rs`'s `build_vm_from_state_and_mem*`
never sets that field — a resumed checkpoint comes back with
`None` while `NodeInfo.has_base_snapshot` stays `true`, so the next
`fork_batch` re-prepares and rolls the base generation under any
suspended descendants. (2) The K7DL pack cannot detect the skew:
`write_delta` accepts and **ignores** `_base_node_id`
(`tree.rs` ~:1236), the header's last u64 is `reserved`
(`tree.rs` ~:31-42), and `resume` pairs pack↔base by
`nearest_checkpoint` path at resume time. The tmp+rename dump
(#130 item 5) protects live *mappings* of the old inode, not
on-disk packs that reference the old *content* by node id. Same
family as #143 (suspend/resume generation bugs), different member:
#143 drops a generation on one node; this skews generations across
nodes.

**Fix:** none in `crates/k7d/src` (27a freeze; 30a's verdict is
`do not implement (H)`). Recorded as the first prerequisite for
*any* future persist/tape increment: make packs self-identifying
(write the base identity into the header and verify it on
`apply_delta`) and make resume restore `fork_source_base_path`
(or key prepare's idempotence on `has_base_snapshot`) before
building B/C/F from the referenced work. Until then: do not suspend a
checkpoint node that has suspended descendants and then fork from
it.

**Reference:** CHALLENGES #130 (item 5), #143;
`internal notes` §Recommendation.

**Time lost:** none — audit finding while verifying 30a's H5/H11.

**Closed by the referenced work.** Packs now carry a base generation in the
header's former `reserved` u64 (`k7dl_set_base_identity` /
`k7dl_base_identity`, identity 0 = "unknown" so pre-30b packs still
load) and `apply_delta` refuses a known mismatch. `resume` restores
`fork_source_base_path` on a checkpoint, so forking a resumed
checkpoint reuses its keyframe instead of rolling a generation under
suspended descendants. Both halves are regression-tested in
`test_resume_rejects_stale_base`.

---

## 153. Tetragon score 502s the lease when member-0 k3s is down 

**Symptom:** k7-slime live GRPO `grpo-20260823T181800Z` could only
keep groups where member 0 sampled `start-k3s`. `kill-member-0` +
noop then `POST /score` with `GYM_SCOREBOARD=tetragon` was HTTP
502 (`Expecting value: line 1 column 1`). Reset leases 502 the
same way on a fresh cluster (`no tetragon pods`). The published
fork JSONL is all reward 1.0; the reset arm does not exist.

**Root cause:** two halves. (1) `curl_api` writes `\n%{http_code}`.
A connect fail is curl rc 7 and trailer `000`. `000 < 400`, so
`tetragon_pod_names` json-parsed an empty body and raised; one
sibling took down the whole lease. (2) `_bring_up_ubuntu_cluster`
adopted after nodes Ready and never Helm-installed Tetragon.
`tree_prepare_fork_source` after a later install is a no-op
(`wrote_base=false`); children restore the pre-sensor
`memory.bin`. Installing after prepare ages the live source
(k7-slime CHALLENGES #3).

**Fix:** `curl_api` maps `http_code < 100` to 599. Unreachable or
empty probe is `TetragonProbeError`; `_score_tetragon` emits a
row with `reachable=False` (`contained=0`, `liveness=0`) instead
of 502. Valid JSON with zero Tetragon pods stays `RuntimeError`
(sensor missing, not silent health). `ensure_tetragon` Helm-installs
1.7.0 (pin `v3.16.4`) after Ready and **before**
`tree_adopt_cluster`, so reset `collect_events` and the first
`memory.bin` already contain the DaemonSet.

**Reference:** k7-slime CHALLENGES #2–#4; the referenced work helm pin;
`examples/k7d-mcp/cluster.py` `helm_install_tetragon`.

**Time lost:** the live GRPO run (flat 1.0 curve) plus one remint
of the fork source.

The scoring half (`TetragonProbeError` → row with
`reachable=False`) is kept. The install-before-adopt half is
**not** host-kubectl `ensure_tetragon` after flannel Ready: this
branch uses `k7d.cni=none` + `install_cilium_tetragon` on the
guest bridge (CHALLENGES #144 / 26a-inc5). Host Ready-wait would
hang.

---

## 154. Headline compared n=8 fork std to n=2 reset std

**Symptom:** tetra3 / eval3 headline figures showed fork std
0.066 (health 0.132) vs reset 0.100 (health 0.200). That looks
like fork≪reset.

**Root cause:** harvest used `--fork-n 8 --reset-n 2` because two
live reset clusters cannot share `10.200.0.1` under Cilium
(CHALLENGES #149). Within-group pstdev of a one-hot split is
`|Δ|√((n-1)/n²)`. Same 0.8/1.0 bit is 0.066 at n=8 and 0.100
at n=2.

**Fix:** `match_group_n` keeps members `0..n-1` of every group
(`n` = smallest group). Headline and noise-floor plots use that
before `group_stds`. Matched tetra3 noop is 0.100 = 0.100.

**Reference:** none (sample-size identity).

**Time lost:** the published LIVE SVGs until this entry.

---

## 155. One exam question after a Ready wait cannot show fork≪reset

**Symptom:** tetra3 and tetra-churn harvests (equal n, tetragon
scoreboard) produce env0=0.8 / siblings=1.0 on **both** fork and
reset. Fair std is a tie. The recruiting claim is that
byte-identical starts keep a group together; the plot does not
show it.

**Root cause:** Two stacked compressions. (1) Lease waits until
nodes + sensors are Ready, so independent reset boots have
already converged to the same attractor before anyone is scored.
(2) The score is one yes/no poke (`contained` after `event_key`
drops time and pod UID). Photocopy vs rewrite does not matter
on a one-line true/false after everyone was handed the same
finished answer sheet. Piled-up differences would show on a
long same-exam, not on a single path inject.

**Fix:** Do not train on that bit. Do not invent jitter or score
UUIDs. Next measurement is `internal notes`:
the same 20-page SRE playbook on every member, `ready_gate=api`,
graded reward per turn, std vs turn, equal n.

**Reference:** none (measurement design).

**Time lost:** tetra3 + tetra-churn harvests before the instrument
was the problem.

---

## 146. k3s v1.32.5 device-plugin socket is stock kubelet, not the rancher path 

**Symptom:** fake GPU DaemonSet pods were Running (then CrashLooping
with exit 1 every ~30 s). `nvidia.com/gpu` Capacity and Allocatable
stayed unset on every node. Plugin logs:
`kubelet.sock missing at /var/lib/rancher/k3s/agent/kubelet/device-plugins/kubelet.sock`.
Inside the container that hostPath had only our `nvidia-gpu.sock`.

**Root cause:** the referenced work invariant 6 predicted k3s would watch
`/var/lib/rancher/k3s/agent/kubelet/device-plugins/` and that stock
`/var/lib/kubelet/device-plugins/` would fail loud. On k3s
`v1.32.5+k3s1` (host and Ubuntu guest) kubelet still uses the
compiled-in `DevicePluginPath` = `/var/lib/kubelet/device-plugins/`.
The rancher path is a different directory. `hostPath` +
`DirectoryOrCreate` on the rancher path minted an empty decoy; the
plugin listened there; kubelet never saw the socket.

**Fix:** mount both dirs; the plugin `stat`s `kubelet.sock` and uses
the dir that has it (stock path first after `PLUGIN_SOCK_DIR`).
Failure messages name both paths. Invariant 6 in
`internal notes` updated with this measurement.

**Reference:** Kubernetes `pkg/kubelet/apis/deviceplugin/v1beta1`
`DevicePluginPath`; k3s v1.32.5+k3s1 on the bare-metal node
(`/var/lib/kubelet/device-plugins/kubelet.sock` present, rancher
sibling empty).

**Time lost:** ~40 minutes (first Ubuntu cluster bring-up + 180 s
Allocatable wait + privileged debug pod).

---

## 147. `status.allocatable[nvidia.com/gpu]` does not drop when a GPU pod is Running 

**Symptom:** fake plugin registered (`Capacity=2` on every node) and
`gpu-pause` (`nvidia.com/gpu: 1`) became Running, but
`status.allocatable[nvidia.com/gpu]` stayed `2/2/2`. The test waited
180 s for Allocatable sum=5 and failed.

**Root cause:** kubelet reports `status.allocatable` as the healthy
device-plugin count, not "Capacity minus scheduled requests".
`kubectl describe node` "Allocated resources" is the sum of pod
requests. The scheduler subtracts those from Allocatable; it does
not rewrite the Node object.

**Fix:** assert Capacity=2/node (plugin healthy) and that the sum of
Running pods' `nvidia.com/gpu` requests is 1 (then 2 on the child
after the extra pod). Failure messages say so (CHALLENGES #147).

**Reference:** Kubernetes device-plugin `ListAndWatch` + kubelet
allocated-resources accounting; none of our VMM references.

**Time lost:** ~25 minutes (second Ubuntu cluster bring-up + 180 s
wait + `kubectl describe` vs `status.allocatable` diff).

---

## 148. busybox nslookup does not apply cluster DNS search 

**Symptom:** JobSet workers became Running (`nvidia.com/gpu: 1` each)
and the headless Service `gpu-jobset-done` had Endpoints with
`hostname: gpu-jobset-done-workers-0-0`. The train script's
`nslookup gpu-jobset-done-workers-0-0.gpu-jobset-done` returned
`NXDOMAIN` from CoreDNS at `10.245.0.10` for 60 s, then the Job
hit `backoffLimit` and the JobSet never Completes.

**Root cause:** busybox `nslookup` sends the name as written and
does not append `resolv.conf` search domains
(`default.svc.cluster.local` …). The short JobSet hostname the
docs show (`<pod>.<jobset>`) is not an FQDN. `wget` / `getaddrinfo`
would have resolved it; the `nslookup && wget` gate never reached
wget.

**Fix:** rendezvous on
`<jobset>-workers-<i>-0.<jobset>.default.svc.cluster.local`.
Failure messages still name that hostname.

**Reference:** JobSet concepts (headless Service = JobSet name;
pod hostname `<jobset>-<replicatedJob>-<jobIndex>-<podIndex>`);
busybox `nslookup` vs glibc resolver.

**Time lost:** ~15 minutes (cluster bring-up + 60 s rendezvous +
Job backoff + `kubectl logs` / Endpoints).

---

## 149. JobSet worker that exits after wget kills the sibling's rendezvous 

**Symptom:** After switching to the FQDN, worker-0 logs
`rendezvous ok` for both hostnames and Completes. Worker-1 stays
Running; `wget` to worker-0 is `No route to host`. JobSet never
reaches `terminalState=Completed`.

**Root cause:** each worker starts `httpd` then exits as soon as
*its* wget loop succeeds. Worker-0 finishes first, the pod
network namespace disappears, worker-1's later wget hits a dead
IP. Endpoints still list the hostname until kubelet reports the
pod down.

**Fix:** two-phase barrier: wget `/whoami` on both FQDNs, write
`/www/done`, wget `/done` on both, then `sleep 2` and exit so
httpd stays up until the sibling has also observed.

**Reference:** none (rendezvous race, not JobSet API).

**Time lost:** ~10 minutes (second bring-up + live `kubectl exec`
wget).

---

## 150. Ubuntu splits `ibv_devinfo` out of the `rdma-core` binary package 

**Symptom:** the referenced work says: if Soft-RoCE userspace is missing,
add `rdma-core` (and only that) to `APT_PACKAGES`. A loop-mount of
the 25a Ubuntu 24.04 image showed `rdma_rxe.ko` already in
`linux-modules-extra` (so not a `config-minimal` stop), `rdma`
already in `iproute2`, and **no** `ibv_devinfo`. Installing only
the binary package `rdma-core` would not have created that binary.

**Root cause:** Debian/Ubuntu split the `rdma-core` *source* package
into several binaries. On noble:

- `rdma-core` is udev rules + `rdma-ndd` / `iwpmd` (no `ibv_devinfo`)
- `ibverbs-utils` is `ibv_devinfo` / `ibv_devices`
- `ibverbs-providers` is `librxe-rdmav34.so` (already in the cloud
  image via `libibverbs1`)

`linux-image-extra-virtual` already ships the module. The missing
piece for the spec's `ibv_devinfo` assertion is `ibverbs-utils`,
not the `rdma-core` binary package.

**Fix:** add `rdma-core` (udev) **and** `ibverbs-utils` (the tool).
Mask `iwpmd.service` and `rdma-ndd.service` so the udev package
does not add a failed unit (`rdma-ndd` wants `dmidecode`, which
`--no-install-recommends` omits). Do not add perftest /
`infiniband-diags`. Do not patch `config-minimal`.

**Reference:** https://packages.ubuntu.com/noble/rdma-core and
https://packages.ubuntu.com/noble/ibverbs-utils (same source
package, different binaries).

**Time lost:** ~20 minutes (loop-mount the cached image, read the
noble file lists, decide not to stop on a missing module).

---

## 151. A stale ancestor path is the reflink keyframe's version of #144 

**Symptom:** none in a test — found while writing the incremental
keyframe path, and it would have been silent data corruption rather
than a crash. An incremental keyframe is `FICLONE(ancestor
memory.bin) + pwrite(dirty pages)`. The dirty set is only complete
*with respect to the exact bytes the live VM was mapped from*. Pick
the ancestor by walking the tree at prepare time — `nearest_checkpoint`
— and you get the ancestor's **current** `memory.bin`, which is not
necessarily the one this VM is running `MAP_PRIVATE` over. If the
ancestor re-prepared since this node forked off it, the clone is a
snapshot of a memory image the child never saw, and the child's dirty
pages patch only the pages *it* touched. Every page the ancestor
changed in between silently becomes part of the child's state.

**Root cause:** the tree graph records lineage, not the CoW mapping.
`nearest_checkpoint(node)` answers "who is my nearest checkpoint
ancestor now", and the incremental dump needs "which file are my
clean pages currently identical to". Those agree right up until the
ancestor is re-prepared — which the referenced work makes *cheap*, so a
re-prepare goes from a rare 7 s operation to something a GRPO loop
might do every generation. Exactly the #144 shape (metadata naming a
base generation that moved) one level up: #144 skews a pack against
its base, this skews a clone against its source.

**Fix:** `SnapshotTree` / `ClusterSnapshotTree` keep a `cow_base` map
from node to `(ancestor, ancestor's base_identity)` recorded at the
moment the VM is mapped — in `fork_batch` and in `resume`. The
incremental path reads that, re-checks the recorded generation
against the ancestor's current `base_identity`, and falls back to a
full dump with a warning when they differ. A full dump is always
correct; it just costs guest RAM.

**Reference:** CHALLENGES #144; `internal notes`.

**Time lost:** ~1 h of design, no debugging — caught by asking what
`nearest_checkpoint` actually promises before wiring it to `FICLONE`.

---

## 152. `du` and `stat` both lie about a reflinked file; only free space tells the truth 

**Symptom:** `test_tree_prepare_incremental` asserted that a cloned
256 MiB keyframe occupied less disk than a full dump and failed with
`du(...) = 274821120 vs logical span 268435456` — the clone appeared
to cost *more* than the file it shared every extent with.

**Root cause:** `stat` reports the full logical length for a reflinked
file, which is correct and useless. `st_blocks` counts shared extents
in **every** inode that references them, so the child reports the
ancestor's blocks as its own — the 30b spec called this out and it is
still easy to walk into. `du` is `st_blocks` with de-duplication only
*within one invocation*: `du` over ancestor and child together reports
roughly one keyframe, but `du` over the child alone reports a whole
one. The test measured the child alone.

**Fix:** sample `statvfs` on the tree filesystem either side of the
operation and assert on the delta (`common::fs_used_bytes`). That is
also the number the spec actually wants — how much disk a generation
costs the node — and it is what `gym/keyframe_cost.py` records. The
in-daemon budget does not use it: the daemon knows the true cost at
write time and records `base_disk_bytes` on `NodeInfo`.

**Reference:** `internal notes` §4; XFS reflink.

**Time lost:** ~20 min, one test run.

---

## 153. A cheap keyframe on a filesystem that cannot clone blows the disk budget 

**Symptom:** caught before it shipped, by an existing test.
`test_tree_prepare_disk_budget_loud` pins that a child prepare with
no disk headroom fails `BudgetExhausted` rather than quietly
overrunning `max_disk_bytes`. Wiring up the incremental path made it
pass for the wrong reason and then fail for a worse one: the tree
lived on `tempfile::tempdir()` (ext4), the prepare projected the
*incremental* cost, the headroom check let it through, and then
`FICLONE` returned `EOPNOTSUPP` and the fallback wrote a full dump
the budget had never been asked about.

**Root cause:** the budget check has to project a keyframe's cost
*before* the write, but whether the write is a clone or a full dump
was only discovered *during* it. Two different regimes, one estimate.

**Fix:** probe the tree root once at construction
(`tree::probe_reflink_root`) and route on the answer. On a filesystem
that cannot clone, the incremental path is never taken, so the
projection is the full span again and the old behaviour — including
that test — is exactly preserved. The per-write `EXDEV` /
`EOPNOTSUPP` fallback stays as the backstop for the cases a
directory-level probe cannot see.

**Reference:** `internal notes` §4.

**Time lost:** ~30 min.

---

## 154. The incremental keyframe's cost was the `fsync`, not the clone 

**Symptom:** the first honest measurement on the Ubuntu 3x2 GiB
cluster said the incremental keyframe was *slower* than the full dump
it replaced: 8.6 s to write 1.5 GiB of dirt, against 6.1 s to write
all 6 GiB. Every level was worse — idle 8.6 s, k8s 9.5 s, kafka 13.6 s
— which is the exact opposite of the increment's premise.

**Root cause:** two things looked guilty and neither was. The obvious
suspect was syscall count: the dirty set was ~400 000 pages and `patch`
did one 4 KiB `pwrite` each. Coalescing adjacent pages into runs cut
that to ~6 000 writes and bought **50 ms** on 8.6 s. Instrumenting the
three phases separately found the real split: `FICLONE` ~100 µs,
writes ~100 ms, `restore-swap` ~150 ms, and `sync_all()` **2–5 s per
member**. Patching a reflinked file is the pathological case for
`fsync` — every written page has to break a shared extent, and the
refcount btree updates that follow are the whole bill. Nothing in the
guest or the clone was slow.

**Fix:** drop the `fsync`. The full dump this path replaces never had
one (`dump_memory` writes, then renames), so the incremental path was
paying for a durability guarantee the codebase does not claim
anywhere else — a keyframe is host-lifetime state, and readers and
`MAP_PRIVATE` see the page cache regardless. idle went 9.09 s → 0.78 s,
kafka 13.5 s → 1.14 s, against 7.8 s for the root's full dump. The
run-coalescing stayed, because it is right even though it was not the
bottleneck, and the per-phase timings stayed as `info` logs so the next
person does not have to re-derive the split.

**Lesson:** "many small writes" is a satisfying diagnosis and it was
wrong by two orders of magnitude. The 50 ms the first fix bought
should have been the signal to stop optimizing and start measuring;
instead it cost a second full harness run to find that out.

**Reference:** `internal notes` §5; XFS CoW /
refcount btree.

**Time lost:** ~1 h, two harness runs on the live cluster.

---

## 155. A Kani harness over a 64-bit bitmap took the whole node down 

**Symptom:** a `#[kani::proof]` over `for_each_dirty_run` — one
nondeterministic `u64` of dirty bitmap, asserting the emitted runs
cover the set bits exactly — ran for 80 minutes and ended with "CBMC
appears to have run out of memory". The second attempt did worse: the
box went to load average 288 and refused SSH for ~25 minutes while the
kernel thrashed, twice, before the OOM killer got there.

**Root cause:** the function loops `for bit in 0..64` per bitmap word,
and the harness's own coverage check loops over each emitted run, so
CBMC unrolls a few thousand symbolic branches and generates ~460 000
VCCs. Constraining the input with `kani::assume(word < 256)` does not
help: the assumption prunes the solution space *after* the equation is
built, and the equation is what does not fit in 62 GB. The first
version was worse still — the out-of-span error path called `format!`,
which drags `String`, `memchr` and the allocator into the model.

**Fix:** three things, in order of how much they mattered.
1. Move the bound check out of the walk (`highest_dirty_page`, one
 comparison in the caller) so the walk is total and allocation-free —
 no `format!` in the model at all.
2. Keep the Kani proof for `highest_dirty_page`, which is the bound the
 `unsafe` slice actually rests on and which verifies in seconds.
3. Check the walk itself **exhaustively in a unit test** over all 2^16
 16-page patterns straddling the word boundary. For an 8-bit-scoped
 property that is exactly as strong as the symbolic version and runs in
 microseconds.

**Lesson:** before pointing CBMC at a loop, count the iterations it
will unroll — and if the answer is "64 times a symbolic word", an
exhaustive test over a representative width is the same theorem for
none of the cost. Also: `cargo kani` has no memory ceiling by default,
so an over-ambitious harness is a denial of service against the shared
node, not just a failed check.

**Reference:** Kani 0.67.0 / CBMC 6.8.0; `crates/k7d/src/snapshot.rs`.

**Time lost:** ~3 h, most of it waiting for the node to come back.

---

## 156. Three `make remote-check` runs, three different timing flakes, none of them the change 

**Symptom:** three consecutive full-suite runs on the same node each
failed on exactly one test, and a *different* one each time:

| Run | Test | Failure |
|---|---|---|
| 1 | `test_fork_requeues_interrupted_injection` | fork unreachable over vsock after 30 s |
| 2 | `test_latency_virtiofs_write` | 2.219 ms against a 2 ms ceiling |
| 3 | `test_inner_k3s_etcd_datastore_fork` | 1.99 s against a 1 s budget — while the daemon's own log says the fork took 114 ms |

Every one of them passed on re-run in isolation, and run 1 reproduced
identically at the pre-change commit, so none was the change under
test.

**Root cause:** the suite runs `--test-threads=1` for ~60 minutes and
the budgets were measured on a quiet node. By the time the tail of the
suite runs, the box has hundreds of VM lifetimes of page-cache and KVM
state behind it, and the *client-observed* latency picks up queueing
the daemon's own instrumentation does not see — run 3 is the clearest
case: 114 ms of daemon work inside a 1 993 ms round trip.
`latency.rs` already says this in prose for two constants
(`FORK_CLUSTER_TREE_3VM`, and the Longhorn row in `LATENCY_BUDGETS.md`
records 1 139 ms for a fork budgeted at 1 s "when the same test runs
last in a 66-minute `make check`"), so this is a known property of the
loop that nobody had written down as a *pattern*.

**Fix:** none applied here — widening someone else's budget to make an
unrelated PR go green is how a ceiling stops meaning anything. What a
change author should do instead, and what this increment did: re-run
the failing test in isolation, and if it passes, check whether it also
fails at the base commit before spending any more on it.

**Later data point :** the same test failed again at the
tail of a 53-minute suite, and this time it was the *daemon* clock over
budget, not just the client RTT — `latency_ns` 1.0027 s, of which
`warm=993 ms`. So switching the assertion to `latency_ns` (which this
suite has since done) narrows the gap but does not close it: under
enough tail contention the daemon's own work crosses a budget measured
on a quiet node. Run alone on the same node minutes later, the same
fork reported **120 ms** — an 8× margin. Treat a *near*-budget daemon
reading at the tail of a full suite as the same flake, and re-run it
alone before reading anything into it. The real fix below is unchanged.

**The real fix, when someone takes it:** the budgets need to be either
measured under the load they are asserted under, or asserted against
the daemon-reported latency (`latency_ns` on the reply) rather than the
client round trip. The second is cheap and would have made all three of
these deterministic.

**Reference:** `LATENCY_BUDGETS.md`; `crates/k7d/src/latency.rs`.

**Time lost:** ~3 h of node time across the re-runs.

---

## 157. KubeRay injects `ray start` and a GCS wait unless you opt out 

**Symptom:** a RayCluster whose containers are digest-pinned busybox
(`sleep 86400`) never keeps a Running GPU worker. The worker sits in
Init, or CrashLoops with `ray: not found` / `bash: ray: not found`.
Pulling `rayproject/ray` instead would take minutes and blow a 2 GB
Ubuntu node.

**Root cause:** KubeRay's pod builder (`ray-operator/controllers/ray/common/pod.go`)
always appends `ulimit; ray start …` unless the RayCluster carries
`ray.io/overwrite-container-cmd: "true"`. Independently, unless the
operator env `ENABLE_INIT_CONTAINER_INJECTION` is `"false"`, every
worker gets a `wait-gcs-ready` init that runs `ray health-check` against
the head — with busybox that init never succeeds. Probe injection
(`ENABLE_PROBES_INJECTION`, default on) would then kill the sleep
container for failing Ray health checks.

This is the control-plane ≠ runtime invariant: inc4 proves the operator
and `nvidia.com/gpu: 1` scheduling, not Ray / CUDA.

**Fix:** pin Helm chart `kuberay-operator-1.7.0.tgz` and rewrite the
operator image to digest; template with both env flags `"false"`; set
the overwrite-cmd annotation on every RayCluster (including the
child-only diverge). Operand stays the same busybox pin as inc1/inc2.
RayJob is skipped — it needs a live dashboard.

**Reference:** KubeRay v1.7.0 `pod.go` `BuildPod` /
`DefaultWorkerPodTemplate`; `utils.RayOverwriteContainerCmdAnnotationKey`.

**Time lost:** ~30 min reading the operator instead of pulling the
official Ray image.

---

## 158. Strict per-TAP `ip saddr` anti-spoof kills flannel host-gw 

**Symptom:** with the the referenced work per-TAP anti-spoof installed
(`ip saddr != <guest_ip> drop` on the TAP's netdev ingress), all seven
inner-k3s suites failed the same way: `inner pause pod 10.60.2.2
unreachable from server node`. The cluster came up, nodes registered,
routes were present and correct — only pod-to-pod traffic across nodes
was dead.

**Root cause:** the inner k3s clusters run flannel in **host-gw** mode.
There is no encapsulation and no SNAT for node-to-node pod traffic: a
frame carrying a pod's packet leaves the guest's eth0 with the **pod
IP** (`10.60.x.x`) as `ip saddr`, and the peer node routes the pod /24
via the guest's `10.200.0.x` address as next hop. The strict pin
"every frame's source must equal the TAP's assigned IP" therefore
classifies the CNI's entire data plane as spoofing. Nothing about this
shows up at install time — the ruleset is valid, k3s starts fine, and
the first casualty is a pod ping several layers up.

**Fix:** scope the IP pin to the shared guest subnet:
`ip saddr <guest_/24> ip saddr != <assigned_ip> drop`. The identity the
fork invariant needs protected is another guest's address in the shared
`10.200.0.0/24`; sources *outside* that subnet are routed workload
traffic and pass (the tree jail's forward chain still governs where
they may go). MAC and ARP-sender pins stay exact. The netjail
integration test now pings the gateway from a `10.60.0.5` source
through a pinned TAP to keep host-gw parity honest.

**Reference:** flannel host-gw backend (route-based, no overlay).

**Time lost:** one full 40-minute `make remote-check` cycle plus the
re-run to catch the panic line.

---

## 159. One `nft` process per TAP tripled the 50-cluster fork batch 

**Symptom:** after adding the per-TAP anti-spoof,
`test_cluster_tree_fork_batch_50` went from ~75 ms to **254 ms per
forked cluster** (3.7 s → 12.7 s for the batch). Still inside the 20 s
budget, so nothing failed — the regression only showed up because the
spec demanded a re-baseline.

**Root cause:** the fork path went from one `nft -f` per cluster (the
bridge jail) to four (bridge + three TAP pins). A single `nft`
invocation is not ~5 ms process spawn; on a node carrying a few hundred
jail tables it costs tens of milliseconds each, and it is on the
serialized host-net section of the fork.

**Fix:** batch. `ClusterNetwork::add_taps_at` creates all member TAPs
unpinned and installs every pin in **one** `nft` transaction (the
netdev tables just concatenate into one file; nft applies it
atomically). `fork_cluster_warm_batch` uses it; the ordinary
`add_tap`/`add_tap_at` paths keep the inline per-TAP install. Result:
77.0 ms per cluster, ~2 ms over the 29a jail.

**Reference:** none — measured on k7-node-02.

**Time lost:** ~1 h of measurement and rework.

---

## 160. `test_keyframe_cost` red on k7-node-02: the tree root predated the referenced work (node state, not code)

**Symptom:** on k7-node-02, `test_keyframe_cost_ubuntu_divergence_levels`
failed with `prepare fell back to a full dump -- is the tree root on
the reflink XFS?` — identically at the base commit and with
`K7D_NET_JAIL=off`, so nothing in the change under test.

**Root cause:** the referenced work was developed on a different node
(CHALLENGES #114). On k7-node-02, `/var/lib/k7d/trees` was still a
**non-empty plain directory on ext4** left by pre-30b daemons.
`ensure_reflink_tree_root` deliberately refuses to relocate a non-empty
tree root (it only warns), so every keyframe paid a full guest-RAM dump
and the harness's fallback detector fired.

**Fix:** what the warning says: park the stale dir
(`mv /var/lib/k7d/trees /var/lib/k7d/trees.ext4-<ts>`) and symlink
`/var/lib/k7d/trees -> /var/lib/k7d/disks/trees` (the reflink XFS),
exactly as `your node provisioning` does. Test green
afterwards. If a 30b-era test fails on a node that predates 30b, check
the daemon startup log for the "not the reflink XFS" warning before
reading any code.

**Reference:** `your node provisioning`,
`k7d::disks::ensure_reflink_tree_root`.

**Time lost:** ~45 min including the base-commit control run.

---

## 161. `DefaultRestrictAddressFamilies` does not apply to `systemd-run` 

**Symptom:** Ubuntu guest image had
`/etc/systemd/system.conf.d/k7d-deny-vsock.conf` with
`DefaultRestrictAddressFamilies=~AF_VSOCK`, and `k7-agent.service`
cleared it. `test_ubuntu_vsock_denied_to_non_agent` then ran
`systemd-run --uid=nobody python3 … socket(AF_VSOCK)` and the probe
printed `opened uid=65534` — EPERM never happened. The drop-in was
present in the image; systemd had no failed units.

**Root cause:** the manager default in `system.conf` is not applied to
transient units created by `systemd-run`. The probe ran as a transient
`.service` with no `RestrictAddressFamilies` of its own, so it kept
the unrestricted `socket()` surface. `SystemCallFilter=` cannot match
`socket()` by family either, so the "put it in system.conf" shape is a
silent no-op for the exact workload the increment has to deny.

**Fix (did not work):** type-wide `service.d` `RestrictAddressFamilies=~AF_VSOCK`
plus `k7-agent.service.d` empty assignment. Two more problems then
showed up on the re-image:

1. `RestrictAddressFamilies` fails `socket(AF_VSOCK)` with
   **`EAFNOSUPPORT` (97)**, not `EPERM`/`EACCES` — the increment's
   required errno.
2. The empty `RestrictAddressFamilies=` in the agent unit / drop-in
   does **not** win the merge against `service.d`. The agent itself
   got EAFNOSUPPORT, logged `vsock unavailable`, and fell back to
   serial. `connect_agent` then timed out.

**Fix (landed):** path-attached AppArmor on the workload interpreter
and the agent, plus `AppArmorProfile=k7-deny-vsock` on the k3s units
only. A `/**` catch-all broke dbus/logind. A type-wide `service.d`
`AppArmorProfile=k7-deny-vsock` then confined `apparmor.service`
itself (`Failed to prepare AppArmor profile change to k7-deny-vsock:
No such file or directory`) so profiles never loaded and the guest
could not boot. `deny network vsock` on `/usr/bin/python3*` returns
`EACCES`. `allow all` inherit-execs (`ix`). Adding `/** px ->
k7-deny-vsock` is a conflicting x modifier: `apparmor_parser -Q`
rejects it, `apparmor.service` fails, and the agent never starts.
The image builder used `-p` (preprocess only) and shipped the broken
profile. Landed: no `px`; `change_profile -> k7-deny-vsock` on the
agent; the proof test `aa-exec`s into the deny profile then
`setpriv`s to nobody. Builder compile-checks with `-Q`.
`k7-agent.service` is `After=apparmor.service` and `ExecStartPre`s a
profile-enforcing check.

**Reference:** systemd.exec(5) `RestrictAddressFamilies=` (EAFNOSUPPORT);
AppArmor 4 `deny network vsock`; `abi/4.0` `allow all`.

`allow all` also omits `mount`: k3s under `AppArmorProfile=k7-deny-vsock`
then failed overlay (`permission denied`) and the agent could not
mount virtiofs. Both profiles now name `mount`/`umount`/`capability`/
`userns`/`change_profile` (runc must be able to attach a container
profile) in addition to `dbus`/`unix`.

`make k7d-mcp-test` then failed with `agent never answered (ping miss)`
on a daemon `CreateVm` even after overlay worked: serial shows
`k7-agent: listening on vsock port 1024` and k7d logs
`vhost-vsock activated with CID …`. The in-process
`test_ubuntu_guest` suite (including ping + exec) is green on the same
image. Host-side vsock to a daemon CID is out of 29b-inc2.

**Time lost:** ~4 h (seccomp dead-ends, service.d chicken-egg, `px` vs `allow all`, mount class, mcp ping miss).

---

## 162. Daemon `latency_ns` can still miss a 1 s cluster-fork budget 

**Symptom:** after converting inner-k3s `TreeFork` asserts from client
`Instant` to `Response::TreeForked.latency_ns` (the #156 fix),
`test_inner_k3s_ingress_fork` failed in isolation at **1.26 s** and
again at **2.30 s** against `FORK_INNER_K3S_CLUSTER_3VM` (1 s). Client
RTT matched daemon `latency_ns` to <1 ms. `fork_cluster_warm_batch`
stayed **203–261 ms**. A later isolation run on the same node passed
at **349 ms** (pause+capture 20 ms, warm 209 ms). CoreDNS and
metrics-server isolation were 231 / 238 ms.

**Root cause:** `latency_ns` is the whole `ClusterSnapshotTree::fork`,
not the memcpy line in the journal. A later suite-tail CoreDNS fail
split that remainder: `start_jail` 1.08 s + `save_evict` 1.04 s after
a 98 ms warm. Two independent stalls, neither #156 (client ≈ daemon):

1. `fork_batch` called `start()` then `enable_dirty_tracking()`. The
   latter pauses a *running* child and `wait_quiescent` can sit on
   virtio-blk/net for up to 2 s each (ingress also hit the "did not
   park within 2 s" warn during prepare).
2. `atomic_write` `sync_all`'d tiny JSON (`cluster.json` in the start
   loop, `tree.json` in `save_metadata`). On a dirty XFS journal after
   a long `make check` each fsync waited ~1 s for *other* writeback.

Widening the shared 1 s constant would hide both.

**Fix:** none to the budget.
- Enable dirty tracking while the child is still stopped.
- Drop `sync_all` from cluster-tree `atomic_write` (rename stays
  atomic; a daemon crash drops the live VMs anyway).
- Cap virtio-blk/net `wait_quiescent` and `drain_device_queues` at
  200 ms (above the 100 ms worker poll). A stuck scratch-disk worker
  already proceeds with a warn; the old 2 s + 2 s stack was 4 s of
  no-op on a CoW-green fork (13 k dirty pages / 53 MiB).

Stage timings now split `save` vs `evict`. Isolation CoreDNS after the
first two fixes was 231 ms (`start_jail` 19 ms, `save` 88 µs).

A later suite tail still missed 1 s with client ≈ daemon: `warm` was
the remainder, not start/save. Two stacked inode holds on the 8 GiB
`scratch-vm-*.img`:

3. On pause the virtio-blk worker **drained the whole avail ring**
   (`process_queue` until `used.idx == avail.idx`). A busy inner-k3s
   guest queues many `OUT`/`FLUSH` chains; `FLUSH` is `sync_data()` of
   that scratch. Park therefore took 0.5–3 s, and `FICLONE` of the same
   inode while a worker was still in `pwrite`/`sync_data` took **3–7 s**
   vs **~1 ms** once parked. Waiting up to 10 s for park before
   `FICLONE` fixed the clone but charged the wait to `latency_ns`
   (local-path 547 ms park + 180 ms memcpy = 1.005 s).

**Fix (cont.):** park after the in-flight request only — leftover
descriptors stay on the ring and are replayed by the child worker and
on parent resume (same contract as virtio-net / #79). Drop the
used==avail wait in `fork_memory_for_state` (it became a 200 ms tax
per member). Cap the extra pre-`FICLONE` wait at 200 ms.

That still left a first-in-suite ArgoCD miss: extra quiesce 201 ms
`parked=false`, then `FICLONE` of `scratch-vm-*-0.img` took **3.55 s**
(members 1 and 2 cloned in 1 ms). The worker was inside `sync_data`.
`fdatasync` of the 8 GiB scratch is uninterruptible D-state on a dirty
XFS journal — `pthread_kill(SIGRTMIN)` does not wake it, and `FICLONE`
waits on the same inode. `write_all_at` also retries `EINTR` (fixed
with a pause-aware `write_at` loop).

**Fix (cont.):** `VIRTIO_BLK_T_FLUSH` returns `OK` without `sync_data`.
The guest still sees a completed FLUSH; writes are already in the page
cache and `FICLONE` shares those extents. Same class of cost as
dropping `sync_all` on cluster-tree JSON.

**Reference:** CHALLENGES #156, #79, #43; `crates/k7d/src/cluster_tree.rs`
`fork_batch` / `atomic_write`; `crates/k7d/src/block.rs` `process_queue`.

**Time lost:** ~8 h of suite-tail isolation (fsync, 2 s quiesce,
FICLONE-vs-writer, then drain-on-pause).

---

## 163. Fresh Ubuntu k3s has pause, not busybox 

**Symptom:** playbook harvest died on the first fork lease after a
Ready source:

```
RuntimeError: pinned image docker.io/library/busybox:1.36.1 not on guest
cid=0; refusing to pull mid-exam. crictl images:
docker.io/rancher/mirrored-pause  3.6  …
```

**Root cause:** 26a-inc8 pinned the 25a-inc4 Tetragon inject image and
assumed it was already on the guests. It is not. A fresh k3s airgap
only imports pause (and the rancher set). busybox lands on a node
only after a Tetragon src-probe / `crictl pull` (CHALLENGES #116).
Playbook is `fault_id=none` and must not pull mid-exam (registry
lottery, theatrical table). Waiting for a guest pull after
`ready_gate=api` would also wait out the early Ready pages the exam
is supposed to measure.

**Fix:** host-side `k3s ctr images export` of the pin (cached under
`/var/cache/k7d-ubuntu/`), plant the tarball into each reflinked
`ubuntu-gym-*.img` at `/var/lib/rancher/k3s/agent/images/` **before**
`CreateVm`. k3s imports it at first start. `wait_pinned_image` polls
`crictl images` only. Never `crictl pull` in a guest.

**Reference:** k3s airgap dir `/var/lib/rancher/k3s/agent/images/`;
CHALLENGES #116.

**Time lost:** first turns20 harvest (~3 min source bring-up) then
the discover crash.

---

## 164. Seven cached Ubuntu base images plus 24 reset disks fill the 96G XFS 

**Symptom:** playbook reset g0 (n=8, 3 VMs each) reached
`/var/lib/k7d/disks` 100% full (20 KiB free). Members then failed
with `exec failed: I/O error (os error 5)` and `http=599` to
`:6443`. Fork arm (320 rows) was fine. Reset g1, after release,
had 86 GiB free and finished clean.

**Root cause:** `build-node-image.sh` content-keys a new
`ubuntu-24.04-<key>.img` whenever the builder script changes.
The node had **seven** cached bases (~24 GiB unique) plus 24
live `ubuntu-gym-*.img` after plant+k3s write. `du` on a
16 GiB sparse file is ~3.5–4 GiB once the guest has booted.
CHALLENGES #151 was leftover gym disks; this time the leftovers
were unused **base images**.

**Fix:** delete unused `base-images/ubuntu-24.04-*` that the live
run's log does not name (keep the content key in use). Drop the
disk-full reset-g0 rows; re-harvest that group only
(`--only-arm reset --append-jsonl`, skip g1). Do not quote the
poisoned group as fork≪reset.

**Reference:** CHALLENGES #151.

**Time lost:** one poisoned reset group (~20 min of 599 polls)
plus a redo (~15 min).

---

## 165. Reset n=8: host kubectl hits a sibling's 10.200.0.2 

**Symptom:** first reset member Helm-installs Tetragon in ~99s.
Member 1 then `wait_nodes_ready` 502s after 600s:
`tls: failed to verify certificate: x509: certificate signed by
unknown authority`. k7-slime reset eval died on the first lease.

**Root cause:** every Ubuntu cluster uses guest IPs
`10.200.0.2/3/4` on its own `k7-br-*` with `10.200.0.1/24`.
`wait_nodes_ready` / `ensure_tetragon` use host `kubectl` /
`helm` against `https://10.200.0.2:6443`. With two live
bridges the kernel picks one default route; the kubeconfig CA
is the new cluster's, the TCP peer is the old one.

Score already uses `curl --interface <bridge>`. Bring-up did not.

**Fix:** `pin_guest_route(bridge, 10.200.0.2)` —
`ip route replace 10.200.0.2/32 dev <k7-br-*>` — around
`wait_nodes_ready` + `ensure_tetragon`. Delete the /32 on the
way out. Act/score stay on `--interface`.

**Reference:** `gym/README.md` (shared guest IPs); CHALLENGES
#145 leftover DOWN `k7-br-*` stealing `10.200.0.1/24`.

**Time lost:** one 13-minute reset lease (member 0 ok, member 1
waited out CLUSTER_READY_S).

The follow-on: with the /32 in place, member 1 Helm-installs but
agent pods stay `ImagePullBackOff` for 10 min (`agents=1` on
the server node only). All guests NAT through one host IP;
quay rate-limits the second cluster. `k3s ctr pull` on every
guest still hits the same NAT. `ensure_tetragon` now quay-pulls
on the server CID only, host-relays the `ctr export` (guest
`/dev/tcp` → host HTTP → agent `curl` + `ctr import`), then
deletes the backoff pods before waiting Ready (still no airgap
tar, no `imagePullPolicy: Never`).

The first relay still 502'd member 1 at 600s with `agents=1
operator=1` and agent pods `1/2 ImagePullBackOff`. Main +
operator were local; the chart's `export-stdout` sidecar
(`quay.io/cilium/hubble-export-stdout:v1.1.1`) was not in
`TETRAGON_IMAGES`, so kubelet still hit quay for the second
container.

With the sidecar in the tar, members 0–4 reached Tetragon Ready
in ~150s each. Member 5 `ctr import` then failed with
`input/output error` writing overlayfs (`usr/bin/tetra`). The
96 GiB `/var/lib/k7d/disks` loop was 96% full: 46 leftover
`ubuntu-gym-*.img` from earlier 502 abandons. `tree_drop`
stops VMs and does not unlink gym-owned reflink clones;
Tetragon layers dirty them. `_drop_tree_loud` now
`remove_tree_disks`, and `startup_sweep` unlinks
`ubuntu-gym-*.img` whose creating pid is dead.

---

## 166. k3s AppArmor + no_new_privs blocks unprivileged pod exec

**Symptom:** `make remote-check` died in `test_mcp_ubuntu_smoke`:
`tetragon-operator never Ready (readyReplicas='' want>=1) after
600s`. Guest logs were `exec /usr/bin/tetragon-operator:
operation not permitted`; coredns, metrics-server, and
klipper-helm failed the same way. Privileged Cilium / Tetragon
DaemonSet pods ran. Nodes were Ready.

**Root cause:** k3s units set `AppArmorProfile=k7-deny-vsock`
(29b-inc2). runc then `change_onexec`s to
`cri-containerd.apparmor.d`. Unprivileged pods set
`allowPrivilegeEscalation: false` → `no_new_privs`. AppArmor
refuses that transition (`info="no new privs"`) because the CRI
profile allows vsock and is not a subset of `k7-deny-vsock`.
`allow all` + `change_profile` is not enough under NNP
(CHALLENGES #161 only covered overlay/`ix` vs `px`).

**Fix:** bake k3s `config-v3.toml.tmpl` (v1.32.5+k3s1
`ContainerdConfigTemplateV3` plus `disable_apparmor = true` in
the existing runtime table) so runc does not change profile.
Containers inherit `k7-deny-vsock` — vsock stays denied, exec
works. A `{{ template "base" }}` plus a second
`[plugins.'io.containerd.cri.v1.runtime']` table is invalid
TOML (`table already exists`); containerd then exits 1 and
`k7d-k3s.service` fails. Rebuilds the content-keyed Ubuntu
image.

**Reference:** AppArmor `aa_label_is_subset` + NNP in
`security/apparmor/domain.c`; k3s
`ContainerdConfigTemplateV3` (`disable_apparmor` only when
`IsRunningInUserNS`).

**Time lost:** ~20 min (600 s tetragon wait + dmesg).

---

## 167. `test_tap_anti_spoof` pings a gateway IP owned by two bridges

**Symptom:** `make remote-check` died in `test_netjail`:
`B with the DUPLICATE ip on its own bridge must reach its
gateway`. Isolated re-run failed in 1.3 s; not leftover Ubuntu
state. The AppArmor/CRI fix never touches host nft/bridges.

**Root cause:** the test puts `10.{A}.0.1/24` on both tree
bridges so B can share A's guest IP. ICMP echo reply to
`10.{A}.0.2` is routed by the host's one FIB entry, which
prefers the first bridge (A). B never sees the reply. The
per-TAP pin is fine; the assertion was about host routing.

**Fix:** keep the unique `10.{A}.0.254/32` on B's bridge, but
probe it with an L2 ARP request sourced as `(mac_b, 10.{A}.0.2)`.
ICMP still fails: the echo reply is IPv4 to `10.{A}.0.2` and
the host FIB sends it out A's `/24` even when the request
target is unique to B. ARP replies to B's MAC on B's TAP.

**Reference:** none (host `ip addr` + FIB, not nft).

**Time lost:** ~40 min (suite wait + isolated repro + /32 ICMP
still red). Isolated re-run after the ARP probe also showed
`ip link add njhaa: File exists`: deleting the bridge unenslaves
the host veth and does not delete it, so `Side::down` now
`ip link delete`s the veth by name. The IPv6 EtherType check
now emits a raw 0x86dd frame instead of `ping6` (DAD NS is
dropped by the pin, so ping6 can send nothing).

---

## 168. `nfs-server` on a public bare-metal node is an open Portmapper (CERT-Bund)

**Symptom:** bare-metal forwarded two CERT-Bund / BSI reports for every
k7d fleet IP (`<node-ip>`, `<node-ip>`, `<node-ip>`).
`rpcinfo` from the internet returned portmapper + mountd + nfs +
statd + nlockmgr on 111/udp. bare-metal said this is informational,
not abuse.

**Root cause:** `your node provisioning` 
`systemctl enable --now nfs-server` so `test_iscsi_nfs.rs` has a
real NFSv4 server. The package starts `rpcbind.socket` on
`0.0.0.0:111` / `[::]:111`. CHALLENGES #99 already disabled
`tgt.service` for the same class of hole (unauthenticated iSCSI
on 3260) and left nfsd up because it cannot bind to
`10.200.0.1` at boot — that address exists only while a test
bridge is up. Export ACLs were scoped to `10.200.0.0/24` and
`/etc/exports` was empty, so nothing was *shared*, but rpcbind
still answered strangers. That is enough for a DDoS-reflection
listing. Offline dataset jobs on two of the nodes were unrelated.

**Fix:** `utils/lock-down-nfs-rpcbind.sh`, called from the setup
script: NFSv4-only (`vers2=n`/`vers3=n`), `rpcbind.socket` bound
to `127.0.0.1:111` plus the AF_UNIX socket, `rpcbind -h 127.0.0.1`,
and an nftables `inet k7-rpc` input hook that accepts 111/2049
only from lo and `10.200.0.0/24`. Do not enable distro
`nftables.service` (it can flush other tables). Do not pass
`-h ::1` — rpcbind on Ubuntu 24.04 double-frees if that address
is already taken. The daemon still opens `[::]:111`; nft drops
it. Apply on a live node only when no long-running job owns it
— the script restarts `rpcbind` and `nfs-server`.

**Reference:** CERT-Bund Portmapper advisory; systemd.socket(5)
empty `ListenStream=` reset; the referenced work ("NFSv4 … needs no
rpcbind/statd").

**Time lost:** ~20 min (decode the report, confirm all three
IPs, confirm generation was `clue_removal` in Docker).

---

## 169. A guest AppArmor profile, hand-loaded on the host, confined every host python3

**Symptom:** `guest/ubuntu/build-node-image.sh` (via
`gym.ubuntu.build_or_cache_image`) failed with
`mount: /tmp/tmp.*: cannot mount /dev/loop1 read-only` on
`k7-node-02` — a script that had built the same image on that node
before. dmesg showed
`apparmor="DENIED" operation="mount" profile="k7-deny-vsock"`.

**Root cause:** `k7-deny-vsock`  is a *guest*
profile that path-attaches to `/usr/bin/python3*` to deny vsock to
workloads inside Ubuntu guests. During 29b development a stale
revision of it was `apparmor_parser`-loaded into the **host**
kernel and never removed (it was not in the host's
`/etc/apparmor.d`, so it survived only in kernel memory — 10 days
of uptime). Path attachment does not care whose python it is:
every host python3, including the mcp-venv symlink, ran confined.
The loaded revision predated the #161 fix that names `mount`, so
the image builder's loop mount got EACCES. It would equally have
broken k7view's host-side `AF_VSOCK` probe.

**Fix:** `printf k7-deny-vsock > /sys/kernel/security/apparmor/.remove`
on the host. The profile belongs inside the guest image only —
never `apparmor_parser -r` it on a node. If host python breaks
mysteriously, check `/sys/kernel/security/apparmor/profiles` for
guest profile names.

**Reference:** the referenced work; CHALLENGES #161/#166 (the guest-side
history of this profile).

**Time lost:** ~30 min.

---

## 170. `make rsync --delete` ate the harness JSONL of a finished agent run

**Symptom:** a 20-minute real-model baseline run's JSONL
(`examples/k7d-mcp/logs/…jsonl`) vanished between the run finishing
and the plots being rendered. `plots.py` failed with
`jsonl missing`.

**Root cause:** experiment logs were written inside the rsynced
repo tree, and `utils/rsync-to-node.sh` uses `--delete` with no
exclude for them. The next `make rsync` (to ship an unrelated
classifier fix) deleted every log not present in the local
workspace. A second run's logs survived only because they were
created after the sync.

**Fix:** `--exclude "examples/k7d-mcp/logs*"` in
`utils/rsync-to-node.sh`, and long runs now write to a `--log-dir`
outside the repo (e.g. `/root/demo-runs/…`). The run itself had to
be repeated. Rule of thumb: anything a node-side process *produces*
must either live outside the repo tree or be in the rsync excludes,
or `--delete` will eventually eat it.

**Reference:** none (self-inflicted).

**Time lost:** ~25 min (one full baseline agent run repeated).

---

## 171. A time-gated incident whose layers are readable on disk does not induce deep forking

**Symptom:** built the `dormant` incident to make the agent fork a
copy of a copy: three host layers that resurrect a miner, with each
reseed on a systemd *timer* (~75-90 s) so reaching a cleared,
soaked state is expensive. On the first real-model run the agent
never forked past depth 1. It `cat`-ed `/var/lib/node-telemetry/sync.sh`
and `/usr/lib/systemd-unit-audit/restore.sh` and ran
`systemctl list-timers` **on the source before forking**, read the
entire three-layer chain off disk, and fixed it in one shot.

**Root cause:** two independent properties were conflated. The time
gate makes an intermediate state *expensive to reach*, but deep
forking is only rational when that state is *expensive to discover*
— i.e. when you cannot know layer N+1 exists without first
destroying layer N. My timer layers were fully discoverable by a
plain filesystem read (`.timer`/`.service` files, `state.json`,
`restore.sh`, and `systemctl list-timers` all name them), so a
thorough agent enumerated the whole chain up front and had no reason
to checkpoint anything. This is exactly the "smart agent + easy
discovery ⇒ fork gives no edge" failure the incident was meant to
avoid.

**Fix:** rebuild `dormant` on `relay`'s hidden mechanism (dormant
`.path` units the inspect battery is blind to: a `.path` is
`active (waiting)`, never a running service/timer/cron; the guard
lives in the vendor unit dir `start`ed-not-`enable`d so it leaves
nothing in `/etc/systemd/system`), and add the time gate *inside*
that — each reveal `sleep`s `DORMANT_DELAY_SEC` before it re-acts.
Now layer N+1 is invisible until layer N is destroyed *and* a soak
elapses, so the cheapest path to trying several deep fixes is to
fork the post-soak checkpoint (a copy of a copy). Hidden-ness and
the time gate are orthogonal; you need both.

**Reference:** relay incident , `incidents.py`.

**Time lost:** ~1 h (one wasted real-model recording).

---

## 172. `branch_exec`'s 60 s exec cap silently truncated every soak

**Symptom:** on the first `dormant` run every `sleep 120; recheck`
the agent issued came back `agent timeout … timed out`. The agent
could not confirm (or rule out) a timed reseeder because its soak
never completed.

**Root cause:** `tools.py` `branch_exec` called
`agent.exec_cmd(..., timeout_s=60)`. `dormant`'s reseed fires at
~75 s, so a soak long enough to observe it always exceeded the 60 s
guest-exec cap and was killed mid-sleep. The 60 s default was fine
when every incident (relay, hydra, sleeper) reseeded within seconds;
a timer/delayed reseeder is the first case that needs a minutes-long
soak in a single exec.

**Fix:** raise the `branch_exec` guest-exec cap to 240 s (the k7d
client call timeout is already 600 s) and teach the shared SRE
prompt that a reseeder may be on a timer, so a fix is only confirmed
after a couple of minutes of quiet. Normal execs still return in
well under a second; 240 s is only ever reached by a deliberate
soak or a genuinely hung command.

**Reference:** none.

**Time lost:** ~15 min.

---

## 173. Oracle `kubectl delete` returns while the miner is still Running 

**Symptom:** First live `GYM_SCOREBOARD=incident` harvest scored
`R=0` on every oracle member. `peel_ok=True` in ~1 s, then
`act=incident` returned `soak_fail` in ~20 ms. Shallow would have
been the same bit. The plot would have been an all-zero tie.

**Root cause:** `Relay.remediate_cmd` ends in `k3s kubectl delete
deploy node-agent`. That returns 0 when the delete is *accepted*,
not when the pod leaves `status.phase=Running`. The soak
predicate requires miner absent on the first poll. Starting the
30 s window immediately after the exec is a first-poll fail, not
a soak-miss.

**Fix:** After the remediating act, harvest polls until no Running
`app=node-agent` (ceiling 60 s) and folds that wait into
`t_solve` — real remediation wall time, not a sleep. Then the
soak window starts. `soak_fail` detail now names `miner` /
`victim` / `window` so a first-poll fail is not silent.

**Reference:** none (gym harvest).

**Time lost:** ~15 min (read gym-fork timestamps vs 30 s soak).

---

## 174. Self-play reused the relay incident but the lease/source path diverged in three spots 

**Symptom:** First live `GYM_SCOREBOARD=selfplay --role blue` lease
failed `502 "scripted red never settled (miner not Running)"`. The
settle branch had `plant_host` run ("relay layers 2/3 planted") but the
layer-1 miner Deployment never reached `status.phase=Running` in 120 s.
After that was fixed, the next run died at
`RuntimeError: lease missing good_fix_hint`.

**Root cause:** self-play reuses the `relay` incident payload,
`_IncidentProbe`, and `soak_clean` verbatim — but `_bring_up_ubuntu_cluster`
and the lease response gate their incident-specific setup on
`scoreboard in ("playbook","incident")` / `("tetragon","incident")`,
and `selfplay` was in none of those lists. So the self-play source came
up **without** the airgap-pinned busybox (`plant_pinned_airgap` /
`wait_pinned_image`, #163) and **without** `cni=none`+Cilium+Tetragon.
The miner pod had no image to pull (no foothold egress) and no CNI to
schedule on, so it sat non-Running and the settle wait timed out. The
lease response also omitted `good_fix_hint`, which the `blue=oracle`
checkpoint reads for the full peel.

**Fix:** add `"selfplay"` to the three source-prep branches in
`_bring_up_ubuntu_cluster` (pinned image, `cni=none`+Cilium+Tetragon,
`wait_pinned_image`) so the self-play source/reset bring-up is
byte-for-byte the incident bring-up, and return
`good_fix_hint` (the scenario incident's `remediate_cmd`) from both
`_selfplay_lease` and `_selfplay_reset_lease`. Caught by a fork-only
`--groups 1 --turns 1` smoke before the multi-hour run — run the smoke
first when a new scoreboard reuses an existing fault's machinery.

**Reference:** none (gym harvest).

**Time lost:** ~40 min (two smoke iterations, one per diverging branch set).

---

## 175. A timing-sensitive fork test failed on one gym node but passed on an identical one

**Symptom:** `make remote-check` was green on fmt/deny/clippy and all
210 gym Python units, then `test_fork_requeues_interrupted_injection`
panicked `fork ... reachable via vsock: Connection timed out` on node
`<node-ip>`. It reproduced on a direct re-run. The change under test
was Python-only (`gym/*.py`), so the Rust fork path could not have
regressed.

**Root cause:** node-local, not a code regression. The test forces an
interrupt mid-injection and asserts the restored fork is reachable over
vsock (#78); it is timing-sensitive. The same commit's `test_fork`
passed first try on `<node-ip>` — identical hardware (AMD Ryzen 5
3600), one kernel patch apart (6.8.0-136 vs -137). Some accumulated
state on `.53` (or that kernel build) tips the vsock re-queue window.

**Fix:** probe found all three gym nodes ready; pin the one that passes.
Re-ran the full `make remote-check` on `<node-ip>` — green. When a
KVM/vsock-timing test fails on a Python-only diff, re-run it on another
ready node before treating it as a regression; do **not** `#[ignore]`
it or provider-reset a node that is otherwise healthy.

**Reference:** CHALLENGES #78 (interrupt re-queue on restore).

**Time lost:** ~20 min (two re-runs + cross-node confirm).

---

## 176. Red's payload never counted as productive — the miner forks a fresh process per loop, so instantaneous `ps %cpu` measures only the idle parent 

**Symptom:** the first live red self-play harvest gave every `catalog`
member `clean=False victim=True payload=False t_solve≈61 s` — so
`red_R` gated to **0** across the board, exactly where it should be ~1.
`noop` was correctly 0. The 61 s was the full `PAYLOAD_WAIT_S` timeout:
the miner was Running (`deployment.apps/node-agent created`, and the
API `Running` check passed) but `payload_productive` kept returning
False.

**Root cause:** the relay miner command is
`while true; do /tmp/nodecheck sha256sum /tmp/nodecheck; sleep 0.02; done`
— each iteration **execs a fresh `nodecheck` process** (busybox
`sha256sum` runs and exits). Those children live ~milliseconds, so an
instantaneous `ps -eo pcpu,args | grep nodecheck` almost never catches
one; it catches only the long-lived parent `sh`, which mostly sleeps
(~1.3 %). The 5 % floor then read the busy miner as present-and-idle.
The debug log confirmed it: `running=True nodecheck_lines=1
cpu_total=1.3`. Blue never exposed this — blue peels the miner, so
blue's `payload_productive` is *expected* False and is not blue's gate.

**Fix:** measure CPU-time **accumulated over a window**, not an
instantaneous percentage. The parent `sh` reaps each child, so its
`utime+stime+cutime+cstime` (`/proc/<pid>/stat` fields 14–17) captures
the exited children's work. Sample the sum over a 4 s window; productive
if `≥ 2 %` of one core. Measured value for the real miner is ~7 %
(delta_jiffies≈22–28 over 4 s), a clean margin over an idle decoy's ~0.
Same windowed probe in the harvest wait-poll (`_payload_productive`),
which dropped catalog `t_solve` from 61 s to ~6 s. Lesson: for a
"burning CPU" gate, measure CPU **time over an interval** — a
fork-per-iteration workload is invisible to a point-in-time `%cpu`.

**Reference:** none (gym harvest).

**Time lost:** ~50 min (two instrumented red smokes + threshold pick).

---

## 177. Self-play reset arm planted the opponent before the fresh cluster's nodes were Ready 

**Symptom:** after #174, the fork arm of both roles was green, but the
**reset** arm failed on its first lease with the same
`502 "scripted red never settled (miner not Running)"`. The gym log
showed Cilium+Tetragon Ready and busybox pinned — only the miner pod
never reached Running in the settle window.

**Root cause:** `_bring_up_ubuntu_cluster` returns at the `ready_gate=api`
gate (apiserver `/readyz` up), which for a **fresh** reset cluster is
*before* the nodes are `Ready` (Cilium still marking the node
schedulable). `_apply_opponent` then planted the miner immediately, so
the scheduler had nowhere to place it and the 120 s settle wait timed
out. The fork arm never hit this: a fork of the settled source inherits
already-Ready nodes.

**Fix:** wait `wait_nodes_ready_on_bridge` at the top of
`_apply_opponent` (a fast no-op for the fork settle branch, a real wait
for reset), and pass the **right** certs per mode — the source certs for
the fork settle branch (all forks share the source CA), each reset env's
own `cert_path`/`key_path` for reset (independent clusters, `_env_certs`).
Bumped the settle deadline 120 s → 180 s for margin. Lesson: `api` gate
means "apiserver answers", not "nodes schedulable" — wait Ready before
anything that needs the scheduler.

**Reference:** CHALLENGES #144 (host kubectl hits the wrong 10.200.0.2),
#149 (sequential n=1 reset leases).

**Time lost:** ~40 min (one reset smoke + cert-per-mode refactor).

---

## 178. Pausing a VM mid-`pwrite` hands the guest a hard write error — ext4 aborts its journal and remounts read-only 

**Symptom:** the time-warp survey (5 000 pause→sample→resume cycles
across three Ubuntu k3s nodes) ended with the guest agent refusing to
run anything: `exec failed: I/O error (os error 5)`. The kernel console
told the real story:

```
I/O error, dev vda, sector 17088480 op 0x1:(WRITE) ...
Aborting journal on device vda-8.
EXT4-fs error (device vda): Detected aborted journal
EXT4-fs (vda): Remounting filesystem read-only
```

after which containerd's bolt DB, flannel's CNI state and
`fork/exec /usr/sbin/iptables` all failed with EIO and k3s panicked. The
host had 85 GB free on the reflink XFS, so this was not ENOSPC. It bit
once per run, always during the busiest phase, and looked at first like
a transient agent/vsock blip.

**Root cause:** CHALLENGES #162 made the virtio-blk worker abortable so
`FICLONE` would not wait 3–7 s behind an in-flight `pwrite`:
`write_all_at_unless_paused` returns `Interrupted` when the pause
signal lands mid-write. But the caller then did
`return (VIRTIO_BLK_S_IOERR, 0)`, so `process_queue` **completed the
descriptor with an I/O error status**. From the guest's point of view a
perfectly good write to its root disk had failed on the hardware, and
ext4 does the only correct thing with that: abort the journal and
remount read-only. Pausing once per fork made this a rare unexplained
guest, so it survived; pausing 5 000 times made it certain.

**Fix:** distinguish "aborted for pause" from "I/O error".
`execute_request` returns `None` for the former, `handle_request`
propagates it, and `process_queue` rolls `last_avail` back by one and
parks without touching the used ring — so the chain stays *available*
and is replayed on resume, the same contract the rest of the ring
already relies on. Replay is idempotent: the guest cannot reuse a
buffer whose descriptor was never completed, so re-writing it from the
start is the same bytes at the same offset. `VIRTIO_BLK_S_IOERR` is now
only ever a real error.

**Lesson:** an abortable I/O path needs somewhere to put the aborted
request. Cancelling the syscall was the easy half; the hard half is
that "not finished" and "failed" are different answers, and a virtio
device that conflates them tells the guest its disk is broken.

**Reference:** CHALLENGES #162 (the interruptible-pwrite change this
completes), #79 (leftover avail descriptors are replayed, not drained);
none upstream — Firecracker's block device is not pause-abortable.

**Time lost:** ~1 h across three survey runs (two full 5-minute cluster
runs before the console dump named the cause).

---

## 179. `KVM_KVMCLOCK_CTRL` had never once been issued — the ioctl number was wrong 

**Symptom:** the first end-to-end `warp_clock` op failed loudly on step
4: `KVM_KVMCLOCK_CTRL on vCPU 0: Invalid argument (os error 22) — this
guest has no kvmclock page registered`. That message was copied from
`fork.rs`, which had been logging the same thing as a warning on every
restore since the referenced work. But the guest demonstrably *does* have kvmclock:
`current_clocksource` is `kvm-clock`, `patch_cpuid_for_kvm_guest`
advertises `KVM_FEATURE_CLOCKSOURCE2`, and the referenced work's whole point is
that `KVM_SET_CLOCK` reaches the guest's clocksource.

**Root cause:** the constant. `KVM_KVMCLOCK_CTRL` is
`_IO(KVMIO, 0xad)` = `0xAEAD`; the code said `0x0000_AE7D`, which is
`_IO(KVMIO, 0x7d)` — an unassigned vCPU ioctl, so KVM answered EINVAL
for the honest reason that there is no such request. The error string
next to it named a plausible-sounding cause (no pvclock page) and the
call site only warned, so a hardcoded ioctl that never worked read as a
property of the guest for four months.

**Fix:** one `crate::vm::kvmclock_ctrl(vcpu_fd)` helper with the number
derived as `(KVMIO << 8) | 0xad`, used by both the restore path and
`Vm::warp_clock`. The warp path treats a failure as an error, not a
warning: a guest that cannot be told the jump was a suspend is a guest
that will report it as a stalled CPU.

**Lesson:** a hand-computed ioctl number and a best-effort call site are
a bad pair — the fallback explains away the very failure that proves the
number wrong. Either derive the number from the macro's parts (so it is
readable against the header) or let the call fail loud.

**Reference:** `include/uapi/linux/kvm.h`; none upstream (Firecracker
and Cloud Hypervisor get the number from bindings).

**Time lost:** ~20 min.

---

## 180. The guest un-warped itself: an in-guest NTP client stepped `CLOCK_REALTIME` back, and the kubelet's crash-loop backoff is wall-clock 

**Symptom:** the lockstep-warp mechanism worked — all three nodes' three
clocks jumped by the full delta — and the functional proof still failed.
A pod parked in a ~80 s `CrashLoopBackOff` did not restart within 20 s
of a +90 s warp, while `kubectl describe` showed the kubelet actively
refusing it (`BackOff` x6 over 62 s). Worse, the *jump* assertion also
failed, but only sometimes and only on one node: `agent-1` reported
`realtime +0.086s, monotonic +120.065s, boottime +120.070s` on a run
where `server` and `agent-2` both reported `+120` on all three.

**Root cause:** two independent facts that only bite together.

1. The Ubuntu 24.04 node image ships `systemd-timesyncd` enabled
   (`sysinit.target.wants`), and a k7d guest is NATted out to the
   internet with public resolvers in `/etc/resolv.conf`. So it reaches
   `ntp.ubuntu.com`, sees a two-minute offset, and — being far past the
   slew threshold — *steps* `CLOCK_REALTIME` back to true time within
   seconds of the warp. Per-node poll phase is why it looked like one
   node misbehaving rather than a daemon doing its job.
2. `CLOCK_MONOTONIC` is not stepped back, so anything measuring with it
   stays warped. That made the failure look like "the clock moved but
   the timers did not" — the opposite of the truth.

The kubelet lands on the wrong side of that split. `doBackOff` compares
`m.clock.Now()` against `cStatus.FinishedAt`, and `FinishedAt` comes
from containerd as a parsed timestamp with **no monotonic reading**, so
Go's `Sub` falls back to the wall clocks for that one subtraction. The
pod worker's requeue delay is monotonic and did fire immediately; the
backoff decision it then re-ran was wall-clock, and the wall clock had
been put back. Every restart-timing conclusion drawn before finding this
was measuring timesyncd's reaction time.

**Fix:** mask `systemd-timesyncd.service` (and
`systemd-time-wait-sync.service`, the barrier that would then never be
satisfied) in `guest/ubuntu/build-node-image.sh`, with the reason in the
manifest like every other masked unit. k7d owns the guest clock; there
is no sharing it with a daemon whose job is to disagree.
`test_warp_clock.rs` asserts the unit is masked as a named precondition,
so the day it comes back the failure says so instead of reading as a
flaky timer.

**Lesson:** when a warp is only half-undone, look for something with an
*opinion* about the clock before suspecting the mechanism — and check
which clock the consumer actually reads. Go hides that: two `time.Time`
values subtract via the monotonic clock or the wall clock depending on
where each came from, so a single struct field arriving from an RPC is
enough to turn a monotonic comparison into a wall-clock one. Also: an
image built from a distro cloud image inherits that distro's opinions
about time, and "the guest has no network" was an assumption, not a
fact.

**Reference:** kubelet `kuberuntime_manager.go` `doBackOff` +
`k8s.io/client-go/util/flowcontrol` `IsInBackOffSince`; Go `time`
package's monotonic-clock rules. None of the microVM projects hit this
because none of them warp a live guest's clock.

**Time lost:** ~2 h, most of it theorising about LAPIC re-arm and
pvclock internals before instrumenting all three guest clocks — which
answered it in one run.

---

## 181. Do-nothing red paid a host-wall 30s soak (grant smokes)

**Symptom:** flat GRPO ~73s/step, Tree-GRPO ~328s/step. kubectl
`t_solve_s` was ~0.15s. Incremental `prepare_fork_source` was ~300ms.
The leftover was a 30s `soak_clean` hold: GRPO overlapped it across
n=8; Tree-GRPO serialized it across 9 envs (~275s).

**Root cause:** untrained red plants nothing. `first_fail_reason` is
empty (no miner, victim Ready), so `action=selfplay` ran the full
host-clock `SOAK_S`. `red_R` is already 0 without a payload — the
hold proved a negative that does not change the score. Time-warp
cannot compress this: the deadline is `time.perf_counter` in the
gym process.

**Fix:** `idle_red_skips_hold` — skip `SOAK_S` when role is red and
`payload_productive` is false. Blue still holds (a peel must survive
the window). `/score` only requires a soak on envs that acted, so
idle lease members are not a 400.

**Reference:** none (gym scoreboard).

**Time lost:** grant-smoke log reconstruction (k7d journal +
`gym-fork.log`).

---

## 182. Mid-tree fork paid ~23 s to write a keyframe the child already mapped

**Symptom:** first `/fork` from a prepared lease root ~3.3 s; the
next `/fork` from that child ~23 s (Tree-GRPO smoke
`treegrpo-20260831T120017Z`). Hypothesis "re-prepare" was right.

**Root cause:** `fork_warm` already memcpys dirty pages from the live
mapping onto `MAP_PRIVATE(ancestor memory.bin)`. It refuses unless
`fork_source_base_path` is set. `fork_batch` always called
`prepare_fork_source` first ("children are not checkpoints until
prepared", #59). A share-less prepare **restore-swaps** (shutdown +
restore onto a new `memory.bin`) so later forks share that file's
page cache. The child already mapped the ancestor file — the swap
was the tax, not the memcpy. Gym `fork_env` prepared again on top.

A second trap: idempotence keyed on `fork_source_base_path`. If
inherit set the path and prepare still used that key, an explicit
`tree_prepare_fork_source` (the dirty-set reset) would no-op.

Resume already applies one `delta.pack` onto `nearest_checkpoint`.
Hop-count is not the number of packs. The old
`restore_chain_depth > max_chain_depth.min(1)` guard would have
failed a grandchild resume if we skipped prepare without dropping
it. `tree_model.rs` was left alone.

**Fix:** `ensure_forkable` inherits the ancestor `memory.bin` when
the file exists (virtiofs still prepares — FUSE DMA is invisible).
Children copy the path; `has_base_snapshot` stays false.
`prepare_fork_source` is idempotent on `has_base_snapshot` only.
Gym `/env/{id}/fork` no longer prepares. Lease settle still
prepares the episode root. Depth 2–8 and much greater stay
correct; dirty vs the root keyframe grows toward full RAM; memcpy
of ~2 GiB × 3 still beats dump + restore-swap. Explicit prepare
remains the reset. Do not auto-prepare at `max_chain_depth`.

**Reference:** none (k7d tree + gym logs).

**Time lost:** one grant-smoke reconstruction; the 23 s was sitting
in `gym-fork.log` as a second prepare.

---

## 183. Replacing a vCPU thread on every pause cost 2 ms of `synchronize_rcu` per vCPU — invisible until something paused 20 times a second 

**Symptom:** the auto-warp policy loop made the cluster *slower*. Its
first run reported 0.63× compression on a crash-loop backoff it was
supposed to shorten, and a mean pause of 6.4 ms against inc2's measured
0.79–0.83 ms for the entire three-VM warp — so 88% of every cycle was
spent in the one phase a warp has nothing to show for. Two rounds of
guessing which part of the pause that was were both wrong (the virtio
workers' 1 ms park poll, then a suspected lost stop signal).

**Root cause:** three separate things, and the order they were found in
is the whole lesson.

1. `Vm::pause` **ended** the vCPU threads and `Vm::resume` spawned
   fresh ones. KVM ties a vCPU to the thread that runs it: when
   `KVM_RUN` arrives from a different task than last time, it
   republishes `vcpu->pid` behind a full `synchronize_rcu()`. The
   calling thread waits that grace period out in state `D`, where no
   signal reaches it — ~2 ms per vCPU, six vCPUs per cycle. Perfectly
   affordable for a fork, which pauses once; ruinous at 20 Hz.
2. The stop signal was mostly being *swallowed*. `SIGRTMIN` was
   deliverable to the vCPU thread at all times, so any instance that
   arrived while the thread was handling an MMIO exit ran the no-op
   handler outside `KVM_RUN` and was gone. The thread then sat in
   `KVM_RUN` until the guest happened to exit on its own: 10.6 signals
   and ~1.1 ms per vCPU to stop a three-node cluster.
3. The loop was phase-locked to the guests' own timers. Declining
   because a timer was about to fire and then sleeping the sampling
   cadence meant the next sample landed exactly on the wakeup that
   timer caused — the one instant a vCPU is guaranteed to be awake. Half
   of all cycles declined for `vcpu_awake` on a cluster inc0 had
   measured 73.4% all-idle.

**Fix:** park the vCPU threads instead of replacing them — the thread
hands its `VcpuFd` down a channel and blocks on another, so KVM never
sees the owner change and `synchronize_rcu` never runs. Block the stop
signal on the vCPU thread and hand KVM a mask that unblocks *only* it
via `KVM_SET_SIGNAL_MASK`, which makes a signal that lands outside
`KVM_RUN` stay pending until the next entry: one `pthread_kill` is now
always enough (measured: exactly 1.0 signals per vCPU per cycle). And
give a decline that knows when it stops being true — an idle cluster
whose next deadline is inside `MIN_JUMP` — a `retry_after` of exactly
that long instead of the probe interval. Mean pause fell from 6.4 ms to
0.20 ms and the same crash-loop backoff now compresses 2.34×.

**Lesson:** instrument the phases before optimising one. A pause total
of 6.4 ms was consistent with all three causes and with two more that
turned out to be innocent, and each guess cost a 4-minute run to
disprove. Splitting `PauseCost` into freeze / stop-vcpus / quiesce named
the culprit in a single run. Also: a mechanism that is free at one
frequency is not free at another — `synchronize_rcu` per pause is
invisible in a fork path and dominant in a policy loop — and a sampling
loop that waits for the event it is waiting on will always find the
system busy.

**Reference:** KVM `kvm_vcpu_ioctl` (the `vcpu->pid` republish and its
`synchronize_rcu`), `KVM_SET_SIGNAL_MASK` semantics in
`Documentation/virt/kvm/api.rst`. Firecracker and Cloud Hypervisor both
keep vCPU threads for the VM's lifetime and pause them with a signal
plus a barrier, which is the same conclusion arrived at from the other
direction.

**Time lost:** ~3 h, over four full test runs.

---

## 184. The backoff schedule was asserted rather than measured, so a 81 s window was reported as the 300 s cap 

**Symptom:** the jump-mode test counted pod restarts, assumed the
kubelet's nominal 10/20/40/80/160/300 s doubling, and asserted the sixth
window was the ~300 s one. It reported compressing a "300 s" backoff that
the cluster's own timestamps said had been 81 s.

**Root cause:** the nominal schedule is not a promise.
`flowcontrol.Backoff` doubles a *per-pod* entry that also gets reset and
garbage-collected, whether the first failure backs off at all depends on
how the container exits, and the gap a test can actually observe is
death-to-death — it carries the container's own start-and-exit time and
the polling lag. Counting restarts and indexing into an assumed table
gets the window wrong and then states the wrong number confidently.

**Fix:** walk the schedule instead. Read
`lastState.terminated.finishedAt` at every restart, subtract successive
values to get the gap the cluster itself believes it waited, and take
the compression claim from the longest window observed — printing the
whole observed schedule next to the nominal one on every run. The test
no longer knows which restart is the capped one; it finds out.

**Lesson:** when a test's claim is about a number the system under test
chose, read that number from the system, not from documentation. The
version that assumed passed and the assumption was the bug — which is
the worst failure mode a measurement can have.

**Time lost:** ~40 min.

---

## 185. A virtio worker inherited the vCPU thread's blocked signal mask, and filled the per-user `RLIMIT_SIGPENDING` one pause at a time 

**Symptom:** ~180 s into the jump-mode run — around 86 000 policy cycles
— a vCPU stopped being stoppable. `Vm::pause` gave up after 5 s with
"257 signals did not move it", the VM was left neither running nor
paused, and every subsequent cycle declined `member_not_running`. It
reproduced at roughly the same cycle count every run, which is what
finally gave it away: nothing about the workload changed at 180 s.

**Root cause:** `/proc/<tid>/status` on the wedged thread said
`SigQ: 256510/256510`, `SigPnd: 0`, and `pthread_kill` was returning
`EAGAIN`. The signal queue was full, so no signal was being sent at all;
the vCPU was blocked in `kvm_vcpu_block` waiting for one that could not
be delivered.

What filled it: a new thread inherits the signal mask of the thread that
spawns it, and the virtio workers are spawned from *device activation*,
which is an MMIO exit — i.e. on a vCPU thread, which blocks its own stop
signal deliberately (#183). Since both jobs used `SIGRTMIN`, every
virtio-blk worker was born unable to receive the signal
`interrupt_blk_worker` sends it on every pause. `SIGRTMIN` is a
real-time signal, so each undeliverable instance *queued* instead of
coalescing, against a limit counted per **user** rather than per thread.
Three members × ~86 000 pauses ≈ 258 000 queued signals ≈ exactly the
256 510 the kernel reported. Then every thread in the process — vCPUs
included — stopped being signallable.

**Fix:** give the vCPU stop signal its own number (`SIGRTMIN() + 1`), so
the mask discipline the vCPU path needs cannot swallow a signal meant
for anything else, and explicitly `SIG_UNBLOCK` the worker's own
interrupt at the top of the worker thread so an inherited mask can never
silently swallow a kick again. Separately, back the stop-signal retry
off from a flat 50 µs to a doubling 50 µs → 20 ms: a wedged vCPU used to
queue 45 536 signals inside one 5 s timeout, which turned one stuck
thread into a process-wide outage.

**Lesson:** a blocked real-time signal is a slow memory leak with a
process-wide blast radius, and "the signal had no effect" and "the
signal was never sent" look identical from userspace. The kernel already
knows which it is — `SigQ`, `SigPnd` and `SigBlk` in
`/proc/<tid>/status` answered in one run what a day of reasoning about
KVM's wait loops did not. Also: sharing one signal between two
subsystems couples their masking rules, and thread-mask inheritance
makes "which thread spawned this one" part of the interface.

**Reference:** `signal(7)` on real-time signal queueing and
`RLIMIT_SIGPENDING`; `pthread_sigmask(3)` on inheritance. None of the
reference VMMs hit this — they interrupt their workers with eventfds
rather than signals.

**Time lost:** ~1.5 h, of which the last 10 minutes were the only ones
that mattered: printing the signal lines of `/proc/<tid>/status`.

---

## 186. Red no-egress fetch was HTTP 502 and aborted the GRPO group

**Symptom:** untrained Qwen emitted `curl http`. Gym refused it
(`no egress supply line`) as `RuntimeError` → HTTP 502. Trainer
`is_illegal_act` only skipped 400, so `EnvPool.map_handles`
quarantined member 7 and killed the 10-step smoke.

**Root cause:** a foothold *policy* refusal is a client error, not a
dead k7d. `RuntimeError` in `gym/server.py` `do_POST` is 502.

**Fix:** `refuse_egress_fetch` / `assert_no_admin_creds` raise
`ValueError` (400). Trainer also skips a 502 that still names the
egress/admin guard, so a stale gym process does not abort the group.

**Reference:** none (gym scoreboard).

**Time lost:** one RunPod placement + pip + first step.

---

## 187. `test_resume_rejects_stale_base` still assumed fork prepares mid

**Symptom:** first full `make remote-check` after #216 (inherit
ancestor keyframe) failed only this test, after clippy and the
long inner-k3s / kubectl binaries had already passed:

```
assertion `left != right` failed: a prepared node must carry a base generation
  left: 0
  right: 0
```

**Root cause:** the test forked `leaf` from `mid` and treated that
as `prepare_fork_source(mid)` — true before the referenced work, false after.
`mid.base_identity` stays 0 (inherited path, no owned keyframe).
The pack the leaf writes names the **root** generation. The
stale-base check itself is still right; the setup was stale.

**Fix:** prepare `mid` explicitly before forking `leaf`, so the
pack still names a real generation and the first half still
proves a resumed checkpoint is not re-keyed by a later fork.

**Reference:** none (`test_tree.rs` vs the referenced work).

**Time lost:** one full `remote-check` on k7-node-01 (~1 h) to
reach this binary.

---

## 188. A host-paced churn loop makes the accelerated arm of a benchmark do less work, and reports it as a win 

**Symptom:** none — which is the point. The busy phase of the warp
benchmark was, following inc0, a host-side loop that scaled a Deployment
every ~2 s of *host* time while a pod burned CPU, for a phase whose
length is set in guest time. Under arm B that phase would have reported
a healthy compression with no error, no warning and no failed assertion.

**Root cause:** the phase ends on a guest-time event (a pod that
`sleep 180`s and then `Succeeded`s), so under a policy that compresses
wall time by C, the phase's wall duration shrinks by C — and a loop
paced in wall time therefore performs `1/C` as many rounds inside it.
Arm B's cluster would have been asked to reconcile ~86 times in arm A
and ~47 times in arm B, so the two arms would have shared a phase name
and not a workload. The measured quantity, "how long does *this*
episode take", quietly became "how long does a lighter episode take".
The spec's Trap says "any host-side sleep in the harness is a bug that
silently caps B/C/D", which is the same hazard pointed the other way:
a host sleep *lengthens* the accelerated arm, a host-paced work loop
*lightens* it. The first is conservative and the second flatters.

**Fix:** move the churn into the guest — one brief `exec` backgrounds a
`while …; do k3s kubectl scale …; sleep 2; done` shell on the server
node, writing a round counter to a file the harness reads afterwards.
`sleep` in the guest is guest time, so the loop's rate is warped along
with everything else it is supposed to be pacing against. Then assert
the counter across arms: both arms completed **86** rounds, which is the
evidence that the workload was fixed in guest time rather than a claim
that it was. Round count belongs in the fidelity table next to probe
failures, for the same reason.

**Lesson:** in a benchmark of a mechanism that changes the guest's clock
rate, every actor has to be classified by which clock paces it, and
anything on the host's clock is either capping the accelerated arm or
thinning it. "No host sleeps" is not sufficient; the harness must also
own no timed *loop*. And the cheapest guard is a workload counter that
must come out equal across arms — an equality that is trivially true in
the baseline and only holds in the warped arm if the pacing is right.

**Reference:** none — inc0's survey loop was correct for a survey, where
no arm compresses anything, and was carried into a place where it was
not.

**Time lost:** ~1 h, all of it before the first arm-B run — caught while
reading the spec's Traps against the phase code rather than by a
failure, which is the only way this one can be caught.

---

## 189. Dropping `CONFIG_DEBUG_INFO_BTF_MODULES` from a module build makes every module unloadable 

**Symptom:** the carried KVM modules built cleanly against the running
kernel's source, `modinfo -F vermagic` matched `uname -r` exactly, and
`insmod` answered `Invalid module format`. `dmesg` had one line:
`module kvm: .gnu.linkonce.this_module section size must match the
kernel's built struct module size at run time`.

**Root cause:** the build script copied `/boot/config-$(uname -r)` and
then turned off `DEBUG_INFO_BTF` and `DEBUG_INFO_BTF_MODULES`, on the
reasonable-sounding grounds that BTF needs a `pahole` matching the
distro build and buys an out-of-tree module nothing.
`CONFIG_DEBUG_INFO_BTF_MODULES` is not only a build step, though: it is
`#ifdef`'d into `struct module` itself (`btf_data`, `btf_data_size`), so
disabling it shrinks the struct the module declares while the running
kernel still expects the larger one. Nothing in the vermagic string
covers it, which is why every version check passed.

**Fix:** leave the config alone. The BTF *generation* step in
`scripts/Makefile.modfinal` skips itself with a printed warning when
`vmlinux` is absent — which it always is, since only `modules_prepare`
is run — so keeping the option costs a warning and buys a loadable
module. Only `MODULE_SIG_ALL` and the trusted-key blobs are turned off,
and neither is in `struct module`.

**Lesson:** for an out-of-tree module, the distro `.config` is part of
the ABI, not a build preference. Any option that appears inside an
`#ifdef` in `include/linux/module.h` has to survive unchanged, and
vermagic will not tell you which ones those are. The kernel's own error
message names the mechanism precisely — read it before assuming a
version mismatch.

**Reference:** Linux `include/linux/module.h`, `kernel/module/main.c`
(`elf_validity_cache_index_mod`).

**Time lost:** ~40 min, two full module rebuilds.

---

## 190. The APIC bus cycle was calibrated in wall time, so dilation silently moved the whole jump policy into the wrong unit 

**Symptom:** none, and that is the whole entry. Arm D of the warp bench
(continuous dilation *and* the jump policy) would have run green,
warped, and reported a number — a number that was eight times too
small, with the daemon's counters agreeing with the guests' clocks
because both were wrong in the same direction.

**Root cause:** `Driver::decide_jump` targets `earliest_deadline − ε`,
and the deadline comes from the LAPIC's `TMCCT` count times a
*measured* APIC bus cycle (`Vm::calibrate_apic_bus_cycle_fs`, ~996 fs
on this node). That calibration drains the count over a
`std::thread::sleep` window and divides by the window, so it measures
wall nanoseconds per bus cycle. At 1× that is also guest nanoseconds
per bus cycle and nothing notices. Under dilation the count drains N
times faster in wall time, so the same arithmetic returns `1/N` ns and
every consumer of it — ε, `MIN_JUMP`, the 30 s `MAX_JUMP` cap, and the
deadline a jump aims at — quietly became a wall-time quantity. But
`warp_clock` applies its delta as *guest* nanoseconds. So a jump aimed
at a deadline 800 ms of guest time away would have advanced the guest
by 100 ms, and the cap meant to protect a 40 s node lease would have
protected 5 s of it.

**Fix:** one multiplication. `calibrate_apic_bus_cycle_fs` scales its
window by the VM's dilation factor before dividing, so it reports guest
nanoseconds per bus cycle — the unit the guest's own timers are in, and
the unit every consumer already assumed. At 1× it is the identity. Arm
D's three runs measure 995 799–998 854 fs, the same ~1 ns as the
undilated arms, which is the assertion that it worked: a bus cycle that
still reads 1 ns under dilation is one measured in the guest's units.

The plausibility band on that calibration (0.1–100 ns) is also worth
knowing about: without the fix it would have read 0.125 ns at N=8 and
been *accepted*, and would only have been rejected somewhere past N=10.
A range check wide enough to admit a wrong answer is not a guard.

**Lesson:** when a system gains a second time base, every measured
constant has to be re-labelled with which base it is in, including the
ones that were correct for years. The dangerous ones are exactly those
where the two bases coincided — a wall-time calibration feeding a
guest-time actuator is invisible until the rates differ, and then it is
silently off by the rate.

**Reference:** none.

**Time lost:** ~30 min of reading, zero of debugging — found by walking
`decide_jump` backwards through its units before running arm D, which
is the only point at which it was cheap to find.

---

## 191. A dilated guest mints TLS certificates in the host's future, and host-side `kubectl` refuses them 

**Symptom:** the first `kubectl get nodes` calls against a freshly
booted 8× cluster failed with `x509: certificate has expired or is not
yet valid: current time 2026-09-01T01:59:12+02:00 is before
2026-08-31T23:59:16Z`. They then succeeded a few seconds later and the
cluster was fine.

**Root cause:** k3s generates its CA and serving certificates inside
the guest, with `notBefore` taken from the guest's `CLOCK_REALTIME`.
That clock runs 8× wall from the moment the VM starts, so by the time
k3s bootstraps its TLS the guest is already seconds — and after a
30 s boot, minutes — ahead of the host. `kubectl` runs on the host and
validates against host time, so the certificate is legitimately not yet
valid from where it is standing. It resolves itself only because host
time catches up.

**Fix:** none needed at N=8 — the existing `wait_nodes_ready` retry
loop absorbs it, and the offset at cert-minting time is a few seconds
because k3s mints early in boot. Recorded rather than fixed because the
scaling is bad: the skew at any later moment is `(N−1)` times the
guest's uptime, so anything that mints a certificate *late* in a long
dilated run hands the host something valid minutes or hours from now,
and no retry loop absorbs that. The two ways out, if it ever bites, are
to talk to the API server from inside the guest (`k3s kubectl`, which
`warp_bench`'s in-guest churn loop already does) or to start the VM
with its realtime clock set back by the skew the run will accumulate.

**Lesson:** dilation is not confined to the guest the moment anything
crosses the boundary carrying a timestamp. Certificates are the obvious
case; log correlation, `Expires` headers and anything signed have the
same shape.

**Reference:** none.

**Time lost:** ~15 min, all of it deciding it was expected rather than
a bug.

---

## 192. A dead workspace-lock holder lets a second agent rsync over a live `make check`

**Symptom:** `make remote-check` for the gym AutoWarp PR reported
`test_gym` as `running 2 tests` — the new
`test_gym_autowarp_mode_jump` was in git and in the local tree
(832 lines) but `/root/k7d/crates/k7d/tests/test_gym.rs` on the
node was the pre-PR file (733 lines). `gym/tests/test_autowarp.py`
was gone. Python gym tests earlier in the same log had passed
against the PR sources.

**Root cause:** `utils/remote-run.sh` holds `workspace.lock` with a
detached `flock` process so an ssh drop does not release mid-build.
That holder (pid 778132) died while the `check` `run.sh` was still
alive. A parallel dilation agent (`dilbuild`,
`internal notes`) then acquired the lock and
`rsync --delete`'d its tree onto `/root/k7d` (every key file mtime
`2026-09-01 01:37:35 +0200`, same second as `dilbuild/origin`).
Cargo rebuilt later integration binaries from the overwritten
tree. The dilation install itself then failed (`kvm_amd` in use)
and left the stock module; the damage was the source tree, not
KVM.

**Fix:** treat a live `check` whose `/root/k7d` no longer matches
the agent branch as corrupted — `K7_REMOTE_RESTART=1 make
remote-check` so the next rsync is ours. Do not trust a green
suite that compiled after a foreign rsync. After the restart,
delete any leftover `k7-br-*` that is DOWN but still has
`10.200.0.1/24` (`cleanup_stale_k7_bridges` / `ip link delete`)
before the next suite: the killed ubuntu-k3s run left
`k7-br-ubk3s` in that state, the kernel kept
`10.200.0.0/24 dev k7-br-ubk3s … linkdown`, and the MCP ubuntu
smoke then failed with `dial tcp 10.200.0.2:6443: no route to
host`. The lock is still the right interlock; a dead holder is a
preexisting hole, not a reason to skip it.

**Reference:** none (`utils/remote-run.sh` lock vs two Cursor
agents on one `K7_NODE_IP`).

**Time lost:** ~the rest of that `remote-check` after the
overwrite (ubuntu binaries compiled against the wrong tree) plus
the diagnosis.

---

## 193. `AutoWarp` looked only at the CreateVm registry, so every gym child was "no VM on cluster"

**Symptom:** `test_gym_autowarp_mode_jump` got HTTP 502:

```
auto_warp: no VM on cluster gym-src-warp-…-gym-br-…-0000
```

The gym had just forked that cluster (`_envs_from_forks` found the
bridge). `inject none` succeeded. `_enable_autowarp` then failed.

**Root cause:** `Daemon::auto_warp` / the policy loop only scan
`self.vms` (CreateVm / shim members). `tree_create_cluster` and
`tree_fork_batch` own their VMs inside `ClusterSnapshotTree::live`.
inc3's Ubuntu tests drive `Driver` in-process; the warp-bench
keeps CreateVm VMs in the registry. The gym's real path is the
tree, so `{tree_id}-{node_id}` never matched a registry entry.

**Fix:** the start check and each cycle also resolve
`{tree_id}-{node_id}` (or `tree_id` → live `root`) through
`trees`. Tree members have no CreateVm CFS cgroup to reattach.

**Reference:** none (daemon registry vs cluster tree).

**Time lost:** one `remote-check` to reach `test_gym`.

---

## 194. In-guest `kubectl` still dies if the exec outlives the agent's 30 s window 

**Symptom:** the first N=1 sweep run, after moving every cluster call
onto `k3s kubectl` inside the guest (CHALLENGES #191), panicked with
`guest exec ... Timeout` while deleting the RTT pods. Host-side
`kubectl` never hit this; the same episode had been passing for inc4.

**Root cause:** the guest agent exec path is a 30 s RPC. Two in-guest
calls ignored that:

1. `kubectl rollout status --timeout=300s` is one exec that blocks for
   up to five minutes of *guest* time. At N=1 that is 300 s of wall.
2. The episode's clock / Ready poll reconnected every 500 ms. Each
   reconnect is an agent exec; by the time the RTT cleanup ran, the
   next call landed on a connection the previous tight loop had
   already burned.

`--request-timeout=20s` on the kubectl invocation is necessary but
not sufficient: it only bounds the API call, not a `rollout status`
that is designed to wait.

**Fix:** poll `readyReplicas` with short `get`s; force-delete leftover
pods; sample every 2 s of wall (`POLL` / `SAMPLE_EVERY` in
`test_dilation.rs`), not 500 ms. `guest_kubectl` returns `Err` on
timeout instead of panicking so a missed poll is a retry, not a
failed suite.

**Lesson:** moving a call *into* the guest does not make it free of
host-side deadlines. The agent's exec window is a host-time budget
on a guest-time command. Anything that waits in guest time has to
be a loop of short execs.

**Reference:** none.

**Time lost:** ~40 min (one N=1 run plus the poll rewrite).

---

## 195. systemd `TimeoutStartSec` and `timeout 180` are guest seconds 

**Symptom:** N=1..12 of the sweep completed. The first N=16 bring-up
failed with `agent-1: systemd is degraded` / `k7d-k3s.service`
`status=1`. The journal said `k3s-agent.service did not start within
180s`, then on the retry `TimeoutStartSec=240` killed the oneshot
before the script's own timeout could fire. From the host the agent
had been up for ~12 s.

**Root cause:** every timeout in the Ubuntu image is a guest-time
budget. At N=16, 180 s of guest time is 11 s of wall and 240 s is
15 s — shorter than k3s-agent's unpack + join. The oneshot is
calibrated for a stock boot, where 180 s is generous. Dilation does
not make k3s start faster; it only makes the clock that measures
the start faster.

**Fix:** `timeout 180` → `600` and the `/readyz` wait 90 → 300
(`guest/ubuntu/k7d-k3sconfig`); `TimeoutStartSec=240` → `900`
(`guest/ubuntu/units/k7d-k3s.service`). 900 s is 56 s of wall at
16× and still only a hang ceiling at 1×. These files are hashed
into the Ubuntu node image, so the next `bring_up_cluster` rebuilds
it.

**Lesson:** a start timeout that is tight in guest seconds becomes a
race the moment the guest clock is a multiple of wall. Raise the
guest-time budget; do not "fix" it by shortening anything, and do
not treat a 12 s wall failure as a k3s hang.

**Reference:** none.

**Time lost:** ~90 min (one failed N=16 bring-up, image rebuild,
follow-up `K7_DILATION_SWEEP=16`).

---

## 196. An edited KVM patch silently installed the previous one, so the new ioctl path was never running 

**Symptom:** every live dilation change in `test_dilation.rs` failed
with `KVM_SET_DEVICE_ATTR(KVM_VM_DILATION) = 4: Device or resource
busy`, on a host that `state.sh` cheerfully reported as `patched
(default factor 1)`. `EBUSY` is exactly what the *new* code returns
when a vCPU is runnable, so the obvious reading was that `pause()`
does not really get the vCPUs out of `KVM_RUN` — a wrong and
expensive thing to start debugging.

**Root cause:** two independent staleness shortcuts in the install
path. `build.sh` stamped the patched source tree with a bare
`.k7-dilation-applied` flag and skipped `patch` whenever it existed,
and `install.sh` skipped `build.sh` entirely whenever a `kvm.ko`
existed in `$WORK/modules`. Both are correct for re-installing the
*same* patch and both are silent when the patch has been edited: the
tree still held the inc4 patch, the modules were still the inc4
modules, and the host really was patched — with generation 1, whose
whole behaviour is to refuse a live change.

A third shortcut then hid the fix: a failed `patch` run left the tree
half-rewritten with no stamp, and a tree with no stamp was treated as
pristine, so the next install re-applied over it and died with
"Reversed (or previously applied) patch detected".

**Fix:** key everything on the patch's own content.
`build.sh` stamps the tree with the patch's `sha256`, re-extracts
whenever the stamp is missing *or* different (missing means a failed
apply, not a clean tree), drops `--forward` so a "previously applied"
hunk on a fresh tree is an error rather than a skip, and clears
`$WORK/modules` before copying. `install.sh` rebuilds unless
`$OUT/patch.sha256` matches the patch it is about to install.

And the loud check the whole thing needed: the patch now exposes its
own generation as a read-only `KVM_VM_DILATION_ABI` attribute
(1 = inc4 create-time only, 2 = inc8 live SET), `probe.c` prints it,
and the suite's `require_patched_host()` refuses a host below the
generation it needs. Generation 1 predates the attribute and is
inferred from its absence, so an old module is *named* rather than
guessed at.

**Lesson:** "is this host patched" is not a sharp enough question for
a patch that lives in the tree and is rebuilt from it. A cache keyed
on "an artifact exists" is a silent fallback with a build step
attached, and the failure it produces is a plausible-looking bug in
whatever code called the missing feature. Version the interface, not
just the presence of it.

**Reference:** none.

**Time lost:** ~45 min, plus two 90-second install cycles and one
abandoned 40-minute suite run.

## 197. `dilation-install` stopped k7d, then could not unload `kvm_amd`, and left the node with no daemon 

**Symptom:** `make remote-dilation-fork-test` on the first fleet node
died in two lines — `== stopping k7d (it holds /dev/kvm)` /
`modprobe: FATAL: Module kvm_amd is in use` — and afterwards
`systemctl is-active k7d` said `inactive`. The readiness probe every
other agent runs on that node would have failed from then on. The
node's own `/run/k7d-remote/dilation/log` showed the inc6 agent had
hit the identical wall on the same node that morning and moved on
without a note.

**Root cause:** two things. (1) `fuser /dev/kvm` was empty because the
holder does not keep `/dev/kvm` open — a VM is an `anon_inode:kvm-vm`
fd. Walking `/proc/*/fd` found it: a **Kata + firecracker pod**
(`default/t-…`, label `katakate.org/sandbox: t`, RuntimeClass `kata`)
running on that node for 16 days, unrelated to k7d, pinning the module
refcount. (2) `install.sh` stopped k7d *before* the `modprobe -r`
interlock and only defined `start_k7d`/the `ERR` trap *after* it, so
the interlock failing under `set -e` exited with the daemon down.

**Fix:** `install.sh` now defines `start_k7d` first; when
`modprobe -r` fails it lists every process holding a `kvm-vm` fd,
restarts k7d, and exits 1. The Kata pod was left alone (not ours);
the fork tests ran on the primary node instead, where `kvm_amd` had
refcount 0.

**Lesson:** "module in use" on a fleet node is a *who*, not a *what* —
look in `/proc/*/fd` for `anon_inode:kvm-vm`, not at `/dev/kvm`. And a
script that stops a shared daemon must restart it on every exit path
that is not the success path, including the one before its own trap
is armed.

**Reference:** none.

**Time lost:** ~20 min, plus whatever the daemon-less node cost anyone
probing it in the interval.

---

## 198. N=1 on patched modules is stock-clean except for the same single-restart flake inc6 already published at other N 

**Symptom:** `test_dilation_three_node_k3s_fidelity_sweep` failed at
the N=1 `hard_clean` assertion after a full 70-minute suite: run 0
and run 2 each had one unscripted kube-apiserver restart, wall
241.2–241.6 s, compression 1.00×, NotReady 0, splats 0. A re-run
got the same restart on N=1 run 2. inc8's first sweep hit it once
too and passed only on a second full sweep.

**Root cause:** at N=1 the dilation map is the identity
(`dilation_base_ns == dilation_base_out_ns`, so
`kvm_dilated_base_ns` returns `host_ns`). A restart there is k3s,
not the patch. inc6's own `## Results` already records a single
restart at N=8 on 2/3 runs and at N=16 on 2/3 of the same episode;
sampling that flake at N=1 does not make N=1 a different cluster.

**Fix:** keep the stock-number checks (wall, 1.00×, fsync band,
elections 0). Fail N=1 on NotReady, splats, more than one restart,
or *every* run restarting. Do not fail the suite on the documented
single-restart flake. Do not `#[ignore]`. Do not widen a budget.

**Reference:** the referenced work `## Results` ("The N=1 identity still
holds"); the referenced work `## Results` (hard columns not monotonic at
n=3).

**Time lost:** one 70-minute `remote-dilation-test` plus ~15 minutes
of a second sweep before it was going to fail the same way.

---

## 199. `state.sh` last line is `patched (abi N, default factor F)`, not the token `patched` 

**Symptom:** `--profile ubuntu-dilated` exited before creating a VM
with `utils/kvm-dilation/state.sh printed 'patched (abi 2, default
factor 1)'` even though the modules were loaded (`exit 0`).

**Root cause:** `probe.c` / `state.sh` print a parenthetical ABI and
default factor after the stock/patched token. The scenario compared
the whole last line to `"patched"`.

**Fix:** take the first token of the last line (`dilation_token`).
Refuse anything that is not `patched`.

**Reference:** `utils/kvm-dilation/state.sh`, the referenced work.

**Time lost:** ~5 minutes plus a missed capture window.

---

## 200. Dilated `kubectl --timeout` is guest CLOCK — 30s expires before a 40s readiness gate 

**Symptom:** `--profile ubuntu-dilated` wave 0 applied the Deployment
on all 6 forks but every `rollout status` returned not-Ready in
8–10 s wall (guest Δt ≈ 65–80 s) with empty error. Wave 1 apply
failed with `failed to download openapi: TLS handshake timeout`
(`timeout=32s` on `/openapi/v2`).

**Root cause:** only waiting compresses. `kubectl --timeout=30s` and
the OpenAPI client's 32 s GET are guest-monotonic. Under ×8 they
expire in ~4 s of wall, before `initialDelaySeconds: 40` (5 s wall)
and before a TLS handshake that is compute/I/O and does not
speed up. `sleep 8` → 1.07 s wall confirmed dilation was on.

**Fix:** pass `--timeout=90s` (guest) so the gate can fire; keep the
host exec budget in wall seconds; `kubectl apply --validate=false`
to skip the OpenAPI fetch; wait `/readyz` after each fork. Fail the
wave if no branch becomes Ready.

**Reference:** `internal notes` invariants; CHALLENGES #180
(NTP steps a warp back out).

**Time lost:** one 3-wave take (~2 min) plus diagnosis.

---

## 201. Pause image + hostPath `/usr/bin/sleep` CrashLoops — missing dynamic linker 

**Symptom:** `k7-rollout` pods on the dilated Ubuntu forks were
`CrashLoopBackOff` (`exec /hostbin/sleep: no such file or directory`)
even though `/usr/bin/sleep` exists on the guest. `kubectl logs`
showed the kernel ENOENT, not a missing mount.

**Root cause:** `rancher/mirrored-pause` is scratch. Ubuntu
`/usr/bin/sleep` is dynamically linked (`interpreter
/lib64/ld-linux-x86-64.so.2`). hostPath `/usr/bin` → `/hostbin` does
not bring the loader or libc, so exec looks like "no such file".

**Fix:** keep the pause binary as PID 1 (it stays Running). Mount
guest `/usr/bin`, `/lib`, and `/lib64` so the readiness probe
`/hostbin/true` can exec. The gate remains `initialDelaySeconds: 40`.

**Reference:** none.

**Time lost:** the same failed take as #200, plus a describe/logs
round-trip on the kept tree.

---

## 202. Post-fork `/readyz` must be waited on the host clock 

**Symptom:** wave 0 scored 5/6 Ready under ×8. Wave 1 (forks of the
winner) failed `wait_apiserver` in 20 s wall:
`context deadline exceeded`, `apiserver not ready`,
`Client.Timeout exceeded while awaiting headers`. Two minutes later
the same CIDs answered `ok` in 0.13 s.

**Root cause:** guest `kubectl --request-timeout=8s` is guest CLOCK
(1 s wall at ×8). TLS/HTTP after a fork is compute and does not
compress, so every probe died before the apiserver finished
recovering. Host `curl --interface $bridge` without the k3s client
cert always fails (anonymous `/readyz` is off), so a 35 s host-curl
loop just burned the clip budget; the guest fallback with
`--request-timeout=120s` then returned `ok` immediately.

**Fix:** poll `/readyz` only via guest kubectl with a 120 s *guest*
request-timeout (~15 s wall). Per-wave Deployment names so a child
does not inherit an already-Ready gate.

**Reference:** CHALLENGES #144 (host kubectl to `10.200.0.2` on the
wrong bridge); `internal notes` (I/O does not dilate).

**Time lost:** one 90 s capture of a crashed wave-1 take.

---

## 203. Headless CDP cannot hold 8 fps — encoding at `-framerate 8` silently speeds the take 

**Symptom:** `capture.py --fps 8 --max-s 90` wrote 181 PNGs, then
`ffmpeg -framerate 8` produced a 22.6 s mp4. That looks like a
`setpts` 4× speed-up even though the encode line has none.

**Root cause:** each `Page.captureScreenshot` took ~500 ms on the
tunnelled 1920×1080 session. The recorder loop uses wall `elapsed`
for `--max-s` but still labels frames `f_%05d` and tells ffmpeg they
are 8 fps. ffmpeg then plays 181 frames in 22 s.

**Fix:** encode at the *actual* spacing (`181/90` fps → 90.0 s,
`r_frame_rate=181/90`). No `setpts`. GIF is a 14 s trim of that
timeline. Do not pass the requested fps to ffmpeg when the PNG count
is `elapsed * fps`.

**Reference:** none.

**Time lost:** one encode pass before `ffprobe` showed 22 s.

---

## 204. Catalog `exec_ok` swallows vsock death — GRPO paid `contained=1` on a wrecked fork 

**Symptom:** After member 7 ran `systemctl stop k3s; reboot`, `POST /score`
stayed HTTP 200 (good) but that row was `reward=0.4` with
`contained=1`, `restored=0`, no `unreachable`. A later `/act` `true`
on the same env was HTTP 502 (`vsock connect cid=… timed out`). The
other seven rows were intact.

**Root cause:** `gym/faults/probe.py` `exec_ok` catches `RuntimeError`
and returns `False`. `_score_grpo` treated that as "fault not
visible" → `contained=1`. A dead vsock therefore looked like a
contained incident instead of an unscorable wreck (internal notes).

**Fix:** probe `agent.exec_cmd(cid, ["true"], timeout_s=5)` first
under `_hold_autowarp`. Only then call `fault_visible` / `healthy`.
A raising probe zeros the row and sets `unreachable: true`. Unit
test: `test_dead_vsock_probe_is_unreachable_even_if_visible_swallows`.

**Reference:** internal notes; CHALLENGES #146
(keep_apiserver vs kill-member-0).

**Time lost:** ~40 min (first live n=8 lease + 90 s settle + wreck
score, then diagnosing `exec_ok`).

---

## Reference projects and what each taught us

| Project | What we learned |
|---------|----------------|
| **Firecracker** | MMIO register layout, boot params fields, GDT/segment setup, page table identity mapping, E820 memory map, interrupt_status pattern for vhost devices, ioeventfd for QUEUE_NOTIFY |
| **crosvm** | `VIRTIO_F_ACCESS_PLATFORM` must be cleared for vhost backends, vhost ioctl ordering (features → mem_table → vring setup → cid → start) |
| **Cloud Hypervisor** | Kernel loading via linux-loader, virtio-fs device tree setup, vhost-user connection pattern |
| **Linux kernel source** | vhost-vsock queue count (2 not 3), `vhost_vq_access_ok()` validation path, ENOBUFS meaning (`idx >= dev->nvqs`) |
