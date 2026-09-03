# Hacking on k7d

## Requirements

k7d is Linux x86_64 + KVM only - the rust-vmm crates (kvm-ioctls,
kvm-bindings, vm-memory) do not compile on macOS or Windows. You need:

- `/dev/kvm`, `/dev/vhost-vsock`, `/dev/net/tun`
- Rust (stable, pinned in `rust-toolchain.toml`) with the
  `x86_64-unknown-linux-musl` target (for the static guest agent)
- Docker (guest rootfs build)
- virtiofsd at `/usr/libexec/virtiofsd` (RW hostPath fallback only)
- root (bridge / TAP / iptables setup in tests)
- k3s, for the kubectl integration suite

## Build & test on a Linux/KVM host

```bash
make build          # daemon + shim (cargo build --release)
make build-agent    # static musl guest agent
make build-guest-kernel
make build-guest-rootfs
make release        # all of the above, artifacts into dist/

make check              # fmt + deny + clippy + all tests (--test-threads=1)
make test-integration   # kubectl / k3s suite
```

Tests run with `--test-threads=1` to avoid vsock CID collisions.

## Remote development workflow (no local KVM)

If you edit from a machine without KVM, drive a remote Linux node over
SSH. The `remote-*` targets rsync the repo to the node and run the
corresponding target there:

```bash
export K7_NODE_IP=…       # your node
# K7_SSH_KEY=…            # private key content (PEM), or ~/.ssh/id_ed25519

make remote-install-rust      # once per fresh node
make remote-check             # fmt + deny + clippy + all tests
make remote-test-integration  # kubectl / k3s suite
make remote-kani              # proofs for unsafe paths
make remote-verif             # Aeneas/Lean tree proofs (after remote-install-verif once)
```

| Variable | Default | Purpose |
|---|---|---|
| `K7_NODE_IP` | (required) | Build/test node IP |
| `K7_NODE_USER` | `root` | SSH user |
| `K7_SSH_KEY` | (uses `~/.ssh/id_ed25519`) | Private key content (PEM) |
| `K7_REMOTE_RESTART` | `0` | `1` kills an in-flight run and starts fresh |
| `K7_REMOTE_LOCK_WAIT` | `2700` | Seconds to wait for the node's workspace lock |

### Surviving a dropped connection

The full suite takes 25-40 minutes, so the long `remote-*` targets do not
run over the SSH connection - `utils/remote-run.sh` starts them detached
on the node (`nohup setsid`, output to `/run/k7d-remote/<target>/log`)
and the local side is only a viewer that streams that log and exits with
the run's recorded exit code.

Losing the connection therefore costs nothing. The viewer reconnects on
its own; if the local process dies too, re-running the same target
**reattaches to the run in flight** rather than starting a second one
(it skips the rsync in that case, since the run is building the sources
already on the node). `Ctrl-C` detaches without stopping the run. To
abandon a run and start over, `K7_REMOTE_RESTART=1 make remote-check`.

`utils/rsync-to-node.sh` syncs with `--checksum` and bumps the mtime of
every file it transfers, so a source on the node can never end up older
than an artifact built from different content (CHALLENGES.md #64).

### One workspace, one run at a time

A run of a *different* name on the same node waits instead of rsyncing
into a live build - the node has one `/root/k7d` and one `/dev/kvm`, and
two runs sharing them fail in a different place each time, which reads as
flakiness rather than contention. The waiter prints who holds the lock.

The lock lives on the node and is held by a detached process, not by the
SSH connection, so a dropped connection cannot release it mid-build and a
killed client cannot wedge the node (the kernel drops the `flock` when
that process dies). `K7_REMOTE_LOCK_WAIT` (default 2700s) bounds the
wait; past it the run fails loudly naming the holder. See
CHALLENGES.md #75.

## Verification suite

- `make kani` / `make remote-kani` - Kani bounded model checking of
  proof harnesses co-located with the `unsafe` code (`vm.rs`,
  `fork.rs`, `snapshot.rs`, devices). Run after touching unsafe blocks
  or address arithmetic.
- `make verif-gen && make verif-build` (or `make remote-verif`) - 
  regenerate `verif/Verif/TreeModel.lean` from
  `crates/k7d/src/tree_model.rs` via Charon + Aeneas, then `lake build`
  the theorems. Mandatory when `tree_model.rs` changes. Toolchain
  install: `make remote-install-verif` (once per node). Any new Aeneas axiom not in
  `verif/axiom-allowlist.txt` fails the build (`utils/check-verif-axioms.sh`).
- `make miri` - Miri on the pure (non-KVM) unit tests.
- `make fuzz` - libFuzzer runs over the agent protocol and virtio-blk
  request parsing.
- `make dilation-install` / `make dilation-test` / `make dilation-revert`
  — continuous ×N guest-clock dilation. Builds patched `kvm.ko` +
  `kvm-amd.ko` / `kvm-intel.ko` for the running kernel from
  `utils/kvm-dilation/` (Ubuntu x86, root, Launchpad `linux-source`).
  Kept out of `make check`: stock CI must stay on stock modules. Never
  leave the host patched — `dilation-test` / `remote-dilation-test`
  revert whatever they did. Lockstep jumps (`make warp-bench`) need no
  patch.

## Running pods in k7d via containerd / k3s

Four steps register the `k7` RuntimeClass on a k3s node:

1. **Install + start the daemon.** `cp dist/k7d /usr/local/bin/`,
   install the guest kernel and initramfs somewhere the daemon can read
   them (`packaging/install.sh` uses `/usr/local/share/k7d/`), then
   create a `k7d.service` systemd unit with `ExecStart=/usr/local/bin/k7d`,
   `Environment=RUST_LOG=info` and - required - the guest pair:

   ```ini
   Environment=K7D_KERNEL=/usr/local/share/k7d/vmlinux
   Environment=K7D_INITRD=/usr/local/share/k7d/initramfs.cpio.gz
   ```

   Then `systemctl enable --now k7d`. The daemon is the *only* process
   that decides which guest a VM boots; nothing else may pass a path,
   and a daemon without these refuses to create a VM rather than
   guessing (CHALLENGES #72). The shim is a thin client: sandbox
   `Create` calls the daemon over `/run/k7d/k7d.sock` and fails loudly
   if it is not running.
2. **Install the shim.**
   `cp dist/containerd-shim-k7-v1 /usr/local/bin/`.
3. **Register the runtime in containerd.** Add to
   `/var/lib/rancher/k3s/agent/etc/containerd/config-v3.toml.tmpl`:

   ```toml
   [plugins."io.containerd.cri.v1.runtime".containerd.runtimes.k7]
     runtime_type = "io.containerd.k7.v1"
     pod_annotations = ["k7d.katakate.org/*"]
     privileged_without_host_devices = true
     snapshotter = "overlayfs"
   ```

   Do **not** add an `[options]` section with `BinaryName` - containerd
   resolves the binary from `runtime_type` automatically, and the
   option value leaks into the cgroup path and breaks shim startup.
   `pod_annotations` forwards the `k7d.katakate.org/*` annotations
   (`cluster-id`, `fork-vm-index`, …) into the sandbox OCI spec, which
   cluster-mode pods require.
4. **Restart k3s and create the RuntimeClass.**

   ```bash
   systemctl restart k3s
   kubectl apply -f - <<'EOF'
   apiVersion: node.k8s.io/v1
   kind: RuntimeClass
   metadata:
     name: k7
   handler: k7
   EOF
   ```

Integration tests self-install all of this
(`common::ensure_k7d_daemon_running()`, `ensure_shim_installed()`).

## Ground rules

- Failures must be loud - no silent default fallbacks
- Clean up resources (KVM fds, TAP devices, virtiofsd children, temp
  files) via `Drop` or scopeguard
- No `unwrap()` in library code (tests and `main` only)
- Pin all dependency versions
- Every latency claim must be an enforced test budget
  (`crates/k7d/src/latency.rs` is the single source of truth)
- Non-trivial debugging war stories go in `CHALLENGES.md`
