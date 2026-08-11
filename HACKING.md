# Hacking on k7d

## Requirements

k7d is Linux x86_64 + KVM only — the rust-vmm crates (kvm-ioctls,
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
| `K7_NODE_IP` | `(required: set K7_NODE_IP)` | Build/test node IP |
| `K7_NODE_USER` | `root` | SSH user |
| `K7_SSH_KEY` | (uses `~/.ssh/id_ed25519`) | Private key content (PEM) |

## Verification suite

- `make kani` / `make remote-kani` — Kani bounded model checking of
  proof harnesses co-located with the `unsafe` code (`vm.rs`,
  `fork.rs`, `snapshot.rs`, devices). Run after touching unsafe blocks
  or address arithmetic.
- `make verif-gen && make verif-build` (or `make remote-verif`) —
  regenerate `verif/Verif/TreeModel.lean` from
  `crates/k7d/src/tree_model.rs` via Charon + Aeneas, then `lake build`
  the theorems. Mandatory when `tree_model.rs` changes. Toolchain
  install: `make remote-install-verif` (once per node). Any new Aeneas axiom not in
  `verif/axiom-allowlist.txt` fails the build (`utils/check-verif-axioms.sh`).
- `make miri` — Miri on the pure (non-KVM) unit tests.
- `make fuzz` — libFuzzer runs over the agent protocol and virtio-blk
  request parsing.

## Running pods in k7d via containerd / k3s

Four steps register the `k7` RuntimeClass on a k3s node:

1. **Install + start the daemon.** `cp dist/k7d /usr/local/bin/`,
   create a `k7d.service` systemd unit
   (`ExecStart=/usr/local/bin/k7d`, `Environment=RUST_LOG=info`), then
   `systemctl enable --now k7d`. The shim is a thin client: sandbox
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

   Do **not** add an `[options]` section with `BinaryName` — containerd
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

- Failures must be loud — no silent default fallbacks
- Clean up resources (KVM fds, TAP devices, virtiofsd children, temp
  files) via `Drop` or scopeguard
- No `unwrap()` in library code (tests and `main` only)
- Pin all dependency versions
- Every latency claim must be an enforced test budget
  (`crates/k7d/src/latency.rs` is the single source of truth)
- Non-trivial debugging war stories go in `CHALLENGES.md`
