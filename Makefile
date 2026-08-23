.PHONY: build build-agent build-guest-kernel build-guest-rootfs \
       test test-integration lint fmt-check deny bench check gym-test \
       k7d-mcp-deps k7d-mcp-test k7view-test \
       miri fuzz kani kani-harness verif-gen verif-build \
       rsync remote-check remote-build remote-test-integration remote-bench \
       remote-install-rust remote-miri remote-fuzz remote-kani \
       remote-install-verif remote-verif remote-release reference release

REFERENCE_DIR := reference
REMOTE_DIR := /root/k7d
K7D_VERSION := $(shell sed -n 's/^version = "\(.*\)"/\1/p' Cargo.toml | head -1)
RELEASE_NAME := k7d-v$(K7D_VERSION)-x86_64-linux
RELEASE_TGZ := dist/$(RELEASE_NAME).tar.gz

# --- Serialized test-binary runner (used by test / test-integration) ---
# `cargo test -- --test-threads=1` only serializes tests *within* one
# binary; cargo still runs the many test binaries in crates/*/tests/
# concurrently, so several VMs boot at once and fork/vsock tests miss
# their deadlines (CHALLENGES.md #76). Run one test binary at a time,
# enumerated from cargo metadata so a new tests/*.rs file is picked up
# without a Makefile edit. $(1) is extra libtest args (e.g. --ignored).
define run_test_binaries
set -e; \
targets="$$(cargo metadata --no-deps --format-version 1 \
  | jq -r '.packages[] | .name as $$p | .targets[] | select(.kind[] == "test") | "\($$p) \(.name)"')"; \
[ -n "$$targets" ] || { echo "no test targets found in cargo metadata" >&2; exit 1; }; \
echo "$$targets" | while read -r pkg name; do \
  echo "==> test binary: $$name (package $$pkg)"; \
  cargo test -p "$$pkg" --test "$$name" -- $(1) --test-threads=1 \
    || { echo "FAILED test binary: $$name (package $$pkg)" >&2; exit 1; }; \
done
endef

# --- SSH setup (used by all remote-* targets) ---
# Source utils/ssh-setup.sh to get SSH_OPTS, NODE, SSH_PRIVKEY
define ssh_setup
source utils/ssh-setup.sh && \
[[ -n "$${_SSH_TMPDIR:-}" ]] && trap "rm -rf '$$_SSH_TMPDIR'" EXIT;
endef

# --- Local targets (formatting only -- rust-vmm crates are Linux-only) ---

fmt-check:
	cargo fmt --check

# --- Targets that run ON the node (require Linux + KVM) ---

build:
	cargo build --release

build-agent:
	cargo build --release --target x86_64-unknown-linux-musl -p k7-agent

build-guest-kernel:
	cd guest/kernel && ./build.sh

build-guest-rootfs:
	cd guest/rootfs && ./build.sh

deny:
	cargo deny check

lint:
	cargo fmt --check
	cargo deny check
	cargo clippy -- -D warnings

# Rebuild the guest agent + initramfs before testing so the
# suite never runs against a stale guest (rsync excludes the initramfs
# artifact; both builds are no-op-fast when nothing changed).
test: build-agent build-guest-rootfs
	# Cluster leftovers are reaped by the spec-22d sweep (age-gated
	# `k7-test-run` selector). A cluster-wide `kubectl delete` here
	# would kill a concurrent suite's live pods and kube-system.
	-pkill -9 virtiofsd 2>/dev/null
	-pkill -9 -f containerd-shim-k7-v1 2>/dev/null
	-mount | awk '/k7d-shim/ {print $$3}' | sort -ru | xargs -r umount -l 2>/dev/null
	-rm -rf /tmp/k7d-shim-* /tmp/k7d-virtiofs-* /tmp/k7d-fork-* 2>/dev/null
	sleep 2
	cargo test --workspace --lib --bins -- --test-threads=1
	@$(call run_test_binaries,)
	cargo test --workspace --doc

test-integration:
	@$(call run_test_binaries,--ignored)

bench:
	cargo bench

# Pure-Python gym unit tests (no KVM). The Rust integration test in
# crates/k7d/tests/test_gym.rs covers the HTTP+k7d path and does not
# duplicate these.
#
# k7d-mcp-test is the 27a-inc1 Python path: stub MCP round-trip (no
# KVM) plus one Ubuntu Cilium+Tetragon smoke (needs the live daemon).
# PEP 668: Ubuntu 24.04 refuses system-site pip. Keep the venv off
# the rsync tree so --delete cannot wipe the wheels.
K7D_MCP_VENV := /var/lib/k7d/mcp-venv
k7d-mcp-deps:
	@if [ ! -x "$(K7D_MCP_VENV)/bin/python" ]; then \
	  python3 -m venv "$(K7D_MCP_VENV)" 2>/dev/null \
	    || { apt-get install -y python3-venv python3-pip && python3 -m venv "$(K7D_MCP_VENV)"; }; \
	fi
	$(K7D_MCP_VENV)/bin/pip install -q -r examples/k7d-mcp/requirements.txt

k7d-mcp-test: k7d-mcp-deps
	cd examples/k7d-mcp && $(K7D_MCP_VENV)/bin/python -m unittest discover -s tests -v

gym-test: k7d-mcp-test k7view-test
	cd gym && python3 -m unittest discover -s tests -v

# k7view observer unit tests (pure Python, no KVM; the referenced work)
k7view-test:
	python3 examples/k7view/test_store.py
	python3 examples/k7view/test_probe.py

check: lint gym-test test

miri:
	# Miri runs on pure unit tests only — integration tests touch KVM, the
	# filesystem, virtiofsd, etc. and trip Miri's isolation. The pure unit
	# tests in `tree_model` and similar pure modules are what Miri can
	# meaningfully check.
	cargo +nightly miri test --lib -p k7d -- tree_model

fuzz:
	cd fuzz && cargo +nightly fuzz run agent_protocol -- -max_total_time=150
	cd fuzz && cargo +nightly fuzz run blk_request -- -max_total_time=150

kani:
	cargo kani -p k7d

kani-harness:
	cargo kani -p k7d --harness $(HARNESS)

# --- Aeneas / Lean verification ---

# Regenerate Verif/TreeModel.lean from crates/k7d/src/tree_model.rs via
# Charon + Aeneas. Honors $$HOME/aeneas/{bin/aeneas,charon/bin/charon} if
# present (the layout produced by `make remote-install-verif`).
verif-gen:
	@CHARON_BIN="$${CHARON:-$$HOME/aeneas/charon/bin/charon}"; \
	AENEAS_BIN="$${AENEAS:-$$HOME/aeneas/bin/aeneas}"; \
	$(MAKE) -C verif gen CHARON="$$CHARON_BIN" AENEAS="$$AENEAS_BIN"
	@# Fail loudly on new Aeneas axioms before lake build
	@bash utils/check-verif-axioms.sh

# Run the Lean theorems against the regenerated model.
verif-build:
	$(MAKE) -C verif build

# Release tarball in the official layout (matches the katakate/k7d
# GitHub release artifact): a k7d-v<version>-x86_64-linux/ directory
# with the binaries, guest kernel/initramfs, and install.sh. The
# runtime boots guest/rootfs/initramfs.cpio.gz (there is no rootfs.img
# — container rootfs erofs images are built at runtime); runc.amd64 is
# included as an extra so nodes without a host runc still work (the
# shim's tools-image lookup includes /opt/k7d/runc.amd64).
#
# Run ON a Linux/KVM host, or via `make remote-release`.
release: build build-agent build-guest-kernel build-guest-rootfs
	@test -f guest/kernel/vmlinux || { echo "missing guest/kernel/vmlinux" >&2; exit 1; }
	@test -f guest/rootfs/initramfs.cpio.gz || { echo "missing guest/rootfs/initramfs.cpio.gz" >&2; exit 1; }
	@test -f guest/rootfs/runc.amd64 || { echo "missing guest/rootfs/runc.amd64" >&2; exit 1; }
	@test -x target/release/k7d || { echo "missing target/release/k7d" >&2; exit 1; }
	@test -x target/release/containerd-shim-k7-v1 || { echo "missing shim binary" >&2; exit 1; }
	@test -x target/x86_64-unknown-linux-musl/release/k7-agent || { echo "missing k7-agent binary" >&2; exit 1; }
	rm -rf "dist/$(RELEASE_NAME)"
	mkdir -p "dist/$(RELEASE_NAME)"
	cp target/release/k7d "dist/$(RELEASE_NAME)/"
	cp target/release/containerd-shim-k7-v1 "dist/$(RELEASE_NAME)/"
	cp target/x86_64-unknown-linux-musl/release/k7-agent "dist/$(RELEASE_NAME)/"
	cp guest/kernel/vmlinux "dist/$(RELEASE_NAME)/"
	cp guest/rootfs/initramfs.cpio.gz "dist/$(RELEASE_NAME)/"
	cp guest/rootfs/runc.amd64 "dist/$(RELEASE_NAME)/"
	install -m 755 packaging/install.sh "dist/$(RELEASE_NAME)/install.sh"
	tar -C dist -czf "$(RELEASE_TGZ)" "$(RELEASE_NAME)"
	@echo "==> $(RELEASE_TGZ)"
	@tar -tzf "$(RELEASE_TGZ)"

# --- Remote targets (rsync + run on bare-metal node via SSH) ---

# Every long-running remote target goes through utils/remote-run.sh: it
# rsyncs, starts the command detached from the SSH connection (nohup
# setsid, output to a log on the node), streams that log back, and exits
# with the remote command's own exit code. A dropped connection no longer
# SIGHUPs the run mid-suite — re-running the same target reattaches to
# the run in flight. See CHALLENGES.md #64.

rsync:
	@bash utils/rsync-to-node.sh

remote-check:
	@bash utils/remote-run.sh check "make check"

remote-build:
	@bash utils/remote-run.sh build "make build"

remote-test-integration:
	@bash utils/remote-run.sh test-integration "make test-integration"

# Build the tarball on the node, then fetch it back to ./dist.
remote-release:
	@bash utils/remote-run.sh release "make release"
	@bash -c '$(ssh_setup) \
	mkdir -p dist && \
	rsync -az -e "ssh $${SSH_OPTS[*]}" \
	  "$$NODE:$(REMOTE_DIR)/$(RELEASE_TGZ)" "$(RELEASE_TGZ)" && \
	echo "==> fetched $(RELEASE_TGZ)"'

remote-bench:
	@bash utils/remote-run.sh bench "make bench"

remote-miri:
	@bash utils/remote-run.sh miri "make miri"

remote-fuzz:
	@bash utils/remote-run.sh fuzz "make fuzz"

remote-kani:
	@bash utils/remote-run.sh kani "make kani"

remote-install-rust:
	@bash -c '$(ssh_setup) \
	echo "==> Installing Rust toolchain on $$NODE" && \
	ssh "$${SSH_OPTS[@]}" "$$NODE" \
	  "curl --proto =https --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y && \
	   source ~/.cargo/env && \
	   rustup target add x86_64-unknown-linux-musl"'

# --- Aeneas / Charon / Lean install on the node (Step 2) ---
#
# Idempotent: re-running on a partially-installed node just no-ops the
# bits that are already there. After a node reset, run this once before
# `make remote-verif`.
#
# Installs:
#   * apt deps (opam, ocaml-base toolchain, gmp, m4, pkg-config, ...)
#   * an OCaml 5.3.0 opam switch + the Aeneas package list
#   * Charon (cloned by `aeneas/Makefile`'s `setup-charon` target, built
#     against rustup's nightly)
#   * Aeneas itself (built with `make` in ~/aeneas)
#   * elan + the Lean toolchain pinned in `verif/lean-toolchain`
#
# The script is intentionally chatty so progress is visible in the
# tmux pane this is launched from.
#
# Aeneas rev pin: the node checkout and
# `verif/lakefile.toml` must reference the SAME commit —
#   044c73b72171670cbe3a245ee7bccc4d626f0113
# `install-aeneas.sh` reads it from AENEAS_REV; bump both together.
remote-install-verif:
	@bash utils/remote-run.sh install-verif "bash $(REMOTE_DIR)/utils/install-aeneas.sh"

# remote-run.sh sources ~/.elan/env and puts ~/aeneas/{bin,charon/bin}
# on PATH for every run, so verif needs no extra environment here.
remote-verif:
	@bash utils/remote-run.sh verif "make verif-gen && make verif-build"

# --- Reference repos (for agent exploration, not tracked in git) ---

reference: $(REFERENCE_DIR)/cloud-hypervisor $(REFERENCE_DIR)/firecracker $(REFERENCE_DIR)/kata-containers $(REFERENCE_DIR)/firecracker-containerd $(REFERENCE_DIR)/containerd-cloudhypervisor $(REFERENCE_DIR)/zeroboot $(REFERENCE_DIR)/virtiofsd $(REFERENCE_DIR)/cubesandbox

$(REFERENCE_DIR)/cloud-hypervisor:
	git clone --depth 1 https://github.com/cloud-hypervisor/cloud-hypervisor.git $@

$(REFERENCE_DIR)/firecracker:
	git clone --depth 1 https://github.com/firecracker-microvm/firecracker.git $@

$(REFERENCE_DIR)/kata-containers:
	git clone --depth 1 https://github.com/kata-containers/kata-containers.git $@

$(REFERENCE_DIR)/firecracker-containerd:
	git clone --depth 1 https://github.com/firecracker-microvm/firecracker-containerd.git $@

$(REFERENCE_DIR)/containerd-cloudhypervisor:
	git clone --depth 1 https://github.com/devigned/containerd-cloudhypervisor.git $@

$(REFERENCE_DIR)/zeroboot:
	git clone --depth 1 https://github.com/zerobootdev/zeroboot.git $@

$(REFERENCE_DIR)/virtiofsd:
	git clone --depth 1 https://gitlab.com/virtio-fs/virtiofsd.git $@

$(REFERENCE_DIR)/cubesandbox:
	git clone --depth 1 https://github.com/tencentcloud/CubeSandbox.git $@
