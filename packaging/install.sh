#!/usr/bin/env bash
# Install k7d from a release tarball layout (run from the extracted dir).
# Version: 0.8.0
set -euo pipefail

VERSION="0.8.0"
PREFIX="${PREFIX:-/usr/local}"
BIN_DIR="${PREFIX}/bin"
SHARE_DIR="${PREFIX}/share/k7d"
UNIT_PATH="/etc/systemd/system/k7d.service"
WITH_K3S=0

usage() {
  cat <<'EOF'
Usage: ./install.sh [--with-k3s] [--prefix DIR]

Installs k7d + containerd-shim-k7-v1 to $PREFIX/bin (default /usr/local),
guest kernel/initramfs to $PREFIX/share/k7d, k7d-mount-disks to
/usr/local/libexec, and a systemd unit (from k7d.service.in) that sets
K7D_KERNEL / K7D_INITRD + RUST_LOG=info + LimitNOFILE=524288 plus the
capability bounding set and ProtectSystem=strict.

  --with-k3s   Also register RuntimeClass k7 and k7-fc in k3s/containerd
               (config-v3.toml.tmpl blocks; no BinaryName options).
  --prefix DIR Install prefix (default: /usr/local)
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --with-k3s) WITH_K3S=1; shift ;;
    --prefix) PREFIX="$2"; BIN_DIR="${PREFIX}/bin"; SHARE_DIR="${PREFIX}/share/k7d"; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    *) echo "unknown arg: $1" >&2; usage >&2; exit 1 ;;
  esac
done

if [[ "$(id -u)" -ne 0 ]]; then
  echo "install.sh must run as root" >&2
  exit 1
fi

HERE="$(cd "$(dirname "$0")" && pwd)"
for f in k7d containerd-shim-k7-v1 vmlinux initramfs.cpio.gz runc.amd64 docker/bin/dockerd \
         k7d-account.sh 60-k7d.rules; do
  if [[ ! -e "$HERE/$f" ]]; then
    echo "missing $HERE/$f — run from the extracted release tarball" >&2
    exit 1
  fi
done

echo "==> installing binaries to $BIN_DIR"
install -d "$BIN_DIR"
install -m 755 "$HERE/k7d" "$BIN_DIR/k7d"
install -m 755 "$HERE/containerd-shim-k7-v1" "$BIN_DIR/containerd-shim-k7-v1"

echo "==> installing guest assets to $SHARE_DIR"
install -d "$SHARE_DIR"
install -m 644 "$HERE/vmlinux" "$SHARE_DIR/vmlinux"
install -m 644 "$HERE/initramfs.cpio.gz" "$SHARE_DIR/initramfs.cpio.gz"

# Shim tools-image lookup includes /opt/k7d/runc.amd64. Always
# install there so a stock release works on nodes without a host runc;
# also mirror under $SHARE_DIR for the tarball layout's completeness.
echo "==> installing runc.amd64 to /opt/k7d and $SHARE_DIR"
install -d /opt/k7d
install -m 755 "$HERE/runc.amd64" /opt/k7d/runc.amd64
install -m 755 "$HERE/runc.amd64" "$SHARE_DIR/runc.amd64"

echo "==> installing docker payload to $SHARE_DIR/docker"
rm -rf "$SHARE_DIR/docker"
cp -a "$HERE/docker" "$SHARE_DIR/docker"
chmod -R a+rX "$SHARE_DIR/docker"

KERNEL="$SHARE_DIR/vmlinux"
INITRD="$SHARE_DIR/initramfs.cpio.gz"

UNIT_IN="$HERE/k7d.service.in"
[[ -f "$UNIT_IN" ]] || {
  echo "missing $UNIT_IN — packaging/k7d.service.in is the unit body" >&2
  exit 1
}
MOUNT_SRC="$HERE/k7d-mount-disks.sh"
[[ -f "$MOUNT_SRC" ]] || MOUNT_SRC="$HERE/k7d-mount-disks"
[[ -f "$MOUNT_SRC" ]] || {
  echo "missing k7d-mount-disks next to install.sh" >&2
  exit 1
}
echo "==> installing /usr/local/libexec/k7d-mount-disks"
install -d /usr/local/libexec
install -m 755 "$MOUNT_SRC" /usr/local/libexec/k7d-mount-disks

# ProtectSystem=strict bind-mounts every ReadWritePaths= entry when
# the unit starts. systemd fails with status=226/NAMESPACE if a path
# is missing — kubelet and k3s have not created theirs yet when this
# runs on a join node (k7 install HA, before k3s). Empty dirs are
# enough; kubelet reuses them (CHALLENGES #262).
echo "==> creating systemd ReadWritePaths that k3s/kubelet own later"
install -d -m 0755 /var/lib/kubelet/pods /var/lib/rancher/k3s

# Privilege separation — the VM broker's uid, the vhost-vsock udev rule and the
# ownership of the state it writes. Shared with
# your node provisioning so there is one copy of it.
ACCOUNT_SRC="$HERE/k7d-account.sh"
[[ -f "$ACCOUNT_SRC" ]] || {
  echo "missing $ACCOUNT_SRC — packaging/k7d-account.sh provisions uid k7d" >&2
  exit 1
}
echo "==> provisioning the VM broker's identity (uid k7d, group kvm, 60-k7d.rules)"
# shellcheck source=k7d-account.sh
source "$ACCOUNT_SRC"
# Account first so k7d-mount-disks can chown the XFS root to uid k7d
# instead of leaving it root-owned and warning. provision is still
# after the mount: k7d_own_state_dirs needs the XFS.
k7d_create_account
/usr/local/libexec/k7d-mount-disks
k7d_provision_vm_broker_identity "$HERE/60-k7d.rules"

# Jailer chroot base must live on the reflink XFS with the writable
# disks (`link(2)` is EXDEV across mounts). ProtectSystem=strict also
# bind-mounts /usr, so even same-disk /usr/local/share/k7d →
# /var/lib/k7d/fc on ext4 fails hard-link with EXDEV (CHALLENGES #263).
# Staging then copies the guest pair once into the XFS ro-cache.
echo "==> pointing /var/lib/k7d/fc at the reflink XFS"
mkdir -p /var/lib/k7d/disks/fc
chown root:root /var/lib/k7d/disks/fc
chmod 0700 /var/lib/k7d/disks/fc
if [[ -L /var/lib/k7d/fc ]]; then
  ln -sfn /var/lib/k7d/disks/fc /var/lib/k7d/fc
elif [[ -d /var/lib/k7d/fc ]]; then
  if [[ -n "$(ls -A /var/lib/k7d/fc 2>/dev/null || true)" ]]; then
    stale="/var/lib/k7d/fc.ext4-$(date +%s)"
    mv /var/lib/k7d/fc "$stale"
  else
    rmdir /var/lib/k7d/fc
  fi
  ln -sfn /var/lib/k7d/disks/fc /var/lib/k7d/fc
else
  ln -sfn /var/lib/k7d/disks/fc /var/lib/k7d/fc
fi

echo "==> writing $UNIT_PATH"
sed -e "s|@K7D_BIN@|${BIN_DIR}/k7d|g" \
    -e "s|@KERNEL@|${KERNEL}|g" \
    -e "s|@INITRD@|${INITRD}|g" \
    "$UNIT_IN" >"$UNIT_PATH"

systemctl daemon-reload
systemctl enable --now k7d
systemctl restart k7d

# Wait for control socket.
deadline=$((SECONDS + 15))
while [[ ! -S /run/k7d/k7d.sock ]]; do
  if (( SECONDS >= deadline )); then
    echo "k7d socket /run/k7d/k7d.sock did not appear — check: journalctl -u k7d" >&2
    exit 1
  fi
  sleep 0.2
done
echo "==> k7d ${VERSION} running (socket=/run/k7d/k7d.sock)"
echo "==> try: k7d doctor && k7d quickstart"

if [[ "$WITH_K3S" -eq 1 ]]; then
  CONFIG=/var/lib/rancher/k3s/agent/etc/containerd/config-v3.toml.tmpl
  if [[ ! -f "$CONFIG" ]]; then
    echo "k3s containerd template missing at $CONFIG" >&2
    exit 1
  fi
  if ! grep -q 'runtimes.k7]' "$CONFIG"; then
    echo "==> registering k7 runtime in containerd template"
    cat >>"$CONFIG" <<'EOF'

[plugins."io.containerd.cri.v1.runtime".containerd.runtimes.k7]
  runtime_type = "io.containerd.k7.v1"
  pod_annotations = ["k7d.katakate.org/*"]
  privileged_without_host_devices = true
  snapshotter = "overlayfs"
EOF
  else
    # Ensure pod_annotations is present (cluster-mode pods need it).
    if ! grep -q 'pod_annotations = \["k7d.katakate.org/\*"\]' "$CONFIG"; then
      echo "==> adding pod_annotations to existing k7 runtime block"
      # Insert after runtime_type line inside the k7 block — loud if shape unexpected.
      if ! grep -A5 'runtimes.k7]' "$CONFIG" | grep -q 'runtime_type = "io.containerd.k7.v1"'; then
        echo "existing k7 runtime block looks unexpected; edit $CONFIG by hand" >&2
        exit 1
      fi
      python3 - <<'PY'
from pathlib import Path
p = Path("/var/lib/rancher/k3s/agent/etc/containerd/config-v3.toml.tmpl")
text = p.read_text()
needle = 'runtime_type = "io.containerd.k7.v1"\n'
insert = needle + '  pod_annotations = ["k7d.katakate.org/*"]\n'
if 'pod_annotations = ["k7d.katakate.org/*"]' not in text:
    if needle not in text:
        raise SystemExit("k7 runtime_type line not found")
    text = text.replace(needle, insert, 1)
    p.write_text(text)
PY
    fi
  fi
  mkdir -p /etc/k7d
  printf 'backend = "firecracker"\n' > /etc/k7d/shim-k7-fc.toml
  if ! grep -q 'runtimes.k7-fc]' "$CONFIG"; then
    echo "==> registering k7-fc runtime in containerd template (ConfigPath, no BinaryName)"
    cat >>"$CONFIG" <<'EOF'

[plugins."io.containerd.cri.v1.runtime".containerd.runtimes.k7-fc]
  runtime_type = "io.containerd.k7.v1"
  pod_annotations = ["k7d.katakate.org/*"]
  privileged_without_host_devices = true
  snapshotter = "overlayfs"
  [plugins."io.containerd.cri.v1.runtime".containerd.runtimes.k7-fc.options]
    ConfigPath = "/etc/k7d/shim-k7-fc.toml"
EOF
  fi
  # Never add BinaryName — containerd resolves the shim from runtime_type.
  if grep -A20 'runtimes.k7]' "$CONFIG" | grep -q 'BinaryName'; then
    echo "ERROR: k7 runtime block must not set BinaryName (breaks shim cgroup path)" >&2
    exit 1
  fi
  if grep -A20 'runtimes.k7-fc]' "$CONFIG" | grep -q 'BinaryName'; then
    echo "ERROR: k7-fc runtime block must not set BinaryName (breaks shim cgroup path)" >&2
    exit 1
  fi
  if systemctl is-active k3s >/dev/null 2>&1; then
    systemctl restart k3s
  elif systemctl is-active k3s-agent >/dev/null 2>&1; then
    systemctl restart k3s-agent
  else
    echo "k3s is not active; containerd template updated, restart k3s yourself" >&2
    exit 1
  fi
  sleep 5
  kubectl apply -f - <<'EOF'
apiVersion: node.k8s.io/v1
kind: RuntimeClass
metadata:
  name: k7
handler: k7
EOF
  kubectl apply -f - <<'EOF'
apiVersion: node.k8s.io/v1
kind: RuntimeClass
metadata:
  name: k7-fc
handler: k7-fc
overhead:
  podFixed:
    cpu: 50m
    memory: 32Mi
EOF
  kubectl get runtimeclass k7 k7-fc
  echo "==> k3s RuntimeClass k7 and k7-fc ready"
else
  cat <<EOF

k7d ${VERSION} installed. To register with k3s later, re-run:
  sudo ./install.sh --with-k3s

Or manually add to ${CONFIG:-/var/lib/rancher/k3s/agent/etc/containerd/config-v3.toml.tmpl}:

[plugins."io.containerd.cri.v1.runtime".containerd.runtimes.k7]
  runtime_type = "io.containerd.k7.v1"
  pod_annotations = ["k7d.katakate.org/*"]
  privileged_without_host_devices = true
  snapshotter = "overlayfs"

[plugins."io.containerd.cri.v1.runtime".containerd.runtimes.k7-fc]
  runtime_type = "io.containerd.k7.v1"
  pod_annotations = ["k7d.katakate.org/*"]
  privileged_without_host_devices = true
  snapshotter = "overlayfs"
  [plugins."io.containerd.cri.v1.runtime".containerd.runtimes.k7-fc.options]
    ConfigPath = "/etc/k7d/shim-k7-fc.toml"

Do NOT add BinaryName. Then: echo 'backend = "firecracker"' > /etc/k7d/shim-k7-fc.toml && systemctl restart k3s && kubectl apply RuntimeClass k7 and k7-fc.
EOF
fi
