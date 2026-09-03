#!/usr/bin/env bash
# Install k7d from a release tarball layout (run from the extracted dir).
# Version: 0.4.0
set -euo pipefail

VERSION="0.4.0"
PREFIX="${PREFIX:-/usr/local}"
BIN_DIR="${PREFIX}/bin"
SHARE_DIR="${PREFIX}/share/k7d"
UNIT_PATH="/etc/systemd/system/k7d.service"
WITH_K3S=0

usage() {
  cat <<'EOF'
Usage: ./install.sh [--with-k3s] [--prefix DIR]

Installs k7d + containerd-shim-k7-v1 to $PREFIX/bin (default /usr/local),
guest kernel/initramfs to $PREFIX/share/k7d, and a systemd unit that sets
K7D_KERNEL / K7D_INITRD + RUST_LOG=info + LimitNOFILE=524288.

  --with-k3s   Also register RuntimeClass k7 in k3s/containerd
               (config-v3.toml.tmpl block; no BinaryName options).
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
for f in k7d containerd-shim-k7-v1 vmlinux initramfs.cpio.gz runc.amd64; do
  if [[ ! -f "$HERE/$f" ]]; then
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

KERNEL="$SHARE_DIR/vmlinux"
INITRD="$SHARE_DIR/initramfs.cpio.gz"

echo "==> writing $UNIT_PATH"
cat >"$UNIT_PATH" <<EOF
[Unit]
Description=k7d microVM runtime daemon
After=network.target

[Service]
ExecStart=${BIN_DIR}/k7d
Restart=on-failure
Environment=RUST_LOG=info
Environment=K7D_KERNEL=${KERNEL}
Environment=K7D_INITRD=${INITRD}
# Soft default without this is 1024 — far too low for multi-cluster forks.
LimitNOFILE=524288

[Install]
WantedBy=multi-user.target
EOF

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
  if ! grep -q 'runtimes.k7' "$CONFIG"; then
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
      if ! grep -A5 'runtimes.k7' "$CONFIG" | grep -q 'runtime_type = "io.containerd.k7.v1"'; then
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
  # Never add [options] / BinaryName — containerd resolves the shim from runtime_type.
  if grep -A20 'runtimes.k7' "$CONFIG" | grep -q 'BinaryName'; then
    echo "ERROR: k7 runtime block must not set BinaryName (breaks shim cgroup path)" >&2
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
  kubectl get runtimeclass k7
  echo "==> k3s RuntimeClass k7 ready"
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

Do NOT add [options] with BinaryName. Then: systemctl restart k3s && kubectl apply RuntimeClass k7.
EOF
fi
