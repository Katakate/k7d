#!/usr/bin/env bash
# Install a pinned single-node k3s on a fresh node (run as root), then seed
# the containerd template so packaging/install.sh --with-k3s has somewhere
# to add the k7 / k7-fc runtimes. The upstream install script is
# sha256-checked; it verifies the k3s binary against the release's
# sha256sum-amd64.txt itself.
set -euo pipefail
K3S_VERSION="v1.36.5+k3s1"
K3S_INSTALL_SHA256="46177d4c99440b4c0311b67233823a8e8a2fc09693f6c89af1a7161e152fbfad"

if command -v k3s >/dev/null && k3s --version | grep -qF "k3s version $K3S_VERSION "; then
  echo "==> k3s $K3S_VERSION already installed"
else
  tmp="$(mktemp)"
  trap 'rm -f "$tmp"' EXIT
  curl -fsSL --retry 3 -o "$tmp" "https://raw.githubusercontent.com/k3s-io/k3s/${K3S_VERSION/+/%2B}/install.sh"
  echo "$K3S_INSTALL_SHA256  $tmp" | sha256sum -c --quiet -
  INSTALL_K3S_VERSION="$K3S_VERSION" INSTALL_K3S_EXEC="server --write-kubeconfig-mode=0600" sh "$tmp"
fi

CONFIG=/var/lib/rancher/k3s/agent/etc/containerd/config-v3.toml.tmpl
if [[ ! -f "$CONFIG" ]]; then
  mkdir -p "$(dirname "$CONFIG")"
  printf '# version = 3\n{{ template "base" . }}\n' >"$CONFIG"
  systemctl restart k3s
fi
for _ in $(seq 60); do kubectl get node "$(hostname)" >/dev/null 2>&1 && break; sleep 2; done
kubectl wait --for=condition=Ready "node/$(hostname)" --timeout=180s
echo "==> k3s $K3S_VERSION ready"
