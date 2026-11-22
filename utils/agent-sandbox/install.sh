#!/usr/bin/env bash
# Install kubernetes-sigs/agent-sandbox (core + extensions controller and the
# Go sandbox-router) into the cluster kubectl points at. Every download is
# sha256-checked and every image is digest-pinned (pins.env). Idempotent.
#
# The node must already run k7d with RuntimeClasses k7 / k7-fc
# (packaging/install.sh --with-k3s); this script does not touch the node.
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
# shellcheck source=pins.env
source "$HERE/pins.env"

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

fetch() { # url sha256 dest
  curl -fsSL --retry 3 -o "$3" "$1"
  echo "$2  $3" | sha256sum -c --quiet - || { echo "sha256 mismatch for $1" >&2; exit 1; }
}

# Replace exactly one occurrence of $2 by $3 in file $1, loudly.
pin_image() {
  local n
  n="$(grep -c -- "image: $2\$" "$1" || true)"
  [[ "$n" == 1 ]] || { echo "expected one 'image: $2' in $1, found $n" >&2; exit 1; }
  sed -i "s|image: $2\$|image: $3|" "$1"
}

REL="https://github.com/kubernetes-sigs/agent-sandbox/releases/download/$AGENT_SANDBOX_VERSION"
RAW="https://raw.githubusercontent.com/kubernetes-sigs/agent-sandbox/$AGENT_SANDBOX_COMMIT/sandbox-router/deploy"

fetch "$REL/sandbox-with-extensions.yaml" "$AGENT_SANDBOX_MANIFEST_SHA256" "$TMP/core.yaml"
pin_image "$TMP/core.yaml" "registry.k8s.io/agent-sandbox/agent-sandbox-controller:$AGENT_SANDBOX_VERSION" "$CONTROLLER_IMAGE"

fetch "$RAW/serviceaccount.yaml" "$ROUTER_SA_SHA256" "$TMP/router-sa.yaml"
fetch "$RAW/rbac.yaml" "$ROUTER_RBAC_SHA256" "$TMP/router-rbac.yaml"
fetch "$RAW/deployment.yaml" "$ROUTER_DEPLOYMENT_SHA256" "$TMP/router-deployment.yaml"
fetch "$RAW/service.yaml" "$ROUTER_SERVICE_SHA256" "$TMP/router-service.yaml"
pin_image "$TMP/router-deployment.yaml" "registry.k8s.io/agent-sandbox/sandbox-router-go:latest" "$ROUTER_IMAGE"

echo "==> agent-sandbox $AGENT_SANDBOX_VERSION: CRDs + controller"
kubectl apply --server-side --force-conflicts -f "$TMP/core.yaml"
kubectl wait --for=condition=Established --timeout=120s \
  crd/sandboxes.agents.x-k8s.io crd/sandboxtemplates.extensions.agents.x-k8s.io \
  crd/sandboxclaims.extensions.agents.x-k8s.io crd/sandboxwarmpools.extensions.agents.x-k8s.io
kubectl -n agent-sandbox-system rollout status deploy/agent-sandbox-controller --timeout=300s

echo "==> sandbox-router (Go) $AGENT_SANDBOX_VERSION"
for f in router-sa router-rbac router-deployment router-service; do
  kubectl apply -f "$TMP/$f.yaml"
done
kubectl -n agent-sandbox-system rollout status deploy/sandbox-router --timeout=300s
echo "==> agent-sandbox $AGENT_SANDBOX_VERSION installed"
