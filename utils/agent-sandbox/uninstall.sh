#!/usr/bin/env bash
# Remove what install.sh applied. Agent-sandbox objects are deleted first,
# while the controller still runs, so their finalizers and owned pods (k7d
# VMs) go away cleanly before the CRDs do. Idempotent.
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
# shellcheck source=pins.env
source "$HERE/pins.env"

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

curl -fsSL --retry 3 -o "$TMP/core.yaml" \
  "https://github.com/kubernetes-sigs/agent-sandbox/releases/download/$AGENT_SANDBOX_VERSION/sandbox-with-extensions.yaml"
echo "$AGENT_SANDBOX_MANIFEST_SHA256  $TMP/core.yaml" | sha256sum -c --quiet -

if kubectl get crd sandboxes.agents.x-k8s.io >/dev/null 2>&1; then
  echo "==> deleting remaining agent-sandbox objects in all namespaces"
  kubectl delete sandboxclaims.extensions.agents.x-k8s.io,sandboxwarmpools.extensions.agents.x-k8s.io \
    -A --all --wait=true --timeout=300s
  kubectl delete sandboxes.agents.x-k8s.io,sandboxtemplates.extensions.agents.x-k8s.io \
    -A --all --wait=true --timeout=300s
fi

echo "==> deleting sandbox-router"
kubectl delete clusterrolebinding/sandbox-router clusterrole/sandbox-router --ignore-not-found
kubectl -n agent-sandbox-system delete deploy/sandbox-router svc/sandbox-router-svc sa/sandbox-router \
  --ignore-not-found --wait=true --timeout=120s

echo "==> deleting agent-sandbox $AGENT_SANDBOX_VERSION controller + CRDs"
kubectl delete -f "$TMP/core.yaml" --ignore-not-found --wait=true --timeout=300s
echo "==> agent-sandbox uninstalled"
