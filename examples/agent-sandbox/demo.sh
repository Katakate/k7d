#!/usr/bin/env bash
# agent-sandbox on k7d, end to end, on a node prepared by
# packaging/install.sh --with-k3s (run as root on the node):
#   1. install agent-sandbox (pinned, utils/agent-sandbox/install.sh)
#   2. warm pool of 3 Firecracker VMs (k7-fc) + a claim that adopts one
#   3. the upstream Python SDK through the sandbox-router
#   4. Docker-in-VM: `docker run hello-world` inside a claimed k7 sandbox
# Everything it creates lives in namespace $NS, deleted on exit.
# KEEP_AGENT_SANDBOX=1 leaves the controller installed.
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$HERE/../.." && pwd)"
# shellcheck source=../../utils/agent-sandbox/pins.env
source "$ROOT/utils/agent-sandbox/pins.env"
: "${KUBECONFIG:?set KUBECONFIG for the SDK (k3s: /etc/rancher/k3s/k3s.yaml)}"
export KUBECONFIG
NS="${NS:-k7-agent-sandbox-demo}"
VENV="${VENV:-/var/tmp/k7d-agent-sandbox-venv}"
HELLO="docker.io/library/hello-world@sha256:5e22040d441e5fb3aed38368acbe8486b575d7018df38dbdfbc7311fbb2ef3a9"

step() { printf '\n\033[1m==> %s\033[0m\n' "$*"; }
cleanup() {
  step "cleanup"
  kubectl delete namespace "$NS" --ignore-not-found --wait=true --timeout=300s
  [[ "${KEEP_AGENT_SANDBOX:-0}" == 1 ]] || bash "$ROOT/utils/agent-sandbox/uninstall.sh"
}
trap cleanup EXIT

step "install agent-sandbox $AGENT_SANDBOX_VERSION"
bash "$ROOT/utils/agent-sandbox/install.sh"
kubectl create namespace "$NS"

step "SandboxTemplate + SandboxWarmPool(3) + SandboxClaim on k7-fc"
kubectl -n "$NS" apply -f "$HERE/template-warmpool-claim-k7-fc.yaml"
kubectl -n "$NS" wait sandboxwarmpool/python-k7-fc-pool --for=jsonpath='{.status.readyReplicas}'=3 --timeout=300s
kubectl -n "$NS" wait sandboxclaim/python-k7-fc-claim --for=condition=Ready --timeout=180s
POD="$(kubectl -n "$NS" get sandboxclaim python-k7-fc-claim -o jsonpath='{.status.sandbox.name}')"
kubectl -n "$NS" get pod "$POD" -o custom-columns=POD:.metadata.name,RUNTIME:.spec.runtimeClassName,IP:.status.podIP,RESTARTS:.status.containerStatuses[0].restartCount
# shellcheck disable=SC2016 # expands in the guest
kubectl -n "$NS" exec "$POD" -- sh -c 'echo "inside: $(uname -r), $(nproc) vCPU, $(grep -c hypervisor /proc/cpuinfo) hypervisor flag(s)"'

step "Python SDK $SDK_VERSION via sandbox-router (Tunnel mode)"
[[ -x "$VENV/bin/python" ]] || python3 -m venv "$VENV"
"$VENV/bin/pip" install -q --require-hashes -r "$HERE/requirements.txt"
"$VENV/bin/python" "$HERE/sdk_smoke.py" "$NS" python-k7-fc-pool

step "Docker-in-VM on k7 (annotations k7d.katakate.org/docker*)"
kubectl -n "$NS" apply -f "$HERE/template-docker-k7.yaml"
kubectl -n "$NS" wait sandboxclaim/docker-k7-claim --for=condition=Ready --timeout=300s
POD="$(kubectl -n "$NS" get sandboxclaim docker-k7-claim -o jsonpath='{.status.sandbox.name}')"
kubectl -n "$NS" exec "$POD" -- sh -c "docker info --format 'driver={{.Driver}} root={{.DockerRootDir}}' && docker run --rm $HELLO | head -2"
step "done"
