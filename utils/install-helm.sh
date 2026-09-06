#!/usr/bin/env bash
# Pin helm v3.16.4 to /usr/local/lib/k7d-helm/v3.16.4/helm.
#
# Same pin as crates/k7d/tests/common/ubuntu_helm.rs, gym/sensors.py,
# and examples/k7d-mcp/cluster.py. A host helm of any other version
# must not silently change the Cilium/Tetragon chart renderer.
#
# Usage (from a clone, as root):
#   make helm-pin
#   # or: bash utils/install-helm.sh
set -euo pipefail

HELM_VERSION="v3.16.4"
HELM_TGZ="helm-${HELM_VERSION}-linux-amd64.tar.gz"
HELM_URL="https://get.helm.sh/${HELM_TGZ}"
DEST_DIR="/usr/local/lib/k7d-helm/${HELM_VERSION}"
CACHE="/var/cache/k7d-helm"
HELM_BIN="${DEST_DIR}/helm"

die() { echo "helm-pin: $*" >&2; exit 1; }

if [[ "$(id -u)" -ne 0 ]]; then
    die "must run as root (installs ${HELM_BIN})"
fi

if [[ -x "${HELM_BIN}" ]]; then
    got="$("${HELM_BIN}" version --short 2>/dev/null || true)"
    if [[ "${got}" == *"${HELM_VERSION}"* ]]; then
        echo "helm-pin: already ${HELM_VERSION} at ${HELM_BIN}"
        exit 0
    fi
fi

command -v curl >/dev/null || die "curl is required"
command -v sha256sum >/dev/null || die "sha256sum is required"
command -v tar >/dev/null || die "tar is required"

mkdir -p "${CACHE}" "${DEST_DIR}"
tgz="${CACHE}/${HELM_TGZ}"
sum="${CACHE}/${HELM_TGZ}.sha256sum"
if [[ ! -f "${tgz}" ]]; then
    echo "helm-pin: downloading ${HELM_URL}"
    curl -fsSL -o "${tgz}" "${HELM_URL}"
fi
if [[ ! -f "${sum}" ]]; then
    curl -fsSL -o "${sum}" "${HELM_URL}.sha256sum"
fi
(cd "${CACHE}" && sha256sum -c "${HELM_TGZ}.sha256sum") \
    || die "tarball digest mismatch"

tar -xzf "${tgz}" -C "${DEST_DIR}" --strip-components=1 linux-amd64/helm
chmod 755 "${HELM_BIN}"
got="$("${HELM_BIN}" version --short)"
[[ "${got}" == *"${HELM_VERSION}"* ]] \
    || die "helm reports ${got}, want ${HELM_VERSION}"
echo "helm-pin: ${HELM_VERSION} at ${HELM_BIN}"
