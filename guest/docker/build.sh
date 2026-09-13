#!/usr/bin/env bash
# Build the pinned Docker payload slot (engine + CLI plugins + static iptables).
# Requires Docker. Does not touch the guest kernel, initramfs, or Ubuntu image.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
# shellcheck disable=SC1091
source "$SCRIPT_DIR/pins.env"

: "${DOCKER_VERSION:?}" "${COMPOSE_VERSION:?}" "${BUILDX_VERSION:?}"
: "${IPTABLES_VERSION:?}" "${IPTABLES_BACKEND:?}"
: "${DOCKER_TGZ_SHA256:?}" "${COMPOSE_SHA256:?}" "${BUILDX_SHA256:?}"
: "${IPTABLES_TARBALL_SHA256:?}" "${ALPINE_IMAGE:?}" "${CA_BUNDLE_SHA256:?}"

if [[ "$IPTABLES_BACKEND" != "nft" && "$IPTABLES_BACKEND" != "legacy" ]]; then
    echo "IPTABLES_BACKEND=$IPTABLES_BACKEND must be nft or legacy" >&2
    exit 1
fi

PAYLOAD="$SCRIPT_DIR/payload"
CACHE="$SCRIPT_DIR/.cache"
mkdir -p "$CACHE" "$PAYLOAD/bin" "$PAYLOAD/cli-plugins"
# Tests run this binary in parallel; one flock so they don't stomp the
# tarball unpack / alpine build.
exec 9>"$CACHE/build.lock"
flock 9

payload_complete() {
    local bin plug
    for bin in dockerd docker docker-proxy docker-init containerd \
        containerd-shim-runc-v2 runc ctr iptables ip; do
        [[ -e "$PAYLOAD/bin/$bin" ]] || return 1
    done
    for plug in docker-compose docker-buildx; do
        [[ -x "$PAYLOAD/cli-plugins/$plug" ]] || return 1
    done
    [[ -f "$PAYLOAD/etc/ssl/certs/ca-certificates.crt" ]] || return 1
    return 0
}

install_ca_bundle() {
    local dest="$PAYLOAD/etc/ssl/certs/ca-certificates.crt"
    mkdir -p "$(dirname "$dest")"
    if [[ -f "$dest" ]]; then
        local got
        got="$(sha256sum "$dest" | awk '{print $1}')"
        if [[ "$got" == "$CA_BUNDLE_SHA256" ]]; then
            return 0
        fi
        echo "CA bundle hash mismatch for $dest (got $got want $CA_BUNDLE_SHA256); re-extracting" >&2
        rm -f "$dest"
    fi
    echo "==> extracting CA bundle from $ALPINE_IMAGE"
    docker run --rm --entrypoint cat "$ALPINE_IMAGE" \
        /etc/ssl/certs/ca-certificates.crt >"$dest"
    chmod 644 "$dest"
    local got
    got="$(sha256sum "$dest" | awk '{print $1}')"
    if [[ "$got" != "$CA_BUNDLE_SHA256" ]]; then
        echo "CA bundle sha256 mismatch: got $got want $CA_BUNDLE_SHA256" >&2
        rm -f "$dest"
        exit 1
    fi
}

# Cheap: existing payloads that already have the binaries just pick up CAs.
install_ca_bundle
if payload_complete; then
    echo "==> Docker payload already present: $PAYLOAD"
    exit 0
fi

fetch() {
    local url="$1" dest="$2" sha="$3"
    if [[ -f "$dest" ]]; then
        local got
        got="$(sha256sum "$dest" | awk '{print $1}')"
        if [[ "$got" == "$sha" ]]; then
            return 0
        fi
        echo "cache hash mismatch for $dest (got $got want $sha); re-fetching" >&2
        rm -f "$dest"
    fi
    echo "==> fetching $url"
    curl -fsSL -o "$dest" "$url"
    local got
    got="$(sha256sum "$dest" | awk '{print $1}')"
    if [[ "$got" != "$sha" ]]; then
        echo "sha256 mismatch for $dest: got $got want $sha" >&2
        rm -f "$dest"
        exit 1
    fi
}

fetch "https://download.docker.com/linux/static/stable/x86_64/docker-${DOCKER_VERSION}.tgz" \
    "$CACHE/docker-${DOCKER_VERSION}.tgz" "$DOCKER_TGZ_SHA256"
fetch "https://github.com/docker/compose/releases/download/v${COMPOSE_VERSION}/docker-compose-linux-x86_64" \
    "$CACHE/docker-compose-linux-x86_64" "$COMPOSE_SHA256"
fetch "https://github.com/docker/buildx/releases/download/v${BUILDX_VERSION}/buildx-v${BUILDX_VERSION}.linux-amd64" \
    "$CACHE/docker-buildx" "$BUILDX_SHA256"
fetch "https://www.netfilter.org/projects/iptables/files/iptables-${IPTABLES_VERSION}.tar.xz" \
    "$CACHE/iptables-${IPTABLES_VERSION}.tar.xz" "$IPTABLES_TARBALL_SHA256"

echo "==> unpacking docker ${DOCKER_VERSION} static tarball"
tar -C "$CACHE" -xzf "$CACHE/docker-${DOCKER_VERSION}.tgz"
for bin in dockerd docker docker-proxy docker-init containerd containerd-shim-runc-v2 runc ctr; do
    if [[ ! -f "$CACHE/docker/$bin" ]]; then
        echo "docker tarball missing bin/$bin" >&2
        exit 1
    fi
    cp "$CACHE/docker/$bin" "$PAYLOAD/bin/$bin"
    chmod 755 "$PAYLOAD/bin/$bin"
done

cp "$CACHE/docker-compose-linux-x86_64" "$PAYLOAD/cli-plugins/docker-compose"
cp "$CACHE/docker-buildx" "$PAYLOAD/cli-plugins/docker-buildx"
chmod 755 "$PAYLOAD/cli-plugins/docker-compose" "$PAYLOAD/cli-plugins/docker-buildx"

echo "==> statically linking iptables ${IPTABLES_VERSION} (${IPTABLES_BACKEND}) + ip"
docker run --rm \
    -e "IPTABLES_VERSION=${IPTABLES_VERSION}" \
    -e "IPTABLES_BACKEND=${IPTABLES_BACKEND}" \
    -v "$CACHE/iptables-${IPTABLES_VERSION}.tar.xz:/src/iptables.tar.xz:ro" \
    -v "$SCRIPT_DIR/static-iptables.sh:/src/static-iptables.sh:ro" \
    -v "$PAYLOAD:/out" \
    "$ALPINE_IMAGE" \
    /bin/sh /src/static-iptables.sh

echo "==> verifying payload"
install_ca_bundle
for bin in dockerd docker docker-proxy docker-init containerd \
    containerd-shim-runc-v2 runc ctr iptables ip; do
    if [[ ! -e "$PAYLOAD/bin/$bin" ]]; then
        echo "payload missing bin/$bin" >&2
        exit 1
    fi
done
for plug in docker-compose docker-buildx; do
    if [[ ! -x "$PAYLOAD/cli-plugins/$plug" ]]; then
        echo "payload missing cli-plugins/$plug" >&2
        exit 1
    fi
done
if [[ ! -f "$PAYLOAD/etc/ssl/certs/ca-certificates.crt" ]]; then
    echo "payload missing etc/ssl/certs/ca-certificates.crt" >&2
    exit 1
fi

echo "==> Docker payload built: $PAYLOAD"
ls -l "$PAYLOAD/bin" "$PAYLOAD/cli-plugins"
