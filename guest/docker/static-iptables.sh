#!/bin/sh
# Runs inside alpine:3.21. Statically links xtables-{nft,legacy}-multi + busybox ip.
# Musl's netinet/if_ether.h and linux/if_ether.h both define struct ethhdr;
# -D__UAPI_DEF_ETHHDR=0 is the distro fix. iptables 1.8.11's configure
# uses bash `regular_CFLAGS+=` (ash treats that as a command), so configure
# runs under bash.
set -eu
# busybox ash on alpine 3.21 understands pipefail
set -o pipefail

: "${IPTABLES_VERSION:?}" "${IPTABLES_BACKEND:?}"

# libnftnl.a ships in libnftnl-dev on alpine 3.21 (no libnftnl-static
# package). libmnl-static provides libmnl.a.
apk add --no-cache \
    bash build-base linux-headers bison flex pkgconf \
    libmnl-dev libmnl-static libnftnl-dev \
    file busybox-static xz

mkdir -p /build
tar -C /build -xJf /src/iptables.tar.xz
cd "/build/iptables-${IPTABLES_VERSION}"

nft_flag='--disable-nftables'
if [ "$IPTABLES_BACKEND" = nft ]; then
    nft_flag='--enable-nftables'
fi

# Force the musl ethhdr guard into every compile; do not rely on configure
# detecting it (that detection is what emits the bash-only `+=` line).
export CFLAGS="${CFLAGS:-} -D__UAPI_DEF_ETHHDR=0 -Os"
export CPPFLAGS="${CPPFLAGS:-} -D__UAPI_DEF_ETHHDR=0"
export LDFLAGS="${LDFLAGS:-} -static"
# libtool drops -static unless -all-static is also set; pkg-config --static
# pulls libnftnl.a + libmnl.a instead of the .so.
export LIBS="${LIBS:-} $(pkg-config --static --libs libnftnl)"

CONFIG_SHELL=/bin/bash
export CONFIG_SHELL
bash ./configure \
    --prefix=/opt/ipt \
    --enable-static \
    --disable-shared \
    "$nft_flag" \
    --with-xtlibdir=/opt/ipt/libexec/xtables

make -j"$(nproc)" LDFLAGS="-all-static -static"
make install

if [ "$IPTABLES_BACKEND" = nft ]; then
    multi=/opt/ipt/sbin/xtables-nft-multi
else
    multi=/opt/ipt/sbin/xtables-legacy-multi
fi
if [ ! -x "$multi" ]; then
    echo "iptables multi-call binary missing after static build" >&2
    ls -l /opt/ipt/sbin >&2
    exit 1
fi
if ! file "$multi" | grep -q 'statically linked'; then
    echo "iptables is not static: $(file "$multi")" >&2
    ldd "$multi" >&2 || true
    exit 1
fi

mkdir -p /out/bin
cp "$multi" /out/bin/iptables
chmod 755 /out/bin/iptables
ln -sfn iptables /out/bin/ip6tables
ln -sfn iptables /out/bin/iptables-restore
ln -sfn iptables /out/bin/iptables-save
ln -sfn iptables /out/bin/ip6tables-restore
ln -sfn iptables /out/bin/ip6tables-save
cp /bin/busybox.static /out/bin/busybox
chmod 755 /out/bin/busybox
ln -sfn busybox /out/bin/ip
