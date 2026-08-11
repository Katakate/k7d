FROM alpine:3.20 AS rootfs
RUN apk add --no-cache busybox runc
COPY target/x86_64-unknown-linux-musl/release/k7-agent /usr/local/bin/k7-agent
COPY guest/rootfs/init.sh /init
RUN chmod +x /init /usr/local/bin/k7-agent
