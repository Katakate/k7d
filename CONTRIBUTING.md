# Contributing to k7d

Thanks for contributing. Build, test, and RuntimeClass setup live in
[`HACKING.md`](HACKING.md) — start there.

## What you need

- Linux x86_64 host with `/dev/kvm` (and usually `/dev/vhost-vsock`,
  `/dev/net/tun`, root for bridge/TAP tests)
- Rust (version pinned in `rust-toolchain.toml`) and Docker
- Optional: k3s for the kubectl / RuntimeClass suite

macOS and the CI remote sandbox cannot compile the rust-vmm crates.
If you edit elsewhere, use a remote Linux/KVM host via the Makefile
`remote-*` targets (`K7_NODE_IP` required).

## Workflow

1. Read [`HACKING.md`](HACKING.md) and the product docs at
   [docs.katakate.org/k7d](https://docs.katakate.org/k7d).
2. Make a focused change; keep errors loud (no silent defaults).
3. On a KVM host: `make check` (fmt + deny + clippy + tests with
   `--test-threads=1`). For kubectl paths: `make test-integration`.
4. After non-trivial debugging, consider a short note in `CHALLENGES.md`
   (symptom / root cause / fix) so the next person does not rediscover it.

Never add `#[ignore]` to hide failures — fix the test or the code.
The primary test host has KVM, virtiofsd, and k3s.

## Project direction

See the README roadmap. Near-term: `/etc/k7d/config.toml`, then
cross-node fork.

## Reporting issues

Include host OS/kernel, whether `/dev/kvm` is present, k7d version or
commit, exact command, and logs (`journalctl -u k7d`, test output).
Security reports: see [`SECURITY.md`](SECURITY.md).

## License

By contributing you agree your contributions are licensed under Apache-2.0
(see [`LICENSE`](LICENSE)).
