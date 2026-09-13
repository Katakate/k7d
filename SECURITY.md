# Security Policy

## Supported versions

k7d is pre-1.0. Security fixes land on the latest release only until 1.0.0.

| Version | Supported |
|---------|-----------|
| 0.3.x   | ✅        |
| < 0.3   | ❌        |

## Reporting a vulnerability

Email **security@katakate.org** (preferred), or open a private GitHub
Security Advisory on [Katakate/k7d](https://github.com/Katakate/k7d).

Include impact, reproduction steps or a PoC, and affected version / commit.
We aim to acknowledge within 72 hours.

Please do not open a public issue for security-sensitive reports.

## Threat model (honest summary)

k7d is built for fleets of **your own** environments (RL rollouts, agent
evals, sandboxes you control) — not for hostile multi-tenant isolation
between sibling forks of the same tenant.

| Boundary | Strength |
|----------|----------|
| Guest → host | KVM hardware isolation |
| Between unrelated VMs / trees | Separate bridges, separate guest memory files |
| Between sibling CoW forks of one tree | **Weaker** — parent and child share one daemon address space by design (live CoW requires it) |

Additional limits:

- Single host, Linux x86_64 + KVM only; no cross-node fork yet
- Young codebase (≤30k LOC VMM + shim); no third-party security audit yet
- Control socket `/run/k7d/k7d.sock` is local Unix — see the section below

For product-facing detail see the docs site security page and the README
"Security model & limitations" section.

## Guest-controlled paths

The guest is attacker-controlled from its first instruction. The shim
and daemon run as host root. These rules apply to every host filesystem
operation whose *path* the guest can influence:

1. No `create`, `mkdir`, `open(O_CREAT)`, `rename`, `unlink`, `chown`,
   `copy`, or `mount` at a path under a directory the guest can write,
   unless the final component is opened relative to a share-root fd
   with `O_NOFOLLOW` / `openat2(RESOLVE_BENEATH | RESOLVE_NO_SYMLINKS)`
   and an existing entry is an **error**, never reused.
2. Anything the host attaches to more than one VM is read-only and
   host-enforced (`O_RDONLY` + write rejection), never "RO because
   the guest mounts it `ro`".
3. Strings from the guest agent (paths, names, sizes) never reach a
   host path, command line, or cgroup path. Responses are bounded.
4. Confinement fields in the OCI spec pass through. Strip only what
   the guest provably lacks (`apparmorProfile`: no LSM; host
   namespace `path`s; `cgroupsPath`) and say so in the code.

The virtiofs hostPath fallback (`/var/lib/k7d/pods/<id>/volumes-rw`)
is the one directory the guest can write that the host still operates
under after boot. Placeholders are created with `mkdirat` /
`openat(O_CREAT|O_EXCL|O_NOFOLLOW)` relative to an `O_PATH` share-root
fd; bind-mounts go through `/proc/self/fd/N`. Read-only shares are
`MS_RDONLY` bind-remounted on the host before virtiofsd chroots.
`K7D_DENY_VIRTIOFS_FALLBACK=1` fails Create for any pod that would
take the fallback (hardened / Firecracker profiles).

## Firecracker profile (`runtimeClassName: k7-fc`)

Stock Firecracker under the stock jailer. Same shim, same daemon, same
agent; a different VMM process. See `docs/backends.md` for the
selection matrix.

| | What |
|---|---|
| **Gained** | The VMM is out of the daemon's address space. Each VM has its own uid, chroot, pid namespace, cgroup, and Firecracker's default seccomp. A guest→VMM escape lands in that jail, not in `k7d`. |
| **Unchanged** | The daemon is still host root and still one process (control socket, TAP/bridge, vsock proxy, tree bookkeeping). The shim still rewrites the OCI spec — the same floor applies to both backends. Network is still the daemon's bridge. The guest agent is the same binary and protocol. Sibling CoW forks of one tree still share the daemon. |
| **Lost** | Time warp, dilation, autowarp. virtiofs / hostPath (Create fails with `backend firecracker has no virtiofs`). Native MAP_PRIVATE fork latency — FC fork is Diff snapshot + `LoadSnapshot` (see `LATENCY_BUDGETS.md`). |

`runtimeClassName: k7` stays the native in-process VMM. The
`k7d.katakate.org/backend: firecracker` annotation on a `k7` pod is
the opt-in; `k7-fc` is the admission-gateable default. An
explicit `backend: native` on `k7-fc` is a loud Create error.

Multi-tenant `--docker` should use `k7-fc`: the guest side is
identical, so that is a RuntimeClass switch, not a rewrite. The VMM
jail is the extra boundary; in-guest `docker.sock` is still guest
root.

## Control socket

`/run/k7d/k7d.sock` is a Unix socket owned by the daemon (host root).
`serve` creates the parent at `0750` and the socket at `0660`
(`root:root`). k7-api and the k7-agent DaemonSet run as uid 0, so
those bits do not break the product path.

This is an audit trail and a floor, not an auth system. A process that
can connect can create, stop, and fork every VM on the node — the same
power as a compromised shim. Optional `K7D_ALLOWED_UIDS=0,1000` refuses
connections from any other uid (logged with `SO_PEERCRED` uid/gid/pid).
Mutating ops (`create_vm`, `stop_vm`, `fork_vm`, tree writes,
`delete_data_disk`, …) log peer cred at `info`; reads at `debug`.

Put the socket in a dedicated directory (`/run/k7d`), not `/tmp`. A
world-writable sticky parent is not tightened to `0750`.

## Pod `securityContext` reaches guest runc

`runtimeClassName: k7` does not rewrite the confinement kubelet and
containerd already encoded in the OCI spec. Guest runc sees:

- `linux.seccomp` (including `seccompProfile: RuntimeDefault`)
- `maskedPaths` / `readonlyPaths`
- `linux.resources.devices` as CRI emitted them (deny-all for
  unprivileged, allow-all for privileged — the latter is what lets
  in-guest kubelet open `/dev/kmsg`)
- capabilities, `noNewPrivileges`, memory/cpu limits

The shim strips only what the guest kernel cannot honour:
`process.apparmorProfile` (no LSM in `config-minimal`), host
`cgroupsPath`, and host namespace `path`s. If guest runc rejects a
seccomp profile, Create fails with runc's error; the shim does not
strip the profile and retry. See CHALLENGES #210.

## `--docker`

`k7d.katakate.org/docker=true` runs a pinned `dockerd` as a child of
the guest PID 1 agent. `docker.sock` is guest root: the sandbox
`securityContext` no longer bounds the guest. The only remaining
boundaries are the VMM and the host-side rules above.

- The payload slot (`/run/k7d/docker-tools`) is a read-only virtio-blk
  image, host-enforced (`O_RDONLY` + `T_OUT` rejected). A guest that
  could rewrite `dockerd` would trojan every later sandbox
  (CVE-2020-2025).
- The graph disk is a per-VM scratch image, reflinked on fork, deleted
  with the VM — never a host directory shared across pods.
- The CRI container is not privileged. Inner containers get dockerd's
  default seccomp and capabilities. Because the guest root is
  initramfs, dockerd is started with `DOCKER_RAMDISK=1` so runc uses
  `--no-pivot` (chroot) instead of `pivot_root(2)`, which returns
  EINVAL on rootfs.
- Multi-tenant `--docker` should use `k7-fc`; the guest
  side is identical so that is a RuntimeClass switch, not a rewrite.

## Responsible disclosure

Coordinate disclosure; we will credit reporters unless anonymity is requested.
