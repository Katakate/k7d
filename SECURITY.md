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
- `k7d` is **two processes** (privilege separation, below). The one that parses
  guest and shim input is uid `k7d` with an empty capability set; the one
  that holds the root-equivalent `CAP_SYS_ADMIN` has no listening socket
  and a closed verb table as its only input.

For product-facing detail see the docs site security page and the README
"Security model & limitations" section.

## Privilege separation

`k7d.service` starts one binary that forks itself in two before it
allocates a thread or binds a socket. What a guest→daemon escape reaches
is the second row.

| Process | Identity | Holds | Its input |
|---|---|---|---|
| **node broker** | uid 0, the measured bounding set below, seccomp `NODE_SYSCALLS` | TAP/bridge/`nft`/CNI netns, `mount`/`umount2` for shares, the Firecracker jailer and its uid leases, `chown`/`link` into jails, `SIGKILL` of jailed pids, the jailer cgroup tree, and the root-only files the shim hands over | **Only** the VM broker, over a `SOCK_SEQPACKET` socketpair created before the fork. No listening socket, no path, no second peer. Its request type is a closed enum of ids — there is no `exec`, `mount(source, target)`, `chown` or `write_file` verb, because each of those is a capability with a free parameter. |
| **VM broker** | uid `k7d`, gid `k7d`, supplementary group `kvm` only; `CapInh`/`CapPrm`/`CapEff`/`CapBnd`/`CapAmb` all empty; `NoNewPrivs=1`; `PR_SET_DUMPABLE=0`; seccomp `VM_SYSCALLS` | `/run/k7d/k7d.sock` and its parser, the guest agent clients, vCPU threads and every virtio device model, the snapshot trees, and its own state under `/var/lib/k7d/{trees,sandboxes,stage,disks}` | The shim (control socket), the guest agents (vhost-vsock / Firecracker UDS), guest virtio descriptor chains, and FUSE traffic. Everything attacker-influenced. |
| **helper spawner** | uid `k7d`, no capabilities, seccomp `HELPER_SYSCALLS` (pre-seccomp helper spawner) | `execve` of helpers that need no capability (`mkfs.ext4`, `mkfs.erofs`, `cp --reflink`) | The VM broker |

So the escape sentence is: a guest that gets out of KVM and out of the
device models lands in a process that cannot mount, cannot create a
network device, cannot write another uid's cgroup, cannot regain a
capability through any setuid binary, and cannot be inspected through
`/proc` by another `k7d`-uid process. What it can do is send the node
broker one of the verbs in the closed table above, each naming an id the
node broker already registered — never a path.

Paths cross exactly once, at `vm.register`, before any disk is
provisioned or any network acquired. Each is checked against a per-class
root allowlist (§5) and resolved with
`openat2(RESOLVE_BENEATH | RESOLVE_NO_SYMLINKS | RESOLVE_NO_MAGICLINKS)`,
then pinned as an `O_PATH` descriptor that later verbs address by index.
A path outside the allowlist fails `CreateVm` with the field and index
named. `/tmp` is never a root on its own — only the
`/tmp/k7d-shim-<sandbox>` family — because a world-writable sticky
directory would otherwise let any local uid present a share to the
daemon.

Crash coupling is total in both directions: the VM broker carries
`PR_SET_PDEATHSIG=SIGKILL`, so it cannot outlive the node broker, and a
VM broker that dies makes the node broker release every registered id and
exit non-zero so systemd replaces the pair rather than leaving half of it
live.

`packaging/install.sh` creates the `k7d` account (system user, `nologin`,
member of `kvm`) and installs `60-k7d.rules`, which puts
`/dev/vhost-vsock` in group `kvm` — that membership, not a capability, is
what lets a process with no privileges open `/dev/kvm` and
`/dev/vhost-vsock`. `/var/lib/k7d/fc` and `/sys/fs/cgroup/k7d` stay root
`0700`: they are the node broker's, and the test suite asserts uid `k7d`
cannot create in either.

`K7D_PRIVSEP` selects the mode. The shipped unit sets it `on`
(`packaging/k7d.service.in`). `off` is the escape hatch: one root
process. `k7d doctor`'s `privsep:` section reports which it is.

## Daemon capability bounding set

`k7d.service` drops every capability not in this list. The table is
the `kprobe:cap_capable` union over a full `make remote-check` on
k7-node-01 (`K7_NODE_IP=<node-ip>`; see CHALLENGES #244), not a
guess. `CapBnd` of the running daemon must equal the mask in
`crates/k7d/src/doctor.rs` (`EXPECTED_CAPBND`); `k7d doctor` reports it.

| Capability | Who needs it |
|---|---|
| `CAP_SYS_ADMIN` | `mount`/`umount2` (virtiofs, hostPath), loop-mount of the reflink XFS (now `ExecStartPre`), cgroup v2, `setns` for CNI |
| `CAP_NET_ADMIN` | TAP create/move, bridge, `nft`, `ip` |
| `CAP_NET_RAW` | `iptables` (xtables still checks it; nft does not) |
| `CAP_SETUID` / `CAP_SETGID` / `CAP_SETPCAP` / `CAP_SETFCAP` / `CAP_SYS_CHROOT` / `CAP_SYS_RESOURCE` / `CAP_MKNOD` | Inherited by the **jailer** and **virtiofsd** children. virtiofsd 1.10 `drop_capabilities` requires `SETFCAP` (not in the bpftrace table). |
| `CAP_CHOWN` | Re-owning RW disks into a jail uid |
| `CAP_KILL` | `SIGKILL` a jailed Firecracker running as another uid |
| `CAP_SYS_PTRACE` | Firecracker spawn reaper: `/proc/<pid>/status` of a jailed Firecracker (other uid). An earlier guess said this was test-only; `fc/spawn.rs` `pids_owned_by` is product. |
| `CAP_FSETID` | Jailer `chmod` of staged binaries (setuid/gid bits) |
| `CAP_FOWNER` | `chmod` on files the daemon does not own (staged kernel) |
| `CAP_DAC_OVERRIDE` / `CAP_DAC_READ_SEARCH` | kubelet 0400 Secret files |

Not in the bounding set: `CAP_SYS_MODULE` (`ip` probes it to load
netdev modules; the check fails harmlessly once they are loaded),
`CAP_SYS_RAWIO`,
`CAP_SYS_BOOT`, `CAP_SYS_TIME`, `CAP_BPF`, `CAP_PERFMON`, `CAP_SYSLOG`,
`CAP_IPC_LOCK`, `CAP_SYS_NICE`. The suite is the
test that they stay dropped.

The unit also sets `ProtectSystem=strict` (`/usr` is EROFS in the
service mount namespace), `NoNewPrivileges=yes`,
`DevicePolicy=closed` with DeviceAllow for kvm / vhost-vsock / tun /
loop, and `RestrictAddressFamilies` to unix/vsock/netlink/inet/inet6.
`PrivateTmp` and `ProtectHome` were dropped (CHALLENGES #244): the
shim still stages overlay slots under `/tmp/k7d-shim-*`, and the gym
still passes `/root/k7d/guest/kernel/vmlinux` on create. The reflink
XFS is mounted from `ExecStartPre=+` so it lives in the host
namespace and slave-propagates in; kubelet's volume mounts under
`/var/lib/kubelet/pods` do the same.

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
| **Gained (Firecracker jail integrity)** | A failed spawn cannot leave a VMM running as a uid the allocator will reuse: after the jailer clones, every error path kills the orphan (verified from `/proc`, quarantining the uid if it survives) and removes its cgroup before the uid lease and chroot are released. The jailed Firecracker inherits no daemon descriptor — every pipe and eventfd k7d makes is `CLOEXEC` (`fdutil.rs`), the guest-memory memfd keeps its `MFD_CLOEXEC`, asserted against `/proc/<fc_pid>/fd` and a helper child's `/proc/self/fd`. Read-only volume staging is `0700` under `/var/lib/k7d`, source modes kept. |
| **Unchanged** | The daemon is still the one host component both backends share (control socket, TAP/bridge, vsock proxy, tree bookkeeping) — privilege separation splits *which of its processes* holds root, not which host owns the work. The shim still rewrites the OCI spec — the same floor applies to both backends. Network is still the daemon's bridge. The guest agent is the same binary and protocol. Sibling CoW forks of one tree still share the daemon. |
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
