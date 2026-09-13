//! Daemon-wide seccomp allowlist.
//!
//! k7d is one process and every tree's VMs are threads of it, so there
//! is no per-tree process to filter: a filter installed on the main
//! thread before any VM exists is inherited by every thread spawned
//! afterwards and therefore covers all trees at once. That is what this
//! module installs.
//!
//! The `ioctl` surface is the interesting part. Rather than enumerate
//! several dozen KVM request numbers (which change shape with every
//! kvm-bindings bump), the filter matches the *type* byte of the ioctl
//! request — bits 8..15 of the request encode the driver. The VMM
//! surface is KVM (`0xAE`), vhost (`0xAF`), and TUN/terminal (`'T'`).
//! Helpers and the daemon's own disk path add the rest: `FICLONE`
//! (`0x94`), socket `SIOC*` (`0x89`), block (`0x12`), loop (`0x4C`),
//! XFS (`0x58`), and the floppy/CDROM probes `mkfs` issues.
//!
//! ## Why the default is `enforce`
//!
//! Two reasons the filter used to default to `log`, both still
//! load-bearing as *reasons to keep the allowlist honest*:
//!
//! 1. An allowlist that is missing one syscall does not fail a test —
//!    it kills the node's entire VM fleet at once, because there is one
//!    process.
//! 2. **Seccomp filters survive `execve`.** k7d spawns helpers
//!    (`virtiofsd`, `nft`, `ip`, `iptables`), and they inherit this
//!    filter. Their syscall surface is much wider than the daemon's, so
//!    the allowlist has to cover them too.
//!
//! The default flipped to enforce after a full suite run on
//! k7-node-02 produced no daemon/helper `SECCOMP` audit lines (the
//! only hits were the unit-test `getcpu` probe). `K7D_SECCOMP=log`
//! and `off` remain escape hatches.

use std::collections::BTreeMap;

use seccompiler::{
    BpfProgram, SeccompAction, SeccompCmpArgLen, SeccompCmpOp, SeccompCondition, SeccompFilter,
    SeccompRule, TargetArch,
};

/// What the filter does with a syscall that is not on the allowlist.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    /// Kill the process. The default: a mismatch takes the whole
    /// fleet with it, which is why the allowlist was proven in `log`
    /// mode first.
    Enforce,
    /// Log and allow. Escape hatch: `K7D_SECCOMP=log`.
    Log,
    /// Install nothing.
    Off,
}

impl Mode {
    /// Parse `K7D_SECCOMP`. Unset is [`Mode::Enforce`]; an unrecognised
    /// value is an error, never a silent downgrade.
    pub fn from_env() -> Result<Self, String> {
        match std::env::var("K7D_SECCOMP") {
            Err(_) => Ok(Self::Enforce),
            Ok(v) => Self::parse(v.trim()),
        }
    }

    fn parse(value: &str) -> Result<Self, String> {
        match value {
            "" | "log" => Ok(Self::Log),
            "enforce" => Ok(Self::Enforce),
            "off" => Ok(Self::Off),
            other => Err(format!(
                "K7D_SECCOMP={other:?} is not one of enforce|log|off"
            )),
        }
    }

    fn mismatch_action(self) -> SeccompAction {
        match self {
            Self::Enforce => SeccompAction::KillProcess,
            // `Off` never builds a filter; the arm exists so the match
            // stays total if someone reuses this helper.
            Self::Log | Self::Off => SeccompAction::Log,
        }
    }
}

/// ioctl request types (bits 8..15) the daemon and its helpers may issue.
const IOCTL_TYPES: [u64; 11] = [
    0xAE, // KVM
    0xAF, // vhost / vhost-vsock
    0x54, // 'T': TUN/TAP and the terminal ioctls Rust's std issues
    0x94, // FICLONE / FICLONERANGE (disk CoW)
    0x66, // 'f': FS_IOC_FIEMAP — the shared-extent proof behind every FC fork
    0x89, // socket SIOC* (`ip` and TAP identity)
    0x12, // BLK* (`mkfs.ext4`, `mount`)
    0x4C, // LOOP_* (`losetup`)
    0x58, // XFS (`mkfs.xfs`)
    0x53, // CDROM_* (`mount` / `mkfs` capability probes)
    0x02, // FDGETPRM / FDGETFDCSTAT (`mkfs` floppy probes)
];

/// Mask selecting the type byte of an ioctl request number.
const IOCTL_TYPE_MASK: u64 = 0x0000_FF00;

/// Syscalls the daemon itself needs: VM setup and run, the control
/// socket, the tree store on disk, threads, and timers.
const DAEMON_SYSCALLS: &[libc::c_long] = &[
    libc::SYS_read,
    libc::SYS_write,
    libc::SYS_readv,
    libc::SYS_writev,
    libc::SYS_pread64,
    libc::SYS_pwrite64,
    libc::SYS_preadv,
    libc::SYS_pwritev,
    libc::SYS_preadv2,
    libc::SYS_pwritev2,
    libc::SYS_open,
    libc::SYS_openat,
    libc::SYS_close,
    libc::SYS_stat,
    libc::SYS_fstat,
    libc::SYS_lstat,
    libc::SYS_newfstatat,
    libc::SYS_statx,
    libc::SYS_statfs,
    libc::SYS_fstatfs,
    libc::SYS_lseek,
    libc::SYS_mmap,
    libc::SYS_mremap,
    libc::SYS_mprotect,
    libc::SYS_munmap,
    libc::SYS_madvise,
    libc::SYS_msync,
    libc::SYS_mlock,
    libc::SYS_munlock,
    libc::SYS_brk,
    libc::SYS_memfd_create,
    libc::SYS_ftruncate,
    libc::SYS_fallocate,
    libc::SYS_fsync,
    libc::SYS_fdatasync,
    libc::SYS_sync,
    libc::SYS_syncfs,
    libc::SYS_copy_file_range,
    libc::SYS_sendfile,
    libc::SYS_splice,
    libc::SYS_fcntl,
    libc::SYS_flock,
    libc::SYS_dup,
    libc::SYS_dup2,
    libc::SYS_dup3,
    libc::SYS_pipe,
    libc::SYS_pipe2,
    libc::SYS_getdents64,
    libc::SYS_getcwd,
    libc::SYS_chdir,
    libc::SYS_mkdir,
    libc::SYS_mkdirat,
    libc::SYS_rmdir,
    libc::SYS_rename,
    libc::SYS_renameat,
    libc::SYS_renameat2,
    libc::SYS_link,
    libc::SYS_linkat,
    libc::SYS_symlink,
    libc::SYS_symlinkat,
    libc::SYS_readlink,
    libc::SYS_readlinkat,
    libc::SYS_unlink,
    libc::SYS_unlinkat,
    libc::SYS_access,
    libc::SYS_faccessat,
    libc::SYS_faccessat2,
    libc::SYS_utimensat,
    libc::SYS_umask,
    libc::SYS_ioctl,
    libc::SYS_socket,
    libc::SYS_socketpair,
    libc::SYS_bind,
    libc::SYS_listen,
    libc::SYS_accept,
    libc::SYS_accept4,
    libc::SYS_connect,
    libc::SYS_shutdown,
    libc::SYS_sendto,
    libc::SYS_recvfrom,
    libc::SYS_sendmsg,
    libc::SYS_recvmsg,
    libc::SYS_getsockname,
    libc::SYS_getpeername,
    libc::SYS_setsockopt,
    libc::SYS_getsockopt,
    libc::SYS_epoll_create1,
    libc::SYS_epoll_ctl,
    libc::SYS_epoll_wait,
    libc::SYS_epoll_pwait,
    libc::SYS_poll,
    libc::SYS_ppoll,
    libc::SYS_select,
    libc::SYS_pselect6,
    libc::SYS_eventfd2,
    libc::SYS_timerfd_create,
    libc::SYS_timerfd_settime,
    libc::SYS_timerfd_gettime,
    libc::SYS_nanosleep,
    libc::SYS_clock_nanosleep,
    libc::SYS_clock_gettime,
    libc::SYS_clock_getres,
    libc::SYS_gettimeofday,
    libc::SYS_time,
    libc::SYS_getrandom,
    libc::SYS_uname,
    libc::SYS_sysinfo,
    libc::SYS_getpid,
    libc::SYS_gettid,
    libc::SYS_getppid,
    libc::SYS_getuid,
    libc::SYS_geteuid,
    libc::SYS_getgid,
    libc::SYS_getegid,
    libc::SYS_prlimit64,
    libc::SYS_getrlimit,
    libc::SYS_setrlimit,
    libc::SYS_getrusage,
    libc::SYS_sched_yield,
    libc::SYS_sched_getaffinity,
    libc::SYS_sched_setaffinity,
    libc::SYS_sched_getparam,
    libc::SYS_sched_getscheduler,
    libc::SYS_futex,
    libc::SYS_set_robust_list,
    libc::SYS_get_robust_list,
    libc::SYS_rseq,
    libc::SYS_membarrier,
    libc::SYS_clone,
    libc::SYS_clone3,
    libc::SYS_execve,
    libc::SYS_wait4,
    libc::SYS_waitid,
    libc::SYS_kill,
    libc::SYS_tkill,
    libc::SYS_tgkill,
    libc::SYS_pidfd_open,
    libc::SYS_pidfd_send_signal,
    libc::SYS_rt_sigaction,
    libc::SYS_rt_sigprocmask,
    libc::SYS_rt_sigreturn,
    libc::SYS_rt_sigtimedwait,
    libc::SYS_sigaltstack,
    libc::SYS_signalfd4,
    libc::SYS_prctl,
    libc::SYS_arch_prctl,
    libc::SYS_set_tid_address,
    libc::SYS_restart_syscall,
    libc::SYS_exit,
    libc::SYS_exit_group,
    // Volume bind mounts into the virtiofs share.
    libc::SYS_mount,
    libc::SYS_umount2,
];

/// Extra syscalls the helper processes k7d spawns need. They inherit
/// this filter through `execve`, so an allowlist that only covers the
/// daemon would kill `virtiofsd` the moment it jails itself.
const HELPER_SYSCALLS: &[libc::c_long] = &[
    libc::SYS_chroot,
    libc::SYS_pivot_root,
    libc::SYS_unshare,
    libc::SYS_setns,
    libc::SYS_capget,
    libc::SYS_capset,
    libc::SYS_setuid,
    libc::SYS_setgid,
    libc::SYS_setresuid,
    libc::SYS_setresgid,
    libc::SYS_setgroups,
    libc::SYS_getgroups,
    libc::SYS_seccomp,
    libc::SYS_chmod,
    libc::SYS_fchmod,
    libc::SYS_fchmodat,
    libc::SYS_chown,
    libc::SYS_fchown,
    libc::SYS_fchownat,
    libc::SYS_lchown,
    libc::SYS_truncate,
    libc::SYS_mknod,
    libc::SYS_mknodat,
    libc::SYS_getxattr,
    libc::SYS_setxattr,
    libc::SYS_lgetxattr,
    libc::SYS_lsetxattr,
    libc::SYS_fgetxattr,
    libc::SYS_fsetxattr,
    libc::SYS_listxattr,
    libc::SYS_removexattr,
    libc::SYS_name_to_handle_at,
    libc::SYS_open_by_handle_at,
    libc::SYS_openat2,
    libc::SYS_sync_file_range,
    libc::SYS_setpriority,
    libc::SYS_getpriority,
    libc::SYS_setsid,
    libc::SYS_setpgid,
    libc::SYS_getpgrp,
    libc::SYS_personality,
    // iptables (xtables-legacy-multi) times out its lock wait with alarm(3).
    libc::SYS_alarm,
    // Firecracker's jailer. It sheds every inherited
    // descriptor with one close_range(3, ~0) and asks getsid(0) whether
    // it already leads a session before setsid(). Denying either kills
    // the jailer with SIGSYS before it has staged anything, and the only
    // evidence is an audit record (CHALLENGES #214). The rest of its
    // trace — unshare, pivot_root, chroot, mknod, mount, setgroups,
    // capset, seccomp, execve — is already covered above by virtiofsd's
    // and the volume mounts' entries.
    libc::SYS_close_range,
    libc::SYS_getsid,
];

/// Build the filter program for `mode`.
fn build(mode: Mode) -> Result<BpfProgram, String> {
    let mut rules: BTreeMap<i64, Vec<SeccompRule>> = BTreeMap::new();
    for &syscall in DAEMON_SYSCALLS.iter().chain(HELPER_SYSCALLS) {
        // An empty rule vector means "match on the syscall number
        // alone", which is what every entry except `ioctl` wants.
        rules.entry(syscall).or_default();
    }
    let ioctl_rules = IOCTL_TYPES
        .iter()
        .map(|ty| {
            let cond = SeccompCondition::new(
                1,
                SeccompCmpArgLen::Dword,
                SeccompCmpOp::MaskedEq(IOCTL_TYPE_MASK),
                ty << 8,
            )
            .map_err(|e| format!("ioctl condition for type {ty:#x}: {e}"))?;
            SeccompRule::new(vec![cond]).map_err(|e| format!("ioctl rule: {e}"))
        })
        .collect::<Result<Vec<_>, String>>()?;
    rules.insert(libc::SYS_ioctl, ioctl_rules);

    let filter = SeccompFilter::new(
        rules,
        mode.mismatch_action(),
        SeccompAction::Allow,
        TargetArch::x86_64,
    )
    .map_err(|e| format!("build seccomp filter: {e}"))?;
    filter
        .try_into()
        .map_err(|e| format!("compile seccomp filter: {e}"))
}

/// Install the filter for the calling thread (and, by inheritance,
/// every thread and child process created afterwards).
///
/// Call this from `main` **before** the first VM exists. Returns the
/// mode that was applied.
pub fn install() -> Result<Mode, String> {
    let mode = Mode::from_env()?;
    if mode == Mode::Off {
        log::warn!("K7D_SECCOMP=off: daemon runs with no syscall filter");
        return Ok(mode);
    }
    let program = build(mode)?;
    seccompiler::apply_filter(&program).map_err(|e| format!("apply seccomp filter: {e}"))?;
    match mode {
        Mode::Enforce => log::info!(
            "seccomp filter enforced ({} syscalls allowed; ioctl limited by type byte)",
            program.len()
        ),
        Mode::Log => log::info!(
            "seccomp filter installed in LOG mode — mismatches are logged, not blocked \
             (dmesg | grep -i seccomp)"
        ),
        Mode::Off => unreachable!("handled above"),
    }
    Ok(mode)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mode_parsing_is_total_and_loud() {
        assert_eq!(Mode::parse("").unwrap(), Mode::Log);
        assert_eq!(Mode::parse("log").unwrap(), Mode::Log);
        assert_eq!(Mode::parse("enforce").unwrap(), Mode::Enforce);
        assert_eq!(Mode::parse("off").unwrap(), Mode::Off);
        assert!(Mode::parse("yes").is_err());
    }

    fn with_env<T>(val: Option<&str>, f: impl FnOnce() -> T) -> T {
        let key = "K7D_SECCOMP";
        let prev = std::env::var(key).ok();
        match val {
            Some(v) => std::env::set_var(key, v),
            None => std::env::remove_var(key),
        }
        let out = f();
        match prev {
            Some(v) => std::env::set_var(key, v),
            None => std::env::remove_var(key),
        }
        out
    }

    /// Unset `K7D_SECCOMP` is `enforce`. Explicit `log` / `off` still
    /// work; an empty value stays `log` so `K7D_SECCOMP=` is not a
    /// silent flip.
    #[test]
    fn unset_defaults_to_enforce() {
        assert_eq!(with_env(None, Mode::from_env).unwrap(), Mode::Enforce);
        assert_eq!(with_env(Some("log"), Mode::from_env).unwrap(), Mode::Log);
        assert_eq!(with_env(Some("off"), Mode::from_env).unwrap(), Mode::Off);
        assert_eq!(with_env(Some(""), Mode::from_env).unwrap(), Mode::Log);
    }

    #[test]
    fn filter_builds_for_every_acting_mode() {
        for mode in [Mode::Log, Mode::Enforce] {
            let program = build(mode).unwrap_or_else(|e| panic!("build {mode:?}: {e}"));
            assert!(!program.is_empty(), "{mode:?} produced an empty program");
        }
    }

    /// The daemon's own hot path must be on the allowlist: without
    /// `ioctl`, `futex` and `mmap` a filter in `enforce` mode kills
    /// every VM on the node at once.
    #[test]
    fn allowlist_covers_the_vmm_hot_path() {
        let all: Vec<libc::c_long> = DAEMON_SYSCALLS
            .iter()
            .chain(HELPER_SYSCALLS)
            .copied()
            .collect();
        for required in [
            libc::SYS_ioctl,
            libc::SYS_futex,
            libc::SYS_mmap,
            libc::SYS_munmap,
            libc::SYS_read,
            libc::SYS_write,
            libc::SYS_clone,
            libc::SYS_execve,
            libc::SYS_pwritev2,
        ] {
            assert!(all.contains(&required), "missing syscall {required}");
        }
    }

    /// Run `f` in a forked child and return its raw wait status. The
    /// child only does async-signal-safe work (seccomp, one syscall,
    /// `_exit`), which is what makes forking from a multi-threaded test
    /// binary legal here. A filter cannot be uninstalled, so this is
    /// also the only way to exercise `install` without poisoning every
    /// other test in the binary.
    fn in_child(f: impl FnOnce()) -> libc::c_int {
        // SAFETY: the child touches nothing that needs the malloc lock.
        let pid = unsafe { libc::fork() };
        assert!(pid >= 0, "fork: {}", std::io::Error::last_os_error());
        if pid == 0 {
            f();
            // SAFETY: _exit is async-signal-safe and never returns.
            unsafe { libc::_exit(0) };
        }
        let mut status = 0;
        // SAFETY: `pid` is this process's child and `status` is valid.
        let waited = unsafe { libc::waitpid(pid, &raw mut status, 0) };
        assert_eq!(waited, pid, "waitpid: {}", std::io::Error::last_os_error());
        status
    }

    /// `getcpu` is deliberately absent from both allowlists, so it is
    /// the probe for what the mismatch action actually does.
    fn call_unlisted_syscall() {
        // SAFETY: getcpu with three null arguments has no side effects.
        unsafe { libc::syscall(libc::SYS_getcpu, 0, 0, 0) };
    }

    /// Apply `mode`'s filter to the calling (child) process. The
    /// program is compiled by the *parent* and only applied here:
    /// `fork` from a multi-threaded test binary leaves the child with
    /// whatever locks the other threads held, so the child must not
    /// allocate.
    fn apply_in_child(program: &BpfProgram) {
        if seccompiler::apply_filter(program).is_err() {
            // SAFETY: async-signal-safe, and distinguishable from the
            // exit codes the probes themselves use.
            unsafe { libc::_exit(9) };
        }
    }

    /// The point of the `log` default: a syscall that is not on the
    /// allowlist is recorded, and the process lives. If this ever
    /// starts failing, the default is no longer safe to ship.
    #[test]
    fn log_mode_does_not_kill_on_a_mismatch() {
        let program = build(Mode::Log).expect("build log filter");
        let status = in_child(|| {
            apply_in_child(&program);
            call_unlisted_syscall();
        });
        assert!(
            libc::WIFEXITED(status) && libc::WEXITSTATUS(status) == 0,
            "log mode must let a mismatched syscall through (status {status:#x})"
        );
    }

    /// And the other half of the claim: `enforce` really does act, so
    /// flipping the default is a real change and not a no-op.
    #[test]
    fn enforce_mode_kills_on_a_mismatch() {
        let program = build(Mode::Enforce).expect("build enforce filter");
        let status = in_child(|| {
            apply_in_child(&program);
            call_unlisted_syscall();
        });
        assert!(
            libc::WIFSIGNALED(status) && libc::WTERMSIG(status) == libc::SIGSYS,
            "enforce mode must kill on a mismatched syscall (status {status:#x})"
        );
    }

    /// The allowlist has to cover the daemon's own hot path *through a
    /// real filter*, not just by inspection: an `enforce` child that
    /// opens `/dev/kvm`, asks it for its API version and writes to a
    /// pipe survives only if `openat`, the KVM ioctl type byte and
    /// `write` are all allowed.
    #[test]
    fn enforce_mode_allows_the_kvm_ioctl_surface() {
        let program = build(Mode::Enforce).expect("build enforce filter");
        let status = in_child(|| {
            apply_in_child(&program);
            // SAFETY: open + KVM_GET_API_VERSION (`_IO(0xAE, 0x00)`) on
            // an fd we own, then close. Raw `syscall` rather than the
            // `ioctl` wrapper so the request type does not depend on
            // libc's `Ioctl` alias.
            unsafe {
                let fd = libc::open(
                    b"/dev/kvm\0".as_ptr().cast::<libc::c_char>(),
                    libc::O_RDWR | libc::O_CLOEXEC,
                );
                if fd < 0 {
                    libc::_exit(2);
                }
                if libc::syscall(libc::SYS_ioctl, fd, 0xAE00, 0) < 0 {
                    libc::_exit(3);
                }
                libc::close(fd);
            }
        });
        assert!(
            libc::WIFEXITED(status) && libc::WEXITSTATUS(status) == 0,
            "enforce mode broke the KVM path (status {status:#x})"
        );
    }

    /// A KVM ioctl matches the type-byte condition and, say, a socket
    /// ioctl from a different driver does not. FICLONE (disk `CoW`) is
    /// on the allowlist; RNDGETENTCNT is not.
    #[test]
    fn ioctl_type_mask_selects_the_vmm_drivers() {
        // KVM_RUN is _IO(0xAE, 0x80).
        let kvm_run: u64 = 0xAE80;
        assert_eq!(kvm_run & IOCTL_TYPE_MASK, 0xAE << 8);
        // FICLONE is _IOW(0x94, 9, int).
        let ficlone: u64 = 0x4004_9409;
        assert!(IOCTL_TYPES
            .iter()
            .any(|ty| ficlone & IOCTL_TYPE_MASK == ty << 8));
        // RNDGETENTCNT is _IOR('R', 0x00, int) — not a VMM or helper driver.
        let rnd: u64 = 0x8004_5200;
        assert!(!IOCTL_TYPES
            .iter()
            .any(|ty| rnd & IOCTL_TYPE_MASK == ty << 8));
    }
}
