//! True virtiofs via virtiofsd + vhost-user protocol.
//!
//! Spawns `virtiofsd` as a child process, connects via vhost-user Unix socket,
//! and provides a `VirtioBackend` for the MMIO transport layer.

use std::io;
use std::os::unix::io::{AsRawFd, RawFd};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};

use vmm_sys_util::eventfd::EventFd;

use crate::virtio_mmio::{VirtioBackend, VirtqueueState};

const VIRTIO_ID_FS: u32 = 26;
const FS_NUM_QUEUES: usize = 2; // hiprio + request
const FS_QUEUE_SIZE: u16 = 1024;

// vhost-user message types (subset needed for virtiofs)
const VHOST_USER_SET_OWNER: u32 = 3;
const VHOST_USER_GET_FEATURES: u32 = 1;
const VHOST_USER_SET_FEATURES: u32 = 2;
const VHOST_USER_GET_PROTOCOL_FEATURES: u32 = 15;
const VHOST_USER_SET_PROTOCOL_FEATURES: u32 = 16;
const VHOST_USER_SET_MEM_TABLE: u32 = 5;
const VHOST_USER_SET_VRING_NUM: u32 = 8;
const VHOST_USER_SET_VRING_ADDR: u32 = 9;
const VHOST_USER_SET_VRING_BASE: u32 = 10;
const VHOST_USER_SET_VRING_KICK: u32 = 12;
const VHOST_USER_SET_VRING_CALL: u32 = 13;
const VHOST_USER_SET_VRING_ENABLE: u32 = 18;

const VHOST_USER_FLAG_VERSION: u32 = 0x1;
const VHOST_USER_FLAG_REPLY_MASK: u32 = 0x4;
const VHOST_USER_F_PROTOCOL_FEATURES: u64 = 1 << 30;

const VIRTIOFSD_PATH: &str = "/usr/libexec/virtiofsd";

/// Sandbox mode virtiofsd is spawned with when `K7D_VIRTIOFSD_SANDBOX`
/// is unset.
///
/// `chroot`, not virtiofsd's own `namespace` default: the namespace
/// sandbox unshares a mount namespace, and k7d bind-mounts per-volume
/// directories into the shared tree *after* virtiofsd is running
/// (`volumes.rs`). Those mounts do not propagate into a private mount
/// namespace, so the guest would see empty volume dirs. A chroot gives
/// the same "cannot name a path outside the share" property while
/// staying in the host mount namespace.
const DEFAULT_SANDBOX: &str = "chroot";

/// Resolve the virtiofsd sandbox mode. An unrecognised value is a loud
/// error: silently falling back to `none` would unjail every share.
fn sandbox_mode() -> Result<String, String> {
    let mode = match std::env::var("K7D_VIRTIOFSD_SANDBOX") {
        Ok(v) if !v.trim().is_empty() => v.trim().to_string(),
        _ => DEFAULT_SANDBOX.to_string(),
    };
    match mode.as_str() {
        "chroot" | "namespace" | "none" => Ok(mode),
        other => Err(format!(
            "K7D_VIRTIOFSD_SANDBOX={other:?} is not one of chroot|namespace|none"
        )),
    }
}

/// Exec `virtiofsd` on a listener the VM broker bound, sharing the
/// directory the node broker pinned at `vm.register`.
///
/// Node-broker side of [`crate::broker::Verb::VirtiofsdSpawn`]. Both
/// descriptors are placed by number rather than by path: `--fd 3` is the
/// listener, and `--shared-dir /proc/self/fd/4` reaches the share
/// through the `O_PATH` pin, so the directory virtiofsd chroots into is
/// the inode `openat2` validated and not whatever the string resolves to
/// now.
///
/// The two descriptors go through [`crate::spawner::Command::fd`], which
/// exists for this one call site: every other helper in the daemon is
/// handed stdio and nothing else. Routing it through the spawner rather
/// than `std::process::Command` keeps `execve` in the one module that is
/// allowed to have it — the node broker could exec directly, but then
/// `only_spawner_execs` would have to grow an exception, and the next
/// caller would inherit it.
pub(crate) fn spawn_jailed(
    listener: &std::os::fd::OwnedFd,
    share: &std::os::fd::OwnedFd,
    tag: &str,
) -> io::Result<crate::spawner::Child> {
    let mut cmd = crate::spawner::command(VIRTIOFSD_PATH);
    cmd.args(["--fd", "3", "--shared-dir", "/proc/self/fd/4"])
        .args(["--tag", tag])
        .args(["--cache", "never"])
        .args(["--sandbox", &sandbox_mode().map_err(io::Error::other)?])
        .args(["--seccomp", "kill"])
        .arg("--no-announce-submounts")
        .fd(3, listener.try_clone()?)
        .fd(4, share.try_clone()?);
    cmd.spawn()
}

/// Who started the helper, which decides who may stop it.
enum Helper {
    /// This process did, through the pre-seccomp helper spawner.
    Own(crate::spawner::Child),
    /// The node broker did, on a listener this process bound
    /// (`virtiofsd.spawn`). The pidfd is for polling only —
    /// the child is root's and a uid-`k7d` process has no `CAP_KILL`
    /// over it, so stopping it is [`crate::broker::Verb::HelperReap`].
    Brokered {
        pid: u32,
        _pidfd: std::os::fd::OwnedFd,
    },
}

/// Manages a virtiofsd child process.
pub struct VirtiofsdProcess {
    child: Helper,
    socket_path: PathBuf,
    /// Share root we bind-mounted read-only before spawn (`readonly:
    /// true`). Umounted in [`Drop`] after the child is killed.
    ro_bind: Option<PathBuf>,
    /// The registered `(vm_id, share_idx)` whose `share.remount_ro` this
    /// process owes a `share.umount`. `Some` only under privilege
    /// separation, where both halves of that pair are the node
    /// broker's.
    ro_share: Option<(String, u16)>,
}

impl VirtiofsdProcess {
    /// Spawn virtiofsd sharing `host_dir` via a vhost-user socket at
    /// `socket_path`. Read-write share — equivalent to
    /// [`Self::spawn_with_options(.., .., .., false)`](Self::spawn_with_options).
    pub fn spawn(host_dir: &Path, socket_path: &Path, tag: &str) -> Result<Self, String> {
        Self::spawn_with_options(host_dir, socket_path, tag, false)
    }

    /// Spawn virtiofsd with explicit `readonly` flag.
    ///
    /// Read-only enforcement for `ConfigMap` / `Secret` /
    /// projected / `downwardAPI` shares lives **in-guest only** today:
    /// the agent issues `mount -t virtiofs -o ro <tag> <mount>` when
    /// it sees `:ro` in the `k7d.virtiofs=` cmdline param, and the
    /// VFS-level `MS_RDONLY` bounces any write attempt back with
    /// `EROFS` before it reaches virtiofsd.
    ///
    /// Host-side RO is enforced by bind-mounting the share root onto
    /// itself and remounting it `MS_RDONLY` *before* virtiofsd
    /// chroots into it. The shipped virtiofsd has no
    /// `--readonly` flag (≥1.7 removed it); the VFS-level remount is
    /// what makes a compromised guest agent hit `EROFS` instead of
    /// writing through. The in-guest `mount -o ro` stays as well.
    pub fn spawn_with_options(
        host_dir: &Path,
        socket_path: &Path,
        tag: &str,
        readonly: bool,
    ) -> Result<Self, String> {
        if crate::broker::client::is_split() {
            return Self::spawn_brokered(host_dir, socket_path, tag, readonly);
        }
        let mut cmd = crate::spawner::command(VIRTIOFSD_PATH);
        cmd.arg("--shared-dir")
            .arg(host_dir)
            .arg("--socket-path")
            .arg(socket_path)
            .arg("--tag")
            .arg(tag)
            .arg("--cache")
            .arg("never")
            // The share is parsed by guest-controlled
            // FUSE traffic, so the daemon that serves it is jailed. The
            // seccomp action is spelled out next to the sandbox mode —
            // they are one decision, and a future virtiofsd default
            // change must not silently unjail us.
            .arg("--sandbox")
            .arg(sandbox_mode()?)
            .arg("--seccomp")
            .arg("kill")
            // virtiofsd >= 1.13 defaults to --announce-submounts, which
            // makes every host mount point inside the share (e.g. the
            // per-volume bind mounts in the volumes-rw scratch
            // tree) a separate FUSE submount in the guest. Each container
            // traversal then automounts its OWN superblock, so two
            // containers binding the same emptyDir get distinct inode
            // objects — files still flow, but unix-socket connect() across
            // containers fails with ECONNREFUSED (the CRI socket
            // over /cri). One superblock per share restores kubelet-like
            // emptyDir semantics.
            .arg("--no-announce-submounts");
        let ro_bind = if readonly {
            let created = crate::volumes::remount_share_readonly(host_dir).map_err(|e| {
                format!(
                    "host RO remount of virtiofs share {}: {e}",
                    host_dir.display()
                )
            })?;
            if created {
                log::info!(
                    "virtiofsd tag={tag}: share {} remounted MS_RDONLY on the host",
                    host_dir.display()
                );
                Some(host_dir.to_path_buf())
            } else {
                log::debug!(
                    "virtiofsd tag={tag}: share {} already MS_RDONLY; not stacking a bind",
                    host_dir.display()
                );
                None
            }
        } else {
            None
        };
        let mut child = match cmd.spawn() {
            Ok(c) => c,
            Err(e) => {
                if let Some(ref p) = ro_bind {
                    let _ = crate::volumes::umount_path(p);
                }
                return Err(format!("failed to spawn virtiofsd: {e}"));
            }
        };

        // Wait for the socket to appear. The
        // deadline lives in `crate::latency` (single source of truth)
        // and is generous because a multi-share pod spawns several
        // virtiofsd children sequentially and 5 s was too tight on a
        // busy node — see VIRTIOFSD_SOCKET_APPEAR.
        let wait = crate::latency::VIRTIOFSD_SOCKET_APPEAR;
        let deadline = std::time::Instant::now() + wait;
        while !socket_path.exists() {
            if std::time::Instant::now() >= deadline {
                let _ = child.kill();
                let _ = child.wait();
                if let Some(ref p) = ro_bind {
                    let _ = crate::volumes::umount_path(p);
                }
                return Err(format!(
                    "virtiofsd socket did not appear within {}s",
                    wait.as_secs()
                ));
            }
            std::thread::sleep(std::time::Duration::from_millis(50));
        }

        Ok(Self {
            child: Helper::Own(child),
            socket_path: socket_path.to_path_buf(),
            ro_bind,
            ro_share: None,
        })
    }

    /// [`Self::spawn_with_options`] under privilege separation.
    ///
    /// The listener goes the other way from every other descriptor in
    /// the split: this process `bind`s and `listen`s in a
    /// directory it owns and hands the *listening* socket to the node
    /// broker, which maps it to fd 3 and passes `--fd 3`. That removes
    /// both halves of the old arrangement's privilege — virtiofsd never
    /// creates a socket in a directory root chose, and this process
    /// never needs the share's path to be resolvable by anyone but the
    /// node broker, which reaches it through the pin `vm.register`
    /// made.
    ///
    /// It also removes the poll: `--socket-path` meant waiting for the
    /// file to appear before connecting, and a socket that is already
    /// listening accepts a `connect` into its backlog immediately.
    fn spawn_brokered(
        host_dir: &Path,
        socket_path: &Path,
        tag: &str,
        readonly: bool,
    ) -> Result<Self, String> {
        use crate::broker::client::{self, Pin};
        let Some((vm_id, share_idx)) = client::pinned_as(Pin::Share, host_dir) else {
            return Err(format!(
                "virtiofs share {} was never registered with the node broker — \
                 vm.register is what validates and pins a host path, and a share that \
                 skipped it has no pin to serve from",
                host_dir.display()
            ));
        };
        let ro_share = if readonly {
            client::ok(&crate::broker::Verb::ShareRemountRo {
                vm_id: vm_id.clone(),
                share_idx,
            })
            .map_err(|e| {
                format!(
                    "host RO remount of virtiofs share {}: {e}",
                    host_dir.display()
                )
            })?;
            Some((vm_id.clone(), share_idx))
        } else {
            None
        };
        let undo_ro = |ro_share: &Option<(String, u16)>| {
            if let Some((vm_id, share_idx)) = ro_share {
                let _ = client::ok(&crate::broker::Verb::ShareUmount {
                    vm_id: vm_id.clone(),
                    share_idx: *share_idx,
                });
            }
        };
        let listener = match std::os::unix::net::UnixListener::bind(socket_path) {
            Ok(l) => l,
            Err(e) => {
                undo_ro(&ro_share);
                return Err(format!(
                    "bind the vhost-user listener {}: {e}",
                    socket_path.display()
                ));
            }
        };
        let spawned = client::virtiofsd_spawn(
            &vm_id,
            share_idx,
            tag,
            None,
            std::os::unix::io::AsRawFd::as_raw_fd(&listener),
        );
        // The node broker holds the only copy virtiofsd needs; keeping
        // this one open would leave a second listener on the socket that
        // never accepts.
        drop(listener);
        let (pid, pidfd) = match spawned {
            Ok(v) => v,
            Err(e) => {
                undo_ro(&ro_share);
                let _ = std::fs::remove_file(socket_path);
                return Err(format!("spawn virtiofsd (tag={tag}): {e}"));
            }
        };
        Ok(Self {
            child: Helper::Brokered { pid, _pidfd: pidfd },
            socket_path: socket_path.to_path_buf(),
            ro_bind: None,
            ro_share,
        })
    }

    /// PID of the virtiofsd child, so a tree can put its helpers in the
    /// tree's cgroup jail.
    #[must_use]
    pub fn pid(&self) -> u32 {
        match &self.child {
            Helper::Own(child) => child.id(),
            Helper::Brokered { pid, .. } => *pid,
        }
    }
}

impl Drop for VirtiofsdProcess {
    fn drop(&mut self) {
        match &mut self.child {
            Helper::Own(child) => {
                let _ = child.kill();
                let _ = child.wait();
            }
            Helper::Brokered { pid, .. } => {
                if let Err(e) =
                    crate::broker::client::ok(&crate::broker::Verb::HelperReap { pid: *pid })
                {
                    log::warn!("helper.reap({pid}) for virtiofsd: {e}");
                }
            }
        }
        if let Some((vm_id, share_idx)) = self.ro_share.take() {
            if let Err(e) = crate::broker::client::ok(&crate::broker::Verb::ShareUmount {
                vm_id: vm_id.clone(),
                share_idx,
            }) {
                log::warn!("share.umount({vm_id}[{share_idx}]): {e}");
            }
        }
        if let Some(ref path) = self.ro_bind {
            if let Err(e) = crate::volumes::umount_path(path) {
                log::warn!(
                    "virtiofsd drop: umount RO share {} failed: {e}",
                    path.display()
                );
            }
        }
        let _ = std::fs::remove_file(&self.socket_path);
        // The per-VM socket dir (see vm.rs) empties out when the last
        // share's socket is removed; remove_dir refuses non-empty dirs
        // so sibling shares are unaffected.
        if let Some(dir) = self.socket_path.parent() {
            let _ = std::fs::remove_dir(dir);
        }
    }
}

#[cfg(test)]
mod sandbox_mode_tests {
    use super::{sandbox_mode, DEFAULT_SANDBOX};

    fn with_env<T>(val: Option<&str>, f: impl FnOnce() -> T) -> T {
        let key = "K7D_VIRTIOFSD_SANDBOX";
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

    #[test]
    fn defaults_to_chroot_and_rejects_unknown_modes() {
        with_env(None, || {
            assert_eq!(sandbox_mode().unwrap(), DEFAULT_SANDBOX);
        });
        with_env(Some("none"), || {
            assert_eq!(sandbox_mode().unwrap(), "none");
        });
        with_env(Some("wide-open"), || {
            assert!(sandbox_mode().is_err(), "unknown mode must fail loudly");
        });
    }
}

/// Minimal vhost-user frontend (client) that talks to virtiofsd.
struct VhostUserClient {
    stream: UnixStream,
}

/// Vhost-user message header (12 bytes, little-endian on the wire).
#[repr(C)]
#[derive(Clone, Copy, Default)]
struct VhostUserMsgHeader {
    request: u32,
    flags: u32,
    size: u32,
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
struct VhostUserVringState {
    index: u32,
    num: u32,
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
struct VhostUserVringAddr {
    index: u32,
    flags: u32,
    desc_user_addr: u64,
    used_user_addr: u64,
    avail_user_addr: u64,
    log_guest_addr: u64,
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
struct VhostUserMemRegion {
    guest_phys_addr: u64,
    memory_size: u64,
    userspace_addr: u64,
    mmap_offset: u64,
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
struct VhostUserMemory {
    num_regions: u32,
    padding: u32,
}

impl VhostUserClient {
    fn connect(socket_path: &Path) -> Result<Self, String> {
        let stream = UnixStream::connect(socket_path)
            .map_err(|e| format!("vhost-user connect {}: {e}", socket_path.display()))?;
        Ok(Self { stream })
    }

    fn send_msg(&self, request: u32, payload: &[u8]) -> Result<(), String> {
        let hdr = VhostUserMsgHeader {
            request,
            flags: VHOST_USER_FLAG_VERSION,
            size: payload.len() as u32,
        };
        // SAFETY: hdr is a valid repr(C) struct; pointer and length match its size.
        let hdr_bytes = unsafe {
            std::slice::from_raw_parts(
                (&raw const hdr).cast::<u8>(),
                std::mem::size_of::<VhostUserMsgHeader>(),
            )
        };

        let mut iov = [
            libc::iovec {
                iov_base: hdr_bytes.as_ptr() as *mut libc::c_void,
                iov_len: hdr_bytes.len(),
            },
            libc::iovec {
                iov_base: if payload.is_empty() {
                    std::ptr::null_mut()
                } else {
                    payload.as_ptr() as *mut libc::c_void
                },
                iov_len: payload.len(),
            },
        ];

        let msghdr = libc::msghdr {
            msg_name: std::ptr::null_mut(),
            msg_namelen: 0,
            msg_iov: iov.as_mut_ptr(),
            msg_iovlen: if payload.is_empty() { 1 } else { 2 },
            msg_control: std::ptr::null_mut(),
            msg_controllen: 0,
            msg_flags: 0,
        };

        // SAFETY: msghdr and iov are properly initialized, stream fd is valid.
        let ret = unsafe { libc::sendmsg(self.stream.as_raw_fd(), &msghdr, 0) };
        if ret < 0 {
            return Err(format!(
                "sendmsg (req {request}): {}",
                io::Error::last_os_error()
            ));
        }
        Ok(())
    }

    fn send_msg_with_fds(&self, request: u32, payload: &[u8], fds: &[RawFd]) -> Result<(), String> {
        let hdr = VhostUserMsgHeader {
            request,
            flags: VHOST_USER_FLAG_VERSION,
            size: payload.len() as u32,
        };
        // SAFETY: hdr is a valid repr(C) struct; pointer and length match.
        let hdr_bytes = unsafe {
            std::slice::from_raw_parts(
                (&raw const hdr).cast::<u8>(),
                std::mem::size_of::<VhostUserMsgHeader>(),
            )
        };

        // SAFETY: CMSG_SPACE computes the byte length needed for the control message.
        let cmsg_space = unsafe { libc::CMSG_SPACE(std::mem::size_of_val(fds) as u32) } as usize;
        let mut cmsg_buf = vec![0u8; cmsg_space];

        let mut iov = [
            libc::iovec {
                iov_base: hdr_bytes.as_ptr() as *mut libc::c_void,
                iov_len: hdr_bytes.len(),
            },
            libc::iovec {
                iov_base: payload.as_ptr() as *mut libc::c_void,
                iov_len: payload.len(),
            },
        ];

        let mut msghdr = libc::msghdr {
            msg_name: std::ptr::null_mut(),
            msg_namelen: 0,
            msg_iov: iov.as_mut_ptr(),
            msg_iovlen: 2,
            msg_control: cmsg_buf.as_mut_ptr().cast(),
            msg_controllen: cmsg_space,
            msg_flags: 0,
        };

        // SAFETY: cmsg_buf is large enough for CMSG_SPACE; msghdr is properly set up.
        unsafe {
            let cmsg = libc::CMSG_FIRSTHDR(&msghdr);
            (*cmsg).cmsg_level = libc::SOL_SOCKET;
            (*cmsg).cmsg_type = libc::SCM_RIGHTS;
            (*cmsg).cmsg_len = libc::CMSG_LEN(std::mem::size_of_val(fds) as u32) as usize;
            std::ptr::copy_nonoverlapping(
                fds.as_ptr().cast::<u8>(),
                libc::CMSG_DATA(cmsg),
                std::mem::size_of_val(fds),
            );
        }

        // Recalculate controllen to actual cmsg length
        msghdr.msg_controllen = cmsg_space;

        // SAFETY: msghdr, iov, cmsg_buf are all properly initialized.
        let ret = unsafe { libc::sendmsg(self.stream.as_raw_fd(), &msghdr, 0) };
        if ret < 0 {
            return Err(format!(
                "sendmsg with fds (req {request}): {}",
                io::Error::last_os_error()
            ));
        }
        Ok(())
    }

    fn recv_reply(&self) -> Result<(VhostUserMsgHeader, Vec<u8>), String> {
        let mut hdr = VhostUserMsgHeader::default();
        let hdr_size = std::mem::size_of::<VhostUserMsgHeader>();
        // SAFETY: hdr is valid, reading exactly hdr_size bytes into it.
        let ret = unsafe {
            libc::recv(
                self.stream.as_raw_fd(),
                (&raw mut hdr).cast(),
                hdr_size,
                libc::MSG_WAITALL,
            )
        };
        #[allow(clippy::cast_possible_wrap)]
        if ret != hdr_size as isize {
            return Err(format!("recv header: got {ret} bytes, expected {hdr_size}"));
        }

        let payload_size = hdr.size as usize;
        let mut payload = vec![0u8; payload_size];
        if payload_size > 0 {
            // SAFETY: payload is properly allocated, reading exactly payload_size bytes.
            let ret = unsafe {
                libc::recv(
                    self.stream.as_raw_fd(),
                    payload.as_mut_ptr().cast(),
                    payload_size,
                    libc::MSG_WAITALL,
                )
            };
            #[allow(clippy::cast_possible_wrap)]
            if ret != payload_size as isize {
                return Err(format!(
                    "recv payload: got {ret} bytes, expected {payload_size}"
                ));
            }
        }

        Ok((hdr, payload))
    }

    fn set_owner(&self) -> Result<(), String> {
        self.send_msg(VHOST_USER_SET_OWNER, &[])
    }

    fn get_features(&self) -> Result<u64, String> {
        self.send_msg(VHOST_USER_GET_FEATURES, &[])?;
        let (hdr, payload) = self.recv_reply()?;
        if hdr.flags & VHOST_USER_FLAG_REPLY_MASK == 0 {
            return Err("GET_FEATURES: no reply flag".to_string());
        }
        if payload.len() < 8 {
            return Err(format!("GET_FEATURES: short payload ({})", payload.len()));
        }
        Ok(u64::from_le_bytes(payload[..8].try_into().unwrap()))
    }

    fn set_features(&self, features: u64) -> Result<(), String> {
        self.send_msg(VHOST_USER_SET_FEATURES, &features.to_le_bytes())
    }

    fn get_protocol_features(&self) -> Result<u64, String> {
        self.send_msg(VHOST_USER_GET_PROTOCOL_FEATURES, &[])?;
        let (hdr, payload) = self.recv_reply()?;
        if hdr.flags & VHOST_USER_FLAG_REPLY_MASK == 0 {
            return Err("GET_PROTOCOL_FEATURES: no reply flag".to_string());
        }
        if payload.len() < 8 {
            return Err(format!(
                "GET_PROTOCOL_FEATURES: short payload ({})",
                payload.len()
            ));
        }
        Ok(u64::from_le_bytes(payload[..8].try_into().unwrap()))
    }

    fn set_protocol_features(&self, features: u64) -> Result<(), String> {
        self.send_msg(VHOST_USER_SET_PROTOCOL_FEATURES, &features.to_le_bytes())
    }

    fn set_mem_table(
        &self,
        guest_phys_addr: u64,
        memory_size: u64,
        userspace_addr: u64,
        mem_fd: RawFd,
    ) -> Result<(), String> {
        let mem_hdr = VhostUserMemory {
            num_regions: 1,
            padding: 0,
        };
        let region = VhostUserMemRegion {
            guest_phys_addr,
            memory_size,
            userspace_addr,
            mmap_offset: 0,
        };

        let mut payload = Vec::new();
        // SAFETY: mem_hdr and region are repr(C); appending their raw bytes.
        unsafe {
            payload.extend_from_slice(std::slice::from_raw_parts(
                (&raw const mem_hdr).cast::<u8>(),
                std::mem::size_of::<VhostUserMemory>(),
            ));
            payload.extend_from_slice(std::slice::from_raw_parts(
                (&raw const region).cast::<u8>(),
                std::mem::size_of::<VhostUserMemRegion>(),
            ));
        }

        self.send_msg_with_fds(VHOST_USER_SET_MEM_TABLE, &payload, &[mem_fd])
    }

    fn set_vring_num(&self, index: u32, num: u32) -> Result<(), String> {
        let state = VhostUserVringState { index, num };
        // SAFETY: state is repr(C); converting to bytes.
        let bytes = unsafe {
            std::slice::from_raw_parts(
                (&raw const state).cast::<u8>(),
                std::mem::size_of::<VhostUserVringState>(),
            )
        };
        self.send_msg(VHOST_USER_SET_VRING_NUM, bytes)
    }

    fn set_vring_addr(
        &self,
        index: u32,
        desc_addr: u64,
        used_addr: u64,
        avail_addr: u64,
        mem_host_addr: u64,
    ) -> Result<(), String> {
        let addr = VhostUserVringAddr {
            index,
            flags: 0,
            desc_user_addr: mem_host_addr + desc_addr,
            used_user_addr: mem_host_addr + used_addr,
            avail_user_addr: mem_host_addr + avail_addr,
            log_guest_addr: 0,
        };
        // SAFETY: addr is repr(C); converting to bytes.
        let bytes = unsafe {
            std::slice::from_raw_parts(
                (&raw const addr).cast::<u8>(),
                std::mem::size_of::<VhostUserVringAddr>(),
            )
        };
        self.send_msg(VHOST_USER_SET_VRING_ADDR, bytes)
    }

    fn set_vring_base(&self, index: u32, base: u32) -> Result<(), String> {
        let state = VhostUserVringState { index, num: base };
        // SAFETY: state is repr(C); converting to bytes.
        let bytes = unsafe {
            std::slice::from_raw_parts(
                (&raw const state).cast::<u8>(),
                std::mem::size_of::<VhostUserVringState>(),
            )
        };
        self.send_msg(VHOST_USER_SET_VRING_BASE, bytes)
    }

    fn set_vring_kick(&self, index: u32, fd: RawFd) -> Result<(), String> {
        let val: u64 = u64::from(index);
        self.send_msg_with_fds(VHOST_USER_SET_VRING_KICK, &val.to_le_bytes(), &[fd])
    }

    fn set_vring_call(&self, index: u32, fd: RawFd) -> Result<(), String> {
        let val: u64 = u64::from(index);
        self.send_msg_with_fds(VHOST_USER_SET_VRING_CALL, &val.to_le_bytes(), &[fd])
    }

    fn set_vring_enable(&self, index: u32, enable: bool) -> Result<(), String> {
        let state = VhostUserVringState {
            index,
            num: u32::from(enable),
        };
        // SAFETY: state is repr(C); converting to bytes.
        let bytes = unsafe {
            std::slice::from_raw_parts(
                (&raw const state).cast::<u8>(),
                std::mem::size_of::<VhostUserVringState>(),
            )
        };
        self.send_msg(VHOST_USER_SET_VRING_ENABLE, bytes)
    }
}

/// Config space for virtio-fs: just the tag (36 bytes) + `num_request_queues` (u32).
#[repr(C)]
struct VirtioFsConfig {
    tag: [u8; 36],
    num_request_queues: u32,
}

/// Virtio-fs backend for the MMIO transport, connected to virtiofsd via vhost-user.
pub struct VirtioFsBackend {
    tag: String,
    mem_host_addr: u64,
    mem_size: u64,
    mem_fd: RawFd,
    vhost_features: u64,
    acked_features: u64,
    kick_evts: Vec<EventFd>,
    /// Kept alive so virtiofsd doesn't shut down.
    client: VhostUserClient,
}

impl VirtioFsBackend {
    /// Create a new virtio-fs backend. Connects to virtiofsd via the vhost-user socket
    /// and negotiates features. The connection is kept alive for the lifetime of this object.
    pub fn new(
        socket_path: &Path,
        tag: &str,
        mem_host_addr: u64,
        mem_size: u64,
        mem_fd: RawFd,
    ) -> Result<Self, String> {
        let client = VhostUserClient::connect(socket_path)?;
        client.set_owner()?;
        let features = client.get_features()?;
        log::info!("virtiofs vhost-user features: {features:#x}");

        if features & VHOST_USER_F_PROTOCOL_FEATURES != 0 {
            let proto_features = client.get_protocol_features()?;
            log::info!("virtiofs protocol features: {proto_features:#x}");
            client.set_protocol_features(proto_features)?;
        }

        Ok(Self {
            tag: tag.to_string(),
            mem_host_addr,
            mem_size,
            mem_fd,
            vhost_features: features,
            acked_features: 0,
            kick_evts: Vec::new(),
            client,
        })
    }
}

impl VirtioFsBackend {
    /// Validate one queue's geometry against a guest mapping before its
    /// addresses are handed to the vhost-user daemon, which DMAs into
    /// them (`docs/bug-candidates.md` #44's class, one process further
    /// out).
    fn validated(
        &self,
        q: &VirtqueueState,
        index: usize,
        mem_base: u64,
    ) -> Result<crate::virtio_mmio::ValidatedQueue, String> {
        crate::virtio_mmio::ValidatedQueue::new(q, mem_base, self.mem_size)
            .map_err(|e| format!("virtiofs queue {index} geometry: {e}"))
    }

    /// Restore-time activation: like [`VirtioBackend::activate`], but the
    /// guest driver finished feature negotiation and queue setup long ago
    /// (the memory image was forked from a running VM), so each vring
    /// base is seeded from the guest used ring's `idx` instead of 0.
    /// Requests the guest published but the *old* virtiofsd never
    /// answered (entries between `used.idx` and `avail.idx`) are then
    /// replayed against the fresh daemon.
    ///
    /// `guest_mem_host_addr` must be the fork's own mapping — reading the
    /// ring state from the source would race its still-running guest.
    pub fn activate_with_bases(
        &mut self,
        queues: &[VirtqueueState],
        irq_evt: &EventFd,
        guest_mem_host_addr: u64,
    ) -> Result<(), String> {
        let client = &self.client;
        let features = self.acked_features | (self.vhost_features & VHOST_USER_F_PROTOCOL_FEATURES);
        client.set_features(features)?;
        client.set_mem_table(0, self.mem_size, self.mem_host_addr, self.mem_fd)?;

        let mut kick_evts = Vec::new();
        for (idx, q) in queues.iter().enumerate() {
            if !q.ready {
                continue;
            }
            let i = idx as u32;
            let vq = self.validated(q, idx, self.mem_host_addr)?;
            // The rings are programmed against this device's own mapping,
            // but `used.idx` is read out of the fork's `MAP_PRIVATE` view.
            let read_vq = self.validated(q, idx, guest_mem_host_addr)?;
            let kick = crate::fdutil::eventfd_cloexec(libc::EFD_NONBLOCK)
                .map_err(|e| format!("eventfd: {e}"))?;

            client.set_vring_num(i, u32::from(vq.size()))?;
            client.set_vring_addr(
                i,
                vq.desc_ring().0,
                vq.used_ring_span().0,
                vq.avail_ring_span().0,
                self.mem_host_addr,
            )?;
            // Resume reading the avail ring where the old daemon's
            // completions stopped (used ring layout: flags u16, idx u16).
            // SAFETY: `used_idx` is the idx field of a ring this geometry
            // placed inside the fork's guest memory mapping, which the
            // caller owns and which outlives this call.
            let used_idx = unsafe { std::ptr::read_volatile(read_vq.used_idx().cast_const()) };
            client.set_vring_base(i, u32::from(used_idx))?;
            client.set_vring_call(i, irq_evt.as_raw_fd())?;
            client.set_vring_kick(i, kick.as_raw_fd())?;
            client.set_vring_enable(i, true)?;

            // Nudge the fresh daemon once: pending avail entries exist
            // only in guest memory; nothing else will kick for them.
            let _ = kick.write(1);
            kick_evts.push(kick);
        }

        log::info!(
            "virtiofs vhost-user restored+activated (tag={}, {} queues)",
            self.tag,
            kick_evts.len()
        );
        self.kick_evts = kick_evts;
        Ok(())
    }
}

impl VirtioBackend for VirtioFsBackend {
    fn device_type(&self) -> u32 {
        VIRTIO_ID_FS
    }

    fn device_features(&self) -> u64 {
        self.vhost_features
    }

    fn ack_features(&mut self, features: u64) {
        self.acked_features = features;
    }

    fn num_queues(&self) -> usize {
        FS_NUM_QUEUES
    }

    fn max_queue_size(&self) -> u16 {
        FS_QUEUE_SIZE
    }

    fn guest_mapping(&self) -> (u64, u64) {
        (self.mem_host_addr, self.mem_size)
    }

    fn read_config(&self, offset: u64, data: &mut [u8]) {
        let mut config = VirtioFsConfig {
            tag: [0u8; 36],
            num_request_queues: 1,
        };
        let tag_bytes = self.tag.as_bytes();
        let copy_len = tag_bytes.len().min(36);
        config.tag[..copy_len].copy_from_slice(&tag_bytes[..copy_len]);

        // SAFETY: config is repr(C) and 40 bytes; pointer and length are valid.
        let config_bytes = unsafe {
            std::slice::from_raw_parts(
                (&raw const config).cast::<u8>(),
                std::mem::size_of::<VirtioFsConfig>(),
            )
        };
        let start = offset as usize;
        let end = (start + data.len()).min(config_bytes.len());
        if start < config_bytes.len() {
            let len = end - start;
            data[..len].copy_from_slice(&config_bytes[start..end]);
        }
    }

    fn write_config(&mut self, _offset: u64, _data: &[u8]) {}

    fn queue_notify(&self, queue_index: u32) {
        if let Some(kick) = self.kick_evts.get(queue_index as usize) {
            let _ = kick.write(1);
        }
    }

    fn activate(&mut self, queues: &[VirtqueueState], irq_evt: &EventFd) -> Result<(), String> {
        let client = &self.client;

        // Include PROTOCOL_FEATURES bit since we negotiated protocol features
        let features = self.acked_features | (self.vhost_features & VHOST_USER_F_PROTOCOL_FEATURES);
        client.set_features(features)?;

        client.set_mem_table(0, self.mem_size, self.mem_host_addr, self.mem_fd)?;

        let mut kick_evts = Vec::new();
        for (idx, q) in queues.iter().enumerate() {
            if !q.ready {
                continue;
            }
            let i = idx as u32;
            let vq = self.validated(q, idx, self.mem_host_addr)?;

            let kick = crate::fdutil::eventfd_cloexec(libc::EFD_NONBLOCK)
                .map_err(|e| format!("eventfd: {e}"))?;

            client.set_vring_num(i, u32::from(vq.size()))?;
            client.set_vring_addr(
                i,
                vq.desc_ring().0,
                vq.used_ring_span().0,
                vq.avail_ring_span().0,
                self.mem_host_addr,
            )?;
            client.set_vring_base(i, 0)?;
            client.set_vring_call(i, irq_evt.as_raw_fd())?;
            client.set_vring_kick(i, kick.as_raw_fd())?;
            client.set_vring_enable(i, true)?;

            kick_evts.push(kick);
        }

        log::info!("virtiofs vhost-user activated (tag={})", self.tag);
        self.kick_evts = kick_evts;

        Ok(())
    }
}
