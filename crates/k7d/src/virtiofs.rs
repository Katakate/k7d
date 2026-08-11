//! True virtiofs via virtiofsd + vhost-user protocol.
//!
//! Spawns `virtiofsd` as a child process, connects via vhost-user Unix socket,
//! and provides a `VirtioBackend` for the MMIO transport layer.

use std::io;
use std::os::unix::io::{AsRawFd, RawFd};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::process::{Child, Command};

use vm_memory::Address;
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

/// Manages a virtiofsd child process.
pub struct VirtiofsdProcess {
    child: Child,
    socket_path: PathBuf,
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
    /// Read-only enforcement for internal notes's `ConfigMap` / `Secret` /
    /// projected / `downwardAPI` shares lives **in-guest only** today:
    /// the agent issues `mount -t virtiofs -o ro <tag> <mount>` when
    /// it sees `:ro` in the `k7d.virtiofs=` cmdline param, and the
    /// VFS-level `MS_RDONLY` bounces any write attempt back with
    /// `EROFS` before it reaches virtiofsd.
    ///
    /// The host-side "belt-and-suspenders" `--readonly` flag does
    /// not exist in the rust-vmm virtiofsd we ship (≥1.7 removed
    /// it). When that flag becomes available again — or if we
    /// switch to a virtiofsd build that supports `--readonly` via
    /// some other knob (e.g. the legacy `-o ro` compat option) —
    /// this is the place to wire it up. We accept the `readonly`
    /// argument now so callers don't need to change later and so
    /// the host already records the intent in its logs.
    pub fn spawn_with_options(
        host_dir: &Path,
        socket_path: &Path,
        tag: &str,
        readonly: bool,
    ) -> Result<Self, String> {
        let mut cmd = Command::new(VIRTIOFSD_PATH);
        cmd.arg("--shared-dir")
            .arg(host_dir)
            .arg("--socket-path")
            .arg(socket_path)
            .arg("--tag")
            .arg(tag)
            .arg("--cache")
            .arg("never")
            .arg("--sandbox")
            .arg("none")
            // virtiofsd >= 1.13 defaults to --announce-submounts, which
            // makes every host mount point inside the share (e.g. the
            // per-volume bind mounts in the spec-10b volumes-rw scratch
            // tree) a separate FUSE submount in the guest. Each container
            // traversal then automounts its OWN superblock, so two
            // containers binding the same emptyDir get distinct inode
            // objects — files still flow, but unix-socket connect() across
            // containers fails with ECONNREFUSED (internal notes's CRI socket
            // over /cri). One superblock per share restores kubelet-like
            // emptyDir semantics.
            .arg("--no-announce-submounts");
        if readonly {
            log::debug!(
                "virtiofsd tag={tag}: caller requested readonly; \
                 enforcement is in-guest (mount -o ro) only on this virtiofsd version"
            );
        }
        let child = cmd
            .spawn()
            .map_err(|e| format!("failed to spawn virtiofsd: {e}"))?;

        // Wait for the socket to appear. internal notes: the
        // deadline lives in `crate::latency` (single source of truth)
        // and is generous because a multi-share pod spawns several
        // virtiofsd children sequentially and 5 s was too tight on a
        // busy node — see VIRTIOFSD_SOCKET_APPEAR.
        let wait = crate::latency::VIRTIOFSD_SOCKET_APPEAR;
        let deadline = std::time::Instant::now() + wait;
        while !socket_path.exists() {
            if std::time::Instant::now() >= deadline {
                return Err(format!(
                    "virtiofsd socket did not appear within {}s",
                    wait.as_secs()
                ));
            }
            std::thread::sleep(std::time::Duration::from_millis(50));
        }

        Ok(Self {
            child,
            socket_path: socket_path.to_path_buf(),
        })
    }
}

impl Drop for VirtiofsdProcess {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        let _ = std::fs::remove_file(&self.socket_path);
        // The per-VM socket dir (see vm.rs) empties out when the last
        // share's socket is removed; remove_dir refuses non-empty dirs
        // so sibling shares are unaffected.
        if let Some(dir) = self.socket_path.parent() {
            let _ = std::fs::remove_dir(dir);
        }
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
            if !q.ready || q.size == 0 {
                continue;
            }
            let i = idx as u32;
            let kick = EventFd::new(libc::EFD_NONBLOCK).map_err(|e| format!("eventfd: {e}"))?;

            client.set_vring_num(i, u32::from(q.size))?;
            client.set_vring_addr(
                i,
                q.desc_addr.raw_value(),
                q.used_addr.raw_value(),
                q.avail_addr.raw_value(),
                self.mem_host_addr,
            )?;
            // Resume reading the avail ring where the old daemon's
            // completions stopped (used ring layout: flags u16, idx u16).
            let used_idx_addr = (guest_mem_host_addr + q.used_addr.raw_value() + 2) as *const u16;
            // SAFETY: used_idx_addr points into the fork's guest memory
            // mapping, which the caller owns and which outlives this call.
            let used_idx = unsafe { std::ptr::read_volatile(used_idx_addr) };
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
            if !q.ready || q.size == 0 {
                continue;
            }
            let i = idx as u32;

            let kick = EventFd::new(libc::EFD_NONBLOCK).map_err(|e| format!("eventfd: {e}"))?;

            client.set_vring_num(i, q.size as u32)?;
            client.set_vring_addr(
                i,
                q.desc_addr.raw_value(),
                q.used_addr.raw_value(),
                q.avail_addr.raw_value(),
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
