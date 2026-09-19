//! One datagram plus descriptors over a `SOCK_SEQPACKET` socketpair.
//!
//! Framing is the kernel's: a `SOCK_SEQPACKET` read returns exactly one
//! datagram or nothing, so a half-parsed message is impossible by
//! construction and a truncated one is reported (`MSG_TRUNC`) rather
//! than silently shortened. The pre-seccomp helper spawner established
//! this shape ([`crate::spawner`]); privilege separation reuses it
//! verbatim for every node-broker channel ([`crate::broker`]), which is why the
//! plumbing lives here instead of in either of them.
//!
//! The spawner keeps its own copy of `send_msg`/`recv_msg` with a
//! three-descriptor `CmsgBuf`: it is forked before the broker exists and
//! its filter is a different list, so the two are deliberately not one
//! call graph. What they share is this file's rules — `MSG_CMSG_CLOEXEC`
//! on every receive, a truncated datagram is an error and never a short
//! read, and `Ok(0)` means the peer is gone.

use std::io;
use std::os::fd::{AsRawFd, BorrowedFd, FromRawFd, OwnedFd, RawFd};

/// Biggest request or reply datagram. argv for the widest spawner call
/// site (`iptables` rule specs, the jailer's ~20 arguments) and the
/// widest broker verb (`vm.register` with a pathological `hostPath`
/// list) are both a few hundred bytes to a few KiB; 64 KiB is room for
/// a pathological one without being a buffer worth streaming.
pub const MESSAGE_MAX: usize = 64 * 1024;

/// Most descriptors one datagram may carry. `vm.register` pins several
/// share roots and `fc.spawn` replies with three, so the broker needs
/// more than the spawner's three stdio slots.
pub const FDS_MAX: usize = 8;

/// `SCM_RIGHTS` control buffer, aligned for `cmsghdr` and sized for
/// [`FDS_MAX`] descriptors: `CMSG_SPACE(8 * 4)` is 48 on x86-64, so 64
/// bytes leaves the header room and keeps the buffer one cache line.
#[repr(align(8))]
struct CmsgBuf([u8; 64]);

impl CmsgBuf {
    fn zeroed() -> Self {
        Self([0u8; 64])
    }
}

fn last_error() -> io::Error {
    io::Error::last_os_error()
}

/// `socketpair(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC)`.
///
/// Unforgeable by construction: no path, no `bind`, and no peer other
/// than the process that inherited the other end.
pub fn socketpair() -> io::Result<(OwnedFd, OwnedFd)> {
    let mut socks = [-1i32; 2];
    // SAFETY: `socks` is a valid 2-element array for socketpair(2) to fill.
    let rc = unsafe {
        libc::socketpair(
            libc::AF_UNIX,
            libc::SOCK_SEQPACKET | libc::SOCK_CLOEXEC,
            0,
            socks.as_mut_ptr(),
        )
    };
    if rc < 0 {
        return Err(last_error());
    }
    // SAFETY: socketpair returned two fresh descriptors this process owns
    // and nothing else has seen; each is wrapped exactly once.
    Ok(unsafe {
        (
            OwnedFd::from_raw_fd(socks[0]),
            OwnedFd::from_raw_fd(socks[1]),
        )
    })
}

/// Send one datagram plus `fds`.
pub fn send_msg(sock: BorrowedFd<'_>, payload: &[u8], fds: &[RawFd]) -> io::Result<()> {
    assert!(
        fds.len() <= FDS_MAX,
        "at most {FDS_MAX} descriptors per datagram, got {}",
        fds.len()
    );
    let mut iov = libc::iovec {
        iov_base: payload.as_ptr().cast::<libc::c_void>().cast_mut(),
        iov_len: payload.len(),
    };
    // SAFETY: an all-zero msghdr is the documented "nothing set" value.
    let mut msg: libc::msghdr = unsafe { std::mem::zeroed() };
    msg.msg_iov = &raw mut iov;
    msg.msg_iovlen = 1;
    let mut cmsg = CmsgBuf::zeroed();
    if !fds.is_empty() {
        let bytes = u32::try_from(std::mem::size_of_val(fds)).expect("fd array fits u32");
        // SAFETY: CMSG_SPACE/CMSG_LEN are pure arithmetic on their argument.
        let (space, len) = unsafe { (libc::CMSG_SPACE(bytes), libc::CMSG_LEN(bytes)) };
        assert!(
            space as usize <= cmsg.0.len(),
            "cmsg buffer holds {} bytes, {FDS_MAX} descriptors need {space}",
            cmsg.0.len()
        );
        msg.msg_control = cmsg.0.as_mut_ptr().cast::<libc::c_void>();
        msg.msg_controllen = space as _;
        // SAFETY: msg_control points at an aligned buffer of msg_controllen
        // bytes, so CMSG_FIRSTHDR yields a header inside it; the writes
        // below stay within CMSG_SPACE(bytes), asserted above.
        unsafe {
            let hdr = libc::CMSG_FIRSTHDR(&raw const msg);
            (*hdr).cmsg_level = libc::SOL_SOCKET;
            (*hdr).cmsg_type = libc::SCM_RIGHTS;
            (*hdr).cmsg_len = len as _;
            std::ptr::copy_nonoverlapping(
                fds.as_ptr(),
                libc::CMSG_DATA(hdr).cast::<RawFd>(),
                fds.len(),
            );
        }
    }
    // SAFETY: `msg` describes `payload` and `cmsg`, both live for the call.
    let sent = unsafe { libc::sendmsg(sock.as_raw_fd(), &raw const msg, 0) };
    if sent < 0 {
        return Err(last_error());
    }
    if sent as usize != payload.len() {
        return Err(io::Error::other(format!(
            "short sendmsg on a seqpacket channel: {sent} of {} bytes",
            payload.len()
        )));
    }
    Ok(())
}

/// Receive one datagram into `buf`, collecting any passed descriptors
/// into `fds`.
///
/// `Ok(0)` is EOF: the peer is gone.
pub fn recv_msg(sock: BorrowedFd<'_>, buf: &mut [u8], fds: &mut Vec<OwnedFd>) -> io::Result<usize> {
    let mut iov = libc::iovec {
        iov_base: buf.as_mut_ptr().cast::<libc::c_void>(),
        iov_len: buf.len(),
    };
    // SAFETY: an all-zero msghdr is the documented "nothing set" value.
    let mut msg: libc::msghdr = unsafe { std::mem::zeroed() };
    msg.msg_iov = &raw mut iov;
    msg.msg_iovlen = 1;
    let mut cmsg = CmsgBuf::zeroed();
    msg.msg_control = cmsg.0.as_mut_ptr().cast::<libc::c_void>();
    msg.msg_controllen = cmsg.0.len() as _;
    // SAFETY: `msg` describes `buf` and `cmsg`, both live for the call.
    // MSG_CMSG_CLOEXEC is what keeps a received descriptor from leaking
    // into the next helper the receiver execs.
    let got = unsafe { libc::recvmsg(sock.as_raw_fd(), &raw mut msg, libc::MSG_CMSG_CLOEXEC) };
    if got < 0 {
        return Err(last_error());
    }
    // Collect first, then judge: a `MSG_CTRUNC` datagram may still have
    // handed over some descriptors, and dropping the error path's
    // `OwnedFd`s is how they get closed rather than leaked.
    // SAFETY: after a successful recvmsg the control buffer holds
    // well-formed headers; each SCM_RIGHTS payload is `n` descriptors
    // this process now owns.
    unsafe {
        let mut hdr = libc::CMSG_FIRSTHDR(&raw const msg);
        while !hdr.is_null() {
            if (*hdr).cmsg_level == libc::SOL_SOCKET && (*hdr).cmsg_type == libc::SCM_RIGHTS {
                let bytes = (*hdr).cmsg_len as usize - libc::CMSG_LEN(0) as usize;
                let data = libc::CMSG_DATA(hdr).cast::<RawFd>();
                for i in 0..bytes / std::mem::size_of::<RawFd>() {
                    fds.push(OwnedFd::from_raw_fd(data.add(i).read_unaligned()));
                }
            }
            hdr = libc::CMSG_NXTHDR(&raw const msg, hdr);
        }
    }
    if msg.msg_flags & (libc::MSG_TRUNC | libc::MSG_CTRUNC) != 0 {
        return Err(io::Error::other(
            "truncated datagram on a seqpacket channel (payload or SCM_RIGHTS did not fit)",
        ));
    }
    Ok(got as usize)
}

/// `pidfd_open(2)`. Always `CLOEXEC` per the man page, so it never
/// reaches a helper.
pub fn pidfd_open(pid: u32) -> io::Result<OwnedFd> {
    let pid = libc::pid_t::try_from(pid).unwrap_or(libc::pid_t::MAX);
    // SAFETY: pidfd_open takes a pid and flags and returns a descriptor.
    let raw = unsafe { libc::syscall(libc::SYS_pidfd_open, pid, 0u32) };
    if raw < 0 {
        return Err(last_error());
    }
    // SAFETY: the syscall returned a fresh descriptor this process owns.
    Ok(unsafe { OwnedFd::from_raw_fd(raw as RawFd) })
}

/// Whether the process behind `pidfd` has exited, waiting at most
/// `timeout_ms` (negative blocks).
pub fn pidfd_exited(pidfd: BorrowedFd<'_>, timeout_ms: i32) -> io::Result<bool> {
    let mut poll_fd = libc::pollfd {
        fd: pidfd.as_raw_fd(),
        events: libc::POLLIN,
        revents: 0,
    };
    loop {
        // SAFETY: one valid pollfd for the length given.
        let rc = unsafe { libc::poll(&raw mut poll_fd, 1, timeout_ms) };
        if rc < 0 {
            let e = last_error();
            if e.kind() == io::ErrorKind::Interrupted {
                continue;
            }
            return Err(e);
        }
        return Ok(rc > 0);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::fd::AsFd;

    #[test]
    fn round_trips_a_payload_and_a_descriptor() {
        let (a, b) = socketpair().expect("socketpair");
        let (read, write) = crate::fdutil::pipe_cloexec().expect("pipe");
        send_msg(a.as_fd(), b"hello", &[read.as_raw_fd()]).expect("send");
        let mut buf = vec![0u8; 64];
        let mut fds = Vec::new();
        let got = recv_msg(b.as_fd(), &mut buf, &mut fds).expect("recv");
        assert_eq!(&buf[..got], b"hello");
        assert_eq!(fds.len(), 1, "the descriptor did not cross");
        drop((read, write));
    }

    /// The received copy is a different descriptor number on a shared
    /// pipe, which is what makes fd passing (rather than path passing)
    /// the thing the §6 table describes.
    #[test]
    fn a_passed_descriptor_is_the_same_object() {
        let (a, b) = socketpair().expect("socketpair");
        let (read, write) = crate::fdutil::pipe_cloexec().expect("pipe");
        send_msg(a.as_fd(), b"fd", &[write.as_raw_fd()]).expect("send");
        let mut buf = vec![0u8; 16];
        let mut fds = Vec::new();
        recv_msg(b.as_fd(), &mut buf, &mut fds).expect("recv");
        drop(write);
        let received = fds.remove(0);
        // SAFETY: writing 2 bytes from a local buffer to a pipe we own.
        let n = unsafe {
            libc::write(
                received.as_raw_fd(),
                b"ok".as_ptr().cast::<libc::c_void>(),
                2,
            )
        };
        assert_eq!(n, 2, "{}", last_error());
        let mut got = [0u8; 2];
        // SAFETY: reading 2 bytes into a local buffer from a pipe we own.
        let n = unsafe {
            libc::read(
                read.as_raw_fd(),
                got.as_mut_ptr().cast::<libc::c_void>(),
                got.len(),
            )
        };
        assert_eq!(n, 2, "{}", last_error());
        assert_eq!(&got, b"ok");
    }

    #[test]
    fn a_datagram_over_the_buffer_is_reported_not_truncated() {
        let (a, b) = socketpair().expect("socketpair");
        send_msg(a.as_fd(), &vec![7u8; 4096], &[]).expect("send");
        let mut small = vec![0u8; 16];
        let mut fds = Vec::new();
        let err = recv_msg(b.as_fd(), &mut small, &mut fds).expect_err("must not truncate");
        assert!(err.to_string().contains("truncated"), "{err}");
    }

    #[test]
    fn eof_is_zero_not_an_error() {
        let (a, b) = socketpair().expect("socketpair");
        drop(a);
        let mut buf = vec![0u8; 16];
        let mut fds = Vec::new();
        assert_eq!(recv_msg(b.as_fd(), &mut buf, &mut fds).expect("recv"), 0);
    }

    /// The buffer has to hold `FDS_MAX` descriptors, or the verb that
    /// pins several share roots fails as `MSG_CTRUNC` on a node with
    /// many volumes and nowhere else.
    #[test]
    fn the_cmsg_buffer_holds_the_advertised_maximum() {
        let (a, b) = socketpair().expect("socketpair");
        let mut ends = Vec::new();
        let mut raw = Vec::new();
        for _ in 0..FDS_MAX {
            let (r, w) = crate::fdutil::pipe_cloexec().expect("pipe");
            raw.push(r.as_raw_fd());
            ends.push((r, w));
        }
        send_msg(a.as_fd(), b"max", &raw).expect("send FDS_MAX descriptors");
        let mut buf = vec![0u8; 16];
        let mut fds = Vec::new();
        recv_msg(b.as_fd(), &mut buf, &mut fds).expect("recv");
        assert_eq!(fds.len(), FDS_MAX);
    }

    #[test]
    fn pidfd_reports_a_live_and_an_exited_process() {
        let pidfd = pidfd_open(std::process::id()).expect("pidfd_open on self");
        assert!(
            !pidfd_exited(pidfd.as_fd(), 0).expect("poll"),
            "this process is not exited"
        );
    }
}
