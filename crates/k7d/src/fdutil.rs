//! The only two places k7d makes a pipe or an eventfd.
//!
//! k7d is one root process that `execve`s helpers — `virtiofsd`, `nft`,
//! `ip`, `mkfs`, and the Firecracker jailer. Every descriptor without
//! `O_CLOEXEC` crosses into each of them (`seccomp.rs` documents the
//! same inheritance for the syscall filter). For a pipe that is the
//! agent-output write end staying open in a helper so the read end
//! never sees EOF; for a jailed process it is a daemon descriptor
//! inside the jail (`docs/bug-candidates.md` #28). Both constructors
//! here set `CLOEXEC` unconditionally, and the
//! `no_raw_pipe_or_eventfd_outside_fdutil` unit test keeps every other
//! module going through them. Descriptors a child is
//! *meant* to have go through `Stdio::from` / `CommandExt`, which clear
//! the flag on the one fd the child gets, and nothing else.

use std::io;
use std::os::fd::{FromRawFd, OwnedFd};

use vmm_sys_util::eventfd::EventFd;

/// `pipe2(O_CLOEXEC)`: `(read end, write end)`.
pub fn pipe_cloexec() -> io::Result<(OwnedFd, OwnedFd)> {
    let mut fds = [-1i32; 2];
    // SAFETY: `fds` is a valid 2-element array for pipe2(2) to fill.
    if unsafe { libc::pipe2(fds.as_mut_ptr(), libc::O_CLOEXEC) } < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: pipe2 returned two fresh descriptors this process owns and
    // nothing else has seen; each is wrapped exactly once.
    Ok(unsafe { (OwnedFd::from_raw_fd(fds[0]), OwnedFd::from_raw_fd(fds[1])) })
}

/// `EventFd::new(flags | EFD_CLOEXEC)`.
pub fn eventfd_cloexec(flags: i32) -> io::Result<EventFd> {
    EventFd::new(flags | libc::EFD_CLOEXEC)
}

#[cfg(test)]
mod tests {
    use std::os::fd::AsRawFd;
    use std::path::Path;

    use super::*;

    fn fd_flags(fd: i32) -> i32 {
        // SAFETY: F_GETFD takes no argument and reads no memory.
        unsafe { libc::fcntl(fd, libc::F_GETFD) }
    }

    #[test]
    fn both_constructors_set_cloexec() {
        let (r, w) = pipe_cloexec().expect("pipe");
        assert_ne!(fd_flags(r.as_raw_fd()) & libc::FD_CLOEXEC, 0);
        assert_ne!(fd_flags(w.as_raw_fd()) & libc::FD_CLOEXEC, 0);
        let evt = eventfd_cloexec(libc::EFD_NONBLOCK).expect("eventfd");
        assert_ne!(fd_flags(evt.as_raw_fd()) & libc::FD_CLOEXEC, 0);
        assert_ne!(
            fd_flags(eventfd_cloexec(0).expect("eventfd").as_raw_fd()) & libc::FD_CLOEXEC,
            0
        );
    }

    fn rust_files(dir: &Path, out: &mut Vec<std::path::PathBuf>) {
        for entry in std::fs::read_dir(dir).expect("read src dir").flatten() {
            let path = entry.path();
            if path.is_dir() {
                rust_files(&path, out);
            } else if path.extension().is_some_and(|e| e == "rs") {
                out.push(path);
            }
        }
    }

    /// The rule, not the habit: a raw `libc::pipe(` or `EventFd::new(`
    /// anywhere else in the crate is a descriptor without `CLOEXEC`
    /// that the next helper `execve` inherits.
    #[test]
    fn no_raw_pipe_or_eventfd_outside_fdutil() {
        let src = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
        let mut files = Vec::new();
        rust_files(&src, &mut files);
        assert!(files.len() > 10, "found only {} source files", files.len());
        let mut offenders = Vec::new();
        for path in files {
            if path.file_name().is_some_and(|n| n == "fdutil.rs") {
                continue;
            }
            let text = std::fs::read_to_string(&path).expect("read source");
            for (i, line) in text.lines().enumerate() {
                if line.contains("libc::pipe(")
                    || line.contains("libc::pipe2(")
                    || line.contains("EventFd::new(")
                    || line.contains("libc::eventfd(")
                {
                    offenders.push(format!("{}:{}: {}", path.display(), i + 1, line.trim()));
                }
            }
        }
        assert!(
            offenders.is_empty(),
            "raw pipe/eventfd constructors outside fdutil.rs (use fdutil::pipe_cloexec / \
             fdutil::eventfd_cloexec):\n{}",
            offenders.join("\n")
        );
    }
}
