//! The one place a free path crosses into the node broker
//! (privilege-separation path allowlist).
//!
//! `vm.register` is the only verb that takes paths, and it takes them
//! once. Every later verb names an index into what registration pinned,
//! so the node broker never re-resolves a string the VM broker could
//! have changed underneath it — the difference between "open the file
//! the shim named" and "open whatever that name points at now" is the
//! whole class of bug this module exists to remove.
//!
//! A path is accepted only if it is absolute, has no `.` or `..`
//! component, lies under one of the class's allowlisted roots, and
//! resolves with `openat2(RESOLVE_BENEATH | RESOLVE_NO_SYMLINKS |
//! RESOLVE_NO_MAGICLINKS)` relative to that root's descriptor. The
//! result is pinned as an `O_PATH` descriptor plus the `(dev, ino)` it
//! had at that moment; later opens go through the descriptor.
//!
//! The roots themselves are resolved with an ordinary `open`, because
//! `/var/run` is a symlink to `/run` on every modern distro and the CRI
//! netns convention names both. Only the part of the path the *caller*
//! supplied is resolved with symlinks refused.

use std::ffi::CString;
use std::io;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::os::unix::fs::MetadataExt;
use std::path::{Component, Path, PathBuf};

/// `openat2` resolve flags. Not taken from `libc`: the constants landed
/// in different libc releases than `open_how` did, and a filter this
/// load-bearing should not depend on which.
const RESOLVE_NO_MAGICLINKS: u64 = 0x02;
const RESOLVE_NO_SYMLINKS: u64 = 0x04;
const RESOLVE_BENEATH: u64 = 0x08;

/// `struct open_how` as `openat2(2)` defines it. Declared here for the
/// same reason as the flags above.
#[repr(C)]
#[derive(Default)]
struct OpenHow {
    flags: u64,
    mode: u64,
    resolve: u64,
}

/// `statfs.f_type` of `nsfs`, the filesystem every network namespace
/// handle lives on.
const NSFS_MAGIC: libc::c_long = 0x6e73_6673;

/// Colon-separated extra roots (`K7D_HOST_PATH_ROOTS`). The suite adds
/// `/root/k7d` here; the daemon logs the effective list at startup so a
/// node with an operator-widened allowlist says so on inspection.
pub const EXTRA_ROOTS_ENV: &str = "K7D_HOST_PATH_ROOTS";

/// What a path is for, which decides its roots and its extra checks.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Class {
    /// A virtiofs share root or a hostPath etc-file source: kubelet and
    /// k3s volume trees, k7d's own state, the installed guest assets,
    /// and the shim's per-sandbox scratch dirs.
    ShareDir,
    /// A virtio-blk backing file the shim provisioned.
    BlockFile,
    /// A CNI network namespace handle.
    Netns,
}

impl Class {
    fn name(self) -> &'static str {
        match self {
            Self::ShareDir => "share directory",
            Self::BlockFile => "block backing file",
            Self::Netns => "pod netns",
        }
    }
}

/// One allowlisted root. `/tmp/k7d-shim-<sandbox>` is a family rather
/// than a path, and `/tmp` itself is never a root on its own — a
/// world-writable sticky directory would otherwise let any local uid
/// present a share to the daemon.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Root {
    /// Exactly this directory and anything beneath it.
    Exact(PathBuf),
    /// Children of `parent` whose name starts with `prefix`, and
    /// anything beneath them.
    Prefixed {
        /// Directory holding the family.
        parent: PathBuf,
        /// Required start of the child's name.
        prefix: String,
    },
}

impl Root {
    /// The directory `path` should be resolved relative to, plus the
    /// remainder, when this root covers it.
    fn split<'p>(&self, path: &'p Path) -> Option<(PathBuf, &'p Path)> {
        match self {
            Self::Exact(root) => path.strip_prefix(root).ok().map(|rel| (root.clone(), rel)),
            Self::Prefixed { parent, prefix } => {
                let rest = path.strip_prefix(parent).ok()?;
                let first = rest.components().next()?;
                let Component::Normal(name) = first else {
                    return None;
                };
                if !name.to_string_lossy().starts_with(prefix.as_str()) {
                    return None;
                }
                let root = parent.join(name);
                let rel = rest.strip_prefix(name).ok()?;
                Some((root, rel))
            }
        }
    }
}

/// Roots for `class`, in the order they are tried.
///
/// `/usr/local/share/k7d` is here because the installed guest assets are
/// world-readable there; the kernel and initrd themselves are *not*
/// registered at all — the VM broker reads them directly as uid `k7d`,
/// which is why a `K7D_KERNEL` under `/root` fails at startup with the
/// path named instead of at the first boot.
#[must_use]
pub fn roots(class: Class) -> Vec<Root> {
    let mut roots = match class {
        Class::ShareDir => vec![
            Root::Exact(PathBuf::from("/var/lib/kubelet/pods")),
            Root::Exact(PathBuf::from("/var/lib/rancher/k3s")),
            Root::Exact(PathBuf::from("/var/lib/k7d")),
            Root::Exact(PathBuf::from("/usr/local/share/k7d")),
            Root::Prefixed {
                parent: PathBuf::from("/tmp"),
                prefix: "k7d-shim-".to_string(),
            },
        ],
        // `trees`, `sandboxes` and `stage` are the VM broker's own, and
        // are here only because of `vm.register_disk` (§4.4): a
        // Firecracker jail hard-links a suspended node's `vmstate` and
        // `memory.bin` out of a tree directory, and a hard link needs a
        // name the *node* broker resolves. Everything the VM broker
        // opens for itself under them stays verb-free.
        Class::BlockFile => vec![
            Root::Exact(PathBuf::from("/var/lib/k7d/images")),
            Root::Exact(PathBuf::from("/var/lib/k7d/disks")),
            Root::Exact(PathBuf::from("/var/lib/k7d/trees")),
            Root::Exact(PathBuf::from("/var/lib/k7d/sandboxes")),
            Root::Exact(PathBuf::from("/var/lib/k7d/stage")),
            Root::Exact(PathBuf::from("/usr/local/share/k7d")),
            Root::Prefixed {
                parent: PathBuf::from("/tmp"),
                prefix: "k7d-shim-".to_string(),
            },
        ],
        // `/proc/<pid>/ns/net` is the other CRI spelling and is handled
        // by shape rather than by root ([`pin_proc_netns`]).
        Class::Netns => vec![
            Root::Exact(PathBuf::from("/run/netns")),
            Root::Exact(PathBuf::from("/var/run/netns")),
        ],
    };
    roots.extend(extra_roots());
    roots
}

/// Operator- and suite-supplied roots. Relative entries are refused
/// rather than resolved against a working directory nobody controls.
#[must_use]
pub fn extra_roots() -> Vec<Root> {
    let Ok(list) = std::env::var(EXTRA_ROOTS_ENV) else {
        return Vec::new();
    };
    list.split(':')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .filter_map(|s| {
            let path = PathBuf::from(s);
            if path.is_absolute() {
                Some(Root::Exact(path))
            } else {
                log::error!("{EXTRA_ROOTS_ENV} entry {s:?} is not absolute — ignored");
                None
            }
        })
        .collect()
}

/// A validated path, held open so it cannot be swapped.
#[derive(Debug)]
pub struct Pinned {
    fd: OwnedFd,
    dev: u64,
    ino: u64,
    path: PathBuf,
}

impl Pinned {
    /// `(st_dev, st_ino)` as of validation. A later verb that finds a
    /// different pair is looking at a different object.
    #[must_use]
    pub fn ids(&self) -> (u64, u64) {
        (self.dev, self.ino)
    }

    /// The path as the caller spelled it. For log lines and error
    /// messages only — nothing reopens it by name.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Hand a duplicate of the `O_PATH` descriptor to the VM broker.
    pub fn dup(&self) -> io::Result<OwnedFd> {
        self.fd.try_clone()
    }

    /// Re-open the pinned object with real access.
    ///
    /// Through `/proc/self/fd/<n>`, which resolves the descriptor rather
    /// than the name: the path may since have been replaced, and a
    /// 0700 ancestor is not consulted at all. `O_PATH` descriptors
    /// cannot be `dup`'d into readable ones, so this is the documented
    /// way round.
    ///
    /// Deliberately **without** `O_NOFOLLOW`, which the pinned-path
    /// allowlist asks for on the caller's path: `/proc/self/fd/<n>` *is* a magic
    /// link, so `O_NOFOLLOW` here is `ELOOP` every time. What the flag
    /// was there to buy — no symlink at the final component — was already
    /// bought by `RESOLVE_NO_SYMLINKS` when the descriptor was pinned,
    /// and unlike the flag it cannot be raced afterwards.
    pub fn reopen(&self, flags: libc::c_int) -> io::Result<OwnedFd> {
        let proc_path = CString::new(format!("/proc/self/fd/{}", self.fd.as_raw_fd()))
            .map_err(io::Error::other)?;
        // SAFETY: `proc_path` is a valid C string that outlives the call.
        let fd = unsafe { libc::open(proc_path.as_ptr(), flags | libc::O_CLOEXEC) };
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: `open` returned a fresh descriptor this process owns.
        Ok(unsafe { OwnedFd::from_raw_fd(fd) })
    }

    /// `fstatfs().f_type` of the pinned object.
    fn fs_type(&self) -> io::Result<libc::c_long> {
        // SAFETY: an all-zero statfs is a valid out-parameter.
        let mut st: libc::statfs = unsafe { std::mem::zeroed() };
        // SAFETY: `fstatfs` on a descriptor this process owns.
        if unsafe { libc::fstatfs(self.fd.as_raw_fd(), &raw mut st) } < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(st.f_type as libc::c_long)
    }
}

/// Validate and pin `path` for `class`.
///
/// `writable` only matters for [`Class::BlockFile`]: a read-write
/// backing file must be owned by root or by the VM broker's own uid, so
/// that a world-writable image cannot be handed to a guest as its disk.
pub fn validate(class: Class, path: &str, writable: bool) -> io::Result<Pinned> {
    // A trailing slash on a directory is a spelling, not an escape, and
    // CRI hostPaths carry one often enough that refusing it would be a
    // refusal about punctuation. Everything else non-canonical is
    // refused below.
    let path = Path::new(
        path.strip_suffix('/')
            .filter(|s| !s.is_empty())
            .unwrap_or(path),
    );
    if !path.is_absolute() {
        return Err(refused(class, path, "not an absolute path"));
    }
    // Split the string rather than walk `Path::components()`, which
    // normalises `a/b/.` away and would let a non-canonical spelling
    // through into the pinned `path` field that every later log line
    // prints. `openat2` resolves both spellings identically, so this is
    // about the caller and the audit trail agreeing on one name; escape
    // is `RESOLVE_BENEATH`'s job, not this loop's.
    let text = path.to_string_lossy();
    // The first segment of an absolute path is the empty string before
    // the leading `/`; every one after it must be a real name.
    for segment in text.split('/').skip(1) {
        let why = match segment {
            "." | ".." => format!("contains a `{segment}` component"),
            "" => "contains an empty component (`//` or a trailing `/`)".to_string(),
            _ => continue,
        };
        return Err(refused(
            class,
            path,
            &format!("{why} — name the path canonically"),
        ));
    }
    if class == Class::Netns && path.starts_with("/proc") {
        return pin_proc_netns(path);
    }
    let Some((root, rel)) = roots(class).iter().find_map(|root| root.split(path)) else {
        return Err(refused(
            class,
            path,
            &format!(
                "outside every allowlisted root ({}; widen with {EXTRA_ROOTS_ENV})",
                describe_roots(class)
            ),
        ));
    };

    let pinned = open_beneath(class, &root, rel, path)?;
    check_intermediate_permissions(class, &root, rel, path)?;

    // SAFETY: an all-zero stat is a valid out-parameter.
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    // SAFETY: `fstat` on an `O_PATH` descriptor this process owns, which
    // is one of the two calls O_PATH is documented to support.
    if unsafe { libc::fstat(pinned.as_raw_fd(), &raw mut st) } < 0 {
        return Err(io::Error::last_os_error());
    }
    let pinned = Pinned {
        fd: pinned,
        dev: st.st_dev,
        ino: st.st_ino,
        path: path.to_path_buf(),
    };

    match class {
        Class::ShareDir => {
            if st.st_mode & libc::S_IFMT != libc::S_IFDIR {
                return Err(refused(class, path, "not a directory"));
            }
            reject_world_writable(class, path, st.st_mode)?;
        }
        Class::BlockFile => {
            if st.st_mode & libc::S_IFMT != libc::S_IFREG {
                return Err(refused(class, path, "not a regular file"));
            }
            reject_world_writable(class, path, st.st_mode)?;
            // A Firecracker jail's lease uid counts as one of ours: the
            // node broker hard-links a writable drive into the chroot and
            // chowns it so the jailed VMM can write it, and a hard link
            // shares the inode — so the host file the VM broker hands
            // back on the *next* boot of the same data disk is owned by
            // the previous jail, forever (CHALLENGES #252). Range
            // membership is the whole test because nothing else can hold
            // a uid in it: no account exists there and only
            // `fc::stage`'s allocator hands them out.
            if writable
                && st.st_uid != 0
                && !is_vm_broker_uid(st.st_uid)
                && !crate::fc::stage::is_jail_uid(st.st_uid)
            {
                return Err(refused(
                    class,
                    path,
                    &format!(
                        "opened read-write but owned by uid {} — a read-write backing file must \
                         be root's, {}'s, or a Firecracker jail lease's",
                        st.st_uid,
                        super::VM_BROKER_USER
                    ),
                ));
            }
        }
        Class::Netns => {
            let ty = pinned.fs_type()?;
            if ty != NSFS_MAGIC {
                return Err(refused(
                    class,
                    path,
                    &format!("is on filesystem type {ty:#x}, not nsfs ({NSFS_MAGIC:#x})"),
                ));
            }
        }
    }
    Ok(pinned)
}

/// `/proc/<pid>/ns/net`, the other half of the CRI netns convention.
///
/// `openat2` cannot be used here: a namespace handle in `/proc` is a
/// magic link, `RESOLVE_NO_SYMLINKS` implies `RESOLVE_NO_MAGICLINKS`,
/// and following that link is the entire point — the nsfs inode behind
/// it *is* the namespace. So the shape is pinned instead of the
/// resolution: nothing but `/proc/<digits>/ns/net` is accepted, which
/// leaves no caller-controlled component to escape through, and the
/// `NSFS_MAGIC` check on the result is the gate.
fn pin_proc_netns(path: &Path) -> io::Result<Pinned> {
    let shape_ok = path
        .strip_prefix("/proc")
        .ok()
        .and_then(|rest| {
            let mut parts = rest.components();
            let Component::Normal(pid) = parts.next()? else {
                return None;
            };
            let rest: Vec<_> = parts.collect();
            Some(
                pid.to_string_lossy().chars().all(|c| c.is_ascii_digit())
                    && rest.len() == 2
                    && rest[0].as_os_str() == "ns"
                    && rest[1].as_os_str() == "net",
            )
        })
        .unwrap_or(false);
    if !shape_ok {
        return Err(refused(
            Class::Netns,
            path,
            "under /proc but not of the form /proc/<pid>/ns/net",
        ));
    }
    let c = CString::new(path.as_os_str().as_encoded_bytes()).map_err(io::Error::other)?;
    // SAFETY: `c` is a valid C string that outlives the call.
    let fd = unsafe { libc::open(c.as_ptr(), libc::O_PATH | libc::O_CLOEXEC) };
    if fd < 0 {
        return Err(io::Error::new(
            io::Error::last_os_error().kind(),
            format!(
                "pod netns {}: {}",
                path.display(),
                io::Error::last_os_error()
            ),
        ));
    }
    // SAFETY: `open` returned a fresh descriptor this process owns.
    let fd = unsafe { OwnedFd::from_raw_fd(fd) };
    // SAFETY: an all-zero stat is a valid out-parameter.
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    // SAFETY: `fstat` on an `O_PATH` descriptor this process owns.
    if unsafe { libc::fstat(fd.as_raw_fd(), &raw mut st) } < 0 {
        return Err(io::Error::last_os_error());
    }
    let pinned = Pinned {
        fd,
        dev: st.st_dev,
        ino: st.st_ino,
        path: path.to_path_buf(),
    };
    let ty = pinned.fs_type()?;
    if ty != NSFS_MAGIC {
        return Err(refused(
            Class::Netns,
            path,
            &format!("is on filesystem type {ty:#x}, not nsfs ({NSFS_MAGIC:#x})"),
        ));
    }
    Ok(pinned)
}

/// `openat2` the caller's remainder beneath the root's descriptor.
fn open_beneath(class: Class, root: &Path, rel: &Path, whole: &Path) -> io::Result<OwnedFd> {
    let root_c = CString::new(root.as_os_str().as_encoded_bytes()).map_err(io::Error::other)?;
    // The root itself may legitimately be reached through a symlink
    // (`/var/run` → `/run`), so it is opened with an ordinary `open`.
    // SAFETY: `root_c` is a valid C string that outlives the call.
    let root_fd = unsafe {
        libc::open(
            root_c.as_ptr(),
            libc::O_PATH | libc::O_DIRECTORY | libc::O_CLOEXEC,
        )
    };
    if root_fd < 0 {
        return Err(io::Error::new(
            io::Error::last_os_error().kind(),
            format!(
                "allowlisted root {} for {} {}: {}",
                root.display(),
                class.name(),
                whole.display(),
                io::Error::last_os_error()
            ),
        ));
    }
    // SAFETY: `open` returned a fresh descriptor this process owns.
    let root_fd = unsafe { OwnedFd::from_raw_fd(root_fd) };

    // An empty remainder means the caller named the root itself.
    let rel_c = CString::new(if rel.as_os_str().is_empty() {
        b".".to_vec()
    } else {
        rel.as_os_str().as_encoded_bytes().to_vec()
    })
    .map_err(io::Error::other)?;
    let how = OpenHow {
        flags: (libc::O_PATH | libc::O_CLOEXEC) as u64,
        mode: 0,
        resolve: RESOLVE_BENEATH | RESOLVE_NO_SYMLINKS | RESOLVE_NO_MAGICLINKS,
    };
    // SAFETY: `openat2` reads `size_of::<OpenHow>()` bytes from a live,
    // fully initialised `open_how` and `rel_c` outlives the call.
    let fd = unsafe {
        libc::syscall(
            libc::SYS_openat2,
            root_fd.as_raw_fd(),
            rel_c.as_ptr(),
            &raw const how,
            std::mem::size_of::<OpenHow>(),
        )
    };
    if fd < 0 {
        // Every refusal is `EACCES`, whatever the kernel's own errno was,
        // and the errno goes in the message. The caller's branch is
        // "the shim named a path it may not have" either way — a `..`
        // (`EXDEV`), a symlink component (`ELOOP`), a path that is not
        // there (`ENOENT`) — and a `CreateVm` that reports three
        // different kinds for one class of mistake is three things to
        // learn instead of one.
        let err = io::Error::last_os_error();
        return Err(refused(
            class,
            whole,
            &format!(
                "did not resolve beneath {} with symlinks refused: {err} (a `..`, a symlink \
                 component, an escape from the root, or nothing there)",
                root.display()
            ),
        ));
    }
    // SAFETY: the syscall returned a fresh descriptor this process owns.
    Ok(unsafe { OwnedFd::from_raw_fd(fd as i32) })
}

/// Refuse a world-writable directory anywhere between the root and the
/// target. Symlinks are already proven absent, so the string path is the
/// real one and `symlink_metadata` on each ancestor is exact.
///
/// The sticky bit is what makes `/tmp` itself survivable, and `/tmp` is
/// never a root on its own — only `/tmp/k7d-shim-*`, which the shim
/// creates 0700.
fn check_intermediate_permissions(
    class: Class,
    root: &Path,
    rel: &Path,
    whole: &Path,
) -> io::Result<()> {
    if class == Class::Netns {
        // `/run/netns` is root-owned 0755 and holds nsfs bind mounts,
        // not directories; there is no caller-controlled intermediate.
        return Ok(());
    }
    let mut at = root.to_path_buf();
    for component in rel.components() {
        let Component::Normal(name) = component else {
            continue;
        };
        at.push(name);
        let Ok(meta) = std::fs::symlink_metadata(&at) else {
            // The target itself may not exist yet for some callers; the
            // `openat2` above already decided that question.
            break;
        };
        if !meta.is_dir() {
            continue;
        }
        reject_world_writable(class, whole, meta.mode())?;
    }
    Ok(())
}

fn reject_world_writable(class: Class, path: &Path, mode: u32) -> io::Result<()> {
    if mode & 0o002 != 0 && mode & 0o1000 == 0 {
        return Err(refused(
            class,
            path,
            &format!(
                "is world-writable and not sticky (mode {:04o})",
                mode & 0o7777
            ),
        ));
    }
    Ok(())
}

/// Whether `uid` is the VM broker's. Looked up once: the account does
/// not change while the daemon runs, and a node without it never gets
/// this far ([`super::start`] fails first).
fn is_vm_broker_uid(uid: u32) -> bool {
    static UID: std::sync::OnceLock<Option<u32>> = std::sync::OnceLock::new();
    *UID.get_or_init(|| super::lookup_uid(super::VM_BROKER_USER).ok()) == Some(uid)
}

fn describe_roots(class: Class) -> String {
    roots(class)
        .iter()
        .map(|r| match r {
            Root::Exact(p) => p.display().to_string(),
            Root::Prefixed { parent, prefix } => format!("{}/{prefix}*", parent.display()),
        })
        .collect::<Vec<_>>()
        .join(", ")
}

/// Every refusal is `EACCES` with the class, the path and the reason, so
/// the shim's `CreateVm` failure names the offending entry rather than
/// saying "permission denied".
fn refused(class: Class, path: &Path, why: &str) -> io::Error {
    io::Error::new(
        io::ErrorKind::PermissionDenied,
        format!("{} {} refused: {why}", class.name(), path.display()),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::symlink;

    /// Roots the tests can write in, via the operator escape hatch the
    /// suite already uses.
    fn with_root<T>(root: &Path, f: impl FnOnce() -> T) -> T {
        let prev = std::env::var(EXTRA_ROOTS_ENV).ok();
        std::env::set_var(EXTRA_ROOTS_ENV, root);
        let out = f();
        match prev {
            Some(v) => std::env::set_var(EXTRA_ROOTS_ENV, v),
            None => std::env::remove_var(EXTRA_ROOTS_ENV),
        }
        out
    }

    fn tmpdir(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("k7d-paths-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("create temp root");
        dir
    }

    #[test]
    fn a_directory_inside_a_root_is_pinned_to_its_dev_and_ino() {
        let root = tmpdir("inside");
        let share = root.join("share");
        std::fs::create_dir(&share).expect("mkdir");
        let pinned = with_root(&root, || {
            validate(Class::ShareDir, share.to_str().unwrap(), false)
        })
        .expect("inside a root");
        let meta = std::fs::metadata(&share).expect("stat");
        assert_eq!(pinned.ids(), (meta.dev(), meta.ino()));
        assert_eq!(pinned.path(), share);
        std::fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn a_path_outside_every_root_is_refused() {
        let root = tmpdir("outside");
        let err = with_root(&root, || validate(Class::ShareDir, "/etc", false))
            .expect_err("/etc is not a root");
        assert_eq!(err.kind(), io::ErrorKind::PermissionDenied);
        assert!(
            err.to_string().contains("outside every allowlisted root"),
            "{err}"
        );
        std::fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn a_parent_component_is_refused_before_any_syscall() {
        let root = tmpdir("dotdot");
        let err = with_root(&root, || {
            validate(
                Class::ShareDir,
                &format!("{}/../../etc", root.display()),
                false,
            )
        })
        .expect_err("`..` must be refused");
        assert!(err.to_string().contains("`..`"), "{err}");
        std::fs::remove_dir_all(&root).ok();
    }

    /// The interesting case: a name that *is* inside a root but points
    /// out of it. String prefix checks accept it; `RESOLVE_NO_SYMLINKS`
    /// is what does not.
    #[test]
    fn a_symlink_component_inside_a_root_is_refused() {
        let root = tmpdir("symlink");
        symlink("/etc", root.join("escape")).expect("symlink");
        let err = with_root(&root, || {
            validate(
                Class::ShareDir,
                &format!("{}/escape", root.display()),
                false,
            )
        })
        .expect_err("a symlink out of the root must be refused");
        assert_eq!(err.kind(), io::ErrorKind::PermissionDenied);
        std::fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn a_symlinked_intermediate_directory_is_refused() {
        let root = tmpdir("symlink-mid");
        std::fs::create_dir(root.join("real")).expect("mkdir");
        std::fs::create_dir(root.join("real/inner")).expect("mkdir");
        symlink(root.join("real"), root.join("via")).expect("symlink");
        let err = with_root(&root, || {
            validate(
                Class::ShareDir,
                &format!("{}/via/inner", root.display()),
                false,
            )
        })
        .expect_err("a symlinked intermediate must be refused");
        assert_eq!(err.kind(), io::ErrorKind::PermissionDenied);
        std::fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn a_world_writable_share_is_refused_unless_sticky() {
        use std::os::unix::fs::PermissionsExt;
        let root = tmpdir("wworld");
        let share = root.join("open");
        std::fs::create_dir(&share).expect("mkdir");
        std::fs::set_permissions(&share, std::fs::Permissions::from_mode(0o777)).expect("chmod");
        let err = with_root(&root, || {
            validate(Class::ShareDir, share.to_str().unwrap(), false)
        })
        .expect_err("0777 non-sticky must be refused");
        assert!(err.to_string().contains("world-writable"), "{err}");
        std::fs::set_permissions(&share, std::fs::Permissions::from_mode(0o1777)).expect("chmod");
        with_root(&root, || {
            validate(Class::ShareDir, share.to_str().unwrap(), false)
        })
        .expect("1777 is survivable");
        std::fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn a_share_class_refuses_a_regular_file_and_vice_versa() {
        let root = tmpdir("kinds");
        let file = root.join("img");
        std::fs::write(&file, b"x").expect("write");
        let dir = root.join("d");
        std::fs::create_dir(&dir).expect("mkdir");
        let err = with_root(&root, || {
            validate(Class::ShareDir, file.to_str().unwrap(), false)
        })
        .expect_err("a file is not a share");
        assert!(err.to_string().contains("not a directory"), "{err}");
        let err = with_root(&root, || {
            validate(Class::BlockFile, dir.to_str().unwrap(), false)
        })
        .expect_err("a directory is not a disk");
        assert!(err.to_string().contains("not a regular file"), "{err}");
        std::fs::remove_dir_all(&root).ok();
    }

    /// `/dev/null` is the negative case for a netns: it exists,
    /// it resolves, and it is not a namespace handle.
    #[test]
    fn a_netns_that_is_not_nsfs_is_refused() {
        let err = validate(Class::Netns, "/dev/null", false).expect_err("/dev is not a root");
        assert_eq!(err.kind(), io::ErrorKind::PermissionDenied);
        // Under `/proc` the *shape* is the gate, since the handle is a
        // magic link and cannot be resolved with symlinks refused.
        let err =
            validate(Class::Netns, "/proc/self/cmdline", false).expect_err("procfs is not a netns");
        assert!(err.to_string().contains("/proc/<pid>/ns/net"), "{err}");
        let err =
            validate(Class::Netns, "/proc/self/ns/net", false).expect_err("`self` is not a pid");
        assert!(err.to_string().contains("/proc/<pid>/ns/net"), "{err}");
        let err = validate(
            Class::Netns,
            &format!("/proc/{}/ns/uts", std::process::id()),
            false,
        )
        .expect_err("uts is not net");
        assert!(err.to_string().contains("/proc/<pid>/ns/net"), "{err}");
    }

    /// The live netns of this very process, through the magic link the
    /// CRI convention names.
    #[test]
    fn the_processs_own_netns_validates_through_proc() {
        let path = format!("/proc/{}/ns/net", std::process::id());
        let pinned = validate(Class::Netns, &path, false).expect("own netns");
        assert_eq!(pinned.fs_type().expect("fstatfs"), NSFS_MAGIC);
    }

    #[test]
    fn the_shim_scratch_family_is_a_root_but_tmp_itself_is_not() {
        let shim = std::env::temp_dir().join(format!("k7d-shim-paths-{}", std::process::id()));
        std::fs::create_dir_all(shim.join("slot")).expect("create shim dir");
        validate(Class::ShareDir, shim.join("slot").to_str().unwrap(), false)
            .expect("inside /tmp/k7d-shim-*");
        let other = std::env::temp_dir().join(format!("k7d-other-{}", std::process::id()));
        std::fs::create_dir_all(&other).expect("mkdir");
        let err = validate(Class::ShareDir, other.to_str().unwrap(), false)
            .expect_err("/tmp is not a root on its own");
        assert!(
            err.to_string().contains("outside every allowlisted root"),
            "{err}"
        );
        std::fs::remove_dir_all(&shim).ok();
        std::fs::remove_dir_all(&other).ok();
    }

    /// A pinned descriptor reopens the object it pinned, not the name.
    #[test]
    fn reopen_reads_through_the_descriptor_after_the_name_is_replaced() {
        let root = tmpdir("reopen");
        let file = root.join("img");
        std::fs::write(&file, b"original").expect("write");
        let pinned = with_root(&root, || {
            validate(Class::BlockFile, file.to_str().unwrap(), false)
        })
        .expect("pin");
        std::fs::write(&file, b"replaced-in-place").expect("rewrite");
        std::fs::remove_file(&file).expect("unlink");
        std::fs::write(&file, b"a different file entirely").expect("recreate");
        let fd = pinned.reopen(libc::O_RDONLY).expect("reopen");
        let mut buf = [0u8; 32];
        // SAFETY: reading into a local buffer from a descriptor we own.
        let n = unsafe {
            libc::read(
                fd.as_raw_fd(),
                buf.as_mut_ptr().cast::<libc::c_void>(),
                buf.len(),
            )
        };
        assert!(n > 0, "{}", io::Error::last_os_error());
        assert_eq!(
            &buf[..n as usize],
            b"replaced-in-place",
            "reopen followed the name instead of the pinned inode"
        );
        std::fs::remove_dir_all(&root).ok();
    }

    /// Property test over generated paths (§10.1): anything with a `..`,
    /// a symlink component, or a root escape is refused; anything plain
    /// inside a root is accepted with the right identity.
    #[test]
    fn generated_paths_are_accepted_only_when_they_stay_inside() {
        let root = tmpdir("property");
        std::fs::create_dir_all(root.join("a/b/c")).expect("mkdir -p");
        symlink("/etc", root.join("a/link")).expect("symlink");
        // A cheap deterministic generator: every path is built from the
        // components below, so the accepted set is decidable by
        // inspection and the test does not depend on a proptest crate.
        let components = ["a", "b", "c", "..", ".", "link"];
        let mut checked = 0;
        for i in 0..components.len() {
            for j in 0..components.len() {
                for k in 0..components.len() {
                    let rel = format!("{}/{}/{}", components[i], components[j], components[k]);
                    let whole = root.join(&rel);
                    let got = with_root(&root, || {
                        validate(Class::ShareDir, whole.to_str().unwrap(), false)
                    });
                    let plain = rel == "a/b/c";
                    if plain {
                        let pinned = got.expect("a/b/c is inside the root");
                        let meta = std::fs::metadata(&whole).expect("stat");
                        assert_eq!(pinned.ids(), (meta.dev(), meta.ino()));
                    } else {
                        let err = got.expect_err(&format!("{rel} must be refused"));
                        assert_eq!(err.kind(), io::ErrorKind::PermissionDenied, "{rel}: {err}");
                    }
                    checked += 1;
                }
            }
        }
        assert_eq!(checked, components.len().pow(3));
        std::fs::remove_dir_all(&root).ok();
    }

    /// A data disk a Firecracker VM has already run keeps the lease uid
    /// of that jail forever, and coming back read-write is the normal
    /// case for a named disk rather than an attack (CHALLENGES #252).
    /// One uid past the range is the negative case.
    #[test]
    fn a_writable_disk_owned_by_a_jail_lease_is_accepted_and_one_past_it_is_not() {
        let root = tmpdir("jail-owned");
        let lease = root.join("data.img");
        let stranger = root.join("stranger.img");
        for p in [&lease, &stranger] {
            std::fs::write(p, b"x").expect("write");
        }
        let chown = |path: &Path, uid: u32| {
            let c = CString::new(path.to_str().expect("utf-8 temp path")).expect("no NUL");
            // SAFETY: a valid NUL-terminated path and two ids.
            let rc = unsafe { libc::chown(c.as_ptr(), uid, uid) };
            assert_eq!(
                rc,
                0,
                "chown {} to {uid}: {}",
                path.display(),
                io::Error::last_os_error()
            );
        };
        chown(&lease, crate::fc::stage::DEFAULT_UID_BASE);
        chown(
            &stranger,
            crate::fc::stage::DEFAULT_UID_BASE + crate::fc::stage::MAX_LIVE_UIDS,
        );
        with_root(&root, || {
            validate(Class::BlockFile, lease.to_str().unwrap(), true)
        })
        .expect("a jail lease's own disk");
        let err = with_root(&root, || {
            validate(Class::BlockFile, stranger.to_str().unwrap(), true)
        })
        .expect_err("one uid past the range is nobody's");
        assert!(err.to_string().contains("owned by uid"), "{err}");
        std::fs::remove_dir_all(&root).ok();
    }

    /// The extra-root hatch takes absolute paths only: a relative entry
    /// would be resolved against a working directory nobody controls.
    #[test]
    fn relative_extra_roots_are_ignored_loudly() {
        let prev = std::env::var(EXTRA_ROOTS_ENV).ok();
        std::env::set_var(EXTRA_ROOTS_ENV, "relative/path:/root/k7d");
        let got = extra_roots();
        assert_eq!(got, vec![Root::Exact(PathBuf::from("/root/k7d"))]);
        match prev {
            Some(v) => std::env::set_var(EXTRA_ROOTS_ENV, v),
            None => std::env::remove_var(EXTRA_ROOTS_ENV),
        }
    }
}
