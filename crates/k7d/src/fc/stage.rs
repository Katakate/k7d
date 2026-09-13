//! Jailer chroot staging and the per-VM uid allocator.
//!
//! Layout for VM `<vm_id>` with
//! allocated uid/gid `u`:
//!
//! ```text
//! <base>/<exec_name>/<vm_id>/root/       ← chroot
//!   vmlinux, initramfs.cpio.gz           ← hard links of the daemon's guest pair
//!   run/                                 ← chown u:u; Firecracker creates
//!                                          firecracker.socket and v.sock here
//! ```
//!
//! The `<exec_name>` level is the jailer's, not ours: it builds
//! `<chroot-base-dir>/<exec-file-name>/<id>/root` and there is no flag
//! to flatten it. k7d pre-creates that directory and stages into it —
//! the jailer explicitly tolerates an existing chroot path — so the
//! kernel is in place before Firecracker is allowed to look for it.
//!
//! Two rules that are easy to get wrong and loud here:
//!
//! * **Hard links, not copies.** A copy of the kernel per VM is a
//!   megabyte of page cache and a millisecond per boot for a file every
//!   VM on the node shares. A hard link cannot cross a filesystem, so
//!   staging checks `st_dev` up front and names both filesystems when
//!   they differ rather than surfacing a bare `EXDEV` from `link(2)`.
//! * **No `chmod` on the staged link.** A hard link *is* the source
//!   inode; `chmod 0444` on it would silently re-mode the daemon's
//!   installed `/usr/local/share/k7d/vmlinux`. Staging asserts the
//!   source is already world-readable instead — Firecracker reads it as
//!   the unprivileged uid.

use std::collections::BTreeSet;
use std::io::Read;
use std::os::fd::AsRawFd;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::{Mutex, OnceLock};

use super::FcError;

/// First uid/gid handed to a Firecracker VM. Override with
/// `K7D_FC_UID_BASE`.
pub const DEFAULT_UID_BASE: u32 = 60_000;

/// How many concurrent Firecracker VMs one daemon can run. The uid
/// range is `[base, base + MAX_LIVE_UIDS)`; exhausting it is an error,
/// never a wrap-around onto another VM's uid.
pub const MAX_LIVE_UIDS: u32 = 1024;

fn uid_base() -> Result<u32, FcError> {
    match std::env::var("K7D_FC_UID_BASE") {
        Ok(v) => v.trim().parse::<u32>().map_err(|e| FcError::Config {
            message: format!("malformed K7D_FC_UID_BASE {v:?}: {e}"),
        }),
        Err(std::env::VarError::NotPresent) => Ok(DEFAULT_UID_BASE),
        Err(e) => Err(FcError::Config {
            message: format!("read K7D_FC_UID_BASE: {e}"),
        }),
    }
}

fn live_uids() -> &'static Mutex<BTreeSet<u32>> {
    static LIVE: OnceLock<Mutex<BTreeSet<u32>>> = OnceLock::new();
    LIVE.get_or_init(|| Mutex::new(BTreeSet::new()))
}

/// An allocated uid/gid, released when dropped.
///
/// Held by [`super::FcVm`] for the lifetime of the microVM, so a uid is
/// reused only after the process that ran under it is gone and its
/// chroot removed.
#[derive(Debug)]
pub struct UidLease {
    uid: u32,
}

impl UidLease {
    /// Take the lowest free uid in the configured range.
    pub fn acquire() -> Result<Self, FcError> {
        let base = uid_base()?;
        let mut live = live_uids().lock().expect("fc uid allocator poisoned");
        for uid in base..base.saturating_add(MAX_LIVE_UIDS) {
            if live.insert(uid) {
                return Ok(Self { uid });
            }
        }
        Err(FcError::UidsExhausted {
            base,
            count: MAX_LIVE_UIDS,
        })
    }

    /// The allocated uid (also used as the gid).
    #[must_use]
    pub fn uid(&self) -> u32 {
        self.uid
    }
}

impl Drop for UidLease {
    fn drop(&mut self) {
        live_uids()
            .lock()
            .expect("fc uid allocator poisoned")
            .remove(&self.uid);
    }
}

/// Number of uids currently leased. Test/diagnostic accessor: the
/// leak assertion in `test_fc_boot.rs` is exactly this being flat
/// across create/stop cycles.
#[must_use]
pub fn live_uid_count() -> usize {
    live_uids().lock().expect("fc uid allocator poisoned").len()
}

/// Root of every jailer chroot. `K7D_FC_CHROOT_BASE` overrides.
///
/// Default [`crate::disks::FC_LINK`], which the daemon points at the
/// reflink XFS holding [`crate::disks::DISKS_DIR`]
/// ([`crate::disks::ensure_reflink_fc_root`]). That is the filesystem
/// the *writable* disks are on, and a writable disk can only enter a
/// jail as a hard link — same inode, so the guest's writes are the
/// host file's writes — which `link(2)` refuses across mounts. The
/// read-only artifacts (kernel, initrd, erofs images) live on the
/// node's ext4 root instead, and cross that boundary once each through
/// [`ro_cache_dir`].
pub fn chroot_base() -> PathBuf {
    std::env::var("K7D_FC_CHROOT_BASE")
        .map_or_else(|_| PathBuf::from(crate::disks::FC_LINK), PathBuf::from)
}

/// Node-wide cache of read-only artifacts copied onto the chroot base's
/// filesystem, so they can be hard-linked into a jail.
///
/// One copy per artifact per node, not per VM: entries are keyed by the
/// source's `(device, inode, size, mtime)`, so the hundreds of
/// megabytes of an `ubuntu:24.04` erofs image are copied the first time
/// a Firecracker pod uses that image and hard-linked every time after.
/// An operator who puts [`crate::erofs::DEFAULT_CACHE_DIR`] on the same
/// filesystem as the chroot base skips the cache entirely — the
/// same-filesystem fast path in [`stage_read_only`] never consults it.
#[must_use]
pub fn ro_cache_dir(base: &Path) -> PathBuf {
    base.join(".ro-cache")
}

/// A staged chroot. Dropping it removes the whole `<vm_id>` directory
/// (chroot, the jailer's copy of the Firecracker binary, the pid file).
#[derive(Debug)]
pub struct Chroot {
    /// `<base>/<exec_name>/<vm_id>` — what teardown removes.
    vm_dir: PathBuf,
    /// `<vm_dir>/root` — what Firecracker sees as `/`.
    root: PathBuf,
    /// Chroot base, for [`ro_cache_dir`].
    base: PathBuf,
    /// uid/gid the jailed Firecracker runs as.
    uid: u32,
}

/// Chroot-relative directory read-only images are hard-linked into.
pub const IMG_SUBDIR: &str = "img";

/// Chroot-relative directory writable disks are hard-linked into.
pub const DISK_SUBDIR: &str = "disk";

/// Chroot-relative directory Firecracker writes snapshots into and
/// reads `load.mem` from. Owned by the VM's uid.
pub const SNAP_SUBDIR: &str = "snap";

impl Chroot {
    /// Path Firecracker sees as `/`.
    #[must_use]
    pub fn root(&self) -> &Path {
        &self.root
    }

    /// Host path of the API socket Firecracker will create.
    #[must_use]
    pub fn api_socket(&self) -> PathBuf {
        self.root
            .join(super::CHROOT_API_SOCKET.trim_start_matches('/'))
    }

    /// Host path of the vsock UDS Firecracker will create.
    #[must_use]
    pub fn vsock_uds(&self) -> PathBuf {
        self.root
            .join(super::CHROOT_VSOCK_UDS.trim_start_matches('/'))
    }

    /// Host path of the pid file the jailer writes for the process it
    /// clones into the new pid namespace.
    #[must_use]
    pub fn pid_file(&self, exec_name: &str) -> PathBuf {
        self.root.join(format!("{exec_name}.pid"))
    }

    /// `<root>/snap` — the directory the **jailed** Firecracker writes
    /// its Diffs and vmstates into and reads `load.mem` from.
    #[must_use]
    pub fn jail_snap_dir(&self) -> PathBuf {
        self.root.join(SNAP_SUBDIR)
    }

    /// `<vm_dir>/snap` — k7d's own snapshot bookkeeping for this VM
    /// (`base.mem`, `restore-N.mem`, `vmstate-N`, disk clones).
    ///
    /// Deliberately *outside* the chroot: these files decide what a
    /// child or a rollback wakes up as, and a compromised VMM must not
    /// be able to replace them from inside its jail. It can still
    /// unlink `load.mem` in its own `snap/` — that does nothing to the
    /// mapping it already holds.
    #[must_use]
    pub fn snap_dir(&self) -> PathBuf {
        self.vm_dir.join(SNAP_SUBDIR)
    }

    /// uid/gid the jailed Firecracker runs as.
    #[must_use]
    pub fn uid(&self) -> u32 {
        self.uid
    }

    /// Chroot base this jail was staged under.
    #[must_use]
    pub fn base(&self) -> &Path {
        &self.base
    }

    /// Hard-link a **read-only** image (an erofs rootfs, an image slot's
    /// backing file) into `img/` under `name`, and return the path
    /// Firecracker sees it at (`/img/<name>`).
    ///
    /// Cross-filesystem sources go through [`ro_cache_dir`] first; see
    /// [`stage_read_only`].
    pub fn link_read_only(&self, name: &str, src: &Path) -> Result<String, FcError> {
        let dst = self.root.join(IMG_SUBDIR).join(name);
        stage_read_only(&self.base, src, &dst)?;
        Ok(format!("/{IMG_SUBDIR}/{name}"))
    }

    /// Host path of the writable disk staged under `name`
    /// (`<root>/disk/<name>`).
    #[must_use]
    pub fn disk_path(&self, name: &str) -> PathBuf {
        self.root.join(DISK_SUBDIR).join(name)
    }

    /// Hard-link a **writable** disk into `disk/` under `name`, chown it
    /// to the VM's uid, and return the path Firecracker sees it at
    /// (`/disk/<name>`).
    ///
    /// A hard link and not a reflink: a reflink is a copy-on-write
    /// *copy*, so the guest's writes would land in a file the host
    /// throws away with the chroot. That is right for scratch and wrong
    /// for a named data disk, whose whole contract is that its content
    /// outlives the pod — and one mechanism for both
    /// beats two that differ only in which of them silently loses data.
    ///
    /// The `chown` re-owns the **inode**, so it is visible on the host
    /// file too (the same trap as `chmod` on a staged kernel).
    /// That is intended and safe here: these images are k7d's own,
    /// exclusively held by one live VM, and re-chowned on every attach.
    pub fn link_read_write(&self, name: &str, src: &Path) -> Result<String, FcError> {
        let dst = self.root.join(DISK_SUBDIR).join(name);
        link_same_fs(src, &dst)?;
        chown(&dst, self.uid)?;
        Ok(format!("/{DISK_SUBDIR}/{name}"))
    }
}

impl Drop for Chroot {
    fn drop(&mut self) {
        if let Err(e) = std::fs::remove_dir_all(&self.vm_dir) {
            if e.kind() != std::io::ErrorKind::NotFound {
                log::error!("fc: remove chroot {}: {e}", self.vm_dir.display());
            }
        }
        // This chroot's links are gone, so entries it was the last
        // holder of are now collectable. Here rather than at daemon
        // startup because the entries that actually accumulate are
        // per-pod (an image slot's backing file is unique to the pod
        // that declared it), and a node running pods continuously would
        // never reach a restart.
        sweep_ro_cache(&self.base);
    }
}

/// Drop read-only cache entries no jail is linking any more.
///
/// An entry's link count is one per jail holding it plus one for the
/// cache itself, so `nlink == 1` means "nobody is using this". The
/// shared artifacts — a guest kernel, a base image's erofs — are
/// re-copied the next time a VM needs them, which is the right trade:
/// the alternative is keeping every pod's 2 GiB image-slot file
/// forever to avoid re-copying an 18 MB kernel on an idle node.
fn sweep_ro_cache(base: &Path) {
    let dir = ro_cache_dir(base);
    let Ok(entries) = std::fs::read_dir(&dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        // Temp files of a copy in flight are named `.<key>.tmp-<pid>`
        // and have no second link yet; they are not ours to remove.
        if path
            .file_name()
            .is_some_and(|n| n.to_string_lossy().starts_with('.'))
        {
            continue;
        }
        if std::fs::metadata(&path).is_ok_and(|m| m.nlink() == 1) {
            if let Err(e) = std::fs::remove_file(&path) {
                log::warn!("fc: sweep cache entry {}: {e}", path.display());
            }
        }
    }
}

/// Build the chroot for `vm_id` and stage the guest pair into it.
///
/// `exec_name` is the file name of the Firecracker binary handed to the
/// jailer — the jailer derives one level of the chroot path from it.
pub fn stage(
    base: &Path,
    exec_name: &str,
    vm_id: &str,
    kernel: &Path,
    initrd: Option<&Path>,
    uid: u32,
) -> Result<Chroot, FcError> {
    let vm_dir = base.join(exec_name).join(vm_id);
    if vm_dir.exists() {
        // The jailer tolerates this; k7d must not. A leftover directory
        // means a previous VM with this id was not torn down, and its
        // `<exec>.pid` file would make the jailer's `create_new` fail
        // much further along with a bare EEXIST.
        return Err(FcError::Config {
            message: format!(
                "jailer chroot {} already exists — a previous VM with this id \
                 was not torn down",
                vm_dir.display()
            ),
        });
    }
    let root = vm_dir.join("root");
    std::fs::create_dir_all(&root).map_err(|e| FcError::Stage {
        path: root.clone(),
        message: format!("create chroot: {e}"),
    })?;
    let chroot = Chroot {
        vm_dir,
        root,
        base: base.to_path_buf(),
        uid,
    };

    // Read-only images stay root-owned and world-readable; only the
    // directories Firecracker itself writes into are handed over.
    for dir in [IMG_SUBDIR, DISK_SUBDIR] {
        let path = chroot.root.join(dir);
        std::fs::create_dir(&path).map_err(|e| FcError::Stage {
            path: path.clone(),
            message: format!("create {dir} dir: {e}"),
        })?;
    }
    // Firecracker writes its snapshots as the jailed uid.
    let jail_snap = chroot.jail_snap_dir();
    std::fs::create_dir(&jail_snap).map_err(|e| FcError::Stage {
        path: jail_snap.clone(),
        message: format!("create {SNAP_SUBDIR} dir: {e}"),
    })?;
    chown(&jail_snap, uid)?;
    // k7d's bookkeeping stays root-owned, next to — not under — the jail.
    let snap = chroot.snap_dir();
    std::fs::create_dir(&snap).map_err(|e| FcError::Stage {
        path: snap.clone(),
        message: format!("create {SNAP_SUBDIR} dir: {e}"),
    })?;
    std::fs::set_permissions(&snap, std::fs::Permissions::from_mode(0o700)).map_err(|e| {
        FcError::Stage {
            path: snap.clone(),
            message: format!("chmod 0700: {e}"),
        }
    })?;

    stage_read_only(base, kernel, &chroot.root.join(super::CHROOT_KERNEL_NAME))?;
    if let Some(initrd) = initrd {
        stage_read_only(base, initrd, &chroot.root.join(super::CHROOT_INITRD_NAME))?;
    }

    // Firecracker binds its API socket and the vsock UDS under `run/`
    // as the unprivileged uid, so that directory — and only that
    // directory — is handed over.
    let run = chroot.root.join("run");
    std::fs::create_dir(&run).map_err(|e| FcError::Stage {
        path: run.clone(),
        message: format!("create run dir: {e}"),
    })?;
    chown(&run, uid)?;
    Ok(chroot)
}

/// Hard-link a read-only artifact at `src` to `dst` inside a chroot
/// under `base`, going through [`ro_cache_dir`] when the two are on
/// different filesystems.
///
/// Never a copy per VM: `dst` is always a link, either to `src` itself
/// or to this node's single cached copy of it. The cache exists because
/// the chroot base has to sit on the reflink XFS with the writable
/// disks (see [`chroot_base`]) while the guest kernel is installed on
/// the node's root filesystem, and `link(2)` will not cross that.
pub fn stage_read_only(base: &Path, src: &Path, dst: &Path) -> Result<(), FcError> {
    let src_meta = std::fs::metadata(src).map_err(|e| FcError::Stage {
        path: src.to_path_buf(),
        message: format!("stat read-only artifact: {e}"),
    })?;
    // A hard link is the same inode as the daemon's installed artifact,
    // so its mode cannot be changed here without changing the original.
    if src_meta.mode() & 0o004 == 0 {
        return Err(FcError::Stage {
            path: src.to_path_buf(),
            message: format!(
                "mode {:o} is not world-readable; jailed Firecracker runs as an \
                 unprivileged uid and would not be able to read it (chmod o+r it, \
                 not the staged link — the link shares this inode)",
                src_meta.mode() & 0o7777
            ),
        });
    }
    let dst_dir = dst.parent().unwrap_or(Path::new("/"));
    let dst_meta = std::fs::metadata(dst_dir).map_err(|e| FcError::Stage {
        path: dst_dir.to_path_buf(),
        message: format!("stat chroot dir: {e}"),
    })?;
    if src_meta.dev() == dst_meta.dev() {
        return link_same_fs(src, dst);
    }
    let cached = cache_read_only(base, src, &src_meta)?;
    match link_same_fs(&cached, dst) {
        // A concurrent [`sweep_ro_cache`] can unlink the entry between
        // the cache hit and the link — it saw a link count of 1 because
        // this VM had not taken its link yet. Re-copy once; an entry
        // that is missing a second time is a real failure.
        Err(_) if !cached.exists() => {
            log::info!(
                "fc: cache entry {} vanished under us, re-copying",
                cached.display()
            );
            let cached = cache_read_only(base, src, &src_meta)?;
            link_same_fs(&cached, dst)
        }
        other => other,
    }
}

/// Copy `src` into [`ro_cache_dir`] unless an entry for this exact
/// inode revision is already there, and return the cached path.
///
/// The copy goes to a unique temp name and is `rename(2)`d into place,
/// so two VMs staging the same image at once cannot observe a partial
/// file — the same discipline [`crate::erofs::build_erofs_image`] uses.
fn cache_read_only(
    base: &Path,
    src: &Path,
    src_meta: &std::fs::Metadata,
) -> Result<PathBuf, FcError> {
    let dir = ro_cache_dir(base);
    std::fs::create_dir_all(&dir).map_err(|e| FcError::Stage {
        path: dir.clone(),
        message: format!("create read-only staging cache: {e}"),
    })?;
    let key = format!(
        "{:x}-{:x}-{:x}-{:x}",
        src_meta.dev(),
        src_meta.ino(),
        src_meta.size(),
        src_meta.mtime_nsec().unsigned_abs() ^ src_meta.mtime().unsigned_abs(),
    );
    let entry = dir.join(&key);
    if entry.exists() {
        return Ok(entry);
    }
    let tmp = dir.join(format!(".{key}.tmp-{}", std::process::id()));
    let copy = copy_sparse(src, &tmp, src_meta.size()).map_err(|e| FcError::Stage {
        path: tmp.clone(),
        message: format!("copy {} onto the jail's filesystem: {e}", src.display()),
    });
    if let Err(e) = copy {
        let _ = std::fs::remove_file(&tmp);
        return Err(e);
    }
    // Readable by the jailed uid, writable by nobody: this entry is
    // hard-linked into jails owned by different uids at the same time.
    if let Err(e) = std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o444)) {
        let _ = std::fs::remove_file(&tmp);
        return Err(FcError::Stage {
            path: tmp,
            message: format!("chmod 0444: {e}"),
        });
    }
    if let Err(e) = std::fs::rename(&tmp, &entry) {
        let _ = std::fs::remove_file(&tmp);
        return Err(FcError::Stage {
            path: entry,
            message: format!("publish cache entry: {e}"),
        });
    }
    log::info!(
        "fc: cached {} on the jail filesystem as {}",
        src.display(),
        entry.display()
    );
    Ok(entry)
}

/// Copy `src` to `dst` one allocated extent at a time, leaving the
/// holes as holes.
///
/// `std::fs::copy` would read a hole back as zeroes and write them out,
/// which matters here because the biggest read-only "images" a
/// Firecracker pod stages are its **empty image slots**: the shim
/// declares them at the pod's slot capacity (2 GiB each by default) and
/// only fills them when a second container image turns up. Copying
/// those densely would write gigabytes of zeroes per pod before the
/// guest has booted.
fn copy_sparse(src: &Path, dst: &Path, len: u64) -> std::io::Result<()> {
    use std::io::{Seek, SeekFrom};

    let mut src_file = std::fs::File::open(src)?;
    let mut dst_file = std::fs::OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(dst)?;
    dst_file.set_len(len)?;

    let fd = src_file.as_raw_fd();
    let mut offset = 0i64;
    let end = i64::try_from(len).map_err(|_| {
        std::io::Error::new(std::io::ErrorKind::InvalidInput, "file larger than i64")
    })?;
    while offset < end {
        // SAFETY: `fd` is a live descriptor for the duration of the call.
        let data = unsafe { libc::lseek(fd, offset, libc::SEEK_DATA) };
        if data < 0 {
            // ENXIO means "no data at or after `offset`" — the rest of
            // the file is one trailing hole, already covered by set_len.
            let err = std::io::Error::last_os_error();
            if err.raw_os_error() == Some(libc::ENXIO) {
                break;
            }
            return Err(err);
        }
        // SAFETY: as above.
        let hole = unsafe { libc::lseek(fd, data, libc::SEEK_HOLE) };
        let hole = if hole < 0 {
            return Err(std::io::Error::last_os_error());
        } else {
            hole
        };
        src_file.seek(SeekFrom::Start(data.unsigned_abs()))?;
        dst_file.seek(SeekFrom::Start(data.unsigned_abs()))?;
        let span = (hole - data).unsigned_abs();
        std::io::copy(&mut (&mut src_file).take(span), &mut dst_file)?;
        offset = hole;
    }
    dst_file.sync_all()
}

/// Hard-link `src` to `dst`, naming both filesystems when they differ
/// instead of surfacing a bare `EXDEV` from `link(2)`.
fn link_same_fs(src: &Path, dst: &Path) -> Result<(), FcError> {
    let src_meta = std::fs::metadata(src).map_err(|e| FcError::Stage {
        path: src.to_path_buf(),
        message: format!("stat: {e}"),
    })?;
    let dst_dir = dst.parent().unwrap_or(Path::new("/"));
    let dst_meta = std::fs::metadata(dst_dir).map_err(|e| FcError::Stage {
        path: dst_dir.to_path_buf(),
        message: format!("stat chroot dir: {e}"),
    })?;
    if src_meta.dev() != dst_meta.dev() {
        return Err(FcError::CrossFilesystem {
            src: src.to_path_buf(),
            src_fs: fs_description(src),
            dst: dst_dir.to_path_buf(),
            dst_fs: fs_description(dst_dir),
        });
    }
    std::fs::hard_link(src, dst).map_err(|e| FcError::Stage {
        path: dst.to_path_buf(),
        message: format!("hard-link {}: {e}", src.display()),
    })
}

pub(super) fn chown(path: &Path, uid: u32) -> Result<(), FcError> {
    let c = std::ffi::CString::new(path.as_os_str().as_encoded_bytes()).map_err(|e| {
        FcError::Stage {
            path: path.to_path_buf(),
            message: format!("path has an interior NUL: {e}"),
        }
    })?;
    // SAFETY: `c` is a valid NUL-terminated path that outlives the call.
    let rc = unsafe { libc::chown(c.as_ptr(), uid, uid) };
    if rc != 0 {
        return Err(FcError::Stage {
            path: path.to_path_buf(),
            message: format!("chown to {uid}:{uid}: {}", std::io::Error::last_os_error()),
        });
    }
    Ok(())
}

/// `"<fs type> at <mount point>"` for the filesystem holding `path`, so
/// a cross-device staging failure names what to fix instead of leaving
/// the operator to work out which mount each path landed on.
fn fs_description(path: &Path) -> String {
    let Ok(mounts) = std::fs::read_to_string("/proc/mounts") else {
        return "unknown filesystem (/proc/mounts unreadable)".to_string();
    };
    let mut best: Option<(usize, String, String)> = None;
    for line in mounts.lines() {
        let mut f = line.split_whitespace();
        let (Some(_src), Some(mount_point), Some(fs_type)) = (f.next(), f.next(), f.next()) else {
            continue;
        };
        if path.starts_with(mount_point)
            && best.as_ref().is_none_or(|(n, _, _)| mount_point.len() > *n)
        {
            best = Some((
                mount_point.len(),
                mount_point.to_string(),
                fs_type.to_string(),
            ));
        }
    }
    best.map_or_else(
        || "unknown filesystem".to_string(),
        |(_, mount_point, fs_type)| format!("{fs_type} at {mount_point}"),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn uid_leases_are_unique_and_recycled() {
        let before = live_uid_count();
        let a = UidLease::acquire().expect("first uid");
        let b = UidLease::acquire().expect("second uid");
        assert_ne!(a.uid(), b.uid());
        assert_eq!(live_uid_count(), before + 2);
        let recycled = a.uid();
        drop(a);
        assert_eq!(live_uid_count(), before + 1);
        let c = UidLease::acquire().expect("recycled uid");
        assert_eq!(c.uid(), recycled, "a released uid must be reused");
        drop(b);
        drop(c);
        assert_eq!(live_uid_count(), before);
    }

    #[test]
    fn fs_description_names_the_root_filesystem() {
        let desc = fs_description(Path::new("/"));
        assert!(!desc.is_empty(), "{desc}");
        assert!(desc.contains("at /"), "{desc}");
    }

    /// Every pod declares its own image-slot backing files, so an
    /// un-swept cache would gain an entry per slot per pod forever.
    /// One that a jail still links must survive the same sweep.
    #[test]
    fn sweep_drops_unlinked_cache_entries_and_keeps_linked_ones() {
        let base = std::env::temp_dir().join(format!("k7d-fc-sweep-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&base);
        let dir = ro_cache_dir(&base);
        std::fs::create_dir_all(&dir).expect("cache dir");

        let orphan = dir.join("orphan");
        std::fs::write(&orphan, b"gone").expect("write orphan");
        let held = dir.join("held");
        std::fs::write(&held, b"kept").expect("write held");
        let jail_link = base.join("jail-link");
        std::fs::hard_link(&held, &jail_link).expect("link into a jail");
        // A copy in flight has one link too, and is not the sweep's.
        let tmp = dir.join(".inflight.tmp-1");
        std::fs::write(&tmp, b"partial").expect("write tmp");

        sweep_ro_cache(&base);

        assert!(!orphan.exists(), "an unlinked entry must be collected");
        assert!(held.exists(), "an entry a jail links must survive");
        assert!(tmp.exists(), "a copy in flight must not be collected");
        let _ = std::fs::remove_dir_all(&base);
    }

    /// An empty image slot is a multi-gigabyte hole. Staging it onto
    /// the jail's filesystem must move the hole, not two gigabytes of
    /// zeroes.
    #[test]
    fn copy_sparse_preserves_holes_and_data() {
        let dir = std::env::temp_dir().join(format!("k7d-fc-sparse-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("dir");
        let src = dir.join("src.img");
        let len = 512 * 1024 * 1024;
        {
            use std::io::{Seek, SeekFrom, Write};
            let mut f = std::fs::File::create(&src).expect("create");
            f.set_len(len).expect("truncate");
            f.seek(SeekFrom::Start(len - 8)).expect("seek");
            f.write_all(b"tailtail").expect("write tail");
        }
        let dst = dir.join("dst.img");
        copy_sparse(&src, &dst, len).expect("sparse copy");

        let dst_meta = std::fs::metadata(&dst).expect("stat dst");
        assert_eq!(dst_meta.len(), len, "apparent size must be preserved");
        assert!(
            dst_meta.blocks() * 512 < len / 4,
            "the copy allocated {} bytes for a {len}-byte hole",
            dst_meta.blocks() * 512
        );
        let copied = std::fs::read(&dst).expect("read dst");
        assert_eq!(&copied[copied.len() - 8..], b"tailtail");
        assert!(copied[..copied.len() - 8].iter().all(|b| *b == 0));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn stage_hard_links_and_refuses_a_reused_chroot() {
        let base = std::env::temp_dir().join(format!("k7d-fc-stage-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&base);
        std::fs::create_dir_all(&base).expect("base");
        let kernel = base.join("vmlinux-src");
        std::fs::write(&kernel, b"not really a kernel").expect("kernel");

        let uid = UidLease::acquire().expect("uid");
        let chroot = stage(&base, "firecracker", "vm-1", &kernel, None, uid.uid()).expect("stage");
        let staged = chroot.root().join(super::super::CHROOT_KERNEL_NAME);
        assert_eq!(
            std::fs::metadata(&staged).unwrap().ino(),
            std::fs::metadata(&kernel).unwrap().ino(),
            "the staged kernel must be a hard link, not a copy"
        );
        assert!(chroot.root().join("run").is_dir());

        let err = stage(&base, "firecracker", "vm-1", &kernel, None, uid.uid())
            .expect_err("a live chroot must not be reused");
        assert!(err.to_string().contains("already exists"), "{err}");

        let vm_dir = base.join("firecracker").join("vm-1");
        drop(chroot);
        assert!(!vm_dir.exists(), "drop must remove the chroot");
        let _ = std::fs::remove_dir_all(&base);
    }
}
