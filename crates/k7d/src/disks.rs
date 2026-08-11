//! Loopback-XFS disk provisioning for writable volume images
//!.
//!
//! Warm forks clone a VM's read-write virtio-blk images with `FICLONE`
//! reflinks — O(1), never a byte copy (see `fork::reflink_file`). That
//! requires a reflink-capable filesystem, and the node's root FS is
//! ext4 on md RAID (no reflink). Rather than repartition, we provision
//! **one sparse XFS image** (`mkfs.xfs -m reflink=1`) loop-mounted at
//! [`DISKS_DIR`], and every writable volume image (emptyDir-on-disk,
//! k7d-provisioned RWO PVCs) is a raw ext4 image file created inside
//! it. Reflinking a fork's copy next to the source image stays on the
//! same filesystem, so `FICLONE` succeeds.
//!
//! Everything here fails loud per the internal notes: no reflink
//! support ⇒ error, never a silent full copy.

use std::os::fd::AsRawFd;
use std::path::{Path, PathBuf};
use std::process::Command;

/// Where writable raw volume images live on the host. Backed by the
/// loopback XFS provisioned by [`ensure_loopback_xfs`] (also done at
/// node-reset time by `your node provisioning`).
pub const DISKS_DIR: &str = "/var/lib/k7d/disks";

/// Default backing image for the loopback XFS behind [`DISKS_DIR`].
pub const DISKS_IMAGE: &str = "/var/lib/k7d/disks.img";

/// Default size of the sparse XFS backing image: 32 GiB. Sparse — real
/// disk usage grows with actual volume writes only.
pub const DISKS_IMAGE_SIZE: u64 = 32 * 1024 * 1024 * 1024;

/// Errors from disk provisioning. All loud, no fallbacks.
#[derive(Debug, thiserror::Error)]
pub enum DiskError {
    /// Filesystem operation failed.
    #[error("disks I/O at {path}: {err}")]
    Io {
        /// Path the operation touched.
        path: PathBuf,
        /// Underlying error.
        err: std::io::Error,
    },
    /// An external command (`mkfs.xfs`, `mkfs.ext4`, `mount`) failed.
    #[error("{cmd} failed: {stderr}")]
    Command {
        /// The command that failed.
        cmd: String,
        /// Captured stderr.
        stderr: String,
    },
    /// The directory is not on a reflink-capable filesystem.
    #[error(
        "{dir} is not reflink-capable (FICLONE probe failed: {probe}) — \
         writable volume images require reflink for O(1) warm forks; \
         provision the loopback XFS (`ensure_loopback_xfs`, see \
         internal notes / your node provisioning)"
    )]
    NoReflink {
        /// The directory that failed the probe.
        dir: PathBuf,
        /// The FICLONE errno.
        probe: String,
    },
}

fn io_err(path: &Path, err: std::io::Error) -> DiskError {
    DiskError::Io {
        path: path.to_path_buf(),
        err,
    }
}

fn run(cmd: &str, args: &[&str]) -> Result<(), DiskError> {
    let output = Command::new(cmd)
        .args(args)
        .output()
        .map_err(|e| io_err(Path::new(cmd), e))?;
    if !output.status.success() {
        return Err(DiskError::Command {
            cmd: format!("{cmd} {}", args.join(" ")),
            stderr: String::from_utf8_lossy(&output.stderr).trim().to_string(),
        });
    }
    Ok(())
}

/// Probe whether `dir` supports `FICLONE` reflinks by cloning a tiny
/// scratch file onto a sibling. Returns `Ok(())` on support, loud
/// [`DiskError::NoReflink`] otherwise. Both probe files are removed.
pub fn assert_reflink_capable(dir: &Path) -> Result<(), DiskError> {
    let seq = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.subsec_nanos());
    let src = dir.join(format!(".reflink-probe-src-{}-{seq}", std::process::id()));
    let dst = dir.join(format!(".reflink-probe-dst-{}-{seq}", std::process::id()));
    let result = (|| {
        std::fs::write(&src, b"probe").map_err(|e| io_err(&src, e))?;
        // FICLONE requires the source fd open for reading (EBADF otherwise).
        let f = std::fs::File::open(&src).map_err(|e| io_err(&src, e))?;
        let d = std::fs::File::create(&dst).map_err(|e| io_err(&dst, e))?;
        // SAFETY: both fds are valid for the duration of the call; FICLONE
        // takes the source fd as its integer argument.
        let rc = unsafe { libc::ioctl(d.as_raw_fd(), libc::FICLONE, f.as_raw_fd()) };
        if rc < 0 {
            return Err(DiskError::NoReflink {
                dir: dir.to_path_buf(),
                probe: std::io::Error::last_os_error().to_string(),
            });
        }
        Ok(())
    })();
    let _ = std::fs::remove_file(&src);
    let _ = std::fs::remove_file(&dst);
    result
}

/// Ensure a reflink-capable (`reflink=1`) XFS is loop-mounted at
/// `mount_point`, provisioning a sparse backing image at `image` on
/// first use. Idempotent: an already-mounted, reflink-capable
/// `mount_point` returns immediately.
///
/// Node resets run the same provisioning from
/// `your node provisioning` (plus an `/etc/fstab` entry so the
/// mount survives reboots); this function is the programmatic
/// equivalent that integration tests and the daemon can call to
/// self-provision. Requires root (mount).
pub fn ensure_loopback_xfs(
    image: &Path,
    mount_point: &Path,
    size_bytes: u64,
) -> Result<(), DiskError> {
    std::fs::create_dir_all(mount_point).map_err(|e| io_err(mount_point, e))?;
    if is_mounted(mount_point)? {
        // Already mounted — but never trust it silently: the whole
        // point is reflink, so verify or fail loud.
        return assert_reflink_capable(mount_point);
    }

    if !image.exists() {
        if let Some(parent) = image.parent() {
            std::fs::create_dir_all(parent).map_err(|e| io_err(parent, e))?;
        }
        let f = std::fs::File::create(image).map_err(|e| io_err(image, e))?;
        f.set_len(size_bytes).map_err(|e| io_err(image, e))?;
        drop(f);
        // reflink=1 is the default on modern mkfs.xfs but we pass it
        // explicitly — it is the reason this filesystem exists.
        if let Err(e) = run(
            "mkfs.xfs",
            &["-q", "-m", "reflink=1", &image.to_string_lossy()],
        ) {
            let _ = std::fs::remove_file(image);
            return Err(e);
        }
        log::info!(
            "disks: created sparse XFS image {} ({} GiB, reflink=1)",
            image.display(),
            size_bytes / (1024 * 1024 * 1024)
        );
    }

    run(
        "mount",
        &[
            "-o",
            "loop",
            &image.to_string_lossy(),
            &mount_point.to_string_lossy(),
        ],
    )?;
    log::info!(
        "disks: loop-mounted {} at {}",
        image.display(),
        mount_point.display()
    );
    assert_reflink_capable(mount_point)
}

/// Create a raw ext4 volume image of `size_bytes` at `dir/name`,
/// for attaching to a guest via
/// [`crate::vm::VmBuilder::block_device_mounted`] (`fstype = "ext4"`).
///
/// `dir` must be reflink-capable ([`assert_reflink_capable`]) — a
/// writable image that cannot be reflinked would silently force every
/// warm fork onto the fail-loud `FICLONE` error path, so we refuse to
/// create it in the wrong place at all. `size_bytes` is rounded up to
/// a 512-byte multiple (the virtio-blk sector size). The image is
/// sparse: real blocks are allocated as the guest writes.
pub fn create_ext4_volume(dir: &Path, name: &str, size_bytes: u64) -> Result<PathBuf, DiskError> {
    assert_reflink_capable(dir)?;
    let path = dir.join(name);
    let padded = size_bytes.div_ceil(crate::block::SECTOR_SIZE) * crate::block::SECTOR_SIZE;
    let f = std::fs::File::create(&path).map_err(|e| io_err(&path, e))?;
    f.set_len(padded).map_err(|e| io_err(&path, e))?;
    drop(f);
    if let Err(e) = run("mkfs.ext4", &["-F", "-q", &path.to_string_lossy()]) {
        let _ = std::fs::remove_file(&path);
        return Err(e);
    }
    log::info!(
        "disks: created ext4 volume image {} ({} MiB)",
        path.display(),
        padded / (1024 * 1024)
    );
    Ok(path)
}

/// Idempotent [`create_ext4_volume`]: when
/// `dir/name` already exists it is returned as-is — this is the
/// "PVC outlives the pod" semantic for k7d-provisioned RWO volumes
/// (a pod restart reattaches the same image with its data intact).
/// Only a missing image is created and formatted.
pub fn ensure_ext4_volume(dir: &Path, name: &str, size_bytes: u64) -> Result<PathBuf, DiskError> {
    let path = dir.join(name);
    if path.exists() {
        log::info!(
            "disks: reusing existing ext4 volume image {}",
            path.display()
        );
        return Ok(path);
    }
    create_ext4_volume(dir, name, size_bytes)
}

/// Whether `mount_point` is currently a mount point (an entry in
/// `/proc/mounts` names it exactly).
fn is_mounted(mount_point: &Path) -> Result<bool, DiskError> {
    let mounts = std::fs::read_to_string("/proc/mounts")
        .map_err(|e| io_err(Path::new("/proc/mounts"), e))?;
    let want = mount_point.to_string_lossy();
    Ok(mounts
        .lines()
        .filter_map(|l| l.split_whitespace().nth(1))
        .any(|mp| mp == want))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reflink_probe_fails_loud_on_tmpfs_or_ext4() {
        // The build/test hosts run /tmp on tmpfs or ext4 — neither
        // supports FICLONE, so the probe must fail with the loud
        // NoReflink error (naming the dir), never a silent pass.
        let dir = tempfile::tempdir().unwrap();
        match assert_reflink_capable(dir.path()) {
            Err(DiskError::NoReflink { dir: d, .. }) => assert_eq!(d, dir.path()),
            Ok(()) => {
                // A dev box with /tmp on btrfs/XFS legitimately passes;
                // nothing to assert beyond "no probe files leak".
            }
            Err(other) => panic!("expected NoReflink, got {other}"),
        }
        assert_eq!(
            std::fs::read_dir(dir.path()).unwrap().count(),
            0,
            "probe files must not leak"
        );
    }

    #[test]
    fn create_ext4_volume_refuses_non_reflink_dir() {
        let dir = tempfile::tempdir().unwrap();
        if assert_reflink_capable(dir.path()).is_ok() {
            // Reflink-capable tmp: the refusal path can't be exercised
            // here; covered by the loud error type test above.
            return;
        }
        let err = create_ext4_volume(dir.path(), "vol.img", 8 * 1024 * 1024).unwrap_err();
        assert!(
            matches!(err, DiskError::NoReflink { .. }),
            "must refuse to create a writable image on a non-reflink fs, got {err}"
        );
        assert!(!dir.path().join("vol.img").exists());
    }

    #[test]
    fn is_mounted_detects_root() {
        assert!(is_mounted(Path::new("/")).unwrap());
        assert!(!is_mounted(Path::new("/definitely-not-a-mount-point-k7d")).unwrap());
    }
}
