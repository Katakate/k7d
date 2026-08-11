//! Host-side erofs image pipeline.
//!
//! Turns a container's resolved rootfs directory into an immutable
//! read-only erofs disk image via `mkfs.erofs`, cached per image
//! identity under [`DEFAULT_CACHE_DIR`]. The image is attached to the
//! guest read-only through the userspace virtio-blk device
//! ([`crate::block`]) and mounted by the agent per the `k7d.blk=`
//! kernel cmdline param; the container rootfs becomes
//! `overlay(lower=erofs, upper+work=tmpfs)` in the guest.
//!
//! Cache identity: the caller's image digest when it has one (the
//! containerd path), else a SHA-256 content walk of the source
//! directory. Concurrent builders never corrupt the cache — every
//! build goes to a temp name in the destination directory and is
//! `rename(2)`d into place atomically.

use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};

use sha2::{Digest, Sha256};

/// Default digest-keyed erofs image cache directory on the host.
pub const DEFAULT_CACHE_DIR: &str = "/var/lib/k7d/images";

/// Uniquifies concurrent temp-file names within this process.
static TMP_SEQ: AtomicU64 = AtomicU64::new(0);

/// Errors from the erofs image pipeline. All loud, no fallbacks.
#[derive(Debug, thiserror::Error)]
pub enum ErofsError {
    /// `mkfs.erofs` is not installed on the host.
    #[error(
        "mkfs.erofs not found — install erofs-utils on the node \
         (`apt-get install -y erofs-utils`): {0}"
    )]
    MkfsMissing(std::io::Error),
    /// `mkfs.erofs` ran but failed.
    #[error("mkfs.erofs of {dir} failed: {stderr}")]
    MkfsFailed {
        /// Source rootfs directory that was being packed.
        dir: PathBuf,
        /// Captured stderr from `mkfs.erofs`.
        stderr: String,
    },
    /// Filesystem operation failed.
    #[error("erofs pipeline I/O at {path}: {err}")]
    Io {
        /// Path the operation touched.
        path: PathBuf,
        /// Underlying error.
        err: std::io::Error,
    },
}

fn io_err(path: &Path, err: std::io::Error) -> ErofsError {
    ErofsError::Io {
        path: path.to_path_buf(),
        err,
    }
}

/// Pack `rootfs_dir` into an erofs image at `out_path`.
///
/// Builds to a unique temp name in `out_path`'s directory, pads the
/// image to a 512-byte multiple (the virtio-blk sector size — erofs'
/// 4 KiB block size already satisfies this, the pad is defensive), and
/// `rename(2)`s into place, so concurrent builders of the same image
/// race benignly: last rename wins with identical content, and no
/// reader ever observes a half-written file.
pub fn build_erofs_image(rootfs_dir: &Path, out_path: &Path) -> Result<(), ErofsError> {
    let dir = out_path
        .parent()
        .ok_or_else(|| io_err(out_path, std::io::Error::other("output path has no parent")))?;
    std::fs::create_dir_all(dir).map_err(|e| io_err(dir, e))?;

    let tmp = dir.join(format!(
        ".{}.tmp-{}-{}",
        out_path
            .file_name()
            .map_or_else(|| "img".into(), |n| n.to_string_lossy()),
        std::process::id(),
        TMP_SEQ.fetch_add(1, Ordering::SeqCst)
    ));

    let result = (|| {
        let output = Command::new("mkfs.erofs")
            .arg(&tmp)
            .arg(rootfs_dir)
            .output()
            .map_err(|e| {
                if e.kind() == std::io::ErrorKind::NotFound {
                    ErofsError::MkfsMissing(e)
                } else {
                    io_err(Path::new("mkfs.erofs"), e)
                }
            })?;
        if !output.status.success() {
            return Err(ErofsError::MkfsFailed {
                dir: rootfs_dir.to_path_buf(),
                stderr: String::from_utf8_lossy(&output.stderr).to_string(),
            });
        }
        let len = std::fs::metadata(&tmp).map_err(|e| io_err(&tmp, e))?.len();
        let padded = len.div_ceil(crate::block::SECTOR_SIZE) * crate::block::SECTOR_SIZE;
        if padded != len {
            let f = std::fs::OpenOptions::new()
                .write(true)
                .open(&tmp)
                .map_err(|e| io_err(&tmp, e))?;
            f.set_len(padded).map_err(|e| io_err(&tmp, e))?;
        }
        std::fs::rename(&tmp, out_path).map_err(|e| io_err(out_path, e))?;
        Ok(())
    })();
    if result.is_err() {
        let _ = std::fs::remove_file(&tmp);
    }
    result
}

/// Return the cached erofs image for `rootfs_dir` under `cache_dir`,
/// building it with [`build_erofs_image`] on a cache miss.
///
/// The cache key is `image_digest` when the caller has one (e.g. the
/// containerd image digest — the same content re-keyed by digest never
/// rebuilds), else a SHA-256 content walk of the source directory
/// (paths, modes, symlink targets, file contents).
pub fn cached_erofs_image(
    cache_dir: &Path,
    rootfs_dir: &Path,
    image_digest: Option<&str>,
) -> Result<PathBuf, ErofsError> {
    let key = match image_digest {
        Some(d) => sanitize_digest(d),
        None => hash_rootfs_dir(rootfs_dir)?,
    };
    let image = cache_dir.join(format!("{key}.erofs"));
    if image.exists() {
        log::info!(
            "erofs cache hit: {} -> {}",
            rootfs_dir.display(),
            image.display()
        );
        return Ok(image);
    }
    build_erofs_image(rootfs_dir, &image)?;
    log::info!(
        "erofs cache build: {} -> {}",
        rootfs_dir.display(),
        image.display()
    );
    Ok(image)
}

/// Derive a stable cache key from an opaque snapshot identity string
/// (internal notes: the shim keys container rootfs images by the
/// containerd overlayfs `lowerdir` chain — stable per image on a
/// node — instead of re-walking hundreds of MB of rootfs per pod).
#[must_use]
pub fn snapshot_cache_key(ident: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(ident.as_bytes());
    format!("snap-{:x}", hasher.finalize())
}

/// Make an image digest safe to use as a file name (`sha256:abc…` →
/// `sha256-abc…`).
fn sanitize_digest(digest: &str) -> String {
    digest
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() { c } else { '-' })
        .collect()
}

/// SHA-256 content walk of a rootfs directory: relative paths (sorted),
/// file modes, symlink targets, and regular-file contents all feed the
/// hash, so any content change produces a different cache key.
fn hash_rootfs_dir(root: &Path) -> Result<String, ErofsError> {
    let mut hasher = Sha256::new();
    let mut stack = vec![root.to_path_buf()];
    while let Some(dir) = stack.pop() {
        let mut entries: Vec<PathBuf> = std::fs::read_dir(&dir)
            .map_err(|e| io_err(&dir, e))?
            .map(|e| e.map(|e| e.path()))
            .collect::<Result<_, _>>()
            .map_err(|e| io_err(&dir, e))?;
        entries.sort();
        for path in entries {
            let meta = path.symlink_metadata().map_err(|e| io_err(&path, e))?;
            let rel = path.strip_prefix(root).expect("entry under root");
            hasher.update(rel.as_os_str().as_encoded_bytes());
            hasher.update([0u8]);
            {
                use std::os::unix::fs::MetadataExt;
                hasher.update(meta.mode().to_le_bytes());
            }
            if meta.file_type().is_symlink() {
                let target = std::fs::read_link(&path).map_err(|e| io_err(&path, e))?;
                hasher.update(b"l");
                hasher.update(target.as_os_str().as_encoded_bytes());
            } else if meta.file_type().is_dir() {
                hasher.update(b"d");
                stack.push(path);
            } else {
                hasher.update(b"f");
                hasher.update(meta.len().to_le_bytes());
                let mut f = std::fs::File::open(&path).map_err(|e| io_err(&path, e))?;
                let mut buf = vec![0u8; 64 * 1024];
                loop {
                    let n = f.read(&mut buf).map_err(|e| io_err(&path, e))?;
                    if n == 0 {
                        break;
                    }
                    hasher.update(&buf[..n]);
                }
            }
            hasher.update([0u8]);
        }
    }
    Ok(format!("walk-{:x}", hasher.finalize()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn digest_sanitized_for_filenames() {
        assert_eq!(sanitize_digest("sha256:ab/12"), "sha256-ab-12");
    }

    #[test]
    fn content_walk_hash_tracks_content() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(dir.path().join("sub")).unwrap();
        std::fs::write(dir.path().join("sub/a.txt"), "one").unwrap();
        std::os::unix::fs::symlink("a.txt", dir.path().join("sub/link")).unwrap();

        let h1 = hash_rootfs_dir(dir.path()).unwrap();
        let h2 = hash_rootfs_dir(dir.path()).unwrap();
        assert_eq!(h1, h2, "hash must be deterministic");

        std::fs::write(dir.path().join("sub/a.txt"), "two").unwrap();
        let h3 = hash_rootfs_dir(dir.path()).unwrap();
        assert_ne!(h1, h3, "content change must change the hash");

        // Symlink target changes are identity changes too.
        std::fs::remove_file(dir.path().join("sub/link")).unwrap();
        std::os::unix::fs::symlink("b.txt", dir.path().join("sub/link")).unwrap();
        let h4 = hash_rootfs_dir(dir.path()).unwrap();
        assert_ne!(h3, h4, "symlink target change must change the hash");
    }
}
