//! Block-backed kubelet volume translation.
//!
//! The successor to [`crate::volumes::PodVolumes`]' virtiofs shares:
//! every kubelet volume class a normal pod uses moves off virtiofs so
//! the pod carries **zero** vhost-user devices and stays on the `CoW`
//! warm-fork path.
//!
//! - **Read-only volumes** (`configmap`, `secret`, `downwardAPI`,
//!   `projected`): the materialized kubelet trees are staged into one
//!   directory and packed into a single erofs image via
//!   [`crate::erofs::cached_erofs_image`] with a **content-walk** cache
//!   key (kubelet rewrites these files in place on API-object updates,
//!   so the key must track content, not a path). The image is attached
//!   read-only through the userspace virtio-blk device and mounted by
//!   the agent at [`VM_VOLUMES_RO_MOUNT`].
//!
//!   **Loudly documented cut:** kubelet's atomic-symlink `ConfigMap` /
//!   Secret updates do NOT propagate into a packed image — the pod
//!   sees the volume contents as of sandbox Create. Acceptable for
//!   forkable pods (a fork's volumes are frozen anyway); logged as a
//!   warning at prepare time so the trade is visible per pod.
//!
//! - **emptyDir**: no host materialization at all. The OCI mount is
//!   rewritten to a guest tmpfs path under [`GUEST_EMPTYDIR_BASE`]
//!   that the agent creates at boot (`k7d.mkdir=` kernel cmdline
//!   param, see [`crate::vm::VmBuilder::guest_dir`]). All containers
//!   in the pod share the directory, and forks inherit its contents
//!   through the memory `CoW` for free.
//!
//! Writable *disk* volumes (k7d-provisioned RWO PVCs, emptyDir-on-
//! disk) are raw ext4 images created on the reflink-capable loopback
//! XFS ([`crate::disks`]) and attached read-write — `fork_warm`
//! reflinks them in O(1). They are provisioned by the caller (shim /
//! daemon) via [`crate::disks::create_ext4_volume`], not here: kubelet
//! has no materialized tree for them.

use std::path::{Path, PathBuf};

use crate::erofs::cached_erofs_image;
use crate::volumes::{classify_kubelet_plugin, MountRewriteMap, VolumeError};

/// In-VM mount point of the packed read-only volumes image. Same guest
/// path the virtiofs-era `pod-volumes-ro` share used, so container OCI
/// rewrites are indistinguishable to runc inside the guest.
pub const VM_VOLUMES_RO_MOUNT: &str = "/mnt/pod-volumes-ro";

/// Guest tmpfs base for emptyDir volumes. The guest agent creates
/// `<base>/<name>` at boot from the `k7d.mkdir=` cmdline param; the
/// guest rootfs (initramfs) is tmpfs, so nothing else is needed.
pub const GUEST_EMPTYDIR_BASE: &str = "/run/k7d/emptydir";

/// Block-backed translation of a pod's kubelet volumes.
///
/// Produced by [`Self::prepare`] at sandbox Create time; the caller
/// applies it to the VM build via [`Self::apply_to_builder`] and to
/// each workload's OCI spec via `rewrites.rewrite_oci_mounts`.
pub struct BlockVolumes {
    /// Packed erofs image holding every read-only kubelet volume, or
    /// `None` when the pod has none. Attach read-only; every fork
    /// shares the same backing file (zero copy).
    pub ro_image: Option<PathBuf>,
    /// Guest tmpfs directories to create at boot — one per emptyDir
    /// volume, `/run/k7d/emptydir/emptydir-<name>`.
    pub emptydir_guest_dirs: Vec<String>,
    /// Host source → in-VM path map for OCI spec rewriting (same
    /// mechanics as the virtiofs-era map).
    pub rewrites: MountRewriteMap,
}

impl BlockVolumes {
    /// Translate the kubelet volumes of pod `pod_uid` (scanning
    /// `/var/lib/kubelet/pods/<uid>/volumes/`), caching packed RO
    /// images under `cache_dir`.
    pub fn prepare(pod_uid: &str, cache_dir: &Path) -> Result<Self, VolumeError> {
        let kubelet_dir = PathBuf::from("/var/lib/kubelet/pods")
            .join(pod_uid)
            .join("volumes");
        if kubelet_dir.is_dir() {
            Self::prepare_from_kubelet_dir(&kubelet_dir, cache_dir)
        } else {
            log::debug!(
                "BlockVolumes::prepare: {} is not a directory; no kubelet volumes",
                kubelet_dir.display()
            );
            Ok(Self {
                ro_image: None,
                emptydir_guest_dirs: Vec::new(),
                rewrites: MountRewriteMap::default(),
            })
        }
    }

    /// Like [`Self::prepare`] but scans an explicit kubelet volumes
    /// directory (`<pod-dir>/volumes/` layout:
    /// `kubernetes.io~<plugin>/<name>/…`). Lets tests exercise the
    /// pipeline against a synthetic tree.
    pub fn prepare_from_kubelet_dir(
        kubelet_volumes_dir: &Path,
        cache_dir: &Path,
    ) -> Result<Self, VolumeError> {
        let mut out = Self {
            ro_image: None,
            emptydir_guest_dirs: Vec::new(),
            rewrites: MountRewriteMap::default(),
        };

        // Stage every RO volume tree into one directory, then pack it
        // once. Staged names reuse the virtiofs-era `<class>-<name>`
        // convention so in-VM paths line up with the old share layout.
        let staging = staging_root()?;
        let result = out.stage_and_pack(kubelet_volumes_dir, cache_dir, &staging);
        // The staging tree is scratch either way — the packed image is
        // the durable artifact.
        let _ = std::fs::remove_dir_all(&staging);
        result?;
        Ok(out)
    }

    fn stage_and_pack(
        &mut self,
        kubelet_volumes_dir: &Path,
        cache_dir: &Path,
        staging: &Path,
    ) -> Result<(), VolumeError> {
        let mut staged_ro = 0usize;
        for plugin_entry in std::fs::read_dir(kubelet_volumes_dir)? {
            let plugin_entry = plugin_entry?;
            let plugin_str = plugin_entry.file_name().to_string_lossy().to_string();
            let Some(class) = classify_kubelet_plugin(&plugin_str) else {
                // Unknown plugins (local-volume PVCs, CSI) are not
                // this module's problem: writable PVCs go through
                // `crate::disks` images, everything else stays on the
                // opt-in virtiofs slow path (PVC matrix).
                log::debug!("BlockVolumes: skipping kubelet plugin {plugin_str:?}");
                continue;
            };
            let plugin_dir = plugin_entry.path();
            if !plugin_dir.is_dir() {
                continue;
            }
            for vol_entry in std::fs::read_dir(&plugin_dir)? {
                let vol_entry = vol_entry?;
                let vol_path = vol_entry.path();
                if !vol_path.is_dir() {
                    continue;
                }
                let vol_name = vol_entry.file_name().to_string_lossy().to_string();
                let dest_name = format!("{}-{vol_name}", class.synthetic_prefix());
                if class.is_readonly() {
                    copy_tree(&vol_path, &staging.join(&dest_name))?;
                    self.rewrites.insert(
                        vol_path.clone(),
                        PathBuf::from(VM_VOLUMES_RO_MOUNT).join(&dest_name),
                        true,
                    );
                    staged_ro += 1;
                } else {
                    // emptyDir: guest tmpfs, nothing staged on the host.
                    let guest_dir = format!("{GUEST_EMPTYDIR_BASE}/{dest_name}");
                    self.rewrites
                        .insert(vol_path.clone(), PathBuf::from(&guest_dir), false);
                    self.emptydir_guest_dirs.push(guest_dir);
                }
            }
        }

        if staged_ro > 0 {
            // Content-walk key (`image_digest: None`): kubelet rewrites
            // configmap/secret files in place, so identity must follow
            // content.
            let image = cached_erofs_image(cache_dir, staging, None)?;
            log::warn!(
                "BlockVolumes: packed {staged_ro} read-only kubelet volume(s) into {} — \
                 ConfigMap/Secret updates after this point will NOT propagate into the \
                 pod (packed-image semantics)",
                image.display()
            );
            self.ro_image = Some(image);
        }
        Ok(())
    }

    /// Apply this translation to a VM build: attach the packed RO
    /// image (agent-mounted erofs at [`VM_VOLUMES_RO_MOUNT`]) and
    /// register every emptyDir guest tmpfs dir for boot-time creation.
    #[must_use]
    pub fn apply_to_builder(&self, mut builder: crate::vm::VmBuilder) -> crate::vm::VmBuilder {
        if let Some(img) = &self.ro_image {
            builder = builder.block_device_mounted(img, true, VM_VOLUMES_RO_MOUNT, "erofs");
        }
        for dir in &self.emptydir_guest_dirs {
            builder = builder.guest_dir(dir);
        }
        builder
    }
}

/// A fresh, root-only staging directory under
/// [`crate::disks::STAGE_DIR`]: `<pid>-<nanos>`, mode `0700`, with the
/// parent re-`chmod`ed to `0700` in case it pre-existed under a wider
/// umask. What is staged here is kubelet's Secret / projected-token
/// material, so the directory must never be traversable by anyone but
/// root for even the length of the pack (bug-candidates #57).
fn staging_root() -> Result<PathBuf, VolumeError> {
    use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
    let parent = PathBuf::from(crate::disks::STAGE_DIR);
    std::fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(&parent)?;
    std::fs::set_permissions(&parent, std::fs::Permissions::from_mode(0o700))?;
    let staging = parent.join(format!(
        "{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_nanos())
    ));
    std::fs::DirBuilder::new().mode(0o700).create(&staging)?;
    Ok(staging)
}

/// Recursively copy `src` into `dst` (created), preserving file and
/// directory modes and symlinks (kubelet's `..data` atomic-swap layout
/// is symlink-based; erofs packs symlinks natively so the tree stays
/// coherent read-only). Modes matter: a `0400` token stays `0400` in
/// staging and, since `mkfs.erofs` reads them from the tree, in the
/// image.
fn copy_tree(src: &Path, dst: &Path) -> Result<(), VolumeError> {
    use std::os::unix::fs::PermissionsExt;
    let src_meta = std::fs::metadata(src)?;
    std::fs::create_dir_all(dst)?;
    for entry in std::fs::read_dir(src)? {
        let entry = entry?;
        let from = entry.path();
        let to = dst.join(entry.file_name());
        let meta = from.symlink_metadata()?;
        if meta.file_type().is_symlink() {
            let target = std::fs::read_link(&from)?;
            std::os::unix::fs::symlink(target, &to)?;
        } else if meta.file_type().is_dir() {
            copy_tree(&from, &to)?;
        } else {
            // `fs::copy` carries the source's permission bits.
            std::fs::copy(&from, &to)?;
        }
    }
    // After the children: a read-only source directory must not stop
    // its own copy from being populated.
    std::fs::set_permissions(
        dst,
        std::fs::Permissions::from_mode(src_meta.permissions().mode() & 0o7777),
    )?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fake_kubelet_dir(root: &Path) -> PathBuf {
        let volumes = root.join("volumes");
        let cm = volumes.join("kubernetes.io~configmap/app-config");
        std::fs::create_dir_all(&cm).unwrap();
        // kubelet's atomic-swap layout: real files under a timestamped
        // dir, reached through the `..data` symlink.
        let ts = cm.join("..2026_08_07_00_00_00.0001");
        std::fs::create_dir_all(&ts).unwrap();
        std::fs::write(ts.join("greeting"), "hello-from-configmap").unwrap();
        std::os::unix::fs::symlink("..2026_08_07_00_00_00.0001", cm.join("..data")).unwrap();
        std::os::unix::fs::symlink("..data/greeting", cm.join("greeting")).unwrap();

        let secret = volumes.join("kubernetes.io~secret/creds");
        std::fs::create_dir_all(&secret).unwrap();
        std::fs::write(secret.join("api-key"), "sk-test").unwrap();

        let empty = volumes.join("kubernetes.io~empty-dir/scratch");
        std::fs::create_dir_all(&empty).unwrap();
        volumes
    }

    #[test]
    fn copy_tree_preserves_symlinks() {
        let src = tempfile::tempdir().unwrap();
        std::fs::write(src.path().join("real"), "x").unwrap();
        std::os::unix::fs::symlink("real", src.path().join("link")).unwrap();
        let dst = tempfile::tempdir().unwrap();
        let out = dst.path().join("copy");
        copy_tree(src.path(), &out).unwrap();
        assert_eq!(std::fs::read_to_string(out.join("link")).unwrap(), "x");
        assert!(out.join("link").symlink_metadata().unwrap().is_symlink());
    }

    #[test]
    fn prepare_classifies_ro_and_emptydir() {
        // Needs mkfs.erofs; present on the node (erofs-utils) and in
        // the dev container. The RO classes pack into one image, the
        // emptyDir gets a guest tmpfs rewrite and no host artifact.
        let pod = tempfile::tempdir().unwrap();
        let volumes = fake_kubelet_dir(pod.path());
        let cache = tempfile::tempdir().unwrap();

        let bv = BlockVolumes::prepare_from_kubelet_dir(&volumes, cache.path()).unwrap();

        let img = bv.ro_image.as_ref().expect("RO volumes must pack");
        assert!(img.exists());
        assert_eq!(std::fs::metadata(img).unwrap().len() % 512, 0);

        assert_eq!(
            bv.rewrites
                .translate(&volumes.join("kubernetes.io~configmap/app-config"))
                .as_deref(),
            Some(Path::new("/mnt/pod-volumes-ro/configmap-app-config"))
        );
        assert_eq!(
            bv.rewrites
                .translate(&volumes.join("kubernetes.io~secret/creds"))
                .as_deref(),
            Some(Path::new("/mnt/pod-volumes-ro/secret-creds"))
        );
        assert_eq!(
            bv.rewrites
                .translate(&volumes.join("kubernetes.io~empty-dir/scratch"))
                .as_deref(),
            Some(Path::new("/run/k7d/emptydir/emptydir-scratch"))
        );
        assert_eq!(
            bv.emptydir_guest_dirs,
            vec!["/run/k7d/emptydir/emptydir-scratch".to_string()]
        );

        // subPath-style translation still works through the map.
        assert_eq!(
            bv.rewrites
                .translate(&volumes.join("kubernetes.io~configmap/app-config/greeting"))
                .as_deref(),
            Some(Path::new(
                "/mnt/pod-volumes-ro/configmap-app-config/greeting"
            ))
        );
    }

    #[test]
    fn prepare_content_keyed_cache_tracks_updates() {
        // kubelet rewrites configmap files in place on updates; the
        // content-walk key must produce a NEW image for new content
        // (the old pod keeps its frozen image, a new pod sees the new
        // content).
        let pod = tempfile::tempdir().unwrap();
        let volumes = fake_kubelet_dir(pod.path());
        let cache = tempfile::tempdir().unwrap();

        let bv1 = BlockVolumes::prepare_from_kubelet_dir(&volumes, cache.path()).unwrap();
        let bv2 = BlockVolumes::prepare_from_kubelet_dir(&volumes, cache.path()).unwrap();
        assert_eq!(bv1.ro_image, bv2.ro_image, "same content must cache-hit");

        std::fs::write(
            volumes.join("kubernetes.io~secret/creds/api-key"),
            "sk-rotated",
        )
        .unwrap();
        let bv3 = BlockVolumes::prepare_from_kubelet_dir(&volumes, cache.path()).unwrap();
        assert_ne!(
            bv1.ro_image, bv3.ro_image,
            "changed volume content must produce a new image"
        );
    }

    #[test]
    fn staging_root_is_root_only_and_not_in_tmp() {
        use std::os::unix::fs::PermissionsExt;
        let staging = staging_root().expect("staging root");
        let parent = Path::new(crate::disks::STAGE_DIR);
        assert!(staging.starts_with(parent), "{}", staging.display());
        assert!(
            !staging.starts_with(std::env::temp_dir()),
            "staging must not be under {}",
            std::env::temp_dir().display()
        );
        for dir in [parent, staging.as_path()] {
            let mode = std::fs::metadata(dir).unwrap().permissions().mode() & 0o7777;
            assert_eq!(mode, 0o700, "{} is {mode:o}, not 0700", dir.display());
        }
        // A pre-existing parent that umask left wider is tightened.
        std::fs::set_permissions(parent, std::fs::Permissions::from_mode(0o755)).unwrap();
        let again = staging_root().expect("second staging root");
        assert_eq!(
            std::fs::metadata(parent).unwrap().permissions().mode() & 0o7777,
            0o700
        );
        std::fs::remove_dir_all(&staging).unwrap();
        std::fs::remove_dir_all(&again).unwrap();
    }

    /// kubelet keeps tokens at 0400; the copy into staging and the
    /// packed image must not widen that, and nothing may appear under
    /// /tmp while the pack runs (bug-candidates #57).
    #[test]
    fn prepare_keeps_0400_token_and_stages_nothing_in_tmp() {
        use std::os::unix::fs::PermissionsExt;
        let pod = tempfile::tempdir().unwrap();
        let volumes = fake_kubelet_dir(pod.path());
        let tok_dir = volumes.join("kubernetes.io~projected/kube-api-access-x");
        std::fs::create_dir_all(&tok_dir).unwrap();
        let tok = tok_dir.join("token");
        std::fs::write(&tok, "eyJhbGciOi").unwrap();
        std::fs::set_permissions(&tok, std::fs::Permissions::from_mode(0o400)).unwrap();
        let cache = tempfile::tempdir().unwrap();

        let stop = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let watcher = {
            let stop = stop.clone();
            std::thread::spawn(move || {
                let mut tmp_hits = Vec::new();
                let mut stage_modes = Vec::new();
                while !stop.load(std::sync::atomic::Ordering::SeqCst) {
                    for e in std::fs::read_dir(std::env::temp_dir()).unwrap().flatten() {
                        let name = e.file_name().to_string_lossy().into_owned();
                        if name.starts_with("k7d-volblk-stage-") {
                            tmp_hits.push(name);
                        }
                    }
                    if let Ok(entries) = std::fs::read_dir(crate::disks::STAGE_DIR) {
                        for e in entries.flatten() {
                            if let Ok(m) = e.metadata() {
                                stage_modes.push((e.path(), m.permissions().mode() & 0o7777));
                            }
                        }
                    }
                    std::thread::sleep(std::time::Duration::from_micros(200));
                }
                (tmp_hits, stage_modes)
            })
        };

        let bv = BlockVolumes::prepare_from_kubelet_dir(&volumes, cache.path()).unwrap();
        stop.store(true, std::sync::atomic::Ordering::SeqCst);
        let (tmp_hits, stage_modes) = watcher.join().unwrap();
        assert!(
            tmp_hits.is_empty(),
            "staging appeared under /tmp: {tmp_hits:?}"
        );
        for (path, mode) in &stage_modes {
            assert_eq!(*mode, 0o700, "{} was {mode:o} while staged", path.display());
        }
        let mine = format!("{}-", std::process::id());
        assert!(
            std::fs::read_dir(crate::disks::STAGE_DIR)
                .unwrap()
                .flatten()
                .all(|e| !e.file_name().to_string_lossy().starts_with(&mine)),
            "staging directory not removed after the pack"
        );

        // Mode inside the image: extract it with the modes erofs stored.
        let img = bv.ro_image.expect("RO volumes must pack");
        let out = tempfile::tempdir().unwrap();
        let extract = out.path().join("x");
        let fsck = crate::spawner::command("fsck.erofs")
            .arg(format!("--extract={}", extract.display()))
            .arg("--preserve-perms")
            .arg(&img)
            .output()
            .expect("fsck.erofs");
        assert!(
            fsck.status.success(),
            "fsck.erofs --extract: {}",
            String::from_utf8_lossy(&fsck.stderr)
        );
        let packed = extract.join("projected-kube-api-access-x/token");
        let mode = std::fs::metadata(&packed)
            .unwrap_or_else(|e| panic!("{}: {e}", packed.display()))
            .permissions()
            .mode()
            & 0o7777;
        assert_eq!(mode, 0o400, "token is {mode:o} inside the image");
    }

    #[test]
    fn prepare_emptydir_only_pod_has_no_image() {
        let pod = tempfile::tempdir().unwrap();
        let volumes = pod.path().join("volumes");
        std::fs::create_dir_all(volumes.join("kubernetes.io~empty-dir/cache")).unwrap();
        let cache = tempfile::tempdir().unwrap();
        let bv = BlockVolumes::prepare_from_kubelet_dir(&volumes, cache.path()).unwrap();
        assert!(bv.ro_image.is_none());
        assert_eq!(bv.emptydir_guest_dirs.len(), 1);
        assert_eq!(
            std::fs::read_dir(cache.path()).unwrap().count(),
            0,
            "no erofs image should be built for an emptyDir-only pod"
        );
    }
}
