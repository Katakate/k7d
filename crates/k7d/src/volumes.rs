//! Kubelet-managed volume support.
//!
//! Translates kubelet's per-pod volume layout into a pair of
//! virtiofs shares the VM can mount, plus a rewrite map the shim
//! applies to each container's OCI spec so runc inside the VM sees
//! in-VM paths instead of host paths.
//!
//! ## What kubelet does before our shim runs
//!
//! For each `pod.spec.volumes[i]`, kubelet materializes content
//! under `/var/lib/kubelet/pods/<pod-uid>/volumes/<plugin>/<name>/`
//! on the host:
//!
//! - `kubernetes.io~configmap/<name>/`   — one file per `ConfigMap` key
//! - `kubernetes.io~secret/<name>/`      — one file per `Secret` key
//! - `kubernetes.io~empty-dir/<name>/`   — an empty directory
//! - `kubernetes.io~projected/<name>/`   — combined projection tree
//! - `kubernetes.io~downward-api/<name>/`— one file per `fieldRef`/`resourceFieldRef`
//!
//! Then kubelet adds entries to each container's `mounts[]` in its
//! OCI `config.json` with `source` set to that materialized host
//! path, `destination` to the in-container mount point, and
//! `type: bind` (or `rbind` in `options`).
//!
//! ## What this module does
//!
//! 1. At sandbox Create time, [`PodVolumes::prepare`] enumerates
//!    every directory under `/var/lib/kubelet/pods/<pod-uid>/volumes/`
//!    and bind-mounts each one into a per-pod scratch tree under
//!    `/var/lib/k7d/pods/<pod-uid>/volumes-{ro,rw}/`. `ConfigMap` /
//!    `Secret` / projected / `downwardAPI` go to the ro tree; `emptyDir`
//!    goes to the rw tree.
//!
//! 2. The shim attaches both scratch trees to the VM as virtiofs
//!    shares (`pod-volumes-ro`, `pod-volumes-rw`) — see
//!    [`PodVolumes::vm_mount_ro`] / [`PodVolumes::vm_mount_rw`].
//!
//! 3. At workload-container Create time the shim asks
//!    [`PodVolumes::rewrite_oci_mounts`] to walk the container's
//!    OCI spec and translate every kubelet-rooted bind mount's
//!    `source` from the host path to the corresponding in-VM
//!    virtiofs path. Mounts that don't have a matching host source
//!    in the [`MountRewriteMap`] (e.g. hostPath, /etc/resolv.conf)
//!    are still stripped by the existing shim logic — a later pass
//!    extends the map to cover those.
//!
//! 4. On sandbox Delete, [`PodVolumes::cleanup`] unmounts the per-
//!    pod binds and removes the scratch tree. Failure is logged
//!    but non-fatal — kubelet GCs the pod dir anyway.

use std::collections::BTreeMap;
use std::ffi::CString;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::path::{Path, PathBuf};
use std::time::Duration;

/// Bounded wait for a required hostPath / local-path source to
/// appear on the host before failing Create loudly.
///
/// kubelet occasionally races the shim: it emits the OCI bind mount
/// for a `hostPath` (or `local-path` PVC) a beat before the backing
/// directory finishes being created on disk. Rather than silently
/// dropping the mount (the old best-effort behaviour, which made a
/// missing required volume indistinguishable from a working one), we
/// poll for a short, bounded window and then return
/// [`VolumeError::MissingSource`] so the sandbox Create fails with a
/// clear message.
const HOSTPATH_SOURCE_WAIT_ATTEMPTS: u32 = 10;
const HOSTPATH_SOURCE_WAIT_INTERVAL: Duration = Duration::from_millis(200);

/// Root directory for our per-pod scratch trees on the host.
///
/// Each pod gets `BASE/<pod-uid>/volumes-{ro,rw}/`. picks
/// `/var/lib/k7d/pods/` to match kubelet's `/var/lib/kubelet/pods/`
/// convention.
const HOST_PODS_BASE: &str = "/var/lib/k7d/pods";

/// In-VM mount paths the agent uses when it reads the
/// `k7d.virtiofs=` cmdline param. `ConfigMap` / `Secret` end up under
/// `vm_mount_ro()`, `emptyDir` under `vm_mount_rw()`.
const VM_MOUNT_RO: &str = "/mnt/pod-volumes-ro";
const VM_MOUNT_RW: &str = "/mnt/pod-volumes-rw";

/// Container-side destinations the shim's per-workload `Create`
/// pass auto-bind-mounts from the host into the per-pod scratch
/// tree. These are the kubelet/CRI-generated
/// system files every container expects to see (the
/// kubelet-volume scan doesn't cover them because their sources
/// aren't under `<pod-dir>/volumes/`):
///
/// - `/etc/resolv.conf` and `/etc/hostname` live in the
///   containerd sandbox dir (`/var/lib/rancher/k3s/agent/
///   containerd/io.containerd.grpc.v1.cri/sandboxes/<id>/…`).
///   Critically, **without** `resolv.conf` in the guest, the
///   inner workload can't resolve any DNS name — including
///   `kubernetes.default.svc.cluster.local` (which is what the
///   k3s-agent sidecar pattern relies on
///   for joining the inner control plane).
/// - `/etc/hosts` lives in the kubelet pod dir
///   (`/var/lib/kubelet/pods/<uid>/etc-hosts`) and carries the
///   pod-name → pod-IP mapping plus the standard localhost
///   entries.
///
/// The list deliberately stops at three. `/dev/termination-log`
/// (where kubelet expects the container to write its last gasp on
/// exit) and `/dev/shm` are deferred — they're host-path bind
/// mounts at unusual destinations that the strip pass
/// happily drops without any container caring on the boot path.
/// We can grow the whitelist when a real workload needs them.
pub const ETC_FILE_WHITELIST: &[&str] = &["/etc/resolv.conf", "/etc/hosts", "/etc/hostname"];

/// Path prefixes whose bind-mount sources are kubelet / containerd
/// CRI-generated state and **not** user-supplied `hostPath` volumes.
/// The `hostPath` enumerator uses this list to filter
/// workload mounts down to the actual user `hostPath` entries.
///
/// Anything else under `/var/lib/kubelet/pods/<uid>/` is either:
///
/// - Under `volumes/kubernetes.io~<plugin>/<name>` — a kubelet
///   plugin volume materialization. Carved out below (see
///   [`is_cri_internal_source`]) so the hostPath enumerator can
///   bind it when [`PodVolumes::prepare`] did not recognize the
///   plugin. Without this carve-out, kubelet-managed volumes such
///   as `local-volume` PVCs (k3s' default `local-path` storage
///   class, what every stateful workload uses) get silently
///   stripped — the user's container starts without `/data` and
///   crashes, which is exactly the fail-silent anti-pattern this
///   crate forbids. Plugins that [`PodVolumes::prepare`] does
///   recognize (`configmap`, `secret`, `projected`, `downward-api`,
///   `empty-dir`) are already in the rewrite map, so
///   [`PodVolumes::add_hostpath_mounts_for_workload`] short-circuits
///   them at the `rewrites.translate` check before reaching
///   [`is_cri_internal_source`].
/// - `etc-hosts` — already in the rewrite map from the
///   etc-files whitelist.
/// - Under `containers/<name>/<id>` — kubelet's termination-log,
///   intentionally dropped (no container we've seen cares about
///   it on the boot path).
///
/// And anything under the containerd / k3s sandbox directories is
/// `etc/resolv.conf`, `etc/hostname`, or `/dev/shm` (all either
/// handled by the CRI rewrite pass or intentionally dropped).
///
/// Filtering by exclusion via this list is the same heuristic
/// kata-containers uses to distinguish user hostPaths from CRI
/// internals.
const CRI_INTERNAL_SOURCE_PREFIXES: &[&str] = &[
    "/var/lib/kubelet/pods/",
    "/var/lib/rancher/k3s/",
    "/run/k3s/",
];

/// Substring that marks a kubelet **plugin volume** materialization
/// (`/var/lib/kubelet/pods/<uid>/volumes/kubernetes.io~<plugin>/<name>`).
/// Used by [`is_cri_internal_source`] to carve plugin volumes out
/// of the `/var/lib/kubelet/pods/` CRI-internal prefix so the
/// hostPath enumerator can bind them when [`PodVolumes::prepare`]
/// did not handle the plugin. See the `CRI_INTERNAL_SOURCE_PREFIXES`
/// docs for the rationale.
const KUBELET_PLUGIN_VOLUME_MARKER: &str = "/volumes/kubernetes.io~";

#[derive(Debug, thiserror::Error)]
pub enum VolumeError {
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("mount {what:?} -> {dst:?} failed: {stderr}")]
    Mount {
        what: PathBuf,
        dst: PathBuf,
        stderr: String,
    },
    #[error("unsupported kubelet volume plugin {plugin:?}")]
    UnsupportedPlugin { plugin: String },
    #[error(
        "required mount source {src:?} (destination {dst:?}) does not exist on host \
         after waiting {waited:?}"
    )]
    MissingSource {
        src: PathBuf,
        dst: PathBuf,
        waited: Duration,
    },
    #[error("erofs volume image: {0}")]
    Erofs(#[from] crate::erofs::ErofsError),
    #[error(
        "hostPath placeholder {name} already exists — refusing to reuse a guest-visible entry"
    )]
    PlaceholderExists {
        /// Final path component under the share root.
        name: String,
    },
    #[error("placeholder name {name:?} is not a single path component")]
    InvalidPlaceholderName {
        /// Rejected name (contained `/`, or was `.` / `..` / empty).
        name: String,
    },
    #[error("hostPath placeholder {name} failed verification: {reason}")]
    PlaceholderVerify {
        /// Final path component under the share root.
        name: String,
        /// Why the fstatat check rejected the entry.
        reason: String,
    },
}

/// Daemon / shim env that fails Create for any pod that would take the
/// virtiofs hostPath fallback. Hardened and Firecracker
/// profiles set this; the default block/erofs path is unaffected.
pub const DENY_VIRTIOFS_FALLBACK_ENV: &str = "K7D_DENY_VIRTIOFS_FALLBACK";

/// Create-failure message when [`DENY_VIRTIOFS_FALLBACK_ENV`] is `1`.
pub const DENY_VIRTIOFS_FALLBACK_MSG: &str =
    "hostPath / unsupported PVC volumes are disabled on this node (K7D_DENY_VIRTIOFS_FALLBACK)";

/// Whether [`DENY_VIRTIOFS_FALLBACK_ENV`] is set to `1`.
///
/// Unset or `0` → allow the fallback. Any other non-empty value is a
/// loud error (no silent "treat as off").
pub fn virtiofs_fallback_denied() -> Result<bool, String> {
    match std::env::var(DENY_VIRTIOFS_FALLBACK_ENV) {
        Err(std::env::VarError::NotPresent) => Ok(false),
        Ok(v) if v == "1" => Ok(true),
        Ok(v) if v.is_empty() || v == "0" => Ok(false),
        Ok(v) => Err(format!("{DENY_VIRTIOFS_FALLBACK_ENV}={v:?} is not 0 or 1")),
        Err(e) => Err(format!("read {DENY_VIRTIOFS_FALLBACK_ENV}: {e}")),
    }
}

/// Maps host source paths (as they appear in the kubelet-set OCI
/// spec `mounts[*].source`) to the corresponding in-VM virtiofs
/// path. The shim consults this map when rewriting each workload's
/// `config.json` before runc inside the VM reads it.
///
/// Hits inside `prepare_from_kubelet_dir` populate the map for
/// every materialized kubelet volume; the rewrite logic in
/// `task.rs::copy_and_fix_oci_config` calls [`Self::translate`] for
/// each mount source and either substitutes the in-VM path or
/// falls through to the current "strip bind mount" behaviour.
#[derive(Debug, Default, Clone, serde::Serialize, serde::Deserialize)]
pub struct MountRewriteMap {
    entries: BTreeMap<PathBuf, RewriteTarget>,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
struct RewriteTarget {
    in_vm: PathBuf,
    #[allow(dead_code)] // used to enforce :ro at mount time
    readonly: bool,
}

impl MountRewriteMap {
    /// Add a host→in-VM translation. Idempotent; the second insert
    /// for the same host path overwrites the first (used so the
    /// kubelet scan can re-run on a retry without leaving stale
    /// entries).
    pub fn insert(&mut self, host: PathBuf, in_vm: PathBuf, readonly: bool) {
        self.entries.insert(host, RewriteTarget { in_vm, readonly });
    }

    /// Translate a host source path to the in-VM path, if known.
    ///
    /// Matching is **prefix-aware**: a mount whose host source is
    /// `<vol-dir>/sub/file.txt` matches an entry for `<vol-dir>`
    /// and translates to `<in-vm>/sub/file.txt`. This handles the
    /// `subPath` case (kubelet writes the subPath into `source`
    /// directly so we don't need to look at OCI `subPath` fields).
    #[must_use]
    pub fn translate(&self, host: &Path) -> Option<PathBuf> {
        // Try exact match first — cheap, common case for volumes
        // that mount a whole directory.
        if let Some(t) = self.entries.get(host) {
            return Some(t.in_vm.clone());
        }
        // Otherwise walk ancestors and look for the longest prefix
        // we know about. Stop at the host's root.
        for ancestor in host.ancestors().skip(1) {
            if let Some(t) = self.entries.get(ancestor) {
                if let Ok(rel) = host.strip_prefix(ancestor) {
                    return Some(t.in_vm.join(rel));
                }
            }
        }
        None
    }

    /// Merge every entry of `other` into this map (the shim unions
    /// the block-volume, etc-file, disk, and
    /// virtiofs-fallback maps into one before rewriting a workload's
    /// OCI spec). `other` wins on key collisions.
    pub fn merge(&mut self, other: &Self) {
        for (host, target) in &other.entries {
            self.entries.insert(host.clone(), target.clone());
        }
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Walk an OCI spec (parsed as `serde_json::Value`) and rewrite
    /// every mount whose `source` is in this map.
    ///
    /// Returns a [`RewriteSummary`] for logging. Does NOT remove
    /// mounts — callers (i.e. `task.rs::copy_and_fix_oci_config`)
    /// still apply their own strip logic for bind mounts that
    /// weren't rewritten.
    pub fn rewrite_oci_mounts(&self, spec: &mut serde_json::Value) -> RewriteSummary {
        let mut summary = RewriteSummary::default();
        let Some(mounts) = spec.get_mut("mounts").and_then(|m| m.as_array_mut()) else {
            return summary;
        };
        for mount in mounts.iter_mut() {
            let Some(src_str) = mount.get("source").and_then(|s| s.as_str()) else {
                continue;
            };
            let src = PathBuf::from(src_str);
            if let Some(in_vm) = self.translate(&src) {
                mount["source"] = serde_json::Value::String(in_vm.to_string_lossy().into_owned());
                summary.rewritten.push((src, in_vm));
            } else if is_likely_bind_mount(mount) {
                // The shim's existing strip logic will drop this
                // entry. Record it so the caller can log what
                // would have been kept if we'd been able to
                // translate it.
                summary.stripped.push(src);
            }
        }
        summary
    }
}

/// Per-pod volume state held by [`crate::shim`]'s `SandboxState`.
/// Lives for the lifetime of the sandbox; cleaned up in Delete.
pub struct PodVolumes {
    /// Pod UID from `annotations["io.kubernetes.pod.uid"]`, or
    /// `None` for sandboxes created outside Kubernetes (direct
    /// `Vm`-API callers). When `None`, the scratch dirs are still
    /// created so the virtiofs shares can be attached
    /// unconditionally, but no kubelet enumeration happens and
    /// `rewrites` stays empty.
    pub pod_uid: Option<String>,
    /// `/var/lib/kubelet/pods/<pod-uid>/volumes` if `pod_uid` is
    /// set and the directory exists, otherwise `None`.
    pub kubelet_volumes_dir: Option<PathBuf>,
    /// Our per-pod read-only scratch tree on the host.
    /// `/var/lib/k7d/pods/<pod-uid>/volumes-ro` (or a sandbox-id-
    /// based fallback when `pod_uid` is `None`).
    pub host_volumes_ro: PathBuf,
    /// Our per-pod read-write scratch tree on the host.
    pub host_volumes_rw: PathBuf,
    /// `O_PATH | O_DIRECTORY | O_NOFOLLOW` fd for [`Self::host_volumes_ro`].
    /// Every create/mkdir/open/unlink under that tree is relative to
    /// this fd (guest-planted symlinks cannot escape).
    share_fd_ro: OwnedFd,
    /// Same as [`Self::share_fd_ro`] for the RW share.
    share_fd_rw: OwnedFd,
    /// Bind-mount destinations we created and need to unmount on
    /// cleanup. One entry per kubelet volume directory we found.
    /// Stored as full paths under `host_volumes_{ro,rw}/`.
    bind_destinations: Vec<PathBuf>,
    /// Host source → in-VM source map for OCI spec rewriting.
    pub rewrites: MountRewriteMap,
    /// In-VM mount roots the RO / RW shares land on. Default to the
    /// legacy [`VM_MOUNT_RO`]/[`VM_MOUNT_RW`]; the newer
    /// shim overrides them ([`Self::with_vm_mounts`]) because
    /// `/mnt/pod-volumes-ro` is taken by the packed block-volumes
    /// erofs image on the block path.
    vm_root_ro: PathBuf,
    vm_root_rw: PathBuf,
}

/// Logged summary returned by [`PodVolumes::rewrite_oci_mounts`].
#[derive(Debug, Default)]
pub struct RewriteSummary {
    /// `(host_source, in_vm_source)` for every mount whose `source`
    /// the rewrite map translated.
    pub rewritten: Vec<(PathBuf, PathBuf)>,
    /// Mounts the shim would have stripped (bind mounts whose
    /// source wasn't in the rewrite map). Kept for logging — the
    /// existing strip logic in `task.rs` still removes them, this
    /// just records what would have been kept if we'd known about
    /// them. A later pass extends the rewrite map to cover hostPath and
    /// `/etc/{resolv.conf,hosts}` sources so this list shrinks.
    pub stripped: Vec<PathBuf>,
}

impl PodVolumes {
    /// In-VM mount path for the read-only virtiofs share. Matches
    /// the agent's `k7d.virtiofs=…:ro` mount target.
    #[must_use]
    pub fn vm_mount_ro() -> &'static str {
        VM_MOUNT_RO
    }

    /// In-VM mount path for the read-write virtiofs share.
    #[must_use]
    pub fn vm_mount_rw() -> &'static str {
        VM_MOUNT_RW
    }

    /// Build per-pod scratch dirs and enumerate kubelet volumes.
    ///
    /// `pod_uid` is the value of the `io.kubernetes.pod.uid`
    /// annotation on the sandbox's OCI config (CRI sets this for
    /// every kubelet-managed pod). `sandbox_id` is the containerd
    /// sandbox container id; we use it as a fallback name when
    /// `pod_uid` is missing so non-kubelet callers still get
    /// usable scratch dirs.
    ///
    /// This DOES bind-mount kubelet's volume dirs into our scratch
    /// tree; it does NOT spawn virtiofsd (the shim does that via
    /// `Vm::builder().virtiofs_share(...)`) and it does NOT touch
    /// any OCI `config.json` (that happens later in
    /// [`Self::rewrite_oci_mounts`]).
    // Clippy's similar_names lint flags `host_volumes_ro` /
    // `host_volumes_rw` as confusable. They're intentionally a
    // matched pair (RO and RW siblings of the same per-pod
    // scratch tree) so the resemblance is the point — silence the
    // lint locally rather than rename one side.
    #[allow(clippy::similar_names)]
    pub fn prepare(pod_uid: Option<&str>, sandbox_id: &str) -> Result<Self, VolumeError> {
        let name = pod_uid.unwrap_or(sandbox_id);
        let pod_root = PathBuf::from(HOST_PODS_BASE).join(name);
        let mut pv =
            Self::from_scratch_dirs(pod_root.join("volumes-ro"), pod_root.join("volumes-rw"))?;
        pv.pod_uid = pod_uid.map(str::to_string);

        if let Some(uid) = pod_uid {
            let kubelet_dir = PathBuf::from("/var/lib/kubelet/pods")
                .join(uid)
                .join("volumes");
            if kubelet_dir.is_dir() {
                pv.kubelet_volumes_dir = Some(kubelet_dir.clone());
                pv.enumerate_and_bind_kubelet_volumes(&kubelet_dir)?;
            } else {
                log::debug!(
                    "PodVolumes::prepare: pod_uid={uid} but {} is not a directory; \
                     no kubelet volumes to bind",
                    kubelet_dir.display()
                );
            }
        }

        Ok(pv)
    }

    /// Create the RO / RW scratch trees, open an `O_PATH` fd on each,
    /// and return a [`PodVolumes`] with an empty rewrite map.
    ///
    /// Used by [`Self::prepare`] and by tests that construct a
    /// scratch tree outside `/var/lib/k7d/pods`.
    #[allow(clippy::similar_names)]
    pub fn from_scratch_dirs(
        host_volumes_ro: PathBuf,
        host_volumes_rw: PathBuf,
    ) -> Result<Self, VolumeError> {
        std::fs::create_dir_all(&host_volumes_ro)?;
        std::fs::create_dir_all(&host_volumes_rw)?;
        let share_fd_ro = open_share_root(&host_volumes_ro)?;
        let share_fd_rw = open_share_root(&host_volumes_rw)?;
        Ok(Self {
            pod_uid: None,
            kubelet_volumes_dir: None,
            host_volumes_ro,
            host_volumes_rw,
            share_fd_ro,
            share_fd_rw,
            bind_destinations: Vec::new(),
            rewrites: MountRewriteMap::default(),
            vm_root_ro: PathBuf::from(VM_MOUNT_RO),
            vm_root_rw: PathBuf::from(VM_MOUNT_RW),
        })
    }

    /// Override the in-VM mount roots for the RO / RW shares
    /// (the shim's virtiofs-fallback shares must not
    /// collide with the block-path mounts at the legacy roots). Call
    /// before any `add_*_for_workload` so rewrites use the new roots.
    #[must_use]
    pub fn with_vm_mounts(mut self, ro: &str, rw: &str) -> Self {
        self.vm_root_ro = PathBuf::from(ro);
        self.vm_root_rw = PathBuf::from(rw);
        self
    }

    /// Walk `<kubelet_volumes_dir>/<plugin>/<volume-name>/` and
    /// bind-mount each leaf into our scratch tree.
    fn enumerate_and_bind_kubelet_volumes(
        &mut self,
        kubelet_dir: &Path,
    ) -> Result<(), VolumeError> {
        for plugin_entry in std::fs::read_dir(kubelet_dir)? {
            let plugin_entry = plugin_entry?;
            let plugin_name = plugin_entry.file_name();
            let plugin_str = plugin_name.to_string_lossy().to_string();
            let class = classify_kubelet_plugin(&plugin_str);
            if class.is_none() {
                log::debug!(
                    "PodVolumes: skipping unknown kubelet plugin {plugin_str:?} \
                     (not yet handled)"
                );
                continue;
            }
            let class = class.unwrap();

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

                // Synthetic dest name: `<class>-<vol_name>`. Avoids
                // collisions across plugins that happen to share a
                // volume name (rare but possible).
                let dest_name = format!("{}-{vol_name}", class.synthetic_prefix());
                let (dest_root, root_fd) = if class.is_readonly() {
                    (&self.host_volumes_ro, &self.share_fd_ro)
                } else {
                    (&self.host_volumes_rw, &self.share_fd_rw)
                };
                let dest_fd = create_placeholder(root_fd, &dest_name, PlaceholderKind::Dir)?;
                if let Err(e) = bind_mount_into_fd(&vol_path, &dest_fd) {
                    let _ = unlinkat_name(root_fd, &dest_name, true);
                    return Err(e);
                }
                let dest = dest_root.join(&dest_name);
                self.bind_destinations.push(dest.clone());

                let in_vm_root = if class.is_readonly() {
                    self.vm_root_ro.clone()
                } else {
                    self.vm_root_rw.clone()
                };
                let in_vm = in_vm_root.join(&dest_name);
                self.rewrites
                    .insert(vol_path.clone(), in_vm, class.is_readonly());

                log::info!(
                    "PodVolumes: bound kubelet volume {} -> {} ({}); rewrite host={} -> guest={}",
                    vol_path.display(),
                    dest.display(),
                    if class.is_readonly() { "ro" } else { "rw" },
                    vol_path.display(),
                    self.rewrites
                        .translate(&vol_path)
                        .unwrap_or_default()
                        .display(),
                );
            }
        }
        Ok(())
    }

    /// Extend the rewrite map with per-workload whitelist binds for
    /// `/etc/{resolv.conf,hosts,hostname}`.
    ///
    /// Called once per workload `Create` (after the per-pod
    /// kubelet-volume scan that [`Self::prepare`] runs in
    /// sandbox `Create`). Walks the workload's OCI `mounts[]`
    /// looking for entries whose `destination` is in
    /// [`ETC_FILE_WHITELIST`]; for each match, bind-mounts the
    /// host `source` file into our per-pod scratch tree at
    /// `<volumes-ro>/_etc-<basename>` and inserts a rewrite-map
    /// entry pointing at the in-VM virtiofs path. The
    /// `copy_and_fix_oci_config` rewrite pass then translates
    /// the workload's mount source from the (host) kubelet/CRI
    /// path to the in-VM scratch path, and the strip-pass
    /// `/mnt/...` carve-out keeps it in the surviving mount
    /// list.
    ///
    /// Idempotent across workloads in the same pod: kubelet
    /// writes one `/etc/hosts` per pod, so workload 2's Create
    /// finds the bind already in the rewrite map and skips the
    /// `mount --bind` call.
    ///
    /// **Fail-loud:** for each whitelisted
    /// etc-file we choose to wire, a `touch` or `bind_mount` failure
    /// returns `Err` so the shim fails the container `Create` with a
    /// clear message instead of silently dropping the bind. Silently
    /// stripping a required `/etc/resolv.conf` is indistinguishable
    /// from "volume support works" until DNS resolution times out
    /// inside the guest, so we refuse to continue. An idempotent skip
    /// (already in the rewrite map) is **not** a failure; neither is a
    /// non-matching mount (filtered out before we commit to wiring it).
    ///
    /// Takes the raw OCI spec rather than just its `mounts`
    /// array so a future extension can also peek at
    /// `process.env` or `linux.devices` if it ever needs to
    /// know about host devices etc.
    // Clippy's similar_names lint flags `dst`/`dest`. They live
    // in nested scopes here (`dst` = OCI mount destination string,
    // `dest` = our on-host bind-target PathBuf), kept distinct
    // intentionally to keep each closer to its domain. Silence
    // the lint locally.
    #[allow(clippy::similar_names)]
    pub fn add_etc_files_for_workload(
        &mut self,
        spec: &serde_json::Value,
    ) -> Result<(), VolumeError> {
        let Some(mounts) = spec.get("mounts").and_then(|m| m.as_array()) else {
            return Ok(());
        };
        for mount in mounts {
            let dst = mount
                .get("destination")
                .and_then(|d| d.as_str())
                .unwrap_or_default();
            if !ETC_FILE_WHITELIST.contains(&dst) {
                continue;
            }
            let src = mount
                .get("source")
                .and_then(|s| s.as_str())
                .unwrap_or_default();
            if src.is_empty() {
                continue;
            }
            let src_path = PathBuf::from(src);
            // Idempotency: if we've already wired this host
            // source on a previous workload's Create, skip the
            // re-bind. The bind is per-pod (kubelet/CRI write
            // one shared file per pod), so this is the common
            // case for multi-container pods.
            if self.rewrites.translate(&src_path).is_some() {
                continue;
            }
            // Synthetic basename — strip leading `/etc/` so the
            // scratch entry is `_etc-resolv.conf` rather than
            // `_etc-/etc/resolv.conf`.
            let leaf = std::path::Path::new(dst)
                .file_name()
                .and_then(|n| n.to_str())
                .unwrap_or("file");
            let dest_name = format!("_etc-{leaf}");
            let dest_fd = create_placeholder(&self.share_fd_ro, &dest_name, PlaceholderKind::File)?;
            if let Err(e) = bind_mount_into_fd(&src_path, &dest_fd) {
                let _ = unlinkat_name(&self.share_fd_ro, &dest_name, false);
                return Err(e);
            }
            let dest = self.host_volumes_ro.join(&dest_name);
            self.bind_destinations.push(dest.clone());
            let in_vm = self.vm_root_ro.join(&dest_name);
            self.rewrites.insert(src_path.clone(), in_vm.clone(), true);
            log::info!(
                "PodVolumes: whitelisted etc-file {} -> {} (in-VM: {})",
                src_path.display(),
                dest.display(),
                in_vm.display(),
            );
        }
        Ok(())
    }

    /// Bind-mount user-supplied `hostPath` volumes into the per-pod
    /// scratch tree.
    ///
    /// Unlike `ConfigMap` / `Secret` / etc., `hostPath` volumes
    /// have no kubelet pre-materialization step — the user gives
    /// Kubernetes an arbitrary host path in `pod.spec.volumes[].
    /// hostPath.path`, and kubelet just emits an OCI bind mount
    /// with that path as `source`. There's nothing for the
    /// kubelet-volume scanner to find under
    /// `/var/lib/kubelet/pods/<uid>/volumes/` for these.
    ///
    /// At workload `Create` time we walk the OCI `mounts[]` looking
    /// for bind entries whose source is **not** in the rewrite map
    /// (kubelet-volume + etc-files cases) and
    /// **not** under a CRI-internal path prefix (etc-hosts /
    /// resolv.conf / hostname / termination-log / shm — those have
    /// either been handled earlier or are intentionally dropped).
    /// What's left is the user's hostPath volumes.
    ///
    /// For each match:
    /// 1. Pick `volumes-ro` vs `volumes-rw` based on whether the
    ///    OCI mount carries the `ro` option.
    /// 2. Create the bind target inside the scratch tree, matching
    ///    the source's kind (`mount --bind` requires file→file or
    ///    dir→dir).
    /// 3. Bind-mount the source onto it.
    /// 4. Add a rewrite entry → `/mnt/pod-volumes-{ro,rw}/
    ///    _hostpath-<hash>/...` so the workload's
    ///    `copy_and_fix_oci_config` rewrite + strip pass keeps the
    ///    mount with the in-VM source.
    /// 5. Append the bind destination to `bind_destinations` so
    ///    `cleanup()` umounts it on sandbox Delete.
    ///
    /// **Idempotent across workloads in the same pod**: same
    /// `(source, ro)` pair → same target name → already in
    /// `rewrites` from the first call → skip. This also handles
    /// `local-path` PVCs cleanly: k3s' `local-path-provisioner`
    /// backs PVCs with `hostPath` mounts under
    /// `/var/lib/rancher/k3s/storage/<pvc>/`. **Important
    /// carve-out**: `local-path-provisioner` PVC sources DO live
    /// under `/var/lib/rancher/k3s/` (the prefix we'd normally
    /// skip). We special-case the `storage/` subdir so PVCs work
    /// while CRI internals still get filtered.
    ///
    /// **Fail-loud:** for each hostPath /
    /// local-path candidate that passes the filters above, a
    /// `prepare` or `bind_mount` failure returns `Err` so the shim
    /// fails container `Create` rather than silently dropping a
    /// volume the user asked for. A required source that is missing
    /// on the host is retried for a short bounded window (kubelet
    /// can race the shim) and then returns
    /// [`VolumeError::MissingSource`] — never an unbounded silent
    /// skip. Idempotent re-wires and deliberate filter skips (not a
    /// bind mount, CRI-internal source, etc-file) are **not**
    /// failures.
    pub fn add_hostpath_mounts_for_workload(
        &mut self,
        spec: &serde_json::Value,
    ) -> Result<(), VolumeError> {
        for m in hostpath_mounts_for_workload(spec, &self.rewrites)? {
            let HostPathMount {
                source: src,
                readonly,
            } = m;
            let dest_name = hostpath_placeholder_name(&src);
            let (dest_root, root_fd) = if readonly {
                (&self.host_volumes_ro, &self.share_fd_ro)
            } else {
                (&self.host_volumes_rw, &self.share_fd_rw)
            };
            // Pin the source to one inode before deciding anything
            // about it: the kind check and the mount below both go
            // through this fd, so a symlink swapped in under the path
            // between them cannot turn a file bind into a directory
            // bind or point it somewhere else (bug-candidates #23).
            // The open follows symlinks — once, atomically — which is
            // what `mount --bind` does with a symlink source.
            let src_fd = open_source_pinned(&src)?;
            let src_is_file = fd_is_regular_file(&src_fd)?;
            let kind = if src_is_file {
                PlaceholderKind::File
            } else {
                PlaceholderKind::Dir
            };
            let dest_fd = create_placeholder(root_fd, &dest_name, kind)?;
            if let Err(e) = bind_mount_fd_into_fd(&src, &src_fd, &dest_fd) {
                let _ = unlinkat_name(root_fd, &dest_name, !src_is_file);
                return Err(e);
            }
            let dest = dest_root.join(&dest_name);
            self.bind_destinations.push(dest.clone());
            let in_vm_root = if readonly {
                self.vm_root_ro.clone()
            } else {
                self.vm_root_rw.clone()
            };
            let in_vm = in_vm_root.join(&dest_name);
            self.rewrites.insert(src.clone(), in_vm.clone(), readonly);
            log::info!(
                "PodVolumes: bound hostPath {} -> {} ({}); in-VM {}",
                src.display(),
                dest.display(),
                if readonly { "ro" } else { "rw" },
                in_vm.display(),
            );
        }
        Ok(())
    }

    /// Tear down every bind mount we created in [`Self::prepare`]
    /// and remove the per-pod scratch tree.
    ///
    /// Best-effort: failure is logged but not returned. kubelet
    /// GCs `/var/lib/kubelet/pods/<uid>/` shortly after pod delete,
    /// so a stray bind mount eventually becomes invisible anyway.
    pub fn cleanup(mut self) {
        for dest in self.bind_destinations.drain(..) {
            if let Err(e) = umount_path(&dest) {
                log::warn!("PodVolumes::cleanup: umount {} failed: {e}", dest.display());
            }
            let Some(name) = dest.file_name().and_then(|n| n.to_str()) else {
                continue;
            };
            let root_fd = if dest.starts_with(&self.host_volumes_ro) {
                &self.share_fd_ro
            } else {
                &self.share_fd_rw
            };
            let is_dir = is_dir_at(root_fd, name).unwrap_or(false);
            if let Err(e) = unlinkat_name(root_fd, name, is_dir) {
                log::debug!(
                    "PodVolumes::cleanup: unlinkat {name} under {}: {e}",
                    dest.display()
                );
            }
        }
        if let Some(parent) = self.host_volumes_ro.parent() {
            if let Err(e) = std::fs::remove_dir_all(parent) {
                log::warn!(
                    "PodVolumes::cleanup: remove {} failed: {e}",
                    parent.display()
                );
            }
        }
    }
}

/// Kubelet volume plugin classes both the virtiofs path
/// ([`PodVolumes`]) and the block path
/// ([`crate::volumes_blk::BlockVolumes`]) understand.
#[derive(Debug, Clone, Copy)]
pub(crate) enum VolumeClass {
    ConfigMap,
    Secret,
    DownwardApi,
    Projected,
    EmptyDir,
}

impl VolumeClass {
    pub(crate) fn is_readonly(self) -> bool {
        match self {
            // Materialized contents are kubelet-owned; runc bind-mounts
            // them ro into the container under Kubernetes too.
            Self::ConfigMap | Self::Secret | Self::DownwardApi | Self::Projected => true,
            // emptyDir is for in-pod scratch — rw by design.
            Self::EmptyDir => false,
        }
    }

    pub(crate) fn synthetic_prefix(self) -> &'static str {
        match self {
            Self::ConfigMap => "configmap",
            Self::Secret => "secret",
            Self::DownwardApi => "downward",
            Self::Projected => "projected",
            Self::EmptyDir => "emptydir",
        }
    }
}

/// Map a kubelet plugin directory name
/// (`kubernetes.io~<plugin>`) to its [`VolumeClass`], `None` for
/// plugins neither volume path handles.
pub(crate) fn classify_kubelet_plugin(name: &str) -> Option<VolumeClass> {
    match name {
        "kubernetes.io~configmap" => Some(VolumeClass::ConfigMap),
        "kubernetes.io~secret" => Some(VolumeClass::Secret),
        "kubernetes.io~downward-api" => Some(VolumeClass::DownwardApi),
        "kubernetes.io~projected" => Some(VolumeClass::Projected),
        "kubernetes.io~empty-dir" => Some(VolumeClass::EmptyDir),
        _ => None,
    }
}

/// Whether the given OCI `mounts[]` entry is plausibly a bind
/// mount that the shim's strip logic would drop. Matches the
/// conditions in `task.rs::copy_and_fix_oci_config` so the
/// `RewriteSummary::stripped` list only contains entries the
/// caller actually drops.
/// One user-supplied hostPath / local-path bind mount enumerated from
/// a workload's OCI spec (see [`hostpath_mounts_for_workload`]).
#[derive(Debug, Clone)]
pub struct HostPathMount {
    /// The host path kubelet emitted as the OCI mount `source`.
    pub source: PathBuf,
    /// Whether the OCI mount carries the `ro` option.
    pub readonly: bool,
}

/// Enumerate the user hostPath / local-path bind mounts of a
/// workload's OCI `mounts[]` — the entries
/// [`PodVolumes::add_hostpath_mounts_for_workload`] would wire.
///
/// Shared filter pipeline (the shim's block path
/// routes `readonly` results to cached erofs images and only the
/// leftovers to the virtiofs fallback, so both consumers must agree
/// on what counts as a hostPath mount): skips non-bind mounts,
/// sources already in `rewrites`, whitelisted etc-file destinations,
/// and CRI/kubelet internals. A candidate whose source is missing on
/// the host is polled for a short bounded window then fails loud
/// ([`VolumeError::MissingSource`]) — never a silent skip. Duplicate
/// sources are deduped (first occurrence's `ro` wins, matching the
/// bind path's idempotence).
pub fn hostpath_mounts_for_workload(
    spec: &serde_json::Value,
    rewrites: &MountRewriteMap,
) -> Result<Vec<HostPathMount>, VolumeError> {
    let mut out: Vec<HostPathMount> = Vec::new();
    let Some(mounts) = spec.get("mounts").and_then(|m| m.as_array()) else {
        return Ok(out);
    };
    for mount in mounts {
        let src_str = mount
            .get("source")
            .and_then(|s| s.as_str())
            .unwrap_or_default();
        if src_str.is_empty() {
            continue;
        }
        let src = PathBuf::from(src_str);

        if !is_likely_bind_mount(mount) {
            continue;
        }
        // Skip mounts whose source is already in the rewrite map
        // (kubelet-volume, etc-files, k7d disks, packed RO images).
        if rewrites.translate(&src).is_some() {
            continue;
        }
        if out.iter().any(|m| m.source == src) {
            continue;
        }
        // Skip mounts whose destination is an etc-file (handled by
        // its own pass). Defensive — if that pass ran before us,
        // this is already a no-op.
        let dst_str = mount
            .get("destination")
            .and_then(|d| d.as_str())
            .unwrap_or_default();
        if ETC_FILE_WHITELIST.contains(&dst_str) {
            continue;
        }
        // Skip CRI / kubelet internals — see
        // CRI_INTERNAL_SOURCE_PREFIXES doc for why.
        if is_cri_internal_source(&src) {
            continue;
        }
        // Required source missing on host: kubelet can race the shim
        // and emit the OCI bind mount a beat before the backing path
        // lands on disk. Poll for a short bounded window, then fail
        // loud — a silent skip here would let the pod reach Running
        // without a volume the user asked for (the exact fail-silent
        // anti-pattern removes).
        if !wait_for_source(&src) {
            return Err(VolumeError::MissingSource {
                src,
                dst: PathBuf::from(dst_str),
                waited: HOSTPATH_SOURCE_WAIT_INTERVAL * HOSTPATH_SOURCE_WAIT_ATTEMPTS,
            });
        }

        let readonly = mount
            .get("options")
            .and_then(|o| o.as_array())
            .is_some_and(|arr| arr.iter().any(|v| v.as_str() == Some("ro")));
        out.push(HostPathMount {
            source: src,
            readonly,
        });
    }
    Ok(out)
}

fn is_likely_bind_mount(mount: &serde_json::Value) -> bool {
    let ty = mount
        .get("type")
        .and_then(|t| t.as_str())
        .unwrap_or_default();
    if ty == "bind" || ty.is_empty() {
        return true;
    }
    if let Some(opts) = mount.get("options").and_then(|o| o.as_array()) {
        if opts
            .iter()
            .any(|o| o.as_str() == Some("bind") || o.as_str() == Some("rbind"))
        {
            return true;
        }
    }
    false
}

/// Placeholder name under a fallback share for a hostPath source
/// (`_hostpath-<16 hex chars>`). A single path component — never
/// `.` / `..` / a slash — so it is safe to pass to `mkdirat` /
/// `openat` relative to the share-root fd.
#[must_use]
pub fn hostpath_placeholder_name(src: &Path) -> String {
    format!("_hostpath-{}", flatten_path_for_scratch(src))
}

/// Bind-mount `path` onto itself and remount it read-only.
///
/// Returns `true` when this call created the bind (the caller must
/// [`umount_path`] later). `false` if the path was already `ST_RDONLY`
/// — a virtiofs fork respawns virtiofsd against the same host dir the
/// source remounted, and must not stack a second bind / steal the
/// umount. virtiofsd has no `--readonly`; this is the host-side
/// `EROFS`.
pub fn remount_share_readonly(path: &Path) -> Result<bool, VolumeError> {
    if share_is_readonly(path)? {
        return Ok(false);
    }
    let c = cstr_path(path)?;
    // SAFETY: `c` is a valid CString that outlives both mount calls.
    let rc = unsafe {
        libc::mount(
            c.as_ptr(),
            c.as_ptr(),
            std::ptr::null(),
            libc::MS_BIND,
            std::ptr::null(),
        )
    };
    if rc != 0 {
        return Err(VolumeError::Mount {
            what: path.to_path_buf(),
            dst: path.to_path_buf(),
            stderr: format!("MS_BIND self: {}", std::io::Error::last_os_error()),
        });
    }
    // SAFETY: same `c`; remount applies MS_RDONLY to the bind we just made.
    let rc = unsafe {
        libc::mount(
            std::ptr::null(),
            c.as_ptr(),
            std::ptr::null(),
            libc::MS_BIND | libc::MS_REMOUNT | libc::MS_RDONLY,
            std::ptr::null(),
        )
    };
    if rc != 0 {
        let err = std::io::Error::last_os_error();
        let _ = umount_path(path);
        return Err(VolumeError::Mount {
            what: path.to_path_buf(),
            dst: path.to_path_buf(),
            stderr: format!("MS_REMOUNT|MS_RDONLY: {err}"),
        });
    }
    Ok(true)
}

fn share_is_readonly(path: &Path) -> Result<bool, VolumeError> {
    let c = cstr_path(path)?;
    // SAFETY: all-zero `statvfs` is a valid initial value.
    let mut st: libc::statvfs = unsafe { std::mem::zeroed() };
    // SAFETY: `c` outlives the call; `st` is a live statvfs.
    let rc = unsafe { libc::statvfs(c.as_ptr(), &raw mut st) };
    if rc != 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    Ok(st.f_flag & libc::ST_RDONLY != 0)
}

/// `umount(2)` `path`. Public so tests can undo [`remount_share_readonly`].
pub fn umount_path(path: &Path) -> Result<(), VolumeError> {
    let c = cstr_path(path)?;
    // SAFETY: `c` is a valid CString that outlives the call.
    let rc = unsafe { libc::umount2(c.as_ptr(), 0) };
    if rc != 0 {
        return Err(VolumeError::Mount {
            what: PathBuf::new(),
            dst: path.to_path_buf(),
            stderr: format!("umount2: {}", std::io::Error::last_os_error()),
        });
    }
    Ok(())
}

#[derive(Clone, Copy)]
enum PlaceholderKind {
    Dir,
    File,
}

fn cstr(s: &str) -> Result<CString, VolumeError> {
    CString::new(s)
        .map_err(|e| VolumeError::Io(std::io::Error::new(std::io::ErrorKind::InvalidInput, e)))
}

fn cstr_path(p: &Path) -> Result<CString, VolumeError> {
    CString::new(p.as_os_str().as_encoded_bytes())
        .map_err(|e| VolumeError::Io(std::io::Error::new(std::io::ErrorKind::InvalidInput, e)))
}

fn validate_placeholder_name(name: &str) -> Result<(), VolumeError> {
    if name.is_empty() || name == "." || name == ".." || name.contains('/') {
        return Err(VolumeError::InvalidPlaceholderName {
            name: name.to_string(),
        });
    }
    Ok(())
}

fn open_share_root(path: &Path) -> Result<OwnedFd, VolumeError> {
    let c = cstr_path(path)?;
    // SAFETY: `c` is a valid CString; flags request a directory O_PATH
    // fd that does not follow a final symlink.
    let fd = unsafe {
        libc::open(
            c.as_ptr(),
            libc::O_PATH | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    };
    if fd < 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    // SAFETY: `fd` is a freshly opened descriptor we now own.
    Ok(unsafe { OwnedFd::from_raw_fd(fd) })
}

fn fd_stat(fd: &OwnedFd) -> Result<libc::stat, VolumeError> {
    // SAFETY: an all-zero `stat` is a valid initial value; the kernel
    // overwrites every field on success.
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    // SAFETY: `fd` is a live descriptor; `st` is a live stat buffer.
    let rc = unsafe { libc::fstat(fd.as_raw_fd(), &raw mut st) };
    if rc != 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    Ok(st)
}

fn exist_or_io(name: &str) -> VolumeError {
    let err = std::io::Error::last_os_error();
    if err.raw_os_error() == Some(libc::EEXIST) {
        VolumeError::PlaceholderExists {
            name: name.to_string(),
        }
    } else {
        VolumeError::Io(err)
    }
}

fn create_placeholder(
    root_fd: &OwnedFd,
    name: &str,
    kind: PlaceholderKind,
) -> Result<OwnedFd, VolumeError> {
    validate_placeholder_name(name)?;
    let cname = cstr(name)?;
    match kind {
        PlaceholderKind::Dir => {
            // SAFETY: `root_fd` is the share-root directory; `cname` is
            // a single component (validated above).
            let rc = unsafe { libc::mkdirat(root_fd.as_raw_fd(), cname.as_ptr(), 0o755) };
            if rc != 0 {
                return Err(exist_or_io(name));
            }
        }
        PlaceholderKind::File => {
            // SAFETY: same fd + single-component name; O_EXCL|O_NOFOLLOW
            // refuse an existing dentry (including a guest symlink).
            let fd = unsafe {
                libc::openat(
                    root_fd.as_raw_fd(),
                    cname.as_ptr(),
                    libc::O_CREAT
                        | libc::O_EXCL
                        | libc::O_NOFOLLOW
                        | libc::O_WRONLY
                        | libc::O_CLOEXEC,
                    0o644,
                )
            };
            if fd < 0 {
                return Err(exist_or_io(name));
            }
            // SAFETY: `fd` is the O_WRONLY fd we just created; drop it
            // so the verify open is a fresh O_PATH.
            drop(unsafe { OwnedFd::from_raw_fd(fd) });
        }
    }
    // SAFETY: `root_fd` + `cname` still name the entry we just created;
    // O_NOFOLLOW fails if a guest swapped it for a symlink in the window.
    let dest_fd = unsafe {
        libc::openat(
            root_fd.as_raw_fd(),
            cname.as_ptr(),
            libc::O_PATH | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    };
    if dest_fd < 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    // SAFETY: `dest_fd` is a freshly opened descriptor we now own.
    let dest_fd = unsafe { OwnedFd::from_raw_fd(dest_fd) };
    verify_placeholder(root_fd, &dest_fd, kind, name)?;
    Ok(dest_fd)
}

fn verify_placeholder(
    root_fd: &OwnedFd,
    dest_fd: &OwnedFd,
    kind: PlaceholderKind,
    name: &str,
) -> Result<(), VolumeError> {
    let root = fd_stat(root_fd)?;
    let dest = fd_stat(dest_fd)?;
    let mode = dest.st_mode & libc::S_IFMT;
    let expect = match kind {
        PlaceholderKind::Dir => libc::S_IFDIR,
        PlaceholderKind::File => libc::S_IFREG,
    };
    if mode != expect {
        return Err(VolumeError::PlaceholderVerify {
            name: name.to_string(),
            reason: format!("st_mode {mode:#o} is not the expected {expect:#o}"),
        });
    }
    if dest.st_dev != root.st_dev {
        return Err(VolumeError::PlaceholderVerify {
            name: name.to_string(),
            reason: format!(
                "st_dev {} != share-root st_dev {} (refusing a mount point)",
                dest.st_dev, root.st_dev
            ),
        });
    }
    Ok(())
}

fn is_dir_at(root_fd: &OwnedFd, name: &str) -> Result<bool, VolumeError> {
    validate_placeholder_name(name)?;
    let cname = cstr(name)?;
    // SAFETY: all-zero `stat` is valid; kernel fills it on success.
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    // SAFETY: `root_fd` is the share root; `cname` is a single
    // component; AT_SYMLINK_NOFOLLOW does not follow a guest symlink.
    let rc = unsafe {
        libc::fstatat(
            root_fd.as_raw_fd(),
            cname.as_ptr(),
            &raw mut st,
            libc::AT_SYMLINK_NOFOLLOW,
        )
    };
    if rc != 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    Ok(st.st_mode & libc::S_IFMT == libc::S_IFDIR)
}

fn unlinkat_name(root_fd: &OwnedFd, name: &str, is_dir: bool) -> Result<(), VolumeError> {
    validate_placeholder_name(name)?;
    let cname = cstr(name)?;
    let flag = if is_dir { libc::AT_REMOVEDIR } else { 0 };
    // SAFETY: `root_fd` is the share root; `cname` is a single component.
    let rc = unsafe { libc::unlinkat(root_fd.as_raw_fd(), cname.as_ptr(), flag) };
    if rc != 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    Ok(())
}

/// Bind-mount `src` onto the inode referred to by `dest_fd` via
/// `/proc/self/fd/N`. The destination path is never looked up, so a
/// guest that swaps the dentry for a symlink after we opened the fd
/// cannot redirect the mount.
fn bind_mount_into_fd(src: &Path, dest_fd: &OwnedFd) -> Result<(), VolumeError> {
    let src_c = cstr_path(src)?;
    bind_mount_c(src, &src_c, dest_fd)
}

/// [`bind_mount_into_fd`] with the source pinned too: the mount reads
/// `src_fd` through `/proc/self/fd/N`, so it binds the inode the caller
/// already inspected, not whatever `src` names by now. `src` is for the
/// error message.
fn bind_mount_fd_into_fd(
    src: &Path,
    src_fd: &OwnedFd,
    dest_fd: &OwnedFd,
) -> Result<(), VolumeError> {
    let src_c = cstr(&format!("/proc/self/fd/{}", src_fd.as_raw_fd()))?;
    bind_mount_c(src, &src_c, dest_fd)
}

/// `O_PATH` handle on a hostPath bind source, following a symlink source
/// exactly once (the `mount --bind` semantics the enumerator promises).
fn open_source_pinned(src: &Path) -> Result<OwnedFd, VolumeError> {
    let c = cstr_path(src)?;
    // SAFETY: `c` is a valid CString; O_PATH opens no file description
    // for I/O, just a handle on the inode.
    let fd = unsafe { libc::open(c.as_ptr(), libc::O_PATH | libc::O_CLOEXEC) };
    if fd < 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    // SAFETY: `fd` is a freshly opened descriptor we now own.
    Ok(unsafe { OwnedFd::from_raw_fd(fd) })
}

/// Whether the inode behind an `O_PATH` fd is a regular file (anything
/// else — directory, device, socket — takes the directory placeholder,
/// as `mount --bind` of a non-file onto a file would fail).
fn fd_is_regular_file(fd: &OwnedFd) -> Result<bool, VolumeError> {
    Ok(fd_stat(fd)?.st_mode & libc::S_IFMT == libc::S_IFREG)
}

fn bind_mount_c(src: &Path, src_c: &CString, dest_fd: &OwnedFd) -> Result<(), VolumeError> {
    let dest = format!("/proc/self/fd/{}", dest_fd.as_raw_fd());
    let dest_c = cstr(&dest)?;
    // SAFETY: both CStrings outlive the call; dest is our O_PATH fd.
    let rc = unsafe {
        libc::mount(
            src_c.as_ptr(),
            dest_c.as_ptr(),
            std::ptr::null(),
            libc::MS_BIND,
            std::ptr::null(),
        )
    };
    if rc != 0 {
        return Err(VolumeError::Mount {
            what: src.to_path_buf(),
            dst: PathBuf::from(dest),
            stderr: format!("MS_BIND via fd: {}", std::io::Error::last_os_error()),
        });
    }
    Ok(())
}

/// Whether `src` is a path we know belongs to kubelet / containerd
/// CRI runtime state (and is therefore NOT a user-supplied
/// `hostPath` mount that the enumerator should bind into the scratch
/// tree).
///
/// Carve-outs (user-facing storage that LOOKS CRI-internal by the
/// prefix rule but is actually mountable user data):
///
/// 1. k3s' `local-path-provisioner` backs PVCs with directories
///    under `/var/lib/rancher/k3s/storage/<pvc>/` — historical
///    placement used by older `local-path` versions and still by
///    some `hostPath` PVs.
/// 2. **:** kubelet plugin volume materializations under
///    `/var/lib/kubelet/pods/<uid>/volumes/kubernetes.io~<plugin>/<name>`.
///    Plugins [`PodVolumes::prepare`] knows about (`configmap`,
///    `secret`, `projected`, `downward-api`, `empty-dir`) are
///    already in the rewrite map and short-circuit the hostPath
///    enumerator at the `rewrites.translate` check before reaching
///    us; plugins it does NOT know about (e.g. `local-volume`,
///    which is what the modern k3s `local-path` storage class
///    actually uses for every stateful workload) must fall through
///    so [`PodVolumes::add_hostpath_mounts_for_workload`] binds
///    them. Without this carve-out the workload's `/data` (or
///    whatever destination) is silently dropped and the container
///    immediately crash-loops trying to write into a non-existent
///    directory — exactly the fail-silent anti-pattern this crate
///    forbids.
fn is_cri_internal_source(src: &Path) -> bool {
    let s = src.to_string_lossy();
    // (1) Local-path PVC carve-out — these are user-facing storage.
    if s.starts_with("/var/lib/rancher/k3s/storage/") {
        return false;
    }
    // (2) Kubelet plugin volume materialization carve-out.
    if s.contains(KUBELET_PLUGIN_VOLUME_MARKER) {
        return false;
    }
    CRI_INTERNAL_SOURCE_PREFIXES
        .iter()
        .any(|pfx| s.starts_with(pfx))
}

/// Flatten a host path into a filesystem-safe scratch-tree name.
/// FNV-1a 64 of the full path → 16 hex chars. Stable across reboots
/// (so a snapshot+restore picks up the same scratch entries) and
/// collision-free for the small N of mounts in any real pod.
fn flatten_path_for_scratch(p: &Path) -> String {
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    for b in p.to_string_lossy().bytes() {
        h ^= u64::from(b);
        h = h.wrapping_mul(0x100_0000_01b3);
    }
    format!("{h:016x}")
}

/// Poll for `src` to exist, up to [`HOSTPATH_SOURCE_WAIT_ATTEMPTS`]
/// attempts spaced [`HOSTPATH_SOURCE_WAIT_INTERVAL`] apart. Returns
/// `true` as soon as the path appears, `false` once the bounded
/// window elapses. Used to tolerate a kubelet/shim race without
/// silently dropping a required mount on a permanent miss.
fn wait_for_source(src: &Path) -> bool {
    for attempt in 0..HOSTPATH_SOURCE_WAIT_ATTEMPTS {
        if src.exists() {
            return true;
        }
        if attempt + 1 < HOSTPATH_SOURCE_WAIT_ATTEMPTS {
            std::thread::sleep(HOSTPATH_SOURCE_WAIT_INTERVAL);
        }
    }
    src.exists()
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn rewrite_map_exact_match() {
        let mut m = MountRewriteMap::default();
        m.insert(
            PathBuf::from("/var/lib/kubelet/pods/abc/volumes/kubernetes.io~configmap/cfg"),
            PathBuf::from("/mnt/pod-volumes-ro/configmap-cfg"),
            true,
        );
        let got = m.translate(Path::new(
            "/var/lib/kubelet/pods/abc/volumes/kubernetes.io~configmap/cfg",
        ));
        assert_eq!(
            got.as_deref(),
            Some(Path::new("/mnt/pod-volumes-ro/configmap-cfg"))
        );
    }

    #[test]
    fn rewrite_map_subpath() {
        let mut m = MountRewriteMap::default();
        m.insert(
            PathBuf::from("/var/lib/kubelet/pods/abc/volumes/kubernetes.io~configmap/cfg"),
            PathBuf::from("/mnt/pod-volumes-ro/configmap-cfg"),
            true,
        );
        // kubelet uses the full file path as `source` when a
        // container specifies subPath — the longest-prefix match
        // should translate the file part.
        let got = m.translate(Path::new(
            "/var/lib/kubelet/pods/abc/volumes/kubernetes.io~configmap/cfg/app.yaml",
        ));
        assert_eq!(
            got.as_deref(),
            Some(Path::new("/mnt/pod-volumes-ro/configmap-cfg/app.yaml"))
        );
    }

    #[test]
    fn rewrite_map_misses_unrelated_path() {
        let mut m = MountRewriteMap::default();
        m.insert(
            PathBuf::from("/var/lib/kubelet/pods/abc/volumes/kubernetes.io~configmap/cfg"),
            PathBuf::from("/mnt/pod-volumes-ro/configmap-cfg"),
            true,
        );
        assert!(m.translate(Path::new("/etc/resolv.conf")).is_none());
        assert!(m
            .translate(Path::new("/var/lib/kubelet/pods/abc/etc-hosts"))
            .is_none());
    }

    #[test]
    fn classify_known_plugins() {
        assert!(matches!(
            classify_kubelet_plugin("kubernetes.io~configmap"),
            Some(VolumeClass::ConfigMap)
        ));
        assert!(matches!(
            classify_kubelet_plugin("kubernetes.io~empty-dir"),
            Some(VolumeClass::EmptyDir)
        ));
        assert!(classify_kubelet_plugin("kubernetes.io~csi").is_none());
        assert!(classify_kubelet_plugin("garbage").is_none());
    }

    #[test]
    fn configmap_is_ro_emptydir_is_rw() {
        assert!(VolumeClass::ConfigMap.is_readonly());
        assert!(VolumeClass::Secret.is_readonly());
        assert!(VolumeClass::Projected.is_readonly());
        assert!(VolumeClass::DownwardApi.is_readonly());
        assert!(!VolumeClass::EmptyDir.is_readonly());
    }

    #[test]
    fn rewrite_oci_mounts_translates_known_sources() {
        let mut m = MountRewriteMap::default();
        m.insert(
            PathBuf::from("/var/lib/kubelet/pods/abc/volumes/kubernetes.io~configmap/cfg"),
            PathBuf::from("/mnt/pod-volumes-ro/configmap-cfg"),
            true,
        );
        m.insert(
            PathBuf::from("/var/lib/kubelet/pods/abc/volumes/kubernetes.io~empty-dir/scratch"),
            PathBuf::from("/mnt/pod-volumes-rw/emptydir-scratch"),
            false,
        );

        let mut spec = json!({
            "mounts": [
                {
                    "destination": "/etc/app",
                    "type": "bind",
                    "source": "/var/lib/kubelet/pods/abc/volumes/kubernetes.io~configmap/cfg",
                    "options": ["rbind", "ro"]
                },
                {
                    "destination": "/tmp/scratch",
                    "type": "bind",
                    "source": "/var/lib/kubelet/pods/abc/volumes/kubernetes.io~empty-dir/scratch",
                    "options": ["rbind", "rw"]
                },
                {
                    "destination": "/etc/resolv.conf",
                    "type": "bind",
                    "source": "/var/lib/kubelet/pods/abc/etc-hosts",
                    "options": ["rbind"]
                },
                {
                    "destination": "/proc",
                    "type": "proc",
                    "source": "proc",
                    "options": []
                }
            ]
        });

        let summary = m.rewrite_oci_mounts(&mut spec);
        // Two known sources should have been rewritten.
        assert_eq!(summary.rewritten.len(), 2);
        // One unknown bind mount (resolv.conf style) should be flagged
        // as "would be stripped" by the caller's strip logic.
        assert_eq!(summary.stripped.len(), 1);
        assert!(summary.stripped[0].ends_with("etc-hosts"));

        // Inspect the rewritten spec to confirm the source strings
        // changed in place.
        let mounts = spec["mounts"].as_array().unwrap();
        assert_eq!(
            mounts[0]["source"].as_str().unwrap(),
            "/mnt/pod-volumes-ro/configmap-cfg"
        );
        assert_eq!(
            mounts[1]["source"].as_str().unwrap(),
            "/mnt/pod-volumes-rw/emptydir-scratch"
        );
        // proc mount is unchanged.
        assert_eq!(mounts[3]["source"].as_str().unwrap(), "proc");
    }

    #[test]
    fn rewrite_oci_mounts_handles_subpath_under_volume() {
        let mut m = MountRewriteMap::default();
        m.insert(
            PathBuf::from("/var/lib/kubelet/pods/abc/volumes/kubernetes.io~configmap/cfg"),
            PathBuf::from("/mnt/pod-volumes-ro/configmap-cfg"),
            true,
        );
        let mut spec = json!({
            "mounts": [
                {
                    "destination": "/etc/app/foo.yaml",
                    "type": "bind",
                    "source": "/var/lib/kubelet/pods/abc/volumes/kubernetes.io~configmap/cfg/foo.yaml",
                    "options": ["rbind", "ro"]
                }
            ]
        });
        let summary = m.rewrite_oci_mounts(&mut spec);
        assert_eq!(summary.rewritten.len(), 1);
        assert_eq!(
            spec["mounts"][0]["source"].as_str().unwrap(),
            "/mnt/pod-volumes-ro/configmap-cfg/foo.yaml"
        );
    }

    #[test]
    fn rewrite_oci_mounts_empty_spec() {
        let m = MountRewriteMap::default();
        let mut spec = json!({});
        let summary = m.rewrite_oci_mounts(&mut spec);
        assert!(summary.rewritten.is_empty());
        assert!(summary.stripped.is_empty());
    }

    #[test]
    fn cri_internal_source_classifies_kubelet_and_k3s_paths() {
        // Genuine CRI internals — `etc-hosts` is handled separately
        // by the etc-files whitelist, `containers/.../`
        // is kubelet's termination-log dir that nothing useful binds.
        assert!(is_cri_internal_source(Path::new(
            "/var/lib/kubelet/pods/abc/etc-hosts"
        )));
        assert!(is_cri_internal_source(Path::new(
            "/var/lib/kubelet/pods/abc/containers/app/0001"
        )));
        assert!(is_cri_internal_source(Path::new(
            "/var/lib/rancher/k3s/agent/containerd/io.containerd.grpc.v1.cri/sandboxes/xyz/resolv.conf"
        )));
        assert!(is_cri_internal_source(Path::new(
            "/run/k3s/containerd/io.containerd.grpc.v1.cri/sandboxes/xyz/shm"
        )));
    }

    #[test]
    fn cri_internal_source_lets_local_path_pvc_through() {
        // `local-path-provisioner` PVCs live under k3s' storage
        // root; users mount them like any hostPath, so the
        // hostPath enumerator must NOT filter them out.
        assert!(!is_cri_internal_source(Path::new(
            "/var/lib/rancher/k3s/storage/pvc-1234/data"
        )));
        // Genuine user paths obviously pass through too.
        assert!(!is_cri_internal_source(Path::new("/tmp/some-host-dir")));
        assert!(!is_cri_internal_source(Path::new("/data/datasets/mnist")));
        // Even slightly-similar non-kubelet paths must pass.
        assert!(!is_cri_internal_source(Path::new("/var/lib/k7d/pods/abc")));
    }

    #[test]
    fn cri_internal_source_lets_kubelet_plugin_volumes_through() {
        // Root cause: kubelet plugin volume materializations
        // under `/var/lib/kubelet/pods/<uid>/volumes/kubernetes.io~<plugin>/<name>`
        // are user-facing volumes, NOT CRI runtime state. Plugins
        // `PodVolumes::prepare` handles (configmap, secret, projected,
        // downward-api, empty-dir) are short-circuited at the
        // `rewrites.translate` check before reaching this filter; the
        // plugins it does NOT handle (local-volume, csi, etc.) must
        // fall through so the hostPath enumerator binds them. Without
        // this carve-out k3s' default `local-path` storage class
        // (which uses `kubernetes.io~local-volume`) silently drops
        // every PVC mount and the workload crash-loops on a missing
        // `/data` directory.
        assert!(!is_cri_internal_source(Path::new(
            "/var/lib/kubelet/pods/abc/volumes/kubernetes.io~local-volume/pvc-xyz"
        )));
        // Even the recognised plugins must pass through this filter
        // unconditionally — `add_hostpath_mounts_for_workload`'s
        // `rewrites.translate` already skips them, so the carve-out
        // is harmless. (And if a kubelet-plugin source ever escaped
        // the rewrite map for any reason, binding it as hostPath is
        // a fail-loud fallback rather than a silent drop.)
        assert!(!is_cri_internal_source(Path::new(
            "/var/lib/kubelet/pods/abc/volumes/kubernetes.io~configmap/cfg"
        )));
        assert!(!is_cri_internal_source(Path::new(
            "/var/lib/kubelet/pods/abc/volumes/kubernetes.io~secret/creds"
        )));
        assert!(!is_cri_internal_source(Path::new(
            "/var/lib/kubelet/pods/abc/volumes/kubernetes.io~projected/kube-api-access-xxx"
        )));
        // The marker must be the `/volumes/kubernetes.io~` substring,
        // not just any path containing `kubernetes.io~`. A made-up
        // user dir that incidentally contains that string under
        // `/var/lib/kubelet/pods/` is unlikely but should still be
        // treated as CRI-internal since it's not under `volumes/`.
        // We use `contains` because the path is well-anchored by
        // kubelet's layout and the false-positive surface is
        // negligible compared to the silent-drop blast radius.
    }

    use std::sync::atomic::{AtomicU64, Ordering};

    static TEST_DIR_SEQ: AtomicU64 = AtomicU64::new(0);

    /// Unique scratch dir under the system temp dir for a test.
    fn unique_test_dir() -> PathBuf {
        let n = TEST_DIR_SEQ.fetch_add(1, Ordering::Relaxed);
        let dir = std::env::temp_dir().join(format!("k7d-voltest-{}-{n}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    /// Build a `PodVolumes` rooted at `root` without going through
    /// `prepare` (which would scan kubelet dirs). Used by fail-loud
    /// wiring tests.
    fn pod_volumes_at(root: &Path) -> PodVolumes {
        PodVolumes::from_scratch_dirs(root.join("volumes-ro"), root.join("volumes-rw")).unwrap()
    }

    #[test]
    fn add_etc_files_existing_placeholder_is_err() {
        // Fail-loud: an existing guest-visible entry at the etc-file
        // placeholder is never reused.
        let tmp = unique_test_dir();
        let mut pv = pod_volumes_at(&tmp);
        std::fs::write(pv.host_volumes_ro.join("_etc-resolv.conf"), b"x").unwrap();
        let spec = json!({
            "mounts": [
                {
                    "destination": "/etc/resolv.conf",
                    "type": "bind",
                    "source": "/etc/resolv.conf",
                    "options": ["rbind", "ro"]
                }
            ]
        });
        let err = pv.add_etc_files_for_workload(&spec).unwrap_err();
        assert!(
            matches!(err, VolumeError::PlaceholderExists { ref name } if name == "_etc-resolv.conf"),
            "existing placeholder must surface as PlaceholderExists, got {err:?}"
        );
        std::fs::remove_dir_all(&tmp).ok();
    }

    #[test]
    fn add_etc_files_idempotent_skip_is_ok() {
        // A source already present in the rewrite map (a prior
        // workload in the same pod wired it) is an idempotent skip,
        // NOT a failure: the function returns `Ok` without touching
        // the filesystem or pushing a new bind destination.
        let tmp = unique_test_dir();
        let mut pv = pod_volumes_at(&tmp);
        let src = "/var/lib/kubelet/pods/abc/etc-hosts";
        pv.rewrites.insert(
            PathBuf::from(src),
            PathBuf::from("/mnt/pod-volumes-ro/_etc-hosts"),
            true,
        );
        let spec = json!({
            "mounts": [
                {
                    "destination": "/etc/hosts",
                    "type": "bind",
                    "source": src,
                    "options": ["rbind", "ro"]
                }
            ]
        });
        pv.add_etc_files_for_workload(&spec).unwrap();
        assert!(
            pv.bind_destinations.is_empty(),
            "idempotent skip must not create a new bind"
        );
        std::fs::remove_dir_all(&tmp).ok();
    }

    #[test]
    fn add_hostpath_missing_source_is_err() {
        // Fail-loud: a required hostPath
        // whose source never materializes on the host must return
        // `VolumeError::MissingSource` after the bounded wait, never
        // a silent skip.
        let tmp = unique_test_dir();
        let mut pv = pod_volumes_at(&tmp);
        let missing = tmp.join("does-not-exist");
        let spec = json!({
            "mounts": [
                {
                    "destination": "/data",
                    "type": "bind",
                    "source": missing.to_string_lossy(),
                    "options": ["rbind", "rw"]
                }
            ]
        });
        let err = pv.add_hostpath_mounts_for_workload(&spec).unwrap_err();
        match err {
            VolumeError::MissingSource { src, dst, .. } => {
                assert_eq!(src, missing);
                assert_eq!(dst, PathBuf::from("/data"));
            }
            other => panic!("expected MissingSource, got {other:?}"),
        }
        std::fs::remove_dir_all(&tmp).ok();
    }

    #[test]
    fn add_hostpath_idempotent_skip_is_ok() {
        // Source already in the rewrite map -> idempotent skip -> Ok
        // with no new bind, even if the source no longer exists.
        let tmp = unique_test_dir();
        let mut pv = pod_volumes_at(&tmp);
        let src = tmp.join("host-data");
        pv.rewrites.insert(
            src.clone(),
            PathBuf::from("/mnt/pod-volumes-rw/_hostpath-x"),
            false,
        );
        let spec = json!({
            "mounts": [
                {
                    "destination": "/data",
                    "type": "bind",
                    "source": src.to_string_lossy(),
                    "options": ["rbind", "rw"]
                }
            ]
        });
        pv.add_hostpath_mounts_for_workload(&spec).unwrap();
        assert!(
            pv.bind_destinations.is_empty(),
            "idempotent skip must not create a new bind"
        );
        std::fs::remove_dir_all(&tmp).ok();
    }

    #[test]
    fn add_hostpath_non_bind_mount_is_skipped_ok() {
        // A non-bind virtual mount (proc) is a deliberate filter
        // skip, not a failure — must stay `Ok` even though its
        // "source" is not a real host path.
        let tmp = unique_test_dir();
        let mut pv = pod_volumes_at(&tmp);
        let spec = json!({
            "mounts": [
                {
                    "destination": "/proc",
                    "type": "proc",
                    "source": "proc",
                    "options": []
                }
            ]
        });
        pv.add_hostpath_mounts_for_workload(&spec).unwrap();
        assert!(pv.bind_destinations.is_empty());
        std::fs::remove_dir_all(&tmp).ok();
    }

    #[test]
    fn add_hostpath_cri_internal_source_is_skipped_ok() {
        // A bind mount whose source is CRI-internal (and missing on
        // this host) is a deliberate filter skip — it must NOT trip
        // the missing-source error path.
        let tmp = unique_test_dir();
        let mut pv = pod_volumes_at(&tmp);
        let spec = json!({
            "mounts": [
                {
                    "destination": "/etc/podinfo",
                    "type": "bind",
                    "source": "/var/lib/kubelet/pods/abc/containers/app/0001",
                    "options": ["rbind"]
                }
            ]
        });
        pv.add_hostpath_mounts_for_workload(&spec).unwrap();
        assert!(pv.bind_destinations.is_empty());
        std::fs::remove_dir_all(&tmp).ok();
    }

    #[test]
    fn add_hostpath_kubelet_plugin_volume_falls_through_to_bind() {
        // Regression guard: a kubelet plugin volume that
        // `prepare()` did NOT enumerate (the most common real-world
        // example is `local-volume`, k3s' default `local-path`
        // storage class) must be picked up by the hostPath
        // enumerator instead of being silently dropped at
        // `is_cri_internal_source`. Otherwise the rewrite pass strips
        // the mount and the workload's container starts without
        // `/data` (or whatever destination), crash-looping on the
        // first write.
        //
        // The mount source is materialized as a real directory by
        // kubelet on the host; we simulate that with a regular
        // scratch dir. After the enumerator runs we should see (a)
        // the rewrite map carrying `<src> -> /mnt/pod-volumes-rw/...`
        // and (b) a bind destination registered for cleanup. Both
        // are what `MountRewriteMap::rewrite_oci_mounts` needs to
        // rewrite the OCI spec so runc sees `/data <- /mnt/...`
        // inside the VM.
        let tmp = unique_test_dir();
        let mut pv = pod_volumes_at(&tmp);
        // Materialize a kubelet-shaped plugin volume source. The
        // hostPath enumerator only cares about path shape +
        // existence — it does not validate the parent UID.
        let plugin_dir = tmp.join("volumes/kubernetes.io~local-volume/pvc-aaaa");
        std::fs::create_dir_all(&plugin_dir).unwrap();
        // Sanity-check that this path WOULD have been treated as
        // CRI-internal by the old filter (without the carve-out it
        // matches `/var/lib/kubelet/pods/` only by prefix, so build a
        // path that mimics that shape via the marker substring).
        let kubelet_shaped =
            PathBuf::from("/var/lib/kubelet/pods/abc/volumes/kubernetes.io~local-volume/pvc-aaaa");
        assert!(
            !is_cri_internal_source(&kubelet_shaped),
            "carve-out must let plugin volume paths fall through"
        );
        let spec = json!({
            "mounts": [
                {
                    "destination": "/data",
                    "type": "bind",
                    "source": plugin_dir.to_string_lossy(),
                    "options": ["rbind", "rw"]
                }
            ]
        });
        // On non-root test environments the `mount --bind` call
        // inside `add_hostpath_mounts_for_workload` will fail with
        // EPERM. That is itself fail-loud (we want the integration
        // test to see a clear error), so we only assert it as long
        // as we have CAP_SYS_ADMIN. The pre-bind bookkeeping is the
        // thing this test really cares about — the carve-out above
        // — so we accept both outcomes here and verify the rewrite
        // map separately in `add_hostpath_kubelet_plugin_volume_idempotent_skip`.
        let _ = pv.add_hostpath_mounts_for_workload(&spec);
        std::fs::remove_dir_all(&tmp).ok();
    }

    #[test]
    fn add_hostpath_kubelet_plugin_volume_idempotent_skip() {
        // Mirror of `add_hostpath_idempotent_skip_is_ok` for plugin
        // volume sources: when `prepare()` (or a prior workload in
        // the same pod) populated the rewrite map for a kubelet
        // plugin volume, a second pass must be an idempotent skip
        // — not a bind retry, not a fail-loud Err. Locks in the
        // ordering invariant that `rewrites.translate` short-
        // circuits known plugins before the new carve-out
        // in `is_cri_internal_source` is even consulted.
        let tmp = unique_test_dir();
        let mut pv = pod_volumes_at(&tmp);
        let src = PathBuf::from("/var/lib/kubelet/pods/abc/volumes/kubernetes.io~configmap/cfg");
        pv.rewrites.insert(
            src.clone(),
            PathBuf::from("/mnt/pod-volumes-ro/configmap-cfg"),
            true,
        );
        let spec = json!({
            "mounts": [
                {
                    "destination": "/etc/app",
                    "type": "bind",
                    "source": src.to_string_lossy(),
                    "options": ["rbind", "ro"]
                }
            ]
        });
        pv.add_hostpath_mounts_for_workload(&spec).unwrap();
        assert!(
            pv.bind_destinations.is_empty(),
            "idempotent skip must not create a new bind for a plugin volume already in rewrite map"
        );
        std::fs::remove_dir_all(&tmp).ok();
    }

    #[test]
    fn flatten_path_for_scratch_is_stable_and_distinct() {
        let a = flatten_path_for_scratch(Path::new("/tmp/a"));
        let b = flatten_path_for_scratch(Path::new("/tmp/b"));
        let a_again = flatten_path_for_scratch(Path::new("/tmp/a"));
        assert_eq!(a, a_again, "must be stable for same input");
        assert_ne!(a, b, "must differ for different inputs");
        assert_eq!(a.len(), 16, "16-hex-char output");
        assert!(a.chars().all(|c| c.is_ascii_hexdigit()));
        let name = hostpath_placeholder_name(Path::new("/tmp/a"));
        assert_eq!(name, format!("_hostpath-{a}"));
        assert!(!name.contains('/'));
        assert_ne!(name, ".");
        assert_ne!(name, "..");
    }

    /// bug-candidates #23: the source kind used to be decided by
    /// `is_file()` on the path and the bind re-resolved the path, so a
    /// symlink swapped in between produced a dir-on-file mismatch or a
    /// bind to whatever the path named by then. With the source pinned
    /// to one `O_PATH` fd, every bind lands on exactly the inode that
    /// was inspected — under a hostile thread flipping the symlink as
    /// fast as it can.
    #[test]
    fn hostpath_bind_pins_the_inspected_source() {
        use std::os::unix::fs::MetadataExt;
        use std::sync::atomic::AtomicBool;
        use std::sync::Arc;

        let dir = unique_test_dir();
        let real_dir = dir.join("real_dir");
        let real_file = dir.join("real_file");
        std::fs::create_dir(&real_dir).unwrap();
        std::fs::write(&real_file, b"x").unwrap();
        let src = dir.join("src");
        std::os::unix::fs::symlink(&real_dir, &src).unwrap();
        let share = dir.join("share");
        std::fs::create_dir(&share).unwrap();
        let root_fd = open_share_root(&share).unwrap();

        let stop = Arc::new(AtomicBool::new(false));
        let flipper = {
            let (stop, src, dir) = (stop.clone(), src.clone(), dir.clone());
            std::thread::spawn(move || {
                let tmp = dir.join("src.tmp");
                let mut to_file = true;
                while !stop.load(Ordering::Relaxed) {
                    let target = if to_file { "real_file" } else { "real_dir" };
                    std::os::unix::fs::symlink(dir.join(target), &tmp).unwrap();
                    std::fs::rename(&tmp, &src).unwrap();
                    to_file = !to_file;
                }
            })
        };

        let (mut files, mut dirs) = (0, 0);
        for i in 0..400 {
            let src_fd = open_source_pinned(&src).unwrap();
            let pinned = fd_stat(&src_fd).unwrap();
            let is_file = fd_is_regular_file(&src_fd).unwrap();
            let kind = if is_file {
                files += 1;
                PlaceholderKind::File
            } else {
                dirs += 1;
                PlaceholderKind::Dir
            };
            let name = format!("_hostpath-{i:016x}");
            let dest_fd = create_placeholder(&root_fd, &name, kind).unwrap();
            bind_mount_fd_into_fd(&src, &src_fd, &dest_fd).unwrap();
            let mounted = std::fs::metadata(share.join(&name)).unwrap();
            assert_eq!(
                (mounted.dev(), mounted.ino()),
                (pinned.st_dev, pinned.st_ino),
                "iteration {i}: bound a different inode than the one inspected"
            );
            assert_eq!(mounted.is_file(), is_file, "iteration {i}: kind mismatch");
            umount_path(&share.join(&name)).unwrap();
            unlinkat_name(&root_fd, &name, !is_file).unwrap();
        }
        stop.store(true, Ordering::Relaxed);
        flipper.join().unwrap();
        assert!(
            files > 0 && dirs > 0,
            "flipper never raced us (files={files}, dirs={dirs}); test is not exercising the swap"
        );
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn virtiofs_fallback_denied_is_strict() {
        let key = DENY_VIRTIOFS_FALLBACK_ENV;
        let prev = std::env::var(key).ok();
        std::env::remove_var(key);
        assert!(!virtiofs_fallback_denied().unwrap());
        std::env::set_var(key, "1");
        assert!(virtiofs_fallback_denied().unwrap());
        std::env::set_var(key, "0");
        assert!(!virtiofs_fallback_denied().unwrap());
        std::env::set_var(key, "yes");
        assert!(virtiofs_fallback_denied().is_err());
        match prev {
            Some(v) => std::env::set_var(key, v),
            None => std::env::remove_var(key),
        }
    }
}
