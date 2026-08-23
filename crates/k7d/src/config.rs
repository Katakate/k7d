//! Daemon configuration: warm-pool sizing read
//! from the environment at daemon start. No config file yet — a TOML
//! file can come with the deployment work.

/// Kernel + optional initrd a `CreateVm` / tree-boot will load.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GuestArtifacts {
    /// Guest kernel path (explicit or `K7D_KERNEL`).
    pub kernel: String,
    /// Initramfs path. `None` is a disk-root boot (`root=` +
    /// `block_devices`) — never a guessed `K7D_INITRD`.
    pub initrd: Option<String>,
}

/// Resolve kernel/initrd paths from explicit values or the environment
/// (`K7D_KERNEL` / `K7D_INITRD`) — loudly. Missing both is an error;
/// there is **no silent default path** (project rule: failures must be
/// loud).
///
/// The warm pool and the busybox `RuntimeClass` path use this. Ubuntu
/// `root=` disk boots go through [`resolve_vm_guest`] so an omitted
/// initrd cannot pick up the daemon's busybox `K7D_INITRD`.
pub fn resolve_guest_paths(
    kernel: Option<&str>,
    initrd: Option<&str>,
) -> Result<(String, String), String> {
    let kernel = kernel
        .filter(|s| !s.is_empty())
        .map(ToString::to_string)
        .or_else(|| std::env::var("K7D_KERNEL").ok())
        .ok_or_else(|| "no kernel: set config.kernel or env K7D_KERNEL".to_string())?;
    let initrd = initrd
        .filter(|s| !s.is_empty())
        .map(ToString::to_string)
        .or_else(|| std::env::var("K7D_INITRD").ok())
        .ok_or_else(|| "no initrd: set config.initrd or env K7D_INITRD".to_string())?;
    Ok((kernel, initrd))
}

/// Resolve guest artifacts for `CreateVm` / `boot_tree_member`.
///
/// Initrd is optional when the caller sets at least one block device
/// *and* the cmdline contains a `root=` token (the Ubuntu node image).
/// Empty/omitted initrd in that case must **not** fall back to
/// `K7D_INITRD` — those env vars are the `RuntimeClass` busybox pair
/// (CHALLENGES #72). Any other omission still requires an initrd
/// (config or env). Loud if neither an initrd nor a `root=` disk is
/// present.
pub fn resolve_vm_guest(
    kernel: Option<&str>,
    initrd: Option<&str>,
    cmdline: Option<&str>,
    block_devices: usize,
) -> Result<GuestArtifacts, String> {
    let kernel = kernel
        .filter(|s| !s.is_empty())
        .map(ToString::to_string)
        .or_else(|| std::env::var("K7D_KERNEL").ok())
        .ok_or_else(|| "no kernel: set config.kernel or env K7D_KERNEL".to_string())?;

    let explicit_initrd = initrd.filter(|s| !s.is_empty());
    let has_root_disk = block_devices > 0
        && cmdline.is_some_and(|c| c.split_whitespace().any(|tok| tok.starts_with("root=")));

    if let Some(path) = explicit_initrd {
        return Ok(GuestArtifacts {
            kernel,
            initrd: Some(path.to_string()),
        });
    }
    if has_root_disk {
        return Ok(GuestArtifacts {
            kernel,
            initrd: None,
        });
    }
    match std::env::var("K7D_INITRD") {
        Ok(path) if !path.is_empty() => Ok(GuestArtifacts {
            kernel,
            initrd: Some(path),
        }),
        _ => Err("no initrd: set config.initrd or env K7D_INITRD, or pass \
             block_devices plus cmdline with root="
            .to_string()),
    }
}

#[cfg(test)]
mod resolve_vm_guest_tests {
    use super::*;

    fn with_env<T>(key: &str, val: Option<&str>, f: impl FnOnce() -> T) -> T {
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
    fn ubuntu_root_disk_omits_initrd_and_ignores_env() {
        with_env("K7D_KERNEL", None, || {
            with_env("K7D_INITRD", Some("/busybox/initrd"), || {
                let got = resolve_vm_guest(
                    Some("/ubuntu/bzImage"),
                    None,
                    Some("console=ttyS0 root=/dev/vda rw"),
                    1,
                )
                .expect("root-disk boot");
                assert_eq!(got.kernel, "/ubuntu/bzImage");
                assert_eq!(got.initrd, None);
            });
        });
    }

    #[test]
    fn empty_initrd_on_root_disk_is_none_not_env() {
        with_env("K7D_INITRD", Some("/busybox/initrd"), || {
            let got = resolve_vm_guest(Some("/ubuntu/bzImage"), Some(""), Some("root=/dev/vda"), 1)
                .expect("empty initrd + root disk");
            assert_eq!(got.initrd, None);
        });
    }

    #[test]
    fn busybox_omission_still_uses_env() {
        with_env("K7D_KERNEL", Some("/busybox/vmlinux"), || {
            with_env("K7D_INITRD", Some("/busybox/initrd"), || {
                let got = resolve_vm_guest(None, None, None, 0).expect("busybox env");
                assert_eq!(got.kernel, "/busybox/vmlinux");
                assert_eq!(got.initrd.as_deref(), Some("/busybox/initrd"));
            });
        });
    }

    #[test]
    fn neither_initrd_nor_root_disk_is_loud() {
        with_env("K7D_KERNEL", Some("/k"), || {
            with_env("K7D_INITRD", None, || {
                let err = resolve_vm_guest(None, None, Some("console=ttyS0"), 0)
                    .expect_err("must not guess");
                assert!(err.contains("no initrd"), "{err}");
                assert!(err.contains("root="), "{err}");
            });
        });
    }

    #[test]
    fn block_devices_without_root_token_still_need_initrd() {
        with_env("K7D_KERNEL", Some("/k"), || {
            with_env("K7D_INITRD", None, || {
                let err = resolve_vm_guest(None, None, Some("console=ttyS0"), 1)
                    .expect_err("disk without root=");
                assert!(err.contains("no initrd"), "{err}");
            });
        });
    }
}

/// Warm-pool configuration.
///
/// Read from the environment at daemon start via [`PoolConfig::from_env`]:
///
/// | Env | Default | Meaning |
/// |---|---|---|
/// | `K7D_POOL_SIZE` | `0` (pool disabled) | target number of idle warm VMs |
/// | `K7D_POOL_MEMORY_MB` | `256` | template VM RAM in MiB |
/// | `K7D_POOL_VCPUS` | `1` | template VM vCPU count |
///
/// Kernel/initrd are resolved exactly like `VmConfig` does (env
/// `K7D_KERNEL` / `K7D_INITRD`) — a loud error when the pool is
/// enabled but they are missing.
#[derive(Debug, Clone)]
pub struct PoolConfig {
    /// Target number of idle warm VMs.
    pub size: usize,
    /// Template VM RAM in MiB.
    pub memory_mb: u64,
    /// Template VM vCPU count: the pool serves only
    /// requests asking for exactly this many vCPUs — a multi-vCPU
    /// pool is an operator choice, not a code change.
    pub vcpus: u32,
    /// Guest kernel the template boots.
    pub kernel: String,
    /// Initramfs the template boots.
    pub initrd: String,
}

impl PoolConfig {
    /// Read the pool configuration from the environment.
    ///
    /// Returns `Ok(None)` when the pool is disabled (`K7D_POOL_SIZE`
    /// unset or `0` — a missing env var is not an error). A *malformed*
    /// value, or an enabled pool without a resolvable kernel/initrd, is
    /// a loud `Err` — the daemon must refuse to start rather than
    /// silently run without the pool the operator asked for.
    pub fn from_env() -> Result<Option<Self>, String> {
        let size = match std::env::var("K7D_POOL_SIZE") {
            Ok(v) => v
                .trim()
                .parse::<usize>()
                .map_err(|e| format!("malformed K7D_POOL_SIZE {v:?}: {e}"))?,
            Err(std::env::VarError::NotPresent) => 0,
            Err(e) => return Err(format!("read K7D_POOL_SIZE: {e}")),
        };
        if size == 0 {
            return Ok(None);
        }
        let memory_mb = match std::env::var("K7D_POOL_MEMORY_MB") {
            Ok(v) => v
                .trim()
                .parse::<u64>()
                .map_err(|e| format!("malformed K7D_POOL_MEMORY_MB {v:?}: {e}"))?,
            Err(std::env::VarError::NotPresent) => 256,
            Err(e) => return Err(format!("read K7D_POOL_MEMORY_MB: {e}")),
        };
        let vcpus = match std::env::var("K7D_POOL_VCPUS") {
            Ok(v) => v
                .trim()
                .parse::<u32>()
                .map_err(|e| format!("malformed K7D_POOL_VCPUS {v:?}: {e}"))?,
            Err(std::env::VarError::NotPresent) => 1,
            Err(e) => return Err(format!("read K7D_POOL_VCPUS: {e}")),
        };
        if vcpus == 0 {
            return Err("K7D_POOL_VCPUS must be >= 1".to_string());
        }
        let (kernel, initrd) = resolve_guest_paths(None, None)
            .map_err(|e| format!("pool enabled (K7D_POOL_SIZE={size}) but {e}"))?;
        Ok(Some(Self {
            size,
            memory_mb,
            vcpus,
            kernel,
            initrd,
        }))
    }
}
