//! Daemon configuration: warm-pool sizing read
//! from the environment at daemon start. No config file yet — a TOML
//! file can come with the deployment work.

/// Resolve kernel/initrd paths from explicit values or the environment
/// (`K7D_KERNEL` / `K7D_INITRD`) — loudly. Missing both is an error;
/// there is **no silent default path** (project rule: failures must be
/// loud).
pub fn resolve_guest_paths(
    kernel: Option<&str>,
    initrd: Option<&str>,
) -> Result<(String, String), String> {
    let kernel = kernel
        .map(ToString::to_string)
        .or_else(|| std::env::var("K7D_KERNEL").ok())
        .ok_or_else(|| "no kernel: set config.kernel or env K7D_KERNEL".to_string())?;
    let initrd = initrd
        .map(ToString::to_string)
        .or_else(|| std::env::var("K7D_INITRD").ok())
        .ok_or_else(|| "no initrd: set config.initrd or env K7D_INITRD".to_string())?;
    Ok((kernel, initrd))
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
