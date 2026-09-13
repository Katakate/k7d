//! Integration tests for: per-container writable-space limits
//! and per-container usage accounting.
//!
//! What these assert: a container given its own image hits `ENOSPC` at
//! **its** limit while its sibling on the pod's shared scratch keeps
//! writing far past that point; the usage reported through the agent
//! tracks what was written and goes back down when it is deleted (which
//! is why usage is measured in the guest and not from the host's
//! allocated blocks); and a warm fork inherits the arrangement — the
//! fork's container is limited the same way and its usage is
//! independent of its parent's.
//!
//! Requires KVM, /dev/vhost-vsock, the built guest kernel and
//! initramfs, busybox + mkfs.erofs + mkfs.ext4 + mkfs.xfs on the host,
//! and guest/rootfs/runc.amd64.

use std::path::{Path, PathBuf};
use std::time::Duration;

use k7d::api::AgentClient;
use k7d::disks::ScratchDisk;
use k7d::erofs::build_erofs_image;
use k7d::vm::Vm;

/// Guest RAM. Small on purpose: every limit asserted below is a
/// property of a block device, never of memory (CHALLENGES #65).
const GUEST_MEMORY_MB: u64 = 512;

/// Capacity of the shared sandbox scratch. Comfortably bigger than the
/// per-container limit, so a sibling can write past that limit and
/// prove the `ENOSPC` was the dedicated device's own.
const SANDBOX_SCRATCH: u64 = 1024 * 1024 * 1024;

/// Capacity of the dedicated container's image.
const CONTAINER_SCRATCH: u64 = 64 * 1024 * 1024;

/// The Kubernetes container name the annotation would carry. Different
/// from the guest runc names below on purpose: the agent has to match
/// on the bundle's CRI annotation, not on the name runc knows.
const K8S_LIMITED: &str = "builder";

/// Guest runc names of the two containers.
const LIMITED: &str = "ctr-limited-0001";
const SIBLING: &str = "ctr-sibling-0002";

fn workspace_path(relative: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(|p| p.parent())
        .expect("workspace root")
        .join(relative)
}

fn make_busybox_rootfs(dir: &Path) {
    for d in &["bin", "proc", "dev", "tmp", "etc"] {
        std::fs::create_dir_all(dir.join(d)).unwrap();
    }
    let busybox = Path::new("/bin/busybox");
    assert!(busybox.exists(), "busybox required at /bin/busybox");
    std::fs::copy(busybox, dir.join("bin/busybox")).unwrap();
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(
            dir.join("bin/busybox"),
            std::fs::Permissions::from_mode(0o755),
        )
        .unwrap();
    }
    for cmd in &[
        "sh", "echo", "cat", "ls", "sleep", "dd", "df", "sync", "rm", "true",
    ] {
        std::os::unix::fs::symlink("busybox", dir.join("bin").join(cmd)).unwrap();
    }
}

fn guest_sh(agent: &mut AgentClient, cmd: &str) -> String {
    let out = agent.exec(&["sh", "-c", cmd]).unwrap();
    assert_eq!(
        out.exit_code, 0,
        "guest command `{cmd}` failed: stdout={} stderr={}",
        out.stdout, out.stderr
    );
    out.stdout
}

fn push_runc(agent: &mut AgentClient) {
    let runc_src = workspace_path("guest/rootfs/runc.amd64");
    assert!(runc_src.exists(), "runc.amd64 not found at {runc_src:?}");
    let bytes = std::fs::read(&runc_src).unwrap();
    agent
        .write_file("/usr/local/bin/runc", &bytes)
        .expect("push runc into guest tmpfs");
    guest_sh(agent, "chmod 755 /usr/local/bin/runc");
}

/// Push an OCI bundle whose rootfs is the agent-mounted erofs image and
/// whose annotations carry `k8s_name` — what the agent matches against
/// the per-container scratch mounts. Returns the bundle path.
fn push_bundle(agent: &mut AgentClient, dir_name: &str, k8s_name: &str) -> String {
    let bundle = format!("/run/k7d/bundle-{dir_name}");
    let config = serde_json::json!({
        "ociVersion": "1.0.2",
        "annotations": {
            "io.kubernetes.cri.container-type": "container",
            "io.kubernetes.cri.container-name": k8s_name,
        },
        "process": {
            "terminal": false,
            "user": { "uid": 0, "gid": 0 },
            "args": ["sleep", "infinity"],
            "env": ["PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"],
            "cwd": "/"
        },
        "root": { "path": "/run/k7d/rootfs", "readonly": false },
        "linux": {
            "namespaces": [
                { "type": "pid" },
                { "type": "mount" },
                { "type": "ipc" },
                { "type": "uts" }
            ]
        },
        "mounts": [
            { "destination": "/proc", "type": "proc", "source": "proc" },
            {
                "destination": "/dev",
                "type": "tmpfs",
                "source": "tmpfs",
                "options": ["nosuid", "strictatime", "mode=755", "size=65536k"]
            }
        ]
    });
    agent
        .write_file(
            &format!("{bundle}/config.json"),
            serde_json::to_string_pretty(&config).unwrap().as_bytes(),
        )
        .expect("push bundle config.json");
    bundle
}

fn make_scratch(tag: &str, size_bytes: u64) -> ScratchDisk {
    ScratchDisk::create(
        &format!("test-cscratch-{tag}-{}", std::process::id()),
        size_bytes,
    )
    .expect("provision scratch image on the reflink loopback XFS")
}

fn build_rootfs_image(dir: &Path) -> PathBuf {
    let src = tempfile::tempdir().unwrap();
    make_busybox_rootfs(src.path());
    let img = dir.join("rootfs.erofs");
    build_erofs_image(src.path(), &img).unwrap();
    img
}

/// Boot a VM with the shared sandbox scratch plus one per-container
/// image for [`K8S_LIMITED`], and start both containers: [`LIMITED`]
/// (whose bundle claims that Kubernetes name) and [`SIBLING`] (which
/// does not, so it shares the pod's disk).
fn boot_pod(tag: &str, img: &Path) -> (Vm, AgentClient) {
    let mut vm = Vm::builder()
        .kernel_and_initrd()
        .memory_mb(GUEST_MEMORY_MB)
        .vsock(true)
        .block_device_mounted(img, true, "/run/k7d/rootfs", "erofs")
        .scratch_disk(make_scratch(&format!("{tag}-pod"), SANDBOX_SCRATCH))
        .container_scratch_disk(
            K8S_LIMITED,
            make_scratch(&format!("{tag}-{K8S_LIMITED}"), CONTAINER_SCRATCH),
        )
        .build()
        .expect("VM with a sandbox scratch and one per-container image");
    vm.start().unwrap();
    let mut agent = vm
        .connect_agent(Duration::from_secs(90))
        .expect("agent connect");
    push_runc(&mut agent);

    let limited_bundle = push_bundle(&mut agent, "limited", K8S_LIMITED);
    let sibling_bundle = push_bundle(&mut agent, "sibling", "sidecar");
    agent
        .container_start(LIMITED, &limited_bundle)
        .expect("limited container should start on its own scratch disk");
    agent
        .container_start(SIBLING, &sibling_bundle)
        .expect("sibling container should start on the shared scratch disk");
    (vm, agent)
}

/// `dd` `mib` MiB into `path` inside `container`, returning
/// `Ok(())` on success and the combined output on failure.
fn write_mib(agent: &mut AgentClient, container: &str, path: &str, mib: u32) -> Result<(), String> {
    let out = agent
        .container_exec(
            container,
            &[
                "sh",
                "-c",
                &format!("dd if=/dev/zero of={path} bs=1M count={mib} conv=fsync 2>&1"),
            ],
        )
        .expect("the exec itself must succeed — only the write may fail");
    if out.exit_code == 0 {
        Ok(())
    } else {
        Err(format!("{}{}", out.stdout, out.stderr))
    }
}

fn usage_mib(agent: &mut AgentClient, container: &str) -> u64 {
    agent
        .container_usage(container)
        .unwrap_or_else(|e| panic!("container_usage({container}): {e}"))
        .used_bytes
        / (1024 * 1024)
}

/// Test 1: the container with its own limit runs out of space
/// at that limit, and its sibling keeps writing well past it. Before
/// per-container scratch, both shared one image, so this write would
/// have consumed space the sibling needed instead of failing.
#[test]
fn test_container_limit_scopes_enospc_to_the_offender() {
    let _ = env_logger::builder().is_test(true).try_init();

    let dir = tempfile::tempdir().unwrap();
    let img = build_rootfs_image(dir.path());
    let (mut vm, mut agent) = boot_pod("enospc", &img);

    // The limited container's writable layer really is its own device.
    let mount = k7d::disks::container_scratch_mount(K8S_LIMITED);
    let mounts = guest_sh(&mut agent, &format!("grep ' {mount} ' /proc/mounts"));
    assert!(
        mounts.contains("ext4"),
        "expected {K8S_LIMITED}'s own ext4 image mounted at {mount}, got: {mounts}"
    );
    let limited = agent.container_usage(LIMITED).expect("limited usage");
    assert!(
        limited.dedicated,
        "the container named by the annotation must be reported as limited"
    );
    assert!(
        limited.capacity_bytes <= CONTAINER_SCRATCH
            && limited.capacity_bytes > CONTAINER_SCRATCH / 2,
        "capacity {} should be about the {CONTAINER_SCRATCH}-byte image it was given",
        limited.capacity_bytes
    );
    let sibling = agent.container_usage(SIBLING).expect("sibling usage");
    assert!(
        !sibling.dedicated,
        "an unnamed container shares the pod scratch and must NOT be reported as limited"
    );
    assert!(
        sibling.capacity_bytes > CONTAINER_SCRATCH * 4,
        "the sibling's capacity {} should be the pod's whole scratch disk",
        sibling.capacity_bytes
    );

    // Writing 4x its limit fails, cleanly, on the device.
    let overshoot = (CONTAINER_SCRATCH / (1024 * 1024) * 4) as u32;
    let complaint = write_mib(&mut agent, LIMITED, "/fill", overshoot)
        .expect_err("writing 4x the container's limit must fail")
        .to_ascii_lowercase();
    assert!(
        complaint.contains("no space left"),
        "expected a clean ENOSPC from the container's own device, got: {complaint}"
    );

    // The sibling writes MORE than that limit, successfully — the
    // headline of: the blast radius was the container, not the
    // pod.
    write_mib(&mut agent, SIBLING, "/big", overshoot)
        .expect("the sibling must keep writing past the limit that stopped its neighbour");

    // And the offender is still alive and still limited: it has space
    // again the moment it deletes what it wrote.
    let alive = agent
        .container_exec(LIMITED, &["sh", "-c", "rm -f /fill && sync && echo ok"])
        .expect("the limited container must survive its own ENOSPC");
    assert_eq!(alive.exit_code, 0, "stderr: {}", alive.stderr);
    assert_eq!(alive.stdout.trim(), "ok");
    assert_eq!(
        agent.container_wait_poll(LIMITED).expect("poll exit"),
        None,
        "the container init must still be running (an OOM kill would have reaped it)"
    );

    agent.container_stop(LIMITED).ok();
    agent.container_stop(SIBLING).ok();
    vm.shutdown();
}

/// Test 2: reported usage tracks reality in both directions,
/// for a dedicated image (`statfs`) and for a container sharing the pod
/// scratch (a walk of its `upper`). The delete half is the point: the
/// host's allocated-blocks view of the sparse image never shrinks, which
/// is why this number comes from the guest.
#[test]
fn test_reported_usage_tracks_writes_and_deletes() {
    let _ = env_logger::builder().is_test(true).try_init();

    let dir = tempfile::tempdir().unwrap();
    let img = build_rootfs_image(dir.path());
    let (mut vm, mut agent) = boot_pod("usage", &img);

    let write = 32u32;
    for container in [LIMITED, SIBLING] {
        let before = usage_mib(&mut agent, container);
        write_mib(&mut agent, container, "/payload", write)
            .unwrap_or_else(|e| panic!("write {write} MiB in {container}: {e}"));
        let after = usage_mib(&mut agent, container);
        let grew = after.saturating_sub(before);
        assert!(
            grew >= u64::from(write) * 9 / 10 && grew <= u64::from(write) * 3 / 2,
            "{container}: writing {write} MiB moved reported usage by {grew} MiB \
             (before={before} after={after})"
        );

        let out = agent
            .container_exec(container, &["sh", "-c", "rm -f /payload && sync"])
            .expect("delete the payload");
        assert_eq!(out.exit_code, 0, "stderr: {}", out.stderr);
        let freed = usage_mib(&mut agent, container);
        assert!(
            freed <= before + u64::from(write) / 4,
            "{container}: reported usage stayed at {freed} MiB after deleting {write} MiB \
             (started at {before} MiB) — this is the number the host cannot compute"
        );
    }

    // A container the agent does not know about is an error, not a
    // zero that reads as "empty".
    let err = agent
        .container_usage("no-such-container")
        .expect_err("usage of an unknown container must fail loudly");
    assert!(
        err.to_string().contains("no-such-container"),
        "the error must name the container, got: {err}"
    );

    agent.container_stop(LIMITED).ok();
    agent.container_stop(SIBLING).ok();
    vm.shutdown();
}

/// Test 4: a warm fork inherits the whole arrangement. The
/// fork's container is still limited by its own image (a reflink-CoW
/// copy), and what it writes is invisible to the parent — a fork that
/// shared the parent's image would let one sandbox's writes fill
/// another's limit.
#[test]
fn test_warm_fork_keeps_per_container_limits_independently() {
    let _ = env_logger::builder().is_test(true).try_init();

    let dir = tempfile::tempdir().unwrap();
    let img = build_rootfs_image(dir.path());
    let (mut source, mut agent) = boot_pod("fork", &img);
    let source_images: Vec<PathBuf> = source
        .container_scratch_paths()
        .iter()
        .map(|p| p.to_path_buf())
        .collect();
    assert_eq!(
        source_images.len(),
        1,
        "the source VM owns exactly the one per-container image it was given"
    );

    // Pre-fork content, inside the limited container's own layer.
    let out = agent
        .container_exec(LIMITED, &["sh", "-c", "echo before-fork > /marker && sync"])
        .expect("pre-fork write");
    assert_eq!(out.exit_code, 0, "stderr: {}", out.stderr);
    let parent_before = usage_mib(&mut agent, LIMITED);
    drop(agent);

    source
        .prepare_fork_source()
        .expect("prepare_fork_source with per-container images attached");
    let mut agent = source
        .connect_agent(Duration::from_secs(30))
        .expect("reconnect after prepare_fork_source");
    for image in &source_images {
        assert!(
            image.exists(),
            "prepare_fork_source must not remove the source's per-container image at {}",
            image.display()
        );
    }

    let mut fork = source
        .fork_warm_batch(&["cscratch-fork-a"], None)
        .expect("warm fork must reflink the per-container image, never byte-copy it")
        .pop()
        .expect("one fork");
    let fork_images: Vec<&Path> = fork
        .block_devices()
        .iter()
        .map(|b| b.host_path.as_path())
        .collect();
    for image in &source_images {
        assert!(
            !fork_images.contains(&image.as_path()),
            "the fork shares the parent's per-container image {} — one sandbox's writes \
             would fill another's limit",
            image.display()
        );
    }
    fork.start().unwrap();
    let mut fork_agent = fork
        .connect_agent(Duration::from_secs(30))
        .expect("fork agent");

    // Inherited (CoW, not empty), and still reported as limited with
    // the same capacity.
    let inherited = fork_agent
        .container_exec(LIMITED, &["sh", "-c", "cat /marker"])
        .expect("read the pre-fork marker in the fork");
    assert_eq!(inherited.stdout.trim(), "before-fork");
    let fork_usage = fork_agent.container_usage(LIMITED).expect("fork usage");
    assert!(
        fork_usage.dedicated && fork_usage.capacity_bytes <= CONTAINER_SCRATCH,
        "the fork's container must still be limited by its own image, got {fork_usage:?}"
    );

    // Independent: the fork's writes move only the fork's number…
    let write = 16u32;
    write_mib(&mut fork_agent, LIMITED, "/fork-payload", write).expect("write in the fork");
    let fork_after = usage_mib(&mut fork_agent, LIMITED);
    let parent_after = usage_mib(&mut agent, LIMITED);
    assert!(
        fork_after >= parent_before + u64::from(write) * 9 / 10,
        "the fork's usage ({fork_after} MiB) should reflect its own {write} MiB write \
         (parent was at {parent_before} MiB)"
    );
    assert!(
        parent_after <= parent_before + u64::from(write) / 4,
        "the parent's usage moved from {parent_before} to {parent_after} MiB when the FORK \
         wrote — the writable layers are not isolated"
    );
    let probe = agent
        .container_exec(LIMITED, &["sh", "-c", "test -e /fork-payload"])
        .expect("probe the parent for the fork's file");
    assert_ne!(
        probe.exit_code, 0,
        "the parent can see the fork's file — the writable layers are not isolated"
    );

    // …and the limit still bites in the fork.
    let overshoot = (CONTAINER_SCRATCH / (1024 * 1024) * 4) as u32;
    let complaint = write_mib(&mut fork_agent, LIMITED, "/fork-fill", overshoot)
        .expect_err("the fork's container must hit its inherited limit")
        .to_ascii_lowercase();
    assert!(
        complaint.contains("no space left"),
        "expected ENOSPC from the fork's own image, got: {complaint}"
    );

    fork.shutdown();
    source.shutdown();
}
