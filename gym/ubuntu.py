"""25a Ubuntu node source: image, cmdline, disks, Ready wait.

The gym talks only to `/run/k7d/k7d.sock`. This module does not boot
`Vm` in-process — it builds the guest artifacts and the cmdline the
daemon's `CreateVm` needs.
"""

from __future__ import annotations

import json
import logging
import os
import subprocess
import time
from pathlib import Path
from typing import Any

import agent

log = logging.getLogger("gym.ubuntu")

# crates/k7d/tests/common/ubuntu.rs
NODE_MEMORY_MB = 2048
NODE_VCPUS = 2
BOOT_TO_AGENT_S = 120
SYSTEMD_READY_S = 180
# crates/k7d/src/latency.rs BOOT_UBUNTU_K3S_CLUSTER_3NODE
CLUSTER_READY_S = 600
UBUNTU_LSM_LIST = "landlock,lockdown,yama,integrity,apparmor,bpf"
# crates/k7d/tests/common/ubuntu_k3s.rs
K3S_TOKEN = "K7dUbuntuClusterToken.inc2"
# 25a-inc2 measured ~1.35 GiB host RAM / node.
HOST_RAM_PER_NODE_BYTES = int(1.35 * 1024**3)
DISKS_DIR = Path("/var/lib/k7d/disks")
BASE_IMAGES = DISKS_DIR / "base-images"


def guest_ip(vm_index: int) -> str:
    if vm_index < 0:
        raise ValueError(f"vm_index must be >= 0, got {vm_index}")
    return f"10.200.0.{2 + vm_index}"


def node_cmdline(guest_ip_s: str, k3s: str | None, cni: str | None = None) -> str:
    """Byte-stable with `common/ubuntu.rs` `node_cmdline_with`.

    `cni` is `k7d.cni=flannel|none`. `None` leaves the
    token off (absent == flannel) so the gym's default path stays
    byte-identical. Cilium/Tetragon bring-up must pass `cni="none"`.
    """
    cmd = (
        "console=ttyS0 earlyprintk=serial,ttyS0,115200 noapic reboot=k panic=1 pci=off "
        "net.ifnames=0 root=/dev/vda rootfstype=ext4 rw mitigations=off "
        "clocksource=kvm-clock cpuidle_haltpoll.force=1 "
        "haltpoll.guest_halt_poll_ns=200000 haltpoll.guest_halt_poll_grow_start=200000 "
        f"haltpoll.guest_halt_poll_allow_shrink=0 lsm={UBUNTU_LSM_LIST} "
        f"k7d.ip={guest_ip_s}/24,10.200.0.1,eth0"
    )
    if k3s:
        cmd = f"{cmd} k7d.k3s={k3s}"
    if cni is not None:
        if cni not in ("flannel", "none"):
            raise ValueError(f"k7d.cni must be flannel or none, got {cni!r}")
        cmd = f"{cmd} k7d.cni={cni}"
    return cmd


def k3s_spec(role: str, server_ip: str) -> str:
    if role not in ("server", "agent"):
        raise ValueError(f"k3s role must be server|agent, got {role!r}")
    return f"{role},{server_ip},{K3S_TOKEN}"


def build_or_cache_image(repo: Path) -> dict[str, Any]:
    """Run `guest/ubuntu/build-node-image.sh` and return its manifest.

    Content-keyed; a cache hit is a no-op. Failures are loud — never
    fall back to `K7D_KERNEL`/`K7D_INITRD`.
    """
    script = repo / "guest" / "ubuntu" / "build-node-image.sh"
    if not script.is_file():
        raise RuntimeError(f"Ubuntu image builder missing: {script}")
    agent_bin = repo / "target" / "x86_64-unknown-linux-musl" / "release" / "k7-agent"
    if not agent_bin.is_file():
        raise RuntimeError(
            f"static k7-agent missing at {agent_bin} — run `make build-agent`"
        )
    if not DISKS_DIR.is_dir():
        raise RuntimeError(
            f"{DISKS_DIR} is missing; the reflink XFS is not mounted "
            "(run the 25a image builder / ensure_loopback_xfs first)"
        )
    env = os.environ.copy()
    env["AGENT_BIN"] = str(agent_bin)
    log.info("building/caching Ubuntu node image via %s", script)
    out = subprocess.run(
        ["bash", str(script)],
        check=False,
        capture_output=True,
        text=True,
        env=env,
        cwd=str(repo),
    )
    if out.returncode != 0:
        raise RuntimeError(
            f"{script} failed (exit {out.returncode}):\n"
            f"stderr:\n{out.stderr}\nstdout:\n{out.stdout}"
        )
    json_start = out.stdout.find("{")
    if json_start < 0:
        raise RuntimeError(f"image builder printed no manifest:\n{out.stdout}")
    manifest = json.loads(out.stdout[json_start:])
    for key in ("image", "kernel"):
        if key not in manifest:
            raise RuntimeError(f"image manifest missing {key}: {manifest}")
        p = Path(str(manifest[key]))
        if not p.is_file():
            raise RuntimeError(f"manifest {key} is not a file: {p}")
    log.info(
        "ubuntu image kernel=%s image=%s",
        manifest.get("kernel_version"),
        manifest["image"],
    )
    return manifest


def reflink_disk(base: Path, dest: Path) -> None:
    dest.parent.mkdir(parents=True, exist_ok=True)
    r = subprocess.run(
        ["cp", "--reflink=always", "-f", str(base), str(dest)],
        check=False,
        capture_output=True,
        text=True,
    )
    if r.returncode != 0:
        raise RuntimeError(
            f"cp --reflink=always {base} → {dest} failed: {r.stderr}"
        )


def wait_agent(cid: int, ceiling_s: float, *, dump) -> None:
    deadline = time.monotonic() + ceiling_s
    last = ""
    while time.monotonic() < deadline:
        if agent.ping(cid, timeout_s=3):
            return
        last = "ping miss"
        time.sleep(1)
    extra = ""
    try:
        extra = dump()
    except (OSError, RuntimeError) as e:
        extra = f"(dump_serial failed: {e})"
    raise RuntimeError(
        f"ubuntu cid={cid}: agent never answered within {ceiling_s}s "
        f"({last})\n{extra}"
    )


def wait_systemd_healthy(cid: int, ceiling_s: float = SYSTEMD_READY_S) -> None:
    deadline = time.monotonic() + ceiling_s
    state = ""
    while time.monotonic() < deadline:
        r = agent.exec_cmd(
            cid,
            ["sh", "-c", "systemctl is-system-running 2>/dev/null || true"],
            timeout_s=8,
        )
        state = (r["stdout"] or "").strip()
        if state and state not in ("starting", "initializing"):
            break
        time.sleep(1)
    else:
        raise RuntimeError(
            f"ubuntu cid={cid}: systemd still {state!r} after {ceiling_s}s"
        )
    if state not in ("running", "degraded"):
        raise RuntimeError(
            f"ubuntu cid={cid}: systemd is {state}, expected running or degraded"
        )
    failed = agent.exec_cmd(
        cid,
        [
            "sh",
            "-c",
            "systemctl list-units --state=failed --no-legend --plain --no-pager || true",
        ],
        timeout_s=8,
    )
    units = [
        line.split()[0]
        for line in (failed["stdout"] or "").splitlines()
        if line.split()
    ]
    if units:
        raise RuntimeError(
            f"ubuntu cid={cid}: systemd is {state} with failed units: {units}"
        )


def wait_guest_readyz(cid: int, ceiling_s: float) -> None:
    deadline = time.monotonic() + ceiling_s
    last = ""
    while time.monotonic() < deadline:
        r = agent.exec_cmd(
            cid,
            ["sh", "-c", "k3s kubectl get --raw=/readyz 2>&1 || true"],
            timeout_s=10,
        )
        out = (r["stdout"] or "") + (r["stderr"] or "")
        if r["exit_code"] == 0 and "ok" in out:
            return
        last = f"exit={r['exit_code']} out={out[-200:]!r}"
        time.sleep(2)
    logs = agent.exec_cmd(
        cid,
        [
            "sh",
            "-c",
            "journalctl -u k3s -u k3s-agent -u k7d-k3s --no-pager -n 80 || true",
        ],
        timeout_s=15,
    )
    raise RuntimeError(
        f"ubuntu cid={cid}: /readyz never ok after {ceiling_s}s ({last})\n"
        f"{logs['stdout']}"
    )


def wait_unit_active(cid: int, unit: str, ceiling_s: float = 120) -> None:
    deadline = time.monotonic() + ceiling_s
    last = ""
    while time.monotonic() < deadline:
        r = agent.exec_cmd(
            cid, ["systemctl", "is-active", unit], timeout_s=8
        )
        last = (r["stdout"] or "").strip()
        if last == "active":
            return
        time.sleep(2)
    raise RuntimeError(
        f"ubuntu cid={cid}: {unit} never active after {ceiling_s}s (last={last!r})"
    )


def write_host_kubeconfig(cid: int, server_ip: str, dest: Path) -> tuple[Path, Path, Path]:
    r = agent.exec_cmd(cid, ["cat", "/etc/rancher/k3s/k3s.yaml"], timeout_s=10)
    if r["exit_code"] != 0:
        raise RuntimeError(
            f"cat k3s.yaml failed: stderr={r['stderr']!r} stdout={r['stdout']!r}"
        )
    yaml = r["stdout"]
    if "127.0.0.1" not in yaml and "localhost" not in yaml:
        raise RuntimeError(f"k3s.yaml does not point at loopback:\n{yaml}")
    rewritten = yaml.replace(
        "https://127.0.0.1:6443", f"https://{server_ip}:6443"
    ).replace("https://localhost:6443", f"https://{server_ip}:6443")
    dest.mkdir(parents=True, exist_ok=True)
    kube = dest / "kubeconfig"
    kube.write_text(rewritten)

    def field(key: str) -> bytes:
        for line in rewritten.splitlines():
            if line.lstrip().startswith(key):
                b64 = line.split()[1]
                return subprocess.run(
                    ["base64", "-d"],
                    input=b64.encode(),
                    check=True,
                    capture_output=True,
                ).stdout
        raise RuntimeError(f"no {key} in kubeconfig")

    cert = dest / "client.pem"
    key = dest / "client-key.pem"
    ca = dest / "ca.crt"
    cert.write_bytes(field("client-certificate-data:"))
    key.write_bytes(field("client-key-data:"))
    ca.write_bytes(field("certificate-authority-data:"))
    return kube, cert, key


# Same pin as 25a-inc3 / sensors.py. Pull before helm so a registry
# or DNS failure is loud in ~3 min, not a 600 s ContainerCreating wait.
CILIUM_PULL_IMAGE = "quay.io/cilium/cilium:v1.16.10"
CILIUM_PULL_S = 180


def assert_guest_egress(cids: list[int]) -> None:
    """Cilium image pull hangs in ContainerCreating without IPv4 egress."""
    if not cids:
        raise RuntimeError("assert_guest_egress: no guest cids")
    for cid in cids:
        r = agent.exec_cmd(
            cid, ["ping", "-c", "1", "-W", "5", "8.8.8.8"], timeout_s=12
        )
        if r["exit_code"] != 0:
            raise RuntimeError(
                f"guest cid={cid} has no IPv4 egress (ping 8.8.8.8): "
                f"stdout={r.get('stdout')!r} stderr={r.get('stderr')!r}"
            )


def assert_guest_image_pull(
    cids: list[int], image: str = CILIUM_PULL_IMAGE
) -> None:
    """Resolve quay.io and `crictl pull` Cilium. Helm Ready-wait is 600 s."""
    if not cids:
        raise RuntimeError("assert_guest_image_pull: no guest cids")
    for cid in cids:
        dns = agent.exec_cmd(
            cid,
            ["sh", "-c", "getent hosts quay.io || ping -c 1 -W 5 quay.io"],
            timeout_s=15,
        )
        if dns["exit_code"] != 0:
            raise RuntimeError(
                f"guest cid={cid} cannot resolve quay.io: "
                f"stdout={dns.get('stdout')!r} stderr={dns.get('stderr')!r}"
            )
        r = agent.exec_cmd(
            cid, ["k3s", "crictl", "pull", image], timeout_s=CILIUM_PULL_S
        )
        if r["exit_code"] != 0:
            raise RuntimeError(
                f"guest cid={cid} crictl pull {image} failed: "
                f"stdout={r.get('stdout')!r} stderr={r.get('stderr')!r}"
            )


def wait_nodes_present(kubeconfig: Path, names: list[str], ceiling_s: float) -> None:
    """Nodes registered. With k7d.cni=none they stay NotReady until Cilium."""
    _wait_nodes(kubeconfig, names, ceiling_s, ready=False)


def wait_nodes_ready(kubeconfig: Path, names: list[str], ceiling_s: float) -> None:
    _wait_nodes(kubeconfig, names, ceiling_s, ready=True)


def wait_nodes_ready_on_bridge(
    bridge: str,
    cert: Path,
    key: Path,
    ceiling_s: float,
    *,
    want: int = 3,
) -> None:
    """Ready-wait bound to `bridge`. Host kubectl to 10.200.0.2 is wrong
    when another Ubuntu cluster is already using those guest IPs
    (reset n>1, or a leftover fork source)."""
    from scoring import curl_nodes_ready

    deadline = time.monotonic() + ceiling_s
    while time.monotonic() < deadline:
        if curl_nodes_ready(bridge, cert=cert, key=key, want=want):
            log.info("ubuntu cluster Ready via %s (want=%s)", bridge, want)
            return
        time.sleep(3)
    raise RuntimeError(
        f"ubuntu cluster never Ready via {bridge} after {ceiling_s}s "
        "(do not fall back to host kubectl / 10.200.0.2)"
    )


def wait_nodes_present_on_bridge(
    bridge: str,
    cert: Path,
    key: Path,
    ceiling_s: float,
    *,
    want: int = 3,
) -> None:
    """Nodes registered via `bridge`. Ready waits until Cilium (cni=none)."""
    from scoring import curl_nodes_present

    deadline = time.monotonic() + ceiling_s
    while time.monotonic() < deadline:
        if curl_nodes_present(bridge, cert=cert, key=key, want=want):
            log.info("ubuntu cluster present via %s (want=%s)", bridge, want)
            return
        time.sleep(3)
    raise RuntimeError(
        f"ubuntu cluster never present via {bridge} after {ceiling_s}s "
        "(do not fall back to host kubectl / 10.200.0.2)"
    )


def _wait_nodes(
    kubeconfig: Path, names: list[str], ceiling_s: float, *, ready: bool
) -> None:
    deadline = time.monotonic() + ceiling_s
    last = ""
    want_state = "Ready" if ready else None
    while time.monotonic() < deadline:
        r = subprocess.run(
            ["kubectl", "--kubeconfig", str(kubeconfig), "get", "nodes", "--no-headers"],
            check=False,
            capture_output=True,
            text=True,
        )
        last = (r.stdout or "") + (r.stderr or "")
        if r.returncode == 0:
            found = 0
            for want in names:
                for line in (r.stdout or "").splitlines():
                    cols = line.split()
                    if len(cols) < 2 or cols[0] != want:
                        continue
                    if want_state is None or cols[1] == want_state:
                        found += 1
                        break
            if found == len(names):
                log.info(
                    "ubuntu cluster: %s %s\n%s",
                    len(names),
                    "Ready" if ready else "present",
                    r.stdout,
                )
                return
        time.sleep(3)
    kind = "Ready" if ready else "present"
    raise RuntimeError(
        f"ubuntu cluster: {names} never {kind} after {ceiling_s}s\n{last}"
    )


def node_names(server_ip: str) -> list[str]:
    def name(ip: str) -> str:
        return "k7d-" + ip.replace(".", "-")

    # vm_index 0/1/2 → 10.200.0.2/3/4
    return [name(guest_ip(i)) for i in range(3)]


def persist_meta(dest: Path, payload: dict[str, Any]) -> None:
    dest.mkdir(parents=True, exist_ok=True)
    (dest / "meta.json").write_text(json.dumps(payload, indent=2))


def load_meta(dest: Path) -> dict[str, Any] | None:
    p = dest / "meta.json"
    if not p.is_file():
        return None
    return json.loads(p.read_text())


def certs_dir(tree_id: str) -> Path:
    return Path(f"/tmp/k7-gym-ubuntu-{tree_id}")


def remove_disks(paths: list[Path]) -> None:
    for p in paths:
        try:
            p.unlink()
        except FileNotFoundError:
            continue
        except OSError as e:
            log.warning("unlink %s: %s", p, e)


def remove_tree_disks(tree_id: str) -> int:
    """Unlink `ubuntu-gym-{tree_id}-*.img`. tree_drop does not."""
    if not tree_id:
        raise RuntimeError("remove_tree_disks: empty tree_id")
    n = 0
    for p in DISKS_DIR.glob(f"ubuntu-gym-{tree_id}-*.img"):
        try:
            p.unlink()
            n += 1
        except FileNotFoundError:
            continue
        except OSError as e:
            log.warning("unlink %s: %s", p, e)
    return n


def prune_unused_base_images(base_dir: Path | None = None) -> int:
    """Delete unused `ubuntu-24.04-*` keys. Keep the newest .img's key.

    `build-node-image.sh` content-keys a new image whenever the builder
    changes. Leftover keys plus live gym disks fill the 96G XFS
    (CHALLENGES #164).
    """
    d = base_dir or BASE_IMAGES
    if not d.is_dir():
        return 0
    imgs = sorted(
        d.glob("ubuntu-24.04-*.img"),
        key=lambda p: p.stat().st_mtime,
        reverse=True,
    )
    if not imgs:
        return 0
    keep = imgs[0].name[len("ubuntu-24.04-") :].removesuffix(".img")
    if not keep:
        raise RuntimeError(f"base image name has no content key: {imgs[0]}")
    n = 0
    for p in sorted(d.iterdir()):
        name = p.name
        if not name.startswith("ubuntu-24.04-"):
            continue
        if keep in name:
            continue
        log.warning("prune unused base image %s (keep key %s)", p, keep)
        try:
            p.unlink()
            n += 1
        except OSError as e:
            log.warning("unlink %s: %s", p, e)
    return n


def sweep_orphaned_gym_disks() -> int:
    """Delete `ubuntu-gym-*.img` whose creating gym pid is dead.

    Reset n=8 dirties each reflink clone (k3s + Tetragon layers).
    The 96 GiB loop fills if a 502 abandon leaves the clones behind
    (`tree_drop` stops VMs, does not unlink gym-owned images).
    """
    if not DISKS_DIR.is_dir():
        return 0
    n = 0
    for p in DISKS_DIR.glob("ubuntu-gym-*.img"):
        stem = p.name.removesuffix(".img")
        pid_s = stem.rsplit("-", 1)[-1]
        if not pid_s.isdigit():
            raise RuntimeError(f"gym disk name has no pid: {p}")
        if Path(f"/proc/{pid_s}").is_dir():
            continue
        try:
            p.unlink()
            n += 1
            log.warning("swept orphan gym disk %s (pid %s dead)", p, pid_s)
        except FileNotFoundError:
            continue
        except OSError as e:
            log.warning("unlink %s: %s", p, e)
    return n


def memory_floor_error(memory_mb: int) -> str | None:
    if memory_mb < NODE_MEMORY_MB:
        return (
            f"GYM_MEMORY_MB={memory_mb} < NODE_MEMORY_MB={NODE_MEMORY_MB} "
            f"(ubuntu mode refuses the create-mode leftover default of 256; "
            f"a 25a node is {NODE_MEMORY_MB} MiB guest / ~1.35 GiB host RAM)"
        )
    return None


def tree_budget_floor_error(
    *,
    vm_count: int,
    memory_mb: int,
    max_live_vms: int,
    max_live_ram_bytes: int,
) -> str | None:
    """1 source + 1 fork must fit the TreeBudget. Spell the arithmetic."""
    min_vms = vm_count + vm_count
    need_guest = min_vms * memory_mb * 1024 * 1024
    measured = min_vms * HOST_RAM_PER_NODE_BYTES
    reasons: list[str] = []
    if min_vms > max_live_vms:
        reasons.append(
            f"need {min_vms} live VMs (source={vm_count} + n=1 * "
            f"vms_per_branch={vm_count}) > GYM_MAX_LIVE_VMS={max_live_vms}"
        )
    if need_guest > max_live_ram_bytes:
        reasons.append(
            f"need {need_guest} RAM bytes ({min_vms} VMs * {memory_mb} MiB) "
            f"> GYM_MAX_LIVE_RAM_BYTES={max_live_ram_bytes} "
            f"(measured ~1.35 GiB/node × {min_vms} = {measured} B)"
        )
    if not reasons:
        return None
    return "ubuntu TreeBudget cannot fit 1 source + 1 fork: " + "; ".join(reasons)
