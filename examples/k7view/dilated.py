"""Ubuntu k3s source + guest-time rollout scoring for ``--profile ubuntu-dilated``.

Talks to k7d the same way the gym does (CreateVm × 3, then adopt). A
``tree_create_cluster`` cannot carry per-node disks or k3s role cmdlines.
k7view stays a pure observer — this module is the scenario driver.
"""

from __future__ import annotations

import json
import subprocess
import sys
import threading
import time
from pathlib import Path
from typing import Any, Callable

HERE = Path(__file__).resolve().parent
REPO = HERE.parents[1]
sys.path.insert(0, str(REPO / "gym"))

import agent as guest_agent  # noqa: E402
import ubuntu as ubuntu_src  # noqa: E402
from host import k7_bridge_name, list_bridges  # noqa: E402

from probe import parse_uptime  # noqa: E402

DILATION_FACTOR = 8
DILATED_WAVES = [6, 4, 4]
DILATED_MAX_LIVE_VMS = 24
ROLLOUT_INITIAL_DELAY_S = 40
ROLLOUT_PERIOD_S = 10
ROLLOUT_REPLICAS = 2
# Under ×8 the readiness gate is ~5–6 s of wall. kubectl's --timeout is
# *guest* CLOCK — 30 guest-s expires before initialDelaySeconds: 40.
# 90 guest-s covers the delay + two periods; the host exec budget is
# wall (guest / N + slack). Not a host-side pace sleep.
ROLLOUT_GUEST_TIMEOUT_S = 120
ROLLOUT_WALL_TIMEOUT_S = 35
# Post-fork k3s recovery is compute/I/O (not dilated). Wave 0 from a
# live source is already Ready; later waves need a host-time settle.
FORK_SETTLE_WALL_S = 2.0
SLEEP8_WALL_S = 8.0


class JsonlLog:
    def __init__(self, path: Path | None) -> None:
        self.path = path
        self._fp = path.open("a") if path else None

    def write(self, event: str, **fields: Any) -> None:
        rec = {"ts": time.time(), "event": event, **fields}
        line = json.dumps(rec, separators=(",", ":"), default=str)
        extra = " ".join(f"{k}={fields[k]}" for k in fields)
        print(f"[scenario] {event} {extra}".rstrip(), flush=True)
        if self._fp is not None:
            self._fp.write(line + "\n")
            self._fp.flush()

    def close(self) -> None:
        if self._fp is not None:
            self._fp.close()
            self._fp = None


def dilated_budget() -> dict[str, int]:
    return {
        "max_live_vms": DILATED_MAX_LIVE_VMS,
        "max_live_ram_bytes": 64 * 1024**3,
        "max_disk_bytes": 256 * 1024**3,
        "max_chain_depth": 8,
    }


def dilation_token(text: str) -> str:
    """First token of state.sh's last line: ``patched`` or ``stock``."""
    last = text.strip().splitlines()[-1].strip() if text.strip() else ""
    return last.split()[0] if last.split() else ""


def require_patched_dilation() -> str:
    script = REPO / "utils" / "kvm-dilation" / "state.sh"
    if not script.is_file():
        raise SystemExit(f"dilation state helper missing: {script}")
    proc = subprocess.run(
        ["bash", str(script)],
        check=False,
        capture_output=True,
        text=True,
    )
    text = ((proc.stdout or "") + (proc.stderr or "")).strip()
    last = text.splitlines()[-1].strip() if text.splitlines() else ""
    # probe.c prints "patched (abi N, default factor F)" — only the first
    # token is the stock/patched bit (exit 0 / 1).
    if dilation_token(last) != "patched":
        raise SystemExit(
            f"ubuntu-dilated requires patched KVM modules; "
            f"utils/kvm-dilation/state.sh printed {last!r} (exit {proc.returncode}). "
            "Run `make remote-dilation-install` only when no other job owns the box."
        )
    return last


def live_dilation_map(client: Any, tree_id: str) -> dict[str, int]:
    resp = client.tree_nodes(tree_id)
    raw = resp.get("live_dilation") or {}
    out: dict[str, int] = {}
    for nid, factor in raw.items():
        try:
            out[str(nid)] = int(factor)
        except (TypeError, ValueError) as exc:
            raise RuntimeError(
                f"tree_nodes.live_dilation[{nid!r}] is not an int: {factor!r}"
            ) from exc
    return out


def assert_live_dilation(client: Any, tree_id: str, want: int) -> dict[str, int]:
    got = live_dilation_map(client, tree_id)
    nodes = client.tree_nodes(tree_id).get("nodes") or []
    live = [n["id"] for n in nodes if n.get("state") == "live" and "id" in n]
    bad = [nid for nid in live if got.get(nid, 1) != want]
    if bad:
        raise RuntimeError(
            f"live_dilation want ×{want} on live nodes, mismatches={bad} map={got}"
        )
    return got


def guest_uptime_s(cid: int) -> float:
    r = guest_agent.exec_cmd(cid, ["cat", "/proc/uptime"], timeout_s=8)
    up = parse_uptime((r.get("stdout") or "").strip())
    if up is None:
        raise RuntimeError(f"cid={cid}: /proc/uptime unparseable: {r}")
    return up


def guest_kubectl(cid: int, args: list[str], timeout_s: float = 60) -> dict[str, Any]:
    r = guest_agent.exec_cmd(cid, ["k3s", "kubectl", *args], timeout_s=timeout_s)
    return r


def pause_image(cid: int) -> str:
    r = guest_agent.exec_cmd(cid, ["k3s", "crictl", "images"], timeout_s=20)
    if r["exit_code"] != 0:
        raise RuntimeError(f"crictl images cid={cid}: {r}")
    for line in (r.get("stdout") or "").splitlines():
        if "pause" not in line.lower():
            continue
        parts = line.split()
        if len(parts) >= 2 and parts[0] != "IMAGE":
            return f"{parts[0]}:{parts[1]}"
    raise RuntimeError(f"no pause image on cid={cid}:\n{r.get('stdout')}")


def deploy_name(wave: int) -> str:
    if wave < 0:
        raise ValueError(f"wave must be >= 0, got {wave}")
    return f"k7-rollout-w{wave}"


def node_bridge(tree_id: str, node_id: str) -> str:
    """Fork bridges are ``{tree_id}-{node_id}``; adopt root is ``tree_id``."""
    if node_id == "root":
        return k7_bridge_name(tree_id)
    return k7_bridge_name(f"{tree_id}-{node_id}")


def rollout_manifest(image: str, name: str = "k7-rollout") -> str:
    """Deployment whose Ready gate is guest time (not a host sleep).

    Pause is scratch — hostPath ``/usr/bin`` alone cannot exec glibc
    ``true`` (CHALLENGES #201). PID 1 stays the pause binary.
    Per-wave name so a fork of a winner does not inherit a Ready gate.
    """
    if not image or ":" not in image:
        raise ValueError(f"rollout image must be name:tag, got {image!r}")
    if not name or name != name.lower() or "/" in name or "_" in name:
        raise ValueError(f"deploy name must be a DNS label, got {name!r}")
    return (
        "apiVersion: apps/v1\n"
        "kind: Deployment\n"
        "metadata:\n"
        f"  name: {name}\n"
        "spec:\n"
        f"  replicas: {ROLLOUT_REPLICAS}\n"
        "  selector:\n"
        "    matchLabels:\n"
        f"      app: {name}\n"
        "  template:\n"
        "    metadata:\n"
        "      labels:\n"
        f"        app: {name}\n"
        "    spec:\n"
        "      containers:\n"
        "      - name: wait\n"
        f"        image: {image}\n"
        "        imagePullPolicy: IfNotPresent\n"
        "        volumeMounts:\n"
        "        - name: hostbin\n"
        "          mountPath: /hostbin\n"
        "          readOnly: true\n"
        "        - name: hostlib\n"
        "          mountPath: /lib\n"
        "          readOnly: true\n"
        "        - name: hostlib64\n"
        "          mountPath: /lib64\n"
        "          readOnly: true\n"
        "        readinessProbe:\n"
        "          exec:\n"
        "            command: [\"/hostbin/true\"]\n"
        f"          initialDelaySeconds: {ROLLOUT_INITIAL_DELAY_S}\n"
        f"          periodSeconds: {ROLLOUT_PERIOD_S}\n"
        "          failureThreshold: 1\n"
        "      volumes:\n"
        "      - name: hostbin\n"
        "        hostPath:\n"
        "          path: /usr/bin\n"
        "          type: Directory\n"
        "      - name: hostlib\n"
        "        hostPath:\n"
        "          path: /lib\n"
        "          type: Directory\n"
        "      - name: hostlib64\n"
        "        hostPath:\n"
        "          path: /lib64\n"
        "          type: Directory\n"
    )


def apply_argv(path: str) -> list[str]:
    # --validate=false skips the OpenAPI fetch. Under ×8 that GET's 32s
    # guest timeout is ~4s wall; TLS is compute and does not compress.
    # --request-timeout is guest CLOCK — 120s ≈ 15s wall at ×8.
    return [
        "apply",
        "--validate=false",
        "--request-timeout=120s",
        "-f",
        path,
    ]


def apply_rollout(cid: int, yaml: str, *, attempts: int = 4) -> None:
    path = "/tmp/k7-dilated-rollout.yaml"
    guest_agent.write_file(cid, path, yaml.encode())
    last = ""
    for i in range(attempts):
        r = guest_kubectl(cid, apply_argv(path), timeout_s=20)
        if r["exit_code"] == 0:
            return
        last = (
            f"exit={r['exit_code']} stderr={r.get('stderr')!r} "
            f"stdout={r.get('stdout')!r}"
        )
        time.sleep(0.4)
    raise RuntimeError(f"kubectl apply cid={cid} after {attempts} tries: {last}")


def wait_apiserver(
    cid: int,
    *,
    tree_id: str,
    node_id: str,
    wall_s: float = 20,
    settle_s: float = 0.0,
) -> None:
    """Wait for /readyz with a long *guest* request-timeout.

    Host ``curl`` to 6443 needs the k3s client cert (anonymous /readyz
    is off). A short guest ``--request-timeout`` expires in wall/N and
    never sees the post-fork apiserver recover (CHALLENGES #202).
    ``settle_s`` is host-time I/O recovery, not a rollout pace sleep.
    """
    del tree_id  # reserved: host-bridge wait needs certs we do not have
    deadline = time.monotonic() + wall_s
    last = ""
    ok_at: float | None = None
    while time.monotonic() < deadline:
        r = guest_agent.exec_cmd(
            cid,
            [
                "sh",
                "-c",
                "k3s kubectl get --raw=/readyz --request-timeout=32s 2>&1 || true",
            ],
            timeout_s=6,
        )
        out = (r.get("stdout") or "") + (r.get("stderr") or "")
        if r.get("exit_code") == 0 and "ok" in out:
            if ok_at is None:
                ok_at = time.monotonic()
            if time.monotonic() - ok_at >= settle_s:
                return
        else:
            ok_at = None
            last = f"exit={r.get('exit_code')} out={out[-160:]!r}"
        time.sleep(0.2)
    raise RuntimeError(
        f"cid={cid} node={node_id}: /readyz never ok in {wall_s}s wall ({last})"
    )


def wait_rollout(cid: int, name: str, wall_s: float) -> dict[str, Any]:
    """Poll rollout status. ``--timeout`` is guest seconds (see module constants)."""
    r = guest_kubectl(
        cid,
        [
            "rollout",
            "status",
            f"deploy/{name}",
            f"--timeout={ROLLOUT_GUEST_TIMEOUT_S}s",
            "--request-timeout=120s",
        ],
        timeout_s=wall_s + 15,
    )
    return r


def spot_check_sleep8(cid: int) -> float:
    """``sleep 8`` inside a ×8 guest must cost ~1 s of wall."""
    t0 = time.perf_counter()
    r = guest_agent.exec_cmd(cid, ["sleep", "8"], timeout_s=20)
    wall = time.perf_counter() - t0
    if r["exit_code"] != 0:
        raise RuntimeError(f"sleep 8 cid={cid}: {r}")
    if wall > 2.5:
        raise RuntimeError(
            f"sleep 8 on cid={cid} cost {wall:.3f}s wall — dilation is not ×8"
        )
    return wall


def server_cid(fork: dict[str, Any]) -> int:
    cids = fork.get("guest_cids") or []
    if not cids:
        raise RuntimeError(f"fork {fork.get('node_id')} has no guest_cids")
    return int(cids[0])


def score_rollouts(
    forks: list[dict[str, Any]],
    image: str,
    *,
    tree_id: str,
    deploy_name: str,
    settle_s: float = 0.0,
    on_line: Callable[[str, str], None] | None = None,
) -> list[tuple[float, dict[str, Any], dict[str, Any]]]:
    """Apply the readiness-gated Deployment on every branch in parallel.

    Reward is completion order (first Ready wins). Tie-break is branch index.
    Returns ``(reward, fork, detail)`` sorted best-first.
    """
    if not tree_id:
        raise ValueError("score_rollouts requires tree_id (host-bridge /readyz)")
    yaml = rollout_manifest(image, deploy_name)
    details: dict[str, dict[str, Any]] = {}
    lock = threading.Lock()

    def one(idx: int, fork: dict[str, Any]) -> None:
        nid = fork["node_id"]
        cid = server_cid(fork)
        detail: dict[str, Any] = {
            "node_id": nid,
            "index": idx,
            "cid": cid,
            "ready": False,
            "wall_s": None,
            "guest_s": None,
            "error": "",
        }
        t0 = time.perf_counter()
        up0 = None
        try:
            wait_apiserver(
                cid,
                tree_id=tree_id,
                node_id=nid,
                wall_s=20.0 + settle_s,
                settle_s=settle_s,
            )
            up0 = guest_uptime_s(cid)
            apply_rollout(cid, yaml)
            if on_line:
                on_line(
                    nid,
                    f"applied {deploy_name} on cid={cid} (guest uptime {up0:.1f}s)",
                )
            status = wait_rollout(cid, deploy_name, ROLLOUT_WALL_TIMEOUT_S)
            up1 = guest_uptime_s(cid)
            detail["ready"] = status.get("exit_code") == 0
            detail["guest_s"] = round(up1 - up0, 3)
            if not detail["ready"]:
                err = (
                    (status.get("stderr") or "") + " " + (status.get("stdout") or "")
                ).strip()
                detail["error"] = err[:240]
            if on_line:
                on_line(
                    nid,
                    (
                        f"rollout {'Ready' if detail['ready'] else 'timeout'} "
                        f"wall={time.perf_counter() - t0:.2f}s guest={detail['guest_s']:.1f}s"
                    ),
                )
        except Exception as exc:  # noqa: BLE001 — one branch must not kill the wave
            detail["error"] = str(exc)[:240]
            if on_line:
                on_line(nid, f"rollout error: {detail['error']}")
        detail["wall_s"] = round(time.perf_counter() - t0, 3)
        with lock:
            details[nid] = detail

    threads = [
        threading.Thread(target=one, args=(i, f), daemon=True)
        for i, f in enumerate(forks)
    ]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=ROLLOUT_WALL_TIMEOUT_S + 40)

    ranked: list[tuple[float, dict[str, Any], dict[str, Any]]] = []
    ready_times: list[tuple[float, int, str]] = []
    for i, f in enumerate(forks):
        d = details.get(f["node_id"]) or {
            "node_id": f["node_id"],
            "index": i,
            "ready": False,
            "wall_s": None,
            "guest_s": None,
            "error": "thread did not finish",
        }
        if d.get("ready"):
            ready_times.append((float(d["wall_s"]), i, f["node_id"]))
        ranked.append((0.0, f, d))
    ready_times.sort()
    order = {nid: pos for pos, (_w, _i, nid) in enumerate(ready_times)}
    out: list[tuple[float, dict[str, Any], dict[str, Any]]] = []
    for _rew, f, d in ranked:
        if d.get("ready"):
            # First Ready = 1.0, later Ready decay by rank; unfinished = 0.
            reward = 1.0 - (order[f["node_id"]] / max(1, len(order)))
        else:
            reward = 0.0
        d["reward"] = round(reward, 3)
        out.append((reward, f, d))
    out.sort(key=lambda x: (-x[0], x[2].get("index", 0)))
    return out


def create_ubuntu_source(
    client: Any,
    *,
    tree_id: str,
    budget: dict[str, int],
    dilation: int,
    log: JsonlLog,
    timeout_s: float = 300,
) -> dict[str, Any]:
    """CreateVm × 3 (Ubuntu + k3s flannel) at ``dilation``, then adopt."""
    if dilation != DILATION_FACTOR:
        raise RuntimeError(
            f"ubuntu-dilated source dilation must be {DILATION_FACTOR}, got {dilation}"
        )
    manifest = ubuntu_src.build_or_cache_image(REPO)
    kernel = Path(str(manifest["kernel"]))
    base = Path(str(manifest["image"]))
    if "initramfs" in str(kernel):
        raise RuntimeError(
            f"ubuntu source refused busybox guest path {kernel} "
            "(CHALLENGES #72: never K7D_KERNEL/K7D_INITRD)"
        )
    server_ip = ubuntu_src.guest_ip(0)
    created_ids: list[str] = []
    disks: list[Path] = []
    cids: list[int] = []
    before = list_bridges()
    t0 = time.perf_counter()
    try:
        for idx, role in enumerate(("server", "agent", "agent")):
            dest = ubuntu_src.DISKS_DIR / (
                f"ubuntu-k7view-{tree_id}-{idx}-{time.time_ns()}.img"
            )
            ubuntu_src.reflink_disk(base, dest)
            disks.append(dest)
            ip = ubuntu_src.guest_ip(idx)
            cmdline = ubuntu_src.node_cmdline(
                ip, ubuntu_src.k3s_spec(role, server_ip), cni=None
            )
            cfg = {
                "kernel": str(kernel),
                "memory_mb": ubuntu_src.NODE_MEMORY_MB,
                "vcpus": ubuntu_src.NODE_VCPUS,
                "vsock": True,
                "dilation": dilation,
                "cmdline": cmdline,
                "block_devices": [{"host_path": str(dest), "readonly": False}],
                "network": {
                    "cluster_id": tree_id,
                    "vm_index": idx,
                    "pod_netns": None,
                },
            }
            log.write("create_vm", role=role, vm_index=idx, ip=ip, dilation=dilation)
            resp = client.create_vm(cfg, timeout=timeout_s)
            if resp.get("status") != "vm_created":
                raise RuntimeError(f"create_vm ubuntu {role}/{idx}: {resp}")
            created_ids.append(resp["vm_id"])
            cid = int(resp["guest_cid"])
            cids.append(cid)
            dump = lambda c=cid: str(client.dump_serial(guest_cid=c).get("console") or "")
            ubuntu_src.wait_agent(cid, ubuntu_src.BOOT_TO_AGENT_S, dump=dump)
            ubuntu_src.wait_systemd_healthy(cid)
            if idx == 0:
                ubuntu_src.wait_guest_readyz(cid, ubuntu_src.CLUSTER_READY_S)
            else:
                ubuntu_src.wait_unit_active(cid, "k3s-agent.service")
        names = ubuntu_src.node_names(server_ip)
        deadline = time.monotonic() + ubuntu_src.CLUSTER_READY_S
        last = ""
        while time.monotonic() < deadline:
            r = guest_kubectl(cids[0], ["get", "nodes", "--no-headers"], timeout_s=20)
            last = (r.get("stdout") or "") + (r.get("stderr") or "")
            if r["exit_code"] == 0:
                found = 0
                for want in names:
                    for line in (r.get("stdout") or "").splitlines():
                        cols = line.split()
                        if len(cols) >= 2 and cols[0] == want and cols[1] == "Ready":
                            found += 1
                            break
                if found == len(names):
                    break
            time.sleep(2)
        else:
            raise RuntimeError(
                f"ubuntu cluster {names} never Ready after {ubuntu_src.CLUSTER_READY_S}s\n{last}"
            )
        adopted = client.tree_adopt_cluster(
            created_ids, tree_id=tree_id, budget=budget
        )
        cids = [int(c) for c in adopted.get("guest_cids") or cids]
        new = list_bridges() - before
        bridge = k7_bridge_name(tree_id)
        if bridge not in list_bridges() and new:
            bridge = sorted(new)[0]
        create_ms = (time.perf_counter() - t0) * 1000
        image = pause_image(cids[0])
        sleep8 = spot_check_sleep8(cids[0])
        factors = assert_live_dilation(client, adopted.get("tree_id") or tree_id, dilation)
        log.write(
            "source_ready",
            create_ms=round(create_ms, 1),
            root_id=adopted["root_id"],
            guest_cids=cids,
            bridge=bridge,
            live_dilation=factors,
            pause_image=image,
            sleep8_wall_s=round(sleep8, 3),
        )
        return {
            "tree_id": adopted.get("tree_id") or tree_id,
            "root_id": adopted["root_id"],
            "guest_cids": cids,
            "bridge": bridge,
            "disks": disks,
            "vm_ids": created_ids,
            "create_ms": create_ms,
            "pause_image": image,
            "sleep8_wall_s": sleep8,
        }
    except Exception:
        for vm_id in created_ids:
            try:
                client.stop_vm(vm_id)
            except RuntimeError:
                pass
        try:
            client.tree_drop(tree_id)
        except RuntimeError:
            pass
        ubuntu_src.remove_disks(disks)
        raise
