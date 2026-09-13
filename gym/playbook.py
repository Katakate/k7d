"""20-page SRE exam for GYM_SCOREBOARD=playbook.

Same pages, same order, every member. Reward after turn t is
passed/t — not a Tetragon 0.8/1.0 bit, not UID uniqueness.
Poll ceilings, not sleeps. Image is pinned to one already on
the Ubuntu guests; this module never pulls.
"""

from __future__ import annotations

import json
import logging
import os
import shutil
import subprocess
import tempfile
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable

from scoring import curl_api, curl_nodes_ready, curl_readyz, terms

log = logging.getLogger("gym.playbook")

NS = "k7-exam"
DEPLOY = "web"
SERVICE = "web"
# Tetragon inject image. Discover digest at harvest.
PINNED_IMAGE = "docker.io/library/busybox:1.36.1"
PINNED_AIRGAP = Path("/var/cache/k7d-ubuntu/busybox-1.36.1.tar")
PINNED_AIRGAP_NAME = "busybox-1.36.1.tar"
PAGE_CEILING_S = 20.0
POLL_S = 0.5
PINNED_IMPORT_S = 60.0
INJECT_FAULTS = frozenset({"kill-member-0", "tetra-churn", "partition-member-0"})


@dataclass
class PageResult:
    ok: bool
    elapsed_s: float
    detail: str


@dataclass
class Ctx:
    """Host-side API + vsock exec for one member."""

    bridge: str
    cert: Path | None
    key: Path | None
    guest_ip: str = "10.200.0.2"
    guest_cids: list[int] = field(default_factory=list)
    image: str = PINNED_IMAGE
    curl: Callable[..., tuple[int, str, str]] = curl_api
    readyz: Callable[..., bool] = curl_readyz
    nodes_ready: Callable[..., bool] = curl_nodes_ready
    exec_cmd: Callable[..., dict[str, Any]] | None = None


@dataclass(frozen=True)
class Page:
    id: str
    run: Callable[[Ctx], PageResult]


def refuse_inject_fault(fault_id: str) -> None:
    if fault_id in INJECT_FAULTS or (fault_id and fault_id != "none"):
        raise ValueError(
            f"GYM_SCOREBOARD=playbook is loud with inject fault "
            f"{fault_id!r}; use fault_id=none (no env0-only poke)"
        )


def require_playbook_payload(row: dict[str, Any]) -> dict[str, Any]:
    pb = row.get("playbook")
    if not isinstance(pb, dict):
        raise ValueError(
            f"playbook score row missing playbook payload: {row!r}"[:240]
        )
    for key in ("turn", "passed", "total", "steps", "step_s"):
        if key not in pb:
            raise ValueError(f"playbook payload missing {key}: {pb!r}"[:240])
    return pb


def poll(pred: Callable[[], tuple[bool, str]], ceiling_s: float) -> PageResult:
    """Return as soon as pred is true. ceiling_s is a timeout, not a sleep."""
    t0 = time.perf_counter()
    last = ""
    deadline = t0 + ceiling_s
    while True:
        try:
            ok, last = pred()
        except (OSError, RuntimeError, json.JSONDecodeError, TypeError, ValueError) as e:
            ok, last = False, str(e)
        elapsed = time.perf_counter() - t0
        if ok:
            return PageResult(True, elapsed, last)
        if time.perf_counter() >= deadline:
            return PageResult(False, elapsed, last)
        time.sleep(POLL_S)


def _api(
    ctx: Ctx, path: str, *, method: str = "GET", body: str | None = None, ctype: str | None = None
) -> tuple[int, Any, str]:
    code, raw, err = ctx.curl(
        ctx.bridge,
        path,
        guest_ip=ctx.guest_ip,
        method=method,
        timeout_s=8,
        cert=ctx.cert,
        key=ctx.key,
        body=body,
        content_type=ctype,
    )
    parsed: Any = raw
    if raw:
        try:
            parsed = json.loads(raw)
        except json.JSONDecodeError:
            parsed = raw
    return code, parsed, err


def _get(ctx: Ctx, path: str) -> tuple[int, Any, str]:
    return _api(ctx, path)


def _post(ctx: Ctx, path: str, obj: dict[str, Any]) -> tuple[int, Any, str]:
    return _api(
        ctx,
        path,
        method="POST",
        body=json.dumps(obj),
        ctype="application/json",
    )


def _patch(ctx: Ctx, path: str, obj: dict[str, Any]) -> tuple[int, Any, str]:
    return _api(
        ctx,
        path,
        method="PATCH",
        body=json.dumps(obj),
        ctype="application/merge-patch+json",
    )


def _items(body: Any) -> list[Any]:
    if isinstance(body, dict):
        got = body.get("items")
        if isinstance(got, list):
            return got
    return []


def page_api_live(ctx: Ctx) -> PageResult:
    t0 = time.perf_counter()
    ok = bool(
        ctx.readyz(ctx.bridge, ctx.guest_ip, cert=ctx.cert, key=ctx.key)
    )
    return PageResult(ok, time.perf_counter() - t0, "readyz" if ok else "no /readyz ok")


def page_nodes_listed(ctx: Ctx) -> PageResult:
    def pred() -> tuple[bool, str]:
        code, body, err = _get(ctx, "/api/v1/nodes")
        n = len(_items(body))
        return n >= 3, f"http={code} nodes={n} {err}"

    return poll(pred, PAGE_CEILING_S)


def page_nodes_ready(ctx: Ctx) -> PageResult:
    def pred() -> tuple[bool, str]:
        ok = ctx.nodes_ready(
            ctx.bridge, ctx.guest_ip, cert=ctx.cert, key=ctx.key, want=3
        )
        return ok, "3 Ready" if ok else "nodes not Ready"

    return poll(pred, PAGE_CEILING_S)


def page_namespace(ctx: Ctx) -> PageResult:
    t0 = time.perf_counter()
    code, body, err = _get(ctx, f"/api/v1/namespaces/{NS}")
    if code == 200 and isinstance(body, dict) and body.get("metadata", {}).get("name") == NS:
        return PageResult(True, time.perf_counter() - t0, "exists")
    ns = {
        "apiVersion": "v1",
        "kind": "Namespace",
        "metadata": {"name": NS},
    }
    code, body, err = _post(ctx, "/api/v1/namespaces", ns)
    if code in (200, 201):
        return PageResult(True, time.perf_counter() - t0, f"created http={code}")
    if code == 409:
        return PageResult(True, time.perf_counter() - t0, "already exists")
    return PageResult(False, time.perf_counter() - t0, f"http={code} {err}")


def _deploy_body(image: str, replicas: int = 1) -> dict[str, Any]:
    return {
        "apiVersion": "apps/v1",
        "kind": "Deployment",
        "metadata": {"name": DEPLOY, "namespace": NS},
        "spec": {
            "replicas": replicas,
            "selector": {"matchLabels": {"app": "web"}},
            "template": {
                "metadata": {"labels": {"app": "web"}},
                "spec": {
                    "containers": [
                        {
                            "name": "web",
                            "image": image,
                            "imagePullPolicy": "IfNotPresent",
                            "command": [
                                "sh",
                                "-c",
                                "echo k7-exam-ok > /tmp/index.html && "
                                "httpd -f -p 8080 -h /tmp",
                            ],
                            "ports": [{"containerPort": 8080}],
                        }
                    ]
                },
            },
        },
    }


def page_apply_deploy(ctx: Ctx) -> PageResult:
    t0 = time.perf_counter()
    path = f"/apis/apps/v1/namespaces/{NS}/deployments/{DEPLOY}"
    code, body, err = _get(ctx, path)
    if code == 200 and isinstance(body, dict):
        return PageResult(True, time.perf_counter() - t0, "exists")
    code, body, err = _post(
        ctx,
        f"/apis/apps/v1/namespaces/{NS}/deployments",
        _deploy_body(ctx.image),
    )
    if code in (200, 201, 409):
        return PageResult(True, time.perf_counter() - t0, f"http={code}")
    return PageResult(False, time.perf_counter() - t0, f"http={code} {err}")


def page_pod_scheduled(ctx: Ctx) -> PageResult:
    def pred() -> tuple[bool, str]:
        code, body, err = _get(ctx, f"/api/v1/namespaces/{NS}/pods")
        scheduled = 0
        pending = 0
        for p in _items(body):
            spec = p.get("spec") or {}
            phase = (p.get("status") or {}).get("phase") or ""
            if spec.get("nodeName"):
                scheduled += 1
            if phase == "Pending" and not spec.get("nodeName"):
                pending += 1
        return scheduled >= 1, f"http={code} scheduled={scheduled} pending={pending} {err}"

    return poll(pred, PAGE_CEILING_S)


def _available(ctx: Ctx, want: int, *, exact: bool = False) -> tuple[bool, str]:
    code, body, err = _get(
        ctx, f"/apis/apps/v1/namespaces/{NS}/deployments/{DEPLOY}"
    )
    if not isinstance(body, dict):
        return False, f"http={code} {err}"
    avail = int((body.get("status") or {}).get("availableReplicas") or 0)
    if exact:
        return avail == want, f"availableReplicas={avail} want=={want}"
    return avail >= want, f"availableReplicas={avail} want>={want}"


def page_available_1(ctx: Ctx) -> PageResult:
    return poll(lambda: _available(ctx, 1), PAGE_CEILING_S)


def page_apply_svc(ctx: Ctx) -> PageResult:
    t0 = time.perf_counter()
    path = f"/api/v1/namespaces/{NS}/services/{SERVICE}"
    code, body, err = _get(ctx, path)
    if code == 200 and isinstance(body, dict):
        return PageResult(True, time.perf_counter() - t0, "exists")
    svc = {
        "apiVersion": "v1",
        "kind": "Service",
        "metadata": {"name": SERVICE, "namespace": NS},
        "spec": {
            "selector": {"app": "web"},
            "ports": [{"port": 80, "targetPort": 8080, "protocol": "TCP"}],
            "type": "ClusterIP",
        },
    }
    code, body, err = _post(ctx, f"/api/v1/namespaces/{NS}/services", svc)
    if code in (200, 201, 409):
        return PageResult(True, time.perf_counter() - t0, f"http={code}")
    return PageResult(False, time.perf_counter() - t0, f"http={code} {err}")


def _endpoints(ctx: Ctx) -> tuple[int, Any, str]:
    return _get(ctx, f"/api/v1/namespaces/{NS}/endpoints/{SERVICE}")


def page_ep_object(ctx: Ctx) -> PageResult:
    def pred() -> tuple[bool, str]:
        code, body, err = _endpoints(ctx)
        if code == 200 and isinstance(body, dict) and body.get("metadata"):
            return True, "endpoints object"
        return False, f"http={code} {err}"

    return poll(pred, PAGE_CEILING_S)


def _ep_addrs(body: Any) -> int:
    n = 0
    if not isinstance(body, dict):
        return 0
    for subset in body.get("subsets") or []:
        n += len(subset.get("addresses") or [])
    return n


def page_ep_addrs(ctx: Ctx) -> PageResult:
    def pred() -> tuple[bool, str]:
        code, body, err = _endpoints(ctx)
        n = _ep_addrs(body)
        return n >= 1, f"http={code} addrs={n} {err}"

    return poll(pred, PAGE_CEILING_S)


def _exec(ctx: Ctx, args: list[str], timeout_s: float = 12) -> dict[str, Any]:
    if ctx.exec_cmd is None:
        raise RuntimeError("playbook exec_cmd is not set")
    if not ctx.guest_cids:
        raise RuntimeError("playbook exec needs guest_cids")
    return ctx.exec_cmd(ctx.guest_cids[0], args, timeout_s)


def page_workload(ctx: Ctx) -> PageResult:
    def pred() -> tuple[bool, str]:
        r = _exec(
            ctx,
            [
                "k3s",
                "kubectl",
                "-n",
                NS,
                "exec",
                f"deploy/{DEPLOY}",
                "--",
                "wget",
                "-qO-",
                "http://127.0.0.1:8080/",
            ],
        )
        out = (r.get("stdout") or "") + (r.get("stderr") or "")
        ok = r.get("exit_code") == 0 and "k7-exam-ok" in out
        return ok, f"exit={r.get('exit_code')} out={out[-120:]!r}"

    return poll(pred, PAGE_CEILING_S)


def _scale(ctx: Ctx, n: int) -> PageResult:
    t0 = time.perf_counter()
    code, body, err = _patch(
        ctx,
        f"/apis/apps/v1/namespaces/{NS}/deployments/{DEPLOY}",
        {"spec": {"replicas": n}},
    )
    if code >= 400:
        return PageResult(False, time.perf_counter() - t0, f"http={code} {err}")

    def pred() -> tuple[bool, str]:
        c2, b2, e2 = _get(
            ctx, f"/apis/apps/v1/namespaces/{NS}/deployments/{DEPLOY}"
        )
        if not isinstance(b2, dict):
            return False, f"http={c2} {e2}"
        spec = int((b2.get("spec") or {}).get("replicas") or 0)
        return spec == n, f"spec.replicas={spec} want={n}"

    polled = poll(pred, PAGE_CEILING_S)
    return PageResult(polled.ok, time.perf_counter() - t0, polled.detail)


def page_scale_2(ctx: Ctx) -> PageResult:
    return _scale(ctx, 2)


def page_available_2(ctx: Ctx) -> PageResult:
    return poll(lambda: _available(ctx, 2), PAGE_CEILING_S)


def page_scale_3(ctx: Ctx) -> PageResult:
    return _scale(ctx, 3)


def page_available_3(ctx: Ctx) -> PageResult:
    return poll(lambda: _available(ctx, 3), PAGE_CEILING_S)


def _rs_uids(ctx: Ctx) -> tuple[set[str], str]:
    code, body, err = _get(
        ctx, f"/apis/apps/v1/namespaces/{NS}/replicasets?labelSelector=app=web"
    )
    uids: set[str] = set()
    for rs in _items(body):
        uid = (rs.get("metadata") or {}).get("uid")
        if uid:
            uids.add(str(uid))
    return uids, f"http={code} rs={len(uids)} {err}"


def page_rollout(ctx: Ctx) -> PageResult:
    t0 = time.perf_counter()
    before, detail0 = _rs_uids(ctx)
    stamp = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    code, _body, err = _patch(
        ctx,
        f"/apis/apps/v1/namespaces/{NS}/deployments/{DEPLOY}",
        {
            "spec": {
                "template": {
                    "metadata": {
                        "annotations": {
                            "kubectl.kubernetes.io/restartedAt": stamp
                        }
                    }
                }
            }
        },
    )
    if code >= 400:
        return PageResult(False, time.perf_counter() - t0, f"restart http={code} {err}")

    def pred() -> tuple[bool, str]:
        after, detail = _rs_uids(ctx)
        new = after - before
        return bool(new), f"new_rs={len(new)} {detail} before={detail0}"

    polled = poll(pred, PAGE_CEILING_S)
    return PageResult(polled.ok, time.perf_counter() - t0, polled.detail)


def page_rollout_available(ctx: Ctx) -> PageResult:
    return poll(lambda: _available(ctx, 3), PAGE_CEILING_S)


def page_scale_1(ctx: Ctx) -> PageResult:
    return _scale(ctx, 1)


def page_available_eq_1(ctx: Ctx) -> PageResult:
    return poll(lambda: _available(ctx, 1, exact=True), PAGE_CEILING_S)


def page_still_serves(ctx: Ctx) -> PageResult:
    def pred() -> tuple[bool, str]:
        code, body, err = _endpoints(ctx)
        n = _ep_addrs(body)
        if n < 1:
            return False, f"addrs={n} http={code} {err}"
        r = _exec(
            ctx,
            [
                "k3s",
                "kubectl",
                "-n",
                NS,
                "exec",
                f"deploy/{DEPLOY}",
                "--",
                "wget",
                "-qO-",
                "http://127.0.0.1:8080/",
            ],
        )
        out = (r.get("stdout") or "") + (r.get("stderr") or "")
        served = r.get("exit_code") == 0 and "k7-exam-ok" in out
        return served, f"addrs={n} exec_exit={r.get('exit_code')} {out[-80:]!r}"

    return poll(pred, PAGE_CEILING_S)


PAGES: list[Page] = [
    Page("api-live", page_api_live),
    Page("nodes-listed", page_nodes_listed),
    Page("nodes-ready", page_nodes_ready),
    Page("namespace", page_namespace),
    Page("apply-deploy", page_apply_deploy),
    Page("pod-scheduled", page_pod_scheduled),
    Page("available-1", page_available_1),
    Page("apply-svc", page_apply_svc),
    Page("ep-object", page_ep_object),
    Page("ep-addrs", page_ep_addrs),
    Page("workload", page_workload),
    Page("scale-2", page_scale_2),
    Page("available-2", page_available_2),
    Page("scale-3", page_scale_3),
    Page("available-3", page_available_3),
    Page("rollout", page_rollout),
    Page("rollout-available", page_rollout_available),
    Page("scale-1", page_scale_1),
    Page("available-eq-1", page_available_eq_1),
    Page("still-serves", page_still_serves),
]

if len(PAGES) != 20:
    raise RuntimeError(f"playbook must have 20 pages, got {len(PAGES)}")


def run_page(ctx: Ctx, turn: int) -> PageResult:
    if turn < 1 or turn > len(PAGES):
        raise ValueError(f"playbook turn must be 1..{len(PAGES)}, got {turn}")
    return PAGES[turn - 1].run(ctx)


def run_through(ctx: Ctx, turn: int) -> list[PageResult]:
    """Run pages 1..turn. A failed page does not skip the rest."""
    if turn < 1 or turn > len(PAGES):
        raise ValueError(f"playbook turn must be 1..{len(PAGES)}, got {turn}")
    out: list[PageResult] = []
    for i in range(1, turn + 1):
        out.append(run_page(ctx, i))
    return out


def score_from_results(results: list[PageResult], turn: int) -> dict[str, Any]:
    if turn < 1:
        raise ValueError(f"playbook turn must be >= 1, got {turn}")
    if len(results) < turn:
        raise ValueError(
            f"playbook score needs {turn} page results, got {len(results)}"
        )
    steps = [bool(r.ok) for r in results[:turn]]
    step_s = [float(r.elapsed_s) for r in results[:turn]]
    passed = sum(1 for s in steps if s)
    reward = passed / float(turn)
    return {
        "reward": reward,
        "playbook": {
            "turn": turn,
            "passed": passed,
            "total": turn,
            "steps": steps,
            "step_s": step_s,
        },
    }


def diagnostic_terms(
    *,
    readyz: bool,
    workload_ready: bool,
    source_intact: bool,
    fault_id: str,
) -> dict[str, float]:
    """Frozen five keys as diagnostics. Not the headline reward."""
    none = fault_id == "none"
    return terms(
        liveness=1.0 if readyz else 0.0,
        workload_ready=1.0 if workload_ready else 0.0,
        source_intact=1.0 if source_intact else 0.0,
        contained=1.0 if none else 0.0,
        restored=1.0 if none else 0.0,
    )


def ensure_host_pinned_airgap(
    dest: Path | None = None,
    *,
    run: Callable[..., Any] | None = None,
) -> Path:
    """Host-side docker-save of PINNED_IMAGE. Never `crictl pull` in a guest.

    Fresh Ubuntu k3s only has pause (CHALLENGES #163). The exam must not
    pull — plant this tarball into each gym disk before CreateVm so k3s
    imports it at first start, before /readyz.
    """
    dest = dest or PINNED_AIRGAP
    if dest.is_file() and dest.stat().st_size > 0:
        log.info("pinned airgap cache hit %s (%s bytes)", dest, dest.stat().st_size)
        return dest
    dest.parent.mkdir(parents=True, exist_ok=True)
    runner = run or subprocess.run
    tmp = dest.with_suffix(dest.suffix + ".tmp")
    if tmp.exists():
        tmp.unlink()
    errors: list[str] = []
    pull_cmds = (
        ["k3s", "ctr", "images", "pull", PINNED_IMAGE],
        ["ctr", "-n", "k8s.io", "images", "pull", PINNED_IMAGE],
        ["docker", "pull", PINNED_IMAGE],
    )
    pulled = False
    for cmd in pull_cmds:
        r = runner(cmd, check=False, capture_output=True, text=True)
        if getattr(r, "returncode", 1) == 0:
            pulled = True
            break
        errors.append(f"{' '.join(cmd)}: {(getattr(r, 'stderr', '') or '')[-200:]}")
    if not pulled:
        raise RuntimeError(
            f"host pull of {PINNED_IMAGE} failed; refusing guest pull "
            f"mid-exam:\n" + "\n".join(errors)
        )
    export_cmds = (
        ["k3s", "ctr", "images", "export", str(tmp), PINNED_IMAGE],
        ["ctr", "-n", "k8s.io", "images", "export", str(tmp), PINNED_IMAGE],
        ["docker", "save", "-o", str(tmp), PINNED_IMAGE],
    )
    exported = False
    for cmd in export_cmds:
        r = runner(cmd, check=False, capture_output=True, text=True)
        if getattr(r, "returncode", 1) == 0 and tmp.is_file() and tmp.stat().st_size > 0:
            exported = True
            break
        errors.append(f"{' '.join(cmd)}: {(getattr(r, 'stderr', '') or '')[-200:]}")
    if not exported:
        if tmp.exists():
            tmp.unlink()
        raise RuntimeError(
            f"host export of {PINNED_IMAGE} failed; refusing guest pull "
            f"mid-exam:\n" + "\n".join(errors)
        )
    os.replace(tmp, dest)
    log.info("pinned airgap exported %s (%s bytes)", dest, dest.stat().st_size)
    return dest


def plant_pinned_airgap(disk: Path, tar: Path | None = None) -> None:
    """Copy the host airgap into a reflinked gym disk. No guest pull."""
    tar = Path(tar) if tar is not None else ensure_host_pinned_airgap()
    if not tar.is_file() or tar.stat().st_size <= 0:
        raise RuntimeError(f"pinned airgap missing or empty: {tar}")
    if not disk.is_file():
        raise RuntimeError(f"plant pinned image: disk missing {disk}")
    mnt = Path(tempfile.mkdtemp(prefix="k7-plant-"))
    mounted = False
    try:
        r = subprocess.run(
            ["mount", "-o", "loop", str(disk), str(mnt)],
            check=False,
            capture_output=True,
            text=True,
        )
        if r.returncode != 0:
            raise RuntimeError(
                f"mount {disk} → {mnt} failed: {(r.stderr or r.stdout or '')[-300:]}"
            )
        mounted = True
        dest_dir = mnt / "var/lib/rancher/k3s/agent/images"
        if not dest_dir.is_dir():
            raise RuntimeError(f"k3s airgap dir missing on {disk}: {dest_dir}")
        dest = dest_dir / PINNED_AIRGAP_NAME
        shutil.copy2(tar, dest)
        os.sync()
        log.info(
            "planted %s (%s bytes) into %s",
            dest.name,
            dest.stat().st_size,
            disk,
        )
    finally:
        if mounted:
            u = subprocess.run(
                ["umount", str(mnt)], check=False, capture_output=True, text=True
            )
            if u.returncode != 0:
                subprocess.run(["umount", "-l", str(mnt)], check=False)
        try:
            mnt.rmdir()
        except OSError:
            pass


def discover_pinned_image(exec_cmd: Callable[..., dict[str, Any]], cid: int) -> dict[str, str]:
    """Record name + digest from `crictl images`. Loud if the pin is absent."""
    r = exec_cmd(
        cid,
        ["k3s", "crictl", "images", "--digests"],
        20,
    )
    text = (r.get("stdout") or "") + (r.get("stderr") or "")
    if r.get("exit_code") != 0:
        raise RuntimeError(f"crictl images failed: {text[-400:]!r}")
    digest = ""
    found = False
    for line in text.splitlines():
        if "busybox" not in line.lower() and PINNED_IMAGE not in line:
            continue
        found = True
        parts = line.split()
        for p in parts:
            if p.startswith("sha256:"):
                digest = p
                break
        if "busybox" in line.lower():
            break
    if not found:
        raise RuntimeError(
            f"pinned image {PINNED_IMAGE} not on guest cid={cid}; "
            f"refusing to pull mid-exam. crictl images:\n{text[-800:]}"
        )
    return {"name": PINNED_IMAGE, "digest": digest, "crictl": text[-400:]}


def wait_pinned_image(
    exec_cmd: Callable[..., dict[str, Any]],
    cid: int,
    ceiling_s: float = PINNED_IMPORT_S,
) -> dict[str, str]:
    """Poll crictl until k3s imported the planted airgap. Never pull."""
    deadline = time.monotonic() + ceiling_s
    last = ""
    while True:
        try:
            return discover_pinned_image(exec_cmd, cid)
        except RuntimeError as e:
            last = str(e)
        if time.monotonic() >= deadline:
            raise RuntimeError(
                f"pinned image {PINNED_IMAGE} never imported on cid={cid} "
                f"within {ceiling_s}s (airgap plant, not a pull): {last[-400:]}"
            )
        time.sleep(POLL_S)
