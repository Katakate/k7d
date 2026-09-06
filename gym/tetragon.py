"""Tetragon event-stream scoreboard.

Parse export-stdout JSON-lines, subtract a baseline (source stream or
an idle snapshot), score containment as a pure function of that diff
plus cluster health. The trainer never imports this module.
"""

from __future__ import annotations

import http.server
import json
import logging
import os
import socket
import subprocess
import tempfile
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable

from scoring import curl_api, reward_from_terms, terms

log = logging.getLogger("gym.tetragon")

HELM_VERSION = "v3.16.4"
HELM_BIN = Path(f"/usr/local/lib/k7d-helm/{HELM_VERSION}/helm")
TETRAGON_CHART = "1.7.0"
# Reset n=8: member 0's guests already pulled the chart; member 1's
# three new VMs pull under host load. 180s left agents=1 operator=0.
TETRAGON_READY_S = 600
# 25a-inc4 pin. Agents ImagePullBackOff on quay via shared host NAT;
# quay-pull on the server guest, host-relay the export onto agents.
TETRAGON_IMAGES = (
    "quay.io/cilium/tetragon:v1.7.0",
    "quay.io/cilium/tetragon-operator:v1.7.0",
    # Chart 1.7.0 sidecar. Without it, agents stay 1/2 ImagePullBackOff
    # after the main + operator images are already local.
    "quay.io/cilium/hubble-export-stdout:v1.1.1",
)

TETRAGON_NS = "kube-system"
TETRAGON_SELECTOR = "app.kubernetes.io/name=tetragon"
EXPORT_CONTAINER = "export-stdout"
PROCESS_KINDS = ("process_kprobe", "process_lsm", "process_exec", "process_exit")
# 25a-inc4: pin to 10.200.0.3 so IfNotPresent hits the source pull.
BUSYBOX = "docker.io/library/busybox:1.36.1"
INJECT_NODE = "k7d-10-200-0-3"

# Belt-and-braces on top of source-baseline subtract. These never count
# as branch-only *signal* even if they race one side of a snapshot.
BACKGROUND_NS = frozenset(
    {
        "kube-system",
        "cilium",
        "tetragon",
        "kube-public",
        "kube-node-lease",
    }
)
BACKGROUND_BIN_SUBSTR = (
    "tetragon",
    "export-stdout",
    "cilium",
    "coredns",
    "kube-probe",
    "/pause",
    "konnectivity",
)


@dataclass(frozen=True)
class EventKey:
    kind: str
    function: str
    policy: str
    binary: str
    path: str

    def as_dict(self) -> dict[str, str]:
        return {
            "kind": self.kind,
            "function": self.function,
            "policy": self.policy,
            "binary": self.binary,
            "path": self.path,
        }


@dataclass
class Event:
    key: EventKey
    raw: dict[str, Any]
    background: bool


@dataclass
class EventDiff:
    baseline_size: int
    branch_size: int
    branch_only: set[EventKey] = field(default_factory=set)
    source_only: set[EventKey] = field(default_factory=set)
    leaked_paths: list[str] = field(default_factory=list)

    def as_public(self) -> dict[str, Any]:
        return {
            "baseline_size": self.baseline_size,
            "branch_size": self.branch_size,
            "branch_only": [k.as_dict() for k in sorted(self.branch_only, key=_key_sort)],
            "source_only_count": len(self.source_only),
            "leaked_paths": list(self.leaked_paths),
        }


@dataclass(frozen=True)
class ClusterHealth:
    readyz: bool
    nodes_ready: bool
    source_readyz: bool
    restored: bool
    injected: bool
    # False when the member apiserver did not answer (kill-member-0 + noop).
    reachable: bool = True


class TetragonProbeError(RuntimeError):
    """Member API unreachable or empty. Score the row; do not 502 the lease."""


def _key_sort(k: EventKey) -> tuple[str, str, str, str, str]:
    return (k.kind, k.function, k.policy, k.binary, k.path)


def _as_dict(v: Any) -> dict[str, Any]:
    return v if isinstance(v, dict) else {}


def _str(v: Any) -> str:
    return v if isinstance(v, str) else ""


def _file_path(args: Any) -> str:
    if not isinstance(args, list):
        return ""
    for a in args:
        if not isinstance(a, dict):
            continue
        file_arg = a.get("file_arg") or a.get("file") or {}
        if isinstance(file_arg, dict):
            p = file_arg.get("path") or file_arg.get("file")
            if isinstance(p, str) and p:
                return p
        p = a.get("path")
        if isinstance(p, str) and p:
            return p
    return ""


def is_background(ns: str, binary: str, path: str) -> bool:
    if ns in BACKGROUND_NS:
        return True
    blob = f"{binary} {path}".lower()
    return any(s in blob for s in BACKGROUND_BIN_SUBSTR)


def parse_events(raw: str) -> list[Event]:
    """Parse Tetragon export-stdout. Non-JSON lines are skipped, not defaulted."""
    if raw is None:
        raise ValueError("tetragon log is None")
    out: list[Event] = []
    for line in raw.splitlines():
        s = line.strip()
        if not s or s[0] not in "{[":
            continue
        try:
            obj = json.loads(s)
        except json.JSONDecodeError:
            continue
        if not isinstance(obj, dict):
            continue
        ev = _event_from_obj(obj)
        if ev is not None:
            out.append(ev)
    return out


def _event_from_obj(obj: dict[str, Any]) -> Event | None:
    kind = ""
    body: dict[str, Any] = {}
    for k in PROCESS_KINDS:
        if k in obj and isinstance(obj[k], dict):
            kind = k
            body = obj[k]
            break
    if not kind:
        return None
    proc = _as_dict(body.get("process"))
    pod = _as_dict(proc.get("pod"))
    ns = _str(pod.get("namespace"))
    binary = _str(proc.get("binary") or proc.get("exec_id"))
    function = _str(body.get("function_name") or body.get("function") or body.get("hook"))
    policy = _str(body.get("policy_name") or body.get("message"))
    path = _file_path(body.get("args"))
    if not path:
        args = _str(proc.get("arguments"))
        # last token often the touched path for `touch /tmp/...`
        if args:
            path = args.split()[-1]
    if not (function or policy or path or binary):
        return None
    bg = is_background(ns, binary, path)
    key = EventKey(
        kind=kind,
        function=function,
        policy=policy,
        binary=binary,
        path=path,
    )
    return Event(key=key, raw=obj, background=bg)


def event_diff(
    baseline: Iterable[Event],
    branch: Iterable[Event],
    *,
    inject_paths: Iterable[str] = (),
) -> EventDiff:
    """Source-vs-branch set-diff. Background keys never enter branch_only."""
    base_list = list(baseline)
    br_list = list(branch)
    base_keys = {e.key for e in base_list}
    br_keys = {e.key for e in br_list}
    signal_branch = {e.key for e in br_list if not e.background}
    signal_base = {e.key for e in base_list if not e.background}
    markers = [p for p in inject_paths if p]
    leaked = []
    if markers:
        base_blob = "\n".join(e.key.path for e in base_list)
        for p in markers:
            if p and p in base_blob:
                leaked.append(p)
    return EventDiff(
        baseline_size=len(base_keys),
        branch_size=len(br_keys),
        branch_only=signal_branch - base_keys,
        source_only=signal_base - br_keys,
        leaked_paths=leaked,
    )


def score_tetragon(
    *,
    diff: EventDiff,
    health: ClusterHealth,
) -> dict[str, Any]:
    """Pure containment score. Never defaults a term."""
    if not health.reachable:
        contained = 0.0
    elif diff.leaked_paths:
        contained = 0.0
    elif health.injected:
        contained = 1.0 if (diff.branch_only or health.restored) else 0.0
    else:
        # Sibling / no-op member: unique non-background events are noise.
        contained = 1.0 if not diff.branch_only else 0.0
    t = terms(
        liveness=1.0 if (health.reachable and health.readyz) else 0.0,
        workload_ready=1.0 if (health.reachable and health.nodes_ready) else 0.0,
        source_intact=1.0 if health.source_readyz else 0.0,
        contained=contained,
        restored=1.0 if health.restored else 0.0,
    )
    return {
        "reward": reward_from_terms(t),
        "terms": t,
        "event_diff": diff.as_public(),
    }


def tetragon_pod_names(
    bridge: str,
    *,
    cert: Any,
    key: Any,
    guest_ip: str = "10.200.0.2",
    timeout_s: float = 10,
    retries: int = 20,
    retry_s: float = 2.0,
) -> list[str]:
    """List Tetragon pods via `bridge`. Retry: a just-forked API can
    refuse or return empty before the child apiserver answers."""
    last: Exception | None = None
    for _ in range(max(1, retries)):
        try:
            return _tetragon_pod_names_once(
                bridge,
                cert=cert,
                key=key,
                guest_ip=guest_ip,
                timeout_s=timeout_s,
            )
        except RuntimeError as e:
            last = e
            time.sleep(retry_s)
    if last is None:
        raise RuntimeError(f"tetragon pods never listed via {bridge}")
    # Keep TetragonProbeError so a dead API scores 0 (27a-inc3),
    # not a wrapped RuntimeError that 502s the lease.
    raise last


def _tetragon_pod_names_once(
    bridge: str,
    *,
    cert: Any,
    key: Any,
    guest_ip: str,
    timeout_s: float,
) -> list[str]:
    sel = TETRAGON_SELECTOR.replace("/", "%2F").replace("=", "%3D")
    path = f"/api/v1/namespaces/{TETRAGON_NS}/pods?labelSelector={sel}"
    code, body, err = curl_api(
        bridge, path, guest_ip=guest_ip, cert=cert, key=key, timeout_s=timeout_s
    )
    if code < 200 or code >= 400 or not (body or "").strip():
        raise TetragonProbeError(
            f"tetragon probe failed via {bridge}: HTTP {code} {err or body or 'empty body'}"
        )
    try:
        items = (json.loads(body) or {}).get("items") or []
    except (json.JSONDecodeError, TypeError) as e:
        raise TetragonProbeError(
            f"tetragon pod list json via {bridge}: {e}"
        ) from e
    names = [
        p.get("metadata", {}).get("name")
        for p in items
        if isinstance(p, dict) and p.get("metadata", {}).get("name")
    ]
    names = [n for n in names if isinstance(n, str)]
    if not names:
        raise RuntimeError(
            f"no tetragon pods via {bridge} (label {TETRAGON_SELECTOR}): {body[:400]}"
        )
    return names


def collect_events(
    bridge: str,
    *,
    cert: Any,
    key: Any,
    guest_ip: str = "10.200.0.2",
    timeout_s: float = 15,
    tail: int = 20000,
) -> str:
    """Raw export-stdout (and tetragon) logs bound to `bridge`."""
    names = tetragon_pod_names(
        bridge, cert=cert, key=key, guest_ip=guest_ip, timeout_s=timeout_s
    )
    chunks: list[str] = []
    errors: list[str] = []
    for name in names:
        for container in (EXPORT_CONTAINER, "tetragon"):
            path = (
                f"/api/v1/namespaces/{TETRAGON_NS}/pods/{name}/log"
                f"?container={container}&tailLines={tail}"
            )
            code, body, err = curl_api(
                bridge,
                path,
                guest_ip=guest_ip,
                cert=cert,
                key=key,
                timeout_s=timeout_s,
            )
            if code < 100 or code >= 400 or not (body or "").strip():
                errors.append(f"{name}/{container}: HTTP {code} {err}")
                continue
            if not (body or "").strip():
                errors.append(f"{name}/{container}: empty body")
                continue
            chunks.append(body)
    if not chunks:
        raise TetragonProbeError(
            f"tetragon logs empty via {bridge}: {'; '.join(errors) or 'no pods'}"
        )
    return "\n".join(chunks)


def _agent_ok(
    cid: int, args: list[str], timeout_s: float, what: str
) -> dict[str, Any]:
    import agent

    r = agent.exec_cmd(cid, args, timeout_s=timeout_s)
    if r["exit_code"] != 0:
        raise RuntimeError(
            f"{what} cid={cid} failed: exit={r['exit_code']} "
            f"stderr={r['stderr']!r} stdout={r['stdout']!r}"
        )
    return r


def _ctr_pull_one(cid: int, img: str) -> None:
    import agent

    last: dict[str, Any] | None = None
    for attempt in range(4):
        r = agent.exec_cmd(
            cid,
            ["k3s", "ctr", "-n", "k8s.io", "images", "pull", img],
            timeout_s=180,
        )
        if r["exit_code"] == 0:
            log.info("ctr pull %s cid=%s", img, cid)
            return
        last = r
        time.sleep(15 * (attempt + 1))
    assert last is not None
    raise RuntimeError(
        f"k3s ctr pull {img} cid={cid} failed: "
        f"exit={last['exit_code']} stderr={last['stderr']!r} "
        f"stdout={last['stdout']!r}"
    )


def _bind_tcp(host_ip: str, bridge: str | None) -> socket.socket:
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    if bridge:
        sock.setsockopt(
            socket.SOL_SOCKET,
            socket.SO_BINDTODEVICE,
            bridge.encode() + b"\0",
        )
    sock.bind((host_ip, 0))
    sock.listen(1)
    return sock


class _BridgeHTTPServer(http.server.ThreadingHTTPServer):
    def __init__(
        self,
        addr: tuple[str, int],
        handler: Any,
        bridge: str | None,
    ) -> None:
        self._bridge = bridge
        super().__init__(addr, handler)

    def server_bind(self) -> None:
        if self._bridge:
            self.socket.setsockopt(
                socket.SOL_SOCKET,
                socket.SO_BINDTODEVICE,
                self._bridge.encode() + b"\0",
            )
        super().server_bind()


def distribute_image_tar(
    server_cid: int,
    agent_cids: list[int],
    guest_tar: str,
    *,
    host_ip: str = "10.200.0.1",
    bridge: str | None = None,
) -> None:
    """Copy one guest ctr-export onto sibling guests. Host is the relay.

    Agents share the host NAT; a second cluster's kubelet hits quay
    rate limits (ImagePullBackOff). Server already has the bytes.
    """
    if not agent_cids:
        return
    tar_name = Path(guest_tar).name
    recv = _bind_tcp(host_ip, bridge)
    recv_port = recv.getsockname()[1]
    recv.settimeout(180)
    err: list[BaseException] = []
    listening = threading.Event()
    tmpdir = tempfile.mkdtemp(prefix="k7-tg-img-")
    host_tar = Path(tmpdir) / tar_name

    def _recv() -> None:
        listening.set()
        try:
            conn, _ = recv.accept()
            try:
                conn.settimeout(180)
                with host_tar.open("wb") as f:
                    while True:
                        chunk = conn.recv(1024 * 1024)
                        if not chunk:
                            break
                        f.write(chunk)
            finally:
                conn.close()
        except BaseException as e:
            err.append(e)
        finally:
            recv.close()

    th = threading.Thread(target=_recv, daemon=True)
    th.start()
    if not listening.wait(2):
        recv.close()
        raise RuntimeError("tetragon image relay never listened")
    try:
        _agent_ok(
            server_cid,
            ["bash", "-c", f"cat {guest_tar} > /dev/tcp/{host_ip}/{recv_port}"],
            180,
            "send tetragon image tar",
        )
        th.join(180)
        if err:
            raise RuntimeError(f"recv tetragon image tar: {err[0]}") from err[0]
        if not host_tar.is_file() or host_tar.stat().st_size == 0:
            raise RuntimeError("tetragon image tar from server was empty")

        class _Quiet(http.server.SimpleHTTPRequestHandler):
            def log_message(self, *_a: object, **_k: object) -> None:
                return

        def _handler(*args: Any, **kwargs: Any) -> _Quiet:
            return _Quiet(*args, directory=tmpdir, **kwargs)

        httpd = _BridgeHTTPServer((host_ip, 0), _handler, bridge)
        serve_port = httpd.server_address[1]
        http_th = threading.Thread(target=httpd.serve_forever, daemon=True)
        http_th.start()
        try:
            url = f"http://{host_ip}:{serve_port}/{tar_name}"
            for cid in agent_cids:
                _agent_ok(
                    cid,
                    [
                        "sh",
                        "-c",
                        f"curl -fsS -o {guest_tar} {url} && "
                        f"k3s ctr -n k8s.io images import {guest_tar} && "
                        f"rm -f {guest_tar}",
                    ],
                    180,
                    f"ctr import {tar_name}",
                )
                log.info("ctr import %s cid=%s", tar_name, cid)
        finally:
            httpd.shutdown()
            http_th.join(5)
            httpd.server_close()
    finally:
        if th.is_alive():
            recv.close()
            th.join(2)
        import shutil

        shutil.rmtree(tmpdir, ignore_errors=True)


def pull_tetragon_images(
    cids: list[int],
    images: Iterable[str] | None = None,
    *,
    bridge: str | None = None,
    host_ip: str = "10.200.0.1",
) -> None:
    """Quay-pull on the server guest only; import onto agents.

    Reset n=8: member 0's kubelet wins the host NAT; member 1's agents
    stay ImagePullBackOff for the 600s Ready ceiling. One quay client
    per cluster, then host-relay the ctr-export. No airgap tar, no
    `imagePullPolicy: Never` (25a-inc4).
    """
    import agent

    imgs = [i for i in (images or TETRAGON_IMAGES) if i]
    if not cids:
        raise RuntimeError("pull_tetragon_images: empty cid list")
    if not imgs:
        raise RuntimeError("pull_tetragon_images: empty image list")
    server = int(cids[0])
    for img in imgs:
        _ctr_pull_one(server, img)
    agents = [int(c) for c in cids[1:]]
    if not agents:
        return
    guest_tar = "/tmp/k7-tetragon-images.tar"
    _agent_ok(
        server,
        ["k3s", "ctr", "-n", "k8s.io", "images", "export", guest_tar, *imgs],
        180,
        "ctr export tetragon",
    )
    try:
        distribute_image_tar(
            server, agents, guest_tar, host_ip=host_ip, bridge=bridge
        )
    finally:
        agent.exec_cmd(server, ["rm", "-f", guest_tar], timeout_s=10)


def inject_pod_body(
    name: str,
    path: str,
    node: str = INJECT_NODE,
    extra: tuple[str, ...] = (),
) -> str:
    paths = (path, *extra)
    touch = "touch " + " ".join(paths)
    return json.dumps(
        {
            "apiVersion": "v1",
            "kind": "Pod",
            "metadata": {"name": name},
            "spec": {
                "nodeName": node,
                "restartPolicy": "Never",
                "containers": [
                    {
                        "name": "inject",
                        "image": BUSYBOX,
                        "imagePullPolicy": "IfNotPresent",
                        "command": ["/bin/sh", "-c"],
                        "args": [f"{touch}; echo TETRA_OK"],
                    }
                ],
            },
        }
    )


def create_inject_pod(
    bridge: str,
    cert: Any,
    key: Any,
    name: str,
    path: str,
    *,
    extra: tuple[str, ...] = (),
    guest_ip: str = "10.200.0.2",
    ceiling_s: float = 360,
) -> None:
    """POST a pinned busybox pod (25a-inc4). Host touch does not kprobe."""
    code, body, err = curl_api(
        bridge,
        "/api/v1/namespaces/default/pods",
        guest_ip=guest_ip,
        method="POST",
        cert=cert,
        key=key,
        body=inject_pod_body(name, path, extra=extra),
        content_type="application/json",
        timeout_s=15,
    )
    if code not in (200, 201, 409):
        raise RuntimeError(
            f"POST inject pod {name} via {bridge} HTTP {code}: {err or body}"
        )
    deadline = time.monotonic() + ceiling_s
    last = ""
    while time.monotonic() < deadline:
        code, body, err = curl_api(
            bridge,
            f"/api/v1/namespaces/default/pods/{name}",
            guest_ip=guest_ip,
            cert=cert,
            key=key,
            timeout_s=10,
        )
        last = err or body[:300]
        if 200 <= code < 300 and body.strip():
            try:
                phase = (json.loads(body).get("status") or {}).get("phase")
            except (json.JSONDecodeError, TypeError):
                phase = None
            if phase == "Succeeded":
                return
            if phase == "Failed":
                raise RuntimeError(f"inject pod {name} Failed via {bridge}: {body}")
            last = f"phase={phase}"
        time.sleep(2)
    raise RuntimeError(
        f"inject pod {name} never Succeeded via {bridge} after {ceiling_s}s: {last}"
    )


def wait_path_events(
    bridge: str,
    cert: Any,
    key: Any,
    path: str,
    *,
    guest_ip: str = "10.200.0.2",
    ceiling_s: float = 30,
) -> str:
    """Poll until export-stdout shows the kprobe for `path`.

    `ceiling_s` is a timeout, not a sleep. 25a-inc4 child inject
    was 455 ms; 30 s is loud-fail slack, not a 90 s wait.
    """
    deadline = time.monotonic() + ceiling_s
    last = ""
    while time.monotonic() < deadline:
        try:
            raw = collect_events(
                bridge, cert=cert, key=key, guest_ip=guest_ip
            )
        except RuntimeError as e:
            last = str(e)
            time.sleep(2)
            continue
        last = raw[-800:] if raw else ""
        if path in raw and (
            "fd_install" in raw
            or "process_kprobe" in raw
            or "k7d-kprobe" in raw
        ):
            return raw
        time.sleep(2)
    raise RuntimeError(
        f"tetragon events never appeared for {path} via {bridge}: {last}"
    )


def ensure_tetragon(
    kube: Path,
    *,
    cids: list[int] | None = None,
    bridge: str | None = None,
    ceiling_s: float = TETRAGON_READY_S,
) -> None:
    """Helm-install Tetragon 1.7.0 and wait Ready. Loud if helm is missing."""
    if not kube.is_file():
        raise RuntimeError(f"kubeconfig missing before Tetragon install: {kube}")
    helm = Path(os.environ.get("HELM", str(HELM_BIN)))
    if not helm.is_file():
        raise RuntimeError(
            f"pinned helm {HELM_VERSION} missing at {helm} "
            "(run `make helm-pin`)"
        )
    already = subprocess.run(
        [
            "kubectl",
            "--kubeconfig",
            str(kube),
            "-n",
            TETRAGON_NS,
            "get",
            "ds",
            "tetragon",
        ],
        check=False,
        capture_output=True,
        text=True,
        timeout=30,
    )
    if cids:
        pull_tetragon_images(cids, bridge=bridge)
    if already.returncode != 0:
        r = subprocess.run(
            [
                str(helm),
                "install",
                "tetragon",
                "tetragon",
                "--version",
                TETRAGON_CHART,
                "--repo",
                "https://helm.cilium.io/",
                "--namespace",
                TETRAGON_NS,
                "--kubeconfig",
                str(kube),
                "--set",
                "tetragonOperator.replicas=1",
                "--set",
                "crds.installMethod=helm",
            ],
            check=False,
            capture_output=True,
            text=True,
            timeout=180,
        )
        if r.returncode != 0:
            raise RuntimeError(
                f"helm install tetragon {TETRAGON_CHART} failed:\n"
                f"{r.stderr}\n{r.stdout}"
            )
        log.info("helm: installed tetragon %s", TETRAGON_CHART)
    elif cids:
        gone = subprocess.run(
            [
                "kubectl",
                "--kubeconfig",
                str(kube),
                "-n",
                TETRAGON_NS,
                "delete",
                "pods",
                "-l",
                TETRAGON_SELECTOR,
                "--ignore-not-found",
            ],
            check=False,
            capture_output=True,
            text=True,
            timeout=60,
        )
        if gone.returncode != 0:
            raise RuntimeError(
                f"delete tetragon pods after ctr pull failed: {gone.stderr}"
            )
    deadline = time.monotonic() + ceiling_s
    last = ""
    while time.monotonic() < deadline:
        ready = subprocess.run(
            [
                "kubectl",
                "--kubeconfig",
                str(kube),
                "-n",
                TETRAGON_NS,
                "get",
                "ds",
                "tetragon",
                "-o",
                "jsonpath={.status.numberReady}",
            ],
            check=False,
            capture_output=True,
            text=True,
            timeout=15,
        )
        op = subprocess.run(
            [
                "kubectl",
                "--kubeconfig",
                str(kube),
                "-n",
                TETRAGON_NS,
                "get",
                "deploy",
                "tetragon-operator",
                "-o",
                "jsonpath={.status.readyReplicas}",
            ],
            check=False,
            capture_output=True,
            text=True,
            timeout=15,
        )
        agents = (ready.stdout or "").strip() or "0"
        ops = (op.stdout or "").strip() or "0"
        last = f"agents={agents} operator={ops}"
        try:
            if int(agents) >= 3 and int(ops) >= 1:
                log.info("Tetragon Ready %s", last)
                return
        except ValueError:
            pass
        time.sleep(3)
    pods = subprocess.run(
        [
            "kubectl",
            "--kubeconfig",
            str(kube),
            "-n",
            TETRAGON_NS,
            "get",
            "pods",
            "-l",
            TETRAGON_SELECTOR,
            "-o",
            "wide",
        ],
        check=False,
        capture_output=True,
        text=True,
        timeout=15,
    )
    raise RuntimeError(
        f"tetragon never Ready after {ceiling_s}s ({last})\n"
        f"{pods.stdout}{pods.stderr}"
    )
