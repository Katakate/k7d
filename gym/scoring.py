"""Contain/restore reward. Terms are always itemised — never silently defaulted.

create mode: agent ping per member + source still answers.
adopt mode: /readyz + inner-load Ready + source /readyz (from run_demo.py).
ubuntu mode: /readyz + three Ready nodes + source /readyz.
`contained` + `restored` come from the fault catalog (gym/faults/).
"""

from __future__ import annotations

import json
import subprocess
from pathlib import Path
from typing import Any

def run(
    cmd: list[str], *, timeout_s: float
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        cmd,
        check=False,
        capture_output=True,
        text=True,
        timeout=timeout_s,
    )


def curl_readyz(
    bridge: str,
    guest_ip: str = "10.200.0.2",
    *,
    timeout_s: float = 3,
    cert: Path | None = None,
    key: Path | None = None,
) -> bool:
    cmd = [
        "curl",
        "-sk",
        "--max-time",
        str(max(1, int(timeout_s))),
        "--interface",
        bridge,
        f"https://{guest_ip}:6443/readyz",
    ]
    if cert is not None and key is not None:
        cmd[1] = "-sSk"
        cmd.extend(["--cert", str(cert), "--key", str(key)])
    try:
        r = run(cmd, timeout_s=timeout_s + 1)
    except (OSError, subprocess.TimeoutExpired):
        return False
    return r.returncode == 0 and "ok" in (r.stdout or "")


def curl_nodes_ready(
    bridge: str,
    guest_ip: str = "10.200.0.2",
    *,
    cert: Path | None = None,
    key: Path | None = None,
    want: int = 3,
    timeout_s: float = 5,
) -> bool:
    """True when at least `want` nodes report Ready=True."""
    code, body, _err = curl_api(
        bridge,
        "/api/v1/nodes",
        guest_ip=guest_ip,
        cert=cert,
        key=key,
        timeout_s=timeout_s,
    )
    if code < 100 or code >= 400:
        return False
    try:
        items = (json.loads(body) or {}).get("items") or []
    except (json.JSONDecodeError, TypeError):
        return False
    ready = 0
    for n in items:
        for c in (n.get("status") or {}).get("conditions") or []:
            if c.get("type") == "Ready" and c.get("status") == "True":
                ready += 1
                break
    return ready >= want


def curl_nodes_present(
    bridge: str,
    guest_ip: str = "10.200.0.2",
    *,
    cert: Path | None = None,
    key: Path | None = None,
    want: int = 3,
    timeout_s: float = 5,
) -> bool:
    """True when at least `want` nodes are registered (Ready optional).

    `k7d.cni=none` clusters stay NotReady until Cilium. Do not use
    host kubectl — leftover TAP at 10.200.0.2 is the wrong API
    (CHALLENGES #144).
    """
    code, body, _err = curl_api(
        bridge,
        "/api/v1/nodes",
        guest_ip=guest_ip,
        cert=cert,
        key=key,
        timeout_s=timeout_s,
    )
    if code >= 400:
        return False
    try:
        items = (json.loads(body) or {}).get("items") or []
    except (json.JSONDecodeError, TypeError):
        return False
    return len(items) >= want


def curl_inner_load(
    bridge: str,
    guest_ip: str = "10.200.0.2",
    *,
    cert: Path,
    key: Path,
    timeout_s: float = 5,
    ready_replicas: int = 3,
) -> bool:
    cmd = [
        "curl",
        "-sSk",
        "--max-time",
        str(max(1, int(timeout_s))),
        "--interface",
        bridge,
        "--cert",
        str(cert),
        "--key",
        str(key),
        f"https://{guest_ip}:6443/apis/apps/v1/namespaces/default/deployments/inner-load",
    ]
    try:
        r = run(cmd, timeout_s=timeout_s + 1)
    except (OSError, subprocess.TimeoutExpired):
        return False
    if r.returncode != 0:
        return False
    try:
        body = json.loads(r.stdout or "{}")
        ready = int((body.get("status") or {}).get("readyReplicas") or 0)
    except (json.JSONDecodeError, TypeError, ValueError):
        return False
    return ready >= ready_replicas


def curl_api(
    bridge: str,
    path: str,
    *,
    guest_ip: str = "10.200.0.2",
    method: str = "GET",
    timeout_s: float = 10,
    cert: Path | None = None,
    key: Path | None = None,
    body: str | None = None,
    content_type: str | None = None,
    token: str | None = None,
) -> tuple[int, str, str]:
    """HTTPS to the inner apiserver bound to `bridge`. kubectl cannot do this.

    Pass `cert`/`key` for the gym's admin mTLS, or `token` for a
    ServiceAccount bearer (red acts as its granted foothold, never the
    admin certs — 26a-inc11). The two are mutually exclusive.
    """
    if token is not None and cert is not None:
        raise ValueError(
            "curl_api: pass either admin cert/key or a bearer token, "
            "not both (a foothold must not borrow admin creds)"
        )
    cmd = [
        "curl",
        "-sS",
        "-k",
        "-X",
        method,
        "--max-time",
        str(max(1, int(timeout_s))),
        "--interface",
        bridge,
        "-w",
        "\n%{http_code}",
        f"https://{guest_ip}:6443{path}",
    ]
    if cert is not None and key is not None:
        cmd.extend(["--cert", str(cert), "--key", str(key)])
    if token is not None:
        cmd.extend(["-H", f"Authorization: Bearer {token}"])
    if body is not None:
        cmd.extend(["--data-binary", body])
    if content_type:
        cmd.extend(["-H", f"Content-Type: {content_type}"])
    try:
        r = run(cmd, timeout_s=timeout_s + 1)
    except subprocess.TimeoutExpired as e:
        return 124, "", f"curl timed out: {e}"
    except OSError as e:
        return 599, "", str(e)
    out = r.stdout or ""
    if "\n" in out:
        payload, _, code_s = out.rpartition("\n")
        try:
            code = int(code_s.strip())
        except ValueError:
            code = r.returncode
        # curl writes http_code 000 (and rc 7) when the TCP connect fails.
        # Callers must not json-parse that as a 200-class empty body.
        if code < 100:
            return 599, payload, r.stderr or f"curl rc={r.returncode} http_code={code}"
        return code, payload, r.stderr or ""
    if r.returncode == 0 and out:
        return 200, out, r.stderr or ""
    return 599, out, r.stderr or f"curl rc={r.returncode}"


def kubectl_to_request(args: list[str]) -> tuple[str, str, str | None, str | None]:
    """Map a kubectl-shaped argv to (method, path, body, content_type).

    Loud on anything inc0 does not implement — no silent no-op.
    """
    if not args:
        raise ValueError("kubectl args must be non-empty")
    if args[0].startswith("/"):
        return "GET", args[0], None, None

    rest = list(args)
    ns = "default"
    all_ns = False
    raw: str | None = None
    replicas: str | None = None
    output = None
    cleaned: list[str] = []
    i = 0
    while i < len(rest):
        a = rest[i]
        if a in ("-n", "--namespace") and i + 1 < len(rest):
            ns = rest[i + 1]
            i += 2
            continue
        if a.startswith("--namespace="):
            ns = a.split("=", 1)[1]
            i += 1
            continue
        if a in ("-A", "--all-namespaces"):
            all_ns = True
            i += 1
            continue
        if a == "--raw" and i + 1 < len(rest):
            raw = rest[i + 1]
            i += 2
            continue
        if a.startswith("--raw="):
            raw = a.split("=", 1)[1]
            i += 1
            continue
        if a == "--replicas" and i + 1 < len(rest):
            replicas = rest[i + 1]
            i += 2
            continue
        if a.startswith("--replicas="):
            replicas = a.split("=", 1)[1]
            i += 1
            continue
        if a in ("-o", "--output") and i + 1 < len(rest):
            output = rest[i + 1]
            i += 2
            continue
        cleaned.append(a)
        i += 1
    _ = output  # accepted and ignored; we always return the API JSON

    if raw:
        return "GET", raw, None, None
    if not cleaned:
        raise ValueError(f"kubectl args had only flags: {args}")

    verb = cleaned[0]
    resource = cleaned[1] if len(cleaned) > 1 else None
    name = cleaned[2] if len(cleaned) > 2 else None

    def namespaced(kind_path: str, obj: str | None) -> str:
        if all_ns:
            if obj:
                raise ValueError("cannot name an object with --all-namespaces")
            return f"/api/v1/{kind_path}"
        base = f"/api/v1/namespaces/{ns}/{kind_path}"
        return f"{base}/{obj}" if obj else base

    if verb == "get":
        if resource in (None, ""):
            raise ValueError("kubectl get requires a resource")
        if resource in ("--raw",):
            raise ValueError("kubectl get --raw needs a path")
        if resource in ("nodes", "node", "no"):
            path = "/api/v1/nodes" + (f"/{name}" if name else "")
            return "GET", path, None, None
        if resource in ("ns", "namespace", "namespaces"):
            path = "/api/v1/namespaces" + (f"/{name}" if name else "")
            return "GET", path, None, None
        if resource in ("pods", "pod", "po"):
            return "GET", namespaced("pods", name), None, None
        if resource in ("deploy", "deployment", "deployments"):
            base = f"/apis/apps/v1/namespaces/{ns}/deployments"
            if all_ns:
                base = "/apis/apps/v1/deployments"
            return "GET", f"{base}/{name}" if name else base, None, None
        raise ValueError(
            f"unsupported kubectl get resource {resource!r} "
            f"(inc0: nodes/pods/ns/deploy or --raw=/path)"
        )
    if verb == "delete":
        if resource not in ("pod", "pods", "po") or not name:
            raise ValueError("inc0 kubectl delete supports only: delete pod NAME")
        return "DELETE", namespaced("pods", name), None, None
    if verb == "scale":
        if resource not in ("deploy", "deployment", "deployments") or not name:
            raise ValueError("inc0 kubectl scale supports only: scale deploy NAME --replicas=N")
        if replicas is None:
            raise ValueError("kubectl scale requires --replicas")
        body = json.dumps({"spec": {"replicas": int(replicas)}})
        path = f"/apis/apps/v1/namespaces/{ns}/deployments/{name}"
        return "PATCH", path, body, "application/merge-patch+json"
    raise ValueError(
        f"unsupported kubectl verb {verb!r} "
        f"(inc0: get/delete/scale, or a raw /api path)"
    )


TERM_KEYS = (
    "liveness",
    "workload_ready",
    "source_intact",
    "contained",
    "restored",
)


def terms(
    *,
    liveness: float,
    workload_ready: float,
    source_intact: float,
    contained: float,
    restored: float,
) -> dict[str, float]:
    """Always all five keys. Callers pass computed values, never omit."""
    return {
        "liveness": float(liveness),
        "workload_ready": float(workload_ready),
        "source_intact": float(source_intact),
        "contained": float(contained),
        "restored": float(restored),
    }


def reward_from_terms(t: dict[str, float]) -> float:
    for key in TERM_KEYS:
        if key not in t:
            raise KeyError(f"score terms missing {key} (never default)")
    return sum(t[k] for k in TERM_KEYS) / float(len(TERM_KEYS))


def score_create_env(
    *,
    member_alive: list[bool],
    source_alive: bool,
    contained: float,
    restored: float,
) -> dict[str, Any]:
    if not member_alive:
        raise ValueError("member_alive must be non-empty")
    live = 1.0 if all(member_alive) else 0.0
    # create mode has no inner workload; the guests *are* the workload.
    t = terms(
        liveness=live,
        workload_ready=live,
        source_intact=1.0 if source_alive else 0.0,
        contained=contained,
        restored=restored,
    )
    return {"reward": reward_from_terms(t), "terms": t}


def score_adopt_env(
    *,
    readyz: bool,
    workload_ready: bool,
    source_intact: bool,
    contained: float,
    restored: float,
) -> dict[str, Any]:
    t = terms(
        liveness=1.0 if readyz else 0.0,
        workload_ready=1.0 if workload_ready else 0.0,
        source_intact=1.0 if source_intact else 0.0,
        contained=contained,
        restored=restored,
    )
    return {"reward": reward_from_terms(t), "terms": t}

