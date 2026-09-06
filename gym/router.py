#!/usr/bin/env python3
"""gym-router: sticky groups, Ubuntu RAM admission, drain.

Dumb HTTP proxy in front of ≥2 gym processes. Same paths, same JSON,
plus ``node_id``. Never talks to ``/run/k7d/k7d.sock`` and never forks —
a trainer POSTs ``/lease`` here; the chosen gym is the only process
that may call k7d.
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import signal
import socket
import sys
import threading
import time
import traceback
from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import urlparse
from urllib.request import Request, urlopen

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

from budget import lease_need  # noqa: E402
from ubuntu import NODE_MEMORY_MB, memory_floor_error  # noqa: E402

log = logging.getLogger("gym-router")

VMS_PER_BRANCH = 3
SOURCE_VMS = 3
ARITHMETIC = "2048 MiB × 3 × (1+n)"


class Config:
    def __init__(self, ns: argparse.Namespace) -> None:
        self.bind = ns.bind
        self.port = ns.port
        self.node_id = ns.node_id
        self.upstreams = parse_upstreams(ns.upstreams, ns.upstream)
        if len(self.upstreams) < 2:
            raise SystemExit(
                "GYM_UPSTREAMS must list ≥2 gym base URLs "
                f"(got {self.upstreams!r})"
            )
        self.memory_mb = ns.memory_mb
        floor = memory_floor_error(self.memory_mb)
        if floor:
            raise SystemExit(floor)
        self.vm_count = ns.vm_count
        if self.vm_count != VMS_PER_BRANCH:
            raise SystemExit(
                f"GYM_VM_COUNT={self.vm_count} is not {VMS_PER_BRANCH} "
                "(Ubuntu cluster is 3 VMs per branch)"
            )
        self.max_live_vms = ns.max_live_vms
        self.max_live_ram_bytes = ns.max_live_ram_bytes
        self.max_leases = ns.max_leases
        self.token = ns.token or None
        self.proxy_timeout_s = ns.proxy_timeout_s
        self.health_timeout_s = ns.health_timeout_s
        self.memory_bytes_per_vm = self.memory_mb * 1024 * 1024


def parse_upstreams(joined: str, extra: list[str]) -> list[str]:
    raw: list[str] = []
    if joined.strip():
        raw.extend(joined.split(","))
    raw.extend(extra)
    out: list[str] = []
    for item in raw:
        url = item.strip().rstrip("/")
        if not url:
            continue
        parsed = urlparse(url)
        if parsed.scheme not in ("http", "https") or not parsed.netloc:
            raise SystemExit(f"upstream is not an http(s) URL: {item!r}")
        if url not in out:
            out.append(url)
    return out


@dataclass
class Health:
    ok: bool
    status: int | None
    node_id: str
    error: str
    leases_in_flight: int = 0


class UpstreamDead(Exception):
    def __init__(self, url: str, message: str) -> None:
        super().__init__(f"upstream {url} unreachable: {message}")
        self.url = url
        self.message = message


class LeaseRejected(Exception):
    def __init__(self, message: str) -> None:
        super().__init__(message)
        self.message = message


class StickyDrained(Exception):
    def __init__(self, group_id: str, url: str) -> None:
        super().__init__(
            f"sticky upstream drained for group_id={group_id!r} "
            f"({url}); not migrating a live group"
        )
        self.group_id = group_id
        self.url = url


@dataclass
class Router:
    """In-memory placement. One group_id → one gym while that gym is up."""

    cfg: Config
    group_to_url: dict[str, str] = field(default_factory=dict)
    lease_to_url: dict[str, str] = field(default_factory=dict)
    env_to_url: dict[str, str] = field(default_factory=dict)
    lease_n: dict[str, int] = field(default_factory=dict)
    lease_envs: dict[str, list[str]] = field(default_factory=dict)
    lock: threading.Lock = field(default_factory=threading.Lock)

    def probe_health(self, url: str) -> Health:
        try:
            code, body = http_json(
                "GET",
                f"{url}/healthz",
                timeout_s=self.cfg.health_timeout_s,
                token=self.cfg.token,
            )
        except UpstreamDead as e:
            return Health(ok=False, status=None, node_id="", error=str(e))
        if code == 200 and body.get("ok") is True:
            return Health(
                ok=True,
                status=code,
                node_id=str(body.get("node_id") or ""),
                error="",
                leases_in_flight=int(body.get("leases_in_flight") or 0),
            )
        return Health(
            ok=False,
            status=code,
            node_id=str(body.get("node_id") or ""),
            error=str(body.get("error") or f"healthz HTTP {code}"),
            leases_in_flight=int(body.get("leases_in_flight") or 0),
        )

    def live_already(self, url: str) -> int:
        leased = sum(
            n * VMS_PER_BRANCH
            for lid, n in self.lease_n.items()
            if self.lease_to_url.get(lid) == url
        )
        return SOURCE_VMS + leased

    def admit(self, n: int, live_already: int) -> str | None:
        if n < 1:
            return f"lease rejected: n must be >= 1, got {n}"
        need = lease_need(
            n=n,
            vms_per_branch=VMS_PER_BRANCH,
            source_vms=SOURCE_VMS,
            live_already=live_already,
            max_live_vms=self.cfg.max_live_vms,
            memory_bytes_per_vm=self.cfg.memory_bytes_per_vm,
            max_live_ram_bytes=self.cfg.max_live_ram_bytes,
        )
        msg = need.rejection()
        if msg is None:
            return None
        return (
            f"{msg} ({self.cfg.memory_mb} MiB × 3 × (1+n) Ubuntu admission; "
            f"GYM_MEMORY_MB={self.cfg.memory_mb})"
        )

    def pick(self, group_id: str, n: int) -> str:
        """Choose an upstream. Sticky while that gym is up; never migrate."""
        with self.lock:
            sticky = self.group_to_url.get(group_id)
            if sticky is not None:
                hz = self.probe_health(sticky)
                if not hz.ok:
                    raise StickyDrained(group_id, sticky)
                reject = self.admit(n, self.live_already(sticky))
                if reject:
                    raise LeaseRejected(reject)
                return sticky

            healthy: list[tuple[str, Health]] = []
            last_reject = (
                f"lease rejected: no healthy upstream can fit n={n} "
                f"({self.cfg.memory_mb} MiB × 3 × (1+n) Ubuntu admission; "
                f"GYM_MEMORY_MB={self.cfg.memory_mb})"
            )
            for url in self.cfg.upstreams:
                hz = self.probe_health(url)
                if not hz.ok:
                    log.info("drain skip %s: %s", url, hz.error)
                    continue
                reject = self.admit(n, self.live_already(url))
                if reject:
                    last_reject = reject
                    continue
                healthy.append((url, hz))
            if not healthy:
                raise LeaseRejected(last_reject)
            # Least loaded, then config order — deterministic, no fan-out.
            healthy.sort(key=lambda t: (self.live_already(t[0]), t[0]))
            return healthy[0][0]

    def remember_lease(self, url: str, body: dict[str, Any], resp: dict[str, Any]) -> None:
        lid = str(resp.get("lease_id") or "")
        if not lid:
            raise RuntimeError(f"upstream {url} /lease missing lease_id: {resp}")
        n = int(body["n"])
        envs = resp.get("envs")
        if not isinstance(envs, list):
            raise RuntimeError(f"upstream {url} /lease missing envs: {resp}")
        env_ids = [
            str(e["env_id"])
            for e in envs
            if isinstance(e, dict) and e.get("env_id")
        ]
        with self.lock:
            self.lease_to_url[lid] = url
            self.lease_n[lid] = n
            self.lease_envs[lid] = env_ids
            self.group_to_url.setdefault(str(body["group_id"]), url)
            for eid in env_ids:
                self.env_to_url[eid] = url

    def forget_lease(self, lease_id: str) -> None:
        with self.lock:
            self.lease_to_url.pop(lease_id, None)
            self.lease_n.pop(lease_id, None)
            for eid in self.lease_envs.pop(lease_id, []):
                self.env_to_url.pop(eid, None)

    def owner_for_lease(self, lease_id: str) -> str | None:
        with self.lock:
            return self.lease_to_url.get(lease_id)

    def owner_for_env(self, env_id: str) -> str | None:
        with self.lock:
            return self.env_to_url.get(env_id)

    def remember_fork(self, parent_env_id: str, resp: dict[str, Any]) -> None:
        url = self.owner_for_env(parent_env_id)
        if url is None:
            raise RuntimeError(f"fork parent {parent_env_id} has no owner")
        lid = str(resp.get("lease_id") or "")
        if not lid:
            raise RuntimeError(f"fork missing lease_id: {resp}")
        envs = resp.get("envs")
        if not isinstance(envs, list) or not envs:
            raise RuntimeError(f"fork missing envs: {resp}")
        ids = [
            str(e["env_id"])
            for e in envs
            if isinstance(e, dict) and e.get("env_id")
        ]
        with self.lock:
            for eid in ids:
                self.env_to_url[eid] = url
                self.lease_envs.setdefault(lid, []).append(eid)
            if lid in self.lease_n:
                self.lease_n[lid] = len(self.lease_envs[lid])

    def proxy(
        self, url: str, method: str, path: str, body: dict[str, Any] | None
    ) -> tuple[int, dict[str, Any]]:
        return http_json(
            method,
            f"{url}{path}",
            body=body,
            timeout_s=self.cfg.proxy_timeout_s,
            token=self.cfg.token,
        )

    def healthz(self) -> tuple[int, dict[str, Any]]:
        rows = []
        any_ok = False
        for url in self.cfg.upstreams:
            hz = self.probe_health(url)
            any_ok = any_ok or hz.ok
            rows.append(
                {
                    "url": url,
                    "ok": hz.ok,
                    "drained": not hz.ok,
                    "status": hz.status,
                    "node_id": hz.node_id,
                    "error": hz.error,
                    "leases_in_flight": hz.leases_in_flight,
                }
            )
        with self.lock:
            inflight = len(self.lease_to_url)
        payload = {
            "ok": any_ok,
            "k7d": "router",
            "upstreams": rows,
            "leases_in_flight": inflight,
            "max_leases": self.cfg.max_leases,
            "admission": f"{self.cfg.memory_mb} MiB × 3 × (1+n)",
        }
        return (200 if any_ok else 503), payload


def http_json(
    method: str,
    url: str,
    body: dict[str, Any] | None = None,
    *,
    timeout_s: float,
    token: str | None,
) -> tuple[int, dict[str, Any]]:
    data = None
    if body is not None:
        data = json.dumps(body, separators=(",", ":")).encode()
    req = Request(url, data=data, method=method)
    if data is not None:
        req.add_header("Content-Type", "application/json")
        req.add_header("Content-Length", str(len(data)))
    if token:
        req.add_header("X-Gym-Token", token)
    try:
        with urlopen(req, timeout=timeout_s) as resp:
            raw = resp.read()
            code = getattr(resp, "status", 200)
            return code, _decode_json(raw)
    except HTTPError as e:
        raw = e.read()
        return e.code, _decode_json(raw)
    except (URLError, TimeoutError, socket.timeout, OSError) as e:
        raise UpstreamDead(url, str(e)) from e


def _decode_json(raw: bytes) -> dict[str, Any]:
    if not raw:
        return {}
    try:
        data = json.loads(raw.decode())
    except (json.JSONDecodeError, UnicodeDecodeError):
        return {"error": raw.decode(errors="replace")}
    if isinstance(data, dict):
        return data
    return {"error": f"JSON body must be an object, got {type(data).__name__}"}


class Handler(BaseHTTPRequestHandler):
    router: Router

    def log_message(self, fmt: str, *args: Any) -> None:
        log.info("%s %s", self.address_string(), fmt % args)

    def _read_json(self) -> dict[str, Any]:
        length = int(self.headers.get("Content-Length") or "0")
        raw = self.rfile.read(length) if length else b"{}"
        if not raw:
            return {}
        data = json.loads(raw.decode())
        if not isinstance(data, dict):
            raise ValueError("JSON body must be an object")
        return data

    def _auth(self) -> bool:
        token = self.router.cfg.token
        if not token:
            return True
        if self.headers.get("X-Gym-Token") != token:
            self._send(401, {"error": "missing or wrong X-Gym-Token"})
            return False
        return True

    def _send(self, code: int, body: dict[str, Any]) -> None:
        body.setdefault("node_id", self.router.cfg.node_id)
        payload = json.dumps(body, separators=(",", ":")).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def do_GET(self) -> None:  # noqa: N802
        if not self._auth():
            return
        path = urlparse(self.path).path
        try:
            if path == "/healthz":
                code, body = self.router.healthz()
                self._send(code, body)
                return
            if path.startswith("/lease/"):
                rest = path[len("/lease/") :]
                if not rest or "/" in rest:
                    self._send(404, {"error": f"no such path: {path}"})
                    return
                self._proxy_owned("lease", rest, "GET", path, None)
                return
            self._send(404, {"error": f"no such path: {path}"})
        except Exception as e:
            log.exception("GET %s", path)
            self._send(500, {"error": str(e)})

    def do_POST(self) -> None:  # noqa: N802
        if not self._auth():
            return
        path = urlparse(self.path).path
        try:
            body = self._read_json()
        except (ValueError, json.JSONDecodeError) as e:
            self._send(400, {"error": f"bad json: {e}"})
            return
        try:
            if path == "/lease":
                self._lease(body)
                return
            if path.endswith("/act") and path.startswith("/env/"):
                env_id = path[len("/env/") : -len("/act")]
                self._proxy_owned("env", env_id, "POST", path, body)
                return
            if path.endswith("/obs") and path.startswith("/env/"):
                env_id = path[len("/env/") : -len("/obs")]
                self._proxy_owned("env", env_id, "POST", path, body)
                return
            if path.endswith("/prepare") and path.startswith("/env/"):
                env_id = path[len("/env/") : -len("/prepare")]
                self._proxy_owned("env", env_id, "POST", path, body)
                return
            if path.endswith("/fork") and path.startswith("/env/"):
                env_id = path[len("/env/") : -len("/fork")]
                self._fork(env_id, path, body)
                return
            if path.endswith("/score") and path.startswith("/lease/"):
                lid = path[len("/lease/") : -len("/score")]
                self._proxy_owned("lease", lid, "POST", path, body)
                return
            if path.endswith("/release") and path.startswith("/lease/"):
                lid = path[len("/lease/") : -len("/release")]
                self._release(lid, path, body)
                return
            self._send(404, {"error": f"no such path: {path}"})
        except LeaseRejected as e:
            self._send(400, {"error": e.message})
        except StickyDrained as e:
            self._send(503, {"error": str(e)})
        except UpstreamDead as e:
            self._send(502, {"error": str(e)})
        except KeyError as e:
            self._send(404, {"error": str(e)})
        except ValueError as e:
            self._send(400, {"error": str(e)})
        except Exception as e:
            log.exception("POST %s", path)
            self._send(500, {"error": f"{e}\n{traceback.format_exc()}"})

    def _lease(self, body: dict[str, Any]) -> None:
        for key in ("fault_id", "n", "group_id", "ttl_s"):
            if key not in body:
                raise ValueError(f"POST /lease missing {key}")
        n = int(body["n"])
        group_id = str(body["group_id"])
        t0 = time.perf_counter()
        url = self.router.pick(group_id, n)
        code, resp = self.router.proxy(url, "POST", "/lease", body)
        elapsed_ms = (time.perf_counter() - t0) * 1000.0
        resp.setdefault("router_ms", elapsed_ms)
        if code == 200:
            self.router.remember_lease(url, body, resp)
        else:
            # Sticky only after a successful place. Do not pin a 4xx/5xx.
            log.warning("upstream %s /lease HTTP %s: %s", url, code, resp)
        self._send(code, resp)

    def _fork(self, env_id: str, path: str, body: dict[str, Any]) -> None:
        url = self.router.owner_for_env(env_id)
        if url is None:
            self._send(404, {"error": f"no such env: {env_id}"})
            return
        try:
            code, resp = self.router.proxy(url, "POST", path, body)
        except UpstreamDead as e:
            self._send(502, {"error": str(e)})
            return
        if code == 200:
            self.router.remember_fork(env_id, resp)
        self._send(code, resp)

    def _release(self, lease_id: str, path: str, body: dict[str, Any]) -> None:
        self._proxy_owned("lease", lease_id, "POST", path, body)
        # Drop the mapping either way: a 404 means the gym already forgot it.
        self.router.forget_lease(lease_id)

    def _proxy_owned(
        self,
        kind: str,
        ident: str,
        method: str,
        path: str,
        body: dict[str, Any] | None,
    ) -> None:
        if kind == "lease":
            url = self.router.owner_for_lease(ident)
        else:
            url = self.router.owner_for_env(ident)
        if url is None:
            self._send(404, {"error": f"no such {kind}: {ident}"})
            return
        try:
            code, resp = self.router.proxy(url, method, path, body)
        except UpstreamDead as e:
            self._send(502, {"error": str(e)})
            return
        self._send(code, resp)


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    env = os.environ
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--bind", default=env.get("GYM_BIND", "127.0.0.1"))
    p.add_argument("--port", type=int, default=int(env.get("GYM_PORT", "8080")))
    p.add_argument(
        "--node-id",
        default=env.get("GYM_NODE_ID") or f"router-{socket.gethostname()}",
    )
    p.add_argument(
        "--upstreams",
        default=env.get("GYM_UPSTREAMS", ""),
        help="comma-separated gym base URLs (need ≥2)",
    )
    p.add_argument(
        "--upstream",
        action="append",
        default=[],
        help="repeatable extra gym base URL",
    )
    p.add_argument(
        "--memory-mb",
        type=int,
        default=int(env.get("GYM_MEMORY_MB", str(NODE_MEMORY_MB))),
    )
    p.add_argument(
        "--vm-count", type=int, default=int(env.get("GYM_VM_COUNT", "3"))
    )
    p.add_argument(
        "--max-live-vms",
        type=int,
        default=int(env.get("GYM_MAX_LIVE_VMS", "64")),
    )
    p.add_argument(
        "--max-live-ram-bytes",
        type=int,
        default=int(env.get("GYM_MAX_LIVE_RAM_BYTES", str(64 * 1024**3))),
    )
    p.add_argument(
        "--max-leases", type=int, default=int(env.get("GYM_MAX_LEASES", "4"))
    )
    p.add_argument("--token", default=env.get("GYM_TOKEN", ""))
    p.add_argument(
        "--proxy-timeout-s",
        type=float,
        default=float(env.get("GYM_PROXY_TIMEOUT_S", "30")),
    )
    p.add_argument(
        "--health-timeout-s",
        type=float,
        default=float(env.get("GYM_HEALTH_TIMEOUT_S", "2")),
    )
    return p.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )
    cfg = Config(parse_args(argv))
    router = Router(cfg)
    Handler.router = router
    httpd = ThreadingHTTPServer((cfg.bind, cfg.port), Handler)
    host, port = httpd.server_address[:2]
    print(f"ROUTER_LISTEN={host}:{port}", flush=True)
    log.info(
        "listening on %s:%s node_id=%s upstreams=%s admission=%s",
        host,
        port,
        cfg.node_id,
        cfg.upstreams,
        ARITHMETIC,
    )

    def stop(signum: int, _frame: Any) -> None:
        log.info("signal %s, shutting down", signum)
        threading.Thread(target=httpd.shutdown, daemon=True).start()

    signal.signal(signal.SIGTERM, stop)
    signal.signal(signal.SIGINT, stop)
    try:
        httpd.serve_forever()
    finally:
        httpd.server_close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
