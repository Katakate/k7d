"""gym-router: sticky groups, drain, Ubuntu admission — no KVM."""

from __future__ import annotations

import json
import socket
import sys
import threading
import unittest
from http.server import ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import router as gym_router
import stub as gym_stub
from ubuntu import NODE_MEMORY_MB


def _json(
    method: str, url: str, body: dict[str, Any] | None = None, timeout_s: float = 5
) -> tuple[int, dict[str, Any]]:
    data = None if body is None else json.dumps(body).encode()
    req = Request(url, data=data, method=method)
    if data is not None:
        req.add_header("Content-Type", "application/json")
    try:
        with urlopen(req, timeout=timeout_s) as resp:
            raw = resp.read()
            return resp.status, json.loads(raw) if raw else {}
    except HTTPError as e:
        raw = e.read()
        try:
            parsed = json.loads(raw) if raw else {}
        except json.JSONDecodeError:
            parsed = {"error": raw.decode(errors="replace")}
        return e.code, parsed


def _lease_body(group_id: str, n: int = 1) -> dict[str, Any]:
    return {"fault_id": "none", "n": n, "group_id": group_id, "ttl_s": 60}


class _Http:
    def __init__(self, server: ThreadingHTTPServer) -> None:
        self.server = server
        host, port = server.server_address[:2]
        self.base = f"http://{host}:{port}"
        self.thread = threading.Thread(target=server.serve_forever, daemon=True)
        self.thread.start()

    def close(self) -> None:
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=2)


def _start_stub(node_id: str) -> tuple[_Http, gym_stub.Stub]:
    stub = gym_stub.Stub(node_id, None, "")
    gym_stub.Handler.stub = stub

    class Bound(gym_stub.Handler):
        pass

    Bound.stub = stub
    httpd = ThreadingHTTPServer(("127.0.0.1", 0), Bound)
    return _Http(httpd), stub


def _start_router(upstreams: list[str], **kwargs: Any) -> _Http:
    ns = gym_router.parse_args(
        [
            "--bind",
            "127.0.0.1",
            "--port",
            "0",
            "--memory-mb",
            str(NODE_MEMORY_MB),
            "--upstreams",
            ",".join(upstreams),
        ]
    )
    for k, v in kwargs.items():
        setattr(ns, k, v)
    cfg = gym_router.Config(ns)
    rt = gym_router.Router(cfg)

    class Bound(gym_router.Handler):
        pass

    Bound.router = rt
    httpd = ThreadingHTTPServer(("127.0.0.1", 0), Bound)
    return _Http(httpd)


class TestAdmission(unittest.TestCase):
    def test_refuse_create_mode_memory(self) -> None:
        ns = gym_router.parse_args(
            [
                "--upstreams",
                "http://127.0.0.1:1,http://127.0.0.1:2",
                "--memory-mb",
                "256",
            ]
        )
        with self.assertRaises(SystemExit) as ctx:
            gym_router.Config(ns)
        self.assertIn("GYM_MEMORY_MB=256", str(ctx.exception))
        self.assertIn("2048", str(ctx.exception))

    def test_refuse_one_upstream(self) -> None:
        ns = gym_router.parse_args(["--upstreams", "http://127.0.0.1:1"])
        with self.assertRaises(SystemExit) as ctx:
            gym_router.Config(ns)
        self.assertIn("≥2", str(ctx.exception))

    def test_reject_spells_ubuntu_arithmetic(self) -> None:
        ns = gym_router.parse_args(
            [
                "--upstreams",
                "http://127.0.0.1:1,http://127.0.0.1:2",
                "--memory-mb",
                "2048",
                "--max-live-vms",
                "64",
            ]
        )
        rt = gym_router.Router(gym_router.Config(ns))
        msg = rt.admit(32, live_already=3)
        self.assertIsNotNone(msg)
        assert msg is not None
        self.assertIn("need 99 live VMs", msg)
        self.assertIn("source=3", msg)
        self.assertIn("n=32 * vms_per_branch=3", msg)
        self.assertIn("max_live_vms=64", msg)
        self.assertIn("2048 MiB × 3 × (1+n)", msg)
        self.assertIn("GYM_MEMORY_MB=2048", msg)
        # n=1: 3 source + 3 fork = 6 VMs × 2048 MiB
        self.assertIsNone(rt.admit(1, live_already=3))
        bytes_per = 2048 * 1024 * 1024
        self.assertEqual(6 * bytes_per, 3 * (1 + 1) * bytes_per)

    def test_source_never_talks_to_k7d(self) -> None:
        src = Path(gym_router.__file__).read_text()
        self.assertNotIn("k7d_client", src)
        self.assertNotIn("AF_UNIX", src)
        self.assertNotIn("tree_fork", src)
        self.assertNotIn("create_vm", src)
        # The docstring names the socket to forbid it; no connect.
        self.assertIn("Never talks to", src)
        self.assertNotIn("import socket as _unix", src)


class TestStickyDrainHttp(unittest.TestCase):
    def setUp(self) -> None:
        self.a_http, self.a = _start_stub("node-a")
        self.b_http, self.b = _start_stub("node-b")
        self.rt_http = _start_router([self.a_http.base, self.b_http.base])
        self.addCleanup(self.rt_http.close)
        self.addCleanup(self.b_http.close)
        self.addCleanup(self.a_http.close)

    def test_sticky_group_id(self) -> None:
        code, first = _json(
            "POST", f"{self.rt_http.base}/lease", _lease_body("g1")
        )
        self.assertEqual(code, 200, first)
        node = first["node_id"]
        self.assertIn(node, ("node-a", "node-b"))
        code, second = _json(
            "POST", f"{self.rt_http.base}/lease", _lease_body("g1")
        )
        self.assertEqual(code, 200, second)
        self.assertEqual(second["node_id"], node)
        self.assertNotEqual(first["lease_id"], second["lease_id"])

    def test_unknown_lease_is_404_not_broadcast(self) -> None:
        code, body = _json("GET", f"{self.rt_http.base}/lease/no-such")
        self.assertEqual(code, 404, body)
        self.assertIn("no such lease", body.get("error", ""))
        # Stubs never saw it.
        self.assertIsNone(self.a.get_lease("no-such"))
        self.assertIsNone(self.b.get_lease("no-such"))

    def test_drain_new_group_goes_elsewhere(self) -> None:
        code, first = _json(
            "POST", f"{self.rt_http.base}/lease", _lease_body("g-drain")
        )
        self.assertEqual(code, 200, first)
        owner = first["node_id"]
        env_id = first["envs"][0]["env_id"]
        if owner == "node-a":
            self.a.mark_drained()
            other = "node-b"
        else:
            self.b.mark_drained()
            other = "node-a"
        t0 = time_ms()
        code, nxt = _json(
            "POST", f"{self.rt_http.base}/lease", _lease_body("g-new")
        )
        drain_ms = time_ms() - t0
        self.assertEqual(code, 200, nxt)
        self.assertEqual(nxt["node_id"], other)
        self.assertLess(drain_ms, 2000)
        # Same group_id does not migrate.
        code, stuck = _json(
            "POST", f"{self.rt_http.base}/lease", _lease_body("g-drain")
        )
        self.assertEqual(code, 503, stuck)
        self.assertIn("not migrating", stuck.get("error", ""))
        # In-flight act still targets the drained owner and is loud if we
        # kill the process. 503 health still serves act (stub is up).
        code, act = _json(
            "POST",
            f"{self.rt_http.base}/env/{env_id}/act",
            {"action": "exec", "args": ["true"], "timeout_s": 1},
        )
        self.assertEqual(code, 200, act)
        self.assertEqual(act["node_id"], owner)

    def test_fork_children_stay_on_owner(self) -> None:
        code, lease = _json(
            "POST", f"{self.rt_http.base}/lease", _lease_body("g-fork", n=1)
        )
        self.assertEqual(code, 200, lease)
        parent = lease["envs"][0]["env_id"]
        owner = lease["node_id"]
        code, fork = _json(
            "POST",
            f"{self.rt_http.base}/env/{parent}/fork",
            {"n": 2, "labels": ["child-0", "child-1"]},
        )
        self.assertEqual(code, 200, fork)
        self.assertEqual(fork["lease_id"], lease["lease_id"])
        self.assertEqual(len(fork["envs"]), 2)
        child = fork["envs"][0]["env_id"]
        code, obs = _json("POST", f"{self.rt_http.base}/env/{child}/obs", {})
        self.assertEqual(code, 200, obs)
        self.assertEqual(obs["node_id"], owner)
        code, rel = _json(
            "POST", f"{self.rt_http.base}/lease/{lease['lease_id']}/release", {}
        )
        self.assertEqual(code, 200, rel)
        code, miss = _json("POST", f"{self.rt_http.base}/env/{child}/obs", {})
        self.assertEqual(code, 404, miss)

    def test_unknown_env_is_404(self) -> None:
        code, body = _json(
            "POST",
            f"{self.rt_http.base}/env/missing/act",
            {"action": "exec", "args": ["true"], "timeout_s": 1},
        )
        self.assertEqual(code, 404, body)
        self.assertIn("no such env", body.get("error", ""))

    def test_healthz_lists_upstreams(self) -> None:
        code, hz = _json("GET", f"{self.rt_http.base}/healthz")
        self.assertEqual(code, 200, hz)
        self.assertTrue(hz["ok"])
        self.assertEqual(len(hz["upstreams"]), 2)
        self.assertEqual(hz["admission"], "2048 MiB × 3 × (1+n)")


class TestInflightDead(unittest.TestCase):
    def test_act_on_killed_upstream_is_loud(self) -> None:
        a_http, _a = _start_stub("node-a")
        b_http, _b = _start_stub("node-b")
        rt_http = _start_router([a_http.base, b_http.base])
        self.addCleanup(rt_http.close)
        self.addCleanup(b_http.close)
        # Do not addCleanup(a_http.close) after we close it ourselves.
        code, lease = _json("POST", f"{rt_http.base}/lease", _lease_body("g-kill"))
        self.assertEqual(code, 200, lease)
        owner = lease["node_id"]
        env_id = lease["envs"][0]["env_id"]
        victim = a_http if owner == "node-a" else b_http
        survivor = b_http if owner == "node-a" else a_http
        victim.close()
        code, act = _json(
            "POST",
            f"{rt_http.base}/env/{env_id}/act",
            {"action": "exec", "args": ["true"], "timeout_s": 1},
        )
        self.assertEqual(code, 502, act)
        self.assertIn("unreachable", act.get("error", ""))
        code, nxt = _json("POST", f"{rt_http.base}/lease", _lease_body("g-after"))
        self.assertEqual(code, 200, nxt)
        self.assertNotEqual(nxt["node_id"], owner)
        survivor.close()


def time_ms() -> float:
    import time

    return time.perf_counter() * 1000.0


class TestPickHelpers(unittest.TestCase):
    def test_http_json_dead_raises(self) -> None:
        # Bind-and-close so the port is unused.
        s = socket.socket()
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]
        s.close()
        with self.assertRaises(gym_router.UpstreamDead) as ctx:
            gym_router.http_json(
                "GET",
                f"http://127.0.0.1:{port}/healthz",
                timeout_s=0.3,
                token=None,
            )
        self.assertIn("unreachable", str(ctx.exception))

    def test_urlerror_is_not_swallowed(self) -> None:
        with self.assertRaises((gym_router.UpstreamDead, URLError)):
            gym_router.http_json(
                "GET",
                "http://127.0.0.1:1/healthz",
                timeout_s=0.3,
                token=None,
            )


if __name__ == "__main__":
    unittest.main()
