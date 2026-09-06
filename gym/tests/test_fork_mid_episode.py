"""POST /env/{id}/fork — stub k7d, no KVM."""

from __future__ import annotations

import json
import os
import socket
import subprocess
import sys
import threading
import time
import unittest
from http.server import ThreadingHTTPServer
from pathlib import Path
from typing import Any
from unittest.mock import patch
from urllib.error import HTTPError
from urllib.request import Request, urlopen

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import host as gym_host
import server
import stub as gym_stub
from host import k7_bridge_name
from lease import Env, Lease, LeaseTable, new_env_id, new_lease_id


def _json(
    method: str,
    url: str,
    body: dict[str, Any] | None = None,
    timeout_s: float = 5,
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


class _Http:
    def __init__(self, server_: ThreadingHTTPServer) -> None:
        self.server = server_
        host, port = server_.server_address[:2]
        self.base = f"http://{host}:{port}"
        self.thread = threading.Thread(target=server_.serve_forever, daemon=True)
        self.thread.start()

    def close(self) -> None:
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=2)


def _start_stub(node_id: str) -> tuple[_Http, gym_stub.Stub]:
    stub = gym_stub.Stub(node_id, None, "")

    class Bound(gym_stub.Handler):
        pass

    Bound.stub = stub
    httpd = ThreadingHTTPServer(("127.0.0.1", 0), Bound)
    return _Http(httpd), stub


class FakeK7d:
    def __init__(self) -> None:
        self.prepared: list[tuple[str, str]] = []
        self.batches: list[tuple[str, str, list[str]]] = []
        self.pruned: list[str] = []
        self._n = 0

    def tree_prepare_fork_source(self, tree_id: str, node_id: str, timeout=None):
        self.prepared.append((tree_id, node_id))
        return {"status": "ok"}

    def tree_fork_batch(
        self, tree_id: str, source_id: str, labels: list[str], timeout=None, dilation=None
    ):
        self.batches.append((tree_id, source_id, list(labels)))
        forks = []
        for _lab in labels:
            self._n += 1
            forks.append(
                {
                    "node_id": f"child-{self._n}",
                    "guest_cids": [40 + self._n, 41 + self._n, 42 + self._n],
                }
            )
        return {"forks": forks}

    def tree_prune(self, tree_id: str, node_id: str) -> dict[str, Any]:
        self.pruned.append(node_id)
        return {"status": "ok"}

    def auto_warp(self, cluster_id: str, mode: str) -> dict[str, Any]:
        return {
            "status": "auto_warp",
            "cluster_id": cluster_id,
            "mode": mode,
            "holders": [],
            "stats": {},
        }

    def auto_warp_hold(
        self, cluster_id: str, holder: str, hold: bool
    ) -> dict[str, Any]:
        return {
            "status": "auto_warp",
            "cluster_id": cluster_id,
            "mode": "off",
            "holders": [holder] if hold else [],
            "stats": {},
        }


def _gym(*, max_live_vms: int = 64) -> server.Gym:
    ns = server.parse_args(
        [
            "--source-mode",
            "create",
            "--max-live-vms",
            str(max_live_vms),
            "--max-live-ram-bytes",
            str(64 * 1024**3),
            "--memory-mb",
            "256",
            "--vm-count",
            "3",
        ]
    )
    g = server.Gym(server.Config(ns))
    g.client = FakeK7d()  # type: ignore[assignment]
    g.source_vms = 3
    return g


def _seed_lease(g: server.Gym, n: int = 2) -> Lease:
    import time

    lid = new_lease_id()
    envs = [
        Env(
            env_id=new_env_id(lid, i),
            branch_node_id=f"br-{i}",
            index=i,
            bridge=f"k7-br-x{i}",
            guest_ips=["10.200.0.2"],
            guest_cids=[10 + i],
            tree_id=g.cfg.source_tree_id,
        )
        for i in range(n)
    ]
    now = time.time()
    L = Lease(
        lease_id=lid,
        node_id="node-a",
        group_id="g",
        fault_id="none",
        tree_id=g.cfg.source_tree_id,
        source_node_id="root",
        n=n,
        created_at=now,
        expires_at=now + 60,
        envs=[],
    )
    assert g.leases.reserve(L) is None
    return g.leases.commit(lid, envs)


class TestLeaseAppend(unittest.TestCase):
    def test_append_updates_n(self) -> None:
        g = _gym()
        L = _seed_lease(g, n=2)
        child = Env(
            env_id=new_env_id(L.lease_id, 2),
            branch_node_id="br-2",
            index=2,
            bridge="k7-br-x2",
            guest_ips=["10.200.0.2"],
            guest_cids=[12],
        )
        got = g.leases.append_envs(L.lease_id, [child])
        self.assertEqual(got.n, 3)
        self.assertEqual(len(got.envs), 3)
        self.assertEqual(g.leases.live_vms_in_flight(3), 9)


class TestStubHttpFork(unittest.TestCase):
    def test_lease_n2_fork_n2_same_lease(self) -> None:
        http, stub = _start_stub("gym-a")
        self.addCleanup(http.close)
        code, lease = _json(
            "POST",
            f"{http.base}/lease",
            {"fault_id": "none", "n": 2, "group_id": "g", "ttl_s": 60},
        )
        self.assertEqual(code, 200, lease)
        parent = lease["envs"][0]["env_id"]
        code, fork = _json(
            "POST",
            f"{http.base}/env/{parent}/fork",
            {"n": 2, "labels": ["child-0", "child-1"]},
        )
        self.assertEqual(code, 200, fork)
        self.assertEqual(fork["lease_id"], lease["lease_id"])
        self.assertEqual(fork["parent_env_id"], parent)
        self.assertEqual(len(fork["envs"]), 2)
        self.assertEqual([e["index"] for e in fork["envs"]], [2, 3])
        code, scored = _json("POST", f"{http.base}/lease/{lease['lease_id']}/score", {})
        self.assertEqual(code, 200, scored)
        self.assertEqual(len(scored["scores"]), 4)
        code, rel = _json(
            "POST", f"{http.base}/lease/{lease['lease_id']}/release", {}
        )
        self.assertEqual(code, 200, rel)
        self.assertTrue(rel["released"])
        self.assertEqual(stub.leases, {})

    def test_unknown_env_is_404(self) -> None:
        http, _ = _start_stub("gym-a")
        self.addCleanup(http.close)
        code, body = _json("POST", f"{http.base}/env/missing/fork", {"n": 1})
        self.assertEqual(code, 404, body)
        code, body = _json("POST", f"{http.base}/env/missing/prepare", {})
        self.assertEqual(code, 404, body)


class TestGymForkEnv(unittest.TestCase):
    def test_prepare_then_batch_and_409(self) -> None:
        g = _gym(max_live_vms=64)
        L = _seed_lease(g, n=2)
        parent = L.envs[0]

        def bridges() -> set[str]:
            # Whatever children FakeK7d will mint.
            tids = [g.cfg.source_tree_id]
            nids = [f"child-{i}" for i in range(1, 8)]
            return {k7_bridge_name(f"{tid}-{nid}") for tid in tids for nid in nids}

        with patch.object(gym_host, "list_bridges", bridges), patch.object(
            server, "list_bridges", bridges
        ):
            out = g.fork_env(parent.env_id, {"n": 2})
        self.assertEqual(out["lease_id"], L.lease_id)
        self.assertEqual(len(out["envs"]), 2)
        self.assertEqual([e["index"] for e in out["envs"]], [2, 3])
        fake = g.client
        assert isinstance(fake, FakeK7d)
        self.assertEqual(fake.prepared, [])
        self.assertEqual(len(fake.batches), 1)
        got = g.leases.get(L.lease_id)
        assert got is not None
        self.assertEqual(got.n, 4)
        self.assertEqual(len(got.envs), 4)

        tight = _gym(max_live_vms=9)
        # source 3 + seeded 2*3 = 9 already; one more branch is 3 VMs → 12 > 9
        seeded = _seed_lease(tight, n=2)
        with self.assertRaises(server.ForkRejected) as ctx:
            tight.fork_env(seeded.envs[0].env_id, {"n": 1})
        self.assertIn("need", ctx.exception.message)
        fake2 = tight.client
        assert isinstance(fake2, FakeK7d)
        self.assertEqual(fake2.batches, [])

    def test_prepare_env_dumps_without_fork(self) -> None:
        g = _gym()
        L = _seed_lease(g, n=2)
        parent = L.envs[0]
        out = g.prepare_env(parent.env_id)
        self.assertTrue(out["ok"])
        self.assertEqual(out["env_id"], parent.env_id)
        self.assertEqual(out["lease_id"], L.lease_id)
        self.assertEqual(out["node_id"], parent.branch_node_id)
        fake = g.client
        assert isinstance(fake, FakeK7d)
        self.assertEqual(fake.prepared, [(g.cfg.source_tree_id, parent.branch_node_id)])
        self.assertEqual(fake.batches, [])
        got = g.leases.get(L.lease_id)
        assert got is not None
        self.assertEqual(len(got.envs), 2)

    def test_reset_is_loud(self) -> None:
        ns = server.parse_args(
            [
                "--source-mode",
                "ubuntu",
                "--start-mode",
                "reset",
                "--reset-measurement",
                "--memory-mb",
                "2048",
            ]
        )
        g = server.Gym(server.Config(ns))
        with self.assertRaises(ValueError) as ctx:
            g.fork_env("x", {"n": 1})
        self.assertIn("#149", str(ctx.exception))


LIVE_TREE = os.environ.get("GYM_SOURCE_TREE_ID", "gym-src-k7rl-fork")
K7D_SOCK = os.environ.get("K7D_SOCKET", "/run/k7d/k7d.sock")
GYM_PY = Path(__file__).resolve().parents[1] / "server.py"


def _live_ubuntu_source_ready() -> bool:
    if not os.path.exists(K7D_SOCK):
        return False
    try:
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        sock.settimeout(5)
        sock.connect(K7D_SOCK)
        sock.sendall(b'{"op":"tree_list"}\n')
        raw = sock.recv(65536).decode()
        sock.close()
        data = json.loads(raw)
    except (OSError, json.JSONDecodeError):
        return False
    for t in data.get("trees") or []:
        if t.get("tree_id") == LIVE_TREE and int(t.get("nodes") or 0) >= 1:
            return True
    return False


@unittest.skipUnless(
    _live_ubuntu_source_ready(),
    "needs live k7d + Ubuntu fork source (no #[ignore])",
)
class TestLiveUbuntuFork(unittest.TestCase):
    """Lease n=1, fork n=2 on the gym node. Does not restart k7d."""

    def test_lease_n1_fork_n2_obs_release(self) -> None:
        env = os.environ.copy()
        env.update(
            {
                "GYM_SOURCE_MODE": "ubuntu",
                "GYM_START_MODE": "fork",
                "GYM_SOURCE_TREE_ID": LIVE_TREE,
                "GYM_BIND": "127.0.0.1",
                "GYM_PORT": "0",
                "GYM_MEMORY_MB": "2048",
                "GYM_VM_COUNT": "3",
                "GYM_MAX_LIVE_VMS": "64",
                "GYM_MAX_LEASES": "4",
                "GYM_K7D_TIMEOUT_S": "180",
                "GYM_SCOREBOARD": "health",
            }
        )
        proc = subprocess.Popen(
            [sys.executable, str(GYM_PY), "--port", "0", "--bind", "127.0.0.1"],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            env=env,
        )

        def _stop() -> None:
            if proc.poll() is None:
                proc.terminate()
                try:
                    proc.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    proc.kill()
                    proc.wait(timeout=5)
            if proc.stdout:
                proc.stdout.close()

        self.addCleanup(_stop)
        base = ""
        deadline = time.time() + 90
        assert proc.stdout is not None
        while time.time() < deadline:
            line = proc.stdout.readline()
            if not line and proc.poll() is not None:
                rest = proc.stdout.read()
                self.fail(f"gym exited {proc.returncode}: {rest}")
            if line.startswith("GYM_LISTEN="):
                base = "http://" + line.split("=", 1)[1].strip()
                break
        self.assertTrue(base, "gym never printed GYM_LISTEN")

        code, hz = _json("GET", f"{base}/healthz")
        self.assertEqual(code, 200, hz)
        self.assertTrue(hz.get("ok"))

        code, lease = _json(
            "POST",
            f"{base}/lease",
            {"fault_id": "none", "n": 1, "group_id": "inc12-live", "ttl_s": 180},
            timeout_s=180,
        )
        self.assertEqual(code, 200, lease)
        parent = lease["envs"][0]["env_id"]
        lid = lease["lease_id"]
        code, fork = _json(
            "POST",
            f"{base}/env/{parent}/fork",
            {"n": 2, "labels": ["child-0", "child-1"]},
            timeout_s=180,
        )
        self.assertEqual(code, 200, fork)
        self.assertEqual(fork["lease_id"], lid)
        self.assertEqual(len(fork["envs"]), 2)
        for child in fork["envs"]:
            eid = child["env_id"]
            code, obs = _json(
                "POST", f"{base}/env/{eid}/obs", {}, timeout_s=30
            )
            self.assertEqual(code, 200, obs)
            self.assertIn("readyz", obs.get("observation") or {})
        code, parent_obs = _json(
            "POST", f"{base}/env/{parent}/obs", {}, timeout_s=30
        )
        self.assertEqual(code, 200, parent_obs)
        code, rel = _json(
            "POST", f"{base}/lease/{lid}/release", {}, timeout_s=90
        )
        self.assertEqual(code, 200, rel)
        self.assertEqual(rel.get("residue", {}).get("bridges"), [])
        self.assertTrue(_live_ubuntu_source_ready(), "source tree must survive")
        proc.terminate()
        proc.wait(timeout=15)


if __name__ == "__main__":
    unittest.main()
