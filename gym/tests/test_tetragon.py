"""Tetragon scoreboard — fixture events, no KVM."""

from __future__ import annotations

import inspect
import json
import os
import socket
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from tetragon import (
    BUSYBOX,
    ClusterHealth,
    INJECT_NODE,
    TETRAGON_IMAGES,
    TetragonProbeError,
    collect_events,
    distribute_image_tar,
    ensure_tetragon,
    event_diff,
    inject_pod_body,
    parse_events,
    pull_tetragon_images,
    score_tetragon,
    tetragon_pod_names,
)


def _kp(path: str, *, ns: str = "default", binary: str = "/bin/touch", policy: str = "k7d-fd-install") -> str:
    return json.dumps(
        {
            "process_kprobe": {
                "function_name": "fd_install",
                "policy_name": policy,
                "message": "k7d-tetra-kprobe",
                "process": {
                    "binary": binary,
                    "arguments": f"touch {path}",
                    "pod": {"namespace": ns, "name": "inject"},
                    "pid": 4242,
                },
                "args": [{"file_arg": {"path": path}}],
            },
            "time": "2026-08-19T00:00:00Z",
        }
    )


def _exec(binary: str, *, ns: str = "kube-system", args: str = "") -> str:
    return json.dumps(
        {
            "process_exec": {
                "process": {
                    "binary": binary,
                    "arguments": args,
                    "pod": {"namespace": ns, "name": "probe"},
                    "pid": 7,
                }
            }
        }
    )


SRC_PATH = "/tmp/k7d-tetra-src-1"
CHILD_PATH = "/tmp/k7d-tetra-child-1"
# Source has its own inject + kube-system probe noise.
SOURCE = "\n".join(
    [
        _exec("/usr/lib/cilium/cilium-agent", ns="kube-system"),
        _exec("/usr/bin/tetragon", ns="kube-system"),
        _kp(SRC_PATH),
        "not-json noise from export-stdout",
    ]
)
# Branch sees the source inject (copied RAM / same policies) plus child-only.
BRANCH = "\n".join(
    [
        _exec("/usr/lib/cilium/cilium-agent", ns="kube-system"),
        _exec("/usr/bin/tetragon", ns="kube-system"),
        _kp(SRC_PATH),
        _kp(CHILD_PATH),
    ]
)
# Sibling / no-op: same baseline + a racing probe that is background.
SIBLING = "\n".join(
    [
        _exec("/usr/lib/cilium/cilium-agent", ns="kube-system"),
        _exec("/usr/bin/coredns", ns="kube-system"),
        _kp(SRC_PATH),
    ]
)


def _health(**kw) -> ClusterHealth:
    base = dict(
        readyz=True,
        nodes_ready=True,
        source_readyz=True,
        restored=False,
        injected=True,
    )
    base.update(kw)
    return ClusterHealth(**base)


class TestParseAndDiff(unittest.TestCase):
    def test_diverge_shape(self) -> None:
        src = parse_events(SOURCE)
        br = parse_events(BRANCH)
        self.assertTrue(any(e.key.path == SRC_PATH for e in src))
        self.assertTrue(any(e.key.path == CHILD_PATH for e in br))
        diff = event_diff(src, br, inject_paths=[CHILD_PATH])
        self.assertFalse(diff.leaked_paths)
        paths = {k.path for k in diff.branch_only}
        self.assertIn(CHILD_PATH, paths)
        self.assertNotIn(SRC_PATH, paths)
        # Source stream must not contain the child's path.
        self.assertFalse(any(e.key.path == CHILD_PATH for e in src))

    def test_leak_to_source_zeros_contained(self) -> None:
        leaked_src = SOURCE + "\n" + _kp(CHILD_PATH)
        diff = event_diff(
            parse_events(leaked_src),
            parse_events(BRANCH),
            inject_paths=[CHILD_PATH],
        )
        self.assertEqual(diff.leaked_paths, [CHILD_PATH])
        sc = score_tetragon(diff=diff, health=_health())
        self.assertEqual(sc["terms"]["contained"], 0.0)

    def test_background_jitter_does_not_move_contained(self) -> None:
        src = parse_events(SOURCE)
        sib = parse_events(SIBLING)
        diff = event_diff(src, sib, inject_paths=[])
        self.assertFalse(diff.branch_only)
        sc = score_tetragon(
            diff=diff,
            health=_health(injected=False, restored=True),
        )
        self.assertEqual(sc["terms"]["contained"], 1.0)
        from scoring import TERM_KEYS

        self.assertEqual(set(sc["terms"]), set(TERM_KEYS))
        self.assertIn("event_diff", sc)

    def test_injected_without_unique_events_is_zero_unless_restored(self) -> None:
        src = parse_events(SOURCE)
        # Branch identical to source — inject did not take / already restored.
        diff = event_diff(src, src, inject_paths=[CHILD_PATH])
        dead = score_tetragon(diff=diff, health=_health(restored=False))
        self.assertEqual(dead["terms"]["contained"], 0.0)
        ok = score_tetragon(diff=diff, health=_health(restored=True))
        self.assertEqual(ok["terms"]["contained"], 1.0)
        self.assertEqual(ok["terms"]["restored"], 1.0)

    def test_health_terms_never_defaulted(self) -> None:
        diff = event_diff(parse_events(SOURCE), parse_events(BRANCH), inject_paths=[CHILD_PATH])
        sc = score_tetragon(
            diff=diff,
            health=_health(readyz=False, nodes_ready=False, source_readyz=False),
        )
        t = sc["terms"]
        self.assertEqual(t["liveness"], 0.0)
        self.assertEqual(t["workload_ready"], 0.0)
        self.assertEqual(t["source_intact"], 0.0)
        self.assertEqual(t["contained"], 1.0)
        self.assertEqual(sc["reward"], sum(t.values()) / 5.0)

    def test_unreachable_zeros_contained_and_liveness(self) -> None:
        diff = event_diff(parse_events(SOURCE), parse_events(SOURCE), inject_paths=[])
        sc = score_tetragon(
            diff=diff,
            health=_health(
                injected=False,
                restored=False,
                reachable=False,
                readyz=True,
                nodes_ready=True,
            ),
        )
        t = sc["terms"]
        self.assertEqual(t["contained"], 0.0)
        self.assertEqual(t["liveness"], 0.0)
        self.assertEqual(t["workload_ready"], 0.0)
        self.assertEqual(t["source_intact"], 1.0)
        self.assertEqual(t["restored"], 0.0)
        self.assertLess(sc["reward"], 1.0)


class TestInjectPod(unittest.TestCase):
    def test_body_pins_busybox_to_agent(self) -> None:
        body = json.loads(inject_pod_body("k7-kill-member-0", "/tmp/k7d-tetra-x"))
        self.assertEqual(body["spec"]["nodeName"], INJECT_NODE)
        ctr = body["spec"]["containers"][0]
        self.assertEqual(ctr["image"], BUSYBOX)
        self.assertEqual(ctr["imagePullPolicy"], "IfNotPresent")
        self.assertIn("/tmp/k7d-tetra-x", ctr["args"][0])

    def test_body_can_touch_extra_paths(self) -> None:
        body = json.loads(
            inject_pod_body(
                "k7-tetra-churn",
                "/tmp/k7d-tetra-churn-0",
                extra=("/tmp/k7d-tetra-churn-1",),
            )
        )
        self.assertIn(
            "touch /tmp/k7d-tetra-churn-0 /tmp/k7d-tetra-churn-1",
            body["spec"]["containers"][0]["args"][0],
        )


class TestCollectRetry(unittest.TestCase):
    def test_empty_pod_list_body_is_loud(self) -> None:
        from tetragon import _tetragon_pod_names_once

        def _empty(*_a, **_k):
            return 7, "", "Failed to connect"

        with mock.patch("tetragon.curl_api", _empty):
            with self.assertRaises(TetragonProbeError) as ctx:
                _tetragon_pod_names_once(
                    "k7-br-x", cert=None, key=None, guest_ip="10.200.0.2", timeout_s=1
                )
        msg = str(ctx.exception)
        self.assertTrue("empty body" in msg or "Failed to connect" in msg, msg)

    def test_empty_log_body_is_not_a_chunk(self) -> None:
        from tetragon import collect_events

        def _ok_empty(*_a, **_k):
            return 200, "", ""

        with (
            mock.patch("tetragon.tetragon_pod_names", return_value=["tetra-0"]),
            mock.patch("tetragon.curl_api", _ok_empty),
        ):
            with self.assertRaises(TetragonProbeError) as ctx:
                collect_events("k7-br-x", cert=None, key=None)
        self.assertTrue(
            "empty" in str(ctx.exception).lower()
            or "logs empty" in str(ctx.exception),
            ctx.exception,
        )


class TestScoreboardConfig(unittest.TestCase):
    def test_tetragon_scoreboard_refuses_busybox_modes(self) -> None:
        import server

        for mode in ("create", "adopt"):
            ns = server.parse_args(
                ["--source-mode", mode, "--scoreboard", "tetragon"]
            )
            with self.assertRaises(SystemExit) as ctx:
                server.Config(ns)
            self.assertIn("tetragon", str(ctx.exception))
            self.assertIn("ubuntu", str(ctx.exception))

    def test_unknown_scoreboard_is_loud(self) -> None:
        import server

        ns = server.parse_args(["--scoreboard", "health"])
        ns.scoreboard = "batfish"
        with self.assertRaises(SystemExit) as ctx:
            server.Config(ns)
        self.assertIn("health|tetragon|playbook|incident", str(ctx.exception))


class TestCurlAndProbe(unittest.TestCase):
    def test_curl_api_maps_http_code_000_to_599(self) -> None:
        import scoring

        class _R:
            returncode = 7
            stdout = "\n000"
            stderr = "Failed to connect"

        with patch.object(scoring, "run", return_value=_R()):
            code, body, err = scoring.curl_api("k7-br-dead", "/api/v1/pods")
        self.assertEqual(code, 599)
        self.assertEqual(body, "")
        self.assertTrue(err)

    def test_empty_pod_list_body_is_probe_error(self) -> None:
        with patch("tetragon.curl_api", return_value=(599, "", "connect")):
            with self.assertRaises(TetragonProbeError) as ctx:
                tetragon_pod_names(
                    "k7-br-x", cert=None, key=None, retries=1, retry_s=0
                )
        self.assertIn("HTTP 599", str(ctx.exception))

        with patch("tetragon.curl_api", return_value=(200, "", "")):
            with self.assertRaises(TetragonProbeError):
                tetragon_pod_names(
                    "k7-br-x", cert=None, key=None, retries=1, retry_s=0
                )

    def test_api_up_no_tetragon_pods_stays_runtime_error(self) -> None:
        body = json.dumps({"items": []})
        with patch("tetragon.curl_api", return_value=(200, body, "")):
            with self.assertRaises(RuntimeError) as ctx:
                tetragon_pod_names(
                    "k7-br-x", cert=None, key=None, retries=1, retry_s=0
                )
        self.assertNotIsInstance(ctx.exception, TetragonProbeError)
        self.assertIn("no tetragon pods", str(ctx.exception))

    def test_collect_events_empty_logs_are_probe_error(self) -> None:
        with patch(
            "tetragon.tetragon_pod_names", return_value=["tetragon-abc"]
        ), patch("tetragon.curl_api", return_value=(599, "", "connect")):
            with self.assertRaises(TetragonProbeError) as ctx:
                collect_events("k7-br-x", cert=None, key=None)
        self.assertIn("logs empty", str(ctx.exception))


class TestEnsureTetragon(unittest.TestCase):
    def test_helm_missing_is_loud(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            kube = Path(td) / "kubeconfig"
            kube.write_text("apiVersion: v1\n")
            with patch.dict(os.environ, {"HELM": str(Path(td) / "no-helm")}):
                with self.assertRaises(RuntimeError) as ctx:
                    ensure_tetragon(kube)
        self.assertIn("helm", str(ctx.exception).lower())

    def test_already_installed_skips_helm(self) -> None:
        calls: list[list[str]] = []

        def _run(cmd, **_kw):
            calls.append(list(cmd))
            joined = " ".join(cmd)
            if "jsonpath={.status.numberReady}" in joined:
                return subprocess.CompletedProcess(cmd, 0, "3", "")
            if "jsonpath={.status.readyReplicas}" in joined:
                return subprocess.CompletedProcess(cmd, 0, "1", "")
            if "get" in cmd and "ds" in cmd:
                return subprocess.CompletedProcess(cmd, 0, "tetragon\n", "")
            raise AssertionError(f"unexpected subprocess: {cmd}")

        with tempfile.TemporaryDirectory() as td:
            kube = Path(td) / "kubeconfig"
            kube.write_text("apiVersion: v1\n")
            helm = Path(td) / "helm"
            helm.write_text("#!/bin/true\n")
            helm.chmod(0o755)
            with patch.dict(os.environ, {"HELM": str(helm)}):
                with patch("tetragon.subprocess.run", side_effect=_run):
                    ensure_tetragon(kube, ceiling_s=5)
        self.assertTrue(any("numberReady" in " ".join(c) for c in calls))
        self.assertFalse(any(c and "install" in c for c in calls))

    def test_chart_images_include_export_stdout_sidecar(self) -> None:
        self.assertIn("quay.io/cilium/tetragon:v1.7.0", TETRAGON_IMAGES)
        self.assertIn("quay.io/cilium/tetragon-operator:v1.7.0", TETRAGON_IMAGES)
        self.assertIn("quay.io/cilium/hubble-export-stdout:v1.1.1", TETRAGON_IMAGES)

    def test_ctr_pull_is_loud_on_failure(self) -> None:
        class _Agent:
            @staticmethod
            def exec_cmd(cid, args, timeout_s=180):
                return {"exit_code": 1, "stderr": "429 Too Many Requests", "stdout": ""}

        with patch("agent.exec_cmd", _Agent.exec_cmd), patch("tetragon.time.sleep"):
            with self.assertRaises(RuntimeError) as ctx:
                pull_tetragon_images([3], images=["quay.io/cilium/tetragon:v1.7.0"])
        self.assertIn("429", str(ctx.exception))
        self.assertIn("cid=3", str(ctx.exception))

    def test_ctr_pull_retries_then_ok(self) -> None:
        hits = {"n": 0}

        def _exec(cid, args, timeout_s=180):
            hits["n"] += 1
            if hits["n"] < 2:
                return {"exit_code": 1, "stderr": "toomanyrequests", "stdout": ""}
            return {"exit_code": 0, "stderr": "", "stdout": "done"}

        with patch("agent.exec_cmd", _exec), patch("tetragon.time.sleep"):
            pull_tetragon_images([7], images=["quay.io/cilium/tetragon:v1.7.0"])
        self.assertGreaterEqual(hits["n"], 2)

    def test_agents_import_instead_of_quay_pull(self) -> None:
        pulls: list[int] = []
        exported: list[int] = []

        def _exec(cid, args, timeout_s=180):
            if args[:5] == ["k3s", "ctr", "-n", "k8s.io", "images"] and args[5] == "pull":
                pulls.append(cid)
                return {"exit_code": 0, "stderr": "", "stdout": "ok"}
            if args[:5] == ["k3s", "ctr", "-n", "k8s.io", "images"] and args[5] == "export":
                exported.append(cid)
                return {"exit_code": 0, "stderr": "", "stdout": ""}
            if args[:2] == ["rm", "-f"]:
                return {"exit_code": 0, "stderr": "", "stdout": ""}
            raise AssertionError(f"unexpected exec {cid} {args}")

        with patch("agent.exec_cmd", _exec), patch(
            "tetragon.distribute_image_tar"
        ) as dist:
            pull_tetragon_images(
                [10, 11, 12], images=["quay.io/cilium/tetragon:v1.7.0"]
            )
        self.assertEqual(pulls, [10])
        self.assertEqual(exported, [10])
        dist.assert_called_once()
        self.assertEqual(dist.call_args[0][0], 10)
        self.assertEqual(dist.call_args[0][1], [11, 12])

    def test_distribute_relays_tar_over_localhost(self) -> None:
        payload = b"k7-tetragon-fake-tar"
        imported: dict[int, bytes] = {}

        def _exec(cid, args, timeout_s=180):
            joined = " ".join(args)
            if "/dev/tcp/" in joined:
                _, rest = joined.split("/dev/tcp/", 1)
                host, port_s = rest.strip().split("/", 1)
                sock = socket.create_connection((host, int(port_s)), 5)
                sock.sendall(payload)
                sock.close()
                return {"exit_code": 0, "stderr": "", "stdout": ""}
            if "images import" in joined:
                dest = "/tmp/k7-tetragon-images.tar"
                # args[-1] is the guest sh -c script; run only the curl.
                curl = args[-1].split(" && ")[0]
                r = subprocess.run(
                    ["sh", "-c", curl],
                    check=False,
                    capture_output=True,
                    text=True,
                )
                if r.returncode != 0:
                    return {
                        "exit_code": r.returncode,
                        "stderr": r.stderr,
                        "stdout": r.stdout,
                    }
                imported[cid] = Path(dest).read_bytes()
                Path(dest).unlink(missing_ok=True)
                return {"exit_code": 0, "stderr": "", "stdout": ""}
            raise AssertionError(f"unexpected exec {cid} {args}")

        with patch("agent.exec_cmd", _exec):
            distribute_image_tar(
                10, [11, 12], "/tmp/k7-tetragon-images.tar", host_ip="127.0.0.1"
            )
        self.assertEqual(imported, {11: payload, 12: payload})

    def test_cids_pull_and_delete_when_already_installed(self) -> None:
        calls: list[list[str]] = []

        def _run(cmd, **_kw):
            calls.append(list(cmd))
            joined = " ".join(cmd)
            if "jsonpath={.status.numberReady}" in joined:
                return subprocess.CompletedProcess(cmd, 0, "3", "")
            if "jsonpath={.status.readyReplicas}" in joined:
                return subprocess.CompletedProcess(cmd, 0, "1", "")
            if "delete" in cmd and "pods" in cmd:
                return subprocess.CompletedProcess(cmd, 0, "", "")
            if "get" in cmd and "ds" in cmd:
                return subprocess.CompletedProcess(cmd, 0, "tetragon\n", "")
            raise AssertionError(f"unexpected subprocess: {cmd}")

        with tempfile.TemporaryDirectory() as td:
            kube = Path(td) / "kubeconfig"
            kube.write_text("apiVersion: v1\n")
            helm = Path(td) / "helm"
            helm.write_text("#!/bin/true\n")
            helm.chmod(0o755)
            with patch.dict(os.environ, {"HELM": str(helm)}):
                with patch("tetragon.subprocess.run", side_effect=_run):
                    with patch("tetragon.pull_tetragon_images") as pull:
                        ensure_tetragon(
                            kube, cids=[4, 5, 6], bridge="k7-br-x", ceiling_s=5
                        )
        pull.assert_called_once_with([4, 5, 6], bridge="k7-br-x")
        self.assertTrue(any("delete" in c for c in calls))
        self.assertFalse(any(c and "install" in c for c in calls))


class TestBringUpAndScoreContract(unittest.TestCase):
    def test_bring_up_helms_tetragon_before_adopt(self) -> None:
        import server

        src = inspect.getsource(server.Gym._bring_up_ubuntu_cluster)
        # cni=none: install Cilium+Tetragon on the guest bridge, then
        # Ready-wait on that bridge — not host kubectl / ensure_tetragon.
        self.assertLess(
            src.index("wait_nodes_present_on_bridge"),
            src.index("install_cilium_tetragon"),
        )
        self.assertLess(
            src.index("install_cilium_tetragon"),
            src.index("wait_nodes_ready_on_bridge"),
        )
        self.assertLess(
            src.index("wait_nodes_ready_on_bridge"),
            src.index("tree_adopt_cluster"),
        )
        self.assertNotIn("ensure_tetragon(", src)

    def test_reset_collects_baseline_after_bring_up(self) -> None:
        import server

        src = inspect.getsource(server.Gym._reset_one_env)
        self.assertLess(
            src.index("_bring_up_ubuntu_cluster"), src.index("collect_events")
        )

    def test_kill_member_0_probe_error_scores_row(self) -> None:
        import server
        from faults import get
        from lease import Env, Lease

        ns = server.parse_args(
            [
                "--source-mode",
                "ubuntu",
                "--start-mode",
                "fork",
                "--scoreboard",
                "tetragon",
                "--memory-mb",
                "2048",
            ]
        )
        gym = server.Gym(server.Config(ns))
        gym.source_bridge = "k7-br-src"
        gym.source_cids = [3, 4, 5]
        with tempfile.TemporaryDirectory() as td:
            cert = Path(td) / "client.pem"
            key = Path(td) / "client-key.pem"
            cert.write_text("cert")
            key.write_text("key")
            gym.ubuntu_cert, gym.ubuntu_key = cert, key
            envs = [
                Env(
                    env_id="lease-x-0",
                    branch_node_id="n0",
                    index=0,
                    bridge="k7-br-dead",
                    guest_ips=["10.200.0.2"],
                    guest_cids=[10],
                    cert_path=str(cert),
                    key_path=str(key),
                ),
                Env(
                    env_id="lease-x-1",
                    branch_node_id="n1",
                    index=1,
                    bridge="k7-br-ok",
                    guest_ips=["10.200.0.2"],
                    guest_cids=[11],
                    cert_path=str(cert),
                    key_path=str(key),
                ),
            ]
            L = Lease(
                lease_id="lease-x",
                node_id="test",
                group_id="g",
                fault_id="kill-member-0",
                tree_id="gym-src-t",
                source_node_id="root",
                n=2,
                created_at=0.0,
                expires_at=9e9,
                envs=envs,
            )
            fault = get("kill-member-0")
            fault.source_mode = "ubuntu"
            fault.source_shows_fault = lambda **_kw: False  # type: ignore[method-assign]
            fault.healthy = lambda _env: False  # type: ignore[method-assign]

            def _collect(bridge: str, **_kw: object) -> str:
                if bridge == "k7-br-dead":
                    raise TetragonProbeError("api down")
                return SOURCE

            with patch("server.collect_events", side_effect=_collect), patch(
                "server.curl_readyz", return_value=True
            ), patch("server.curl_nodes_ready", return_value=True):
                out = gym._score_tetragon(L, fault, source_alive=True)

        self.assertEqual(len(out["scores"]), 2)
        dead, live = out["scores"]
        self.assertEqual(dead["env_id"], "lease-x-0")
        self.assertEqual(dead["terms"]["contained"], 0.0)
        self.assertEqual(dead["terms"]["liveness"], 0.0)
        self.assertEqual(dead["terms"]["workload_ready"], 0.0)
        self.assertLess(dead["reward"], 1.0)
        self.assertEqual(live["env_id"], "lease-x-1")
        self.assertEqual(live["terms"]["liveness"], 1.0)
        self.assertIn("reward", live)


if __name__ == "__main__":
    unittest.main()
