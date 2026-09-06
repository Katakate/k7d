"""Cilium + Tetragon on an Ubuntu gym cluster (26a-inc5).

Install only when `GYM_SCOREBOARD=tetragon`. Health bring-up stays
flannel and does not pay Helm. Flags and pins match 25a-inc3/inc4
and `examples/k7d-mcp/cluster.py`. Helm stays a host tool.

Host kubectl/helm talk to https://10.200.0.2:6443. Pin a /32 via
the cluster bridge for the install window so a leftover TAP is not
the API (CHALLENGES #144).
"""

from __future__ import annotations

import logging
import subprocess
import time
from contextlib import contextmanager
from pathlib import Path
from typing import Iterator

log = logging.getLogger("gym.sensors")

HELM_VERSION = "v3.16.4"
HELM_BIN = Path(f"/usr/local/lib/k7d-helm/{HELM_VERSION}/helm")
CILIUM_CHART = "1.16.10"
TETRAGON_CHART = "1.7.0"
CILIUM_NS = "kube-system"
NATIVE_CIDR = "10.244.0.0/16"
HELM_READY_S = 600
API_IP = "10.200.0.2"

KPROBE_POLICY = "k7d-kprobe-fd-install"
KPROBE_MESSAGE = "k7d-kprobe-fd-install"
PATH_PREFIX = "/tmp/k7d-tetra-"
# Same pin as crates/k7d/tests/test_ubuntu_tetragon.rs (10.200.0.3).
BUSYBOX = "docker.io/library/busybox:1.36.1"
INJECT_NODE = "k7d-10-200-0-3"
SRC_PROBE = "tetra-src-probe"
SRC_PROBE_PATH = f"{PATH_PREFIX}src-probe"


def ensure_helm() -> Path:
    if HELM_BIN.is_file():
        return HELM_BIN
    raise RuntimeError(
        f"pinned helm {HELM_VERSION} missing at {HELM_BIN} "
        "(run `make helm-pin`). "
        "GYM_SCOREBOARD=tetragon will not guess another helm."
    )


@contextmanager
def pin_api_route(bridge: str, ip: str = API_IP) -> Iterator[None]:
    """Send host traffic for `ip` out `bridge` only."""
    if not Path(f"/sys/class/net/{bridge}").is_dir():
        raise RuntimeError(f"pin_api_route: no such bridge {bridge}")
    dest = f"{ip}/32"
    r = subprocess.run(
        ["ip", "route", "replace", dest, "dev", bridge],
        check=False,
        capture_output=True,
        text=True,
    )
    if r.returncode != 0:
        raise RuntimeError(
            f"ip route replace {dest} dev {bridge}: {r.stderr or r.stdout}"
        )
    try:
        yield
    finally:
        subprocess.run(
            ["ip", "route", "del", dest, "dev", bridge],
            check=False,
            capture_output=True,
        )


def kubectl(kube: Path, args: list[str], *, timeout_s: float = 60) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["kubectl", "--kubeconfig", str(kube), *args],
        check=False,
        capture_output=True,
        text=True,
        timeout=timeout_s,
    )


def helm_install_cilium(helm: Path, kube: Path, server_ip: str) -> None:
    ns = kubectl(kube, ["get", "ns", CILIUM_NS, "-o", "jsonpath={.metadata.name}"])
    if (ns.stdout or "").strip() != CILIUM_NS:
        raise RuntimeError(f"kube-system missing before cilium helm: {ns.stderr}")
    already = kubectl(kube, ["-n", CILIUM_NS, "get", "ds", "cilium"])
    if already.returncode == 0:
        log.info("cilium already installed; skipping helm")
        return
    r = subprocess.run(
        [
            str(helm),
            "install",
            "cilium",
            "cilium",
            "--version",
            CILIUM_CHART,
            "--repo",
            "https://helm.cilium.io/",
            "--namespace",
            CILIUM_NS,
            "--kubeconfig",
            str(kube),
            "--set",
            "operator.replicas=1",
            "--set",
            "routingMode=native",
            "--set",
            f"ipv4NativeRoutingCIDR={NATIVE_CIDR}",
            "--set",
            "autoDirectNodeRoutes=true",
            "--set",
            "kubeProxyReplacement=true",
            "--set",
            "endpointRoutes.enabled=true",
            "--set",
            "bpf.hostLegacyRouting=true",
            "--set",
            "l2NeighDiscovery.enabled=false",
            "--set",
            "ipam.mode=kubernetes",
            "--set",
            "k8s.requireIPv4PodCIDR=true",
            "--set",
            f"k8sServiceHost={server_ip}",
            "--set",
            "k8sServicePort=6443",
        ],
        check=False,
        capture_output=True,
        text=True,
    )
    if r.returncode != 0:
        raise RuntimeError(
            f"helm install cilium {CILIUM_CHART} failed:\n{r.stderr}\n{r.stdout}"
        )
    log.info("helm: installed cilium %s", CILIUM_CHART)


def helm_install_tetragon(helm: Path, kube: Path) -> None:
    already = kubectl(kube, ["-n", CILIUM_NS, "get", "ds", "tetragon"])
    if already.returncode == 0:
        log.info("tetragon already installed; skipping helm")
        return
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
            CILIUM_NS,
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
    )
    if r.returncode != 0:
        raise RuntimeError(
            f"helm install tetragon {TETRAGON_CHART} failed:\n{r.stderr}\n{r.stdout}"
        )
    log.info("helm: installed tetragon %s", TETRAGON_CHART)


def _wait_field(
    kube: Path, kind: str, name: str, field: str, want: int, ceiling_s: float
) -> None:
    deadline = time.monotonic() + ceiling_s
    last = ""
    while time.monotonic() < deadline:
        r = kubectl(
            kube,
            ["-n", CILIUM_NS, "get", kind, name, f"-o=jsonpath={{.status.{field}}}"],
        )
        last = (r.stdout or "").strip()
        try:
            got = int(last)
        except ValueError:
            got = 0
        if got >= want:
            log.info("%s Ready %s=%s", name, field, got)
            return
        time.sleep(5)
    pods = kubectl(kube, ["-n", CILIUM_NS, "get", "pods", "-o", "wide"])
    raise RuntimeError(
        f"{name} never Ready ({field}={last!r} want>={want}) after {ceiling_s}s\n"
        f"{pods.stdout}\n{pods.stderr}"
    )


def kprobe_policy_yaml() -> str:
    return f"""apiVersion: cilium.io/v1alpha1
kind: TracingPolicy
metadata:
  name: {KPROBE_POLICY}
spec:
  kprobes:
  - call: "fd_install"
    syscall: false
    message: "{KPROBE_MESSAGE}"
    args:
    - index: 0
      type: "int"
    - index: 1
      type: "file"
    selectors:
    - matchArgs:
      - index: 1
        operator: "Prefix"
        values:
        - "{PATH_PREFIX}"
"""


def apply_tracing_policies(kube: Path) -> None:
    deadline = time.monotonic() + 60
    last = ""
    while time.monotonic() < deadline:
        r = kubectl(kube, ["get", "crd", "tracingpolicies.cilium.io"])
        if r.returncode == 0:
            break
        last = r.stderr or r.stdout
        time.sleep(2)
    else:
        raise RuntimeError(f"TracingPolicy CRD never appeared: {last}")
    r = subprocess.run(
        ["kubectl", "--kubeconfig", str(kube), "apply", "-f", "-"],
        input=kprobe_policy_yaml(),
        check=False,
        capture_output=True,
        text=True,
    )
    if r.returncode != 0:
        raise RuntimeError(f"TracingPolicy apply failed: {r.stderr}\n{r.stdout}")
    tps = kubectl(kube, ["get", "tracingpolicies"])
    if KPROBE_POLICY not in (tps.stdout or ""):
        raise RuntimeError(f"kprobe TracingPolicy missing:\n{tps.stdout}\n{tps.stderr}")
    log.info("TracingPolicies:\n%s", tps.stdout)
    time.sleep(5)


def inject_pod_yaml(name: str, path: str, node: str = INJECT_NODE) -> str:
    return f"""apiVersion: v1
kind: Pod
metadata:
  name: {name}
spec:
  nodeName: {node}
  restartPolicy: Never
  containers:
  - name: inject
    image: {BUSYBOX}
    imagePullPolicy: IfNotPresent
    command: ["/bin/sh", "-c"]
    args: ["touch {path}; echo TETRA_OK"]
"""


def pull_inject_image(kube: Path, ceiling_s: float = 360) -> None:
    """Pre-pull busybox on the inject node so a child IfNotPresent hits.

    25a-inc4: a host `touch` is invisible to Tetragon; the kprobe fires
    on a pinned busybox pod. Pulling here also seeds the source stream.
    """
    phase = kubectl(
        kube, ["get", "pod", SRC_PROBE, "-o", "jsonpath={.status.phase}"]
    )
    if (phase.stdout or "").strip() == "Succeeded":
        log.info("inject image already pulled (%s Succeeded)", SRC_PROBE)
        return
    if phase.returncode == 0:
        kubectl(kube, ["delete", "pod", SRC_PROBE, "--wait=false"])
    r = subprocess.run(
        ["kubectl", "--kubeconfig", str(kube), "apply", "-f", "-"],
        input=inject_pod_yaml(SRC_PROBE, SRC_PROBE_PATH),
        check=False,
        capture_output=True,
        text=True,
    )
    if r.returncode != 0:
        raise RuntimeError(f"src-probe apply failed: {r.stderr}\n{r.stdout}")
    deadline = time.monotonic() + ceiling_s
    last = ""
    while time.monotonic() < deadline:
        got = kubectl(
            kube, ["get", "pod", SRC_PROBE, "-o", "jsonpath={.status.phase}"]
        )
        last = (got.stdout or "").strip()
        if last == "Succeeded":
            log.info("inject image pulled (%s Succeeded)", SRC_PROBE)
            return
        if last == "Failed":
            logs = kubectl(kube, ["logs", SRC_PROBE])
            raise RuntimeError(
                f"{SRC_PROBE} Failed:\n{logs.stdout}\n{logs.stderr}"
            )
        time.sleep(2)
    desc = kubectl(kube, ["describe", "pod", SRC_PROBE])
    raise RuntimeError(
        f"{SRC_PROBE} never Succeeded (phase={last!r}) after {ceiling_s}s\n"
        f"{desc.stdout}\n{desc.stderr}"
    )


def install_cilium_tetragon(bridge: str, kube: Path, server_ip: str) -> None:
    """Cilium 1.16.10 + Tetragon 1.7.0 + 25a-inc4 kprobe policy."""
    helm = ensure_helm()
    with pin_api_route(bridge):
        helm_install_cilium(helm, kube, server_ip)
        _wait_field(kube, "ds", "cilium", "numberReady", 3, HELM_READY_S)
        _wait_field(kube, "deploy", "cilium-operator", "readyReplicas", 1, HELM_READY_S)
        helm_install_tetragon(helm, kube)
        _wait_field(kube, "ds", "tetragon", "numberReady", 3, HELM_READY_S)
        _wait_field(
            kube, "deploy", "tetragon-operator", "readyReplicas", 1, HELM_READY_S
        )
        apply_tracing_policies(kube)
        pull_inject_image(kube)
