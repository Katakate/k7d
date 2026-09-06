"""Red as a gym agent — a granted foothold, living off the land (26a-inc11).

Red plays through the **same** act surface blue uses (`gym/server.py`
`act`: exec / kubectl), but from a *defined foothold*, never the gym's
admin certs:

- kubectl acts go out as a ServiceAccount **bearer token**
  (`scoring.curl_api(token=...)`), so red can only do what its
  (possibly over-broad, on purpose) Role/RoleBinding grants.
- exec acts run in a **jailed node-exec** context on one granted node,
  and only when the foothold was granted `node_exec`.

Bounds are enforced *structurally*, not by an enum of allowed moves
(26a-inc9 §Curriculum): (1) the foothold has **no egress** to fetch
tooling (`assert_no_egress`, `assert_no_egress` is `assert_guest_egress`
inverted — CHALLENGES #150); (2) a microVM **escape is a bug, not a
win** (`assert_no_escape` fails the harvest loudly if red state leaks to
the host or outside the lease); (3) the reward is **method-agnostic**
(`red_R` in `soak.py` reads only `not soak_clean` + `payload_productive`,
never red's moves). The catalog (`examples/k7d-mcp/incidents.py`
relay/hydra/sleeper/lateral) is red's **seed distribution**, not its
ceiling — a scripted red replays an opening for CI; a learned red
composes its own persistence from the foothold.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Callable

from incidents_load import incidents_mod
from scoring import curl_api, kubectl_to_request

ExecFn = Callable[[int, list[str], float], dict[str, Any]]

# Off-allowlist probe target for the no-egress assertion. A foothold that
# can reach this has a weaponisation supply line it must not have.
EGRESS_PROBE_IP = "8.8.8.8"
# Actions that fetch external tooling — living-off-the-land red never
# needs them, and rewarding a red that downloads an exploit would be
# scoring offensive-security research (out of bounds, 26a-inc9).
_EGRESS_FETCH_TOKENS = (
    "crictl pull",
    "ctr image pull",
    "docker pull",
    "apt-get install",
    "apt install",
    "pip install",
    "pip3 install",
    "wget ",
    "curl http",
    "curl -o",
)


@dataclass(frozen=True)
class Foothold:
    """The privilege set red starts with. Deliberately narrow: a
    namespaced ServiceAccount plus, optionally, node-exec on one node.
    More privilege must come from a *real* misconfiguration red finds,
    never from a crash or the gym's admin creds."""

    namespace: str
    sa: str
    rbac: str  # Role + RoleBinding YAML granting `sa` in `namespace`
    node_exec: bool = False


@dataclass(frozen=True)
class Scenario:
    """One self-play matchup: which payload seeds red, which foothold red
    is granted, and which victim blue must keep Ready."""

    scenario_id: str
    incident_id: str  # seed opening in the catalog
    foothold: Foothold
    victim: str  # human label for the legitimate workload


def _relay_foothold() -> Foothold:
    ns = "default"
    sa = "deployer"
    rbac = f"""apiVersion: v1
kind: ServiceAccount
metadata:
  name: {sa}
  namespace: {ns}
---
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: {sa}
  namespace: {ns}
rules:
- apiGroups: ["apps"]
  resources: ["deployments"]
  verbs: ["get", "list", "create", "update", "patch", "delete"]
- apiGroups: [""]
  resources: ["pods"]
  verbs: ["get", "list", "delete"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: {sa}
  namespace: {ns}
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: Role
  name: {sa}
subjects:
- kind: ServiceAccount
  name: {sa}
  namespace: {ns}
"""
    return Foothold(namespace=ns, sa=sa, rbac=rbac, node_exec=True)


SCENARIOS: dict[str, Scenario] = {
    "relay-foothold": Scenario(
        scenario_id="relay-foothold",
        incident_id="relay",
        foothold=_relay_foothold(),
        victim="control-plane apiserver /readyz",
    ),
}


def get_scenario(scenario_id: str) -> Scenario:
    sc = SCENARIOS.get(scenario_id)
    if sc is None:
        raise ValueError(
            f"unknown selfplay scenario {scenario_id!r}; "
            f"known: {sorted(SCENARIOS)}"
        )
    return sc


def catalog_openings() -> dict[str, str]:
    """Seed red openings, as *examples* only. A scripted red may replay
    one; a learned red draws on them as few-shot context and invents its
    own persistence. This is red's seed distribution, never its ceiling.
    """
    inc = incidents_mod()
    return {name: type(obj).__name__ for name, obj in inc.CATALOG.items()}


def assert_no_admin_creds(body: dict[str, Any]) -> None:
    """Loud if a red act tries to borrow the gym's admin mTLS. Red acts
    only ever as its granted foothold (SA token / jailed node-exec)."""
    for k in ("cert", "key", "cert_path", "key_path", "admin", "use_admin"):
        if body.get(k):
            raise ValueError(
                f"red act tried to use admin creds ({k!r}); red acts only "
                "as its granted foothold"
            )


def refuse_egress_fetch(args: list[str]) -> None:
    """Loud if a red exec fetches external tooling. Living-off-the-land
    red abuses legitimate machinery already present; it never downloads
    an exploit (no weaponisation supply line, 26a-inc9 guardrail 2)."""
    joined = " ".join(args)
    for tok in _EGRESS_FETCH_TOKENS:
        if tok in joined:
            raise ValueError(
                f"red exec fetches external tooling ({tok!r}); the "
                "foothold has no egress supply line"
            )


def assert_no_egress(
    cids: list[int],
    *,
    exec_cmd: ExecFn,
    probe_ip: str = EGRESS_PROBE_IP,
) -> None:
    """`assert_guest_egress` inverted: red's foothold must NOT be able to
    reach the open internet. If an off-allowlist ping *succeeds*, red has
    a supply line to fetch tooling — a bug in the jail, loud."""
    if not cids:
        raise RuntimeError("assert_no_egress: no guest cids")
    for cid in cids:
        r = exec_cmd(
            cid, ["ping", "-c", "1", "-W", "3", probe_ip], 8.0
        )
        if r.get("exit_code") == 0:
            raise RuntimeError(
                f"red foothold cid={cid} reached {probe_ip}: the granted "
                "foothold has egress to fetch tooling (jail guardrail); "
                "this is a jail bug, not a red move"
            )


def assert_no_escape(
    *,
    host_before: dict[str, Any],
    host_after: dict[str, Any],
    lease_bridges: set[str],
    lease_taps: set[str],
) -> None:
    """Escape/residue check. Any host bridge/tap that appeared while red
    acted and is not owned by the lease is red state that leaked outside
    the microVM — an isolation regression to fix, never a score
    (26a-inc11 guardrail 2; the disposable microVM is the safety
    boundary)."""
    before_br = set(host_before.get("bridges") or [])
    after_br = set(host_after.get("bridges") or [])
    new_br = after_br - before_br - lease_bridges
    before_tap = set(host_before.get("taps") or [])
    after_tap = set(host_after.get("taps") or [])
    new_tap = after_tap - before_tap - lease_taps
    if new_br or new_tap:
        raise RuntimeError(
            "red state leaked outside the lease/microVM — isolation "
            f"finding, not a score: new bridges={sorted(new_br)} "
            f"new taps={sorted(new_tap)}"
        )


def mint_foothold_token(
    cid: int,
    foothold: Foothold,
    *,
    exec_cmd: ExecFn,
    duration: str = "24h",
    timeout_s: float = 40,
) -> str:
    """Apply the foothold's RBAC on the control-plane node and mint a
    ServiceAccount token. Red's kubectl acts go out as this bearer, never
    the admin certs."""
    script = (
        "cat >/tmp/k7-red-foothold.yaml <<'EOFRBAC'\n"
        f"{foothold.rbac}"
        "EOFRBAC\n"
        "k3s kubectl apply -f /tmp/k7-red-foothold.yaml"
    )
    r = exec_cmd(cid, ["sh", "-c", script], timeout_s)
    if r.get("exit_code") != 0:
        raise RuntimeError(f"red foothold RBAC apply failed: {r}"[:240])
    tok = exec_cmd(
        cid,
        [
            "k3s",
            "kubectl",
            "-n",
            foothold.namespace,
            "create",
            "token",
            foothold.sa,
            f"--duration={duration}",
        ],
        timeout_s,
    )
    if tok.get("exit_code") != 0:
        raise RuntimeError(f"red foothold token mint failed: {tok}"[:240])
    token = (tok.get("stdout") or "").strip()
    if not token:
        raise RuntimeError("red foothold token mint returned empty token")
    return token


class RedActor:
    """Executes red acts AS the granted foothold. kubectl → SA bearer;
    exec → jailed node-exec on the granted node. Loud on admin creds and
    on egress-fetch actions."""

    def __init__(
        self,
        *,
        bridge: str,
        guest_ip: str,
        node_cid: int,
        foothold: Foothold,
        token: str,
        exec_cmd: ExecFn,
    ) -> None:
        if not token:
            raise RuntimeError("RedActor needs a foothold token")
        self.bridge = bridge
        self.guest_ip = guest_ip
        self.node_cid = node_cid
        self.foothold = foothold
        self.token = token
        self._exec = exec_cmd

    def act(self, body: dict[str, Any], *, timeout_s: float = 10) -> dict[str, Any]:
        assert_no_admin_creds(body)
        action = body.get("action")
        args = body.get("args")
        if not isinstance(args, list) or not all(isinstance(a, str) for a in args):
            raise ValueError("red act args must be a list of strings")
        if action == "kubectl":
            method, path, req_body, ctype = kubectl_to_request(args)
            code, stdout, stderr = curl_api(
                self.bridge,
                path,
                guest_ip=self.guest_ip,
                method=method,
                timeout_s=timeout_s,
                token=self.token,
                body=req_body,
                content_type=ctype,
            )
            ok = 200 <= code < 300
            return {
                "ok": ok,
                "stdout": stdout,
                "stderr": stderr,
                "exit_code": 0 if ok else code,
                "as_foothold": self.foothold.sa,
            }
        if action == "exec":
            if not self.foothold.node_exec:
                raise RuntimeError(
                    "red foothold was not granted node_exec; refusing exec"
                )
            refuse_egress_fetch(args)
            r = self._exec(self.node_cid, args, timeout_s)
            return {
                "ok": r.get("exit_code") == 0,
                "stdout": r.get("stdout", ""),
                "stderr": r.get("stderr", ""),
                "exit_code": r.get("exit_code"),
                "as_foothold": f"node-exec:{self.node_cid}",
            }
        raise ValueError(
            f"red act unknown action {action!r} (kubectl | exec)"
        )


class ScriptedRed:
    """Frozen catalog red for CI and stage-1/stage-2 fixtures. Replays a
    chosen opening + its `plant_host` chain, then confirms it settled.
    Used as the frozen opponent when blue is on trial."""

    def __init__(self, opening: str = "relay") -> None:
        inc = incidents_mod()
        if opening not in inc.CATALOG:
            raise ValueError(
                f"scripted red opening {opening!r} not in catalog "
                f"{sorted(inc.CATALOG)}"
            )
        self.opening = opening
        self._incident = inc.CATALOG[opening]

    def plant(self, cids: list[int], *, exec_cmd: ExecFn) -> None:
        """Plant the opening's in-cluster payload + host persistence.

        Uses the catalog verbatim (no reimplementation that could drift):
        applies the Deployment via the control-plane node's kubectl, then
        `plant_host` for the systemd reseed chain.
        """
        if not cids:
            raise RuntimeError("scripted red plant: no guest cids")
        cid = int(cids[0])
        yaml = getattr(self._incident, "yaml", "")
        if not yaml:
            raise RuntimeError(
                f"scripted red opening {self.opening!r} has no yaml"
            )
        script = (
            "cat >/tmp/k7-red-open.yaml <<'EOFRED'\n"
            f"{yaml}"
            "EOFRED\n"
            "k3s kubectl apply -f /tmp/k7-red-open.yaml"
        )
        r = exec_cmd(cid, ["sh", "-c", script], 40.0)
        if r.get("exit_code") != 0:
            raise RuntimeError(f"scripted red apply failed: {r}"[:240])
        self._incident.plant_host(cids)
