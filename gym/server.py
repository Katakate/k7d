#!/usr/bin/env python3
"""Per-node gym HTTP service. Python stdlib + the shared k7d_client.

Dependency direction: this file imports `k7d_client` from
`examples/cluster-tree-search/` (sys.path insert below). The demo does
not import gym. Do not vendor a second client.
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
from concurrent.futures import ThreadPoolExecutor, as_completed
from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, Iterator
from urllib.parse import urlparse

HERE = Path(__file__).resolve().parent
REPO = HERE.parent
# gym → examples/cluster-tree-search/k7d_client.py (see module docstring).
sys.path.insert(0, str(REPO / "examples" / "cluster-tree-search"))

from k7d_client import K7dClient  # noqa: E402

AUTOWARP_MODES = ("off", "jump", "micro", "dilate")
# Pinned CreateVm factor. Adaptive N is out of scope.
DILATION_FACTOR = 8
AUTOWARP_MODE_HELP = "off|jump|micro|dilate"
DILATE_REQUIRES = (
    "autowarp_mode=dilate requires GYM_SOURCE_MODE=ubuntu "
    "(busybox is out of scope)"
)
import agent  # noqa: E402
from budget import lease_need, reset_need, tree_budget  # noqa: E402
from host import (  # noqa: E402
    free_ram_bytes,
    guest_ips,
    k7_bridge_name,
    list_bridges,
    list_taps,
    residue as residue_dict,
)
from faults import SCRIPTED_ID  # noqa: E402
from faults import get as get_fault  # noqa: E402
from faults import get_scenario, require_grpo_fault, set_scenario_root  # noqa: E402
from lease import Env, Lease, LeaseTable, new_env_id, new_lease_id  # noqa: E402
from scoring import (  # noqa: E402
    curl_api,
    curl_inner_load,
    curl_nodes_ready,
    curl_readyz,
    kubectl_to_request,
    reward_from_terms,
    score_adopt_env,
    score_create_env,
    terms,
)
import ubuntu as ubuntu_src  # noqa: E402
from tetragon import (  # noqa: E402
    ClusterHealth,
    TetragonProbeError,
    collect_events,
    event_diff,
    parse_events,
    score_tetragon,
)
from playbook import (  # noqa: E402
    Ctx as PlaybookCtx,
    PageResult,
    diagnostic_terms,
    refuse_inject_fault,
    run_page,
    score_from_results,
)
from soak import (  # noqa: E402
    T_BUDGET_S,
    require_incident_fault,
    require_selfplay_role,
    reward_from_solve,
    signed_reward,
    soak_clean,
    first_fail_reason,
    idle_red_skips_hold,
    layer_gates,
)
import red as red_agent  # noqa: E402

log = logging.getLogger("gym")

INNER3_PODS = (
    "test-inner-k3s-3n-server",
    "test-inner-k3s-3n-agent-0",
    "test-inner-k3s-3n-agent-1",
)
INNER3_CERTS = Path("/tmp/k7-gym-inner3-certs")
SOURCE_PREFIX = "gym-src-"
LEASE_LABEL_PREFIX = "gym-br"


class Config:
    def __init__(self, ns: argparse.Namespace) -> None:
        self.bind = ns.bind
        self.port = ns.port
        self.node_id = ns.node_id
        self.source_mode = ns.source_mode
        if self.source_mode not in ("create", "adopt", "ubuntu"):
            raise SystemExit(
                f"GYM_SOURCE_MODE must be create|adopt|ubuntu, got {self.source_mode!r}"
            )
        self.start_mode = ns.start_mode
        if self.start_mode not in ("fork", "reset"):
            raise SystemExit(
                f"GYM_START_MODE must be fork|reset, got {self.start_mode!r}"
            )
        self.reset_measurement = bool(ns.reset_measurement)
        self.scoreboard = ns.scoreboard
        if self.scoreboard not in (
            "health",
            "tetragon",
            "playbook",
            "incident",
            "selfplay",
            "grpo",
        ):
            raise SystemExit(
                f"GYM_SCOREBOARD must be health|tetragon|playbook|incident|"
                f"selfplay|grpo, got {self.scoreboard!r}"
            )
        if self.scoreboard == "tetragon" and self.source_mode != "ubuntu":
            raise SystemExit(
                f"GYM_SCOREBOARD=tetragon requires GYM_SOURCE_MODE=ubuntu "
                f"(got {self.source_mode!r}); the trainer never parses Tetragon"
            )
        if self.scoreboard == "playbook" and self.source_mode != "ubuntu":
            raise SystemExit(
                f"GYM_SCOREBOARD=playbook requires GYM_SOURCE_MODE=ubuntu "
                f"(got {self.source_mode!r})"
            )
        if self.scoreboard == "incident" and self.source_mode != "ubuntu":
            raise SystemExit(
                f"GYM_SCOREBOARD=incident requires GYM_SOURCE_MODE=ubuntu "
                f"(got {self.source_mode!r})"
            )
        if self.scoreboard == "selfplay" and self.source_mode != "ubuntu":
            raise SystemExit(
                f"GYM_SCOREBOARD=selfplay requires GYM_SOURCE_MODE=ubuntu "
                f"(got {self.source_mode!r})"
            )
        if self.scoreboard == "grpo" and self.source_mode != "ubuntu":
            raise SystemExit(
                f"GYM_SCOREBOARD=grpo requires GYM_SOURCE_MODE=ubuntu "
                f"(got {self.source_mode!r})"
            )
        raw_gate = str(getattr(ns, "ready_gate", "") or "")
        if self.scoreboard in ("playbook", "incident", "selfplay"):
            if raw_gate and raw_gate != "api":
                raise SystemExit(
                    f"GYM_SCOREBOARD={self.scoreboard} requires ready_gate=api "
                    f"(got {raw_gate!r}); do not wait CLUSTER_READY_S out"
                )
            self.ready_gate = "api"
        elif raw_gate:
            if raw_gate not in ("nodes", "api"):
                raise SystemExit(
                    f"GYM_READY_GATE must be nodes|api, got {raw_gate!r}"
                )
            self.ready_gate = raw_gate
        else:
            self.ready_gate = "nodes"
        if self.start_mode == "reset":
            if self.source_mode != "ubuntu":
                raise SystemExit(
                    f"GYM_START_MODE=reset requires GYM_SOURCE_MODE=ubuntu, "
                    f"got {self.source_mode!r}"
                )
            if not self.reset_measurement:
                raise SystemExit(
                    "GYM_START_MODE=reset is measurement-only; set "
                    "GYM_RESET_MEASUREMENT=1 (or --reset-measurement) to "
                    "acknowledge. Do not train on reset — fork-group std "
                    "is the training arm."
                )
        self.source_tree_id = ns.source_tree_id
        # Load the pack here so a bad scenario fails gym start with its
        # path, rather than the first lease that happens to name it.
        self.scenario_dir = str(getattr(ns, "scenario_dir", "") or "")
        if self.scenario_dir and self.scoreboard != "grpo":
            raise SystemExit(
                f"GYM_SCENARIO_DIR requires GYM_SCOREBOARD=grpo, got "
                f"{self.scoreboard!r}; scripted scenarios are grpo-only"
            )
        try:
            self.scenario_count = set_scenario_root(self.scenario_dir or None)
        except (OSError, ValueError) as err:
            raise SystemExit(f"GYM_SCENARIO_DIR={self.scenario_dir}: {err}") from err
        self.socket = ns.socket
        self.max_leases = ns.max_leases
        self.max_live_vms = ns.max_live_vms
        self.max_live_ram_bytes = ns.max_live_ram_bytes
        self.max_disk_bytes = ns.max_disk_bytes
        self.vm_count = ns.vm_count
        self.memory_mb = ns.memory_mb
        self.ttl_default_s = ns.ttl_default_s
        self.reaper_interval_s = ns.reaper_interval_s
        self.token = ns.token or None
        self.kernel = ns.kernel
        self.initrd = ns.initrd
        self.tree_prefix = ns.tree_prefix
        self.k7d_timeout_s = ns.k7d_timeout_s
        raw_warp = str(getattr(ns, "autowarp_mode", "off") or "off")
        if raw_warp not in AUTOWARP_MODES:
            raise SystemExit(
                f"GYM_AUTOWARP_MODE must be {AUTOWARP_MODE_HELP}, got {raw_warp!r}"
            )
        if raw_warp == "dilate" and self.source_mode != "ubuntu":
            raise SystemExit(DILATE_REQUIRES)
        self.autowarp_mode = raw_warp
        # Fork mode: the shared source is brought up at this factor and
        # every lease forks it as-is. Reset mode decides per lease.
        self.source_dilation: int | None = (
            DILATION_FACTOR
            if raw_warp == "dilate" and self.start_mode == "fork"
            else None
        )
        if self.source_mode == "ubuntu":
            floor = ubuntu_src.memory_floor_error(self.memory_mb)
            if floor:
                raise SystemExit(floor)
            budget = ubuntu_src.tree_budget_floor_error(
                vm_count=self.vm_count,
                memory_mb=self.memory_mb,
                max_live_vms=self.max_live_vms,
                max_live_ram_bytes=self.max_live_ram_bytes,
            )
            if budget:
                raise SystemExit(budget)


class _IncidentProbe:
    """API + Tetragon snapshot for one soak window. No host kubectl."""

    def __init__(self, env: Env, gym: "Gym") -> None:
        self.env = env
        self.gym = gym
        self.cert, self.key = gym._env_certs(env)
        ips = env.guest_ips
        self.ip = ips[0] if ips else "10.200.0.2"

    def miner_running(self) -> bool:
        from faults.relay import env_miner_running

        return env_miner_running(self.env)

    def victim_ready(self) -> bool:
        if self.cert is None or self.key is None:
            return False
        return curl_readyz(
            self.env.bridge, self.ip, cert=self.cert, key=self.key
        )

    def tetragon_events(self) -> list[Any]:
        if self.cert is None or self.key is None:
            raise TetragonProbeError(
                f"incident soak: certs missing on {self.env.env_id}"
            )
        raw = collect_events(
            self.env.bridge,
            cert=self.cert,
            key=self.key,
            guest_ip=self.ip,
        )
        return parse_events(raw)


# CPU% floor below which a Running payload counts as present-and-idle,
# not productive. The relay miner busy-loops sha256sum (~7% of one core
# over the window); a decoy that merely sleeps stays near 0. The floor
# sits between the two with margin on both sides.
PAYLOAD_CPU_MIN = 2.0
# Sampling window for the CPU-time delta. The relay miner forks a fresh
# `sha256sum` process each iteration, so instantaneous `ps %cpu` misses
# the short-lived children; the parent reaps them, so its
# utime+stime+cutime+cstime over a window captures the real burn.
PAYLOAD_SAMPLE_S = 4.0
_MINER_CPU_PROBE = r"""
read_j() {
  tot=0
  for p in $(pgrep -f /tmp/nodecheck 2>/dev/null); do
    st=$(cat /proc/$p/stat 2>/dev/null) || continue
    rest=${st#*) }
    set -- $rest
    tot=$((tot + ${12} + ${13} + ${14} + ${15}))
  done
  echo "$tot"
}
a=$(read_j); sleep %f; b=$(read_j)
echo "K7CPU $((b - a)) $(getconf CLK_TCK)"
"""


class _SelfplayProbe(_IncidentProbe):
    """Adds `payload_productive` — the red gate. Pure cluster state: the
    payload must be *doing real work* (miner burning CPU), never a policy
    self-report and never sensor silence."""

    def payload_productive(self) -> bool:
        if not self.miner_running():
            log.info("payload_productive: miner not running env=%s", self.env.env_id)
            return False
        cid = self.env.guest_cids[0] if self.env.guest_cids else None
        if cid is None:
            return False
        probe = _MINER_CPU_PROBE % PAYLOAD_SAMPLE_S
        try:
            r = agent.exec_cmd(
                cid,
                ["sh", "-c", probe],
                timeout_s=PAYLOAD_SAMPLE_S + 8,
            )
        except (OSError, RuntimeError):
            return False
        if r.get("exit_code") != 0:
            return False
        delta_jiffies = 0.0
        hz = 100.0
        for line in (r.get("stdout") or "").splitlines():
            parts = line.split()
            if len(parts) == 3 and parts[0] == "K7CPU":
                try:
                    delta_jiffies = float(parts[1])
                    hz = float(parts[2]) or 100.0
                except ValueError:
                    return False
        # CPU seconds the miner burned over the window, as a percentage
        # of one core. A busy sha256sum loop lands well above the floor;
        # a present-and-idle decoy accumulates ~0.
        cpu_pct = 100.0 * (delta_jiffies / hz) / PAYLOAD_SAMPLE_S
        log.info(
            "payload_productive: env=%s cpu_pct=%.1f (delta_jiffies=%.0f hz=%.0f)",
            self.env.env_id,
            cpu_pct,
            delta_jiffies,
            hz,
        )
        return cpu_pct >= PAYLOAD_CPU_MIN


class Gym:
    def __init__(self, cfg: Config) -> None:
        self.cfg = cfg
        self.client = K7dClient(cfg.socket, timeout=cfg.k7d_timeout_s)
        self.leases = LeaseTable(cfg.max_leases)
        self.source_node_id = "root"
        self.source_cids: list[int] = []
        self.source_bridge = ""
        self.source_vms = cfg.vm_count
        self.ubuntu_cert: Path | None = None
        self.ubuntu_key: Path | None = None
        self.ubuntu_disks: list[Path] = []
        self.mutate = threading.Lock()
        self._stop = threading.Event()
        self._reaper: threading.Thread | None = None

    # ----- k7d -----

    def k7d_ready(self) -> tuple[bool, str]:
        if not Path(self.cfg.socket).exists():
            return False, f"k7d socket absent: {self.cfg.socket}"
        try:
            pong = self.client.ping()
        except (OSError, RuntimeError) as e:
            return False, str(e)
        if pong.get("status") != "pong":
            return False, f"unexpected ping response: {pong}"
        return True, "ready"

    def _autowarp_mode_from_body(self, body: dict[str, Any]) -> str:
        if "autowarp_mode" not in body:
            return self.cfg.autowarp_mode
        raw = body["autowarp_mode"]
        if not isinstance(raw, str) or raw not in AUTOWARP_MODES:
            raise ValueError(
                f"autowarp_mode must be {AUTOWARP_MODE_HELP}, got {raw!r}"
            )
        if raw == "dilate" and self.cfg.source_mode != "ubuntu":
            raise ValueError(DILATE_REQUIRES)
        return raw

    def _lease_dilation(self, mode: str) -> int | None:
        if mode != "dilate":
            return None
        return DILATION_FACTOR

    def _fork_child_dilation(self, mode: str) -> int | None:
        """Child factor for tree_fork_batch, or None to inherit the source.

        Dilate on a ×1 source asks for 8; off/jump/micro on a ×8
        source asks for 1; matching the source passes nothing.
        """
        source = self.cfg.source_dilation or 1
        if mode == "dilate" and source != DILATION_FACTOR:
            return DILATION_FACTOR
        if mode != "dilate" and source == DILATION_FACTOR:
            return 1
        return None

    def _enable_autowarp(self, envs: list[Env], mode: str) -> None:
        if mode == "off":
            return
        if mode == "dilate":
            if self.cfg.source_mode != "ubuntu":
                raise RuntimeError(DILATE_REQUIRES)
            # Reset members were created at N; forks take the child
            # factor on tree_fork_batch. The tag is for exec/release.
            for e in envs:
                e.autowarp_mode = mode
            return
        seen: set[str] = set()
        for e in envs:
            e.autowarp_mode = mode
            cid = e.cluster_id
            if not cid or cid in seen:
                continue
            seen.add(cid)
            rec = self.client.auto_warp(cid, mode)
            got = rec.get("mode")
            if got != mode:
                raise RuntimeError(
                    f"auto_warp({cid!r}, {mode}): daemon returned mode={got!r}"
                )

    def _stop_autowarp(self, envs: list[Env]) -> list[dict[str, Any]]:
        seen: set[str] = set()
        stats: list[dict[str, Any]] = []
        for e in envs:
            cid = e.cluster_id
            if not cid or cid in seen or e.autowarp_mode == "off":
                continue
            seen.add(cid)
            if e.autowarp_mode == "dilate":
                stats.append(
                    {
                        "status": "auto_warp",
                        "cluster_id": cid,
                        "mode": "off",
                        "factor": DILATION_FACTOR,
                        "holders": [],
                        "stats": {},
                    }
                )
            else:
                try:
                    stats.append(self.client.auto_warp(cid, "off"))
                except RuntimeError as err:
                    log.warning("auto_warp off %s: %s", cid, err)
            e.autowarp_mode = "off"
        return stats

    @contextmanager
    def _hold_autowarp(self, env: Env, holder: str) -> Iterator[None]:
        cid = env.cluster_id
        if not cid or env.autowarp_mode in ("off", "dilate"):
            yield
            return
        tag = f"{holder}:{env.env_id}"
        self.client.auto_warp_hold(cid, tag, True)
        try:
            yield
        finally:
            try:
                self.client.auto_warp_hold(cid, tag, False)
            except RuntimeError as err:
                log.warning("auto_warp_hold release %s: %s", tag, err)

    def _env_by_cid(self, cid: int) -> Env | None:
        return self.leases.env_by_cid(cid)

    def tree_node_ids(self, tree_id: str) -> list[str]:
        try:
            resp = self.client.tree_nodes(tree_id)
        except RuntimeError as e:
            if "no such tree" in str(e):
                return []
            raise
        return [n["id"] for n in resp.get("nodes") or []]

    def snapshot(self) -> dict[str, Any]:
        return residue_dict(
            bridges=list_bridges(),
            taps=list_taps(),
            tree_node_ids=self.tree_node_ids(self.cfg.source_tree_id),
        )

    # ----- source -----

    def startup_sweep(self) -> None:
        """Reap gym-prefixed trees that are not the protected source."""
        try:
            listing = self.client.tree_list()
        except RuntimeError as e:
            log.warning("startup sweep: tree_list failed: %s", e)
            return
        for t in listing.get("trees") or []:
            tid = t.get("tree_id") or ""
            if not tid.startswith(self.cfg.tree_prefix):
                continue
            if tid == self.cfg.source_tree_id or tid.startswith(SOURCE_PREFIX):
                if self.cfg.start_mode == "reset":
                    # Reset does not reuse a fork source. Leaving it up
                    # owns 10.200.0.2 and Cilium on the fresh cluster
                    # never Ready (CHALLENGES #148).
                    log.warning("reset sweep: dropping leftover %s", tid)
                    self._drop_tree_loud(tid)
                    continue
                self._reap_stray_branches(tid)
                continue
            log.warning("startup sweep: dropping orphan gym tree %s", tid)
            self._drop_tree_loud(tid)
        swept = ubuntu_src.sweep_orphaned_gym_disks()
        if swept:
            log.warning("startup sweep: unlinked %s orphan ubuntu-gym-*.img", swept)

    def _reap_stray_branches(self, tree_id: str) -> None:
        try:
            nodes = self.client.tree_nodes(tree_id).get("nodes") or []
        except RuntimeError as e:
            log.warning("startup sweep: tree_nodes(%s): %s", tree_id, e)
            return
        for n in nodes:
            nid = n.get("id")
            if nid in (None, "root") or n.get("protected"):
                continue
            log.warning(
                "startup sweep: pruning stray node %s on %s", nid, tree_id
            )
            try:
                self.client.tree_prune(tree_id, nid)
            except RuntimeError as e:
                log.warning("startup sweep prune %s: %s", nid, e)

    def _drop_tree_loud(self, tree_id: str) -> None:
        try:
            nodes = self.client.tree_nodes(tree_id).get("nodes") or []
            ids = [n["id"] for n in nodes]
            if "root" in ids:
                self.client.tree_prune(tree_id, "root")
        except RuntimeError as e:
            log.warning("sweep prune %s: %s", tree_id, e)
        try:
            self.client.tree_drop(tree_id)
        except RuntimeError as e:
            log.warning("sweep drop %s: %s", tree_id, e)
        gone = ubuntu_src.remove_tree_disks(tree_id)
        if gone:
            log.info("unlinked %s disks for tree %s", gone, tree_id)

    def prepare_source(self) -> None:
        if self.cfg.start_mode == "reset":
            log.info(
                "GYM_START_MODE=reset: no shared source "
                "(fresh Ubuntu bring-up per group member)"
            )
            self.source_node_id = ""
            self.source_bridge = ""
            self.source_cids = []
            self.source_vms = 3
            self.cfg.vm_count = 3
            return
        existing = None
        try:
            existing = self.client.tree_nodes(self.cfg.source_tree_id)
        except RuntimeError:
            existing = None
        if existing and existing.get("nodes"):
            log.info(
                "reusing source tree %s (protect + prune strays)",
                self.cfg.source_tree_id,
            )
            self.source_node_id = "root"
            self.client.tree_protect(self.cfg.source_tree_id, "root")
            self._reap_stray_branches(self.cfg.source_tree_id)
            self._record_source_from_nodes(existing)
            return
        if self.cfg.source_mode == "create":
            self._create_source()
        elif self.cfg.source_mode == "adopt":
            self._adopt_source()
        else:
            self._ubuntu_source()
        self.client.tree_protect(self.cfg.source_tree_id, self.source_node_id)
        self._bring_source_eth0_up()
        log.info(
            "source ready mode=%s tree=%s root=%s bridge=%s cids=%s",
            self.cfg.source_mode,
            self.cfg.source_tree_id,
            self.source_node_id,
            self.source_bridge,
            self.source_cids,
        )

    def _bring_source_eth0_up(self) -> None:
        """Forks copy guest RAM. Partition needs eth0 UP on the checkpoint."""
        if not self.source_cids:
            log.warning("source has no CIDs; skipping eth0 up")
            return
        for cid in self.source_cids:
            r = agent.exec_cmd(
                cid, ["ip", "link", "set", "eth0", "up"], timeout_s=8
            )
            if r["exit_code"] != 0:
                raise RuntimeError(
                    f"source cid={cid} ip link set eth0 up failed: "
                    f"stderr={r['stderr']!r} stdout={r['stdout']!r}"
                )

    def _budget(self) -> dict[str, int]:
        return tree_budget(
            max_live_vms=self.cfg.max_live_vms,
            max_live_ram_bytes=self.cfg.max_live_ram_bytes,
            max_disk_bytes=self.cfg.max_disk_bytes,
        )

    def _create_source(self) -> None:
        kernel, initrd = self.cfg.kernel, self.cfg.initrd
        if not Path(kernel).is_file():
            raise SystemExit(f"guest kernel missing: {kernel}")
        if not Path(initrd).is_file():
            raise SystemExit(f"guest initrd missing: {initrd}")
        before = list_bridges()
        created = self.client.tree_create_cluster(
            self.cfg.vm_count,
            {
                "kernel": kernel,
                "initrd": initrd,
                "memory_mb": self.cfg.memory_mb,
                "vcpus": 1,
                "vsock": True,
            },
            tree_id=self.cfg.source_tree_id,
            budget=self._budget(),
        )
        self.source_node_id = created["root_id"]
        self.source_cids = [int(c) for c in created.get("guest_cids") or []]
        self.source_vms = self.cfg.vm_count
        self.source_bridge = self._new_bridge(before)

    def _bring_up_ubuntu_cluster(
        self,
        tree_id: str,
        *,
        ready_gate: str | None = None,
        dilation: int | None = None,
    ) -> dict[str, Any]:
        """CreateVm × 3 (Ubuntu bzImage + root disk) then adopt.

        Never `tree_create_cluster` (busybox) and never `k7-br-inner3`.
        `ready_gate=api` returns after /readyz (playbook exam). Default
        `nodes` waits CLUSTER_READY_S so health/tetragon stay unchanged.
        """
        manifest = ubuntu_src.build_or_cache_image(REPO)
        kernel = Path(str(manifest["kernel"]))
        base = Path(str(manifest["image"]))
        if kernel == Path(self.cfg.kernel) or "initramfs" in str(kernel):
            raise RuntimeError(
                f"ubuntu source refused busybox guest path {kernel} "
                "(CHALLENGES #72: never K7D_KERNEL/K7D_INITRD)"
            )
        server_ip = ubuntu_src.guest_ip(0)
        created_ids: list[str] = []
        disks: list[Path] = []
        cids: list[int] = []
        cert: Path | None = None
        key: Path | None = None
        before = list_bridges()
        try:
            for idx, role in enumerate(("server", "agent", "agent")):
                dest = ubuntu_src.DISKS_DIR / (
                    f"ubuntu-gym-{tree_id}-{idx}-{os.getpid()}.img"
                )
                ubuntu_src.reflink_disk(base, dest)
                if self.cfg.scoreboard in ("playbook", "incident", "selfplay"):
                    from playbook import plant_pinned_airgap

                    plant_pinned_airgap(dest)
                disks.append(dest)
                ip = ubuntu_src.guest_ip(idx)
                cni = (
                    "none"
                    if self.cfg.scoreboard in ("tetragon", "incident", "selfplay")
                    else None
                )
                cmdline = ubuntu_src.node_cmdline(
                    ip, ubuntu_src.k3s_spec(role, server_ip), cni=cni
                )
                cfg = {
                    "kernel": str(kernel),
                    "memory_mb": self.cfg.memory_mb,
                    "vcpus": ubuntu_src.NODE_VCPUS,
                    "vsock": True,
                    "cmdline": cmdline,
                    "block_devices": [{"host_path": str(dest), "readonly": False}],
                    "network": {
                        "cluster_id": tree_id,
                        "vm_index": idx,
                        "pod_netns": None,
                    },
                }
                if dilation is not None:
                    if dilation != DILATION_FACTOR:
                        raise RuntimeError(
                            f"dilation must be {DILATION_FACTOR} "
                            f"(pinned, no adaptive N), got {dilation}"
                        )
                    cfg["dilation"] = dilation
                log.info("CreateVm ubuntu %s vm_index=%s ip=%s", role, idx, ip)
                resp = self.client.create_vm(cfg, timeout=self.cfg.k7d_timeout_s)
                if resp.get("status") != "vm_created":
                    raise RuntimeError(f"create_vm ubuntu {role}/{idx}: {resp}")
                vm_id = resp["vm_id"]
                cid = int(resp["guest_cid"])
                created_ids.append(vm_id)
                cids.append(cid)
                if idx == 0:
                    ubuntu_src.wait_agent(
                        cid,
                        ubuntu_src.BOOT_TO_AGENT_S,
                        dump=lambda: self._dump_serial(cid),
                    )
                    ubuntu_src.wait_systemd_healthy(cid)
                    ubuntu_src.wait_guest_readyz(cid, ubuntu_src.CLUSTER_READY_S)
                    dest_dir = ubuntu_src.certs_dir(tree_id)
                    _kube, cert, key = ubuntu_src.write_host_kubeconfig(
                        cid, server_ip, dest_dir
                    )
                else:
                    ubuntu_src.wait_agent(
                        cid,
                        ubuntu_src.BOOT_TO_AGENT_S,
                        dump=lambda c=cid: self._dump_serial(c),
                    )
                    ubuntu_src.wait_systemd_healthy(cid)
                    ubuntu_src.wait_unit_active(cid, "k3s-agent.service")
            names = ubuntu_src.node_names(server_ip)
            kube = ubuntu_src.certs_dir(tree_id) / "kubeconfig"
            _ = (names, kube)
            if cert is None or key is None:
                raise RuntimeError("ubuntu bring-up: kube client certs missing")
            bridge = k7_bridge_name(tree_id)
            if bridge not in list_bridges():
                raise RuntimeError(
                    f"ubuntu bring-up: expected {bridge} after CreateVm, "
                    f"have {sorted(list_bridges())}"
                )
            gate = ready_gate or self.cfg.ready_gate
            if self.cfg.scoreboard in ("tetragon", "incident", "selfplay"):
                # cni=none until Cilium exists. Host kubectl Ready-wait
                # hits the wrong 10.200.0.2 (CHALLENGES #144). Helm
                # before adopt so memory.bin already has the sensors
                # (CHALLENGES #153). Incident soak needs
                # Tetragon event_diff for /tmp/nodecheck.
                ubuntu_src.wait_nodes_present_on_bridge(
                    bridge, cert, key, ubuntu_src.CLUSTER_READY_S
                )
                ubuntu_src.assert_guest_egress(cids)
                ubuntu_src.assert_guest_image_pull(cids)
                from tetragon import pull_tetragon_images

                t_relay = time.perf_counter()
                pull_tetragon_images(cids, bridge=bridge)
                log.info(
                    "ubuntu tetragon image relay %.1fs tree=%s",
                    time.perf_counter() - t_relay,
                    tree_id,
                )
                from sensors import install_cilium_tetragon

                t_s = time.perf_counter()
                install_cilium_tetragon(bridge, kube, server_ip)
                log.info(
                    "ubuntu sensors cilium+tetragon %.1fs tree=%s bridge=%s",
                    time.perf_counter() - t_s,
                    tree_id,
                    bridge,
                )
            if gate == "api":
                log.info(
                    "ready_gate=api: /readyz ok on %s; not waiting "
                    "CLUSTER_READY_S nodes Ready (playbook exam)",
                    bridge,
                )
            elif gate == "nodes":
                ubuntu_src.wait_nodes_ready_on_bridge(
                    bridge, cert, key, ubuntu_src.CLUSTER_READY_S
                )
            else:
                raise RuntimeError(
                    f"ready_gate must be nodes|api, got {gate!r}"
                )
            if self.cfg.scoreboard in ("playbook", "incident", "selfplay"):
                from playbook import wait_pinned_image

                for cid in cids:
                    wait_pinned_image(agent.exec_cmd, cid)
            adopted = self.client.tree_adopt_cluster(
                created_ids,
                tree_id=tree_id,
                budget=self._budget(),
            )
            cids = [int(c) for c in adopted.get("guest_cids") or cids]
            bridge = self._new_bridge(before, tree_id)
            ubuntu_src.persist_meta(
                ubuntu_src.certs_dir(tree_id),
                {
                    "guest_cids": cids,
                    "bridge": bridge,
                    "vm_ids": created_ids,
                    "disks": [str(p) for p in disks],
                },
            )
        except Exception:
            for vm_id in created_ids:
                try:
                    self.client.stop_vm(vm_id)
                except RuntimeError as e:
                    log.warning("ubuntu teardown stop_vm %s: %s", vm_id, e)
            try:
                self.client.tree_drop(tree_id)
            except RuntimeError:
                pass
            ubuntu_src.remove_disks(disks)
            raise
        return {
            "tree_id": tree_id,
            "root_id": adopted["root_id"],
            "guest_cids": cids,
            "bridge": bridge,
            "disks": disks,
            "vm_ids": created_ids,
            "cert": cert,
            "key": key,
        }

    def _ubuntu_source(self) -> None:
        """CreateVm × 3 (Ubuntu bzImage + root disk) then adopt + protect."""
        t0 = time.perf_counter()
        # Fork source stays a live Ready cluster even when the lease
        # gate is api. Children inherit Ready; reset members do not.
        got = self._bring_up_ubuntu_cluster(
            self.cfg.source_tree_id,
            ready_gate="nodes",
            dilation=self.cfg.source_dilation,
        )
        self.source_node_id = got["root_id"]
        self.source_cids = list(got["guest_cids"])
        self.source_vms = 3
        self.cfg.vm_count = 3
        self.source_bridge = got["bridge"]
        self.ubuntu_disks = list(got["disks"])
        self.ubuntu_cert, self.ubuntu_key = got["cert"], got["key"]
        bring_ms = (time.perf_counter() - t0) * 1000.0
        log.info(
            "ubuntu source bring-up %.1f ms tree=%s bridge=%s cids=%s",
            bring_ms,
            self.cfg.source_tree_id,
            self.source_bridge,
            self.source_cids,
        )

    def _dump_serial(self, cid: int) -> str:
        try:
            resp = self.client.dump_serial(guest_cid=cid)
        except RuntimeError as e:
            return f"dump_serial cid={cid}: {e}"
        return str(resp.get("console") or resp)

    def _adopt_source(self) -> None:
        vm_ids = discover_inner3_vm_ids(self.client)
        before = list_bridges()
        adopted = self.client.tree_adopt_cluster(
            vm_ids,
            tree_id=self.cfg.source_tree_id,
            budget=self._budget(),
        )
        self.source_node_id = adopted["root_id"]
        self.source_cids = [int(c) for c in adopted.get("guest_cids") or []]
        self.source_vms = len(vm_ids)
        self.cfg.vm_count = self.source_vms
        new = list_bridges() - before
        # Adopt reuses the existing inner3 bridge; it may not create one.
        if "k7-br-inner3" in list_bridges():
            self.source_bridge = "k7-br-inner3"
        elif new:
            self.source_bridge = sorted(new)[0]
        else:
            raise RuntimeError(
                "tree_adopt_cluster succeeded but no source bridge is visible"
            )
        extract_inner_certs()

    def _record_source_from_nodes(self, nodes_resp: dict[str, Any]) -> None:
        root = next(
            (n for n in nodes_resp.get("nodes") or [] if n.get("id") == "root"),
            None,
        )
        if root is None:
            raise RuntimeError("source tree has no root node")
        # A source tree left by an earlier gym runs at whatever factor
        # that gym asked for, and every fork inherits it. Reusing it
        # under a different GYM_AUTOWARP_MODE would hand out leases
        # tagged one way and running another.
        want = self.cfg.source_dilation or 1
        got = int((nodes_resp.get("live_dilation") or {}).get("root", 1))
        if got != want:
            raise SystemExit(
                f"source tree {self.cfg.source_tree_id} runs at time dilation "
                f"x{got} but this gym's GYM_AUTOWARP_MODE wants x{want}; "
                "drop the tree or match the mode"
            )
        self.source_vms = int(root.get("vm_count") or self.cfg.vm_count)
        self.cfg.vm_count = self.source_vms
        # CIDs are not on NodeInfo; ping via tree_nodes is not enough.
        # Re-read from a fresh protect/nodes is still CID-less. Ask the
        # daemon via a no-op path: dump nothing — store empty and fill
        # from the next lease's source-intact probe. Better: list_vms
        # is not tree-scoped. We keep cids empty and skip vsock score
        # members that have none; source-intact then uses the bridge.
        self.source_cids = []
        if self.cfg.source_mode == "adopt" and "k7-br-inner3" in list_bridges():
            self.source_bridge = "k7-br-inner3"
        elif self.cfg.source_mode == "ubuntu":
            meta = ubuntu_src.load_meta(ubuntu_src.certs_dir(self.cfg.source_tree_id))
            if meta:
                self.source_cids = [int(c) for c in meta.get("guest_cids") or []]
                self.source_bridge = str(meta.get("bridge") or "")
                self.ubuntu_disks = [Path(p) for p in meta.get("disks") or []]
            dest = ubuntu_src.certs_dir(self.cfg.source_tree_id)
            cert, key = dest / "client.pem", dest / "client-key.pem"
            if cert.is_file() and key.is_file():
                self.ubuntu_cert, self.ubuntu_key = cert, key
            if not self.source_bridge:
                expected = k7_bridge_name(self.cfg.source_tree_id)
                self.source_bridge = (
                    expected if expected in list_bridges() else ""
                )
        else:
            expected = k7_bridge_name(self.cfg.source_tree_id)
            self.source_bridge = (
                expected if expected in list_bridges() else ""
            )

    def _new_bridge(self, before: set[str], tree_id: str | None = None) -> str:
        after = list_bridges() - before
        if len(after) == 1:
            return after.pop()
        expected = k7_bridge_name(tree_id or self.cfg.source_tree_id)
        if expected in list_bridges():
            return expected
        raise RuntimeError(
            f"could not identify source bridge (new={sorted(after)})"
        )

    # ----- lease lifecycle -----

    def admit_or_reject(self, n: int) -> str | None:
        if n < 1:
            return f"lease rejected: n must be >= 1, got {n}"
        if self.cfg.start_mode == "reset":
            return reset_need(
                n=n,
                vms_per_branch=self.source_vms or 3,
                memory_bytes_per_vm=self.cfg.memory_mb * 1024 * 1024,
                max_live_vms=self.cfg.max_live_vms,
                max_live_ram_bytes=self.cfg.max_live_ram_bytes,
            ).rejection()
        live_already = self.source_vms + self.leases.live_vms_in_flight(
            self.source_vms
        )
        need = lease_need(
            n=n,
            vms_per_branch=self.source_vms,
            source_vms=self.source_vms,
            live_already=live_already,
            max_live_vms=self.cfg.max_live_vms,
            memory_bytes_per_vm=self.cfg.memory_mb * 1024 * 1024,
            max_live_ram_bytes=self.cfg.max_live_ram_bytes,
        )
        return need.rejection()

    def prepare_env(self, env_id: str) -> dict[str, Any]:
        """POST /env/{id}/prepare — write memory.bin on this node now.

        No new VMs. Mid-episode fork then CoWs. Trainer overlaps this
        with GPU generate so the dump is not on the fork's critical path.
        """
        if self.cfg.start_mode == "reset":
            raise ValueError(
                "prepare is Ubuntu GYM_START_MODE=fork only "
                "(reset has no memory.bin parent, CHALLENGES #149)"
            )
        found = self.leases.env(env_id)
        if found is None:
            raise KeyError(f"no such env: {env_id}")
        lease, env = found
        tree_id = env.tree_id or lease.tree_id
        if not tree_id:
            raise RuntimeError(f"env {env_id} has no tree_id")
        node_id = env.branch_node_id
        t0 = time.perf_counter()
        rec = self.client.tree_prepare_fork_source(tree_id, node_id)
        return {
            "ok": True,
            "env_id": env_id,
            "lease_id": lease.lease_id,
            "tree_id": tree_id,
            "node_id": node_id,
            "prepare_s": time.perf_counter() - t0,
            "k7d": rec if isinstance(rec, dict) else {"status": rec},
        }

    def fork_env(self, env_id: str, body: dict[str, Any]) -> dict[str, Any]:
        """POST /env/{id}/fork — mid-episode children on the same lease.

        Does not call ``tree_prepare_fork_source``. k7d inherits the
        ancestor keyframe. The lease path still prepares
        the episode root before the group fork.
        """
        if self.cfg.start_mode == "reset":
            raise ValueError(
                "mid-episode fork is Ubuntu GYM_START_MODE=fork only "
                "(reset collides Cilium, CHALLENGES #149)"
            )
        if "n" not in body:
            raise ValueError("POST /env/{id}/fork missing n")
        n = int(body["n"])
        if n < 1:
            raise ValueError(f"n must be >= 1, got {n}")
        labels = body.get("labels")
        if labels is not None:
            if not isinstance(labels, list) or len(labels) != n:
                raise ValueError(
                    f"labels length must equal n={n}, got {labels!r}"
                )
            labels = [str(x) for x in labels]
            if any(not x for x in labels):
                raise ValueError("labels must be non-empty strings")
        found = self.leases.env(env_id)
        if found is None:
            raise KeyError(f"no such env: {env_id}")
        lease, parent = found
        reject = self.admit_or_reject(n)
        if reject:
            raise ForkRejected(reject)
        start_index = max(e.index for e in lease.envs) + 1
        if labels is None:
            labels = [
                f"{LEASE_LABEL_PREFIX}-{lease.lease_id[-8:]}-f{start_index + i}"
                for i in range(n)
            ]
        tree_id = parent.tree_id or lease.tree_id
        if not tree_id:
            raise RuntimeError(f"env {env_id} has no tree_id")
        parent_node = parent.branch_node_id
        forks: list[dict[str, Any]] = []
        try:
            batch = self.client.tree_fork_batch(tree_id, parent_node, labels)
            forks = list(batch.get("forks") or [])
            if len(forks) != n:
                raise RuntimeError(
                    f"tree_fork_batch returned {len(forks)} forks, expected {n}"
                )
            children = self._envs_from_forks(
                lease.lease_id, forks, start_index=start_index, tree_id=tree_id
            )
            for e in children:
                e.role = parent.role
                e.scenario_id = parent.scenario_id
                if parent.role == "red":
                    cid = e.guest_cids[0] if e.guest_cids else None
                    if cid is None:
                        raise RuntimeError(
                            f"selfplay red child {e.env_id} has no guest cids"
                        )
                    scenario = red_agent.get_scenario(parent.scenario_id)
                    e.foothold_token = red_agent.mint_foothold_token(
                        int(cid), scenario.foothold, exec_cmd=self._exec3
                    )
            self.leases.append_envs(lease.lease_id, children)
            self._enable_autowarp(children, lease.autowarp_mode)
        except Exception:
            for f in forks:
                nid = f.get("node_id")
                if nid:
                    try:
                        self.client.tree_prune(tree_id, nid)
                    except RuntimeError as err:
                        log.warning("teardown after failed mid-fork prune %s: %s", nid, err)
            raise
        return {
            "envs": [
                {**e.as_public(), "guest_cids": list(e.guest_cids)}
                for e in children
            ],
            "parent_env_id": env_id,
            "lease_id": lease.lease_id,
        }

    def lease(self, body: dict[str, Any], client: str) -> dict[str, Any]:
        if self.cfg.scoreboard == "selfplay":
            return self._selfplay_lease(body, client)
        for key in ("fault_id", "n", "group_id", "ttl_s"):
            if key not in body:
                raise ValueError(f"POST /lease missing {key}")
        fault_id = str(body["fault_id"])
        if self.cfg.scoreboard == "playbook":
            refuse_inject_fault(fault_id)
        if self.cfg.scoreboard == "incident":
            require_incident_fault(fault_id)
        if self.cfg.scoreboard == "grpo":
            require_grpo_fault(fault_id)
        scenario_id = ""
        if fault_id == SCRIPTED_ID:
            if self.cfg.scoreboard != "grpo":
                raise ValueError(
                    f"fault_id={SCRIPTED_ID!r} is grpo-only, got "
                    f"scoreboard={self.cfg.scoreboard!r}"
                )
            if not str(body.get("scenario_id") or ""):
                raise ValueError(
                    f"POST /lease with fault_id={SCRIPTED_ID!r} missing scenario_id"
                )
            scenario_id = str(body["scenario_id"])
            fault = get_scenario(scenario_id)
        else:
            fault = get_fault(fault_id)
        if self.cfg.source_mode not in fault.modes:
            raise ValueError(
                f"fault_id {fault_id!r} does not support "
                f"source_mode={self.cfg.source_mode}"
            )
        fault.source_mode = self.cfg.source_mode
        if self.cfg.source_mode == "ubuntu" and fault_id == "kill-member-0":
            if self.cfg.scoreboard == "tetragon":
                from faults.kill_member_0 import TETRAGON_PATH

                fault.keep_apiserver = True
                fault.good_fix_hint = {
                    "action": "exec",
                    "args": ["rm", "-f", TETRAGON_PATH],
                }
            else:
                # health / grpo: realistic control-plane death. The
                # catalog singleton may still have keep_apiserver=True
                # from a prior tetragon lease in this process.
                if hasattr(fault, "keep_apiserver"):
                    fault.keep_apiserver = False
                fault.good_fix_hint = {
                    "action": "exec",
                    "args": ["systemctl", "start", "k3s.service"],
                }
        if (
            self.cfg.source_mode == "ubuntu"
            and self.cfg.scoreboard == "tetragon"
            and hasattr(fault, "keep_apiserver")
        ):
            fault.keep_apiserver = True
        n = int(body["n"])
        ttl_s = float(body["ttl_s"])
        if ttl_s <= 0:
            raise ValueError(f"ttl_s must be > 0, got {ttl_s}")
        autowarp_mode = self._autowarp_mode_from_body(body)
        reject = self.admit_or_reject(n)
        if reject:
            raise LeaseRejected(reject)

        lid = new_lease_id()
        now = time.time()
        placeholder = Lease(
            lease_id=lid,
            node_id=self.cfg.node_id,
            group_id=str(body["group_id"]),
            fault_id=fault_id,
            scenario_id=scenario_id,
            tree_id=self.cfg.source_tree_id,
            source_node_id=self.source_node_id,
            n=n,
            created_at=now,
            expires_at=now + ttl_s,
            envs=[],
            client=client,
            pending=True,
            autowarp_mode=autowarp_mode,
        )
        reserved = self.leases.reserve(placeholder)
        if reserved:
            raise LeaseRejected(reserved)

        labels = [f"{LEASE_LABEL_PREFIX}-{lid[-8:]}-{i}" for i in range(n)]
        forks: list[dict[str, Any]] = []
        reset_envs: list[Env] = []
        committed = False
        inject_ms = 0.0
        try:
            if self.cfg.start_mode == "reset":
                reset_envs = self._envs_from_reset(
                    lid, n, self._lease_dilation(autowarp_mode)
                )
                envs = reset_envs
            else:
                batch = self.client.tree_fork_batch(
                    self.cfg.source_tree_id,
                    self.source_node_id,
                    labels,
                    dilation=self._fork_child_dilation(autowarp_mode),
                )
                forks = list(batch.get("forks") or [])
                if len(forks) != n:
                    raise RuntimeError(
                        f"tree_fork_batch returned {len(forks)} forks, expected {n}"
                    )
                envs = self._envs_from_forks(lid, forks)
            lease = self.leases.commit(lid, envs)
            committed = True
            t_inj = time.perf_counter()
            self._inject(lease, fault)
            inject_ms = (time.perf_counter() - t_inj) * 1000.0
            self._enable_autowarp(lease.envs, autowarp_mode)
        except Exception:
            if committed:
                try:
                    self.release(lid, reason="inject-failed")
                except (KeyError, RuntimeError) as e:
                    log.warning("teardown after failed inject %s: %s", lid, e)
            else:
                self.leases.abandon(lid)
                for e in reset_envs:
                    self._drop_tree_loud(e.tree_id)
                for f in forks:
                    nid = f.get("node_id")
                    if nid:
                        try:
                            self.client.tree_prune(self.cfg.source_tree_id, nid)
                        except RuntimeError as e:
                            log.warning(
                                "teardown after failed lease prune %s: %s", nid, e
                            )
            raise
        out = {
            "lease_id": lease.lease_id,
            "node_id": self.cfg.node_id,
            "tree_id": lease.tree_id,
            "source_node_id": lease.source_node_id,
            "group_id": lease.group_id,
            "fault_id": lease.fault_id,
            "good_fix_hint": fault.good_fix_hint,
            "inject_ms": inject_ms,
            "autowarp_mode": lease.autowarp_mode,
            "envs": [e.as_public() for e in lease.envs],
        }
        if scenario_id:
            # Tier and family only — never the fix, never the scripts.
            out["scenario_id"] = scenario_id
            out["fault_type"] = fault.fault_type
            out["tier"] = fault.tier
            # The registry is read once at start; the digest lets a
            # harness see that this gym is running an older copy of the
            # scenario than the one on disk.
            out["scenario_digest"] = fault.digest
        return out

    def _selfplay_lease(self, body: dict[str, Any], client: str) -> dict[str, Any]:
        """Fork the SETTLED opponent state (the fork lease).

        Blue on trial: plant the frozen scripted red on a settle branch,
        wait it settled (miner Running), then fork n from that branch —
        so all n tries share a byte-identical *planted* start.
        Red on trial: leave the settle branch defended (clean baseline is
        blue's frozen defence), then fork n; red plants persistence on
        each fork from its granted foothold.

        The forks are minted from the settled branch's memory.bin, not an
        aged live source (invariant 7).
        """
        for key in ("role", "scenario_id", "n", "group_id", "ttl_s"):
            if key not in body:
                raise ValueError(f"POST /lease (selfplay) missing {key}")
        role = str(body["role"])
        require_selfplay_role(role)
        scenario = red_agent.get_scenario(str(body["scenario_id"]))
        n = int(body["n"])
        ttl_s = float(body["ttl_s"])
        if ttl_s <= 0:
            raise ValueError(f"ttl_s must be > 0, got {ttl_s}")
        autowarp_mode = self._autowarp_mode_from_body(body)
        if self.cfg.start_mode == "reset":
            return self._selfplay_reset_lease(body, client, role, scenario, n, ttl_s)
        reject = self.admit_or_reject(n + 1)  # +1 for the settle branch
        if reject:
            raise LeaseRejected(reject)

        lid = new_lease_id()
        now = time.time()
        placeholder = Lease(
            lease_id=lid,
            node_id=self.cfg.node_id,
            group_id=str(body["group_id"]),
            fault_id=scenario.incident_id,
            tree_id=self.cfg.source_tree_id,
            source_node_id=self.source_node_id,
            n=n,
            created_at=now,
            expires_at=now + ttl_s,
            envs=[],
            client=client,
            pending=True,
            extra={"role": role, "scenario_id": scenario.scenario_id},
            autowarp_mode=autowarp_mode,
        )
        reserved = self.leases.reserve(placeholder)
        if reserved:
            raise LeaseRejected(reserved)

        settle_node = ""
        forks: list[dict[str, Any]] = []
        committed = False
        try:
            settle_label = f"{LEASE_LABEL_PREFIX}-{lid[-8:]}-settle"
            settle_batch = self.client.tree_fork_batch(
                self.cfg.source_tree_id,
                self.source_node_id,
                [settle_label],
                dilation=self._fork_child_dilation(autowarp_mode),
            )
            settle_forks = list(settle_batch.get("forks") or [])
            if len(settle_forks) != 1:
                raise RuntimeError(
                    f"settle fork returned {len(settle_forks)}, expected 1"
                )
            settle_node = settle_forks[0]["node_id"]
            placeholder.extra["settle_node_id"] = settle_node
            settle_cids = [int(c) for c in settle_forks[0].get("guest_cids") or []]
            settle_cluster = f"{self.cfg.source_tree_id}-{settle_node}"
            settle_bridge = k7_bridge_name(settle_cluster)
            ip0 = (guest_ips(self.source_vms) or ["10.200.0.2"])[0]

            t_inj = time.perf_counter()
            src_cert, src_key = self._api_certs()
            self._apply_opponent(
                role, scenario, settle_cids, settle_bridge, ip0, src_cert, src_key
            )
            inject_ms = (time.perf_counter() - t_inj) * 1000.0

            self.client.tree_prepare_fork_source(
                self.cfg.source_tree_id, settle_node
            )
            labels = [f"{LEASE_LABEL_PREFIX}-{lid[-8:]}-{i}" for i in range(n)]
            batch = self.client.tree_fork_batch(
                self.cfg.source_tree_id,
                settle_node,
                labels,
                dilation=self._fork_child_dilation(autowarp_mode),
            )
            forks = list(batch.get("forks") or [])
            if len(forks) != n:
                raise RuntimeError(
                    f"selfplay group fork returned {len(forks)}, expected {n}"
                )
            envs = self._envs_from_forks(lid, forks)
            for e in envs:
                e.role = role
                e.scenario_id = scenario.scenario_id
                if role == "red":
                    cid = e.guest_cids[0] if e.guest_cids else None
                    if cid is None:
                        raise RuntimeError(
                            f"selfplay red env {e.env_id} has no guest cids"
                        )
                    e.foothold_token = red_agent.mint_foothold_token(
                        int(cid), scenario.foothold, exec_cmd=self._exec3
                    )
            lease = self.leases.commit(lid, envs)
            committed = True
            self._enable_autowarp(lease.envs, autowarp_mode)
        except Exception:
            if committed:
                try:
                    self.release(lid, reason="selfplay-lease-failed")
                except (KeyError, RuntimeError) as e:
                    log.warning("teardown after failed selfplay lease %s: %s", lid, e)
            else:
                self.leases.abandon(lid)
                for f in forks:
                    nid = f.get("node_id")
                    if nid:
                        try:
                            self.client.tree_prune(self.cfg.source_tree_id, nid)
                        except RuntimeError as e:
                            log.warning("teardown prune fork %s: %s", nid, e)
                if settle_node:
                    try:
                        self.client.tree_prune(self.cfg.source_tree_id, settle_node)
                    except RuntimeError as e:
                        log.warning("teardown prune settle %s: %s", settle_node, e)
            raise
        return {
            "lease_id": lease.lease_id,
            "node_id": self.cfg.node_id,
            "tree_id": lease.tree_id,
            "source_node_id": lease.source_node_id,
            "group_id": lease.group_id,
            "fault_id": lease.fault_id,
            "role": role,
            "scenario_id": scenario.scenario_id,
            "settle_node_id": settle_node,
            "inject_ms": inject_ms,
            "good_fix_hint": self._selfplay_fix_hint(scenario),
            "autowarp_mode": lease.autowarp_mode,
            "envs": [e.as_public() for e in lease.envs],
        }

    def _selfplay_reset_lease(
        self,
        body: dict[str, Any],
        client: str,
        role: str,
        scenario: "red_agent.Scenario",
        n: int,
        ttl_s: float,
    ) -> dict[str, Any]:
        """Reset arm of self-play: a fresh Ubuntu cluster per member, the
        frozen opponent applied per-member (not forked). This is the
        noisier baseline the fork-vs-reset instrument compares against —
        each member is re-minted, never a byte-identical fork.
        """
        if not self.cfg.reset_measurement:
            raise ValueError(
                "selfplay reset is measurement-only; set GYM_RESET_MEASUREMENT=1"
            )
        reject = self.admit_or_reject(n)
        if reject:
            raise LeaseRejected(reject)
        lid = new_lease_id()
        now = time.time()
        placeholder = Lease(
            lease_id=lid,
            node_id=self.cfg.node_id,
            group_id=str(body["group_id"]),
            fault_id=scenario.incident_id,
            tree_id=self.cfg.source_tree_id,
            source_node_id=self.source_node_id,
            n=n,
            created_at=now,
            expires_at=now + ttl_s,
            envs=[],
            client=client,
            pending=True,
            extra={"role": role, "scenario_id": scenario.scenario_id},
            autowarp_mode=self._autowarp_mode_from_body(body),
        )
        reserved = self.leases.reserve(placeholder)
        if reserved:
            raise LeaseRejected(reserved)
        committed = False
        envs: list[Env] = []
        try:
            t_inj = time.perf_counter()
            dilation = self._lease_dilation(placeholder.autowarp_mode)
            for i in range(n):
                e = self._reset_one_env(lid, i, dilation)
                envs.append(e)
                ip0 = e.guest_ips[0] if e.guest_ips else "10.200.0.2"
                env_cert, env_key = self._env_certs(e)
                self._apply_opponent(
                    role, scenario, e.guest_cids, e.bridge, ip0, env_cert, env_key
                )
                e.role = role
                e.scenario_id = scenario.scenario_id
                if role == "red":
                    cid = e.guest_cids[0] if e.guest_cids else None
                    if cid is None:
                        raise RuntimeError(
                            f"selfplay red reset env {e.env_id} has no cids"
                        )
                    e.foothold_token = red_agent.mint_foothold_token(
                        int(cid), scenario.foothold, exec_cmd=self._exec3
                    )
            inject_ms = (time.perf_counter() - t_inj) * 1000.0
            lease = self.leases.commit(lid, envs)
            committed = True
            self._enable_autowarp(lease.envs, lease.autowarp_mode)
        except Exception:
            if committed:
                try:
                    self.release(lid, reason="selfplay-reset-failed")
                except (KeyError, RuntimeError) as e:
                    log.warning("teardown after failed selfplay reset %s: %s", lid, e)
            else:
                self.leases.abandon(lid)
                for e in envs:
                    self._drop_tree_loud(e.tree_id)
                    ubuntu_src.remove_disks([Path(p) for p in e.disks])
            raise
        return {
            "lease_id": lease.lease_id,
            "node_id": self.cfg.node_id,
            "tree_id": lease.tree_id,
            "source_node_id": lease.source_node_id,
            "group_id": lease.group_id,
            "fault_id": lease.fault_id,
            "role": role,
            "scenario_id": scenario.scenario_id,
            "inject_ms": inject_ms,
            "good_fix_hint": self._selfplay_fix_hint(scenario),
            "autowarp_mode": lease.autowarp_mode,
            "envs": [e.as_public() for e in lease.envs],
        }

    def _exec3(self, cid: int, args: list[str], timeout_s: float) -> dict[str, Any]:
        env = self._env_by_cid(cid)
        if env is None:
            return agent.exec_cmd(cid, args, timeout_s)
        with self._hold_autowarp(env, "gym-exec"):
            return agent.exec_cmd(cid, args, timeout_s)

    @staticmethod
    def _selfplay_fix_hint(scenario: "red_agent.Scenario") -> dict[str, Any]:
        """Oracle peel for blue-on-trial: the scenario incident's full
        `remediate_cmd` as an exec act (the blue=oracle checkpoint,
        same peel the incident scoreboard hands blue)."""
        from incidents_load import incidents_mod

        incident = incidents_mod().CATALOG[scenario.incident_id]
        return {"action": "exec", "args": ["sh", "-c", incident.remediate_cmd()]}

    def _apply_opponent(
        self,
        role: str,
        scenario: "red_agent.Scenario",
        cids: list[int],
        bridge: str,
        ip0: str,
        cert: Path | None,
        key: Path | None,
    ) -> None:
        """Settle the frozen opponent before forking (or per reset member).

        Blue on trial → plant the scripted red opening and wait it Running
        (blue must peel a real, settled incident). Red on trial → the
        defended clean baseline is blue's frozen defence; nothing to plant
        (red does its planting on the forks from its foothold).
        """
        if not cids:
            raise RuntimeError("selfplay settle branch has no guest cids")
        if cert is not None and key is not None:
            # A fresh reset cluster returns at the api gate before its
            # nodes are Ready; the scheduler cannot place the miner until
            # then. A fork of a settled source is already Ready, so this
            # returns immediately (CHALLENGES #174).
            ubuntu_src.wait_nodes_ready_on_bridge(
                bridge, cert, key, ubuntu_src.CLUSTER_READY_S
            )
        if role == "blue":
            scripted = red_agent.ScriptedRed(scenario.incident_id)
            scripted.plant(cids, exec_cmd=self._exec3)
            from faults.relay import miner_running_via_api

            deadline = time.monotonic() + 180.0
            while time.monotonic() < deadline:
                if cert and key and miner_running_via_api(
                    bridge, cert=cert, key=key, guest_ip=ip0
                ):
                    return
                time.sleep(2.0)
            raise RuntimeError(
                "selfplay blue-on-trial: scripted red never settled "
                "(miner not Running)"
            )
        # red on trial: defended clean baseline, no plant.
        return

    def _fault_for(self, L: Lease) -> Any:
        """The injector a lease is scored with. Scripted needs its id."""
        if L.fault_id == SCRIPTED_ID:
            fault = get_scenario(L.scenario_id)
        else:
            fault = get_fault(L.fault_id)
        fault.source_mode = self.cfg.source_mode
        return fault

    def _inject(self, lease: Lease, fault: Any) -> None:
        """After the batch. Health/tetragon: env0 only. Incident/grpo:
        every member's control plane (no env0-only plant).

        Eight members inject in parallel: a scripted `inject.sh` may
        poll for its own symptom for tens of seconds, and sequential
        injects would multiply that by n (CHALLENGES #181 — no fixed
        wait may be paid more than once).
        """
        if self.cfg.scoreboard in ("incident", "grpo"):
            targets = list(lease.envs)
        else:
            target = next((e for e in lease.envs if e.index == 0), None)
            if target is None:
                raise RuntimeError("lease missing env index 0; cannot inject")
            targets = [target]
        if not targets:
            raise RuntimeError("lease has no envs; cannot inject")
        if len(targets) == 1:
            self._inject_one(targets[0], fault)
            return
        with ThreadPoolExecutor(max_workers=len(targets)) as pool:
            futures = {
                pool.submit(self._inject_one, t, fault): t for t in targets
            }
            # Drain every future before raising so the release path sees
            # a lease with no inject still running against its guests.
            failures: list[BaseException] = []
            for fut in as_completed(futures):
                err = fut.exception()
                if err is not None:
                    failures.append(err)
        if failures:
            raise failures[0]

    def _inject_one(self, target: Env, fault: Any) -> None:
        t0 = time.perf_counter()
        fault.inject(target, self.client)
        if fault.id != "none" and not fault.fault_visible(target):
            detail = ""
            try:
                cid = target.guest_cids[0]
                with self._hold_autowarp(target, "gym-inject"):
                    r = agent.exec_cmd(
                        cid,
                        ["sh", "-c", "ip link show; echo ---; cat /sys/class/net/eth0/flags 2>/dev/null || true"],
                        timeout_s=5,
                    )
                detail = f" probe stdout={r['stdout']!r} stderr={r['stderr']!r}"
            except (OSError, RuntimeError, IndexError) as e:
                detail = f" probe failed: {e}"
            raise RuntimeError(
                f"inject {self._fault_label(fault)} did not take on "
                f"{target.env_id}{detail}"
            )
        log.info(
            "injected %s on %s in %.0f ms",
            self._fault_label(fault),
            target.env_id,
            (time.perf_counter() - t0) * 1000.0,
        )

    @staticmethod
    def _fault_label(fault: Any) -> str:
        sid = getattr(fault, "scenario_id", "")
        return f"{fault.id}:{sid}" if sid else str(fault.id)

    def _envs_from_forks(
        self,
        lease_id: str,
        forks: list[dict[str, Any]],
        *,
        start_index: int = 0,
        tree_id: str | None = None,
    ) -> list[Env]:
        ips = guest_ips(self.source_vms)
        envs: list[Env] = []
        visible = list_bridges()
        tid = tree_id or self.cfg.source_tree_id
        for i, f in enumerate(forks):
            nid = f["node_id"]
            idx = start_index + i
            cluster_id = f"{tid}-{nid}"
            bridge = k7_bridge_name(cluster_id)
            if bridge not in visible:
                raise RuntimeError(
                    f"fork {nid}: computed bridge {bridge} "
                    f"(cluster_id={cluster_id!r}) is not on the host "
                    f"(k7-br-*={sorted(visible)}). "
                    "ClusterSnapshotTree fork labels must be "
                    "'{tree_id}-{node_id}' using the registry tree_id"
                )
            cert, key = self._api_certs()
            envs.append(
                Env(
                    env_id=new_env_id(lease_id, idx),
                    branch_node_id=nid,
                    index=idx,
                    tree_id=tid,
                    bridge=bridge,
                    guest_ips=list(ips),
                    guest_cids=[int(c) for c in f.get("guest_cids") or []],
                    cert_path=str(cert) if cert else "",
                    key_path=str(key) if key else "",
                    cluster_id=cluster_id,
                )
            )
        return envs

    def _reset_one_env(
        self, lease_id: str, i: int, dilation: int | None = None
    ) -> Env:
        """One fresh Ubuntu cluster. Measurement-only, not CoW."""
        ips = guest_ips(3)
        tid = f"gym-rst-{lease_id[-8:]}-{i}"
        t0 = time.perf_counter()
        got = self._bring_up_ubuntu_cluster(tid, dilation=dilation)
        self.client.tree_protect(tid, got["root_id"])
        baseline = ""
        if self.cfg.scoreboard == "tetragon":
            cert, key = got["cert"], got["key"]
            if cert is None or key is None:
                raise RuntimeError(
                    f"reset {tid}: no kube certs for tetragon baseline"
                )
            baseline = collect_events(got["bridge"], cert=cert, key=key)
        env = Env(
            env_id=new_env_id(lease_id, i),
            branch_node_id=got["root_id"],
            index=i,
            bridge=got["bridge"],
            guest_ips=list(ips),
            guest_cids=list(got["guest_cids"]),
            tree_id=tid,
            baseline_raw=baseline,
            cert_path=str(got["cert"] or ""),
            key_path=str(got["key"] or ""),
            disks=[str(p) for p in got["disks"]],
            cluster_id=tid,
        )
        log.info(
            "reset member %s bring-up %.1f ms tree=%s ready_gate=%s",
            i,
            (time.perf_counter() - t0) * 1000.0,
            tid,
            self.cfg.ready_gate,
        )
        return env

    def _envs_from_reset(
        self, lease_id: str, n: int, dilation: int | None = None
    ) -> list[Env]:
        """Fresh Ubuntu bring-up per member. Measurement-only, not CoW.

        Playbook tries parallel (flannel, not Cilium). A hang is loud
        and falls back to sequential n — never a silent shrink
        (CHALLENGES #149 / #154).
        """
        if n > 1 and self.cfg.ready_gate == "api":
            try:
                return self._envs_from_reset_parallel(lease_id, n, dilation)
            except Exception as e:
                log.error(
                    "parallel reset n=%s failed (%s); sequential "
                    "fallback, not shrinking n (CHALLENGES #149)",
                    n,
                    e,
                )
        envs: list[Env] = []
        current = ""
        try:
            for i in range(n):
                current = f"gym-rst-{lease_id[-8:]}-{i}"
                envs.append(self._reset_one_env(lease_id, i, dilation))
                current = ""
            return envs
        except Exception:
            seen = {e.tree_id for e in envs if e.tree_id}
            if current and current not in seen:
                self._drop_tree_loud(current)
            for e in envs:
                self._drop_tree_loud(e.tree_id)
                ubuntu_src.remove_disks([Path(p) for p in e.disks])
            raise

    def _envs_from_reset_parallel(
        self, lease_id: str, n: int, dilation: int | None = None
    ) -> list[Env]:
        envs_by_i: dict[int, Env] = {}
        errors: list[str] = []
        with ThreadPoolExecutor(max_workers=n) as pool:
            futs = {
                pool.submit(self._reset_one_env, lease_id, i, dilation): i
                for i in range(n)
            }
            for fut in as_completed(futs):
                i = futs[fut]
                try:
                    envs_by_i[i] = fut.result()
                except Exception as e:
                    errors.append(f"member {i}: {e}")
        if errors:
            for e in envs_by_i.values():
                self._drop_tree_loud(e.tree_id)
                ubuntu_src.remove_disks([Path(p) for p in e.disks])
            raise RuntimeError(
                f"parallel reset n={n} failed: {errors}. "
                "Will try sequential; not shrinking n."
            )
        if len(envs_by_i) != n:
            raise RuntimeError(
                f"parallel reset expected {n} members, got {len(envs_by_i)}"
            )
        return [envs_by_i[i] for i in range(n)]

    def release(self, lease_id: str, *, reason: str) -> dict[str, Any]:
        with self.mutate:
            return self._release_locked(lease_id, reason=reason)

    def _release_locked(self, lease_id: str, *, reason: str) -> dict[str, Any]:
        L = self.leases.begin_release(lease_id)
        if L is None:
            raise KeyError(f"no such lease: {lease_id}")
        autowarp = self._stop_autowarp(L.envs)
        pruned: list[str] = []
        errors: list[str] = []
        for e in L.envs:
            try:
                if e.tree_id and e.tree_id != L.tree_id:
                    self._drop_tree_loud(e.tree_id)
                    pruned.append(e.tree_id)
                else:
                    self.client.tree_prune(L.tree_id, e.branch_node_id)
                    pruned.append(e.branch_node_id)
            except RuntimeError as err:
                errors.append(f"{e.branch_node_id}: {err}")
            ubuntu_src.remove_disks([Path(p) for p in e.disks])
        settle_node = L.extra.get("settle_node_id") if L.extra else None
        if settle_node:
            try:
                self.client.tree_prune(L.tree_id, settle_node)
                pruned.append(settle_node)
            except RuntimeError as err:
                errors.append(f"settle {settle_node}: {err}")
        leftover_nodes = []
        for e in L.envs:
            if e.tree_id and e.tree_id != L.tree_id:
                leftover_nodes.extend(self.tree_node_ids(e.tree_id))
            elif e.branch_node_id in self.tree_node_ids(L.tree_id):
                leftover_nodes.append(e.branch_node_id)
        leftover_bridges = [
            e.bridge for e in L.envs if e.bridge in list_bridges()
        ]
        leftover_taps = _taps_for_bridges(leftover_bridges)
        self.leases.mark_released(lease_id)
        res = {
            "released": True,
            "pruned": pruned,
            "reason": reason,
            "residue": {
                "bridges": leftover_bridges,
                "taps": leftover_taps,
                "tree_node_ids": leftover_nodes,
                "errors": errors,
            },
            "node_id": self.cfg.node_id,
        }
        if autowarp:
            res["autowarp"] = autowarp
        if leftover_nodes or leftover_bridges or leftover_taps or errors:
            log.warning("release %s left residue: %s", lease_id, res["residue"])
        else:
            log.info("release %s clean (%s)", lease_id, reason)
        return res

    def reap_once(self) -> None:
        for L in self.leases.expired():
            age = time.time() - L.created_at
            log.warning(
                "TTL reap lease_id=%s age_s=%.1f client=%s group_id=%s",
                L.lease_id,
                age,
                L.client,
                L.group_id,
            )
            try:
                self.release(L.lease_id, reason=f"ttl age_s={age:.1f}")
            except (KeyError, RuntimeError) as e:
                log.warning("TTL reap %s failed: %s", L.lease_id, e)

    def start_reaper(self) -> None:
        interval = self.cfg.reaper_interval_s

        def loop() -> None:
            while not self._stop.wait(interval):
                try:
                    self.reap_once()
                except Exception:
                    log.exception("reaper tick failed")

        self._reaper = threading.Thread(
            target=loop, name="gym-reaper", daemon=True
        )
        self._reaper.start()

    def shutdown(self) -> None:
        self._stop.set()
        for lid in self.leases.all_ids():
            try:
                self.release(lid, reason="gym-shutdown")
            except (KeyError, RuntimeError) as e:
                log.warning("shutdown release %s: %s", lid, e)
        # Keep the source: next gym start reuses it. Tests that want a
        # full wipe prune+drop from the outside (test_gym.rs Drop).

    # ----- act / obs / score -----

    def act(self, env_id: str, body: dict[str, Any]) -> dict[str, Any]:
        found = self.leases.env(env_id)
        if found is None:
            raise KeyError(f"no such env: {env_id}")
        _lease, env = found
        action = body.get("action")
        args = body.get("args")
        if not isinstance(args, list) or not all(isinstance(a, str) for a in args):
            raise ValueError("args must be a list of strings")
        timeout_s = float(body.get("timeout_s") or 10)
        t0 = time.perf_counter()
        if (
            env.role == "red"
            and self.cfg.scoreboard == "selfplay"
            and action in ("exec", "kubectl")
        ):
            scenario = red_agent.get_scenario(env.scenario_id)
            cid = env.guest_cids[0] if env.guest_cids else None
            if cid is None:
                raise RuntimeError(f"red env {env_id} has no guest_cids")
            actor = red_agent.RedActor(
                bridge=env.bridge,
                guest_ip=env.guest_ips[0] if env.guest_ips else "10.200.0.2",
                node_cid=int(cid),
                foothold=scenario.foothold,
                token=env.foothold_token,
                exec_cmd=self._exec3,
            )
            rec = actor.act(body, timeout_s=timeout_s)
            rec["elapsed_ms"] = (time.perf_counter() - t0) * 1000
            rec["node_id"] = self.cfg.node_id
            return rec
        if action == "exec":
            if not env.guest_cids:
                raise RuntimeError(f"env {env_id} has no guest_cids")
            with self._hold_autowarp(env, "gym-exec"):
                result = agent.exec_cmd(env.guest_cids[0], args, timeout_s)
            elapsed_ms = (time.perf_counter() - t0) * 1000
            return {
                "ok": result["exit_code"] == 0,
                "stdout": result["stdout"],
                "stderr": result["stderr"],
                "exit_code": result["exit_code"],
                "elapsed_ms": elapsed_ms,
                "node_id": self.cfg.node_id,
            }
        if action == "kubectl":
            method, path, req_body, ctype = kubectl_to_request(args)
            cert, key = self._api_certs()
            code, stdout, stderr = curl_api(
                env.bridge,
                path,
                guest_ip=env.guest_ips[0] if env.guest_ips else "10.200.0.2",
                method=method,
                timeout_s=timeout_s,
                cert=cert,
                key=key,
                body=req_body,
                content_type=ctype,
            )
            elapsed_ms = (time.perf_counter() - t0) * 1000
            ok = 200 <= code < 300
            return {
                "ok": ok,
                "stdout": stdout,
                "stderr": stderr,
                "exit_code": 0 if ok else code,
                "elapsed_ms": elapsed_ms,
                "node_id": self.cfg.node_id,
            }
        if action == "playbook":
            if self.cfg.scoreboard != "playbook":
                raise ValueError(
                    f"action=playbook requires GYM_SCOREBOARD=playbook "
                    f"(got {self.cfg.scoreboard!r})"
                )
            refuse_inject_fault(_lease.fault_id)
            if not args:
                raise ValueError("playbook act needs turn as args[0]")
            turn = int(args[0])
            cert, key = self._env_certs(env)
            result = run_page(
                PlaybookCtx(
                    bridge=env.bridge,
                    cert=cert,
                    key=key,
                    guest_ip=env.guest_ips[0] if env.guest_ips else "10.200.0.2",
                    guest_cids=list(env.guest_cids),
                    exec_cmd=lambda cid, a, t=10: self._exec3(cid, a, t),
                ),
                turn,
            )
            rec = {
                "ok": result.ok,
                "elapsed_s": result.elapsed_s,
                "detail": result.detail,
                "page": turn,
            }
            if len(env.playbook_results) == turn - 1:
                env.playbook_results.append(rec)
            elif len(env.playbook_results) >= turn:
                env.playbook_results[turn - 1] = rec
            else:
                raise ValueError(
                    f"playbook pages must run in order: have "
                    f"{len(env.playbook_results)} results, act turn={turn}"
                )
            elapsed_ms = (time.perf_counter() - t0) * 1000
            return {
                "ok": result.ok,
                "stdout": result.detail,
                "stderr": "" if result.ok else result.detail,
                "exit_code": 0 if result.ok else 1,
                "elapsed_ms": elapsed_ms,
                "node_id": self.cfg.node_id,
                "playbook": rec,
            }
        if action == "incident":
            if self.cfg.scoreboard != "incident":
                raise ValueError(
                    f"action=incident requires GYM_SCOREBOARD=incident "
                    f"(got {self.cfg.scoreboard!r})"
                )
            require_incident_fault(_lease.fault_id)
            if not args:
                raise ValueError("incident act needs turn as args[0]")
            turn = int(args[0])
            t_solve: float | None = None
            if "t_solve_s" in body and body["t_solve_s"] is not None:
                t_solve = float(body["t_solve_s"])
            elif len(args) > 1:
                t_solve = float(args[1])
            probe = _IncidentProbe(env, self)
            try:
                reason = first_fail_reason(probe)
                if reason:
                    clean = False
                    detail = f"soak_fail:{reason}"
                else:
                    clean = soak_clean(probe)
                    detail = "soak_clean" if clean else "soak_fail:window"
            except TetragonProbeError as e:
                clean = False
                detail = f"tetragon probe: {e}"
            rec = {
                "ok": clean,
                "t_solve_s": t_solve,
                "soak_clean": clean,
                "detail": detail,
                "layer_gates": layer_gates(probe),
            }
            if len(env.incident_results) == turn - 1:
                env.incident_results.append(rec)
            elif len(env.incident_results) >= turn:
                env.incident_results[turn - 1] = rec
            else:
                raise ValueError(
                    f"incident turns must run in order: have "
                    f"{len(env.incident_results)} results, act turn={turn}"
                )
            elapsed_ms = (time.perf_counter() - t0) * 1000
            return {
                "ok": clean,
                "stdout": detail,
                "stderr": "" if clean else detail,
                "exit_code": 0 if clean else 1,
                "elapsed_ms": elapsed_ms,
                "node_id": self.cfg.node_id,
                "incident": rec,
            }
        if action == "selfplay":
            if self.cfg.scoreboard != "selfplay":
                raise ValueError(
                    f"action=selfplay requires GYM_SCOREBOARD=selfplay "
                    f"(got {self.cfg.scoreboard!r})"
                )
            require_selfplay_role(env.role)
            if not args:
                raise ValueError("selfplay act needs turn as args[0]")
            turn = int(args[0])
            t_solve: float | None = None
            if "t_solve_s" in body and body["t_solve_s"] is not None:
                t_solve = float(body["t_solve_s"])
            elif len(args) > 1:
                t_solve = float(args[1])
            probe = _SelfplayProbe(env, self)
            try:
                victim_ok = probe.victim_ready()
                payload_ok = probe.payload_productive()
                reason = first_fail_reason(probe)
                if reason:
                    clean = False
                    detail = f"soak_fail:{reason}"
                elif idle_red_skips_hold(env.role, payload_productive=payload_ok):
                    clean = True
                    detail = "soak_clean:idle_red"
                else:
                    clean = soak_clean(probe)
                    detail = "soak_clean" if clean else "soak_fail:window"
            except TetragonProbeError as e:
                clean = False
                victim_ok = probe.victim_ready()
                payload_ok = probe.payload_productive()
                detail = f"tetragon probe: {e}"
            rec = {
                "ok": clean,
                "t_solve_s": t_solve,
                "soak_clean": clean,
                "victim_ready": victim_ok,
                "payload_productive": payload_ok,
                "role": env.role,
                "scenario_id": env.scenario_id,
                "detail": detail,
            }
            if len(env.selfplay_results) == turn - 1:
                env.selfplay_results.append(rec)
            elif len(env.selfplay_results) >= turn:
                env.selfplay_results[turn - 1] = rec
            else:
                raise ValueError(
                    f"selfplay turns must run in order: have "
                    f"{len(env.selfplay_results)} results, act turn={turn}"
                )
            elapsed_ms = (time.perf_counter() - t0) * 1000
            return {
                "ok": clean,
                "stdout": detail,
                "stderr": "" if clean else detail,
                "exit_code": 0 if clean else 1,
                "elapsed_ms": elapsed_ms,
                "node_id": self.cfg.node_id,
                "selfplay": rec,
            }
        raise ValueError(
            f"unknown action {action!r} (supported: exec | kubectl | playbook | incident | selfplay)"
        )

    def obs(self, env_id: str) -> dict[str, Any]:
        found = self.leases.env(env_id)
        if found is None:
            raise KeyError(f"no such env: {env_id}")
        _lease, env = found
        scenario = (
            get_scenario(_lease.scenario_id)
            if _lease.fault_id == SCRIPTED_ID
            else None
        )
        if self.cfg.source_mode == "create":
            members = []
            for cid, ip in zip(env.guest_cids, env.guest_ips):
                try:
                    with self._hold_autowarp(env, "gym-obs"):
                        r = agent.exec_cmd(cid, ["uname", "-a"], timeout_s=5)
                    uname = r["stdout"].strip()
                    alive = r["exit_code"] == 0
                except (OSError, RuntimeError) as e:
                    uname = ""
                    alive = False
                    members.append(
                        {
                            "guest_cid": cid,
                            "guest_ip": ip,
                            "alive": False,
                            "error": str(e),
                        }
                    )
                    continue
                members.append(
                    {
                        "guest_cid": cid,
                        "guest_ip": ip,
                        "alive": alive,
                        "uname": uname,
                    }
                )
            observation: dict[str, Any] = {
                "bridge": env.bridge,
                "members": members,
            }
        else:
            cert, key = self._api_certs()
            ip0 = env.guest_ips[0] if env.guest_ips else "10.200.0.2"
            nodes_code, nodes, nodes_err = curl_api(
                env.bridge, "/api/v1/nodes", guest_ip=ip0, cert=cert, key=key
            )
            pods_code, pods, pods_err = curl_api(
                env.bridge,
                "/api/v1/pods",
                guest_ip=ip0,
                cert=cert,
                key=key,
            )
            observation = {
                "bridge": env.bridge,
                "readyz": curl_readyz(
                    env.bridge, ip0, cert=cert, key=key
                ),
                "nodes": _maybe_json(nodes),
                "pods": _maybe_json(pods),
                "nodes_error": nodes_err if nodes_code >= 400 else "",
                "pods_error": pods_err if pods_code >= 400 else "",
            }
            # The services/links block names the cause (`k3s.service:
            # inactive`, `eth0: down`). A tier >= 1 scenario blinds it,
            # so the model must run an investigate command instead of
            # reading the answer off the observation.
            if self.cfg.source_mode == "ubuntu" and (
                scenario is None or scenario.expose_services
            ):
                self._obs_ubuntu_services(env, observation)
        packed = json.dumps(observation, separators=(",", ":"))
        out = {
            "observation": observation,
            "truncated_bytes": 0,
            "byte_count": len(packed),
            "node_id": self.cfg.node_id,
        }
        if scenario is not None:
            # Envelope, not observation body: the trainer can log the
            # tier without the model seeing it.
            out["scenario_id"] = scenario.scenario_id
            out["scenario_tier"] = scenario.tier
        return out

    def _obs_ubuntu_services(self, env: Env, observation: dict[str, Any]) -> None:
        """k3s unit + eth0 from one vsock exec. Never fabricate active."""
        if not env.guest_cids:
            observation["services_error"] = "obs services: guest_cids empty"
            return
        cmd = "systemctl is-active k3s.service; ip link show eth0 | sed -n 1p"
        try:
            with self._hold_autowarp(env, "gym-obs"):
                r = agent.exec_cmd(
                    env.guest_cids[0], ["sh", "-c", cmd], timeout_s=5
                )
        except (OSError, RuntimeError) as e:
            observation["services_error"] = str(e)
            return
        if int(r.get("exit_code", 1)) != 0:
            observation["services_error"] = (
                f"exit={r.get('exit_code')} stderr={r.get('stderr')!r}"
            )
            return
        stdout = str(r.get("stdout") or "")
        lines = stdout.splitlines()
        if not lines:
            observation["services_error"] = "empty services probe stdout"
            return
        observation["services"] = {"k3s.service": lines[0].strip() or "unknown"}
        link_line = "\n".join(lines[1:])
        up = "<UP" in link_line or ",UP" in link_line
        observation["links"] = {"eth0": "up" if up else "down"}

    def score(self, lease_id: str, turn: int | None = None) -> dict[str, Any]:
        L = self.leases.get(lease_id)
        if L is None:
            raise KeyError(f"no such lease: {lease_id}")
        if self.cfg.scoreboard == "playbook":
            return self._score_playbook(L, turn)
        if self.cfg.scoreboard == "incident":
            return self._score_incident(L, turn)
        if self.cfg.scoreboard == "selfplay":
            return self._score_selfplay(L, turn)
        if self.cfg.scoreboard == "grpo":
            return self._score_grpo(L)
        fault = self._fault_for(L)
        source_alive = self._source_intact()
        contained, restored = self._contain_restore(L, fault)
        if self.cfg.scoreboard == "tetragon":
            return self._score_tetragon(L, fault, source_alive)
        scores = []
        for e in L.envs:
            if self.cfg.source_mode == "create":
                alive = [
                    agent.ping(cid, timeout_s=3) for cid in e.guest_cids
                ]
                if not alive:
                    alive = [False]
                sc = score_create_env(
                    member_alive=alive,
                    source_alive=source_alive,
                    contained=contained,
                    restored=restored,
                )
            else:
                cert, key = self._env_certs(e)
                ip0 = e.guest_ips[0] if e.guest_ips else "10.200.0.2"
                if self.cfg.source_mode == "ubuntu":
                    workload = bool(cert) and curl_nodes_ready(
                        e.bridge, ip0, cert=cert, key=key, want=3
                    )
                else:
                    workload = bool(cert) and curl_inner_load(
                        e.bridge, ip0, cert=cert, key=key
                    )
                sc = score_adopt_env(
                    readyz=curl_readyz(e.bridge, ip0, cert=cert, key=key),
                    workload_ready=workload,
                    source_intact=source_alive,
                    contained=contained,
                    restored=restored,
                )
            scores.append(
                {
                    "env_id": e.env_id,
                    "reward": sc["reward"],
                    "terms": sc["terms"],
                }
            )
        return {"scores": scores, "node_id": self.cfg.node_id}

    def _score_grpo(self, L: Lease) -> dict[str, Any]:
        """Per-member contain/restore. A wrecked fork is a scored 0.

        Members are scored in parallel: a scenario with
        `restored_poll_s` set pays that bound once per group, not once
        per member.
        """
        require_grpo_fault(L.fault_id)
        fault = self._fault_for(L)
        source_alive = self._source_intact()
        rows: dict[str, dict[str, Any]] = {}
        if len(L.envs) == 1:
            e0 = L.envs[0]
            rows[e0.env_id] = self._score_grpo_member(L, e0, fault, source_alive)
        else:
            with ThreadPoolExecutor(max_workers=len(L.envs)) as pool:
                futs = {
                    pool.submit(
                        self._score_grpo_member, L, e, fault, source_alive
                    ): e
                    for e in L.envs
                }
                for fut in as_completed(futs):
                    rows[futs[fut].env_id] = fut.result()
        return {
            "scores": [rows[e.env_id] for e in L.envs],
            "node_id": self.cfg.node_id,
            "scoreboard": "grpo",
        }

    def _score_grpo_member(
        self, L: Lease, e: Env, fault: Any, source_alive: bool
    ) -> dict[str, Any]:
        unreachable = False
        contained = 1.0
        restored = 1.0
        try:
            if not e.guest_cids:
                raise RuntimeError(f"{e.env_id} has no guest_cids")
            # Catalog exec_ok swallows vsock RuntimeError as False,
            # which would pay contained=1 for a wrecked fork.
            # Probe first so a dead guest is unreachable, not 0.4.
            with self._hold_autowarp(e, "gym-score"):
                agent.exec_cmd(e.guest_cids[0], ["true"], timeout_s=5)
            if L.fault_id != "none":
                contained = 0.0 if fault.fault_visible(e) else 1.0
                restored = 1.0 if fault.healthy(e) else 0.0
        except (OSError, RuntimeError) as err:
            log.warning("grpo probe %s: %s", e.env_id, err)
            unreachable = True
        if unreachable:
            t = terms(
                liveness=0.0,
                workload_ready=0.0,
                source_intact=1.0 if source_alive else 0.0,
                contained=0.0,
                restored=0.0,
            )
        else:
            cert, key = self._env_certs(e)
            ip0 = e.guest_ips[0] if e.guest_ips else "10.200.0.2"
            readyz = curl_readyz(e.bridge, ip0, cert=cert, key=key)
            nodes_ok = bool(cert) and curl_nodes_ready(
                e.bridge, ip0, cert=cert, key=key, want=3
            )
            t = terms(
                liveness=1.0 if readyz else 0.0,
                workload_ready=1.0 if nodes_ok else 0.0,
                source_intact=1.0 if source_alive else 0.0,
                contained=contained,
                restored=restored,
            )
        row: dict[str, Any] = {
            "env_id": e.env_id,
            "reward": reward_from_terms(t),
            "terms": t,
        }
        if unreachable:
            row["unreachable"] = True
        return row

    def _score_tetragon(
        self, L: Lease, fault: Any, source_alive: bool
    ) -> dict[str, Any]:
        source_ev = []
        if self.cfg.start_mode == "fork":
            if not self.source_bridge:
                raise RuntimeError("tetragon score: source bridge missing")
            cert, key = self._api_certs()
            if cert is None or key is None:
                raise RuntimeError("tetragon score: ubuntu kube certs missing")
            source_raw = collect_events(
                self.source_bridge, cert=cert, key=key
            )
            source_ev = parse_events(source_raw)
        source_faulty = fault.source_shows_fault(
            guest_cids=self.source_cids,
            bridge=self.source_bridge,
            guest_ips=guest_ips(self.source_vms),
        )
        scores = []
        for e in L.envs:
            cert, key = self._env_certs(e)
            if cert is None or key is None:
                raise RuntimeError(f"tetragon score: certs missing on {e.env_id}")
            ip0 = e.guest_ips[0] if e.guest_ips else "10.200.0.2"
            reachable = True
            try:
                raw = collect_events(e.bridge, cert=cert, key=key, guest_ip=ip0)
                branch_ev = parse_events(raw)
            except TetragonProbeError as err:
                # kill-member-0 stops k3s on sibling 0. Score the row
                # (reward terms go to 0); do not 502 the lease.
                log.warning("tetragon probe %s: %s", e.env_id, err)
                branch_ev = []
                reachable = False
            if self.cfg.start_mode == "reset":
                if not e.baseline_raw:
                    raise RuntimeError(
                        f"tetragon score: reset env {e.env_id} has empty baseline"
                    )
                base = parse_events(e.baseline_raw)
            else:
                base = source_ev
            markers = tuple(getattr(fault, "tetragon_paths", ()) or ())
            diff = event_diff(base, branch_ev, inject_paths=markers)
            if source_faulty and L.fault_id != "none":
                diff.leaked_paths.append(L.fault_id)
            member_restored = fault.healthy(e) if e.index == 0 else True
            if reachable:
                readyz = curl_readyz(e.bridge, ip0, cert=cert, key=key)
                nodes_ok = curl_nodes_ready(
                    e.bridge, ip0, cert=cert, key=key, want=3
                )
            else:
                readyz = False
                nodes_ok = False
            if (
                reachable
                and e.index == 0
                and L.fault_id != "none"
                and not member_restored
                and not diff.branch_only
            ):
                raise RuntimeError(
                    f"tetragon score: inject on {e.env_id} produced no "
                    f"branch-only events (baseline={diff.baseline_size} "
                    f"branch={diff.branch_size})"
                )
            sc = score_tetragon(
                diff=diff,
                health=ClusterHealth(
                    readyz=readyz,
                    nodes_ready=nodes_ok,
                    source_readyz=source_alive,
                    restored=bool(member_restored) if e.index == 0 else True,
                    injected=(e.index == 0 and L.fault_id != "none"),
                    reachable=reachable,
                ),
            )
            scores.append(
                {
                    "env_id": e.env_id,
                    "reward": sc["reward"],
                    "terms": sc["terms"],
                    "event_diff": sc["event_diff"],
                }
            )
        return {"scores": scores, "node_id": self.cfg.node_id, "scoreboard": "tetragon"}

    def _score_incident(self, L: Lease, turn: int | None) -> dict[str, Any]:
        require_incident_fault(L.fault_id)
        if turn is None:
            raise ValueError("incident score needs turn (1-based)")
        turn_i = int(turn)
        for e in L.envs:
            recs = list(e.incident_results)
            if len(recs) < turn_i:
                raise ValueError(
                    f"incident score turn={turn_i} but {e.env_id} has "
                    f"{len(recs)} results (act each turn first)"
                )
            if "soak_clean" not in recs[turn_i - 1]:
                raise ValueError(
                    f"incident score missing incident payload on {e.env_id} "
                    f"turn={turn_i}"
                )
        source_alive = self._source_intact()
        scores = []
        for e in L.envs:
            rec = e.incident_results[turn_i - 1]
            clean = bool(rec.get("soak_clean"))
            t_solve = rec.get("t_solve_s")
            if t_solve is not None:
                t_solve = float(t_solve)
            r = reward_from_solve(t_solve if clean else None, T_BUDGET_S)
            cert, key = self._env_certs(e)
            ip0 = e.guest_ips[0] if e.guest_ips else "10.200.0.2"
            readyz = bool(cert) and curl_readyz(
                e.bridge, ip0, cert=cert, key=key
            )
            scores.append(
                {
                    "env_id": e.env_id,
                    "reward": r,
                    "terms": terms(
                        liveness=1.0 if readyz else 0.0,
                        workload_ready=1.0 if readyz else 0.0,
                        source_intact=1.0 if source_alive else 0.0,
                        contained=1.0 if clean else 0.0,
                        restored=1.0 if clean else 0.0,
                    ),
                    "incident": {
                        "turn": turn_i,
                        "t_solve_s": t_solve,
                        "soak_clean": clean,
                        "layer_gates": rec.get("layer_gates") or {},
                    },
                }
            )
        return {
            "scores": scores,
            "node_id": self.cfg.node_id,
            "scoreboard": "incident",
        }

    def _score_selfplay(self, L: Lease, turn: int | None) -> dict[str, Any]:
        role = str(L.extra.get("role") or "") if L.extra else ""
        require_selfplay_role(role)
        scenario_id = str(L.extra.get("scenario_id") or "") if L.extra else ""
        if turn is None:
            raise ValueError("selfplay score needs turn (1-based)")
        turn_i = int(turn)
        scored_envs = [e for e in L.envs if len(e.selfplay_results) >= turn_i]
        if not scored_envs:
            raise ValueError(
                f"selfplay score turn={turn_i} but no env has a soak "
                "(act the env that moved first)"
            )
        for e in scored_envs:
            rec = e.selfplay_results[turn_i - 1]
            for key in ("soak_clean", "victim_ready", "payload_productive"):
                if key not in rec:
                    raise ValueError(
                        f"selfplay score missing {key} on {e.env_id} "
                        f"turn={turn_i}"
                    )
        source_alive = self._source_intact()
        scores = []
        for e in scored_envs:
            rec = e.selfplay_results[turn_i - 1]
            clean = bool(rec.get("soak_clean"))
            victim_ok = bool(rec.get("victim_ready"))
            payload_ok = bool(rec.get("payload_productive"))
            t_solve = rec.get("t_solve_s")
            if t_solve is not None:
                t_solve = float(t_solve)
            r = signed_reward(
                role,
                t_solve=t_solve,
                soak_clean=clean,
                victim_ready=victim_ok,
                payload_productive=payload_ok,
                t_budget=T_BUDGET_S,
            )
            scores.append(
                {
                    "env_id": e.env_id,
                    "reward": r,
                    "terms": terms(
                        liveness=1.0 if victim_ok else 0.0,
                        workload_ready=1.0 if victim_ok else 0.0,
                        source_intact=1.0 if source_alive else 0.0,
                        contained=1.0 if clean else 0.0,
                        restored=1.0 if clean else 0.0,
                    ),
                    "selfplay": {
                        "role": role,
                        "scenario_id": scenario_id,
                        "turn": turn_i,
                        "t_solve_s": t_solve,
                        "soak_clean": clean,
                        "victim_ready": victim_ok,
                        "payload_productive": payload_ok,
                    },
                }
            )
        return {
            "scores": scores,
            "node_id": self.cfg.node_id,
            "scoreboard": "selfplay",
        }

    def _score_playbook(self, L: Lease, turn: int | None) -> dict[str, Any]:
        refuse_inject_fault(L.fault_id)
        if turn is None:
            raise ValueError("playbook score needs turn (1-based page index)")
        turn_i = int(turn)
        for e in L.envs:
            recs = list(e.playbook_results)
            if len(recs) < turn_i:
                raise ValueError(
                    f"playbook score turn={turn_i} but {e.env_id} has "
                    f"{len(recs)} page results (act each page first)"
                )
        source_alive = self._source_intact()
        scores = []
        for e in L.envs:
            recs = list(e.playbook_results)
            results = [
                PageResult(
                    ok=bool(r["ok"]),
                    elapsed_s=float(r["elapsed_s"]),
                    detail=str(r.get("detail") or ""),
                )
                for r in recs[:turn_i]
            ]
            sc = score_from_results(results, turn_i)
            if "playbook" not in sc:
                raise RuntimeError("score_from_results omitted playbook payload")
            cert, key = self._env_certs(e)
            ip0 = e.guest_ips[0] if e.guest_ips else "10.200.0.2"
            readyz = bool(cert) and curl_readyz(
                e.bridge, ip0, cert=cert, key=key
            )
            workload = False
            if turn_i >= 7:
                code, body, _err = curl_api(
                    e.bridge,
                    "/apis/apps/v1/namespaces/k7-exam/deployments/web",
                    guest_ip=ip0,
                    cert=cert,
                    key=key,
                )
                if 200 <= code < 300:
                    try:
                        avail = int(
                            (json.loads(body).get("status") or {}).get(
                                "availableReplicas"
                            )
                            or 0
                        )
                    except (json.JSONDecodeError, TypeError, ValueError):
                        avail = 0
                    want = {12: 2, 13: 2, 14: 3, 15: 3, 16: 3, 17: 3}.get(
                        turn_i, 1
                    )
                    if turn_i >= 18:
                        want = 1
                    workload = avail >= want
            sc["terms"] = diagnostic_terms(
                readyz=readyz,
                workload_ready=workload,
                source_intact=source_alive,
                fault_id=L.fault_id,
            )
            scores.append(
                {
                    "env_id": e.env_id,
                    "reward": sc["reward"],
                    "terms": sc["terms"],
                    "playbook": sc["playbook"],
                }
            )
        return {
            "scores": scores,
            "node_id": self.cfg.node_id,
            "scoreboard": "playbook",
        }

    def _env_certs(self, env: Env) -> tuple[Path | None, Path | None]:
        if env.cert_path and env.key_path:
            cert, key = Path(env.cert_path), Path(env.key_path)
            if cert.is_file() and key.is_file():
                return cert, key
        return self._api_certs()

    def _contain_restore(self, L: Lease, fault: Any) -> tuple[float, float]:
        """Group-level contain/restore. Never defaulted — always computed."""
        source_faulty = fault.source_shows_fault(
            guest_cids=self.source_cids,
            bridge=self.source_bridge,
            guest_ips=guest_ips(self.source_vms),
        )
        target = next((e for e in L.envs if e.index == 0), None)
        if target is None:
            raise RuntimeError(f"lease {L.lease_id} has no env index 0")
        on_target = fault.fault_visible(target)
        healthy = fault.healthy(target)
        leaked = source_faulty or any(
            fault.fault_visible(e) for e in L.envs if e.index != 0
        )
        # Isolation holds when siblings+source are clean and the target
        # either still shows the fault or has been restored (healthy).
        # A silent no-op inject is (not on_target) and (not healthy) → 0.
        contained = 1.0 if (not leaked) and (on_target or healthy) else 0.0
        restored = 1.0 if healthy else 0.0
        return contained, restored

    def _api_certs(self) -> tuple[Path | None, Path | None]:
        if self.cfg.source_mode == "ubuntu":
            if self.ubuntu_cert is not None and self.ubuntu_key is not None:
                return self.ubuntu_cert, self.ubuntu_key
            dest = ubuntu_src.certs_dir(self.cfg.source_tree_id)
            cert, key = dest / "client.pem", dest / "client-key.pem"
            if cert.is_file() and key.is_file():
                return cert, key
            return None, None
        return _adopt_certs()

    def _source_intact(self) -> bool:
        if self.cfg.start_mode == "reset":
            # No shared checkpoint — nothing for a member to leak into.
            return True
        if self.cfg.source_mode in ("adopt", "ubuntu") and self.source_bridge:
            cert, key = self._api_certs()
            return curl_readyz(
                self.source_bridge, cert=cert, key=key
            )
        if self.source_cids:
            return all(agent.ping(c, timeout_s=3) for c in self.source_cids)
        # Reused source without stored CIDs: treat the source tree root
        # still being listed as intact — a missing tree is a hard fail.
        return "root" in self.tree_node_ids(self.cfg.source_tree_id)


class LeaseRejected(Exception):
    def __init__(self, message: str) -> None:
        super().__init__(message)
        self.message = message


class ForkRejected(Exception):
    """Mid-episode budget refusal. HTTP 409 — no fork has started."""

    def __init__(self, message: str) -> None:
        super().__init__(message)
        self.message = message


def _adopt_certs() -> tuple[Path | None, Path | None]:
    cert = INNER3_CERTS / "client.pem"
    key = INNER3_CERTS / "client-key.pem"
    if cert.is_file() and key.is_file():
        return cert, key
    return None, None


def _taps_for_bridges(bridges: list[str]) -> list[str]:
    taps = list_taps()
    out = []
    for br in bridges:
        brif = Path(f"/sys/class/net/{br}/brif")
        if not brif.is_dir():
            continue
        for p in brif.iterdir():
            if p.name in taps:
                out.append(p.name)
    return out


def _maybe_json(text: str) -> Any:
    try:
        return json.loads(text)
    except (json.JSONDecodeError, TypeError):
        return text


def discover_inner3_vm_ids(client: K7dClient) -> list[str]:
    import subprocess

    indexed: list[tuple[int, str]] = []
    for pod in INNER3_PODS:
        cid = subprocess.run(
            ["k3s", "crictl", "pods", "-q", "--name", pod],
            check=False,
            capture_output=True,
            text=True,
        )
        sandbox_id = (cid.stdout or "").strip().splitlines()
        if not sandbox_id:
            raise RuntimeError(
                f"no CRI sandbox for pod {pod} (is it Running?): {cid.stderr}"
            )
        found = client.call({"op": "lookup_sandbox", "sandbox_id": sandbox_id[0]})
        if found.get("status") != "sandbox_found":
            raise RuntimeError(f"lookup_sandbox({sandbox_id[0]}): {found}")
        vm_index = found.get("vm_index")
        if vm_index is None:
            raise RuntimeError(
                f"pod {pod}: lookup_sandbox missing vm_index: {found}"
            )
        indexed.append((int(vm_index), found["vm_id"]))
    indexed.sort(key=lambda t: t[0])
    for i, (idx, _) in enumerate(indexed):
        if idx != i:
            raise RuntimeError(
                f"tree_adopt_cluster precondition: vm_index gap: "
                f"expected {i}, got {idx} in {indexed}"
            )
    return [vm_id for _, vm_id in indexed]


def extract_inner_certs() -> None:
    import base64
    import re
    import subprocess

    raw = subprocess.run(
        [
            "kubectl",
            "exec",
            INNER3_PODS[0],
            "-c",
            "k3s",
            "--",
            "cat",
            "/etc/rancher/k3s/k3s.yaml",
        ],
        check=True,
        capture_output=True,
        text=True,
    ).stdout
    cert_b64 = re.search(r"client-certificate-data:\s*(\S+)", raw)
    key_b64 = re.search(r"client-key-data:\s*(\S+)", raw)
    if not cert_b64 or not key_b64:
        raise RuntimeError("could not parse client cert/key from inner kubeconfig")
    INNER3_CERTS.mkdir(parents=True, exist_ok=True)
    (INNER3_CERTS / "client.pem").write_bytes(base64.b64decode(cert_b64.group(1)))
    (INNER3_CERTS / "client-key.pem").write_bytes(base64.b64decode(key_b64.group(1)))


def raise_nofile(min_fds: int = 65536) -> None:
    try:
        import resource

        soft, hard = resource.getrlimit(resource.RLIMIT_NOFILE)
        want = min(max(min_fds, soft), hard)
        if want > soft:
            resource.setrlimit(resource.RLIMIT_NOFILE, (want, hard))
            log.info("RLIMIT_NOFILE %s → %s (hard=%s)", soft, want, hard)
    except (ValueError, OSError) as e:
        log.warning("could not raise RLIMIT_NOFILE: %s", e)


class Handler(BaseHTTPRequestHandler):
    gym: Gym

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
        token = self.gym.cfg.token
        if not token:
            return True
        got = self.headers.get("X-Gym-Token")
        if got != token:
            self._send(401, {"error": "missing or wrong X-Gym-Token"})
            return False
        return True

    def _send(self, code: int, body: dict[str, Any]) -> None:
        body.setdefault("node_id", self.gym.cfg.node_id)
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
                ok, msg = self.gym.k7d_ready()
                if not ok:
                    self._send(
                        503,
                        {
                            "ok": False,
                            "k7d": "unavailable",
                            "error": msg,
                            "leases_in_flight": self.gym.leases.in_flight(),
                            "max_leases": self.gym.cfg.max_leases,
                        },
                    )
                    return
                self._send(
                    200,
                    {
                        "ok": True,
                        "k7d": "ready",
                        "free_ram_bytes": free_ram_bytes(),
                        "leases_in_flight": self.gym.leases.in_flight(),
                        "max_leases": self.gym.cfg.max_leases,
                    },
                )
                return
            if path.startswith("/lease/"):
                lid = path[len("/lease/") :]
                L = self.gym.leases.get(lid)
                if L is None:
                    self._send(404, {"error": f"no such lease: {lid}"})
                    return
                self._send(200, L.as_public())
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
                try:
                    self._send(200, self.gym.lease(body, self.address_string()))
                except LeaseRejected as e:
                    self._send(400, {"error": e.message})
                return
            if path.endswith("/act") and path.startswith("/env/"):
                env_id = path[len("/env/") : -len("/act")]
                self._send(200, self.gym.act(env_id, body))
                return
            if path.endswith("/obs") and path.startswith("/env/"):
                env_id = path[len("/env/") : -len("/obs")]
                self._send(200, self.gym.obs(env_id))
                return
            if path.endswith("/prepare") and path.startswith("/env/"):
                env_id = path[len("/env/") : -len("/prepare")]
                self._send(200, self.gym.prepare_env(env_id))
                return
            if path.endswith("/fork") and path.startswith("/env/"):
                env_id = path[len("/env/") : -len("/fork")]
                try:
                    self._send(200, self.gym.fork_env(env_id, body))
                except ForkRejected as e:
                    self._send(409, {"error": e.message})
                return
            if path.endswith("/score") and path.startswith("/lease/"):
                lid = path[len("/lease/") : -len("/score")]
                turn = body.get("turn")
                self._send(
                    200,
                    self.gym.score(
                        lid, turn=int(turn) if turn is not None else None
                    ),
                )
                return
            if path.endswith("/release") and path.startswith("/lease/"):
                lid = path[len("/lease/") : -len("/release")]
                self._send(200, self.gym.release(lid, reason="client"))
                return
            self._send(404, {"error": f"no such path: {path}"})
        except KeyError as e:
            self._send(404, {"error": str(e)})
        except ValueError as e:
            self._send(400, {"error": str(e)})
        except RuntimeError as e:
            # k7d messages stay verbatim — no wrapping that hides BudgetExhausted.
            self._send(502, {"error": str(e)})
        except Exception as e:
            log.exception("POST %s", path)
            self._send(500, {"error": f"{e}\n{traceback.format_exc()}"})


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    env = os.environ
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--bind", default=env.get("GYM_BIND", "127.0.0.1"))
    p.add_argument("--port", type=int, default=int(env.get("GYM_PORT", "8080")))
    p.add_argument(
        "--node-id",
        default=env.get("GYM_NODE_ID") or socket.gethostname(),
    )
    p.add_argument(
        "--source-mode",
        choices=("create", "adopt", "ubuntu"),
        default=env.get("GYM_SOURCE_MODE", "create"),
    )
    p.add_argument(
        "--start-mode",
        choices=("fork", "reset"),
        default=env.get("GYM_START_MODE", "fork"),
    )
    _reset_ack = env.get("GYM_RESET_MEASUREMENT", "") in ("1", "true", "yes")
    p.add_argument(
        "--reset-measurement",
        action="store_true",
        default=_reset_ack,
        help="required acknowledgement that reset is measurement-only",
    )
    p.add_argument(
        "--scoreboard",
        choices=(
            "health",
            "tetragon",
            "playbook",
            "incident",
            "selfplay",
            "grpo",
        ),
        default=env.get("GYM_SCOREBOARD", "health"),
    )
    p.add_argument(
        "--ready-gate",
        default=env.get("GYM_READY_GATE", ""),
        help="nodes (default) or api. playbook/incident force api.",
    )
    p.add_argument(
        "--source-tree-id",
        default=env.get("GYM_SOURCE_TREE_ID") or f"gym-src-{os.getpid()}",
    )
    p.add_argument(
        "--scenario-dir",
        default=env.get("GYM_SCENARIO_DIR", ""),
        help="k7-scenarios scenarios/ root. Loaded at start; every "
        "scenario becomes fault_id=scripted + scenario_id=<id>. "
        "Unset means no scripted scenarios.",
    )
    p.add_argument("--socket", default=env.get("K7D_SOCKET", "/run/k7d/k7d.sock"))
    p.add_argument(
        "--max-leases", type=int, default=int(env.get("GYM_MAX_LEASES", "4"))
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
        "--max-disk-bytes",
        type=int,
        default=int(env.get("GYM_MAX_DISK_BYTES", str(256 * 1024**3))),
    )
    p.add_argument(
        "--vm-count", type=int, default=int(env.get("GYM_VM_COUNT", "3"))
    )
    p.add_argument(
        "--memory-mb", type=int, default=int(env.get("GYM_MEMORY_MB", "256"))
    )
    p.add_argument(
        "--ttl-default-s",
        type=float,
        default=float(env.get("GYM_TTL_DEFAULT_S", "300")),
    )
    p.add_argument(
        "--reaper-interval-s",
        type=float,
        default=float(env.get("GYM_REAPER_INTERVAL_S", "1")),
    )
    p.add_argument("--token", default=env.get("GYM_TOKEN", ""))
    p.add_argument(
        "--kernel",
        default=env.get("K7D_KERNEL", str(REPO / "guest/kernel/vmlinux")),
    )
    p.add_argument(
        "--initrd",
        default=env.get(
            "K7D_INITRD", str(REPO / "guest/rootfs/initramfs.cpio.gz")
        ),
    )
    p.add_argument(
        "--tree-prefix", default=env.get("GYM_TREE_PREFIX", "gym-")
    )
    p.add_argument(
        "--k7d-timeout-s",
        type=float,
        default=float(env.get("GYM_K7D_TIMEOUT_S", "120")),
    )
    p.add_argument(
        "--autowarp-mode",
        default=env.get("GYM_AUTOWARP_MODE", "off"),
        help="Default time-compression mode when POST /lease omits "
        "autowarp_mode (off|jump|micro|dilate). off is today's "
        "contract: no policy loop and no CreateVm dilation. dilate "
        "is N=8 at CreateVm and requires ubuntu; on start-mode=fork "
        "it dilates the shared source and every lease inherits it.",
    )
    return p.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )
    cfg = Config(parse_args(argv))
    raise_nofile()
    gym = Gym(cfg)
    ok, msg = gym.k7d_ready()
    if not ok:
        raise SystemExit(f"k7d not ready: {msg}")
    gym.startup_sweep()
    log.info("preparing source mode=%s tree=%s", cfg.source_mode, cfg.source_tree_id)
    gym.prepare_source()
    gym.start_reaper()

    Handler.gym = gym
    httpd = ThreadingHTTPServer((cfg.bind, cfg.port), Handler)
    host, port = httpd.server_address[:2]
    print(f"GYM_LISTEN={host}:{port}", flush=True)
    log.info("listening on %s:%s node_id=%s", host, port, cfg.node_id)
    if cfg.scenario_dir:
        log.info(
            "scenario pack: %d scenarios from %s",
            cfg.scenario_count,
            cfg.scenario_dir,
        )

    def stop(signum: int, _frame: Any) -> None:
        log.info("signal %s, shutting down", signum)
        gym.shutdown()
        threading.Thread(target=httpd.shutdown, daemon=True).start()

    signal.signal(signal.SIGTERM, stop)
    signal.signal(signal.SIGINT, stop)
    try:
        httpd.serve_forever()
    finally:
        httpd.server_close()
        gym.shutdown()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
