"""Scenario directory → validated spec. No PyYAML, no silent defaults.

One scenario is `scenario.yaml` plus four POSIX-sh scripts
(inject / contain / restore / wreck). This module is the single
definition of what a valid
scenario is: the gym refuses to start on a bad one, and the
`k7-scenarios` validator vendors this file verbatim so the catalog
cannot disagree with the runtime about it.

The YAML subset is deliberately tiny — scalars, one-level maps, and
lists of scalars. Anything else is a loud parse error, not a partial
read.
"""

from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path
from typing import Any

SCRIPTS = ("inject.sh", "visible.sh", "restored.sh", "reference-fix.sh")
MAX_SCRIPT_BYTES = 8192

REQUIRED_KEYS = (
    "id",
    "fault_type",
    "variant",
    "tier",
    "summary",
    "symptom",
    "inject_timeout_s",
    "probe_timeout_s",
    "restored_poll_s",
    "obs",
    "hit_regex",
    "wreck",
)
OPTIONAL_KEYS = (
    "params",
    "decoy",
    "floor_ceiling",
    "floor_reward",
    "fix_reward",
)
# What a no-op member may score. 0.4 is the control-plane case: the
# fault takes `liveness` and `workload_ready` down with it, so only
# `source_intact` is paid. A kubectl-level fault leaves the API up and
# three nodes Ready, so its structural floor is 0.6 and the scenario
# must say so rather than the harness quietly accepting anything.
DEFAULT_FLOOR_CEILING = 0.4
OBS_KEYS = ("expose_services", "must_match", "must_not_match")
DECOY_KEYS = ("command", "expect_reward_le")

# (key, low, high) — inclusive. A scenario outside a bound is a bug in
# the scenario, not something to clamp.
BOUNDS = (
    ("tier", 0, 3),
    ("inject_timeout_s", 5, 180),
    ("probe_timeout_s", 3, 20),
    ("restored_poll_s", 0, 60),
)

_BASHISMS = (
    (r"\[\[", "[[ ]] test"),
    (r"\]\]", "[[ ]] test"),
    (r"\bfunction\s+[A-Za-z_]", "`function` keyword"),
    (r"\$'", "$'...' quoting"),
    (r"(?m)^\s*local\s", "`local`"),
    (r"<<<", "here-string"),
    (r"\$\{!", "indirect expansion"),
    (r"\bpushd\b|\bpopd\b", "pushd/popd"),
    (r"(?m)^\s*source\s", "`source` (use `.`)"),
    (r"\becho\s+-e\b", "echo -e"),
)


class ScenarioError(ValueError):
    """Loud, path-carrying rejection. Never raised without a reason."""


# --------------------------------------------------------------------
# YAML subset


def _strip_comment(line: str) -> str:
    out: list[str] = []
    quote = ""
    for ch in line:
        if quote:
            out.append(ch)
            if ch == quote:
                quote = ""
            continue
        if ch in "'\"":
            quote = ch
            out.append(ch)
            continue
        if ch == "#":
            break
        out.append(ch)
    return "".join(out).rstrip()


def _scalar(raw: str) -> Any:
    text = raw.strip()
    if text == "[]":
        return []
    if len(text) >= 2 and text[0] == text[-1] and text[0] in "'\"":
        return text[1:-1]
    low = text.lower()
    if low in ("true", "false"):
        return low == "true"
    if re.fullmatch(r"-?\d+", text):
        return int(text)
    if re.fullmatch(r"-?\d+\.\d+", text):
        return float(text)
    if not text:
        raise ScenarioError("empty scalar; quote it if you meant an empty string")
    return text


def _lines(text: str) -> list[tuple[int, str]]:
    out: list[tuple[int, str]] = []
    for n, raw in enumerate(text.splitlines(), 1):
        if "\t" in raw:
            raise ScenarioError(f"line {n}: tab indentation is not allowed")
        body = _strip_comment(raw)
        if not body.strip():
            continue
        out.append((len(body) - len(body.lstrip(" ")), body.strip()))
    return out


def _block(lines: list[tuple[int, str]], i: int, indent: int) -> tuple[Any, int]:
    if lines[i][1].startswith("- "):
        items: list[Any] = []
        while i < len(lines) and lines[i][0] == indent and lines[i][1].startswith("- "):
            items.append(_scalar(lines[i][1][2:]))
            i += 1
        return items, i
    out: dict[str, Any] = {}
    while i < len(lines) and lines[i][0] == indent:
        body = lines[i][1]
        if ":" not in body:
            raise ScenarioError(f"not a `key: value` line: {body!r}")
        key, _, rest = body.partition(":")
        key = key.strip()
        if not key:
            raise ScenarioError(f"empty key in {body!r}")
        if key in out:
            raise ScenarioError(f"duplicate key {key!r}")
        i += 1
        if rest.strip():
            out[key] = _scalar(rest)
            continue
        if i >= len(lines) or lines[i][0] <= indent:
            raise ScenarioError(f"key {key!r} has no value and no nested block")
        out[key], i = _block(lines, i, lines[i][0])
    return out, i


def parse_yaml(text: str) -> dict[str, Any]:
    """Parse the scenario YAML subset. Anything unsupported is loud."""
    lines = _lines(text)
    if not lines:
        raise ScenarioError("empty scenario.yaml")
    if lines[0][0] != 0:
        raise ScenarioError("scenario.yaml must start at column 0")
    doc, i = _block(lines, 0, 0)
    if i != len(lines):
        raise ScenarioError(f"unparsed line at indent {lines[i][0]}: {lines[i][1]!r}")
    if not isinstance(doc, dict):
        raise ScenarioError("scenario.yaml top level must be a mapping")
    return doc


# --------------------------------------------------------------------
# Validation


def _require_keys(
    got: dict[str, Any], required: tuple[str, ...], optional: tuple[str, ...], where: str
) -> None:
    missing = [k for k in required if k not in got]
    if missing:
        raise ScenarioError(f"{where}: missing keys {missing}")
    unknown = sorted(set(got) - set(required) - set(optional))
    if unknown:
        raise ScenarioError(f"{where}: unknown keys {unknown}")


def _regex_list(value: Any, where: str) -> list[str]:
    if not isinstance(value, list) or not all(isinstance(v, str) for v in value):
        raise ScenarioError(f"{where} must be a list of regex strings, got {value!r}")
    for pat in value:
        if not pat.strip():
            raise ScenarioError(f"{where}: empty regex matches everything")
        try:
            re.compile(pat)
        except re.error as err:
            raise ScenarioError(f"{where}: bad regex {pat!r}: {err}") from err
    return list(value)


def validate_spec(spec: dict[str, Any], *, rel_id: str | None = None) -> dict[str, Any]:
    """Check a parsed scenario.yaml. Returns it unchanged, or raises."""
    _require_keys(spec, REQUIRED_KEYS, OPTIONAL_KEYS, "scenario.yaml")
    for key in ("id", "fault_type", "variant", "summary", "symptom", "hit_regex", "wreck"):
        if not isinstance(spec[key], str) or not spec[key].strip():
            raise ScenarioError(f"{key} must be a non-empty string, got {spec[key]!r}")
    for key, low, high in BOUNDS:
        val = spec[key]
        if not isinstance(val, int) or isinstance(val, bool):
            raise ScenarioError(f"{key} must be an int, got {val!r}")
        if not low <= val <= high:
            raise ScenarioError(f"{key}={val} out of range {low}..{high}")
    want = f"{spec['fault_type']}/{spec['variant']}"
    if spec["id"] != want:
        raise ScenarioError(f"id {spec['id']!r} != fault_type/variant {want!r}")
    if rel_id is not None and spec["id"] != rel_id:
        raise ScenarioError(f"id {spec['id']!r} != directory path {rel_id!r}")
    _regex_list([spec["hit_regex"]], "hit_regex")

    params = spec.get("params", {})
    if not isinstance(params, dict):
        raise ScenarioError(f"params must be a mapping, got {params!r}")
    for key, val in params.items():
        if not re.fullmatch(r"[a-z][a-z0-9_]*", key):
            raise ScenarioError(f"param key {key!r} must be lower_snake_case")
        if isinstance(val, (dict, list)):
            raise ScenarioError(f"param {key!r} must be a scalar, got {val!r}")

    obs = spec["obs"]
    if not isinstance(obs, dict):
        raise ScenarioError(f"obs must be a mapping, got {obs!r}")
    _require_keys(obs, OBS_KEYS, (), "obs")
    if not isinstance(obs["expose_services"], bool):
        raise ScenarioError(
            f"obs.expose_services must be a bool, got {obs['expose_services']!r}"
        )
    must = _regex_list(obs["must_match"], "obs.must_match")
    must_not = _regex_list(obs["must_not_match"], "obs.must_not_match")
    if not must:
        raise ScenarioError("obs.must_match must name at least one symptom regex")
    tier = int(spec["tier"])
    if tier == 0 and not obs["expose_services"]:
        raise ScenarioError("tier 0 is a reference scenario: obs.expose_services must be true")
    if tier >= 1:
        if obs["expose_services"]:
            raise ScenarioError(
                f"tier {tier} must blind the obs: obs.expose_services must be false"
            )
        if not must_not:
            raise ScenarioError(
                f"tier {tier} must list the cause words it hides in obs.must_not_match"
            )

    decoy = spec.get("decoy")
    if decoy is not None:
        if not isinstance(decoy, dict):
            raise ScenarioError(f"decoy must be a mapping, got {decoy!r}")
        _require_keys(decoy, DECOY_KEYS, (), "decoy")
        if not isinstance(decoy["command"], str) or not decoy["command"].strip():
            raise ScenarioError(f"decoy.command must be a command, got {decoy['command']!r}")
        cap = decoy["expect_reward_le"]
        if not isinstance(cap, (int, float)) or isinstance(cap, bool) or not 0.0 <= cap <= 1.0:
            raise ScenarioError(f"decoy.expect_reward_le must be in 0..1, got {cap!r}")

    for key in ("floor_ceiling", "floor_reward", "fix_reward"):
        if key in spec:
            val = spec[key]
            if isinstance(val, bool) or not isinstance(val, (int, float)):
                raise ScenarioError(f"{key} must be a number, got {val!r}")
            if not 0.0 <= float(val) <= 1.0:
                raise ScenarioError(f"{key}={val} out of range 0..1")
    return spec


def lint_script(name: str, text: str) -> None:
    """Reject anything the Ubuntu guest's dash would not run the same."""
    raw = text.encode()
    if len(raw) > MAX_SCRIPT_BYTES:
        raise ScenarioError(f"{name}: {len(raw)} bytes > {MAX_SCRIPT_BYTES} limit")
    if not text.startswith("#!/bin/sh\n"):
        raise ScenarioError(f"{name}: first line must be exactly '#!/bin/sh'")
    if not re.search(r"(?m)^set -eu$", text):
        raise ScenarioError(f"{name}: missing a 'set -eu' line")
    for pattern, label in _BASHISMS:
        if re.search(pattern, text):
            raise ScenarioError(f"{name}: bashism ({label}); scripts run under dash")
    if re.search(r"(?m)^\s*(reboot|shutdown|poweroff)\b", text):
        raise ScenarioError(f"{name}: must not reboot the guest")


def env_prelude(spec: dict[str, Any]) -> str:
    """`export` lines the gym prepends to every script text."""
    pairs = [
        ("K7S_ID", str(spec["id"])),
        ("K7S_FAULT_TYPE", str(spec["fault_type"])),
        ("K7S_VARIANT", str(spec["variant"])),
        ("K7S_TIER", str(spec["tier"])),
    ]
    for key, val in sorted((spec.get("params") or {}).items()):
        text = "true" if val is True else "false" if val is False else str(val)
        pairs.append(("K7S_" + key.upper(), text))
    return "".join(f"export {k}='{v}'\n" for k, v in pairs)


def scenario_digest(spec: dict[str, Any], scripts: dict[str, str]) -> str:
    """Fingerprint of one scenario as the gym holds it.

    The gym loads the registry once at start, so a synced-but-not-
    restarted stack silently injects the previous version of a script
    while a harness reads the new one off disk. The lease carries this
    digest so that mismatch is a loud failure instead of a puzzling
    reward.
    """
    h = hashlib.sha256()
    h.update(json.dumps(spec, sort_keys=True, separators=(",", ":")).encode())
    for name in SCRIPTS:
        h.update(b"\0" + name.encode() + b"\0")
        h.update(scripts[name].encode())
    return h.hexdigest()[:16]


def load_scenario(scenario_dir: Path, *, rel_id: str | None = None) -> tuple[dict, dict]:
    """(spec, scripts) for one directory. Every failure names the path."""
    d = Path(scenario_dir)
    yaml_path = d / "scenario.yaml"
    if not yaml_path.is_file():
        raise FileNotFoundError(f"no scenario.yaml in {d}")
    try:
        spec = validate_spec(parse_yaml(yaml_path.read_text()), rel_id=rel_id)
    except ScenarioError as err:
        raise ScenarioError(f"{yaml_path}: {err}") from err
    scripts: dict[str, str] = {}
    for name in SCRIPTS:
        path = d / name
        if not path.is_file():
            raise FileNotFoundError(f"no {name} in {d}")
        text = path.read_text()
        try:
            lint_script(name, text)
        except ScenarioError as err:
            raise ScenarioError(f"{path}: {err}") from err
        scripts[name] = text
    return spec, scripts


def scenario_dirs(root: Path) -> list[tuple[str, Path]]:
    """(id, dir) for every scenario under `root`, sorted. Depth is exactly 2."""
    base = Path(root)
    if not base.is_dir():
        raise FileNotFoundError(f"scenario root is not a directory: {base}")
    found: list[tuple[str, Path]] = []
    for yaml_path in sorted(base.glob("*/*/scenario.yaml")):
        d = yaml_path.parent
        found.append((f"{d.parent.name}/{d.name}", d))
    stray = [
        str(p)
        for p in sorted(base.rglob("scenario.yaml"))
        if p.parent.parent.parent != base
    ]
    if stray:
        raise ScenarioError(
            f"scenario.yaml must live at <root>/<fault_type>/<variant>/; stray: {stray}"
        )
    return found
