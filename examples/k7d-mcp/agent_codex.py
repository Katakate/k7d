#!/usr/bin/env python3
"""Launch OpenAI Codex CLI (Apache-2.0) as the inc1 incident agent.

A drop-in for the `cursor-agent` CLI shape that `scenario_incident.py
--policy cursor-agent` launches (`agent --mcp-config CFG --print
PROMPT`). Translates the cursor-style MCP config into an ephemeral
`CODEX_HOME/config.toml` that points Codex at the untouched
`server.py` MCP server and at OpenRouter (OpenAI-compatible), then
runs `codex exec`. No harness, gym, or tool-surface changes.

Model: `OPENROUTER_MODEL` (default x-ai/grok-4.6). Reasoning effort:
`OPENROUTER_REASONING_EFFORT` (default high). Key: `OPENROUTER_API_KEY`
env or a 0600 key file (same locations as `examples/k7view/llm.py`).
Install: drop the release binary from github.com/openai/codex on PATH
as `codex`, then `ln -s .../agent_codex.py /usr/local/bin/agent` (or a
2-line sh shim).
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
import tempfile
import urllib.request
from pathlib import Path

DEFAULT_MODEL = os.environ.get("OPENROUTER_MODEL", "x-ai/grok-4.6")
# Reasoning effort passed to Codex (`model_reasoning_effort`). Default
# high; override per run with OPENROUTER_REASONING_EFFORT (e.g. medium).
DEFAULT_REASONING = os.environ.get("OPENROUTER_REASONING_EFFORT", "high")


def api_key() -> str:
    env = (os.environ.get("OPENROUTER_API_KEY") or "").strip()
    if env:
        return env
    for p in (Path("/root/.k7view-openrouter"), Path("/tmp/k7view-openrouter")):
        if p.is_file():
            raw = p.read_text().strip()
            if raw:
                return raw
    raise SystemExit("OPENROUTER_API_KEY not set and no key file found")


def toml_str(s: str) -> str:
    return json.dumps(s)  # JSON string escaping is valid TOML


def write_config(codex_home: Path, model: str, server: dict) -> None:
    lines = [
        f"model = {toml_str(model)}",
        'model_provider = "openrouter"',
        f"model_reasoning_effort = {toml_str(DEFAULT_REASONING)}",
        "model_context_window = 500000",
        'approval_policy = "never"',
        'sandbox_mode = "danger-full-access"',
        "",
        "[tools]",
        "web_search = false",
        "",
        "[model_providers.openrouter]",
        'name = "OpenRouter"',
        'base_url = "https://openrouter.ai/api/v1"',
        'env_key = "OPENROUTER_API_KEY"',
        'wire_api = "responses"',
        "",
        "[mcp_servers.k7d]",
        f"command = {toml_str(server['command'])}",
        f"args = [{', '.join(toml_str(a) for a in server.get('args', []))}]",
        'default_tools_approval_mode = "auto"',
        "startup_timeout_sec = 60",
        "tool_timeout_sec = 600",
        "",
        "[mcp_servers.k7d.env]",
    ]
    env = dict(server.get("env", {}))
    # codex spawns the MCP server from its own workdir; keep the JSONL
    # (plots + k7view bridge input) anchored to the harness cwd.
    if "K7D_MCP_LOG" in env:
        env["K7D_MCP_LOG"] = str(Path(env["K7D_MCP_LOG"]).resolve())
    lines += [f"{k} = {toml_str(v)}" for k, v in env.items()]
    (codex_home / "config.toml").write_text("\n".join(lines) + "\n")


def view_post(url: str, payload: dict) -> None:
    if not url:
        return
    try:
        req = urllib.request.Request(
            f"{url}/api/ingest",
            data=json.dumps(payload).encode(),
            headers={"Content-Type": "application/json"},
        )
        urllib.request.urlopen(req, timeout=3).read()
    except OSError:
        pass  # observer plumbing must never fail the run


def relay_event(line: str, view: str, tree_id: str) -> None:
    """Echo one codex --json event; mirror agent text to k7view's feed."""
    try:
        item = json.loads(line).get("item") or {}
    except json.JSONDecodeError:
        return
    kind = item.get("type")
    text = (item.get("text") or "").strip()
    if kind in ("reasoning", "agent_message") and text:
        print(f"[codex {kind}] {text}", flush=True)
        view_post(
            view,
            {"type": "meta", "tree_id": tree_id, "action": "agent", "text": text[:400]},
        )
    elif kind == "mcp_tool_call":
        status = item.get("status") or ("error" if item.get("error") else "done")
        print(
            f"[codex tool] {item.get('tool')} {json.dumps(item.get('arguments'))[:140]}"
            f" ({status})",
            flush=True,
        )
    elif kind == "error":
        print(f"[codex error] {item.get('message')}", file=sys.stderr, flush=True)


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--mcp-config", required=True)
    ap.add_argument("--print", dest="print_mode", action="store_true")
    ap.add_argument("--model", default=DEFAULT_MODEL)
    ap.add_argument("prompt")
    ns = ap.parse_args(argv)

    codex = shutil.which("codex")
    if not codex:
        raise SystemExit("codex not on PATH (github.com/openai/codex release binary)")
    cfg = json.loads(Path(ns.mcp_config).read_text())
    server = next(iter(cfg["mcpServers"].values()))
    tree_id = server.get("env", {}).get("K7D_TREE_ID", "")
    view = (os.environ.get("K7VIEW_URL") or "").rstrip("/")

    with tempfile.TemporaryDirectory(prefix="codex-k7d-") as home:
        write_config(Path(home), ns.model, server)
        workdir = Path(home) / "work"
        workdir.mkdir()
        env = {
            **os.environ,
            "CODEX_HOME": home,
            "OPENROUTER_API_KEY": api_key(),
        }
        proc = subprocess.Popen(
            [
                codex, "exec", "--json", "--skip-git-repo-check", "--ephemeral",
                "--cd", str(workdir), ns.prompt,
            ],
            env=env,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            text=True,
        )
        assert proc.stdout is not None
        for line in proc.stdout:
            relay_event(line, view, tree_id)
        rc = proc.wait()
    if rc != 0:
        raise SystemExit(f"codex exec exited {rc}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
