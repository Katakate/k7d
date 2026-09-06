"""Minimal vsock agent client (JSON-lines, port 1024). Stdlib only.

k7d does not proxy the agent; any host process can talk to a guest CID.
Used for create-mode `act`/`obs`/`score` so a busybox cluster can still
answer without an inner apiserver.
"""

from __future__ import annotations

import base64
import json
import socket
import time
import uuid
from typing import Any

AGENT_VSOCK_PORT = 1024
AF_VSOCK = getattr(socket, "AF_VSOCK", 40)


def _connect(cid: int, timeout_s: float) -> socket.socket:
    deadline = time.monotonic() + timeout_s
    last: OSError | None = None
    while time.monotonic() < deadline:
        sock = socket.socket(AF_VSOCK, socket.SOCK_STREAM)
        sock.settimeout(max(0.2, deadline - time.monotonic()))
        try:
            sock.connect((int(cid), AGENT_VSOCK_PORT))
            return sock
        except OSError as e:
            last = e
            sock.close()
            time.sleep(0.05)
    raise RuntimeError(f"vsock connect cid={cid} port={AGENT_VSOCK_PORT}: {last}")


def _call(cid: int, req: dict[str, Any], timeout_s: float) -> dict[str, Any]:
    payload = (json.dumps(req, separators=(",", ":")) + "\n").encode()
    with _connect(cid, timeout_s) as sock:
        sock.settimeout(timeout_s)
        try:
            sock.sendall(payload)
            buf = b""
            deadline = time.monotonic() + timeout_s
            while b"\n" not in buf:
                if time.monotonic() >= deadline:
                    raise RuntimeError(f"agent timeout waiting for response cid={cid}")
                chunk = sock.recv(65536)
                if not chunk:
                    break
                buf += chunk
        except TimeoutError as e:
            raise RuntimeError(f"agent timeout cid={cid}: {e}") from e
    if not buf.strip():
        raise RuntimeError(f"empty agent response cid={cid} for {req.get('type')}")
    line = buf.split(b"\n", 1)[0]
    return json.loads(line.decode())


def ping(cid: int, timeout_s: float = 3) -> bool:
    try:
        resp = _call(cid, {"type": "ping"}, timeout_s)
    except (OSError, RuntimeError, json.JSONDecodeError):
        return False
    return resp.get("type") == "pong"


def exec_cmd(
    cid: int, args: list[str], timeout_s: float = 10
) -> dict[str, Any]:
    if not args:
        raise ValueError("exec args must be non-empty")
    req_id = uuid.uuid4().hex[:12]
    resp = _call(
        cid,
        {"type": "exec", "id": req_id, "args": list(args)},
        timeout_s,
    )
    if resp.get("type") != "exec_result":
        raise RuntimeError(f"unexpected agent response: {resp}")
    return {
        "exit_code": int(resp.get("exit_code", 1)),
        "stdout": resp.get("stdout") or "",
        "stderr": resp.get("stderr") or "",
    }


def write_file(cid: int, path: str, data: bytes, timeout_s: float = 15) -> None:
    """Guest `write_file` (base64 payload). Loud if the agent rejects it."""
    resp = _call(
        cid,
        {
            "type": "write_file",
            "path": path,
            "data": base64.b64encode(data).decode("ascii"),
        },
        timeout_s,
    )
    if resp.get("type") != "write_file_result" or not resp.get("ok"):
        raise RuntimeError(f"write_file {path} cid={cid}: {resp}")


def read_file(cid: int, path: str, timeout_s: float = 15) -> bytes:
    """Guest `read_file`. Loud if missing."""
    resp = _call(cid, {"type": "read_file", "path": path}, timeout_s)
    if resp.get("type") != "read_file_result":
        raise RuntimeError(f"read_file {path} cid={cid}: {resp}")
    if resp.get("error"):
        raise RuntimeError(f"read_file {path} cid={cid}: {resp['error']}")
    raw = resp.get("data")
    if raw is None:
        raise RuntimeError(f"read_file {path} cid={cid}: no data in {resp}")
    if isinstance(raw, str):
        try:
            return base64.b64decode(raw)
        except Exception:
            return raw.encode()
    raise RuntimeError(f"read_file {path} cid={cid}: unexpected data type")
