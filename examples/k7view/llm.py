"""Optional OpenRouter stream for k7view tiles + controller.

Reads OPENROUTER_API_KEY from the environment (or a 0600 file). Never
logs the key. Stdlib only. If the key is missing, callers fall back to
canned text.
"""

from __future__ import annotations

import json
import os
import urllib.error
import urllib.request
from collections.abc import Callable, Iterator
from pathlib import Path
from typing import Any

DEFAULT_MODEL = os.environ.get("OPENROUTER_MODEL", "google/gemini-3.1-flash-lite")
API_URL = "https://openrouter.ai/api/v1/chat/completions"
KEY_FILES = (
    Path(os.environ.get("OPENROUTER_KEY_FILE", "")) if os.environ.get("OPENROUTER_KEY_FILE") else None,
    Path("/root/.k7view-openrouter"),
    Path("/tmp/k7view-openrouter"),
)


def api_key() -> str | None:
    env = (os.environ.get("OPENROUTER_API_KEY") or "").strip()
    if env:
        return env
    for p in KEY_FILES:
        if p is None or not str(p) or not p.is_file():
            continue
        raw = p.read_text().strip()
        if raw:
            return raw
    return None


def configured() -> bool:
    return api_key() is not None


def stream_chat(
    messages: list[dict[str, str]],
    *,
    model: str | None = None,
    max_tokens: int = 160,
    timeout: float = 30,
) -> Iterator[str]:
    """Yield content deltas from OpenRouter. Loud on HTTP errors."""
    key = api_key()
    if not key:
        raise RuntimeError("OPENROUTER_API_KEY is not set")
    body = json.dumps(
        {
            "model": model or DEFAULT_MODEL,
            "messages": messages,
            "stream": True,
            "max_tokens": max_tokens,
            "temperature": 0.4,
        }
    ).encode()
    req = urllib.request.Request(
        API_URL,
        data=body,
        method="POST",
        headers={
            "Authorization": f"Bearer {key}",
            "Content-Type": "application/json",
            "HTTP-Referer": "https://github.com/Katakate/k7d",
            "X-Title": "k7d-view",
        },
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            while True:
                line = resp.readline()
                if not line:
                    break
                raw = line.decode("utf-8", "replace").strip()
                if not raw or raw.startswith(":"):
                    continue
                if raw.startswith("data:"):
                    raw = raw[5:].strip()
                if raw == "[DONE]":
                    break
                try:
                    obj = json.loads(raw)
                except json.JSONDecodeError:
                    continue
                err = obj.get("error")
                if err:
                    raise RuntimeError(f"openrouter: {err}")
                choices = obj.get("choices") or []
                if not choices:
                    continue
                delta = (choices[0].get("delta") or {}).get("content")
                if delta:
                    yield delta
    except urllib.error.HTTPError as exc:
        detail = exc.read().decode("utf-8", "replace")[:300]
        raise RuntimeError(f"openrouter HTTP {exc.code}: {detail}") from exc


def collect(
    messages: list[dict[str, str]],
    *,
    on_delta: Callable[[str], None] | None = None,
    **kw: Any,
) -> str:
    buf = ""
    for delta in stream_chat(messages, **kw):
        buf += delta
        if on_delta:
            on_delta(buf)
    return buf


def extract_json(text: str) -> dict[str, Any] | None:
    """Best-effort object from a model reply that may wrap ```json."""
    s = text.strip()
    if "```" in s:
        parts = s.split("```")
        for p in parts:
            p = p.strip()
            if p.startswith("json"):
                p = p[4:].strip()
            if p.startswith("{") and "}" in p:
                s = p
                break
    start = s.find("{")
    end = s.rfind("}")
    if start < 0 or end <= start:
        return None
    try:
        obj = json.loads(s[start : end + 1])
    except json.JSONDecodeError:
        return None
    return obj if isinstance(obj, dict) else None
