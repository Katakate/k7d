#!/usr/bin/env python3
"""Stream real OpenRouter comments on the latest measured vsock probe."""

from __future__ import annotations

import os
import sys
import threading
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

import run_scenario as scen  # noqa: E402
import llm as k7view_llm  # noqa: E402


def main() -> int:
    view = os.environ.get("K7VIEW_URL", "http://127.0.0.1:7474")
    ingest = view.rstrip("/") + "/api/ingest"
    if not k7view_llm.configured():
        print("no OpenRouter key", file=sys.stderr)
        return 1
    scen.USE_LLM = True
    stop = threading.Event()
    t = threading.Thread(target=scen.llm_watch, args=(ingest, view, stop), daemon=True)
    t.start()
    print(f"llm watch on {view} model={k7view_llm.DEFAULT_MODEL}")
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        stop.set()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
