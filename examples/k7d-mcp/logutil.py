"""JSONL tool-call log. This file is the plot input."""

from __future__ import annotations

import json
import os
import threading
import time
from pathlib import Path
from typing import Any


class JsonlLog:
    def __init__(self, path: str | Path, *, arm: str, run_id: str) -> None:
        self.path = Path(path)
        self.arm = arm
        self.run_id = run_id
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()

    def append(self, rec: dict[str, Any]) -> dict[str, Any]:
        rec = {
            "ts": rec.get("ts", time.time()),
            "arm": self.arm,
            "run_id": self.run_id,
            **rec,
        }
        line = json.dumps(rec, separators=(",", ":"), default=str)
        with self._lock:
            with self.path.open("a", encoding="utf-8") as f:
                f.write(line + "\n")
                f.flush()
                os.fsync(f.fileno())
        return rec
