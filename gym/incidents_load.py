"""Load `examples/k7d-mcp/incidents.py` without colliding with `gym/faults`.

The catalog is named `incidents` so `import incidents` cannot bind
`gym/faults` when both sit on sys.path (CHALLENGES #124). Gym code
must go through this loader — do not `import incidents` from a
directory that also has `faults/` as a top-level package.

Load by file path so `examples/k7d-mcp` is never inserted on
`sys.path` (that dir also has `server.py`, which would shadow
`gym/server.py`).
"""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path
from types import ModuleType

_MCP = Path(__file__).resolve().parent.parent / "examples" / "k7d-mcp"
_MODNAME = "k7d_mcp_incidents"


def incidents_mod() -> ModuleType:
    cached = sys.modules.get(_MODNAME)
    if cached is not None:
        return cached
    if not _MCP.is_dir():
        raise RuntimeError(f"k7d-mcp incidents dir missing: {_MCP}")
    path = _MCP / "incidents.py"
    if not path.is_file():
        raise RuntimeError(f"k7d-mcp incidents.py missing: {path}")
    spec = importlib.util.spec_from_file_location(_MODNAME, path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot load incidents from {path}")
    mod = importlib.util.module_from_spec(spec)
    sys.modules[_MODNAME] = mod
    spec.loader.exec_module(mod)
    return mod
