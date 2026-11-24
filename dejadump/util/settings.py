"""Persistent user settings (IDA registry, with environment-variable fallback).

Settings live in IDA's per-user registry under ``DejaDump`` so they survive
restarts and — unlike environment variables — are visible to an IDA started from
Finder / the Start menu.  An environment variable still wins when set, which keeps
scripted and CI runs reproducible.  Outside IDA an in-memory store stands in.
"""

from __future__ import annotations

import os
from typing import Optional

SUBKEY = "DejaDump"

#: name -> (environment variable, default)
SETTINGS = {
    "idalib_python": ("DEJADUMP_IDALIB_PYTHON", ""),
    "workers": ("DEJADUMP_WORKERS", "2"),
    "debug": ("DEJADUMP_DEBUG", "0"),
    "highlight": ("DEJADUMP_HIGHLIGHT", "1"),
    "filter_traces": ("DEJADUMP_FILTER_TRACES", "1"),
}

_memory: dict[str, str] = {}


def _registry():
    try:
        import ida_registry

        return ida_registry
    except Exception:
        return None


def get(name: str) -> str:
    env, default = SETTINGS[name]
    value = os.environ.get(env)
    if value not in (None, ""):
        return value
    registry = _registry()
    if registry is not None:
        try:
            # IDA returns "" (not None) for a value that was never written.
            stored = registry.reg_read_string(name, SUBKEY)
            if stored not in (None, ""):
                return stored
        except Exception:
            pass
    return _memory.get(name, default)


def set(name: str, value: str) -> None:  # noqa: A001 - mirrors get()
    if name not in SETTINGS:
        raise KeyError(name)
    registry = _registry()
    if registry is not None:
        try:
            registry.reg_write_string(name, str(value), SUBKEY)
            return
        except Exception:
            pass
    _memory[name] = str(value)


def env_override(name: str) -> Optional[str]:
    """The environment variable currently overriding ``name``, if any."""
    env, _ = SETTINGS[name]
    return env if os.environ.get(env) not in (None, "") else None


def get_bool(name: str) -> bool:
    return get(name).strip().lower() in ("1", "true", "yes", "on")


def get_int(name: str, default: int, lo: int, hi: int) -> int:
    try:
        return max(lo, min(hi, int(get(name))))
    except ValueError:
        return default
