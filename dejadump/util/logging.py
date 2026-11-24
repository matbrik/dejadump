"""Namespaced logger. Every IDA-touching call site logs through this so failures
are visible but never fatal (DESIGN §12 robustness rule).

Debug output (every "skipped" best-effort path) is off by default; enable it from
Edit → DejaDump → Settings… or with ``DEJADUMP_DEBUG=1``.
"""

from __future__ import annotations

import logging

_PREFIX = "dejadump"


def get_logger(name: str = "") -> logging.Logger:
    root = logging.getLogger(_PREFIX)
    if not root.handlers:
        handler = logging.StreamHandler()
        handler.setFormatter(logging.Formatter("[%(name)s] %(levelname)s: %(message)s"))
        root.addHandler(handler)
        root.propagate = False
        root.setLevel(logging.DEBUG if _debug_enabled() else logging.INFO)
    return logging.getLogger(f"{_PREFIX}.{name}") if name else root


def set_debug(enabled: bool) -> None:
    logging.getLogger(_PREFIX).setLevel(logging.DEBUG if enabled else logging.INFO)


def _debug_enabled() -> bool:
    try:
        from . import settings

        return settings.get_bool("debug")
    except Exception:
        return False
