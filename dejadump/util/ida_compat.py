"""IDA 9.4/9.5 compatibility + feature detection.

Keeps the version/feature probing in one place.  The verified APIs DejaDump
relies on (``ida_undo``, ``auto_mark_range``, ``ida_segregs.split_sreg_range``,
``set_segm_addressing``, ``IDB_Hooks.allsegs_moved``, ``netnode.setblob``) are
stable across 9.4/9.5 — the disruptive renames happened at 8.x→9.0, below our
floor.  Prefer the 9.0+ ``ida_ida.inf_get_*`` accessors; ``get_inf_structure()``
was removed.
"""

from __future__ import annotations

from functools import lru_cache


@lru_cache(maxsize=1)
def in_ida() -> bool:
    try:
        import idaapi  # noqa: F401
        return True
    except Exception:
        return False


@lru_cache(maxsize=1)
def ida_version() -> tuple[int, int]:
    """Return (major, minor), e.g. (9, 4); (0, 0) when not in IDA."""
    try:
        import ida_kernwin
        v = ida_kernwin.get_kernel_version()  # e.g. "9.4"
        major, _, minor = v.partition(".")
        return int(major), int(minor or 0)
    except Exception:
        return (0, 0)


@lru_cache(maxsize=1)
def has_undo() -> bool:
    try:
        import ida_undo
        return hasattr(ida_undo, "create_undo_point")
    except Exception:
        return False


@lru_cache(maxsize=1)
def has_idalib() -> bool:
    """idalib ships with IDA Pro (all 9.x) and IDA Home (9.4+), never IDA Free."""
    try:
        import idapro  # noqa: F401
        return True
    except Exception:
        return False


@lru_cache(maxsize=1)
def has_hexrays() -> bool:
    try:
        import ida_hexrays
        return bool(ida_hexrays.init_hexrays_plugin())
    except Exception:
        return False


def default_page_size() -> int:
    """16 KiB on Apple targets, else 4 KiB (override per capture)."""
    try:
        import ida_ida
        filetype = ida_ida.inf_get_filetype()
        # Mach-O / Apple → 16 KiB page.
        macho = getattr(ida_ida, "f_MACHO", None)
        if macho is not None and filetype == macho:
            return 0x4000
    except Exception:
        pass
    return 0x1000
