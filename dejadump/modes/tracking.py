"""Annotation dirty-tracking (IDA-only).

Capturing every annotation of a multi-megabyte volatile set on each epoch switch
costs seconds.  Instead, IDB (and Hex-Rays) events record *where* the analyst
changed something, and Mode A re-captures only those page-sized windows.

DejaDump's own writes (restoring an epoch's annotations, re-analysis) happen
inside :meth:`AnnotationTracker.suspended`, so they are not mistaken for edits.
On save / close the pending windows are flushed into the sidecar, so edits made
since the last switch are not lost when IDA exits.
"""

from __future__ import annotations

from contextlib import contextmanager
from typing import Callable, Optional

import ida_idp

from ..core.intervals import IntervalIndex, merge
from ..util.logging import get_logger

log = get_logger("tracking")

WINDOW = 0x1000


class AnnotationTracker(ida_idp.IDB_Hooks):
    def __init__(self, flush: Optional[Callable[[], None]] = None):
        super().__init__()
        self._dirty: set[int] = set()
        self._suspend = 0
        self._flush = flush
        self.hexrays_hooks = None

    # -- control ------------------------------------------------------------
    @contextmanager
    def suspended(self):
        self._suspend += 1
        try:
            yield
        finally:
            self._suspend -= 1

    def install(self) -> None:
        self.hook()
        try:
            import ida_hexrays

            if ida_hexrays.init_hexrays_plugin():
                self.hexrays_hooks = _HexraysTracker(self)
                self.hexrays_hooks.hook()
        except Exception:
            log.debug("Hex-Rays lvar tracking unavailable")

    def uninstall(self) -> None:
        try:
            self.unhook()
        finally:
            if self.hexrays_hooks is not None:
                self.hexrays_hooks.unhook()
                self.hexrays_hooks = None

    def mark(self, ea) -> None:
        if self._suspend:
            return
        try:
            self._dirty.add(int(ea) & ~(WINDOW - 1))
        except Exception:
            pass

    def windows(self, start: int, end: int) -> list[tuple[int, int]]:
        """Dirty windows intersecting ``[start, end)``, clipped and merged."""
        out = []
        for page in self._dirty:
            lo, hi = max(page, start), min(page + WINDOW, end)
            if lo < hi:
                out.append((lo, hi))
        return merge(out)

    def clear(self, extents=None) -> None:
        if extents is None:
            self._dirty.clear()
            return
        index = IntervalIndex(extents)
        self._dirty = {p for p in self._dirty if not index.overlaps(p, p + WINDOW)}

    @property
    def pending(self) -> int:
        return len(self._dirty)

    # -- IDB events (all return 0: notifications only) -----------------------
    def renamed(self, ea, new_name, local_name, old_name=None):
        self.mark(ea)
        return 0

    def cmt_changed(self, ea, repeatable_cmt):
        self.mark(ea)
        return 0

    def extra_cmt_changed(self, ea, line_idx, cmt):
        self.mark(ea)
        return 0

    def range_cmt_changed(self, kind, a, cmt, repeatable):
        try:
            self.mark(a.start_ea)
        except Exception:
            pass
        return 0

    def func_added(self, pfn):
        self.mark(pfn.start_ea)
        return 0

    def func_updated(self, pfn):
        self.mark(pfn.start_ea)
        return 0

    def deleting_func(self, pfn):
        self.mark(pfn.start_ea)
        return 0

    def set_func_start(self, pfn, new_start):
        self.mark(pfn.start_ea)
        self.mark(new_start)
        return 0

    def set_func_end(self, pfn, new_end):
        self.mark(pfn.start_ea)
        return 0

    def func_tail_appended(self, pfn, tail):
        self.mark(pfn.start_ea)
        return 0

    def func_tail_deleted(self, pfn, tail_ea):
        self.mark(pfn.start_ea)
        return 0

    def ti_changed(self, ea, type, fnames):  # noqa: A002 - IDA's parameter name
        self.mark(ea)
        return 0

    def op_ti_changed(self, ea, n, type, fnames):  # noqa: A002
        self.mark(ea)
        return 0

    def op_type_changed(self, ea, n):
        self.mark(ea)
        return 0

    def item_color_changed(self, ea, color):
        self.mark(ea)
        return 0

    def frame_udm_renamed(self, func_ea, udm, oldname):
        self.mark(func_ea)
        return 0

    def savebase(self):
        self._flush_pending()
        return 0

    def closebase(self):
        self._flush_pending()
        return 0

    def _flush_pending(self) -> None:
        if self._flush is not None and self._dirty:
            try:
                self._flush()
            except Exception:
                log.exception("could not flush annotation edits to the sidecar")


try:  # Hex-Rays is optional
    import ida_hexrays as _ida_hexrays

    _HexraysBase = _ida_hexrays.Hexrays_Hooks
except Exception:  # pragma: no cover - no decompiler
    _HexraysBase = object


class _HexraysTracker(_HexraysBase):
    """Local-variable edits in pseudocode mark the function as dirty."""

    def __init__(self, tracker: AnnotationTracker):
        super().__init__()
        self._tracker = tracker

    def _mark(self, vu):
        try:
            self._tracker.mark(vu.cfunc.entry_ea)
        except Exception:
            pass
        return 0

    def lvar_name_changed(self, vu, v, name, is_user_name):
        return self._mark(vu)

    def lvar_type_changed(self, vu, v, tinfo):
        return self._mark(vu)

    def lvar_cmt_changed(self, vu, v, cmt):
        return self._mark(vu)

    def lvar_mapping_changed(self, vu, frm, to):
        return self._mark(vu)
