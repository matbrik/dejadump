"""Native IDA choosers (IDA-only): epoch picker, source manager, search results,
wave summary.

Built on ``ida_kernwin.Choose`` so they look, sort, filter and copy like every
other IDA list and follow the user's theme.
"""

from __future__ import annotations

import ida_kernwin

from ..util import fmt
from ..util.logging import get_logger

log = get_logger("ui.choosers")

_COL_DEC = ida_kernwin.Choose.CHCOL_DEC if hasattr(ida_kernwin.Choose, "CHCOL_DEC") else 0
_COL_HEX = ida_kernwin.Choose.CHCOL_HEX if hasattr(ida_kernwin.Choose, "CHCOL_HEX") else 0
_COL_PLAIN = ida_kernwin.Choose.CHCOL_PLAIN if hasattr(ida_kernwin.Choose, "CHCOL_PLAIN") else 0


class EpochChooser(ida_kernwin.Choose):
    """Modal epoch picker; :meth:`choose` returns the selected sequence number."""

    def __init__(self, title: str, rows: list[dict], default: int, active: int):
        super().__init__(
            title,
            [["Epoch", 6 | _COL_PLAIN], ["Label", 22 | _COL_PLAIN], ["Kind", 8 | _COL_PLAIN],
             ["Ranges", 6 | _COL_DEC], ["Bytes changed", 12 | _COL_PLAIN],
             ["Boundary PC", 14 | _COL_HEX]],
            flags=ida_kernwin.Choose.CH_MODAL,
        )
        self.rows = rows
        self.items = [[
            "t%d%s" % (r["seq"], " ◀" if r["seq"] == active else ""),
            r.get("label", "") or ("loaded image" if r["seq"] == 0 else ""),
            r["kind"], str(r["ranges"]), fmt.size(r["bytes"]),
            ("0x%X" % r["boundary_pc"]) if r.get("boundary_pc") else "—",
        ] for r in rows]
        self.deflt = next((i for i, r in enumerate(rows) if r["seq"] == default), 0)

    def OnGetSize(self):
        return len(self.items)

    def OnGetLine(self, n):
        return self.items[n]

    def choose(self):
        index = self.Show(True)
        if index is None or index < 0:
            return None
        return int(self.rows[index]["seq"])


class _Window(ida_kernwin.Choose):
    """Non-modal chooser that unregisters itself from the controller on close."""

    def __init__(self, controller, title, columns, flags=0):
        super().__init__(title, columns, flags=flags)
        self.controller = controller

    @staticmethod
    def _safely(fn, *args):
        """Chooser callbacks must not raise into IDA; report like menu actions do."""
        try:
            fn(*args)
            return True
        except Exception as exc:
            log.debug("chooser action failed", exc_info=True)
            ida_kernwin.warning("DejaDump: %s" % exc)
            return False

    def OnClose(self):
        try:
            self.controller.choosers.remove(self)
        except ValueError:
            pass


class SourceChooser(_Window):
    """Sources in the sidecar: Enter selects, Ins/Edit renames, Del deletes."""

    def __init__(self, controller, store):
        flags = ida_kernwin.Choose.CH_CAN_DEL | ida_kernwin.Choose.CH_CAN_EDIT
        if hasattr(ida_kernwin.Choose, "CH_CAN_REFRESH"):
            flags |= ida_kernwin.Choose.CH_CAN_REFRESH
        super().__init__(
            controller, "DejaDump — sources",
            [["ID", 4 | _COL_DEC], ["Label", 28 | _COL_PLAIN], ["Kind", 8 | _COL_PLAIN],
             ["Epochs", 6 | _COL_DEC], ["Created", 19 | _COL_PLAIN],
             ["Status", 22 | _COL_PLAIN]],
            flags=flags)
        self.store = store
        self._load()

    def _load(self):
        # Always read through the controller: the sidecar may have been replaced.
        self.store = self.controller.store or self.store
        active = self.store.active_source_id()
        self.sources = self.store.sources()
        self.items = []
        for src in self.sources:
            status = "active" if src["id"] == active else ""
            duplicate = self.store.duplicate_of(src["id"])
            if duplicate is not None and duplicate < src["id"]:
                status = (status + " · " if status else "") + "duplicate of %d" % duplicate
            self.items.append([str(src["id"]), src["label"] or "", src["kind"],
                               str(src["epochs"]), src["created"] or "—", status])

    def OnGetSize(self):
        return len(self.items)

    def OnGetLine(self, n):
        return self.items[n]

    def OnSelectLine(self, n):
        self._safely(self.controller.select_source, int(self.sources[n]["id"]))
        self._load()
        return (ida_kernwin.Choose.ALL_CHANGED, n)

    def OnEditLine(self, n):
        src = self.sources[n]
        label = ida_kernwin.ask_str(src["label"] or "", 0, "New label for source %d:" % src["id"])
        if label is not None:
            self._safely(self.controller.rename_source, int(src["id"]), label)
            self._load()
        return (ida_kernwin.Choose.ALL_CHANGED, n)

    def OnDeleteLine(self, n):
        deleted = []
        self._safely(lambda: deleted.append(
            self.controller.delete_source(int(self.sources[n]["id"]))))
        if any(deleted):
            self._load()
        return (ida_kernwin.Choose.ALL_CHANGED, max(0, n - 1))

    def OnRefresh(self, n):
        self._load()
        return (ida_kernwin.Choose.ALL_CHANGED, n)


class SearchResults(_Window):
    """Cross-epoch search hits; Enter activates the first epoch containing it and jumps."""

    def __init__(self, controller, query, hits, resolver, length):
        super().__init__(
            controller, "DejaDump — search %s" % query,
            [["Address", 16 | _COL_HEX], ["First", 5 | _COL_PLAIN],
             ["Present in", 24 | _COL_PLAIN], ["Bytes (first epoch)", 40 | _COL_PLAIN]])
        self.hits = hits
        self.items = []
        for hit in hits:
            data = resolver.state(hit["first"], hit["addr"], max(16, length))
            text = "".join(chr(b) if 0x20 <= b < 0x7F else "." for b in data)
            self.items.append([
                "0x%X" % hit["addr"], "t%d" % hit["first"],
                ",".join("t%d" % k for k in hit["epochs"]),
                "%s  %s" % (data[:16].hex(" "), text[:16])])

    def OnGetSize(self):
        return len(self.items)

    def OnGetLine(self, n):
        return self.items[n]

    def OnSelectLine(self, n):
        hit = self.hits[n]
        active = self.controller.active_epoch()
        epoch = active if active in hit["epochs"] else hit["first"]
        self._safely(self.controller.jump_to_epoch_address, epoch, hit["addr"])
        return (ida_kernwin.Choose.NOTHING_CHANGED, n)


class WaveSummary(_Window):
    """What one epoch changed: ranges, functions (+ / − / ~) and revealed strings."""

    def __init__(self, controller, k, rows):
        super().__init__(
            controller, "DejaDump — wave t%d (t%d → t%d)" % (k, k - 1, k),
            [["Change", 11 | _COL_PLAIN], ["Address", 16 | _COL_HEX],
             ["Epoch", 5 | _COL_PLAIN], ["Detail", 60 | _COL_PLAIN]])
        self.rows = rows
        self.items = [[r["kind"], ("0x%X" % r["addr"]) if r["addr"] is not None else "",
                       "t%d" % r["epoch"], r["detail"]] for r in rows]

    def OnGetSize(self):
        return len(self.items)

    def OnGetLine(self, n):
        return self.items[n]

    def OnSelectLine(self, n):
        row = self.rows[n]
        if row["addr"] is not None:
            self._safely(self.controller.jump_to_epoch_address, row["epoch"], row["addr"])
        return (ida_kernwin.Choose.NOTHING_CHANGED, n)
