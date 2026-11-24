"""Write History — who wrote the address under the cursor, and when (IDA-only).

Lists every observed write covering the current address as
``(epoch, writer PC, size, old → new)``; double-click jumps to the writer
(activating its epoch).  Backed by ``EpochStore.writes_for_addr``.  The panel
follows the cursor through IDA's ``screen_ea_changed`` notification (no polling);
untick "Follow cursor" to pin it to one address.
"""

from __future__ import annotations

import ida_kernwin

from . import qt
from ..util import fmt
from ..util.logging import get_logger

log = get_logger("ui.write_history")

_COLS = ("epoch", "writer PC", "write size", "old @ cursor", "new @ cursor")


class WriteHistoryPanel(ida_kernwin.PluginForm):
    TITLE = "DejaDump — Write History"

    def __init__(self, controller):
        super().__init__()
        self.controller = controller
        self.parent = None
        self.table = None
        self.header = None
        self._rows: list[dict] = []
        self.follow_box = None
        self._last_ea = None

    def OnCreate(self, form):
        self.parent = qt.to_qwidget(form)
        W = qt.QtWidgets
        layout = W.QVBoxLayout()

        self.header = W.QLabel("Put the cursor on an address and press Refresh.")
        layout.addWidget(self.header)

        self.table = W.QTableWidget(0, len(_COLS))
        self.table.setHorizontalHeaderLabels(list(_COLS))
        self.table.setSelectionBehavior(W.QAbstractItemView.SelectionBehavior.SelectRows)
        self.table.setEditTriggers(W.QAbstractItemView.EditTrigger.NoEditTriggers)
        self.table.cellDoubleClicked.connect(self._on_double_click)
        layout.addWidget(self.table)

        controls = W.QHBoxLayout()
        self.follow_box = W.QCheckBox("Follow cursor")
        self.follow_box.setChecked(True)
        refresh = W.QPushButton("Refresh (cursor address)")
        refresh.clicked.connect(self._refresh_clicked)
        controls.addWidget(self.follow_box)
        controls.addWidget(refresh)
        layout.addLayout(controls)

        self.parent.setLayout(layout)
        self.refresh()

    def OnClose(self, form):
        self.controller.write_panel = None

    def _refresh_clicked(self, *_args):
        try:
            self.refresh()
        except Exception as exc:
            ida_kernwin.warning("DejaDump: %s" % exc)

    def follow(self, ea):
        """Called by the plugin's UI hook whenever the cursor address changes."""
        if self.table is None or (self.follow_box is not None and
                                  not self.follow_box.isChecked()):
            return
        if ea != self._last_ea:
            self.refresh(ea)

    def refresh(self, ea=None):
        if self.table is None:
            return
        ea = ida_kernwin.get_screen_ea() if ea is None else ea
        self._last_ea = ea
        self._rows = self.controller.writes_for_addr(ea)
        self.header.setText("writes covering 0x%X — %d record(s)" % (ea, len(self._rows)))
        W = qt.QtWidgets
        self.table.setRowCount(len(self._rows))
        for i, w in enumerate(self._rows):
            old = w["old_at_addr"].hex() if w.get("old_at_addr") else "—"
            new = w["new_at_addr"].hex() if w.get("new_at_addr") else "—"
            values = ("t%d" % w["epoch_seq"], fmt.writer(w["writer_pc"]), str(w["size"]), old, new)
            for c, v in enumerate(values):
                self.table.setItem(i, c, W.QTableWidgetItem(v))
        self.table.resizeColumnsToContents()

    def _on_double_click(self, row, _col):
        if 0 <= row < len(self._rows):
            w = self._rows[row]
            try:
                self.controller.jump_to_writer(w["writer_pc"], w["epoch_seq"])
            except Exception as exc:
                ida_kernwin.warning("DejaDump: %s" % exc)

    def show(self):
        opts = getattr(ida_kernwin.PluginForm, "WOPN_PERSIST", 0)
        self.Show(self.TITLE, options=opts)
