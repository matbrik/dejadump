"""Epoch Timeline — a dockable PySide6 panel with the time-slider (IDA-only).

Shows the epochs (t0 = loaded image, t1… = waves), a slider and a table; moving
the slider or double-clicking a row calls Mode A's ``activate``.  Each activation
re-runs analysis, so the slider switches when a drag is *released*, and keyboard
or track-click moves switch after a short debounce.  After every attempt the
slider is re-synchronised with the epoch the IDB really holds.  Widgets are held on this instance — never module globals — to avoid the
9.4 exit-crash with PySide6 widgets in Python globals.
"""

from __future__ import annotations

import ida_kernwin

from . import qt
from ..util.logging import get_logger

log = get_logger("ui.epoch_panel")

_COLS = ("★", "epoch", "label", "note", "kind", "boundary PC", "functions",
         "ranges", "code bytes", "bytes changed", "cache")


class EpochPanel(ida_kernwin.PluginForm):
    TITLE = "DejaDump — Epochs"

    def __init__(self, controller):
        super().__init__()
        self.controller = controller
        self.parent = None
        self.table = None
        self.slider = None
        self.status = None
        self.filter = None
        self.favorites_only = None
        self.preview = None
        self.timer = None
        self._suppress = False

    # -- PluginForm ---------------------------------------------------------
    def OnCreate(self, form):
        self.parent = qt.to_qwidget(form)
        self._build()
        self.reload()

    def OnClose(self, form):
        if self.timer is not None:
            self.timer.stop()
        self.controller.panel = None

    def _build(self):
        W, C = qt.QtWidgets, qt.QtCore
        layout = W.QVBoxLayout()

        self.status = W.QLabel("—")
        self.status.setTextFormat(C.Qt.TextFormat.PlainText)
        layout.addWidget(self.status)

        filters = W.QHBoxLayout()
        self.filter = W.QLineEdit()
        self.filter.setPlaceholderText("Filter epochs by label, note, or kind")
        self.filter.textChanged.connect(self._apply_filter)
        self.favorites_only = W.QCheckBox("Favorites only")
        self.favorites_only.toggled.connect(self._apply_filter)
        source_btn = W.QPushButton("Sources…")
        source_btn.clicked.connect(lambda: self._run(self.controller.manage_sources))
        filters.addWidget(self.filter)
        filters.addWidget(self.favorites_only)
        filters.addWidget(source_btn)
        layout.addLayout(filters)

        self.slider = W.QSlider(C.Qt.Orientation.Horizontal)
        self.slider.setMinimum(0)
        self.slider.setSingleStep(1)
        self.slider.setPageStep(1)
        self.slider.setTickPosition(W.QSlider.TickPosition.TicksBelow)
        self.slider.sliderReleased.connect(self._on_slider_released)
        self.slider.valueChanged.connect(self._on_slider_value)
        self.timer = C.QTimer(self.parent)
        self.timer.setSingleShot(True)
        self.timer.setInterval(250)
        self.timer.timeout.connect(self._on_slider_released)
        layout.addWidget(self.slider)

        self.table = W.QTableWidget(0, len(_COLS))
        self.table.setHorizontalHeaderLabels(list(_COLS))
        self.table.setSelectionBehavior(W.QAbstractItemView.SelectionBehavior.SelectRows)
        self.table.setEditTriggers(W.QAbstractItemView.EditTrigger.DoubleClicked |
                                   W.QAbstractItemView.EditTrigger.EditKeyPressed)
        self.table.horizontalHeader().setStretchLastSection(True)
        self.table.cellDoubleClicked.connect(self._on_row_double_clicked)
        self.table.cellChanged.connect(self._on_cell_changed)
        self.table.cellClicked.connect(self._on_row_selected)
        layout.addWidget(self.table)

        self.preview = W.QPlainTextEdit()
        self.preview.setReadOnly(True)
        self.preview.setMaximumHeight(160)
        self.preview.setPlaceholderText(
            "Select an epoch to preview its most recently cached assembly/pseudocode artifact.")
        layout.addWidget(self.preview)

        row = W.QHBoxLayout()
        prev_btn = W.QPushButton("◀ Prev (Alt+[)")
        next_btn = W.QPushButton("Next (Alt+]) ▶")
        revert_btn = W.QPushButton("Revert to t0")
        back_btn = W.QPushButton("History back")
        forward_btn = W.QPushButton("History forward")
        diff_btn = W.QPushButton("Compare assembly…")
        pseudo_btn = W.QPushButton("Compare pseudocode…")
        bytes_btn = W.QPushButton("Compare bytes…")
        cache_btn = W.QPushButton("Analyze selected…")
        summary_btn = W.QPushButton("Wave summary")
        pin_btn = W.QPushButton("Pin selected")
        unpin_btn = W.QPushButton("Unpin selected")
        prev_btn.clicked.connect(lambda: self._run(self.controller.step, -1))
        next_btn.clicked.connect(lambda: self._run(self.controller.step, +1))
        revert_btn.clicked.connect(lambda: self._run(self.controller.revert))
        back_btn.clicked.connect(lambda: self._run(self.controller.history_back))
        forward_btn.clicked.connect(lambda: self._run(self.controller.history_forward))
        diff_btn.clicked.connect(lambda: self._run(self.controller.compare_with, "assembly"))
        pseudo_btn.clicked.connect(lambda: self._run(self.controller.compare_with, "pseudocode"))
        bytes_btn.clicked.connect(lambda: self._run(self.controller.compare_with, "bytes"))
        cache_btn.clicked.connect(self._analyze_selected)
        summary_btn.clicked.connect(self._summary_selected)
        pin_btn.clicked.connect(lambda: self._run(self.controller.pin_epoch, self.selected_epoch()))
        unpin_btn.clicked.connect(
            lambda: self._run(self.controller.unpin_epoch, self.selected_epoch()))
        for b in (prev_btn, next_btn, back_btn, forward_btn, revert_btn, summary_btn):
            row.addWidget(b)
        layout.addLayout(row)
        row2 = W.QHBoxLayout()
        for b in (diff_btn, pseudo_btn, bytes_btn, cache_btn, pin_btn, unpin_btn):
            row2.addWidget(b)
        layout.addLayout(row2)

        self.parent.setLayout(layout)

    def _run(self, fn, *args):
        """Qt slots must never raise into Qt; show problems like menu actions do."""
        try:
            fn(*args)
        except Exception as exc:
            log.debug("panel action failed", exc_info=True)
            ida_kernwin.warning("DejaDump: %s" % exc)

    # -- data ---------------------------------------------------------------
    def reload(self):
        if self.table is None:
            return
        W = qt.QtWidgets
        epochs = self.controller.epoch_rows()  # list of dict rows incl. synthetic t0
        active = self.controller.active_epoch()

        self._suppress = True
        self.table.setRowCount(len(epochs))
        max_seq = 0
        for i, e in enumerate(epochs):
            max_seq = max(max_seq, e["seq"])
            values = (
                "★" if e.get("favorite") else "☆",
                "t%d%s" % (e["seq"], " ◀" if e["seq"] == active else ""),
                e.get("label", ""),
                e.get("note", ""),
                e["kind"],
                ("0x%x" % e["boundary_pc"]) if e["boundary_pc"] else "—",
                str(e.get("functions", 0)),
                str(e["ranges"]),
                "0x%x" % e.get("code_bytes", 0),
                "0x%x" % e["bytes"],
                "%d / %.0f ms" % (e.get("cache", 0), e.get("cache_ms", 0)),
            )
            for c, v in enumerate(values):
                item = W.QTableWidgetItem(v)
                item.setData(qt.QtCore.Qt.ItemDataRole.UserRole, e.get("id", 0))
                item.setData(int(qt.QtCore.Qt.ItemDataRole.UserRole) + 1, e["seq"])
                if c not in (2, 3):
                    item.setFlags(item.flags() & ~qt.QtCore.Qt.ItemFlag.ItemIsEditable)
                self.table.setItem(i, c, item)
        self.table.resizeColumnsToContents()
        self.slider.setMaximum(max_seq)
        self.slider.setValue(active)
        self._suppress = False
        self._update_status(active)
        self._apply_filter()

    def _update_status(self, active):
        total = self.slider.maximum()
        timing = self.controller.activation_timings()
        detail = ""
        if timing and timing.get("target") == active:
            phases = {name.removesuffix("_ms"): value for name, value in timing.items()
                      if name.endswith("_ms") and name != "total_ms"}
            dominant = max(phases, key=phases.get) if phases else "none"
            cached = " · cached plan" if timing.get("plan_cache_hit") else ""
            detail = " · %.0f ms total · %.0f ms analysis · dominant: %s · %d changed bytes%s" % (
                timing.get("total_ms", 0), timing.get("analysis_ms", 0), dominant,
                timing.get("bytes", 0), cached)
        self.status.setText("active: t%d / t%d%s" % (active, total, detail))

    # -- events -------------------------------------------------------------
    def _on_slider_value(self, _value):
        if self._suppress or self.slider.isSliderDown():
            return
        self.timer.start()

    def _on_slider_released(self):
        if self._suppress:
            return
        if self.timer is not None:
            self.timer.stop()
        target = self.slider.value()
        self._run(self._switch_from_slider, target)

    def _switch_from_slider(self, target):
        try:
            if target != self.controller.active_epoch():
                self.controller.activate(target)
        finally:
            self.reload()

    def _on_row_double_clicked(self, row, col):
        if col == 0:
            item = self.table.item(row, 0)
            seq = int(item.data(int(qt.QtCore.Qt.ItemDataRole.UserRole) + 1))
            enabled = item.text() != "★"
            self._run(self.controller.set_favorite, seq, enabled)
            item.setText("★" if enabled else "☆")
            self._apply_filter()
            return
        if col in (2, 3):
            return
        item = self.table.item(row, 1)
        if not item:
            return
        seq = int(item.data(int(qt.QtCore.Qt.ItemDataRole.UserRole) + 1))
        self._run(self.controller.activate, seq)

    def _on_cell_changed(self, row, col):
        if self._suppress or col not in (2, 3):
            return
        first = self.table.item(row, 1)
        if not first:
            return
        epoch_id = int(first.data(qt.QtCore.Qt.ItemDataRole.UserRole) or 0)
        label = self.table.item(row, 2).text() if self.table.item(row, 2) else ""
        note = self.table.item(row, 3).text() if self.table.item(row, 3) else ""
        self._run(self.controller.update_epoch_text, epoch_id, label, note)

    def _on_row_selected(self, row, _col):
        item = self.table.item(row, 1)
        if not item or self.preview is None:
            return
        seq = int(item.data(int(qt.QtCore.Qt.ItemDataRole.UserRole) + 1))
        try:
            kind, lines = self.controller.cached_preview(seq)
        except Exception:
            log.debug("cache preview failed", exc_info=True)
            kind, lines = "", []
        self.preview.setPlainText(
            ("[%s cache]\n" % kind + "\n".join(lines)) if lines else
            "No cached artifact for t%d. Use a Pre-analyze action to create one." % seq)

    def selected_epoch(self):
        if self.table is None:
            return None
        row = self.table.currentRow()
        item = self.table.item(row, 1) if row >= 0 else None
        return (int(item.data(int(qt.QtCore.Qt.ItemDataRole.UserRole) + 1))
                if item else None)

    def _analyze_selected(self):
        epoch = self.selected_epoch()
        if epoch is None:
            ida_kernwin.warning("DejaDump: select an epoch first.")
            return
        # ask_buttons: 1 = first button, 0 = second, -1 = cancel.
        choice = ida_kernwin.ask_buttons("Assembly", "Pseudocode", "Cancel", 1,
                                         "Artifact to cache for t%d" % epoch)
        if choice >= 0:
            self._run(self.controller.analyze_epoch, epoch,
                      "assembly" if choice == 1 else "pseudocode")

    def _summary_selected(self):
        epoch = self.selected_epoch()
        if epoch is None or epoch == 0:
            epoch = self.controller.active_epoch() or None
        self._run(self.controller.wave_summary, epoch)

    def _apply_filter(self, *_args):
        if self.table is None:
            return
        needle = self.filter.text().strip().lower() if self.filter else ""
        favorite_only = bool(self.favorites_only and self.favorites_only.isChecked())
        for row in range(self.table.rowCount()):
            favorite = self.table.item(row, 0).text() == "★"
            haystack = " ".join(
                self.table.item(row, col).text().lower()
                for col in (1, 2, 3, 4) if self.table.item(row, col)
            )
            self.table.setRowHidden(row, (favorite_only and not favorite) or
                                    (bool(needle) and needle not in haystack))

    def show(self):
        opts = getattr(ida_kernwin.PluginForm, "WOPN_PERSIST", 0)
        self.Show(self.TITLE, options=opts)
