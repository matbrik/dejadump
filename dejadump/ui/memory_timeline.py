"""Memory Timeline — one column per epoch, one row per byte (IDA-only).

Cells are read-through byte values (via :class:`MemoryTimeline`); a cell that
changed from the previous epoch is highlighted, the tooltip shows the writer(s),
and double-clicking a changed cell jumps to the instruction that wrote it
(activating that epoch first).  The active epoch's column is marked, and values
that come only from *observed reads* (never written in the trace) are shown in
italics.  Columns are cached, and rendering goes through a
``QAbstractTableModel`` so a wide grid stays light.
"""

from __future__ import annotations

import ida_kernwin

from . import qt
from ..util import fmt
from ..util.logging import get_logger

log = get_logger("ui.memory_timeline")

_CHANGED_RGB = (0x5A, 0x3A, 0x1A)   # warm, legible in IDA's dark theme
_PLAINTEXT_RGB = (0x1A, 0x44, 0x2A)


class _Model(qt.QtCore.QAbstractTableModel if qt.available() else object):
    def __init__(self, timeline, start, size):
        super().__init__()
        self.tl = timeline
        self.start = start
        self.size = size
        self.cols = timeline.epochs()
        self._columns = {}
        self._plaintext_epoch = timeline.first_plaintext_epoch(start, size)
        self._observed = timeline.observed_mask(start, size)
        self.format = "byte"
        self.active = None

    @property
    def word_size(self):
        return {"byte": 1, "u16": 2, "u32": 4, "u64": 8, "ascii": 1}[self.format]

    def set_format(self, value):
        self.beginResetModel()
        self.format = value
        self.endResetModel()

    def address_at(self, row):
        return self.start + row * self.word_size

    def _cell(self, k, row):
        offset = row * self.word_size
        return self._column(k)[offset:offset + self.word_size]

    def cell_text(self, k, row):
        data = self._cell(k, row)
        if self.format == "ascii":
            value = data[0] if data else 0
            return chr(value) if 0x20 <= value < 0x7F else "."
        if self.format == "byte":
            return "%02X" % (data[0] if data else 0)
        return "0x%0*X" % (self.word_size * 2, int.from_bytes(data, "little"))

    def _column(self, k):
        if k not in self._columns:
            self._columns[k] = self.tl.column(k, self.start, self.size)
        return self._columns[k]

    # -- Qt model ----------------------------------------------------------
    def rowCount(self, _parent=None):
        return (self.size + self.word_size - 1) // self.word_size

    def columnCount(self, _parent=None):
        return len(self.cols)

    def _changed(self, row, col):
        k = self.cols[col]
        if k == 0:
            return False
        prev = self.cols[col - 1]
        return self._cell(k, row) != self._cell(prev, row)

    def data(self, index, role):
        Qt = qt.QtCore.Qt
        row, col = index.row(), index.column()
        k = self.cols[col]
        if role == Qt.ItemDataRole.DisplayRole:
            return self.cell_text(k, row)
        if role == Qt.ItemDataRole.BackgroundRole:
            # A change is the more specific signal; the plaintext tint must not hide it.
            if self._changed(row, col):
                return qt.QtGui.QColor(*_CHANGED_RGB)
            if self._plaintext_epoch is not None and k >= self._plaintext_epoch:
                return qt.QtGui.QColor(*_PLAINTEXT_RGB)
            return None
        if role == Qt.ItemDataRole.FontRole:
            if k >= 1 and self._is_observed(row):
                font = qt.QtGui.QFont()
                font.setItalic(True)
                return font
            return None
        if role == Qt.ItemDataRole.ToolTipRole:
            addr = self.address_at(row)
            ws = []
            for offset in range(self.word_size):
                ws.extend(w for w in self.tl.writers(addr + offset)
                          if w["epoch_seq"] == k and w not in ws)
            if ws:
                return "\n".join("t%d: written by %s" % (w["epoch_seq"], fmt.writer(w["writer_pc"]))
                                 for w in ws)
            if k >= 1 and self._is_observed(row):
                return "0x%x @ t%d — observed at runtime (read, never written in the trace)" % (
                    addr, k)
            return "0x%x @ t%d" % (addr, k)
        if role == Qt.ItemDataRole.TextAlignmentRole:
            return int(Qt.AlignmentFlag.AlignCenter)
        return None

    def headerData(self, section, orientation, role):
        Qt = qt.QtCore.Qt
        if role != Qt.ItemDataRole.DisplayRole:
            return None
        if orientation == Qt.Orientation.Horizontal:
            k = self.cols[section]
            return "t%d ◀" % k if k == self.active else "t%d" % k
        return "0x%X" % self.address_at(section)

    def _is_observed(self, row):
        offset = row * self.word_size
        return any(self._observed[offset:offset + self.word_size])

    def set_active(self, k):
        self.active = k
        if self.cols:
            self.headerDataChanged.emit(qt.QtCore.Qt.Orientation.Horizontal, 0, len(self.cols) - 1)

    # -- helpers -----------------------------------------------------------
    def writer_at(self, row, col):
        addr = self.address_at(row)
        k = self.cols[col]
        for offset in range(self.word_size):
            for w in self.tl.writers(addr + offset):
                if w["epoch_seq"] == k:
                    return k, w["writer_pc"]
        return None


class _Proxy(qt.QtCore.QSortFilterProxyModel if qt.available() else object):
    def __init__(self):
        super().__init__()
        self.changed_only = False
        self.compare_pair = None

    def filterAcceptsRow(self, row, _parent):
        model = self.sourceModel()
        if self.compare_pair is not None:
            a, b = self.compare_pair
            return model._cell(a, row) != model._cell(b, row)
        if self.changed_only:
            return any(model._changed(row, col) for col in range(1, model.columnCount()))
        return True

    def refresh(self):
        self.invalidateFilter()


class MemoryTimelinePanel(ida_kernwin.PluginForm):
    TITLE = "DejaDump — Memory Timeline"

    def __init__(self, controller, timeline, start, size):
        super().__init__()
        self.controller = controller
        self.timeline = timeline
        self.start = start
        self.size = size
        self.parent = None
        self.view = None
        self.model = None
        self.proxy = None

    def OnCreate(self, form):
        self.parent = qt.to_qwidget(form)
        W = qt.QtWidgets
        layout = W.QVBoxLayout()

        pt = self.timeline.first_plaintext_epoch(self.start, self.size)
        header = W.QLabel(
            "range 0x%X … 0x%X   ·   %s"
            % (self.start, self.start + self.size,
               ("first plaintext at t%d" % pt) if pt is not None else "no plaintext detected")
        )
        layout.addWidget(header)

        controls = W.QHBoxLayout()
        changed = W.QCheckBox("Changed rows only")
        changed.toggled.connect(self._changed_only)
        compare = W.QPushButton("Compare two epochs…")
        compare.clicked.connect(self._compare_epochs)
        clear_compare = W.QPushButton("Clear comparison")
        clear_compare.clicked.connect(self._clear_compare)
        self.address = W.QLineEdit()
        self.address.setPlaceholderText("address, e.g. 0x300000")
        go = W.QPushButton("Go")
        go.clicked.connect(self._go_address)
        self.format = W.QComboBox()
        self.format.addItem("Byte (hex)", "byte")
        self.format.addItem("Unsigned 16-bit LE", "u16")
        self.format.addItem("Unsigned 32-bit LE", "u32")
        self.format.addItem("Unsigned 64-bit LE", "u64")
        self.format.addItem("ASCII", "ascii")
        self.format.currentIndexChanged.connect(self._format_changed)
        for widget in (changed, compare, clear_compare, self.format, self.address, go):
            controls.addWidget(widget)
        layout.addLayout(controls)

        self.model = _Model(self.timeline, self.start, self.size)
        self.model.active = self.controller.active_epoch()
        self.proxy = _Proxy()
        self.proxy.setSourceModel(self.model)
        self.view = W.QTableView()
        self.view.setModel(self.proxy)
        self.view.doubleClicked.connect(self._on_double_click)
        self.view.resizeColumnsToContents()
        layout.addWidget(self.view)

        exports = W.QHBoxLayout()
        export = W.QPushButton("Export CSV…")
        export.clicked.connect(self._export_csv)
        markdown = W.QPushButton("Export Markdown…")
        markdown.clicked.connect(self._export_markdown)
        exports.addWidget(export)
        exports.addWidget(markdown)
        layout.addLayout(exports)

        self.parent.setLayout(layout)

    def OnClose(self, form):
        self.controller.memory_panel = None

    def _on_double_click(self, index):
        source = self.proxy.mapToSource(index)
        hit = self.model.writer_at(source.row(), source.column())
        if hit:
            k, writer_pc = hit
            try:
                self.controller.jump_to_writer(writer_pc, k)
            except Exception as exc:
                ida_kernwin.warning("DejaDump: %s" % exc)

    def _changed_only(self, checked):
        self.proxy.changed_only = bool(checked)
        self.proxy.compare_pair = None
        self.proxy.refresh()

    def set_active(self, k):
        if self.model is not None:
            self.model.set_active(k)

    def _compare_epochs(self):
        try:
            a = self.controller.choose_epoch("Memory Timeline — first epoch", 0)
            if a is None:
                return
            b = self.controller.choose_epoch("Memory Timeline — second epoch",
                                             self.model.cols[-1])
        except Exception as exc:
            ida_kernwin.warning("DejaDump: %s" % exc)
            return
        if b is None:
            return
        if int(a) not in self.model.cols or int(b) not in self.model.cols:
            ida_kernwin.warning("DejaDump: epoch is outside this timeline.")
            return
        self.proxy.compare_pair = (int(a), int(b))
        self.proxy.refresh()

    def _clear_compare(self):
        self.proxy.compare_pair = None
        self.proxy.refresh()

    def _go_address(self):
        try:
            ea = int(self.address.text().strip(), 0)
        except ValueError:
            ida_kernwin.warning("DejaDump: enter a hexadecimal or decimal address.")
            return
        offset = ea - self.start
        if not 0 <= offset < self.size:
            ida_kernwin.warning("DejaDump: address is outside this timeline range.")
            return
        row = offset // self.model.word_size
        source = self.model.index(row, 0)
        target = self.proxy.mapFromSource(source)
        if target.isValid():
            self.view.scrollTo(target)
            self.view.setCurrentIndex(target)

    def _format_changed(self, *_args):
        if self.model is None:
            return
        self.model.set_format(self.format.currentData())
        self.proxy.refresh()
        self.view.resizeColumnsToContents()

    def _export_csv(self):
        path = ida_kernwin.ask_file(True, "*.csv", "Export Memory Timeline")
        if not path:
            return
        try:
            cols = self.model.cols
            with open(path, "w", encoding="utf-8") as fh:
                fh.write("address," + ",".join("t%d" % k for k in cols) + "\n")
                for row in range(self.model.rowCount()):
                    cells = [self.model.cell_text(k, row) for k in cols]
                    fh.write("0x%X,%s\n" % (self.model.address_at(row), ",".join(cells)))
            ida_kernwin.info("DejaDump: wrote %s" % path)
        except Exception as exc:
            ida_kernwin.warning("CSV export failed: %s" % exc)

    def _export_markdown(self):
        path = ida_kernwin.ask_file(True, "*.md", "Export Memory Timeline as Markdown")
        if not path:
            return
        try:
            cols = self.model.cols
            with open(path, "w", encoding="utf-8") as fh:
                fh.write("| address | " + " | ".join("t%d" % k for k in cols) + " |\n")
                fh.write("|---|" + "---:|" * len(cols) + "\n")
                for proxy_row in range(self.proxy.rowCount()):
                    source = self.proxy.mapToSource(self.proxy.index(proxy_row, 0))
                    row = source.row()
                    cells = [self.model.cell_text(k, row) for k in cols]
                    fh.write("| 0x%X | %s |\n" %
                             (self.model.address_at(row), " | ".join(cells)))
            ida_kernwin.info("DejaDump: wrote %s" % path)
        except Exception as exc:
            ida_kernwin.warning("Markdown export failed: %s" % exc)

    def show(self):
        opts = getattr(ida_kernwin.PluginForm, "WOPN_PERSIST", 0)
        self.Show(self.TITLE, options=opts)
