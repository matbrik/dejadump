"""Read-only assembly/pseudocode/byte diff viewer (IDA-only).

Two tabs: a coloured unified diff, and an *aligned* side-by-side view in which
inserted/deleted lines are padded so both panes scroll in lockstep and line N
on the left corresponds to line N on the right.  "Jump" activates the pane's
epoch and moves to the selected line's address.
"""

from __future__ import annotations

import ida_kernwin

from . import qt
from ..core.diffing import align

# Translucent backgrounds read well in IDA's light and dark themes.
_ADDED = (46, 160, 67, 70)
_REMOVED = (248, 81, 73, 70)
_CHANGED = (210, 153, 34, 70)
_HUNK = (56, 139, 253, 60)


class DiffViewer(ida_kernwin.PluginForm):
    def __init__(self, controller, title: str, lines: list[str], left=None, right=None,
                 summary: str = "", kind: str = "assembly", normalized: bool = False):
        super().__init__()
        self.controller = controller
        self.title, self.lines, self.parent, self.edit = title, lines, None, None
        self.left = left or (0, [], [])
        self.right = right or (0, [], [])
        self.summary = summary
        self.kind = kind
        self.normalized = normalized

    @staticmethod
    def _paint(edit, colours):
        """Full-width line backgrounds: ``colours[i]`` is an RGBA tuple or None."""
        selections = []
        block = edit.document().firstBlock()
        index = 0
        while block.isValid():
            rgba = colours[index] if index < len(colours) else None
            if rgba is not None:
                sel = qt.QtWidgets.QTextEdit.ExtraSelection()
                sel.format.setBackground(qt.QtGui.QColor(*rgba))
                sel.format.setProperty(qt.QtGui.QTextFormat.Property.FullWidthSelection, True)
                cursor = qt.QtGui.QTextCursor(block)
                sel.cursor = cursor
                selections.append(sel)
            block = block.next()
            index += 1
        edit.setExtraSelections(selections)

    def _pane(self, text: str):
        pane = qt.QtWidgets.QPlainTextEdit()
        pane.setReadOnly(True)
        pane.setLineWrapMode(qt.QtWidgets.QPlainTextEdit.LineWrapMode.NoWrap)
        font = qt.QtGui.QFontDatabase.systemFont(qt.QtGui.QFontDatabase.SystemFont.FixedFont)
        pane.setFont(font)
        pane.setPlainText(text)
        return pane

    def OnCreate(self, form):
        self.parent = qt.to_qwidget(form)
        layout = qt.QtWidgets.QVBoxLayout()
        if self.summary:
            label = qt.QtWidgets.QLabel(self.summary)
            label.setTextFormat(qt.QtCore.Qt.TextFormat.PlainText)
            layout.addWidget(label)
        tabs = qt.QtWidgets.QTabWidget()

        self.edit = self._pane("\n".join(self.lines))
        unified = []
        for line in self.lines:
            if line.startswith("@@"):
                unified.append(_HUNK)
            elif line.startswith("+") and not line.startswith("+++"):
                unified.append(_ADDED)
            elif line.startswith("-") and not line.startswith("---"):
                unified.append(_REMOVED)
            else:
                unified.append(None)
        self._paint(self.edit, unified)
        tabs.addTab(self.edit, "Unified")

        (k_left, left, left_addr), (k_right, right, right_addr) = self.left, self.right
        rows_l, rows_r, addr_l, addr_r, tags = align(
            left, right, left_addr, right_addr, kind=self.kind, normalized=self.normalized)
        self._addresses = (addr_l, addr_r)
        split = qt.QtWidgets.QSplitter(qt.QtCore.Qt.Orientation.Horizontal)
        panes = []
        for rows, colour_for in ((rows_l, {"delete": _REMOVED, "replace": _CHANGED}),
                                 (rows_r, {"insert": _ADDED, "replace": _CHANGED})):
            pane = self._pane("\n".join(rows))
            self._paint(pane, [colour_for.get(tag) for tag in tags])
            split.addWidget(pane)
            panes.append(pane)
        panes[0].verticalScrollBar().valueChanged.connect(
            panes[1].verticalScrollBar().setValue)
        panes[1].verticalScrollBar().valueChanged.connect(
            panes[0].verticalScrollBar().setValue)
        buttons = qt.QtWidgets.QWidget()
        button_row = qt.QtWidgets.QHBoxLayout(buttons)
        for pane, epoch, addresses in zip(panes, (k_left, k_right), (addr_l, addr_r)):
            button = qt.QtWidgets.QPushButton("Jump to selected line in t%d" % epoch)
            button.clicked.connect(
                lambda _checked=False, p=pane, k=epoch, a=addresses: self._jump(p, k, a))
            button_row.addWidget(button)
        side_container = qt.QtWidgets.QWidget()
        side_layout = qt.QtWidgets.QVBoxLayout(side_container)
        side_layout.addWidget(split)
        side_layout.addWidget(buttons)
        tabs.addTab(side_container, "Side by side (aligned)")
        layout.addWidget(tabs)
        self.parent.setLayout(layout)

    def OnClose(self, form):
        try:
            self.controller.diff_panels.remove(self)
        except ValueError:
            pass

    def _jump(self, pane, epoch, addresses):
        row = pane.textCursor().blockNumber()
        if row < 0 or row >= len(addresses) or addresses[row] is None:
            ida_kernwin.warning("DejaDump: this rendered line has no address mapping.")
            return
        try:
            self.controller.jump_to_epoch_address(epoch, int(addresses[row]))
        except Exception as exc:
            ida_kernwin.warning("DejaDump: %s" % exc)

    def show(self):
        self.Show(self.title, options=getattr(ida_kernwin.PluginForm, "WOPN_PERSIST", 0))
