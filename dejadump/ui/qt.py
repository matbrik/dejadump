"""Single Qt import point.

IDA 9.x ships **PySide6 (Qt6)** — PyQt5 was the ≤8.x binding and only works in
9.x through an opt-in shim with a first-import popup and known gaps.  So we author
against PySide6 directly (with a QtPy fallback), and the TWidget↔QWidget bridge
uses ``PluginForm.TWidgetToQtPythonWidget`` (the ``shiboken6.wrapInstance`` path):
despite the legacy "Qt/PyQt" name it is the only bridge that returns a usable
PySide6 widget in **both** IDA 9.4 and 9.5.  ``FormToPySideWidget`` is unreliable
across versions — in 9.4 it is a broken legacy path that dereferences
``ctx.QtGui.QWidget.FromCapsule`` and raises ``AttributeError``; 9.5 re-aliases it
back to ``TWidgetToQtPythonWidget``.  Preferring the latter directly works on both.

Qt6 gotchas handled by importing from here: ``QAction``/``QShortcut`` live in
``QtGui`` (not ``QtWidgets``); enums are scoped (``Qt.AlignmentFlag.AlignLeft``,
``Qt.ItemDataRole.DisplayRole``); signals are ``Signal``/``Slot``;
``QRegularExpression`` replaces ``QRegExp``; ``exec()`` replaces ``exec_()``.
"""

from __future__ import annotations

QT_BINDING = None
QtCore = QtGui = QtWidgets = None  # type: ignore
Signal = Slot = None  # type: ignore

try:
    from PySide6 import QtCore, QtGui, QtWidgets  # type: ignore
    from PySide6.QtCore import Signal, Slot  # type: ignore

    QT_BINDING = "PySide6"
except Exception:  # pragma: no cover - fallback path
    try:
        from qtpy import QtCore, QtGui, QtWidgets  # type: ignore  # noqa: F401
        from qtpy.QtCore import Signal, Slot  # type: ignore  # noqa: F401

        QT_BINDING = "qtpy"
    except Exception:
        QT_BINDING = None


def available() -> bool:
    return QT_BINDING is not None


def to_qwidget(form):  # pragma: no cover - requires IDA
    """Bridge an IDA ``TWidget``/PluginForm handle to a PySide6 QWidget.

    ``TWidgetToQtPythonWidget`` (the ``shiboken6.wrapInstance`` bridge) is tried
    first: it is present and correct in both IDA 9.4 and 9.5.  The
    ``*PySideWidget`` names are only a fallback because 9.4 aliases them to a
    broken legacy implementation (see the module docstring).
    """
    import ida_kernwin

    form_cls = ida_kernwin.PluginForm
    for name in ("TWidgetToQtPythonWidget", "FormToPySideWidget", "TWidgetToPySideWidget"):
        fn = getattr(form_cls, name, None)
        if fn is not None:
            return fn(form)
    raise RuntimeError("no TWidget→QWidget bridge found on ida_kernwin.PluginForm")
