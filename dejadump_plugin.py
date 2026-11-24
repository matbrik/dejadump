"""DejaDump — IDA plugin entry point.

Registers the DejaDump menu, toolbar and actions once, and keeps exactly one
:class:`~dejadump.controller.Controller` per open database: it is created when
IDA reports a database and closed when that database closes, so no sidecar,
netnode handle or activator state can leak from one IDB into the next.

The engine under :mod:`dejadump.core` stays importable and tested headless; this
file and everything it pulls from ``dejadump.modes`` / ``dejadump.ui`` is only
loaded inside IDA.
"""

from __future__ import annotations

import os
import sys

import ida_idaapi
import ida_kernwin

# Resolve symlinks: development installs commonly link this entry point directly
# into IDAUSR/plugins.  abspath(__file__) would then point at the user plugin
# directory and make the adjacent ``dejadump`` package impossible to import.
_HERE = os.path.dirname(os.path.realpath(__file__))
if _HERE not in sys.path:
    sys.path.insert(0, _HERE)

from dejadump import __version__  # noqa: E402
from dejadump.util.logging import get_logger  # noqa: E402

log = get_logger("plugin")

MENU = "Edit/DejaDump/"
TOOLBAR_NAME = "DejaDump"
TOOLBAR_LABEL = "DejaDump"
_ACTIONS = []
_TOOLBAR_CREATED = False
_TOOLBAR_ICONS = {}
_UNDO_ACTIONS = {"UndoAction", "RedoAction", "Undo", "Redo"}


class _Session:
    """Holds the per-database controller (``None`` while no database is open)."""

    controller = None


_SESSION = _Session()


def _database_open() -> bool:
    try:
        import idc

        return bool(idc.get_idb_path())
    except Exception:
        return False


def _controller():
    if _SESSION.controller is None and _database_open():
        from dejadump.controller import Controller

        _SESSION.controller = Controller()
    return _SESSION.controller


def _close_controller():
    controller, _SESSION.controller = _SESSION.controller, None
    if controller is not None:
        try:
            controller.close()
        except Exception:
            log.exception("closing the DejaDump session failed")


_TOOLBAR_ACTIONS = (
    "dejadump:panel",
    "dejadump:prev",
    "dejadump:next",
    "dejadump:compare",
    "dejadump:txref",
)

# Blue/white SVGs remain legible in IDA's light and dark themes.  They are kept
# inline so installing the plugin does not require a separate resource bundle.
#
# They are rasterised to PNG before being handed to ``load_custom_icon``.
# Qt's PNG decoder does not need an SVG image plugin; if rasterising fails, the
# action is registered without a custom icon.
_ICON_SVGS = {
    "dejadump:panel": """<svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 16 16"><rect x="2" y="2" width="12" height="12" rx="2" fill="#438ccb"/><path d="M5 5h6M5 8h6M5 11h4" stroke="white" stroke-width="1.5" stroke-linecap="round"/></svg>""",
    "dejadump:prev": """<svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 16 16"><circle cx="8" cy="8" r="7" fill="#438ccb"/><path d="M10.5 4.5 6.5 8l4 3.5" fill="none" stroke="white" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/></svg>""",
    "dejadump:next": """<svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 16 16"><circle cx="8" cy="8" r="7" fill="#438ccb"/><path d="m5.5 4.5 4 3.5-4 3.5" fill="none" stroke="white" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/></svg>""",
    "dejadump:compare": """<svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 16 16"><path d="M2 3h5v10H2zM9 3h5v10H9z" fill="#438ccb"/><path d="M4 6h1M4 9h1M11 5h1M11 8h1M11 11h1" stroke="white" stroke-width="1.5" stroke-linecap="round"/></svg>""",
    "dejadump:txref": """<svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 16 16"><circle cx="4" cy="4" r="2" fill="#438ccb"/><circle cx="12" cy="4" r="2" fill="#438ccb"/><circle cx="8" cy="12" r="2" fill="#438ccb"/><path d="m5.5 5.5 1.7 4M10.5 5.5l-1.7 4M6 4h4" stroke="#438ccb" stroke-width="1.5"/></svg>""",
}

# Enable rules: "db" needs an open database, "epochs" a sidecar with epochs,
# "debug" a suspended debuggee, "snapshots" pending snapshots and no debugger.
_NEEDS_DB, _NEEDS_EPOCHS, _NEEDS_DEBUG, _NEEDS_SNAPSHOTS = "db", "epochs", "debug", "snapshots"
_NEEDS_SIDECAR = "sidecar"


def _c(method, *args):
    """Late-bound controller call, so actions always reach the current database's session."""
    def run():
        controller = _controller()
        if controller is None:
            raise RuntimeError("open a database first")
        return getattr(controller, method)(*args)
    return run


def _status():
    controller = _controller()
    if controller is None:
        ida_kernwin.info("DejaDump %s — no database open." % __version__)
        return
    ida_kernwin.info(controller.status_text())


#: (id, submenu, label, callback, hotkey, enable rule).  Labels are the
#: user-visible names documented in docs/USER_GUIDE.md (a unit test keeps the
#: two in sync).
SPECS = [
    ("dejadump:import", "Import/", "Import Tenet trace…", _c("import_trace"), "Ctrl-Shift-T", _NEEDS_DB),
    ("dejadump:pair", "Import/", "Import decrypted image pair…", _c("import_decrypted_pair"), "", _NEEDS_DB),
    ("dejadump:dumps", "Import/", "Import memory dump(s)…", _c("import_memory_dumps"), "", _NEEDS_DB),
    ("dejadump:dbgsnap", "Import/", "Capture epoch from debugger", _c("capture_debugger_snapshot"), "", _NEEDS_DEBUG),
    ("dejadump:dbgimport", "Import/", "Import debugger snapshots…", _c("import_debugger_snapshots"), "", _NEEDS_SNAPSHOTS),
    ("dejadump:panel", "", "Open Epoch Timeline", _c("open_panel"), "Ctrl-Shift-E", _NEEDS_EPOCHS),
    ("dejadump:next", "Navigate/", "Next epoch", _c("step", +1), "Alt-]", _NEEDS_EPOCHS),
    ("dejadump:prev", "Navigate/", "Previous epoch", _c("step", -1), "Alt-[", _NEEDS_EPOCHS),
    ("dejadump:goto", "Navigate/", "Go to epoch…", _c("goto_epoch"), "", _NEEDS_EPOCHS),
    ("dejadump:back", "Navigate/", "Epoch history back", _c("history_back"), "", _NEEDS_EPOCHS),
    ("dejadump:forward", "Navigate/", "Epoch history forward", _c("history_forward"), "", _NEEDS_EPOCHS),
    ("dejadump:revert", "Navigate/", "Revert to t0", _c("revert"), "", _NEEDS_EPOCHS),
    ("dejadump:summary", "Views/", "Wave summary…", _c("wave_summary"), "", _NEEDS_EPOCHS),
    ("dejadump:memtl", "Views/", "Memory Timeline (selection)", _c("open_memory_timeline"), "Ctrl-Shift-M", _NEEDS_EPOCHS),
    ("dejadump:writes", "Views/", "Write History (cursor)", _c("open_write_history"), "Ctrl-Shift-W", _NEEDS_EPOCHS),
    ("dejadump:txref", "Views/", "Temporal xrefs for this address", _c("temporal_xrefs_here"), "Ctrl-Shift-X", _NEEDS_EPOCHS),
    ("dejadump:search", "Views/", "Search all epochs…", _c("search_epochs"), "", _NEEDS_EPOCHS),
    ("dejadump:highlight", "Views/", "Toggle changed-line highlighting", _c("toggle_highlight"), "", _NEEDS_DB),
    ("dejadump:compare", "Compare/", "Compare with epoch…", _c("compare_here"), "", _NEEDS_EPOCHS),
    ("dejadump:diffasm", "Compare/", "Compare assembly with epoch…", _c("compare_with", "assembly"), "", _NEEDS_EPOCHS),
    ("dejadump:diffpseudo", "Compare/", "Compare pseudocode with epoch…", _c("compare_with", "pseudocode"), "", _NEEDS_EPOCHS),
    ("dejadump:diffbytes", "Compare/", "Compare raw bytes with epoch…", _c("compare_with", "bytes"), "", _NEEDS_EPOCHS),
    ("dejadump:cacheasm", "Compare/", "Pre-analyze assembly for all epochs", _c("preanalyze_all", "assembly"), "", _NEEDS_EPOCHS),
    ("dejadump:cachepseudo", "Compare/", "Pre-analyze pseudocode for all epochs", _c("preanalyze_all", "pseudocode"), "", _NEEDS_EPOCHS),
    ("dejadump:analyzeasm", "Compare/", "Analyze current epoch (assembly)", _c("analyze_epoch", None, "assembly"), "", _NEEDS_EPOCHS),
    ("dejadump:analyzepseudo", "Compare/", "Analyze current epoch (pseudocode)", _c("analyze_epoch", None, "pseudocode"), "", _NEEDS_EPOCHS),
    ("dejadump:clearcache", "Compare/", "Clear analysis cache", _c("clear_analysis_cache"), "", _NEEDS_EPOCHS),
    ("dejadump:pin", "Pins/", "Pin epoch…", _c("pin_epoch"), "", _NEEDS_EPOCHS),
    ("dejadump:unpin", "Pins/", "Unpin epoch…", _c("unpin_epoch"), "", _NEEDS_EPOCHS),
    ("dejadump:rebasepin", "Pins/", "Preview/rebase typed pointers in pin…", _c("rebase_pinned_pointers"), "", _NEEDS_EPOCHS),
    ("dejadump:provenance", "Annotations/", "Materialize write provenance", _c("materialize_provenance"), "", _NEEDS_EPOCHS),
    ("dejadump:clearprovenance", "Annotations/", "Remove DejaDump write xrefs", _c("clear_provenance"), "", _NEEDS_EPOCHS),
    ("dejadump:promoteann", "Annotations/", "Promote active annotations to all epochs…", _c("promote_annotations"), "", _NEEDS_EPOCHS),
    ("dejadump:copyann", "Annotations/", "Copy annotations between epochs…", _c("copy_annotations"), "", _NEEDS_EPOCHS),
    ("dejadump:export", "", "Export epoch as file…", _c("export_epoch"), "", _NEEDS_EPOCHS),
    ("dejadump:sources", "Sidecar/", "Manage sources…", _c("manage_sources"), "", _NEEDS_SIDECAR),
    ("dejadump:locatesidecar", "Sidecar/", "Locate sidecar…", _c("locate_sidecar"), "", _NEEDS_DB),
    ("dejadump:health", "Sidecar/", "Sidecar health / checkpoint", _c("sidecar_health"), "", _NEEDS_SIDECAR),
    ("dejadump:compact", "Sidecar/", "Compact sidecar", _c("compact_sidecar"), "", _NEEDS_SIDECAR),
    ("dejadump:settings", "", "Settings…", _c("open_settings"), "", _NEEDS_DB),
    ("dejadump:status", "", "Status / about", _status, "", None),
]


def _enabled(rule) -> bool:
    if rule is None:
        return True
    controller = _controller()
    if controller is None:
        return False
    if rule == _NEEDS_DB:
        return True
    if rule == _NEEDS_EPOCHS:
        return controller.has_epochs()
    if rule == _NEEDS_SIDECAR:
        return controller.has_sidecar()
    try:
        import ida_dbg

        if rule == _NEEDS_DEBUG:
            return bool(ida_dbg.is_debugger_on() and
                        ida_dbg.get_process_state() == ida_dbg.DSTATE_SUSP)
        if rule == _NEEDS_SNAPSHOTS:
            return bool(controller.snapshots) and not ida_dbg.is_debugger_on()
    except Exception:
        return False
    return True


class _Handler(ida_kernwin.action_handler_t):
    def __init__(self, fn, rule):
        super().__init__()
        self._fn = fn
        self._rule = rule

    def activate(self, ctx):
        from dejadump.controller import UserError

        try:
            self._fn()
        except UserError as exc:
            ida_kernwin.warning("DejaDump: %s" % exc)
        except Exception as exc:  # never let a UI action crash IDA
            log.exception("action failed")
            ida_kernwin.warning("DejaDump: %s" % exc)
        return 1

    def update(self, ctx):
        try:
            return ida_kernwin.AST_ENABLE if _enabled(self._rule) else ida_kernwin.AST_DISABLE
        except Exception:
            return ida_kernwin.AST_DISABLE


class _UIHooks(ida_kernwin.UI_Hooks):
    _last_action = None

    def database_inited(self, is_new_database, idc_script):
        _close_controller()
        _controller()
        return 0

    def database_closed(self):
        _close_controller()
        return 0

    def preprocess_action(self, name):
        self._last_action = name
        return 0

    def postprocess_action(self):
        name, self._last_action = self._last_action, None
        if name in _UNDO_ACTIONS and _SESSION.controller is not None:
            try:
                _SESSION.controller.on_undo_redo()
            except Exception:
                log.debug("undo/redo resync failed")
        return 0

    def screen_ea_changed(self, ea, prev_ea):
        if _SESSION.controller is not None:
            try:
                _SESSION.controller.on_cursor(ea)
            except Exception:
                log.debug("cursor follow failed")

    def get_lines_rendering_info(self, out, widget, rin):
        controller = _SESSION.controller
        if controller is None or ida_kernwin.get_widget_type(widget) != ida_kernwin.BWN_DISASM:
            return
        try:
            from dejadump.util import settings

            if not settings.get_bool("highlight"):
                return
            spans = controller.highlight_index()
            if not spans:
                return
            import ida_bytes

            color = getattr(ida_kernwin, "CK_EXTRA5", 0x203A5A)
            for section_lines in rin.sections_lines:
                for line in section_lines:
                    ea = line.at.toea()
                    size = max(1, ida_bytes.get_item_size(ea))
                    if spans.overlaps(ea, ea + size):
                        out.entries.push_back(ida_kernwin.line_rendering_output_entry_t(
                            line, ida_kernwin.LROEF_FULL_LINE, color))
        except Exception:
            log.debug("changed-line highlighting failed", exc_info=True)

    def finish_populating_widget_popup(self, widget, popup_handle, ctx=None):
        try:
            widget_type = ida_kernwin.get_widget_type(widget)
            if widget_type == ida_kernwin.BWN_DISASM:
                actions = ("dejadump:diffasm", "dejadump:diffbytes", "dejadump:memtl",
                           "dejadump:writes", "dejadump:txref", "dejadump:search")
            elif widget_type == ida_kernwin.BWN_PSEUDOCODE:
                actions = ("dejadump:diffpseudo", "dejadump:diffasm")
            else:
                return
            for action in actions:
                ida_kernwin.attach_action_to_popup(widget, popup_handle, action, "DejaDump/")
        except Exception:
            log.debug("could not populate DejaDump context menu")


def _svg_to_png(svg: str, size: int = 16):
    """Rasterise an inline SVG to PNG bytes, or ``None`` if Qt cannot render it.

    Rendering here avoids depending on IDA's Qt SVG image plugin when loading
    custom action icons.
    """
    try:
        from PySide6 import QtCore, QtGui, QtSvg
    except Exception:
        log.debug("PySide6/QtSvg unavailable; toolbar icons disabled")
        return None
    try:
        renderer = QtSvg.QSvgRenderer(QtCore.QByteArray(svg.encode("utf-8")))
        if not renderer.isValid():
            return None
        image = QtGui.QImage(size, size, QtGui.QImage.Format.Format_ARGB32_Premultiplied)
        image.fill(QtCore.Qt.GlobalColor.transparent)
        painter = QtGui.QPainter(image)
        try:
            renderer.render(painter)
        finally:
            painter.end()
        if image.isNull():
            return None
        buffer = QtCore.QBuffer()
        buffer.open(QtCore.QIODevice.OpenModeFlag.WriteOnly)
        if not image.save(buffer, "PNG"):
            return None
        return bytes(buffer.data())
    except Exception:
        log.debug("could not rasterise toolbar icon", exc_info=True)
        return None


def _register():
    global _TOOLBAR_CREATED

    for aid, svg in _ICON_SVGS.items():
        png = _svg_to_png(svg)
        if not png:
            continue
        try:
            icon_id = ida_kernwin.load_custom_icon(data=png, format="png")
            if icon_id:
                _TOOLBAR_ICONS[aid] = icon_id
        except Exception:
            log.debug("could not load toolbar icon for %s", aid)

    for aid, submenu, label, cb, hotkey, rule in SPECS:
        if not ida_kernwin.register_action(
            ida_kernwin.action_desc_t(
                aid, label, _Handler(cb, rule), hotkey, label, _TOOLBAR_ICONS.get(aid, -1),
            )
        ):
            log.warning("could not register %s (hotkey %s may be taken)", aid, hotkey or "—")
            continue
        ida_kernwin.attach_action_to_menu(MENU + submenu + label, aid, ida_kernwin.SETMENU_APP)
        _ACTIONS.append(aid)

    # A small, movable native IDA toolbar.  Keeping the buttons attached to
    # registered actions means hotkeys, the Edit menu, and the toolbar all use
    # exactly the same controller paths and error handling.
    created = False
    try:
        created = bool(ida_kernwin.create_toolbar(TOOLBAR_NAME, TOOLBAR_LABEL))
    except Exception:
        created = False
        log.exception("could not create DejaDump toolbar")
    _TOOLBAR_CREATED = created
    # Only attach buttons to a toolbar this call actually created.  When
    # create_toolbar() returns False the toolbar already exists — restored from
    # the saved desktop on a later launch, or left over from a script reload —
    # and its buttons are already attached.  Re-attaching to that existing
    # toolbar has crashed IDA (null dereference inside ida_kernwin), so the
    # restored toolbar is left untouched.
    if created:
        for aid in _TOOLBAR_ACTIONS:
            try:
                ida_kernwin.attach_action_to_toolbar(TOOLBAR_NAME, aid)
            except Exception:
                log.debug("could not attach %s to the DejaDump toolbar", aid)


class DejaDumpPlugin(ida_idaapi.plugin_t):
    # PLUGIN_FIX registers the actions/menu/toolbar once at startup; the
    # per-database session is created/closed by the UI hooks above.
    flags = ida_idaapi.PLUGIN_MOD | ida_idaapi.PLUGIN_FIX
    comment = "A time axis for the IDA database (versioned code and data)."
    help = "Import an execution trace or memory dumps and browse memory across epochs."
    wanted_name = "DejaDump"
    wanted_hotkey = ""

    def init(self):
        _register()
        self.ui_hooks = _UIHooks()
        self.ui_hooks.hook()
        log.info("DejaDump %s loaded", __version__)
        return ida_idaapi.PLUGIN_KEEP

    def run(self, arg):
        controller = _controller()
        if controller is None:
            ida_kernwin.info("DejaDump: open a database first.")
        elif controller.has_epochs():
            controller.open_panel()
        else:
            ida_kernwin.info("DejaDump: nothing imported yet — use Edit → DejaDump → "
                             "Import.\n\n" + controller.status_text())

    def term(self):
        global _TOOLBAR_CREATED
        try:
            if getattr(self, "ui_hooks", None) is not None:
                self.ui_hooks.unhook()
        except Exception:
            pass
        _close_controller()
        if _TOOLBAR_CREATED:
            try:
                for aid in _TOOLBAR_ACTIONS:
                    ida_kernwin.detach_action_from_toolbar(TOOLBAR_NAME, aid)
                ida_kernwin.delete_toolbar(TOOLBAR_NAME)
            except Exception:
                log.debug("could not remove DejaDump toolbar")
        _TOOLBAR_CREATED = False
        for aid in _ACTIONS:
            ida_kernwin.unregister_action(aid)
        _ACTIONS.clear()
        for icon_id in _TOOLBAR_ICONS.values():
            try:
                ida_kernwin.free_custom_icon(icon_id)
            except Exception:
                pass
        _TOOLBAR_ICONS.clear()


def PLUGIN_ENTRY():
    return DejaDumpPlugin()
