"""Check toolbar registration without loading IDA's GUI."""

import importlib.util
import sys
from pathlib import Path
from types import ModuleType


def _load_plugin(monkeypatch, calls, created):
    kernwin = ModuleType("ida_kernwin")
    kernwin.action_handler_t = type("action_handler_t", (), {})
    kernwin.UI_Hooks = type("UI_Hooks", (), {})
    kernwin.action_desc_t = lambda *args: args
    kernwin.register_action = lambda desc: calls.append(("register", desc[0])) or True
    kernwin.attach_action_to_menu = lambda *args: None
    kernwin.load_custom_icon = lambda **kwargs: calls.append(("icon", kwargs["format"])) or 1
    kernwin.free_custom_icon = lambda icon: calls.append(("free", icon))
    kernwin.create_toolbar = lambda *args: calls.append(("create", args[0])) or created
    kernwin.attach_action_to_toolbar = lambda _toolbar, aid: calls.append(("attach", aid))
    kernwin.detach_action_from_toolbar = lambda _toolbar, aid: calls.append(("detach", aid))
    kernwin.delete_toolbar = lambda name: calls.append(("delete", name))
    kernwin.unregister_action = lambda name: calls.append(("unregister", name))
    kernwin.SETMENU_APP = 0
    monkeypatch.setitem(sys.modules, "ida_kernwin", kernwin)

    idaapi = ModuleType("ida_idaapi")
    idaapi.plugin_t = type("plugin_t", (), {})
    idaapi.PLUGIN_MOD = 1
    idaapi.PLUGIN_FIX = 2
    monkeypatch.setitem(sys.modules, "ida_idaapi", idaapi)

    path = Path(__file__).resolve().parents[2] / "dejadump_plugin.py"
    spec = importlib.util.spec_from_file_location("_dejadump_plugin_toolbar_test", path)
    plugin = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(plugin)
    monkeypatch.setattr(plugin.sys, "platform", "darwin")
    monkeypatch.setattr(plugin, "_svg_to_png", lambda _svg: b"png")
    return plugin


def test_macos_registers_toolbar_with_png_icons(monkeypatch):
    calls = []
    plugin = _load_plugin(monkeypatch, calls, created=True)

    plugin._register()
    assert ("create", "DejaDump") in calls
    assert [aid for kind, aid in calls if kind == "attach"] == list(plugin._TOOLBAR_ACTIONS)
    assert sum(kind == "icon" and fmt == "png" for kind, fmt in calls) == len(plugin._ICON_SVGS)
    assert sum(kind == "register" for kind, _ in calls) == len(plugin.SPECS)

    plugin.DejaDumpPlugin().term()
    assert ("delete", "DejaDump") in calls


def test_restored_toolbar_is_not_attached_twice(monkeypatch):
    calls = []
    plugin = _load_plugin(monkeypatch, calls, created=False)

    plugin._register()
    plugin.DejaDumpPlugin().term()
    assert not any(kind in ("attach", "detach", "delete") for kind, _ in calls)
