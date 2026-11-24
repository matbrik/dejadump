"""Every plugin module must import — with the IDA SDK stubbed out.

CI has no IDA, so without this a module that was never committed (or a typo in an
IDA-only file) would only surface when the plugin loads in IDA.  The stubs answer
any attribute with a subclassable, callable, flag-combinable placeholder, which is
all module-level code (base classes, flag constants) needs.
"""

from __future__ import annotations

import importlib
import os
import pkgutil
import sys
import types

import dejadump

IDA_MODULES = (
    "idaapi", "idc", "idautils", "idapro", "ida_auto", "ida_bytes", "ida_dbg",
    "ida_entry", "ida_frame", "ida_funcs", "ida_gdl", "ida_hexrays", "ida_ida",
    "ida_idaapi", "ida_idd", "ida_idp", "ida_kernwin", "ida_lines", "ida_loader",
    "ida_nalt", "ida_name", "ida_netnode", "ida_registry", "ida_segment",
    "ida_segregs", "ida_typeinf", "ida_ua", "ida_undo", "ida_xref",
)


class _Meta(type):
    def __getattr__(cls, name):
        if name.startswith("__"):
            raise AttributeError(name)
        return _stub(name)

    def __or__(cls, _other):
        return cls

    __ror__ = __and__ = __rand__ = __or__

    def __int__(cls):
        return 0

    __index__ = __int__


def _stub(name):
    return _Meta(name, (), {
        "__init__": lambda self, *a, **k: None,
        "__getattr__": lambda self, attr: _stub(attr),
    })


class _StubModule(types.ModuleType):
    def __getattr__(self, name):
        if name.startswith("__"):
            raise AttributeError(name)
        return _stub(name)


def _plugin_modules():
    yield "dejadump_plugin"
    for info in pkgutil.walk_packages(dejadump.__path__, "dejadump."):
        if not info.name.endswith(".__main__"):  # runs the CLI on import
            yield info.name


def test_every_plugin_module_imports_with_stubbed_ida(monkeypatch):
    before = set(sys.modules)
    for name in IDA_MODULES:
        monkeypatch.setitem(sys.modules, name, _StubModule(name))
    failures = []
    try:
        for name in _plugin_modules():
            try:
                importlib.import_module(name)
            except Exception as exc:  # pragma: no cover - reported below
                failures.append("%s: %s: %s" % (name, type(exc).__name__, exc))
    finally:
        for name in set(sys.modules) - before:
            if name not in IDA_MODULES:
                sys.modules.pop(name, None)
    assert not failures, "\n".join(failures)


def test_every_package_file_is_discovered():
    """A stray module outside a package directory would never be imported above."""
    root = os.path.dirname(dejadump.__file__)
    discovered = set(_plugin_modules()) | {"dejadump", "dejadump.__main__"}
    for dirpath, _dirs, files in os.walk(root):
        if "__pycache__" in dirpath:
            continue
        for filename in files:
            if not filename.endswith(".py"):
                continue
            rel = os.path.relpath(os.path.join(dirpath, filename), os.path.dirname(root))
            module = rel[:-3].replace(os.sep, ".")
            if module.endswith(".__init__"):
                module = module[: -len(".__init__")]
            assert module in discovered, module
