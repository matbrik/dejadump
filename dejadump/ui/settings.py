"""Settings dialog (IDA-only), stored in IDA's registry via :mod:`dejadump.util.settings`."""

from __future__ import annotations

import subprocess

import ida_kernwin

from ..util import settings
from ..util.logging import get_logger

log = get_logger("ui.settings")

_FLAGS = (("debug", "rDebug"), ("highlight", "rHighlight"), ("filter_traces", "rFilter"))


def test_worker(python: str) -> str:
    """Try to import ``idapro`` with the given interpreter; return a one-line verdict."""
    if not python:
        return "No interpreter set: comparisons use the live, in-IDB fallback."
    try:
        out = subprocess.run(
            [python, "-c", "import idapro, sys; print(sys.version.split()[0])"],
            capture_output=True, text=True, timeout=120)
    except Exception as exc:
        return "Could not run %s: %s" % (python, exc)
    if out.returncode != 0:
        tail = (out.stderr or out.stdout).strip().splitlines()[-1:] or ["unknown error"]
        return "idalib is not importable with %s: %s" % (python, tail[0])
    return "OK — idalib imports with Python %s." % out.stdout.strip()


class _SettingsForm(ida_kernwin.Form):
    def __init__(self):
        F = ida_kernwin.Form
        super().__init__(r"""STARTITEM 0
BUTTON YES* Save
BUTTON CANCEL Cancel
DejaDump settings

{FormChangeCb}
Background analysis (idalib)
<Python interpreter with idalib:{iPython}>
<Worker pool size (1-4):{iWorkers}>
<Test interpreter:{bTest}>

<##Behaviour##Debug logging in the Output window:{rDebug}>
<Highlight lines the active epoch changed:{rHighlight}>
<Import only trace writes inside the IDB's segments:{rFilter}>{cFlags}>
""", {
            "FormChangeCb": F.FormChangeCb(self._on_change),
            "iPython": F.FileInput(open=True, value=settings.get("idalib_python")),
            "iWorkers": F.NumericInput(tp=F.FT_DEC,
                                       value=settings.get_int("workers", 2, 1, 4)),
            "bTest": F.ButtonInput(self._on_test),
            "cFlags": F.ChkGroupControl(
                tuple(control for _name, control in _FLAGS),
                value=sum(1 << bit for bit, (name, _c) in enumerate(_FLAGS)
                          if settings.get_bool(name))),
        })

    def _on_change(self, fid):
        return 1

    def _on_test(self, code=0):
        python = self.GetControlValue(self.iPython)
        ida_kernwin.info("DejaDump: %s" % test_worker(python or ""))
        return 1


def _ask_fallback() -> bool:
    """Plain prompts when the Form API is unavailable."""
    python = ida_kernwin.ask_str(settings.get("idalib_python"), 0,
                                 "Python interpreter with idalib (empty = live fallback):")
    if python is None:
        return False
    workers = ida_kernwin.ask_long(settings.get_int("workers", 2, 1, 4), "Worker pool size (1-4):")
    if workers is None:
        return False
    settings.set("idalib_python", python.strip())
    settings.set("workers", str(max(1, min(4, int(workers)))))
    for name, label in (("debug", "Enable debug logging?"),
                        ("highlight", "Highlight lines the active epoch changed?"),
                        ("filter_traces", "Import only trace writes inside the IDB's segments?")):
        answer = ida_kernwin.ask_yn(1 if settings.get_bool(name) else 0, label)
        if answer < 0:
            return True
        settings.set(name, "1" if answer == 1 else "0")
    return True


def edit_settings() -> bool:
    """Show the settings dialog; returns True when values were saved."""
    try:
        form = _SettingsForm()
        form.Compile()
        ok = form.Execute()
        if ok == 1:
            settings.set("idalib_python", (form.iPython.value or "").strip())
            settings.set("workers", str(max(1, min(4, int(form.iWorkers.value or 2)))))
            mask = int(form.cFlags.value)
            for bit, (name, _control) in enumerate(_FLAGS):
                settings.set(name, "1" if mask & (1 << bit) else "0")
        form.Free()
        _warn_overrides()
        return ok == 1
    except Exception:
        log.exception("settings form unavailable; using prompts")
        saved = _ask_fallback()
        _warn_overrides()
        return saved


def _warn_overrides() -> None:
    overridden = [env for env in (settings.env_override(name) for name in settings.SETTINGS)
                  if env]
    if overridden:
        ida_kernwin.warning("DejaDump: these environment variables override the saved "
                            "settings: %s" % ", ".join(overridden))
