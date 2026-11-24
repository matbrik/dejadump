"""Run INSIDE IDA (File -> Script file…) to load the DejaDump plugin for testing.

RECOMMENDED: open ``tests/fixtures/arm64_smc.elf`` first — IDA auto-detects
AArch64 and creates CODE@0x100000 / BUF@0x200000 / DATA@0x300000.  Then run this
script (it just registers the plugin menu; it will also create/fill the segments
as a fallback if you opened something else).  Then:

    Edit -> DejaDump -> Import Tenet trace…  ->  tests/fixtures/arm64_smc.tenet
    Edit -> DejaDump -> Open Epoch Timeline   (drag the slider: t0..t4)
    select 16 bytes at 0x300000, then Memory Timeline (Ctrl-Shift-M)

Note: the processor can only be chosen at load time — if you opened a flat .bin as
x86 you'll get garbage disassembly; open the ELF instead.
"""

import json
import os
import sys

import ida_bytes
import ida_kernwin
import ida_segment
import idc

_REPO = None
_PLUGIN = None  # keep a reference so the plugin_t is not garbage-collected


def _repo_root():
    try:
        here = os.path.dirname(os.path.abspath(__file__))
        if os.path.exists(os.path.join(here, "..", "dejadump_plugin.py")):
            return os.path.abspath(os.path.join(here, ".."))
    except Exception:
        pass
    p = ida_kernwin.ask_file(False, "dejadump_plugin.py", "Locate the DejaDump repo (dejadump_plugin.py)")
    return os.path.dirname(p) if p else None


def main():
    global _REPO, _PLUGIN
    _REPO = _repo_root()
    if not _REPO:
        return
    fx = os.path.join(_REPO, "tests", "fixtures")
    with open(os.path.join(fx, "manifest.json")) as fh:
        manifest = json.load(fh)

    # The processor can only be set at load time. If it isn't ARM, the user opened
    # the wrong file (e.g. a flat .bin as x86) — warn, don't fight it.
    proc = ""
    try:
        import ida_ida
        proc = ida_ida.inf_get_procname()
    except Exception:
        pass
    if "ARM" not in proc.upper():
        try:
            idc.set_processor_type("ARM:ARMv8A", idc.SETPROC_LOADER)
        except Exception:
            ida_kernwin.warning(
                "DejaDump: processor is '%s', not ARM.\n"
                "Open tests/fixtures/arm64_smc.elf for correct AArch64 disassembly." % proc
            )

    # Fallback scene build (no-op if you opened the ELF — segments already exist).
    for name in ("code", "buf", "data"):
        d = manifest["dumps"][name]
        base = d["base"]
        with open(os.path.join(fx, d["path"]), "rb") as fh:
            raw = fh.read()
        seginfo = ida_segment.segment_info_t()
        if not ida_segment.get_segment_info(seginfo, base):
            ida_segment.add_segm(0, base, base + len(raw), name,
                                 "DATA" if name == "data" else "CODE")
            ida_bytes.put_bytes(base, raw)
    print("[dejadump] scene ready: CODE@0x100000 BUF@0x200000 DATA@0x300000")

    if _REPO not in sys.path:
        sys.path.insert(0, _REPO)
    import dejadump_plugin

    _PLUGIN = dejadump_plugin.PLUGIN_ENTRY()
    _PLUGIN.init()
    ida_kernwin.info(
        "DejaDump demo scene ready + plugin loaded.\n\n"
        "Edit -> DejaDump -> Import Tenet trace…  ->  tests/fixtures/arm64_smc.tenet\n"
        "then Open Epoch Timeline and drag the slider (t0..t4)."
    )


main()
