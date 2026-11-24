"""Licensed idalib smoke test for an existing real DejaDump sidecar.

Usage::

    python tools/smoke_real_pair.py encrypted.so encrypted.so.dejadump.db

The input ELF and sidecar are copied to a temporary directory.  The test checks
startup journal recovery, a full t0 -> t1 activation, native disassembly and
optional pseudocode, then a verified return to t0.  It never opens the primary
IDB or writes the supplied sidecar.
"""

from __future__ import annotations

import os
import shutil
import sys
import tempfile
import time

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)


def main(input_path: str, sidecar_path: str) -> int:
    import idapro

    if ROOT not in sys.path:
        sys.path.insert(0, ROOT)

    workdir = tempfile.mkdtemp(prefix="dejadump-real-")
    copied_input = os.path.join(workdir, os.path.basename(input_path))
    copied_sidecar = copied_input + ".dejadump.db"
    shutil.copy2(input_path, copied_input)
    shutil.copy2(sidecar_path, copied_sidecar)
    print("temporary copy ready:", workdir, flush=True)

    opened = False
    store = None
    try:
        print("opening copied ELF…", flush=True)
        # Canonical switching assumes the user's initial loader analysis has
        # finished. Otherwise auto_wait_range() would inherit unrelated queues.
        if idapro.open_database(copied_input, run_auto_analysis=True) != 0:
            raise RuntimeError("could not open the copied ELF")
        opened = True
        print("copied ELF opened", flush=True)

        import ida_bytes
        import ida_funcs
        import ida_hexrays
        import ida_idaapi
        import ida_lines

        from dejadump.core.state import StateResolver
        from dejadump.core.store import EpochStore
        from dejadump.modes.mode_a import Activator

        store = EpochStore(copied_sidecar)
        activator = Activator(store)
        pending_before = store.pending_activation()
        reconciled = activator.reconcile()
        pending_after = store.pending_activation()
        print("startup reconciliation:", reconciled,
              "pending:", bool(pending_before), "->", bool(pending_after),
              "active=t%d" % store.active_epoch(), flush=True)
        if not reconciled or pending_after is not None or store.active_epoch() != 0:
            raise RuntimeError("startup recovery did not produce a clean t0")

        print("activating t1…", flush=True)
        began = time.perf_counter()
        activated = activator.activate(1)
        elapsed = (time.perf_counter() - began) * 1000
        resolver = StateResolver(store.load_epochs(), store.base_source())
        identified = resolver.identify_state(
            lambda ea, size: bytes(ida_bytes.get_bytes(ea, size) or b"\0" * size))
        print("t0 -> t1:", activated, "identified=t%s" % identified,
              "wall=%.0f ms" % elapsed, "phases=", activator.last_timings, flush=True)
        if not activated or identified != 1 or store.active_epoch() != 1:
            raise RuntimeError("full decrypted activation failed verification")

        import ida_segment

        # The first t1 range inside an executable segment: traces may tag
        # decrypted .text as merely "written", so do not rely on code hints.
        code_ranges = [(s, e) for s, e in store.epoch_ranges(1)
                       if (ida_segment.getseg(s) is not None and
                           ida_segment.getseg(s).perm & ida_segment.SEGPERM_EXEC)]
        first_code = code_ranges[0][0] if code_ranges else 0
        function = ida_funcs.get_func(first_code) or ida_funcs.get_next_func(first_code)
        disassembly = ""
        pseudocode_lines = 0
        if function and code_ranges and function.start_ea < code_ranges[-1][1]:
            disassembly = ida_lines.tag_remove(
                ida_lines.generate_disasm_line(function.start_ea, 0) or "")
            if ida_hexrays.init_hexrays_plugin():
                cfunc = ida_hexrays.decompile(
                    function.start_ea, flags=getattr(ida_hexrays, "DECOMP_NO_CACHE", 0))
                pseudocode_lines = len(cfunc.get_pseudocode()) if cfunc else 0
        print("native analysis: function=%s disasm=%r pseudocode_lines=%d" % (
            ("0x%X" % function.start_ea) if function else "none",
            disassembly, pseudocode_lines), flush=True)
        if not function or function.start_ea == ida_idaapi.BADADDR or not disassembly:
            raise RuntimeError("IDA did not produce native code after activation")

        print("reverting to t0…", flush=True)
        began = time.perf_counter()
        reverted = activator.revert_to_t0()
        revert_elapsed = (time.perf_counter() - began) * 1000
        identified = resolver.identify_state(
            lambda ea, size: bytes(ida_bytes.get_bytes(ea, size) or b"\0" * size))
        print("t1 -> t0:", reverted, "identified=t%s" % identified,
              "wall=%.0f ms" % revert_elapsed, "phases=", activator.last_timings,
              flush=True)
        ok = reverted and identified == 0 and store.active_epoch() == 0
        print("REAL-PAIR SMOKE:", "PASS" if ok else "FAIL")
        return 0 if ok else 1
    finally:
        if store is not None:
            store.close()
        if opened:
            idapro.close_database(False)
        shutil.rmtree(workdir, ignore_errors=True)


if __name__ == "__main__":
    if len(sys.argv) != 3:
        raise SystemExit(__doc__)
    raise SystemExit(main(sys.argv[1], sys.argv[2]))
