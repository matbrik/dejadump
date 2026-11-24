"""Headless Mode A smoke test for licensed IDA 9.4/9.5.

What it checks end to end in a real IDB:
  * the trace imports into epochs;
  * Mode A ``activate`` swaps bytes + re-runs analysis so BUF disassembles to a
    DIFFERENT stub at t1 vs t3 (versioned code at one address);
  * a name set at t1 survives t1 -> t3 -> t1 (annotation round-trip) and is NOT
    visible at t3 (per-epoch annotations do not leak);
  * the active epoch's changed spans are reported for line highlighting;
  * a second source covering new addresses gets its own t0 snapshot;
  * pin/unpin preserves canonical-shadow mappings and removes every shadow segment.

Run it with idalib (ships with IDA Pro, all 9.x, and IDA Home 9.4+):

    # make sure idalib is importable for your edition, then:
    python tools/smoke_mode_a.py                 # arm64 corpus in tests/fixtures
    python tools/smoke_mode_a.py --x64           # the x86-64 corpus
    python tools/smoke_mode_a.py <corpus_dir> [--x64]

If your idalib build won't set AArch64 from a flat blob, open any small arm64
IDB in the GUI instead and run the body of main() from the IDA Python console
(skip the open_database line). Expected: "SMOKE: PASS".
"""

from __future__ import annotations

import json
import os
import shutil
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)


def main(corpus=None, x64=False) -> int:
    corpus = corpus or os.path.join(ROOT, "tests", "fixtures")
    with open(os.path.join(corpus, "manifest.json")) as fh:
        manifest = json.load(fh)
    if x64:
        manifest = manifest["x64"]
    trace_name = os.path.splitext(manifest["elf"])[0] + ".tenet"

    import idapro

    # idapro initialization may replace sys.path with IDA's embedded-Python
    # paths. Restore the checkout so the smoke test always exercises this tree.
    if ROOT not in sys.path:
        sys.path.insert(0, ROOT)

    # Open the AArch64 ELF: IDA auto-detects the processor and creates the
    # CODE/BUF/DATA segments at the right addresses (no flat-blob guessing).
    workdir = tempfile.mkdtemp(prefix="dejadump-smoke-")
    elf_path = os.path.join(workdir, os.path.basename(manifest["elf"]))
    shutil.copy2(os.path.join(corpus, manifest["elf"]), elf_path)
    idapro.open_database(elf_path, run_auto_analysis=False)

    import ida_auto
    import ida_bytes
    import ida_idaapi
    import ida_kernwin
    import ida_name
    import idc

    # idalib has no UI: show DejaDump's warnings instead of losing them.
    ida_kernwin.warning = lambda message: print("WARNING:", message)
    ida_kernwin.info = lambda message: print("INFO:", message)

    from dejadump.core import tenet
    from dejadump.core.store import EpochStore
    from dejadump.modes.mode_a import Activator

    # Match the plugin's contract: canonical switching starts only after the
    # loader's unrelated initial queues have drained.
    ida_auto.auto_wait()

    db = os.path.join(workdir, "smoke.dejadump.db")
    store = EpochStore(db)
    arch = tenet.AMD64 if x64 else tenet.ARM64

    # Import the way the GUI does (rebase resolution + segment filter from the
    # registry defaults), and replay a misleading "slide=0x0" header over the
    # corpus's absolute addresses: the PC check must offer the detected rebase.
    from dejadump.controller import Controller, idb_segments
    from dejadump.util import settings

    trace_path = os.path.join(corpus, trace_name)
    with open(trace_path, encoding="utf-8") as fh:
        head = [next(fh, "") for _ in range(400)]
    asked = []
    ida_kernwin.ask_yn = lambda _default, message: asked.append(message) or 1
    bad_slide, bad_base, _how = Controller()._trace_rebase(trace_path, ["slide=0x0\n"] + head)
    slide, image_base, how = Controller()._trace_rebase(trace_path, head)
    keep = ([(s, e) for s, e, _perm in idb_segments()]
            if settings.get_bool("filter_traces") else None)
    stats = tenet.ImportStats()
    tenet.import_trace_file(trace_path, store, arch=arch, slide=slide,
                            image_base=image_base, keep=keep, stats=stats)
    import_ok = bool(asked and bad_base - bad_slide == 0 and stats.rebase == 0
                     and keep and not stats.writes_dropped and settings.get_bool("highlight"))
    print("GUI import path:", import_ok, "(%s; rebase %s; bad header caught=%s; filter=%s)" %
          (how, hex(stats.rebase), bool(asked), keep is not None))
    act = Activator(store)
    act.ensure_base()

    buf = manifest["regions"]["buf"]["base"]

    act.activate(1)
    ida_auto.auto_wait()
    d1 = idc.GetDisasm(buf)
    ida_name.set_name(buf, "stub_v1", ida_name.SN_NOCHECK | ida_name.SN_FORCE)

    act.activate(3)
    ida_auto.auto_wait()
    d3 = idc.GetDisasm(buf)
    name_at_t3 = ida_name.get_name(buf)
    spans_t3 = act.changed_spans(3)

    act.activate(1)
    ida_auto.auto_wait()
    d1b = idc.GetDisasm(buf)
    name_back = ida_name.get_name(buf)

    print("t1 BUF        :", d1)
    print("t3 BUF        :", d3)
    print("t1-again BUF  :", d1b)
    print("name round-trip:", name_back, "· name at t3:", name_at_t3)
    print("t3 changed spans:", [(hex(a), hex(b)) for a, b in spans_t3])
    mode_a_ok = ((d1 != d3) and (d1 == d1b) and (name_back == "stub_v1")
                 and name_at_t3 != "stub_v1" and bool(spans_t3))

    # --- R3: data over time ------------------------------------------------
    from dejadump.core.state import StateResolver
    from dejadump.core.timeline import MemoryTimeline
    from dejadump.hexrays import bridge

    data = manifest["regions"]["data"]["base"]
    resolver = StateResolver(store.load_epochs(), base=store.base_source())
    tl = MemoryTimeline(resolver, writer_lookup=store.writes_for_addr)
    pt = tl.first_plaintext_epoch(data, 16)
    plaintext = bytes(tl.column(pt, data, 16)) if pt else b""
    print("first-plaintext epoch:", pt, "->", plaintext)

    n = bridge.materialize_write_xrefs(store, store.volatile_set())
    import ida_xref

    def _drefs_to(ea):
        out, f = [], ida_xref.get_first_dref_to(ea)
        while f != ida_idaapi.BADADDR:
            out.append(f)
            f = ida_xref.get_next_dref_to(ea, f)
        return out

    buf_xrefs = _drefs_to(buf)    # BUF written by the mutator at t1/t2/t3
    data_xrefs = _drefs_to(data)
    print("xrefs to BUF 0x%x (times written):" % buf, [hex(x) for x in buf_xrefs])
    print("xrefs to DATA 0x%x:" % data, [hex(x) for x in data_xrefs])

    r3_ok = (
        pt == 4
        and plaintext == b"DEJADUMP_OK!!!!\x00"
        and n > 0
        and len(buf_xrefs) >= 3     # xref a location across multiple times
        and len(data_xrefs) >= 1
    )

    # t3 -> t4 changes only the DATA region and must not queue code analysis.
    act.activate(3)
    data_only_ok = act.activate(4) and not act.last_timings.get("analysis_required", True)
    print("data-only fast path:", data_only_ok, act.last_timings)

    # --- Mode B: sparse shadow mapping and deterministic cleanup ---------
    from dejadump.modes.mode_b import Pinner
    import ida_segment

    pinner = Pinner(store)
    pinned = pinner.pin(1)
    shadow = pinner.canonical_to_shadow(1, buf)
    mapped_back = pinner.shadow_to_canonical(1, shadow) if shadow is not None else None
    def mapped(ea):
        return ida_segment.getseg(ea) is not None

    existed = bool(shadow is not None and mapped(shadow))
    pinner.unpin(1)
    cleaned = bool(shadow is not None and not mapped(shadow)
                   and store.get_pin(store.epoch_ref(1)) is None)
    pin_ok = bool(pinned and mapped_back == buf and existed and cleaned)
    print("pin/unpin cleanup:", pin_ok, "segments=", len(pinned))

    # Optional, deliberately expensive rollback checks at every transaction stage.
    fault_ok = True
    if os.environ.get("DEJADUMP_FAULT_TESTS") == "1":
        for stage in ("planned", "bytes_applied", "analysis_complete",
                      "annotations_restored", "verified"):
            act.revert_to_t0()
            fired = []

            def inject(current, wanted=stage):
                if current == wanted:
                    fired.append(current)
                    raise RuntimeError("injected fault at " + wanted)

            act.fault_injector = inject
            result = act.activate(1)
            act.fault_injector = None
            # The fault must really have fired: a refused switch proves nothing.
            rolled_back = bool(fired and not result and store.active_epoch() == 0
                               and act.reconcile())
            print("fault %-20s rollback=%s" % (stage, rolled_back))
            fault_ok = fault_ok and rolled_back

    # --- a second source over addresses the first never touched -------------
    from dejadump.core.model import Epoch, Range

    act.revert_to_t0()
    extra = manifest["regions"]["data"]["base"] + 0x800
    original = bytes(ida_bytes.get_bytes(extra, 8) or b"")
    store.import_source("dump", "second source", [
        Epoch(seq=1, ranges=[Range(extra, b"\x5a" * 8, is_code_hint=False)],
              boundary_kind="dump")])
    act.invalidate()
    act.ensure_base()
    base_ok = store.base_source().read(extra, 8) == original
    switched = act.activate(1) and bytes(ida_bytes.get_bytes(extra, 8)) == b"\x5a" * 8
    reverted = act.revert_to_t0() and bytes(ida_bytes.get_bytes(extra, 8)) == original
    second_ok = bool(base_ok and switched and reverted)
    print("second source t0 snapshot:", second_ok, "(base=%s switch=%s revert=%s)" %
          (base_ok, switched, reverted))

    # --- a write no segment covers is refused up front, with the reason --------
    store.import_source("dump", "unmapped", [
        Epoch(seq=1, ranges=[Range(0x400020, b"\x01", is_code_hint=False)],
              boundary_kind="dump")])
    act.invalidate()
    act.ensure_base()
    warned = []
    ida_kernwin.warning = warned.append
    refused = not act.activate(1) and store.active_epoch() == 0
    unmapped_ok = bool(refused and any("no IDB segment covers" in m for m in warned))
    print("unmapped write refused:", unmapped_ok, warned[-1:] and warned[-1].splitlines()[0])

    ok = (import_ok and mode_a_ok and r3_ok and data_only_ok and pin_ok and fault_ok
          and second_ok and unmapped_ok)
    print("SMOKE:", "PASS" if ok else "FAIL",
          "(arch=%s import=%s modeA=%s r3=%s data=%s pin=%s fault=%s second=%s "
          "unmapped=%s)" % (arch.name, import_ok, mode_a_ok, r3_ok, data_only_ok, pin_ok,
                            fault_ok, second_ok, unmapped_ok))

    store.close()
    idapro.close_database(False)
    shutil.rmtree(workdir, ignore_errors=True)
    return 0 if ok else 1


if __name__ == "__main__":
    args = [a for a in sys.argv[1:] if a != "--x64"]
    raise SystemExit(main(args[0] if args else None, x64="--x64" in sys.argv[1:]))
