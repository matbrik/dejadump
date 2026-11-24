"""Bring-your-own-trace import: segment filter, rebase, malformed lines, progress
cancel, observed reads, slide/module discovery and manifests."""

import json

import pytest

from dejadump.core import tenet
from dejadump.core.store import EpochStore

TRACE = [
    "slide=0x7f0000000000",
    "pc=0x7f0000001000",
    "pc=0x7f0000001004,mw=0x7f0000004000:aabbccdd",      # inside the module
    "pc=0x7f0000001008,mw=0x7ffffff0000:11223344",        # stack: outside
    "pc=0x7f000000100c,mr=0x7f0000005000:deadbeef",      # read never written
    "pc=0x7f0000004000",                                   # executes written code
]


def test_keep_filter_drops_outside_writes_and_rebases_to_image_base():
    stats = tenet.ImportStats()
    det, mem = tenet.import_trace(TRACE, arch=tenet.ARM64, image_base=0x100000,
                                  keep=[(0x100000, 0x110000)], stats=stats)
    assert stats.writes_kept == 1 and stats.writes_dropped == 1
    assert mem.read(0x104000, 4) == bytes.fromhex("aabbccdd")
    assert [e.boundary_kind for e in det.epochs] == ["wave"]
    assert det.epochs[0].ranges[0].start == 0x104000
    assert stats.rebase == 0x100000 - 0x7F0000000000


def test_partial_write_is_clipped_to_the_keep_list():
    lines = ["pc=0x1000", "pc=0x1004,mw=0x1ffe:11223344"]
    det, mem = tenet.import_trace(lines, arch=tenet.ARM64, keep=[(0x1000, 0x2000)])
    assert [(r.start, r.data) for r in det.epochs[0].ranges] == [(0x1ffe, b"\x11\x22")]


def test_malformed_lines_are_skipped_and_counted():
    stats = tenet.ImportStats()
    lines = ["pc=0x1000", "pc=0x1004,mw=0x2000:zz", "pc=0x1008,mw=0x2000", "pc=0x100c,mw=0x2000:aa"]
    det, mem = tenet.import_trace(lines, arch=tenet.ARM64, stats=stats)
    assert stats.malformed == 2 and stats.first_malformed_line == 2
    assert mem.read(0x2000, 1) == b"\xaa"
    assert "malformed" in stats.summary()


def test_progress_can_cancel(monkeypatch):
    monkeypatch.setattr(tenet, "PROGRESS_EVERY", 2)
    with pytest.raises(tenet.ImportCancelled):
        tenet.import_trace(["pc=0x1000"] * 10, arch=tenet.ARM64, progress=lambda n: False)


def test_observed_reads_are_kept_for_never_written_bytes(tmp_path):
    stats = tenet.ImportStats()
    tenet.import_trace(TRACE, arch=tenet.ARM64, image_base=0x100000,
                       keep=[(0x100000, 0x110000)], stats=stats)
    assert [(r.start, r.data) for r in stats.observed] == [(0x105000, bytes.fromhex("deadbeef"))]
    # A read of bytes written earlier is not "observed".
    stats2 = tenet.ImportStats()
    tenet.import_trace(["pc=0x1000", "pc=0x1004,mw=0x2000:aa", "pc=0x1008,mr=0x2000:aa"],
                       arch=tenet.ARM64, stats=stats2)
    assert stats2.observed == [] and stats2.reads_observed == 0


def test_import_trace_file_persists_observed_layer_and_params(tmp_path):
    path = tmp_path / "t.tenet"
    path.write_text("\n".join(TRACE))
    store = EpochStore(str(tmp_path / "s.db"))
    source = tenet.import_trace_file(str(path), store, arch=tenet.ARM64, image_base=0x100000,
                                     keep=[(0x100000, 0x110000)])
    assert store.observed(source) == [(0x105000, bytes.fromhex("deadbeef"))]
    params = json.loads(store.sources()[0]["params"])
    assert params["stats"]["writes_dropped"] == 1 and params["image_base"] == 0x100000
    store.close()


def test_detect_arch_and_header():
    assert tenet.detect_arch(["rip=0x1"]) is tenet.AMD64
    assert tenet.detect_arch(["foo=1"]) is None
    header = tenet.read_header(TRACE[:3])
    assert header["slide"] == 0x7F0000000000 and header["pcs"][0] == 0x7F0000001000


def test_detect_slide_votes_for_the_shift_into_code():
    code = [(0x1000, 0x3000)]
    pcs = [0x7F0000001000 + i * 4 for i in range(200)]
    assert tenet.detect_slide(pcs, code) == 0x7F0000000000
    assert tenet.detect_slide([0x1000, 0x1004], code) == 0
    assert tenet.detect_slide([], code) is None


def test_a_wrong_slide_header_is_caught_by_the_pc_fit():
    # The corpus once said "slide=0x0" over absolute addresses: with the IDB image
    # base 0x100000 that rebased everything by +0x100000, out of the code.
    code = [(0x100000, 0x102000), (0x200000, 0x201000)]
    pcs = [0x100000 + i * 4 for i in range(78)] + [0x200000 + i * 4 for i in range(9)]
    header_rebase = 0x100000 - 0x0
    # Most PCs still land in *some* executable segment (the RWX buffer), so only
    # the comparison with the detected rebase exposes the header.
    assert tenet.pcs_in_code(pcs, code, header_rebase) == 78
    assert tenet.detect_slide(pcs, code) == 0
    assert tenet.pcs_in_code(pcs, code, 0) == len(pcs)


def test_frinet_modules_file_and_manifest(tmp_path):
    trace = tmp_path / "app_1700000000_4242.tenet"
    trace.write_text("pc=0x1\n")
    (tmp_path / "app_1700000000.modules").write_text(
        "libc.so 0x7f000000 0x7f100000\nlibtarget.so 0x7e000000 0x7e800000\n")
    found = tenet.find_modules_file(str(trace))
    assert found and found.endswith(".modules")
    module = tenet.module_for(tenet.load_modules(found), "/path/to/libtarget.so")
    assert module == {"name": "libtarget.so", "start": 0x7E000000, "end": 0x7E800000}

    (tmp_path / (trace.name + ".json")).write_text(json.dumps(
        {"arch": "arm64", "slide": "0x7e000000", "keep": [["0x0", "0x1000"]]}))
    manifest = tenet.load_manifest(str(trace))
    assert manifest["arch"] == "arm64" and manifest["slide"] == 0x7E000000
    assert manifest["keep"] == [(0, 0x1000)]
