"""Tenet importer: writer-PC lag, mr/mw/mrw, multi-token lines, Frinet slide."""

from dejadump.core.tenet import ARM64, import_trace, parse_line


def test_writer_pc_lag():
    # On a Tenet line the deltas belong to the PREVIOUS instruction, so a write
    # read on line N was performed by line N-1's PC.
    lines = [
        "pc=0x1000",                      # A about to execute
        "pc=0x1004,mw=0x4000:11223344",   # A executed (wrote 0x4000); B next
        "pc=0x1008,mw=0x4000:55667788",   # B executed (wrote 0x4000); C next
    ]
    det, mem = import_trace(lines, arch=ARM64)
    writes = [w for e in det.epochs for w in e.writes]
    assert len(writes) == 2
    assert writes[0].writer_pc == 0x1000  # NOT 0x1004
    assert writes[1].writer_pc == 0x1004  # NOT 0x1008
    assert mem.read(0x4000, 4) == b"\x55\x66\x77\x88"  # last write wins


def test_mrw_and_multiple_tokens_per_line():
    lines = [
        "pc=0x1000",
        "pc=0x1004,mr=0x4000:aa,mrw=0x5000:bb,mw=0x6000:cc",
    ]
    det, mem = import_trace(lines, arch=ARM64)
    writes = {w.addr: w.data for e in det.epochs for w in e.writes}
    # mrw routed to the write path, and BOTH memory writes on the line parsed.
    assert writes == {0x5000: b"\xbb", 0x6000: b"\xcc"}
    assert mem.read(0x5000, 1) == b"\xbb" and mem.read(0x6000, 1) == b"\xcc"


def test_parse_line_routes_mrw_to_both():
    p = parse_line("pc=0x10,mrw=0x20:de", ARM64)
    assert p.pc == 0x10
    assert p.writes == [(0x20, b"\xde")]
    assert p.reads == [(0x20, b"\xde")]


def test_frinet_slide_is_subtracted():
    lines = [
        "slide=0x1000",
        "pc=0x2000",                     # canonical 0x1000
        "pc=0x2004,mw=0x5000:aa",        # canonical write 0x4000, writer 0x1000
    ]
    det, mem = import_trace(lines, arch=ARM64)
    assert mem.read(0x4000, 1) == b"\xaa"
    w = det.epochs[0].writes[0]
    assert w.addr == 0x4000 and w.writer_pc == 0x1000
