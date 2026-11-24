"""WaveDetector: byte-granular boundaries, no-false-boundary on shared pages,
content dedupe, and trailing-dirty flush."""

from dejadump.core.waves import IntervalSet, MemoryImage, WaveDetector


def _det(page=0x1000, code_align=4):
    return WaveDetector(MemoryImage(page=page), page=page, code_align=code_align)


def test_interval_set_coalesce_and_overlap():
    s = IntervalSet()
    s.add(0x10, 0x20)
    s.add(0x20, 0x30)  # adjacent -> merges
    assert s.ranges() == [(0x10, 0x30)]
    s.add(0x100, 0x110)
    assert s.ranges() == [(0x10, 0x30), (0x100, 0x110)]
    assert s.overlaps(0x2F, 0x31)
    assert not s.overlaps(0x30, 0x100)  # gap between the two intervals


def test_boundary_on_entering_written_bytes():
    det = _det()
    det.on_write(0xAAA, 0x1000, b"\x01\x02\x03\x04")
    assert det.on_exec(0x3000, 4) is None          # different page -> no boundary
    ep = det.on_exec(0x1000, 4)                     # enters written bytes -> boundary
    assert ep is not None
    assert ep.seq == 1
    assert len(ep.ranges) == 1
    r = ep.ranges[0]
    assert r.start == 0x1000 and r.data == b"\x01\x02\x03\x04"
    assert r.entry_pcs == (0x1000,) and r.is_code_hint


def test_no_false_boundary_when_code_and_data_share_a_page():
    # Byte-granular: writing data at 0x1800 must NOT make executing unwritten
    # code at 0x1000 (same 4 KiB page) look like a new wave.
    det = _det()
    det.on_write(0xAAA, 0x1800, b"\xaa")
    assert det.on_exec(0x1000, 4) is None           # same page, but bytes not written
    assert det.on_exec(0x1800, 4) is not None        # actually enters written data


def test_identical_commit_is_suppressed_with_repeat_count():
    det = _det()
    det.on_write(0xAAA, 0x1000, b"\xde\xad")
    assert det.on_exec(0x1000, 4) is not None        # t1
    det.on_write(0xBBB, 0x1000, b"\xde\xad")          # same bytes again
    assert det.on_exec(0x1000, 4) is None             # suppressed (identical)
    assert len(det.epochs) == 1
    assert det.epochs[0].repeat_count == 1


def test_distinct_rewrite_makes_new_epoch():
    det = _det()
    det.on_write(0xAAA, 0x1000, b"\x01\x01")
    det.on_exec(0x1000, 4)
    det.on_write(0xBBB, 0x1000, b"\x02\x02")
    det.on_exec(0x1000, 4)
    assert [e.seq for e in det.epochs] == [1, 2]
    assert det.epochs[0].ranges[0].data == b"\x01\x01"
    assert det.epochs[1].ranges[0].data == b"\x02\x02"


def test_finish_flushes_trailing_dirty_data():
    det = _det()
    det.on_write(0xAAA, 0x5000, b"\x11\x22")          # written but never executed
    ep = det.finish()
    assert ep is not None and ep.boundary_kind == "end"
    assert ep.ranges[0].start == 0x5000 and not ep.ranges[0].is_code_hint
