"""Cross-epoch search, revealed strings, changed spans, observed layer and the
per-instance state cache."""

import gc
import weakref

from dejadump.core.diffing import align
from dejadump.core.model import Epoch, Range
from dejadump.core.search import parse_needle, search_epochs, strings_revealed
from dejadump.core.state import BytesBase, StateResolver
from dejadump.core.timeline import MemoryTimeline


def _resolver(observed=None):
    base = BytesBase([(0x1000, b"\x00" * 0x40)])
    epochs = [
        Epoch(seq=1, ranges=[Range(0x1000, b"\x8a\x91\x77\x00SECRET")]),
        Epoch(seq=2, ranges=[Range(0x1004, b"HELLO_WORLD!")]),
    ]
    return StateResolver(epochs, base=base, observed=observed)


def test_parse_needle():
    assert parse_needle("de ad be ef") == b"\xde\xad\xbe\xef"
    assert parse_needle('"dead"') == b"dead"
    assert parse_needle("hello") == b"hello"


def test_search_reports_every_epoch_containing_the_bytes():
    hits = search_epochs(_resolver(), b"SECRET")
    assert hits == [{"addr": 0x1004, "epochs": [1], "first": 1}]
    hits = search_epochs(_resolver(), b"WORLD")
    assert hits[0]["first"] == 2


def test_strings_revealed_by_a_wave():
    res = _resolver()
    rows = strings_revealed(res, 2, [(0x1004, 0x1010)])
    assert rows and rows[0]["text"].startswith("HELLO_WORLD")
    assert strings_revealed(res, 0, [(0x1000, 0x1010)]) == []


def test_changed_spans_only_cover_bytes_that_differ():
    res = _resolver()
    assert res.changed_spans(1) == [(0x1000, 0x1003), (0x1004, 0x100A)]
    assert res.changed_spans(0) == []


def test_observed_layer_applies_from_t1_under_the_epochs():
    res = _resolver(observed=[(0x1020, b"\x41\x42")])
    assert res.observed_state(0, 0x1020, 2) == b"\x00\x00"
    assert res.observed_state(1, 0x1020, 2) == b"AB"
    assert res.state(1, 0x1020, 2) == b"\x00\x00"           # Mode A never sees it
    assert list(res.observed_mask(0x101E, 4)) == [0, 0, 1, 1]
    tl = MemoryTimeline(res)
    assert tl.column(1, 0x1020, 2) == b"AB"
    assert list(tl.observed_mask(0x1020, 2)) == [1, 1]


def test_identify_state_with_single_read_per_chunk():
    res = _resolver()
    calls = []

    def reader(addr, size):
        calls.append(addr)
        return res.state(2, addr, size)

    assert res.identify_state(reader) == 2
    assert len(calls) == len(set(calls))       # each chunk read once


def test_state_cache_does_not_keep_resolvers_alive():
    res = _resolver()
    res.state(1, 0x1000, 4)
    ref = weakref.ref(res)
    del res
    gc.collect()
    assert ref() is None


def test_align_pads_inserted_and_deleted_lines():
    left, right = ["a", "b", "c"], ["a", "x", "c", "d"]
    rows_l, rows_r, addr_l, addr_r, tags = align(left, right, [1, 2, 3], [1, 9, 3, 4],
                                                 kind="assembly", normalized=False)
    assert len(rows_l) == len(rows_r) == len(tags)
    assert rows_l[-1] == "" and rows_r[-1] == "d" and tags[-1] == "insert"
    assert addr_l[-1] is None and addr_r[-1] == 4
