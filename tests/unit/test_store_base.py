"""Store additions for Mode A: base (t0) snapshot, annotations, active epoch."""

from dejadump.core.state import StateResolver
from dejadump.core.store import EpochStore
from dejadump.core.model import Epoch, Range


def test_base_source_round_trip_and_gaps():
    store = EpochStore(":memory:")
    assert not store.has_base()
    store.set_base_range(0x1000, b"\xAA\xBB\xCC\xDD")
    assert store.has_base()
    src = store.base_source()
    assert src.read(0x1000, 4) == b"\xAA\xBB\xCC\xDD"
    assert src.read(0x1002, 2) == b"\xCC\xDD"
    assert src.read(0x2000, 2) == b"\x00\x00"  # gap -> zero
    store.close()


def test_base_feeds_state_resolver():
    store = EpochStore(":memory:")
    store.set_base_range(0x1000, b"\x00\x00\x00\x00")
    r = StateResolver([Epoch(seq=1, ranges=[Range(0x1000, b"\x11\x11")])], base=store.base_source())
    assert r.state(1, 0x1000, 4) == b"\x11\x11\x00\x00"
    assert r.state(0, 0x1000, 4) == b"\x00\x00\x00\x00"
    store.close()


def test_annotations_and_active_epoch():
    store = EpochStore(":memory:")
    store.set_annot(3, 0x1000, {"names": [{"off": 0, "name": "decrypt_stage3"}]})
    assert store.get_annot(3, 0x1000)["names"][0]["name"] == "decrypt_stage3"
    assert set(store.annots_for_epoch(3)) == {0x1000}

    assert store.active_epoch() == 0
    store.set_active_epoch(3)
    assert store.active_epoch() == 3
    store.close()
