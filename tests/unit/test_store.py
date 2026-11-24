"""EpochStore: round-trip, content-addressed blob dedupe, volatile set, writes."""

from dejadump.core.model import Epoch, Range, WriteRecord
from dejadump.core.store import EpochStore


def _sample_epochs():
    shared = b"STAGE-TWO-CODE!!"  # identical bytes in two epochs -> one blob
    t1 = Epoch(
        seq=1,
        ranges=[Range(0x1000, shared, entry_pcs=(0x1000,), is_code_hint=True)],
        writes=[WriteRecord(0xC0DE, 0x1000, shared, seq=0)],
        boundary_kind="wave",
        boundary_pc=0x1000,
    )
    t2 = Epoch(
        seq=2,
        ranges=[
            Range(0x1000, shared, entry_pcs=(0x1000,), is_code_hint=True),  # same bytes
            Range(0x2000, b"\x00\x01\x02\x03"),
        ],
        writes=[WriteRecord(0xBEEF, 0x2000, b"\x00\x01\x02\x03", seq=0)],
        boundary_kind="end",
    )
    return [t1, t2]


def test_round_trip_and_blob_dedupe():
    store = EpochStore(":memory:")
    store.import_source("tenet", "sample", _sample_epochs())

    eps = store.epochs()
    assert [e["seq"] for e in eps] == [1, 2]
    assert eps[0]["boundary_kind"] == "wave" and eps[0]["boundary_pc"] == 0x1000

    r1 = store.ranges(eps[0]["id"])
    assert len(r1) == 1 and r1[0].start == 0x1000 and r1[0].is_code_hint
    assert r1[0].entry_pcs == (0x1000,)

    # The identical 16-byte stage appears in both epochs but is stored once.
    blob_count = store.conn.execute("SELECT COUNT(*) FROM blobs").fetchone()[0]
    assert blob_count == 2  # the shared stage + the 4-byte range
    store.close()


def test_volatile_set_and_writes_and_hash():
    store = EpochStore(":memory:")
    store.import_source("tenet", "sample", _sample_epochs())

    assert store.volatile_set() == [(0x1000, 0x1010), (0x2000, 0x2004)]

    w = store.writes_for_addr(0x2001)
    assert len(w) == 1 and w[0]["writer_pc"] == 0xBEEF and w[0]["epoch_seq"] == 2

    # content_hash is stable across a reload of the same data.
    h1 = store.content_hash()
    store2 = EpochStore(":memory:")
    store2.import_source("tenet", "sample", _sample_epochs())
    assert store2.content_hash() == h1
    store.close()
    store2.close()


def test_append_manual_epoch_preserves_source_and_base():
    store = EpochStore(":memory:")
    store.set_base_range(0x1000, b"BASE")
    source_id = store.import_source("tenet", "sample", _sample_epochs())
    before_hash = store.content_hash()

    epoch_id = store.append_epoch(Epoch(
        seq=3,
        ranges=[Range(0x1001, b"IDB", is_code_hint=False)],
        boundary_kind="manual",
        label="IDB changes",
    ))

    assert store.active_source_id() == source_id
    assert store.active_epoch() == 3
    assert store.epoch_ref(3).epoch_id == epoch_id
    assert store.base_source().read(0x1000, 4) == b"BASE"
    assert store.load_epochs()[-1].boundary_kind == "manual"
    assert store.content_hash() != before_hash
    store.close()
