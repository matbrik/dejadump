"""Sidecar v3: cached SQL content hash, aggregates, bounded write queries, base
gaps for later sources, source management, pruning and garbage collection."""

import hashlib
import random
import sqlite3

from dejadump.core.model import AnalysisArtifact, Epoch, Range, WriteRecord
from dejadump.core.store import SCHEMA_VERSION, EpochStore


def _legacy_hash(store):
    h = hashlib.sha256()
    for ep in store.epochs():
        h.update(str(ep["seq"]).encode())
        for r in store.ranges(ep["id"]):
            h.update(r.start.to_bytes(8, "little"))
            h.update(r.sha256)
    return h.hexdigest()


def _store():
    store = EpochStore(":memory:")
    store.import_source("tenet", "a", [
        Epoch(seq=1, ranges=[Range(0x1000, b"\x01" * 8, entry_pcs=(0x1000,), is_code_hint=True),
                             Range(0x2000, b"DATA", is_code_hint=False)],
              writes=[WriteRecord(0x500, 0x1000, b"\x01" * 8), WriteRecord(0x504, 0x2000, b"DATA")]),
        Epoch(seq=2, ranges=[], writes=[]),
        Epoch(seq=3, ranges=[Range(0x1004, b"\x02" * 4, is_code_hint=True)],
              writes=[WriteRecord(0x508, 0x1004, b"\x02" * 4)]),
    ])
    return store


def test_content_hash_matches_the_blob_based_original_and_is_cached():
    store = _store()
    assert store.content_hash() == _legacy_hash(store)
    generation = store.generation
    assert store.content_hash() == store.content_hash()
    store.append_epoch(Epoch(seq=4, ranges=[Range(0x3000, b"x")], boundary_kind="manual"))
    assert store.generation > generation
    assert store.content_hash() == _legacy_hash(store)


def test_epoch_summaries_without_reading_blobs():
    store = _store()
    summaries = store.epoch_summaries()
    first = store.epochs()[0]["id"]
    assert summaries[first] == {"ranges": 2, "bytes": 12, "code_bytes": 8, "functions": 1}
    assert store.epochs_touching(0x1000, 0x1008) == [1, 3]
    assert store.epoch_ranges(3) == [(0x1004, 0x1008)]


def test_bounded_write_queries_equal_the_naive_overlap_query():
    rng = random.Random(3)
    writes = []
    for i in range(400):
        size = rng.choice([1, 2, 4, 8, 16, 64, 65, 300, 5000])
        writes.append(WriteRecord(0x400000 + i, rng.randint(0, 0x20000), b"\x00" * size, seq=i))
    store = EpochStore(":memory:")
    store.import_source("tenet", "w", [Epoch(seq=1, ranges=[Range(0, b"\x00")], writes=writes)])
    naive = ("SELECT e.seq,w.seq,w.writer_pc,w.addr,w.size,w.new_bytes,w.old_bytes FROM writes w "
             "JOIN epochs e ON e.id=w.epoch_id WHERE e.source_id=? AND w.addr<? AND ?<w.addr+w.size "
             "ORDER BY e.seq,w.seq")
    for _ in range(200):
        start = rng.randint(0, 0x21000)
        end = start + rng.choice([1, 1, 4, 64, 4096])
        expected = store.conn.execute(naive, (store.active_source_id(), end, start)).fetchall()
        got = [tuple(r[k] for k in store._WRITE_KEYS) for r in store.writes_for_range(start, end)]
        assert got == expected


def test_base_gaps_cover_ranges_of_a_later_source():
    store = _store()
    store.set_base_range(0x1000, b"\x00" * 8)
    store.set_base_range(0x2000, b"\x00" * 4)
    assert store.base_gaps() == []
    store.import_source("dump", "b", [Epoch(seq=1, ranges=[Range(0x1004, b"\x09" * 12)])])
    assert store.base_gaps() == [(0x1008, 0x1010)]


def test_duplicate_detection_rename_and_delete():
    store = _store()
    epochs = [Epoch(seq=1, ranges=[Range(0x1000, b"\x01" * 8, is_code_hint=True)])]
    a = store.import_source("dump", "pair", epochs)
    b = store.import_source("dump", "pair again", epochs)
    assert store.duplicate_of(b) == a and store.duplicate_of(1) is None
    store.rename_source(b, "renamed")
    assert [s["label"] for s in store.sources()][-1] == "renamed"
    store.set_annot(store.epoch_ref(1, b), 0x1000, {"names": []})
    store.delete_source(b)
    assert [s["id"] for s in store.sources()] == [1, a]
    assert store.active_source_id() == a
    assert store.conn.execute("SELECT COUNT(*) FROM annots").fetchone()[0] == 0


def test_stale_artifacts_are_pruned_and_journal_is_capped():
    store = _store()
    ref = store.epoch_ref(1)
    for version in ("v1", "v2"):
        store.put_artifact(AnalysisArtifact(ref, "assembly", 0, 4, version, ["x"], [0]))
    rows = store.conn.execute("SELECT version_key FROM analysis_artifacts").fetchall()
    assert rows == [("v2",)]
    store.JOURNAL_KEEP = 3
    for _ in range(10):
        jid = store.begin_activation(store.epoch_ref(0), ref, {"stage": "planned"})
        store.finish_activation(jid, "committed")
    assert store.conn.execute("SELECT COUNT(*) FROM activation_journal").fetchone()[0] <= 3


def test_garbage_collection_keeps_referenced_and_pending_blobs(tmp_path):
    store = EpochStore(str(tmp_path / "s.db"))
    store.import_source("dump", "x", [Epoch(seq=1, ranges=[Range(0x10, b"keep")])])
    orphan, _ = store.blob_id(b"orphan")
    _, pending = store.blob_id(b"preimage")
    store.conn.commit()
    store.begin_activation(store.epoch_ref(0), store.epoch_ref(1),
                           {"stage": "planned", "preimages": [{"addr": 0, "size": 8,
                                                               "sha256": pending.hex()}]})
    removed = store.compact()["blobs_removed"]
    assert removed == 1
    assert store.blob(pending) == b"preimage"
    store.close()


def test_v2_sidecar_migrates_to_v3_with_signatures(tmp_path):
    path = str(tmp_path / "old.db")
    store = _store()
    backup = sqlite3.connect(path)
    store.conn.backup(backup)
    backup.execute("UPDATE meta SET value='2' WHERE key='schema_version'")
    backup.execute("UPDATE sources SET signature=NULL")
    backup.commit()
    backup.close()
    migrated = EpochStore(path)
    assert migrated.get_meta("schema_version") == str(SCHEMA_VERSION) == "3"
    assert migrated.sources()[0]["signature"] == migrated.content_hash(1)
    migrated.close()


def test_observed_layer_round_trip():
    store = _store()
    store.set_observed(1, [Range(0x5000, b"\xde\xad")])
    assert store.observed() == [(0x5000, b"\xde\xad")]
