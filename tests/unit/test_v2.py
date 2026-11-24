import sqlite3
import struct

from dejadump.core.diffing import normalize_line, unified_diff
from dejadump.core.model import AnalysisArtifact, Epoch, Range
from dejadump.core.state import BytesBase, StateResolver
from dejadump.core.store import EpochStore, SCHEMA_VERSION
from dejadump.capture.rawdump import import_elf_pair


def test_multiple_sources_have_unambiguous_epoch_refs():
    store = EpochStore(":memory:")
    s1 = store.import_source("one", "one", [Epoch(1, [Range(0x1000, b"A")])])
    s2 = store.import_source("two", "two", [Epoch(1, [Range(0x2000, b"B")])])
    assert s1 != s2
    assert store.active_source_id() == s2
    assert [e["source_id"] for e in store.epochs()] == [s2]
    assert store.epoch_ref(1).source_id == s2
    assert store.volatile_set() == [(0x2000, 0x2001)]


def test_multiple_sources_keep_t0_annotations_and_artifacts_separate():
    store = EpochStore(":memory:")
    s1 = store.import_source("one", "one", [Epoch(1, [Range(0x1000, b"A")])])
    s2 = store.import_source("two", "two", [Epoch(1, [Range(0x1000, b"B")])])
    t0_one, t0_two = store.epoch_ref(0, s1), store.epoch_ref(0, s2)
    store.set_annot(t0_one, 0x1000, {"source": "one"})
    store.set_annot(t0_two, 0x1000, {"source": "two"})
    assert store.get_annot(t0_one, 0x1000) == {"source": "one"}
    assert store.get_annot(t0_two, 0x1000) == {"source": "two"}

    a1 = AnalysisArtifact(t0_one, "assembly", 0x1000, 0x1001, "v", ["one"])
    a2 = AnalysisArtifact(t0_two, "assembly", 0x1000, 0x1001, "v", ["two"])
    store.put_artifact(a1)
    store.put_artifact(a2)
    assert store.get_artifact(t0_one, "assembly", 0x1000, 0x1001, "v").lines == ["one"]
    assert store.get_artifact(t0_two, "assembly", 0x1000, 0x1001, "v").lines == ["two"]
    assert store.artifact_stats(t0_one)["count"] == 1
    assert store.artifact_stats(t0_two)["count"] == 1
    assert store.latest_artifact(t0_one).lines == ["one"]


def test_favorites_are_source_local():
    store = EpochStore(":memory:")
    s1 = store.import_source("one", "one", [Epoch(1, [Range(0x1000, b"A")])])
    s2 = store.import_source("two", "two", [Epoch(1, [Range(0x1000, b"B")])])
    store.set_favorite(1, True, s1)
    assert store.favorites(s1) == {1}
    assert store.favorites(s2) == set()


def test_shared_annotations_are_source_scoped_and_invalidate_artifacts():
    store = EpochStore(":memory:")
    s1 = store.import_source("one", "one", [Epoch(1, [Range(0x1000, b"A")])])
    s2 = store.import_source("two", "two", [Epoch(1, [Range(0x1000, b"B")])])
    before = store.annotation_revision(store.epoch_ref(1, s1))
    store.set_shared_annot(0x1000, {"names": [{"name": "shared"}]}, s1)
    assert store.shared_annots(s1)[0x1000]["names"][0]["name"] == "shared"
    assert store.shared_annots(s2) == {}
    assert store.annotation_revision(store.epoch_ref(1, s1)) > before


def test_range_writer_prefetch_is_source_scoped():
    from dejadump.core.model import WriteRecord
    from dejadump.core.timeline import MemoryTimeline

    store = EpochStore(":memory:")
    store.import_source("one", "one", [
        Epoch(1, [Range(0x1000, b"AB")],
              writes=[WriteRecord(0x2000, 0x1000, b"AB", seq=1)])
    ])
    timeline = MemoryTimeline(
        StateResolver(store.load_epochs(), BytesBase([(0x1000, b"\0\0")])),
        writer_range_lookup=store.writes_for_range,
    )
    timeline.prefetch_writers(0x1000, 2)
    assert timeline.writers(0x1000)[0]["writer_pc"] == 0x2000
    assert timeline.writers(0x1001)[0]["writer_pc"] == 0x2000


def test_v1_database_migrates_annotations_to_real_epoch_id(tmp_path):
    path = tmp_path / "old.db"
    conn = sqlite3.connect(path)
    conn.executescript("""
        CREATE TABLE meta(key TEXT PRIMARY KEY,value TEXT);
        CREATE TABLE sources(id INTEGER PRIMARY KEY,kind TEXT,label TEXT,created TEXT,params TEXT);
        CREATE TABLE epochs(id INTEGER PRIMARY KEY,source_id INT,seq INT,label TEXT,
          boundary_kind TEXT,boundary_pc INT,trace_index INT,created TEXT,note TEXT,
          repeat_count INT DEFAULT 0);
        CREATE TABLE annots(epoch_id INT,range_start INT,payload TEXT,
          PRIMARY KEY(epoch_id,range_start));
        INSERT INTO meta VALUES('schema_version','1');
        INSERT INTO sources VALUES(7,'x','x','','{}');
        INSERT INTO epochs VALUES(42,7,1,'','wave',NULL,NULL,'','',0);
        INSERT INTO annots VALUES(1,4096,'{"names":[]}');
    """)
    conn.commit()
    conn.close()
    store = EpochStore(str(path))
    assert store.get_meta("schema_version") == str(SCHEMA_VERSION)
    assert store.conn.execute("SELECT epoch_id FROM annots").fetchone()[0] == 42


def test_fresh_sidecar_does_not_create_migration_backup(tmp_path):
    path = tmp_path / "fresh.db"
    store = EpochStore(str(path))
    store.close()
    assert not (tmp_path / "fresh.db.v1.bak").exists()


def test_chunked_activation_plan_and_state_identification():
    base = BytesBase([(0x1000, b"\0" * 8), (0x2000, b"\0" * 4)])
    epochs = [Epoch(1, [Range(0x1000, b"ABCD", is_code_hint=True),
                        Range(0x2000, b"DATA", is_code_hint=False)])]
    resolver = StateResolver(epochs, base)

    def reader(a, n):
        return resolver.state(0, a, n)

    plan = resolver.activation_plan(0, 1, reader, chunk_size=4)
    assert plan.requires_analysis
    assert {c.kind for c in plan.chunks} == {"code", "data"}
    assert plan.bytes_changed == 8
    assert resolver.identify_state(lambda a, n: resolver.state(1, a, n)) == 1
    mixed = {0x1000: b"ABCD", 0x2000: b"\0" * 4}
    assert resolver.identify_state(lambda a, n: mixed.get(a, b"\0" * n)) is None


def test_activation_plan_preserves_unknown_classification():
    resolver = StateResolver(
        [Epoch(1, [Range(0x1000, b"X", is_code_hint=None)])],
        BytesBase([(0x1000, b"\0")]),
    )
    plan = resolver.activation_plan(0, 1, lambda _a, _n: b"\0", chunk_size=1)
    assert plan.chunks[0].kind == "unknown"
    assert not plan.requires_analysis


def test_artifact_cache_and_activation_journal():
    store = EpochStore(":memory:")
    sid = store.import_source("x", "x", [Epoch(1, [Range(0x1000, b"A")])])
    t0, t1 = store.epoch_ref(0, sid), store.epoch_ref(1, sid)
    artifact = AnalysisArtifact(t1, "assembly", 0x1000, 0x1001, "v", ["nop"], [0x1000])
    store.put_artifact(artifact)
    assert store.get_artifact(t1, "assembly", 0x1000, 0x1001, "v").lines == ["nop"]
    jid = store.begin_activation(t0, t1, {"preimages": []})
    assert store.pending_activation()["id"] == jid
    store.update_activation(jid, "bytes_applied", marker=True)
    assert store.pending_activation()["payload"]["stage"] == "bytes_applied"
    assert store.pending_activation()["payload"]["marker"] is True
    store.finish_activation(jid, "committed")
    assert store.pending_activation() is None
    store.set_annot(t1, 0x1000, {"names": []})
    revision = store.annotation_revision(t1)
    store.set_annot(t1, 0x1000, {"names": []})
    assert store.annotation_revision(t1) == revision
    store.set_annot(t1, 0x2000, {"names": [{"name": "x"}]})
    assert store.annotation_revision(t1) > revision
    store.set_pin(t1, 0x100000000000, 0x100000000,
                  [{"canonical_start": 0x1000, "shadow_start": 0x100000001000}])
    assert store.get_pin(t1)["segments"][0]["canonical_start"] == 0x1000
    assert store.health()["integrity"] == "ok"
    store.remove_pin(t1)
    assert store.get_pin(t1) is None


def test_diff_normalization_removes_address_and_auto_label_noise():
    assert normalize_line("00001000  call sub_DEAD", "assembly") == "call <auto>"
    assert normalize_line("00001000  aa bb cc", "bytes") == "aa bb cc"
    assert unified_diff(["1000  nop"], ["2000  nop"], "a", "b",
                        normalized=True) == []


def test_elf_dump_uses_real_entry_not_changed_range_start():
    enc = bytearray(0x400)
    enc[:6] = b"\x7fELF\x02\x01"
    struct.pack_into("<Q", enc, 24, 0x1010)  # e_entry
    struct.pack_into("<Q", enc, 32, 0x40)    # e_phoff
    struct.pack_into("<H", enc, 54, 56)
    struct.pack_into("<H", enc, 56, 1)
    struct.pack_into("<IIQQ", enc, 0x40, 1, 5, 0x100, 0x1000)
    struct.pack_into("<Q", enc, 0x40 + 32, 0x100)
    dec = bytearray(enc)
    dec[0x108:0x120] = bytes(range(0x18))
    store = EpochStore(":memory:")
    epoch = import_elf_pair(store, bytes(enc), bytes(dec), gap=0)
    assert epoch.ranges[0].start == 0x1009
    assert epoch.ranges[0].entry_pcs == (0x1010,)
    store.close()
