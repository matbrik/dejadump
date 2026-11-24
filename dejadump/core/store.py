"""EpochStore — the SQLite sidecar (``<idb>.dejadump.db``).

Schema follows DESIGN §5.2.  ``blobs`` is content-addressed so identical stage
bytes written many times cost one row.  Bulk import runs in a single transaction
with WAL + ``synchronous=OFF`` and creates the secondary indexes *after* the load
(the fast path for multi-million-row Tenet imports).

Pure Python (``sqlite3`` stdlib only); the netnode index that ties a sidecar to
an IDB lives behind a shim in :mod:`dejadump.core.index` so this all tests
without IDA.
"""

from __future__ import annotations

import hashlib
import json
import os
import sqlite3
import time
from typing import Iterable, Optional

from .intervals import merge, subtract
from .model import AnalysisArtifact, Epoch, EpochRef, Range

SCHEMA_VERSION = 3

#: Writes up to this size use a bounded index range scan in overlap queries;
#: larger ones (dump-pair records) use their own partial index.
SMALL_WRITE = 64

_TABLES = """
CREATE TABLE IF NOT EXISTS meta    (key TEXT PRIMARY KEY, value TEXT);
CREATE TABLE IF NOT EXISTS sources (id INTEGER PRIMARY KEY, kind TEXT, label TEXT,
                                    created TEXT, params TEXT);
CREATE TABLE IF NOT EXISTS epochs  (id INTEGER PRIMARY KEY, source_id INT, seq INT,
                                    label TEXT, boundary_kind TEXT, boundary_pc INT,
                                    trace_index INT, created TEXT, note TEXT,
                                    repeat_count INT DEFAULT 0);
CREATE TABLE IF NOT EXISTS ranges  (id INTEGER PRIMARY KEY, epoch_id INT, start INT,
                                    size INT, sha256 BLOB, is_code_hint INT,
                                    entry_pcs TEXT, blob_id INT);
CREATE TABLE IF NOT EXISTS blobs   (id INTEGER PRIMARY KEY, sha256 BLOB UNIQUE, data BLOB);
CREATE TABLE IF NOT EXISTS writes  (id INTEGER PRIMARY KEY, epoch_id INT, seq INT,
                                    writer_pc INT, addr INT, size INT,
                                    new_bytes BLOB, old_bytes BLOB);
CREATE TABLE IF NOT EXISTS annots  (epoch_id INT, range_start INT, payload TEXT,
                                    PRIMARY KEY(epoch_id, range_start));
CREATE TABLE IF NOT EXISTS shared_annots (
    source_id INT, range_start INT, payload TEXT, revision INT DEFAULT 1,
    PRIMARY KEY(source_id,range_start));
CREATE TABLE IF NOT EXISTS pins    (epoch_id INT PRIMARY KEY, shadow_base INT,
                                    stride INT, segments TEXT);
CREATE TABLE IF NOT EXISTS base    (start INT PRIMARY KEY, size INT, blob_id INT);
CREATE TABLE IF NOT EXISTS analysis_artifacts (
    id INTEGER PRIMARY KEY, epoch_id INT, kind TEXT, start INT, end INT,
    version_key TEXT, payload TEXT, duration_ms REAL DEFAULT 0,
    UNIQUE(epoch_id,kind,start,end,version_key));
CREATE TABLE IF NOT EXISTS activation_journal (
    id INTEGER PRIMARY KEY, source_epoch_id INT, target_epoch_id INT,
    source_seq INT, target_seq INT, status TEXT, payload TEXT, created REAL);
CREATE TABLE IF NOT EXISTS owned_xrefs (
    id INTEGER PRIMARY KEY, epoch_id INT, src INT, dst INT, kind INT,
    UNIQUE(epoch_id,src,dst,kind));
CREATE TABLE IF NOT EXISTS observed (source_id INT, start INT, size INT, blob_id INT,
                                     PRIMARY KEY(source_id,start));
"""

_INDEXES = """
CREATE INDEX IF NOT EXISTS writes_addr  ON writes(addr);
CREATE INDEX IF NOT EXISTS writes_epoch ON writes(epoch_id);
CREATE INDEX IF NOT EXISTS ranges_epoch ON ranges(epoch_id);
CREATE UNIQUE INDEX IF NOT EXISTS epochs_source_seq ON epochs(source_id,seq);
CREATE INDEX IF NOT EXISTS artifacts_epoch ON analysis_artifacts(epoch_id,kind,start);
CREATE INDEX IF NOT EXISTS writes_large ON writes(addr) WHERE size > 64;
CREATE INDEX IF NOT EXISTS writes_writer ON writes(writer_pc, epoch_id);
"""


class EpochStore:
    """Read/write access to the epoch sidecar database."""

    def __init__(self, path: str = ":memory:", fast_import: bool = False):
        self.path = path
        fresh = path == ":memory:" or not os.path.exists(path) or os.path.getsize(path) == 0
        self.conn = sqlite3.connect(path)
        self.conn.execute("PRAGMA foreign_keys=ON")
        self.fast_import = bool(fast_import and path != ":memory:")
        if path != ":memory:":
            self.conn.execute("PRAGMA journal_mode=WAL")
        if self.fast_import:
            self.conn.execute("PRAGMA synchronous=OFF")
        elif path != ":memory:":
            self.conn.execute("PRAGMA synchronous=NORMAL")
        self.conn.executescript(_TABLES)
        #: Bumped whenever epochs/ranges change; keys every derived cache.
        self.generation = 0
        self._hash_cache: dict[tuple[int, Optional[int]], str] = {}
        self._migrate(fresh=fresh)

    def _migrate(self, fresh: bool = False) -> None:
        """Perform small, transactional, forward-only sidecar migrations."""
        raw = self.get_meta("schema_version")
        version = SCHEMA_VERSION if fresh and raw is None else int(raw or 1)
        if version > SCHEMA_VERSION:
            raise RuntimeError("sidecar schema %d is newer than supported %d" %
                               (version, SCHEMA_VERSION))
        if version < 2:
            if self.path != ":memory:":
                backup_path = self.path + ".v1.bak"
                if not os.path.exists(backup_path):
                    backup = sqlite3.connect(backup_path)
                    try:
                        self.conn.backup(backup)
                    finally:
                        backup.close()
            with self.conn:
                cols = {r[1] for r in self.conn.execute("PRAGMA table_info(annots)")}
                if "revision" not in cols:
                    self.conn.execute("ALTER TABLE annots ADD COLUMN revision INT DEFAULT 0")
                # v1 stored epoch sequence numbers in annots. Resolve them to the
                # newest matching epoch id; t0 remains represented by id 0.
                rows = self.conn.execute(
                    "SELECT epoch_id,range_start,payload,revision FROM annots"
                ).fetchall()
                self.conn.execute("DELETE FROM annots")
                for seq, start, payload, revision in rows:
                    hit = self.conn.execute(
                        "SELECT id FROM epochs WHERE seq=? ORDER BY source_id DESC LIMIT 1", (seq,)
                    ).fetchone()
                    eid = hit[0] if hit else seq
                    self.conn.execute(
                        "INSERT OR REPLACE INTO annots(epoch_id,range_start,payload,revision)"
                        " VALUES(?,?,?,?)", (eid, start, payload, revision)
                    )
                self.set_meta("schema_version", "2")
            version = 2
        # Fresh databases still need the ALTERed columns because CREATE TABLE
        # intentionally remains compatible with old SQLite files.
        cols = {r[1] for r in self.conn.execute("PRAGMA table_info(annots)")}
        if "revision" not in cols:
            self.conn.execute("ALTER TABLE annots ADD COLUMN revision INT DEFAULT 0")
        cols = {r[1] for r in self.conn.execute("PRAGMA table_info(sources)")}
        if "signature" not in cols:
            # v3: per-source content signature for duplicate-import detection.
            self.conn.execute("ALTER TABLE sources ADD COLUMN signature TEXT")
        for (source_id,) in self.conn.execute(
                "SELECT id FROM sources WHERE signature IS NULL").fetchall():
            self.conn.execute("UPDATE sources SET signature=? WHERE id=?",
                              (self._compute_hash(source_id), source_id))
        self.set_meta("schema_version", str(SCHEMA_VERSION))
        self.conn.executescript(_INDEXES)
        self.conn.commit()

    # -- meta ---------------------------------------------------------------
    def set_meta(self, key: str, value: str) -> None:
        self.conn.execute(
            "INSERT INTO meta(key,value) VALUES(?,?) "
            "ON CONFLICT(key) DO UPDATE SET value=excluded.value",
            (key, value),
        )

    def get_meta(self, key: str, default: Optional[str] = None) -> Optional[str]:
        row = self.conn.execute("SELECT value FROM meta WHERE key=?", (key,)).fetchone()
        return row[0] if row else default

    # -- indexes ------------------------------------------------------------
    def finalize_indexes(self) -> None:
        """Create secondary indexes; call once after a bulk import."""
        self.conn.executescript(_INDEXES)
        self.conn.commit()
        if self.path != ":memory:":
            self.conn.execute("PRAGMA synchronous=NORMAL")
            self.conn.execute("PRAGMA wal_checkpoint(PASSIVE)")
        self.fast_import = False

    # -- blobs (content-addressed) ------------------------------------------
    def blob_id(self, data: bytes) -> tuple[int, bytes]:
        h = hashlib.sha256(data).digest()
        row = self.conn.execute("SELECT id FROM blobs WHERE sha256=?", (h,)).fetchone()
        if row:
            return row[0], h
        cur = self.conn.execute("INSERT INTO blobs(sha256,data) VALUES(?,?)", (h, data))
        return int(cur.lastrowid), h

    def blob(self, sha256: bytes) -> Optional[bytes]:
        row = self.conn.execute("SELECT data FROM blobs WHERE sha256=?", (sha256,)).fetchone()
        return bytes(row[0]) if row else None

    # -- import -------------------------------------------------------------
    def import_source(
        self,
        kind: str,
        label: str,
        epochs: Iterable[Epoch],
        params: Optional[dict] = None,
        created: str = "",
    ) -> int:
        """Persist a capture source and all its epochs in one transaction."""
        epochs = list(epochs)
        created = created or time.strftime("%Y-%m-%dT%H:%M:%S")
        with self.conn:  # single transaction
            cur = self.conn.execute(
                "INSERT INTO sources(kind,label,created,params) VALUES(?,?,?,?)",
                (kind, label, created, json.dumps(params or {})),
            )
            source_id = int(cur.lastrowid)
            self.set_meta("active_source_id", str(source_id))
            self.set_meta("active_epoch", "0")
            self.set_meta("active_epoch_id", "")
            write_rows: list[tuple] = []
            for ep in epochs:
                cur = self.conn.execute(
                    "INSERT INTO epochs(source_id,seq,label,boundary_kind,boundary_pc,"
                    "trace_index,created,note,repeat_count) VALUES(?,?,?,?,?,?,?,?,?)",
                    (source_id, ep.seq, ep.label, ep.boundary_kind, ep.boundary_pc,
                     ep.trace_index, created, ep.note, ep.repeat_count),
                )
                epoch_id = int(cur.lastrowid)
                for r in ep.ranges:
                    bid, h = self.blob_id(r.data)
                    self.conn.execute(
                        "INSERT INTO ranges(epoch_id,start,size,sha256,is_code_hint,"
                        "entry_pcs,blob_id) VALUES(?,?,?,?,?,?,?)",
                        (epoch_id, r.start, r.size, h,
                         -1 if r.is_code_hint is None else int(r.is_code_hint),
                         json.dumps(list(r.entry_pcs)), bid),
                    )
                for w in ep.writes:
                    write_rows.append(
                        (epoch_id, w.seq, w.writer_pc, w.addr, w.size, w.data, w.old_bytes)
                    )
            if write_rows:
                self.conn.executemany(
                    "INSERT INTO writes(epoch_id,seq,writer_pc,addr,size,new_bytes,old_bytes)"
                    " VALUES(?,?,?,?,?,?,?)",
                    write_rows,
                )
            self.conn.execute("UPDATE sources SET signature=? WHERE id=?",
                              (self._compute_hash(source_id), source_id))
        self._changed()
        self.finalize_indexes()
        return source_id

    def append_epoch(self, epoch: Epoch, source_id: Optional[int] = None,
                     created: str = "") -> int:
        """Append one manually captured epoch to an existing source.

        Unlike :meth:`import_source`, this preserves the active source and its
        t0 base.  The sequence must be the next one so read-through state remains
        deterministic.
        """
        source_id = self.active_source_id() if source_id is None else int(source_id)
        if source_id is None:
            raise RuntimeError("cannot append an epoch without an active source")
        row = self.conn.execute(
            "SELECT COALESCE(MAX(seq),0) FROM epochs WHERE source_id=?", (source_id,)
        ).fetchone()
        expected = int(row[0]) + 1
        if int(epoch.seq) != expected:
            raise ValueError("appended epoch must be t%d, got t%d" % (expected, epoch.seq))
        with self.conn:
            cur = self.conn.execute(
                "INSERT INTO epochs(source_id,seq,label,boundary_kind,boundary_pc,"
                "trace_index,created,note,repeat_count) VALUES(?,?,?,?,?,?,?,?,?)",
                (source_id, epoch.seq, epoch.label, epoch.boundary_kind,
                 epoch.boundary_pc, epoch.trace_index, created, epoch.note,
                 epoch.repeat_count),
            )
            epoch_id = int(cur.lastrowid)
            for captured in epoch.ranges:
                blob_id, digest = self.blob_id(captured.data)
                self.conn.execute(
                    "INSERT INTO ranges(epoch_id,start,size,sha256,is_code_hint,"
                    "entry_pcs,blob_id) VALUES(?,?,?,?,?,?,?)",
                    (epoch_id, captured.start, captured.size, digest,
                     -1 if captured.is_code_hint is None else int(captured.is_code_hint),
                     json.dumps(list(captured.entry_pcs)), blob_id),
                )
            self.set_meta("active_epoch", str(epoch.seq))
            self.set_meta("active_epoch_id", str(epoch_id))
            self.conn.execute("UPDATE sources SET signature=? WHERE id=?",
                              (self._compute_hash(source_id), source_id))
        self._changed()
        return epoch_id

    # -- queries ------------------------------------------------------------
    def sources(self) -> list[dict]:
        rows = self.conn.execute(
            "SELECT s.id,s.kind,s.label,s.created,s.params,s.signature,"
            "(SELECT COUNT(*) FROM epochs e WHERE e.source_id=s.id) "
            "FROM sources s ORDER BY s.id"
        ).fetchall()
        keys = ("id", "kind", "label", "created", "params", "signature", "epochs")
        return [dict(zip(keys, r)) for r in rows]

    def duplicate_of(self, source_id: int) -> Optional[int]:
        """An older source with byte-identical epochs, if one exists."""
        row = self.conn.execute(
            "SELECT b.id FROM sources a JOIN sources b ON a.signature=b.signature "
            "WHERE a.id=? AND b.id<>a.id AND a.signature IS NOT NULL ORDER BY b.id LIMIT 1",
            (source_id,),
        ).fetchone()
        return int(row[0]) if row else None

    def rename_source(self, source_id: int, label: str) -> None:
        self.conn.execute("UPDATE sources SET label=? WHERE id=?", (label, source_id))
        self.conn.commit()

    def delete_source(self, source_id: int) -> None:
        """Remove a source and everything derived from it (blobs are GC'd later)."""
        ids = [r[0] for r in self.conn.execute(
            "SELECT id FROM epochs WHERE source_id=?", (source_id,)).fetchall()]
        storage_ids = ids + [-int(source_id)]
        with self.conn:
            marks = ",".join("?" * len(storage_ids))
            self.conn.execute("DELETE FROM ranges WHERE epoch_id IN (%s)" % marks, storage_ids)
            self.conn.execute("DELETE FROM writes WHERE epoch_id IN (%s)" % marks, storage_ids)
            self.conn.execute("DELETE FROM annots WHERE epoch_id IN (%s)" % marks, storage_ids)
            self.conn.execute("DELETE FROM analysis_artifacts WHERE epoch_id IN (%s)" % marks,
                              storage_ids)
            self.conn.execute("DELETE FROM owned_xrefs WHERE epoch_id IN (%s)" % marks,
                              storage_ids)
            self.conn.execute("DELETE FROM pins WHERE epoch_id IN (%s)" % marks, storage_ids)
            self.conn.execute("DELETE FROM epochs WHERE source_id=?", (source_id,))
            self.conn.execute("DELETE FROM shared_annots WHERE source_id=?", (source_id,))
            self.conn.execute("DELETE FROM observed WHERE source_id=?", (source_id,))
            self.conn.execute("DELETE FROM sources WHERE id=?", (source_id,))
            self.conn.execute("DELETE FROM meta WHERE key=?", ("favorites:%s" % source_id,))
            if self.get_meta("active_source_id") == str(source_id):
                row = self.conn.execute(
                    "SELECT id FROM sources ORDER BY id DESC LIMIT 1").fetchone()
                self.set_meta("active_source_id", str(row[0]) if row else "")
                self.set_meta("active_epoch", "0")
                self.set_meta("active_epoch_id", "")
        self._changed()

    def active_source_id(self) -> Optional[int]:
        raw = self.get_meta("active_source_id")
        if raw not in (None, ""):
            return int(raw)
        row = self.conn.execute("SELECT id FROM sources ORDER BY id DESC LIMIT 1").fetchone()
        return int(row[0]) if row else None

    def epochs(self, source_id: Optional[int] = None) -> list[dict]:
        source_id = self.active_source_id() if source_id is None else source_id
        where, args = (" WHERE source_id=?", (source_id,)) if source_id is not None else ("", ())
        rows = self.conn.execute(
            "SELECT id,source_id,seq,label,boundary_kind,boundary_pc,trace_index,note,repeat_count"
            " FROM epochs" + where + " ORDER BY seq", args
        ).fetchall()
        keys = ("id", "source_id", "seq", "label", "boundary_kind", "boundary_pc", "trace_index",
                "note", "repeat_count")
        return [dict(zip(keys, r)) for r in rows]

    def epoch_ref(self, seq: int, source_id: Optional[int] = None) -> EpochRef:
        source_id = self.active_source_id() if source_id is None else source_id
        if seq == 0:
            return EpochRef(source_id, None, 0)
        row = self.conn.execute(
            "SELECT id FROM epochs WHERE source_id=? AND seq=?", (source_id, seq)
        ).fetchone()
        if not row:
            raise KeyError("unknown epoch t%d for source %r" % (seq, source_id))
        return EpochRef(source_id, int(row[0]), seq)

    def set_active_source(self, source_id: int) -> None:
        if not self.conn.execute("SELECT 1 FROM sources WHERE id=?", (source_id,)).fetchone():
            raise KeyError("unknown source %d" % source_id)
        self.set_meta("active_source_id", str(source_id))
        self.set_meta("active_epoch", "0")
        self.set_meta("active_epoch_id", "")
        self.conn.commit()

    def update_epoch_text(self, epoch_id: int, label: str, note: str) -> None:
        self.conn.execute("UPDATE epochs SET label=?,note=? WHERE id=?", (label, note, epoch_id))
        self.conn.commit()

    def favorites(self, source_id: Optional[int] = None) -> set[int]:
        source_id = self.active_source_id() if source_id is None else source_id
        raw = self.get_meta("favorites:%s" % source_id, "[]") or "[]"
        try:
            return {int(value) for value in json.loads(raw)}
        except Exception:
            return set()

    def set_favorite(self, seq: int, enabled: bool,
                     source_id: Optional[int] = None) -> None:
        source_id = self.active_source_id() if source_id is None else source_id
        values = self.favorites(source_id)
        (values.add if enabled else values.discard)(int(seq))
        self.set_meta("favorites:%s" % source_id, json.dumps(sorted(values)))
        self.conn.commit()

    def artifact_stats(self, epoch: EpochRef) -> dict:
        row = self.conn.execute(
            "SELECT COUNT(*),COALESCE(SUM(duration_ms),0) FROM analysis_artifacts "
            "WHERE epoch_id=?", (self._storage_epoch_id(epoch),)
        ).fetchone()
        return {"count": int(row[0]), "duration_ms": float(row[1])}

    def latest_artifact(self, epoch: EpochRef) -> Optional[AnalysisArtifact]:
        row = self.conn.execute(
            "SELECT kind,start,end,version_key,payload,duration_ms FROM analysis_artifacts "
            "WHERE epoch_id=? ORDER BY id DESC LIMIT 1",
            (self._storage_epoch_id(epoch),),
        ).fetchone()
        if not row:
            return None
        kind, start, end, version, raw, duration = row
        payload = json.loads(raw)
        return AnalysisArtifact(epoch, kind, start, end, version,
                                payload.get("lines", []), payload.get("addresses", []),
                                payload.get("diagnostics", {}), float(duration or 0))

    def load_epochs(self, source_id: Optional[int] = None) -> list[Epoch]:
        """Epochs with their ranges (no writes) — ready for StateResolver."""
        out: list[Epoch] = []
        for e in self.epochs(source_id):
            out.append(
                Epoch(
                    seq=e["seq"],
                    ranges=self.ranges(e["id"]),
                    boundary_kind=e["boundary_kind"],
                    boundary_pc=e["boundary_pc"],
                    label=e["label"],
                )
            )
        return out

    def ranges(self, epoch_id: int) -> list[Range]:
        rows = self.conn.execute(
            "SELECT r.start,r.sha256,r.is_code_hint,r.entry_pcs,b.data FROM ranges r "
            "JOIN blobs b ON b.id=r.blob_id WHERE r.epoch_id=? ORDER BY r.start",
            (epoch_id,),
        ).fetchall()
        out: list[Range] = []
        for start, sha, is_code, entry_pcs, data in rows:
            out.append(
                Range(
                    start=start,
                    data=bytes(data),
                    entry_pcs=tuple(json.loads(entry_pcs)),
                    is_code_hint=None if int(is_code) < 0 else bool(is_code),
                )
            )
        return out

    _WRITE_KEYS = ("epoch_seq", "seq", "writer_pc", "addr", "size", "new_bytes", "old_bytes")

    def _writes_overlapping(self, start: int, end: int) -> list[dict]:
        """Writes of the active source overlapping ``[start, end)``.

        Small writes are found with a bounded scan of the address index
        (``addr`` within ``SMALL_WRITE`` bytes below ``start``); the few large
        records (dump pairs) come from their own partial index.  Both halves are
        exact, so the union equals the naive ``addr < end AND start < addr+size``.
        """
        source_id = self.active_source_id()
        columns = ("SELECT e.seq,w.seq,w.writer_pc,w.addr,w.size,w.new_bytes,w.old_bytes "
                   "FROM writes w JOIN epochs e ON e.id=w.epoch_id WHERE e.source_id=? AND ")
        rows = self.conn.execute(
            columns + "w.addr BETWEEN ? AND ? AND w.size <= ? AND ? < w.addr + w.size "
            "UNION ALL " +
            columns + "w.size > ? AND w.addr < ? AND ? < w.addr + w.size "
            "ORDER BY 1, 2",
            (source_id, start - SMALL_WRITE + 1, end - 1, SMALL_WRITE, start,
             source_id, SMALL_WRITE, end, start),
        ).fetchall()
        return [dict(zip(self._WRITE_KEYS, row)) for row in rows]

    def writes_for_addr(self, addr: int) -> list[dict]:
        return self._writes_overlapping(addr, addr + 1)

    def writes_for_range(self, start: int, end: int) -> list[dict]:
        """Fetch provenance overlapping ``[start,end)`` in one indexed query."""
        return self._writes_overlapping(start, end)

    def iter_writes(self):
        """Yield every write as a dict, ordered by epoch then sequence."""
        rows = self.conn.execute(
            "SELECT e.seq, w.writer_pc, w.addr, w.size, w.new_bytes FROM writes w "
            "JOIN epochs e ON e.id=w.epoch_id WHERE e.source_id=? ORDER BY e.seq, w.seq",
            (self.active_source_id(),),
        )
        for seq, pc, addr, size, nb in rows:
            yield {"epoch_seq": seq, "writer_pc": pc, "addr": addr, "size": size,
                   "new_bytes": bytes(nb) if nb is not None else None}

    def writers_of(self, addr: int) -> list[dict]:
        """Distinct (epoch, writer_pc) that wrote the byte at ``addr`` — the
        'xref this location across epochs' query."""
        rows = [(r["epoch_seq"], r["writer_pc"], r["addr"], r["size"], r["new_bytes"])
                for r in self._writes_overlapping(addr, addr + 1)]
        out, seen = [], set()
        for seq, pc, waddr, size, nb in rows:
            key = (seq, pc)
            if key in seen:
                continue
            seen.add(key)
            out.append({"epoch_seq": seq, "writer_pc": pc, "addr": waddr, "size": size,
                        "new_bytes": bytes(nb) if nb is not None else None})
        return out

    def volatile_set(self, source_id: Optional[int] = None) -> list[tuple[int, int]]:
        """Union of all range extents across all epochs, coalesced."""
        source_id = self.active_source_id() if source_id is None else source_id
        rows = self.conn.execute(
            "SELECT r.start,r.size FROM ranges r JOIN epochs e ON e.id=r.epoch_id "
            "WHERE e.source_id=? ORDER BY r.start", (source_id,)
        ).fetchall() if source_id is not None else []
        merged: list[list[int]] = []
        for start, size in rows:
            end = start + size
            if merged and start <= merged[-1][1]:
                merged[-1][1] = max(merged[-1][1], end)
            else:
                merged.append([start, end])
        return [(s, e) for s, e in merged]

    def _changed(self) -> None:
        self.generation += 1
        self._hash_cache.clear()

    def _compute_hash(self, source_id: Optional[int]) -> str:
        h = hashlib.sha256()
        where, args = ("WHERE e.source_id=?", (source_id,)) if source_id is not None else ("", ())
        rows = self.conn.execute(
            "SELECT e.seq, r.start, r.sha256 FROM epochs e "
            "LEFT JOIN ranges r ON r.epoch_id=e.id " + where +
            " ORDER BY e.seq, r.start", args,
        ).fetchall()
        last_seq = None
        for seq, start, sha in rows:
            if seq != last_seq:
                h.update(str(seq).encode())
                last_seq = seq
            if start is not None:
                h.update(int(start).to_bytes(8, "little"))
                h.update(bytes(sha))
        return h.hexdigest()

    def content_hash(self, source_id: Optional[int] = None) -> str:
        """A stable digest of the stored epochs, to detect a mismatched sidecar.

        Computed from the stored range digests (no blob reads) and cached until
        the next import/append/delete.
        """
        source_id = self.active_source_id() if source_id is None else source_id
        key = (self.generation, source_id)
        cached = self._hash_cache.get(key)
        if cached is None:
            cached = self._compute_hash(source_id)
            self._hash_cache[key] = cached
        return cached

    def epoch_summaries(self, source_id: Optional[int] = None) -> dict[int, dict]:
        """Per-epoch range statistics without loading range bytes."""
        source_id = self.active_source_id() if source_id is None else source_id
        rows = self.conn.execute(
            "SELECT r.epoch_id, COUNT(*), COALESCE(SUM(r.size),0), "
            "COALESCE(SUM(CASE WHEN r.is_code_hint=1 THEN r.size ELSE 0 END),0), "
            "GROUP_CONCAT(r.entry_pcs, '|') "
            "FROM ranges r JOIN epochs e ON e.id=r.epoch_id WHERE e.source_id=? "
            "GROUP BY r.epoch_id", (source_id,),
        ).fetchall()
        out = {}
        for epoch_id, count, size, code, entries in rows:
            pcs = set()
            for chunk in (entries or "").split("|"):
                if chunk:
                    pcs.update(json.loads(chunk))
            out[int(epoch_id)] = {"ranges": int(count), "bytes": int(size),
                                  "code_bytes": int(code), "functions": len(pcs)}
        return out

    def epochs_touching(self, start: int, end: int,
                        source_id: Optional[int] = None) -> list[int]:
        """Sequence numbers of the epochs that captured bytes inside ``[start, end)``."""
        source_id = self.active_source_id() if source_id is None else source_id
        rows = self.conn.execute(
            "SELECT DISTINCT e.seq FROM ranges r JOIN epochs e ON e.id=r.epoch_id "
            "WHERE e.source_id=? AND r.start < ? AND r.start + r.size > ? ORDER BY e.seq",
            (source_id, end, start),
        ).fetchall()
        return [int(r[0]) for r in rows]

    def epoch_ranges(self, seq: int, source_id: Optional[int] = None) -> list[tuple[int, int]]:
        """``(start, end)`` extents captured by one epoch (no bytes)."""
        ref = self.epoch_ref(seq, source_id)
        if ref.epoch_id is None:
            return []
        rows = self.conn.execute(
            "SELECT start, size FROM ranges WHERE epoch_id=? ORDER BY start", (ref.epoch_id,)
        ).fetchall()
        return [(int(s), int(s) + int(n)) for s, n in rows]

    # -- base (t0) snapshot of the volatile set -----------------------------
    def set_base_range(self, start: int, data: bytes) -> None:
        """Persist the original (epoch 0) bytes of a volatile range."""
        bid, _ = self.blob_id(data)
        self.conn.execute(
            "INSERT INTO base(start,size,blob_id) VALUES(?,?,?) "
            "ON CONFLICT(start) DO UPDATE SET size=excluded.size, blob_id=excluded.blob_id",
            (start, len(data), bid),
        )
        self.conn.commit()

    def has_base(self) -> bool:
        return self.conn.execute("SELECT 1 FROM base LIMIT 1").fetchone() is not None

    def base_coverage(self) -> list[tuple[int, int]]:
        """Coalesced extents that have a t0 snapshot."""
        rows = self.conn.execute("SELECT start, size FROM base").fetchall()
        return merge((int(s), int(s) + int(n)) for s, n in rows)

    def base_gaps(self, source_id: Optional[int] = None) -> list[tuple[int, int]]:
        """Volatile extents of a source that have no t0 snapshot yet."""
        return subtract(self.volatile_set(source_id), self.base_coverage())

    def base_source(self) -> "BaseSource":
        rows = self.conn.execute(
            "SELECT b.start, d.data FROM base b JOIN blobs d ON d.id=b.blob_id ORDER BY b.start"
        ).fetchall()
        return BaseSource([(start, bytes(data)) for start, data in rows])

    # -- observed reads (data seen at runtime but never written) -------------
    def set_observed(self, source_id: int, ranges: Iterable[Range]) -> None:
        with self.conn:
            self.conn.execute("DELETE FROM observed WHERE source_id=?", (source_id,))
            for r in ranges:
                bid, _ = self.blob_id(r.data)
                self.conn.execute(
                    "INSERT OR REPLACE INTO observed(source_id,start,size,blob_id) "
                    "VALUES(?,?,?,?)", (source_id, r.start, r.size, bid))

    def observed(self, source_id: Optional[int] = None) -> list[tuple[int, bytes]]:
        source_id = self.active_source_id() if source_id is None else source_id
        rows = self.conn.execute(
            "SELECT o.start, b.data FROM observed o JOIN blobs b ON b.id=o.blob_id "
            "WHERE o.source_id=? ORDER BY o.start", (source_id,),
        ).fetchall()
        return [(int(start), bytes(data)) for start, data in rows]

    def set_base_code_ranges(self, ranges: list[tuple[int, int, tuple[int, ...]]]) -> None:
        self.set_meta("base_code_ranges", json.dumps(
            [[s, e, list(entries)] for s, e, entries in ranges]))
        self.conn.commit()

    def base_code_ranges(self) -> list[tuple[int, int, tuple[int, ...]]]:
        raw = json.loads(self.get_meta("base_code_ranges", "[]") or "[]")
        return [(int(s), int(e), tuple(entries)) for s, e, entries in raw]

    # -- annotations (per epoch, per range) ---------------------------------
    @staticmethod
    def _storage_epoch_id(epoch: EpochRef) -> int:
        """Return a collision-free SQLite key, including each source's t0.

        Observed epochs have positive database IDs.  The implicit t0 has no row
        in ``epochs``, so it uses the negative source ID instead of the legacy
        global key 0.  This keeps t0 annotations/artifacts source-local without
        a disruptive schema rewrite.
        """
        if epoch.epoch_id is not None:
            return int(epoch.epoch_id)
        return -int(epoch.source_id) if epoch.source_id is not None else 0

    def _annotation_epoch_id(self, epoch: int | EpochRef) -> int:
        if isinstance(epoch, EpochRef):
            return self._storage_epoch_id(epoch)
        try:
            return self._storage_epoch_id(self.epoch_ref(int(epoch)))
        except (KeyError, TypeError):
            return int(epoch)  # compatibility for t0 and headless callers

    def set_annot(self, epoch_seq: int | EpochRef, range_start: int, payload: dict) -> None:
        epoch_id = self._annotation_epoch_id(epoch_seq)
        encoded = json.dumps(payload, sort_keys=True, separators=(",", ":"))
        existing = self.conn.execute(
            "SELECT payload FROM annots WHERE epoch_id=? AND range_start=?",
            (epoch_id, range_start),
        ).fetchone()
        if existing:
            try:
                old = json.dumps(json.loads(existing[0]), sort_keys=True, separators=(",", ":"))
                if old == encoded:
                    return
            except Exception:
                pass
        self.conn.execute(
            "INSERT INTO annots(epoch_id,range_start,payload,revision) VALUES(?,?,?,1) "
            "ON CONFLICT(epoch_id,range_start) DO UPDATE SET payload=excluded.payload,"
            " revision=annots.revision+1",
            (epoch_id, range_start, encoded),
        )
        self.conn.commit()

    def get_annot(self, epoch_seq: int | EpochRef, range_start: int) -> Optional[dict]:
        epoch_id = self._annotation_epoch_id(epoch_seq)
        row = self.conn.execute(
            "SELECT payload FROM annots WHERE epoch_id=? AND range_start=?",
            (epoch_id, range_start),
        ).fetchone()
        return json.loads(row[0]) if row else None

    def annots_for_epoch(self, epoch_seq: int | EpochRef) -> dict:
        epoch_id = self._annotation_epoch_id(epoch_seq)
        rows = self.conn.execute(
            "SELECT range_start,payload FROM annots WHERE epoch_id=?", (epoch_id,)
        ).fetchall()
        return {start: json.loads(p) for start, p in rows}

    def set_shared_annot(self, range_start: int, payload: dict,
                         source_id: Optional[int] = None) -> None:
        source_id = self.active_source_id() if source_id is None else source_id
        if source_id is None:
            raise ValueError("shared annotations require a capture source")
        encoded = json.dumps(payload, sort_keys=True, separators=(",", ":"))
        row = self.conn.execute(
            "SELECT payload FROM shared_annots WHERE source_id=? AND range_start=?",
            (source_id, range_start),
        ).fetchone()
        if row and row[0] == encoded:
            return
        self.conn.execute(
            "INSERT INTO shared_annots(source_id,range_start,payload,revision) VALUES(?,?,?,1) "
            "ON CONFLICT(source_id,range_start) DO UPDATE SET payload=excluded.payload,"
            "revision=shared_annots.revision+1",
            (source_id, range_start, encoded),
        )
        self.conn.commit()

    def shared_annots(self, source_id: Optional[int] = None) -> dict:
        source_id = self.active_source_id() if source_id is None else source_id
        rows = self.conn.execute(
            "SELECT range_start,payload FROM shared_annots WHERE source_id=?",
            (source_id,),
        ).fetchall() if source_id is not None else []
        return {start: json.loads(payload) for start, payload in rows}

    def annotation_revision(self, epoch: int | EpochRef) -> int:
        eid = self._annotation_epoch_id(epoch)
        row = self.conn.execute(
            # SUM is monotonic across independently edited ranges; MAX would miss
            # an edit when another range already had the same revision number.
            "SELECT COALESCE(SUM(revision),0) FROM annots WHERE epoch_id=?", (eid,)
        ).fetchone()
        source_id = epoch.source_id if isinstance(epoch, EpochRef) else self.active_source_id()
        shared = self.conn.execute(
            "SELECT COALESCE(SUM(revision),0) FROM shared_annots WHERE source_id=?",
            (source_id,),
        ).fetchone()
        return int(row[0]) + int(shared[0])

    # -- active epoch -------------------------------------------------------
    def active_epoch(self) -> int:
        return int(self.get_meta("active_epoch", "0"))

    def set_active_epoch(self, seq: int) -> None:
        try:
            ref = self.epoch_ref(seq)
        except KeyError:
            # Retained for small headless stores that exercise metadata without
            # importing epochs first.
            ref = EpochRef(self.active_source_id(), None, seq)
        self.set_meta("active_epoch", str(seq))
        if ref.source_id is not None:
            self.set_meta("active_source_id", str(ref.source_id))
        self.set_meta("active_epoch_id", str(ref.epoch_id) if ref.epoch_id is not None else "")
        self.conn.commit()

    # -- activation journal ------------------------------------------------
    def begin_activation(self, source: EpochRef, target: EpochRef, payload: dict) -> int:
        cur = self.conn.execute(
            "INSERT INTO activation_journal(source_epoch_id,target_epoch_id,source_seq,"
            "target_seq,status,payload,created) VALUES(?,?,?,?,?,?,?)",
            (source.epoch_id, target.epoch_id, source.seq, target.seq, "pending",
             json.dumps(payload), time.time()),
        )
        self.conn.commit()
        return int(cur.lastrowid)

    JOURNAL_KEEP = 200

    def finish_activation(self, journal_id: int, status: str) -> None:
        self.conn.execute("UPDATE activation_journal SET status=? WHERE id=?", (status, journal_id))
        self.conn.execute(
            "DELETE FROM activation_journal WHERE status<>'pending' AND id <= ?",
            (journal_id - self.JOURNAL_KEEP,),
        )
        self.conn.commit()

    def update_activation(self, journal_id: int, stage: str, **fields) -> None:
        row = self.conn.execute(
            "SELECT payload FROM activation_journal WHERE id=?", (journal_id,)
        ).fetchone()
        if not row:
            raise KeyError("unknown activation journal %d" % journal_id)
        payload = json.loads(row[0])
        payload.update(fields)
        payload["stage"] = stage
        self.conn.execute(
            "UPDATE activation_journal SET payload=? WHERE id=?",
            (json.dumps(payload), journal_id),
        )
        self.conn.commit()

    def pending_activation(self) -> Optional[dict]:
        row = self.conn.execute(
            "SELECT id,source_seq,target_seq,payload FROM activation_journal "
            "WHERE status='pending' ORDER BY id DESC LIMIT 1"
        ).fetchone()
        if not row:
            return None
        return {"id": row[0], "source_seq": row[1], "target_seq": row[2],
                "payload": json.loads(row[3])}

    # -- rendered analysis artifacts --------------------------------------
    def put_artifact(self, artifact: AnalysisArtifact) -> None:
        eid = self._storage_epoch_id(artifact.epoch)
        payload = json.dumps({"lines": artifact.lines, "addresses": artifact.addresses,
                              "diagnostics": artifact.diagnostics})
        # A new version key supersedes every older rendering of the same view.
        self.conn.execute(
            "DELETE FROM analysis_artifacts WHERE epoch_id=? AND kind=? AND start=? AND end=?"
            " AND version_key<>?",
            (eid, artifact.kind, artifact.start, artifact.end, artifact.version_key),
        )
        self.conn.execute(
            "INSERT INTO analysis_artifacts(epoch_id,kind,start,end,version_key,payload,duration_ms)"
            " VALUES(?,?,?,?,?,?,?) ON CONFLICT(epoch_id,kind,start,end,version_key)"
            " DO UPDATE SET payload=excluded.payload,duration_ms=excluded.duration_ms",
            (eid, artifact.kind, artifact.start, artifact.end, artifact.version_key,
             payload, artifact.duration_ms),
        )
        self.conn.commit()

    def get_artifact(self, epoch: EpochRef, kind: str, start: int, end: int,
                     version_key: str) -> Optional[AnalysisArtifact]:
        row = self.conn.execute(
            "SELECT payload,duration_ms FROM analysis_artifacts WHERE epoch_id=? AND kind=?"
            " AND start=? AND end=? AND version_key=?",
            (self._storage_epoch_id(epoch), kind, start, end, version_key),
        ).fetchone()
        if not row:
            return None
        payload = json.loads(row[0])
        return AnalysisArtifact(epoch, kind, start, end, version_key,
                                payload.get("lines", []), payload.get("addresses", []),
                                payload.get("diagnostics", {}), float(row[1] or 0))

    def clear_artifacts(self, epoch: Optional[EpochRef] = None) -> int:
        if epoch is None:
            cur = self.conn.execute("DELETE FROM analysis_artifacts")
        else:
            cur = self.conn.execute("DELETE FROM analysis_artifacts WHERE epoch_id=?",
                                    (self._storage_epoch_id(epoch),))
        self.conn.commit()
        return cur.rowcount

    # -- pinned shadow epochs ---------------------------------------------
    def set_pin(self, epoch: EpochRef, shadow_base: int, stride: int, segments: list[dict]) -> None:
        if epoch.epoch_id is None:
            raise ValueError("the implicit t0 epoch cannot be pinned")
        self.conn.execute(
            "INSERT INTO pins(epoch_id,shadow_base,stride,segments) VALUES(?,?,?,?) "
            "ON CONFLICT(epoch_id) DO UPDATE SET shadow_base=excluded.shadow_base,"
            "stride=excluded.stride,segments=excluded.segments",
            (epoch.epoch_id, shadow_base, stride, json.dumps(segments)),
        )
        self.conn.commit()

    def get_pin(self, epoch: EpochRef) -> Optional[dict]:
        if epoch.epoch_id is None:
            return None
        row = self.conn.execute(
            "SELECT shadow_base,stride,segments FROM pins WHERE epoch_id=?", (epoch.epoch_id,)
        ).fetchone()
        return ({"shadow_base": row[0], "stride": row[1], "segments": json.loads(row[2])}
                if row else None)

    def remove_pin(self, epoch: EpochRef) -> None:
        if epoch.epoch_id is not None:
            self.conn.execute("DELETE FROM pins WHERE epoch_id=?", (epoch.epoch_id,))
            self.conn.commit()

    # -- plugin-owned xrefs ------------------------------------------------
    def record_owned_xref(self, epoch_seq: int, src: int, dst: int, kind: int) -> None:
        ref = self.epoch_ref(epoch_seq)
        self.conn.execute(
            "INSERT OR IGNORE INTO owned_xrefs(epoch_id,src,dst,kind) VALUES(?,?,?,?)",
            (self._storage_epoch_id(ref), src, dst, kind),
        )
        self.conn.commit()

    def record_owned_xrefs(self, rows: Iterable[tuple[int, int, int, int]]) -> None:
        """Batch form of :meth:`record_owned_xref`: ``(epoch_seq, src, dst, kind)``."""
        refs: dict[int, int] = {}
        values = []
        for seq, src, dst, kind in rows:
            if seq not in refs:
                refs[seq] = self._storage_epoch_id(self.epoch_ref(seq))
            values.append((refs[seq], src, dst, kind))
        if values:
            with self.conn:
                self.conn.executemany(
                    "INSERT OR IGNORE INTO owned_xrefs(epoch_id,src,dst,kind) VALUES(?,?,?,?)",
                    values)

    def writer_summary(self, writer_pc: int, epoch_seq: int) -> dict:
        """Stores, bytes and extent written by one instruction in one epoch."""
        ref = self.epoch_ref(epoch_seq)
        row = self.conn.execute(
            "SELECT COUNT(*), COALESCE(SUM(size),0), MIN(addr), MAX(addr+size) FROM writes "
            "WHERE writer_pc=? AND epoch_id=?", (writer_pc, ref.epoch_id),
        ).fetchone()
        return {"stores": int(row[0]), "bytes": int(row[1]),
                "lo": row[2] if row[2] is not None else 0,
                "hi": row[3] if row[3] is not None else 0}

    def owned_xrefs(self) -> list[dict]:
        rows = self.conn.execute("SELECT id,epoch_id,src,dst,kind FROM owned_xrefs").fetchall()
        return [dict(zip(("id", "epoch_id", "src", "dst", "kind"), r)) for r in rows]

    def clear_owned_xrefs(self) -> None:
        self.conn.execute("DELETE FROM owned_xrefs")
        self.conn.commit()

    def collect_garbage(self) -> int:
        """Delete blobs no range, base snapshot, observed layer or pending
        activation preimage still references.  Returns the number removed."""
        keep = set()
        for row in self.conn.execute("SELECT payload FROM activation_journal "
                                     "WHERE status='pending'"):
            try:
                for item in json.loads(row[0]).get("preimages", []):
                    keep.add(bytes.fromhex(item["sha256"]))
            except Exception:
                continue
        orphans = self.conn.execute(
            "SELECT id, sha256 FROM blobs WHERE id NOT IN (SELECT blob_id FROM ranges) "
            "AND id NOT IN (SELECT blob_id FROM base) "
            "AND id NOT IN (SELECT blob_id FROM observed)"
        ).fetchall()
        doomed = [(bid,) for bid, sha in orphans if bytes(sha) not in keep]
        with self.conn:
            self.conn.executemany("DELETE FROM blobs WHERE id=?", doomed)
        return len(doomed)

    def compact(self) -> dict:
        """Garbage-collect blobs, then rebuild the file (VACUUM)."""
        before = os.path.getsize(self.path) if self.path != ":memory:" and \
            os.path.exists(self.path) else 0
        removed = self.collect_garbage()
        self.conn.execute("VACUUM")
        if self.path != ":memory:":
            self.conn.execute("PRAGMA wal_checkpoint(TRUNCATE)")
        after = os.path.getsize(self.path) if before else 0
        return {"blobs_removed": removed, "size_before": before, "size_after": after}

    def checkpoint(self) -> None:
        if self.path != ":memory:":
            self.conn.execute("PRAGMA wal_checkpoint(PASSIVE)")

    def health(self) -> dict:
        integrity = self.conn.execute("PRAGMA quick_check").fetchone()[0]
        size = os.path.getsize(self.path) if self.path != ":memory:" and os.path.exists(self.path) else 0
        wal = self.path + "-wal" if self.path != ":memory:" else ""
        return {
            "schema_version": int(self.get_meta("schema_version", "0")),
            "integrity": integrity,
            "sources": self.conn.execute("SELECT COUNT(*) FROM sources").fetchone()[0],
            "epochs": self.conn.execute("SELECT COUNT(*) FROM epochs").fetchone()[0],
            "artifacts": self.conn.execute(
                "SELECT COUNT(*) FROM analysis_artifacts").fetchone()[0],
            "pending_activation": self.pending_activation() is not None,
            "size_bytes": size,
            "wal_bytes": os.path.getsize(wal) if wal and os.path.exists(wal) else 0,
        }

    def close(self) -> None:
        self.checkpoint()
        self.conn.close()


class BaseSource:
    """Byte-source over the stored epoch-0 segments; ``read`` returns 0 for gaps."""

    def __init__(self, segments: list[tuple[int, bytes]]):
        self._segs = sorted(segments)

    def read(self, addr: int, size: int) -> bytes:
        out = bytearray(size)
        for start, data in self._segs:
            lo = max(start, addr)
            hi = min(start + len(data), addr + size)
            if lo < hi:
                out[lo - addr:hi - addr] = data[lo - start:hi - start]
        return bytes(out)
