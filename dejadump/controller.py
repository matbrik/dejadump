"""Session controller (IDA-only): owns the sidecar store, the Mode A activator and
the panels, and is the single object the plugin's menu actions talk to.

One controller exists per open database: the plugin creates it when IDA reports
a database and closes it when the database goes away, so nothing (sidecar,
netnode, activator state) can leak from one IDB into the next.
"""

from __future__ import annotations

import hashlib
import os
import time
from typing import Optional

import ida_bytes
import ida_funcs
import ida_kernwin
import ida_nalt
import idc

from . import render
from .core import tenet
from .core.diffing import unified_diff
from .core.index import open_index
from .core.intervals import IntervalIndex
from .core.model import AnalysisArtifact
from .core.state import StateResolver
from .core.store import EpochStore
from .core.timeline import MemoryTimeline
from .ghost import GhostWorkerPool
from .hexrays import bridge
from .modes.mode_a import Activator
from .modes.mode_b import Pinner
from .modes.tracking import AnnotationTracker
from .ui.diff_viewer import DiffViewer
from .ui.epoch_panel import EpochPanel
from .ui.memory_timeline import MemoryTimelinePanel
from .ui.write_history import WriteHistoryPanel
from .util import fmt, ida_compat, settings
from .util.logging import get_logger, set_debug

log = get_logger("controller")

_MAX_TIMELINE_BYTES = 4096
GUIDE_URL = "docs/USER_GUIDE.md"


class UserError(Exception):
    """A problem the analyst can fix; shown as a plain warning, never a traceback."""


#: Sidecar suffix used before the plugin was renamed; still opened if present.
_LEGACY_SUFFIX = ".palimpsest.db"


def default_sidecar_path() -> str:
    idb = idc.get_idb_path()
    base = os.path.splitext(idb)[0] if idb else "dejadump"
    current = base + ".dejadump.db"
    legacy = base + _LEGACY_SUFFIX
    if not os.path.exists(current) and os.path.exists(legacy):
        return legacy
    return current


def _signed_hex(value: int) -> str:
    return ("-0x%X" % -value) if value < 0 else ("+0x%X" % value)


def _is_debugger_segment(seg) -> bool:
    try:
        return bool(seg.is_debugger_segm())
    except Exception:
        return False


def idb_segments(include_debugger: bool = False) -> list[tuple[int, int, int]]:
    """``(start, end, perm)`` of the program's segments.

    Debugger segments and DejaDump's own pinned shadow segments are excluded.
    """
    import ida_segment

    out = []
    for i in range(ida_segment.get_segm_qty()):
        seg = ida_segment.getnseg(i)
        if seg is None:
            continue
        if not include_debugger and _is_debugger_segment(seg):
            continue
        if (ida_segment.get_segm_name(seg) or "").startswith(fmt.SHADOW_PREFIXES):
            continue
        out.append((int(seg.start_ea), int(seg.end_ea), int(seg.perm)))
    return out


class Controller:
    def __init__(self):
        self.store: Optional[EpochStore] = None
        self.activator: Optional[Activator] = None
        self.pinner: Optional[Pinner] = None
        self.tracker: Optional[AnnotationTracker] = None
        self._index = None
        self.panel: Optional[EpochPanel] = None
        self.memory_panel: Optional[MemoryTimelinePanel] = None
        self.write_panel: Optional[WriteHistoryPanel] = None
        self.diff_panels: list[DiffViewer] = []
        self.choosers: list = []
        self.ghost_pool = None
        self._ghost_key = None
        self._history = [0]
        self._history_index = 0
        self._has_epochs: Optional[bool] = None
        self._has_sidecar: Optional[bool] = None
        self._highlight_key = None
        self._highlight: Optional[IntervalIndex] = None
        self.snapshots: list[dict] = []

    # -- lifecycle ----------------------------------------------------------
    @property
    def index(self):
        if self._index is None:
            self._index = open_index()
        return self._index

    def sidecar_path(self) -> str:
        """The sidecar for this IDB: a located one (remembered in the IDB) or the default."""
        try:
            remembered = self.index.get("sidecar_path")
        except Exception:
            remembered = None
        if remembered:
            idb_dir = os.path.dirname(idc.get_idb_path() or "")
            path = remembered if os.path.isabs(remembered) else os.path.join(idb_dir, remembered)
            if os.path.exists(path):
                return path
        return default_sidecar_path()

    def has_sidecar(self) -> bool:
        """Cached: also called from IDA's action-update callbacks."""
        if self.store is not None:
            return True
        if self._has_sidecar is None:
            self._has_sidecar = os.path.exists(self.sidecar_path())
        return self._has_sidecar

    def has_epochs(self) -> bool:
        """Cheap, cached answer for action enable/disable.

        Runs inside IDA's action-update callbacks, so it must never open the
        sidecar for real (that may show dialogs or install hooks): an unopened
        sidecar is probed read-only.
        """
        if self._has_epochs is None:
            if self.store is not None:
                self._has_epochs = bool(self.store.epochs())
            else:
                self._has_epochs = self._probe_sidecar(self.sidecar_path())
        return self._has_epochs

    @staticmethod
    def _probe_sidecar(path: str) -> bool:
        if not os.path.exists(path):
            return False
        import pathlib
        import sqlite3

        try:
            uri = pathlib.Path(os.path.abspath(path)).as_uri() + "?mode=ro"
            conn = sqlite3.connect(uri, uri=True)
            try:
                return conn.execute("SELECT 1 FROM epochs LIMIT 1").fetchone() is not None
            finally:
                conn.close()
        except Exception:
            return False

    def _sidecar_changed(self) -> None:
        self._has_epochs = None
        self._has_sidecar = None
        self._highlight_key = None
        if self.activator is not None:
            self.activator.invalidate()
        self._refresh_views()

    def _open(self, path: str) -> EpochStore:
        store = EpochStore(path)
        self.store = store
        self.tracker = AnnotationTracker(flush=self.flush_annotations)
        try:
            self.tracker.install()
        except Exception:
            log.exception("annotation tracking unavailable; switches capture everything")
            self.tracker = None
        self.activator = Activator(store, self.index, tracker=self.tracker)
        self.pinner = Pinner(store)
        self._verify_sidecar()
        if store.get_meta("idb_imagebase") is None:
            store.set_meta("idb_imagebase", str(self._imagebase()))
            store.conn.commit()
        return store

    def _ensure_store(self) -> EpochStore:
        if self.store is None:
            self._open(self.sidecar_path())
        return self.store

    def _open_sidecar(self) -> EpochStore:
        """The existing sidecar (with or without epochs); never creates one."""
        if not self.has_sidecar():
            raise UserError("there is no sidecar for this IDB yet — import something first.")
        return self._ensure_store()

    def _require_store(self) -> EpochStore:
        if not self.has_sidecar():
            raise UserError("no epochs yet — import a trace, an image pair or memory dumps "
                            "first (Edit → DejaDump → Import).")
        store = self._ensure_store()
        if not store.epochs():
            raise UserError("the sidecar has no epochs for the active source — import one "
                            "first.")
        return store

    @staticmethod
    def _imagebase() -> int:
        try:
            import idaapi

            return int(idaapi.get_imagebase())
        except Exception:
            return 0

    def _idb_fingerprint(self) -> str:
        parts = []
        md5 = self._input_md5()
        if md5:
            parts.append(md5)
        try:
            import ida_ida

            parts.extend([str(self._imagebase()), ida_ida.inf_get_procname(),
                          "64" if ida_ida.inf_is_64bit() else "32"])
            try:
                import ida_segment

                for i in range(ida_segment.get_segm_qty()):
                    seg = ida_segment.getnseg(i)
                    if seg is None:
                        continue
                    name = ida_segment.get_segm_name(seg) or ""
                    # Pins and debugger mappings come and go; they must not
                    # make the sidecar look like it belongs to another IDB.
                    if name.startswith(fmt.SHADOW_PREFIXES) or _is_debugger_segment(seg):
                        continue
                    parts.append("%x:%x:%x:%s:%s" % (
                        seg.start_ea, seg.end_ea, seg.perm, name,
                        ida_segment.get_segm_class(seg) or ""))
            except Exception:
                log.debug("segment layout not included in the fingerprint")
        except Exception:
            parts.append(ida_nalt.get_root_filename() or "")
        return hashlib.sha256("|".join(parts).encode()).hexdigest() if parts else ""

    def _legacy_idb_fingerprint(self) -> str:
        """v2.0 fingerprint before segment-layout binding was added."""
        parts = []
        md5 = self._input_md5()
        if md5:
            parts.append(md5)
        try:
            import ida_ida

            parts.extend([str(self._imagebase()), ida_ida.inf_get_procname(),
                          "64" if ida_ida.inf_is_64bit() else "32"])
        except Exception:
            parts.append(ida_nalt.get_root_filename() or "")
        return hashlib.sha256("|".join(parts).encode()).hexdigest() if parts else ""

    @staticmethod
    def _input_md5() -> str:
        try:
            md5 = ida_nalt.retrieve_input_file_md5()
            return md5.hex() if isinstance(md5, (bytes, bytearray)) else str(md5 or "")
        except Exception:
            return ""

    def _record_fingerprint(self) -> None:
        value = self._idb_fingerprint()
        self.store.set_meta("idb_fingerprint", value)
        self.store.conn.commit()
        try:
            self.index.set("idb_fingerprint", value)
            self.index.set("content_hash", self.store.content_hash())
        except Exception:
            log.debug("netnode index not updated")

    def _verify_sidecar(self) -> None:
        """Disable switching if the sidecar was created for a different IDB."""
        try:
            stored = self.store.get_meta("idb_fingerprint") or self.index.get("idb_fingerprint")
            cur = self._idb_fingerprint()
            legacy = self._legacy_idb_fingerprint()
            accepted = (cur, legacy, self._input_md5())
            if stored and cur and stored not in accepted:
                self.activator.disabled_reason = "the sidecar belongs to a different IDB"
                self.activator.hard_disabled = True
                ida_kernwin.warning(
                    "DejaDump: this sidecar was created for a different database.\n"
                    "Epoch switching is disabled; locate the correct sidecar or re-import."
                )
            elif stored in accepted[1:] and cur not in accepted[1:]:
                self.store.set_meta("idb_fingerprint", cur)
                self.store.conn.commit()
                self.index.set("idb_fingerprint", cur)
        except Exception:
            log.exception("sidecar verification failed")

    def flush_annotations(self) -> None:
        if self.activator is not None:
            self.activator.flush_annotations()

    def close(self):
        for panel in [self.panel, self.memory_panel, self.write_panel,
                      *self.diff_panels, *self.choosers]:
            if panel is None:
                continue
            try:
                if isinstance(panel, ida_kernwin.Choose):
                    panel.Close()
                else:
                    panel.Close(0)
            except Exception:
                log.debug("could not close %r", panel)
        self.panel = self.memory_panel = self.write_panel = None
        self.diff_panels, self.choosers = [], []
        if self.ghost_pool is not None:
            self.ghost_pool.close()
            self.ghost_pool = None
            self._ghost_key = None
        if self.tracker is not None:
            try:
                self.tracker.uninstall()
            except Exception:
                pass
            self.tracker = None
        if self.store is not None:
            self.store.close()
            self.store = None
        self.activator = self.pinner = None
        self._index = None
        self._has_epochs = self._has_sidecar = None

    # -- data for the panel -------------------------------------------------
    def epoch_rows(self) -> list[dict]:
        store = self._ensure_store()
        favorites = store.favorites()
        t0_stats = store.artifact_stats(store.epoch_ref(0))
        rows = [{"seq": 0, "kind": "base", "boundary_pc": None, "ranges": 0,
                 "bytes": 0, "favorite": 0 in favorites, "cache": t0_stats["count"],
                 "cache_ms": t0_stats["duration_ms"], "functions": 0}]
        summaries = store.epoch_summaries()
        for e in store.epochs():
            summary = summaries.get(e["id"], {})
            stats = store.artifact_stats(store.epoch_ref(e["seq"]))
            rows.append({
                "id": e["id"],
                "seq": e["seq"],
                "label": e["label"] or "",
                "note": e["note"] or "",
                "kind": e["boundary_kind"],
                "boundary_pc": e["boundary_pc"],
                "ranges": summary.get("ranges", 0),
                "bytes": summary.get("bytes", 0),
                "code_bytes": summary.get("code_bytes", 0),
                "functions": summary.get("functions", 0),
                "favorite": e["seq"] in favorites,
                "cache": stats["count"],
                "cache_ms": stats["duration_ms"],
            })
        return rows

    def active_epoch(self) -> int:
        if not self.has_sidecar():
            return 0
        return self._ensure_store().active_epoch()

    def max_epoch(self) -> int:
        if not self.has_sidecar():
            return 0
        eps = self._ensure_store().epochs()
        return max((e["seq"] for e in eps), default=0)

    def _refresh_views(self) -> None:
        for view in (self.panel,):
            if view is not None:
                try:
                    view.reload()
                except Exception:
                    log.debug("panel reload failed")
        try:
            ida_kernwin.refresh_idaview_anyway()
        except Exception:
            pass

    # -- choosers -----------------------------------------------------------
    def choose_epoch(self, title: str, default: Optional[int] = None,
                     include_t0: bool = True) -> Optional[int]:
        from .ui.choosers import EpochChooser

        self._require_store()
        rows = [r for r in self.epoch_rows() if include_t0 or r["seq"] > 0]
        if not rows:
            raise UserError("there are no epochs to choose from.")
        default = self.active_epoch() if default is None else default
        return EpochChooser(title, rows, default, self.active_epoch()).choose()

    # -- actions: navigation -------------------------------------------------
    def activate(self, k: int, record_history: bool = True) -> bool:
        self._require_store()
        ok = False
        try:
            ok = self.activator.activate(k)
        finally:
            # Always resync: a failed switch must not leave the slider elsewhere.
            self._highlight_key = None
            self._refresh_views()
            if self.memory_panel is not None:
                self.memory_panel.set_active(self.active_epoch())
        if ok and record_history:
            self._history = self._history[:self._history_index + 1]
            if not self._history or self._history[-1] != k:
                self._history.append(k)
                self._history_index = len(self._history) - 1
        return ok

    def history_back(self) -> None:
        if self._history_index > 0:
            self._history_index -= 1
            self.activate(self._history[self._history_index], record_history=False)

    def history_forward(self) -> None:
        if self._history_index + 1 < len(self._history):
            self._history_index += 1
            self.activate(self._history[self._history_index], record_history=False)

    def goto_epoch(self) -> None:
        k = self.choose_epoch("DejaDump — go to epoch")
        if k is not None:
            self.activate(k)

    def set_favorite(self, seq: int, enabled: bool) -> None:
        self._ensure_store().set_favorite(seq, enabled)

    def activation_timings(self) -> dict:
        return dict(self.activator.last_timings) if self.activator else {}

    def cached_preview(self, seq: int) -> tuple[str, list[str]]:
        epoch = self._ensure_store().epoch_ref(seq)
        artifact = self.store.latest_artifact(epoch)
        if artifact and artifact.version_key == self._artifact_version(epoch, artifact.kind):
            return artifact.kind, artifact.lines[:80]
        return "", []

    def update_epoch_text(self, epoch_id: int, label: str, note: str) -> None:
        if epoch_id:
            self._ensure_store().update_epoch_text(epoch_id, label, note)

    def step(self, delta: int) -> None:
        self._require_store()
        k = max(0, min(self.max_epoch(), self.active_epoch() + delta))
        self.activate(k)

    def revert(self) -> None:
        self._require_store()
        try:
            self.activator.revert_to_t0()
        finally:
            self._highlight_key = None
            self._refresh_views()

    def open_panel(self) -> None:
        self._require_store()
        if self.panel is None:
            self.panel = EpochPanel(self)
        self.panel.show()

    def on_undo_redo(self) -> None:
        """Undo/redo may have reverted an epoch switch: re-identify the IDB state."""
        if self.activator is not None:
            self.activator.invalidate()
            self._highlight_key = None
        if self.panel is not None:
            ida_kernwin.execute_ui_requests([lambda: self._refresh_views() or False])

    def on_cursor(self, ea: int) -> None:
        if self.write_panel is not None:
            self.write_panel.follow(ea)

    # -- annotations ---------------------------------------------------------
    def promote_annotations(self) -> None:
        """Copy active epoch annotations across every epoch in the active source."""
        from .core import annotations

        store = self._require_store()
        current = self.active_epoch()
        if ida_kernwin.ask_yn(
            0, "Promote annotations from t%d to every epoch in this source?" % current
        ) != 1:
            return
        count = 0
        last = self.max_epoch()
        for start, end in store.volatile_set():
            payload = annotations.capture(start, end)
            store.set_shared_annot(start, payload)
            for seq in range(last + 1):
                store.set_annot(store.epoch_ref(seq), start, payload)
                count += 1
        store.clear_artifacts()
        ida_kernwin.info("DejaDump: promoted %d annotation range(s)." % count)

    def copy_annotations(self) -> None:
        from .core import annotations

        store = self._require_store()
        source = self.choose_epoch("Copy annotations FROM epoch")
        if source is None:
            return
        target = self.choose_epoch("Copy annotations TO epoch")
        if target is None:
            return
        if source == self.active_epoch():
            self.activator._capture_current(source)
        payloads = store.annots_for_epoch(store.epoch_ref(source))
        for start, payload in payloads.items():
            store.set_annot(store.epoch_ref(target), start, payload)
            if target == self.active_epoch():
                annotations.restore(start, payload)
        store.clear_artifacts(store.epoch_ref(target))
        if payloads:
            ida_kernwin.refresh_idaview_anyway()
            ida_kernwin.info("DejaDump: copied %d annotation range(s) from t%d to t%d."
                             % (len(payloads), source, target))
        else:
            ida_kernwin.warning(
                "DejaDump: t%d has no captured annotation ranges yet; activate it "
                "once before copying." % source)

    # -- sources -------------------------------------------------------------
    def _prepare_new_source(self) -> None:
        """Bring the IDB back to t0 before a new source becomes active.

        Every source's t0 is the loaded image; leaving another source's epoch
        bytes in the IDB would strand them outside the new volatile set.
        """
        store = self._ensure_store()
        if store.epochs() and store.active_epoch() != 0:
            if not self.activator.revert_to_t0():
                raise UserError("could not revert the current source to t0; resolve that "
                                "first (Edit → DejaDump → Revert to t0).")

    def select_source(self, source_id: int) -> None:
        store = self._open_sidecar()
        previous_source = store.active_source_id()
        if source_id == previous_source:
            return
        self._prepare_new_source()
        try:
            store.set_active_source(int(source_id))
            self.activator.invalidate()
            self.activator.ensure_base()
            if not self.activator.reconcile():
                raise RuntimeError(self.activator.disabled_reason)
            self._history, self._history_index = [self.active_epoch()], 0
        except Exception as exc:
            if previous_source is not None:
                store.set_active_source(previous_source)
            self.activator.disabled_reason = None
            self.activator.invalidate()
            ida_kernwin.warning("DejaDump source selection failed: %s" % exc)
        self._sidecar_changed()

    def rename_source(self, source_id: int, label: str) -> None:
        self._ensure_store().rename_source(source_id, label)

    def delete_source(self, source_id: int) -> bool:
        store = self._open_sidecar()
        if ida_kernwin.ask_yn(0, "Delete source %d and all of its epochs, annotations and "
                                 "cached artifacts from the sidecar?" % source_id) != 1:
            return False
        if source_id == store.active_source_id():
            self._prepare_new_source()
        store.delete_source(source_id)
        self.activator.invalidate()
        if store.epochs():
            self.activator.ensure_base()
        self._sidecar_changed()
        return True

    def manage_sources(self) -> None:
        from .ui.choosers import SourceChooser

        store = self._open_sidecar()
        chooser = SourceChooser(self, store)
        self.choosers.append(chooser)
        chooser.Show()

    def sidecar_health(self) -> None:
        store = self._open_sidecar()
        store.checkpoint()
        h = store.health()
        pending = self.tracker.pending if self.tracker is not None else 0
        ida_kernwin.info(
            "DejaDump sidecar\n%s\n\nSchema: v%d\nIntegrity: %s\nSources: %d\nEpochs: %d\n"
            "Cached artifacts: %d\nPending activation: %s\nUnsaved annotation windows: %d\n"
            "Database: %s\nWAL: %s" % (
                store.path, h["schema_version"], h["integrity"], h["sources"], h["epochs"],
                h["artifacts"], h["pending_activation"], pending,
                fmt.size(h["size_bytes"]), fmt.size(h["wal_bytes"])))

    def compact_sidecar(self) -> None:
        store = self._open_sidecar()
        if ida_kernwin.ask_yn(1, "Compact the sidecar?\n\nRemoves unreferenced data and "
                                 "rebuilds the file (VACUUM).") != 1:
            return
        ida_kernwin.show_wait_box("DejaDump: compacting sidecar…")
        try:
            result = store.compact()
        finally:
            ida_kernwin.hide_wait_box()
        ida_kernwin.info("DejaDump: removed %d unreferenced blob(s); %s → %s." % (
            result["blobs_removed"], fmt.size(result["size_before"]),
            fmt.size(result["size_after"])))

    def locate_sidecar(self) -> None:
        path = ida_kernwin.ask_file(False, "*.dejadump.db;*.db", "Locate DejaDump sidecar")
        if not path:
            return
        try:
            probe = EpochStore(path)
            probe.health()
            probe.close()
        except Exception as exc:
            ida_kernwin.warning("DejaDump could not open sidecar: %s" % exc)
            return
        self.close()
        idb_dir = os.path.dirname(idc.get_idb_path() or "")
        try:
            remembered = os.path.relpath(path, idb_dir) if idb_dir else path
        except ValueError:  # different drive on Windows
            remembered = path
        self.index.set("sidecar_path", remembered)
        self._open(path)
        self._history, self._history_index = [self.active_epoch()], 0
        self._sidecar_changed()
        ida_kernwin.info("DejaDump: using sidecar %s\n(remembered in this IDB)." % path)

    # -- R3: data over time -------------------------------------------------
    def resolver(self, observed: bool = False) -> StateResolver:
        store = self._ensure_store()
        return StateResolver(store.load_epochs(), base=store.base_source(),
                             observed=store.observed() if observed else None)

    def writes_for_addr(self, addr: int) -> list:
        store = self._ensure_store()
        rows = store.writes_for_addr(addr)
        for r in rows:  # sqlite returns memoryview/bytes-ish; normalise
            off = addr - r["addr"]
            for key, at in (("new_bytes", "new_at_addr"), ("old_bytes", "old_at_addr")):
                if r.get(key) is not None:
                    r[key] = bytes(r[key])
                    r[at] = r[key][off:off + 1]
        return rows

    def writes_for_range(self, start: int, end: int) -> list:
        rows = self._ensure_store().writes_for_range(start, end)
        for row in rows:
            for key in ("new_bytes", "old_bytes"):
                if row.get(key) is not None:
                    row[key] = bytes(row[key])
        return rows

    def jump_to_writer(self, writer_pc: Optional[int], epoch: int) -> None:
        if writer_pc is None:
            ida_kernwin.info("DejaDump: this change came from a dump; there is no writer "
                             "instruction to jump to.")
            return
        if epoch != self.active_epoch() and not self.activate(epoch):
            return
        ida_kernwin.jumpto(writer_pc)

    def jump_to_epoch_address(self, epoch: int, address: int) -> None:
        if epoch == self.active_epoch() or self.activate(epoch):
            ida_kernwin.jumpto(address)

    def _current_range(self) -> tuple[int, int]:
        ok, start, end = ida_kernwin.read_range_selection(None)
        if ok and end > start:
            size = end - start
        else:
            head = ida_bytes.get_item_head(ida_kernwin.get_screen_ea())
            start = head
            size = max(1, ida_bytes.get_item_size(head))
        if size > _MAX_TIMELINE_BYTES:
            ida_kernwin.warning(
                "DejaDump: range clamped to %d bytes for the timeline." % _MAX_TIMELINE_BYTES
            )
            size = _MAX_TIMELINE_BYTES
        return start, size

    def open_memory_timeline(self) -> None:
        self._require_store()
        start, size = self._current_range()
        timeline = MemoryTimeline(
            self.resolver(observed=True), writer_lookup=self.writes_for_addr,
            writer_range_lookup=self.writes_for_range)
        timeline.prefetch_writers(start, size)
        if self.memory_panel is not None:
            try:
                self.memory_panel.Close(0)
            except Exception:
                pass
        self.memory_panel = MemoryTimelinePanel(self, timeline, start, size)
        self.memory_panel.show()

    def open_write_history(self) -> None:
        self._require_store()
        if self.write_panel is None:
            self.write_panel = WriteHistoryPanel(self)
        self.write_panel.show()

    # -- highlighting ---------------------------------------------------------
    def highlight_index(self) -> Optional[IntervalIndex]:
        """Spans the active epoch changed vs. its predecessor (cached per switch)."""
        if self.store is None or self.activator is None:
            return None
        key = (self.store.generation, self.store.active_source_id(), self.store.active_epoch())
        if key != self._highlight_key:
            k = self.store.active_epoch()
            self._highlight = IntervalIndex(self.activator.changed_spans(k)) if k else None
            self._highlight_key = key
        return self._highlight

    def toggle_highlight(self) -> None:
        enabled = not settings.get_bool("highlight")
        settings.set("highlight", "1" if enabled else "0")
        ida_kernwin.refresh_idaview_anyway()
        ida_kernwin.msg("DejaDump: changed-line highlighting %s.\n" %
                        ("on" if enabled else "off"))

    # -- cached assembly / pseudocode diff ---------------------------------
    def _artifact_version(self, epoch, kind: str) -> str:
        store = self._ensure_store()
        processor, analysis, decompiler = "", "", "none"
        try:
            import ida_ida

            processor = ida_ida.inf_get_procname()
            analysis = "%x:%x" % (ida_ida.inf_get_af(), ida_ida.inf_get_af2())
        except Exception:
            pass
        if kind == "pseudocode" and ida_compat.has_hexrays():
            try:
                import ida_hexrays

                decompiler = ida_hexrays.get_hexrays_version()
            except Exception:
                decompiler = "available"
        raw = "%s|%s|%s|%s|%s|%s|%s|%s" % (
            store.content_hash(), ida_compat.ida_version(), processor, decompiler,
            analysis, kind, store.annotation_revision(epoch), self._idb_fingerprint(),
        )
        return hashlib.sha256(raw.encode()).hexdigest()

    def _ensure_ghost_pool(self):
        worker_python = settings.get("idalib_python")
        if not worker_python:
            return None
        store = self._ensure_store()
        revisions = tuple(store.annotation_revision(store.epoch_ref(seq))
                          for seq in range(self.max_epoch() + 1))
        template_key = (store.content_hash(), revisions, self._idb_fingerprint())
        if self.ghost_pool is not None and self._ghost_key != template_key:
            self.ghost_pool.close()
            self.ghost_pool = None
        if self.ghost_pool is None:
            if not self.activator.reconcile():
                raise RuntimeError("cannot create worker template: %s" %
                                   self.activator.disabled_reason)
            size = settings.get_int("workers", 2, 1, 4)
            self.ghost_pool = GhostWorkerPool(self._ensure_store(), worker_python, size=size)
            self._ghost_key = template_key
        return self.ghost_pool

    def _render_live(self, kind: str, start: int, end: int, diagnostics: dict):
        if kind == "pseudocode":
            if not ida_compat.has_hexrays():
                raise RuntimeError("a matching Hex-Rays decompiler is not available")
            lines, addresses, warnings = render.render_pseudocode(start, no_cache=True)
            if warnings:
                diagnostics["warnings"] = warnings
        elif kind == "bytes":
            lines, addresses = render.render_bytes(start, end)
        else:
            lines, addresses = render.render_assembly(start, end)
        if kind != "bytes":
            diagnostics["blocks"] = render.block_signatures(start)
        return lines, addresses

    def _render_artifact(self, k: int, kind: str, start: int, end: int) -> AnalysisArtifact:
        store = self._ensure_store()
        epoch = store.epoch_ref(k)
        version = self._artifact_version(epoch, kind)
        cached = store.get_artifact(epoch, kind, start, end, version)
        if cached:
            return cached
        original = self.active_epoch()
        began = time.perf_counter()
        lines, addresses, diagnostics = [], [], {}
        worker_python = settings.get("idalib_python")
        try:
            if worker_python:
                pool = self._ensure_ghost_pool()
                if kind == "pseudocode" and not pool.capabilities.get("hexrays"):
                    raise RuntimeError("the idalib worker has no matching Hex-Rays decompiler")
                ida_kernwin.show_wait_box("DejaDump: rendering t%d in the idalib worker…" % k)
                try:
                    response = pool.render(k, kind, start, end,
                                           cancelled=ida_kernwin.user_cancelled)
                finally:
                    ida_kernwin.hide_wait_box()
                if not response.get("ok"):
                    raise RuntimeError(response.get("error", "worker rendering failed"))
                lines = response.get("lines", [])
                addresses = response.get("addresses", [None] * len(lines))
                diagnostics["backend"] = "idalib"
                if response.get("warnings"):
                    diagnostics["warnings"] = response["warnings"]
                if response.get("blocks") is not None:
                    diagnostics["blocks"] = response["blocks"]
                artifact = AnalysisArtifact(
                    epoch, kind, start, end, version, lines, addresses, diagnostics,
                    (time.perf_counter() - began) * 1000,
                )
                store.put_artifact(artifact)
                return artifact
            if original != k and not self.activator.activate(k):
                raise RuntimeError("could not activate t%d" % k)
            lines, addresses = self._render_live(kind, start, end, diagnostics)
        except Exception as exc:
            diagnostics["error"] = str(exc)
            lines = ["<%s>" % exc]
            addresses = [None]
        finally:
            if not worker_python and self.active_epoch() != original:
                self.activator.activate(original)
        version = self._artifact_version(epoch, kind)
        artifact = AnalysisArtifact(epoch, kind, start, end, version, lines, addresses,
                                    diagnostics, (time.perf_counter() - began) * 1000)
        if "error" not in diagnostics:
            # Failures (no decompiler, refused switch, …) are reported, never cached.
            store.put_artifact(artifact)
        return artifact

    @staticmethod
    def _diff_summary(a: AnalysisArtifact, b: AnalysisArtifact) -> str:
        left = {int(row["start"]): row.get("hash", "")
                for row in a.diagnostics.get("blocks", [])}
        right = {int(row["start"]): row.get("hash", "")
                 for row in b.diagnostics.get("blocks", [])}
        added = len(right.keys() - left.keys())
        removed = len(left.keys() - right.keys())
        modified = sum(left[key] != right[key] for key in left.keys() & right.keys())
        a_lines, b_lines = set(a.lines), set(b.lines)
        plus = sum(1 for line in b.lines if line not in a_lines)
        minus = sum(1 for line in a.lines if line not in b_lines)
        return ("Basic blocks: +%d / −%d / ~%d   ·   rendered lines: +%d / −%d" %
                (added, removed, modified, plus, minus))

    def _view_range(self, kind: str) -> tuple[int, int]:
        ea = ida_kernwin.get_screen_ea()
        selected, start, end = ida_kernwin.read_range_selection(None)
        if selected and end > start:
            return start, end
        f = ida_funcs.get_func(ea)
        if f and kind != "bytes":
            return f.start_ea, f.end_ea
        start, end = ida_bytes.get_item_head(ea), ida_bytes.get_item_end(ea)
        if end <= start or kind == "bytes":
            end = start + 0x100
        return start, end

    def compare_with(self, kind: str = "assembly") -> None:
        self._require_store()
        current = self.active_epoch()
        default = max(0, current - 1) if current else min(1, self.max_epoch())
        other = self.choose_epoch("Compare t%d with epoch" % current, default)
        if other is None:
            return
        if other == current:
            ida_kernwin.warning("DejaDump: choose an epoch other than the active one (t%d)."
                                % current)
            return
        choice = ida_kernwin.ask_yn(1, "Normalize addresses, automatic labels, and whitespace?")
        if choice < 0:
            return
        normalized = choice == 1
        start, end = self._view_range(kind)
        a = self._render_artifact(current, kind, start, end)
        b = self._render_artifact(other, kind, start, end)
        rendered_kind = kind
        fallback = kind == "pseudocode" and (
            bool(a.diagnostics.get("error")) or bool(b.diagnostics.get("error")))
        if fallback:
            rendered_kind = "assembly"
            a = self._render_artifact(current, rendered_kind, start, end)
            b = self._render_artifact(other, rendered_kind, start, end)
        lines = unified_diff(a.lines, b.lines, "t%d" % current, "t%d" % other,
                             kind=rendered_kind, normalized=normalized)
        panel = DiffViewer(self, "DejaDump — %s%s t%d ↔ t%d" %
                           ("Normalized " if normalized else "Exact ",
                            ("Assembly fallback" if fallback else rendered_kind.title()),
                            current, other),
                           lines or ["No differences."],
                           (current, a.lines, a.addresses), (other, b.lines, b.addresses),
                           self._diff_summary(a, b), kind=rendered_kind,
                           normalized=normalized)
        self.diff_panels.append(panel)
        panel.show()

    def compare_here(self) -> None:
        """Compare the current function using the representation of the active view.

        This is primarily used by the toolbar's single Compare button: in a
        pseudocode widget it opens a pseudocode diff, while every other widget
        gets the more generally available assembly diff.
        """
        kind = "assembly"
        try:
            widget = ida_kernwin.get_current_widget()
            if widget is not None and ida_kernwin.get_widget_type(widget) == ida_kernwin.BWN_PSEUDOCODE:
                kind = "pseudocode"
        except Exception:
            pass
        self.compare_with(kind)

    def clear_analysis_cache(self) -> None:
        n = self._require_store().clear_artifacts()
        ida_kernwin.info("DejaDump: removed %d cached analysis artifact(s)." % n)

    def analyze_epoch(self, epoch: Optional[int] = None, kind: str = "assembly") -> None:
        self._require_store()
        epoch = self.active_epoch() if epoch is None else epoch
        if epoch < 0 or epoch > self.max_epoch():
            ida_kernwin.warning("DejaDump: epoch is outside the active source.")
            return
        start, end = self._view_range(kind)
        artifact = self._render_artifact(int(epoch), kind, start, end)
        error = artifact.diagnostics.get("error")
        if error:
            ida_kernwin.warning("DejaDump: could not cache %s for t%d: %s" %
                                (kind, epoch, error))
        else:
            ida_kernwin.info("DejaDump: cached %s for t%d in %.0f ms." %
                             (kind, epoch, artifact.duration_ms))
        if self.panel:
            self.panel.reload()

    def preanalyze_all(self, kind: str = "assembly") -> None:
        self._require_store()
        start, end = self._view_range(kind)
        epochs = list(range(self.max_epoch() + 1))
        pool = self._ensure_ghost_pool() if settings.get("idalib_python") else None
        if pool is not None and kind == "pseudocode" and not pool.capabilities.get("hexrays"):
            ida_kernwin.warning(
                "DejaDump: the configured idalib runtime has no matching Hex-Rays decompiler.")
            return
        ida_kernwin.show_wait_box("DejaDump: caching %s…" % kind)
        completed = 0
        try:
            if pool is not None:
                for offset in range(0, len(epochs), pool.size):
                    if ida_kernwin.user_cancelled():
                        pool.cancel()
                        pool.close()
                        self.ghost_pool = None
                        self._ghost_key = None
                        break
                    batch = epochs[offset:offset + pool.size]
                    ida_kernwin.replace_wait_box(
                        "DejaDump: caching %s (%d/%d)…" % (kind, completed, len(epochs)))
                    began = time.perf_counter()
                    responses = pool.render_many([(k, kind, start, end) for k in batch])
                    duration = (time.perf_counter() - began) * 1000 / max(1, len(batch))
                    for k, response in zip(batch, responses):
                        epoch = self._ensure_store().epoch_ref(k)
                        diagnostics = {"backend": "idalib"}
                        if response.get("warnings"):
                            diagnostics["warnings"] = response["warnings"]
                        if not response.get("ok"):
                            diagnostics["error"] = response.get("error", "worker rendering failed")
                        if response.get("blocks") is not None:
                            diagnostics["blocks"] = response["blocks"]
                        if "error" in diagnostics:
                            continue
                        artifact = AnalysisArtifact(
                            epoch, kind, start, end, self._artifact_version(epoch, kind),
                            response.get("lines", []), response.get("addresses", []),
                            diagnostics, duration,
                        )
                        self.store.put_artifact(artifact)
                        completed += 1
            else:
                for k in epochs:
                    if ida_kernwin.user_cancelled():
                        break
                    ida_kernwin.replace_wait_box(
                        "DejaDump: caching %s for t%d (%d/%d)…" %
                        (kind, k, completed + 1, len(epochs)))
                    self._render_artifact(k, kind, start, end)
                    completed += 1
        finally:
            ida_kernwin.hide_wait_box()
        ida_kernwin.info("DejaDump: cached %s for %d/%d epoch(s)." %
                         (kind, completed, len(epochs)))
        if self.panel:
            self.panel.reload()

    # -- pins ------------------------------------------------------------------
    def pin_epoch(self, k=None) -> None:
        if k is None:
            k = self.choose_epoch("Pin epoch", max(1, self.active_epoch()), include_t0=False)
        if k is None:
            return
        try:
            segments = self.pinner.pin(int(k))
            ida_kernwin.info("DejaDump: pinned t%d in %d shadow segment(s)." %
                             (int(k), len(segments)))
        except Exception as exc:
            ida_kernwin.warning("DejaDump pin failed: %s" % exc)

    def unpin_epoch(self, k=None) -> None:
        if k is None:
            k = self.choose_epoch("Unpin epoch", max(1, self.active_epoch()), include_t0=False)
        if k is None:
            return
        try:
            self.pinner.unpin(int(k))
            ida_kernwin.info("DejaDump: unpinned t%d." % int(k))
        except Exception as exc:
            ida_kernwin.warning("DejaDump unpin failed: %s" % exc)

    def rebase_pinned_pointers(self) -> None:
        k = self.choose_epoch("Preview pointer rebasing for pinned epoch",
                              max(1, self.active_epoch()), include_t0=False)
        if k is None:
            return
        try:
            rows = self.pinner.pointer_rebase_preview(int(k))
            if not rows:
                ida_kernwin.info(
                    "DejaDump: no typed 64-bit pointers into shadowed ranges were found.")
                return
            preview = "\n".join("0x%X: 0x%X → 0x%X" %
                                (row["shadow"], row["old"], row["new"])
                                for row in rows[:20])
            suffix = "\n… and %d more" % (len(rows) - 20) if len(rows) > 20 else ""
            if ida_kernwin.ask_yn(
                0, "Apply %d typed-pointer rebase(s)?\n\n%s%s" %
                (len(rows), preview, suffix)
            ) != 1:
                return
            count = self.pinner.apply_pointer_rebases(int(k), rows)
            ida_kernwin.info("DejaDump: rebased %d typed pointer(s) in t%d." %
                             (count, int(k)))
        except Exception as exc:
            ida_kernwin.warning("DejaDump pointer rebase failed: %s" % exc)

    # -- provenance --------------------------------------------------------------
    def materialize_provenance(self) -> None:
        store = self._require_store()
        ida_kernwin.show_wait_box("DejaDump: materialising write provenance…")

        def progress(done, total):
            if ida_kernwin.user_cancelled():
                return False
            if done % 256 == 0:
                ida_kernwin.replace_wait_box(
                    "DejaDump: materialising write provenance (%d/%d writers)…" %
                    (done, total))
            return True

        try:
            n = bridge.materialize_write_xrefs(store, store.volatile_set(), progress)
        finally:
            ida_kernwin.hide_wait_box()
        ida_kernwin.info(
            "DejaDump: materialised %d temporal write xref(s) on stable-code writers "
            "(one summary comment per writer).\n"
            "Press X on a written address to see the instructions that wrote it." % n
        )

    def clear_provenance(self) -> None:
        n = bridge.remove_materialized_xrefs(self._require_store())
        ida_kernwin.info("DejaDump: removed %d plugin-owned temporal xref(s) and their "
                         "comments." % n)

    def temporal_xrefs_here(self) -> None:
        """Xref the cursor address across epochs: materialise its write xrefs, show
        the Write History, and summarise the times it was written."""
        store = self._require_store()
        ea = ida_kernwin.get_screen_ea()
        writers = bridge.materialize_xrefs_for_addr(store, ea, store.volatile_set())
        self.open_write_history()
        if self.write_panel is not None:
            self.write_panel.refresh()
        if not writers:
            ida_kernwin.info("DejaDump: no recorded writes to 0x%X." % ea)
            return
        lines = "\n".join(
            "t%d: %s%s" % (w["epoch_seq"], fmt.writer(w["writer_pc"]),
                           (" wrote " + w["new_bytes"][:16].hex()) if w.get("new_bytes") else "")
            for w in writers
        )
        ida_kernwin.info(
            "DejaDump: 0x%X was written at %d time(s):\n%s\n\n"
            "Press X on this address for the cross-references." % (ea, len(writers), lines)
        )

    # -- imports -----------------------------------------------------------------
    def _wait_progress(self, label: str):
        last = [0.0]

        def progress(lines):
            if ida_kernwin.user_cancelled():
                return False
            now = time.perf_counter()
            if now - last[0] > 0.5:
                ida_kernwin.replace_wait_box("%s (%s lines)…" % (label, f"{lines:,}"))
                last[0] = now
            return True

        return progress

    def _keep_intervals(self):
        if not settings.get_bool("filter_traces"):
            return None
        return [(s, e) for s, e, _perm in idb_segments()]

    def _trace_rebase(self, path: str, head: list[str]):
        """Return ``(slide, image_base, how)`` for a trace, or raise ``UserError``."""
        manifest = tenet.load_manifest(path)
        image_base = self._imagebase()
        header = tenet.read_header(head)
        code = [(s, e) for s, e, perm in idb_segments() if perm & 1]
        delta = tenet.detect_slide(header["pcs"], code)
        claimed = None
        if "slide" in manifest:
            claimed = (manifest["slide"], manifest.get("image_base", image_base),
                       "manifest %s" % os.path.basename(manifest["path"]))
        elif header["slide"] is not None:
            claimed = (header["slide"], image_base, "trace slide= header")
        else:
            modules_path = tenet.find_modules_file(path)
            if modules_path:
                module = tenet.module_for(tenet.load_modules(modules_path),
                                          manifest.get("module")
                                          or ida_nalt.get_root_filename() or "")
                if module is not None:
                    claimed = (module["start"], image_base, "%s (%s)" % (
                        os.path.basename(modules_path), module["name"]))
        if claimed is not None:
            return self._check_claimed_rebase(claimed, delta, header["pcs"], code)
        if delta == 0:
            return 0, 0, "addresses already match the IDB"
        if delta is not None:
            if ida_kernwin.ask_yn(
                1, "DejaDump: the trace's addresses look shifted by 0x%X from the IDB.\n\n"
                   "Rebase the trace by that amount?" % delta) == 1:
                return delta, 0, "detected from executed addresses"
        base = ida_kernwin.ask_addr(
            image_base, "Runtime base of this module in the trace\n"
                        "(keep the IDB image base if addresses already match):")
        if base is None:
            raise UserError("import cancelled.")
        return base, image_base, "entered manually"

    @staticmethod
    def _check_claimed_rebase(claimed, delta, pcs, code):
        """Keep a header/manifest/.modules rebase unless the executed addresses
        clearly disagree with it — then let the user pick the detected one."""
        slide, image_base, how = claimed
        if delta is None or not pcs:
            return claimed
        hits = tenet.pcs_in_code(pcs, code, image_base - slide)
        detected_hits = tenet.pcs_in_code(pcs, code, -delta)
        if detected_hits <= hits:
            return claimed
        instead = ("Leave the addresses as they are" if delta == 0 else
                   "Move them by %s" % _signed_hex(-delta))
        if ida_kernwin.ask_yn(
            1, "DejaDump: the %s moves the trace's addresses by %s, which puts %d of %d "
               "sampled executed addresses in the IDB's code.\n\n%s instead? That puts "
               "%d of %d there." % (how, _signed_hex(image_base - slide), hits, len(pcs),
                                    instead, detected_hits, len(pcs))) == 1:
            return delta, 0, "detected from executed addresses (%s ignored)" % how
        return claimed

    def _arch_for(self, path: str, head: list[str]):
        manifest = tenet.load_manifest(path)
        if manifest.get("arch"):
            return tenet.ARCHES[manifest["arch"]]
        arch = tenet.detect_arch(head)
        if arch is not None:
            return arch
        try:
            import ida_ida

            proc = ida_ida.inf_get_procname().lower()
            if proc == "arm" and ida_ida.inf_is_64bit():
                return tenet.ARM64
            if proc == "metapc":
                return tenet.AMD64 if ida_ida.inf_is_64bit() else tenet.X86
        except Exception:
            pass
        raise UserError("could not tell the trace's architecture (no pc=/rip=/eip= found).")

    def _discard_empty_source(self, source_id: int, previous: Optional[int]) -> None:
        """Remove a source that produced no epochs and re-activate the previous one."""
        store = self._ensure_store()
        store.delete_source(source_id)
        if previous is not None and any(s["id"] == previous for s in store.sources()):
            store.set_active_source(previous)
        self.activator.invalidate()
        self._sidecar_changed()

    def _after_import(self, source_id: int, summary: str) -> None:
        store = self._ensure_store()
        self.activator.invalidate()
        self.activator.ensure_base()
        try:
            self._record_fingerprint()
        except Exception:
            log.debug("fingerprint not recorded")
        duplicate = store.duplicate_of(source_id)
        if duplicate is not None:
            if ida_kernwin.ask_yn(
                1, "DejaDump: this import is identical to existing source %d.\n\n"
                   "Discard the new copy and keep using source %d?" % (duplicate, duplicate)
            ) == 1:
                store.delete_source(source_id)
                store.set_active_source(duplicate)
                self.activator.invalidate()
                summary += "\n\nIdentical to source %d — kept that one instead." % duplicate
        self._history, self._history_index = [0], 0
        self._sidecar_changed()
        ida_kernwin.info(summary)
        self.open_panel()

    def import_trace(self) -> None:
        path = ida_kernwin.ask_file(False, "*.tenet;*.txt;*.log", "DejaDump: select a Tenet/Frinet trace")
        if not path:
            return
        self._prepare_new_source()
        store = self._ensure_store()
        previous_source = store.active_source_id()
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            head = [next(fh, "") for _ in range(400)]
        arch = self._arch_for(path, head)
        slide, image_base, how = self._trace_rebase(path, head)
        keep = self._keep_intervals()
        stats = tenet.ImportStats()
        ida_kernwin.show_wait_box("DejaDump: importing %s" % os.path.basename(path))
        try:
            source_id = tenet.import_trace_file(
                path, store, arch=arch, slide=slide, image_base=image_base, keep=keep,
                progress=self._wait_progress("DejaDump: importing"), stats=stats,
                label=os.path.basename(path))
        except tenet.ImportCancelled:
            ida_kernwin.info("DejaDump: import cancelled; nothing was stored.")
            return
        finally:
            ida_kernwin.hide_wait_box()
        epochs = store.epochs(source_id)
        waves = sum(1 for e in epochs if e["boundary_kind"] == "wave")
        summary = ("DejaDump: imported %d epochs (%d waves), arch=%s.\n"
                   "Rebase: %s (addresses %s).\n%s" % (
                       len(epochs), waves, arch.name, how, _signed_hex(stats.rebase),
                       stats.summary()))
        if stats.malformed:
            summary += "\nFirst malformed line: %s" % stats.first_malformed_text[:120]
        if not epochs:
            self._discard_empty_source(source_id, previous_source)
            ida_kernwin.warning(
                summary + "\n\nNo writes landed inside the IDB's segments, so nothing was "
                "kept. Check the rebase (a manifest or Frinet .modules file next to the "
                "trace), or turn off trace filtering in Settings.")
            return
        self._after_import(source_id, summary)

    def _input_image(self) -> tuple[str, bytes]:
        path = ida_nalt.get_input_file_path() or ""
        if not os.path.exists(path):
            path = ida_kernwin.ask_file(False, "*.*", "DejaDump: original input file of this IDB")
            if not path:
                raise UserError("the original input file is needed.")
        with open(path, "rb") as fh:
            return path, fh.read()

    def import_decrypted_pair(self) -> None:
        """Import a decrypted *file-layout* image of the CURRENT module as epoch t1."""
        from .capture import rawdump

        dec = ida_kernwin.ask_file(False, "*.so;*.bin;*.*",
                                   "DejaDump: decrypted image of THIS module (file layout)")
        if not dec:
            return
        self._prepare_new_source()
        store = self._ensure_store()
        previous_source = store.active_source_id()
        _enc_path, enc = self._input_image()
        with open(dec, "rb") as fh:
            dmp = fh.read()
        if enc[:4] == b"\x7fELF":
            ep = rawdump.import_elf_pair(store, enc, dmp, label=os.path.basename(dec))
        else:
            ep = rawdump.import_image_pair(store, enc, dmp, base=self._imagebase(),
                                           label=os.path.basename(dec))
        source_id = store.active_source_id()
        if not ep.ranges:
            self._discard_empty_source(source_id, previous_source)
            ida_kernwin.info("DejaDump: the two images are identical where mapped; "
                             "nothing was imported.")
            return
        summary = ("DejaDump: imported decrypted pair — epoch t1 has %d region(s), %s "
                   "changed." % (len(ep.ranges), fmt.size(sum(r.size for r in ep.ranges))))
        if ep.ranges:
            big = max(ep.ranges, key=lambda r: r.size)
            before = b"".join(w.old_bytes or b"" for w in ep.writes if w.addr == big.start)
            summary += "\nLargest region 0x%X (%s): %s" % (
                big.start, fmt.size(big.size), rawdump.describe_change(before, big.data))
        self._after_import(source_id, summary)

    def import_memory_dumps(self) -> None:
        """Import one or more memory-layout dumps (module base + bytes) as epochs."""
        dumps, labels = [], []
        default_base = min((s for s, _e, _p in idb_segments()), default=self._imagebase())
        while True:
            path = ida_kernwin.ask_file(
                False, "*.bin;*.dmp;*.*",
                "DejaDump: memory dump %d (raw bytes starting at a known address)" %
                (len(dumps) + 1))
            if not path:
                break
            base = ida_kernwin.ask_addr(default_base,
                                        "Address of the first byte of %s in this IDB:" %
                                        os.path.basename(path))
            if base is None:
                break
            with open(path, "rb") as fh:
                dumps.append((int(base), fh.read()))
            labels.append(os.path.basename(path))
            default_base = base
            if ida_kernwin.ask_yn(0, "Add another (later) dump as the next epoch?") != 1:
                break
        if not dumps:
            return
        self._import_dumps(dumps, labels, "memory dumps")

    def _import_dumps(self, dumps, labels, label) -> None:
        from .capture import rawdump

        self._prepare_new_source()
        store = self._ensure_store()
        segments = idb_segments()

        def reader(addr, size):
            return bytes(ida_bytes.get_bytes(addr, size) or b"")

        def is_exec(addr):
            for s, e, perm in segments:
                if s <= addr < e:
                    return bool(perm & 1)
            return None

        epochs = rawdump.import_memory_dumps(
            store, reader, dumps, mapped=[(s, e) for s, e, _p in segments], is_exec=is_exec,
            label=label, labels=labels)
        if not epochs:
            ida_kernwin.info("DejaDump: the dump(s) match the IDB bytes; nothing to import.")
            return
        summary = "DejaDump: imported %d epoch(s) from %d dump(s); %s changed." % (
            len(epochs), len(dumps), fmt.size(sum(e.bytes_changed for e in epochs)))
        self._after_import(store.active_source_id(), summary)

    # -- debugger snapshots ---------------------------------------------------------
    def capture_debugger_snapshot(self) -> None:
        """Read the program's segments from the suspended process into a pending epoch."""
        import ida_dbg
        import ida_idd

        if not ida_dbg.is_debugger_on() or ida_dbg.get_process_state() != ida_dbg.DSTATE_SUSP:
            raise UserError("suspend the debugged process first (breakpoint or pause).")
        recorded = int(self._ensure_store().get_meta("idb_imagebase") or self._imagebase()) \
            if self.has_sidecar() else self._imagebase()
        delta = self._imagebase() - recorded
        captured = []
        ida_kernwin.show_wait_box("DejaDump: reading process memory…")
        try:
            for start, end, _perm in idb_segments():
                data = ida_idd.dbg_read_memory(start, end - start)
                if data:
                    captured.append((start - delta, bytes(data)))
        finally:
            ida_kernwin.hide_wait_box()
        if not captured:
            raise UserError("no program memory could be read from the process.")
        try:
            pc = ida_dbg.get_ip_val()
        except Exception:
            pc = None
        self.snapshots.append({"segments": captured, "pc": pc, "time": time.strftime("%H:%M:%S")})
        ida_kernwin.info(
            "DejaDump: captured snapshot %d (%s from %d segment(s)%s).\n\n"
            "Snapshots become epochs once the debugger stops: use "
            "Edit → DejaDump → Import → Import debugger snapshots…" % (
                len(self.snapshots), fmt.size(sum(len(d) for _s, d in captured)),
                len(captured), (" at 0x%X" % (pc - delta)) if pc is not None else ""))

    def import_debugger_snapshots(self) -> None:
        import ida_dbg

        from .capture import rawdump
        from .core.model import Epoch, WriteRecord

        if ida_dbg.is_debugger_on():
            raise UserError("stop the debugger first: snapshots are diffed against the "
                            "static IDB bytes.")
        if not self.snapshots:
            raise UserError("no debugger snapshots were captured in this session.")
        self._prepare_new_source()
        store = self._ensure_store()
        segments = idb_segments()
        mapped = [(s, e) for s, e, _p in segments]

        def is_exec(addr):
            for s, e, perm in segments:
                if s <= addr < e:
                    return bool(perm & 1)
            return None

        def idb_reader(addr, size):
            return bytes(ida_bytes.get_bytes(addr, size) or b"")

        epochs, previous = [], {}
        for index, snap in enumerate(self.snapshots, 1):
            ranges = []
            for base, data in snap["segments"]:
                # Each segment is diffed against the previous snapshot (or the IDB).
                prior = previous.get(base)
                read = ((lambda a, n, p=prior, b=base: p[a - b:a - b + n])
                        if prior is not None else idb_reader)
                eps, _updates = rawdump.memory_dump_epochs(
                    read, [(base, data)], mapped=mapped, is_exec=is_exec)
                for ep in eps:
                    ranges.extend(ep.ranges)
                previous[base] = data
            if ranges:
                epochs.append(Epoch(
                    seq=len(epochs) + 1, ranges=ranges,
                    writes=[WriteRecord(None, r.start, r.data) for r in ranges],
                    boundary_kind="snapshot", boundary_pc=snap["pc"],
                    label="debugger snapshot %d" % index, note="captured %s" % snap["time"]))
        count = len(self.snapshots)
        self.snapshots = []
        if not epochs:
            ida_kernwin.info("DejaDump: the snapshots match the IDB bytes; nothing to import.")
            return
        # t0 bytes for the new ranges are snapshotted from the (static) IDB by
        # ensure_base() in _after_import.
        source_id = store.import_source("debugger", "debugger snapshots", epochs,
                                        params={"snapshots": count})
        self._after_import(source_id, "DejaDump: imported %d debugger snapshot epoch(s)." %
                           len(epochs))

    # -- search, summary, export -----------------------------------------------------
    def search_epochs(self) -> None:
        from .core.search import parse_needle, search_epochs
        from .ui.choosers import SearchResults

        self._require_store()
        text = ida_kernwin.ask_str("", 0, "Search every epoch for (hex bytes, or \"text\"):")
        if not text:
            return
        needle = parse_needle(text)
        resolver = self.resolver()
        ida_kernwin.show_wait_box("DejaDump: searching %d epoch(s)…" %
                                  (resolver.max_epoch() + 1))
        try:
            hits = search_epochs(resolver, needle)
        finally:
            ida_kernwin.hide_wait_box()
        if not hits:
            ida_kernwin.info("DejaDump: %r was not found in any epoch's volatile bytes." % text)
            return
        chooser = SearchResults(self, text, hits, resolver, len(needle))
        self.choosers.append(chooser)
        chooser.Show()

    def wave_summary(self, k: Optional[int] = None) -> None:
        from .ui.choosers import WaveSummary

        self._require_store()
        if k is None:
            k = self.choose_epoch("Summarise the changes of epoch",
                                  max(1, self.active_epoch()), include_t0=False)
        if k is None:
            return
        rows = self.wave_rows(int(k))
        chooser = WaveSummary(self, int(k), rows)
        self.choosers.append(chooser)
        chooser.Show()

    def wave_rows(self, k: int) -> list[dict]:
        """What epoch ``k`` changed relative to ``k-1``: ranges, functions, strings."""
        from .core.search import strings_revealed

        store = self._ensure_store()
        resolver = self.resolver()
        spans = resolver.changed_spans(k)
        changed = IntervalIndex(spans)
        rows = []
        for start, end in store.epoch_ranges(k):
            exec_hint = any(s <= start < e and perm & 1 for s, e, perm in idb_segments())
            rows.append({"kind": "range", "addr": start, "epoch": k,
                         "detail": "%s %s" % (fmt.size(end - start),
                                              "code segment" if exec_hint else "data")})

        def funcs_of(seq):
            if seq == self.active_epoch():
                out = {}
                if not spans:
                    return out
                lowest = min(s for s, _ in spans)
                f = ida_funcs.get_func(lowest) or ida_funcs.get_next_func(lowest)
                limit = max(e for _, e in spans)
                while f is not None and f.start_ea < limit:
                    out[int(f.start_ea)] = int(f.end_ea)
                    f = ida_funcs.get_next_func(f.start_ea)
                return out
            payloads = store.annots_for_epoch(store.epoch_ref(seq))
            if not payloads:
                return None
            return {int(start) + int(f["off"]): int(start) + int(f["end"])
                    for start, payload in payloads.items() for f in payload.get("funcs", [])}

        now, before = funcs_of(k), funcs_of(k - 1)
        if now is None or before is None:
            missing = ", ".join("t%d" % seq for seq, v in ((k - 1, before), (k, now)) if v is None)
            rows.append({"kind": "note", "addr": None, "epoch": k,
                         "detail": "visit %s once to list function changes" % missing})
        else:
            for ea in sorted(set(now) | set(before)):
                end = now.get(ea, before.get(ea))
                if not changed.overlaps(ea, end):
                    continue
                kind = ("function +" if ea not in before else
                        "function −" if ea not in now else "function ~")
                name = ida_funcs.get_func_name(ea) or "sub_%X" % ea
                rows.append({"kind": kind, "addr": ea, "epoch": k if ea in now else k - 1,
                             "detail": "%s (%s)" % (name, fmt.size(end - ea))})
        for item in strings_revealed(resolver, k, spans):
            rows.append({"kind": "string", "addr": item["addr"], "epoch": k,
                         "detail": item["text"][:120]})
        return rows

    def export_epoch(self) -> None:
        from .capture import rawdump

        store = self._require_store()
        k = self.choose_epoch("Export epoch as file", max(1, self.active_epoch()))
        if k is None:
            return
        source_path, original = self._input_image()
        stem, ext = os.path.splitext(os.path.basename(source_path))
        suggested = os.path.join(os.path.dirname(source_path), "%s.t%d%s" % (stem, k, ext))
        out = ida_kernwin.ask_file(True, suggested, "DejaDump: save t%d as" % k)
        if not out:
            return
        resolver = self.resolver()
        data = rawdump.export_image(original, lambda a, n: resolver.state(k, a, n),
                                    store.volatile_set(), base=self._imagebase())
        with open(out, "wb") as fh:
            fh.write(data)
        ida_kernwin.info("DejaDump: wrote t%d to %s (%s)." % (k, out, fmt.size(len(data))))

    # -- settings & status ----------------------------------------------------------
    def open_settings(self) -> None:
        from .ui.settings import edit_settings

        if edit_settings():
            set_debug(settings.get_bool("debug"))
            if self.ghost_pool is not None:
                self.ghost_pool.close()
                self.ghost_pool = None
                self._ghost_key = None
            ida_kernwin.refresh_idaview_anyway()

    def status_text(self) -> str:
        from . import __version__

        lines = ["DejaDump %s" % __version__,
                 "IDA %d.%d · Hex-Rays: %s · idalib worker: %s" % (
                     *ida_compat.ida_version(), ida_compat.has_hexrays(),
                     settings.get("idalib_python") or "not configured")]
        if self.has_sidecar():
            store = self._ensure_store()
            lines.append("Sidecar: %s" % store.path)
            lines.append("Active source: %s · active epoch: t%d of t%d" % (
                store.active_source_id(), store.active_epoch(), self.max_epoch()))
            if self.activator is not None and self.activator.disabled_reason:
                lines.append("Switching disabled: %s" % self.activator.disabled_reason)
        else:
            lines.append("No sidecar yet (nothing imported for this IDB).")
        if self.snapshots:
            lines.append("Pending debugger snapshots: %d" % len(self.snapshots))
        lines.append("Documentation: %s" % GUIDE_URL)
        return "\n".join(lines)
