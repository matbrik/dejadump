"""Pinned epochs in sparse shadow segments (IDA-only).

The implementation deliberately avoids heuristic pointer rewriting.  AArch64 and
x86-64 PC-relative code is useful as-is; unsupported absolute references remain
visible in ghost/canonical views rather than being silently corrupted.
"""

from __future__ import annotations

import ida_auto
import ida_bytes
import ida_ida
import ida_idaapi
import ida_name
import ida_segment
import ida_xref

from ..core import annotations
from ..core.annotation_model import merge_payloads
from ..core.intervals import IntervalIndex
from ..core.state import StateResolver
from ..util.fmt import SHADOW_PREFIX

_BASE = 0x100000000000
_STRIDE = 0x100000000


def _finish_analysis() -> None:
    """Drain the analysis a pin/unpin queued, so epoch switching is not blocked."""
    try:
        if not ida_auto.auto_is_ok():
            ida_auto.auto_wait()
    except Exception:
        pass


class Pinner:
    def __init__(self, store):
        self.store = store

    def _resolver(self):
        return StateResolver(self.store.load_epochs(), self.store.base_source())

    def supported(self) -> bool:
        proc = ida_ida.inf_get_procname().lower()
        return ida_ida.inf_is_64bit() and proc in ("arm", "metapc")

    def canonical_to_shadow(self, seq: int, ea: int) -> int | None:
        pin = self.store.get_pin(self.store.epoch_ref(seq))
        if not pin:
            return None
        for segment in pin["segments"]:
            if segment["canonical_start"] <= ea < segment["canonical_end"]:
                return segment["shadow_start"] + ea - segment["canonical_start"]
        return None

    def shadow_to_canonical(self, seq: int, ea: int) -> int | None:
        pin = self.store.get_pin(self.store.epoch_ref(seq))
        if not pin:
            return None
        for segment in pin["segments"]:
            if segment["shadow_start"] <= ea < segment["shadow_end"]:
                return segment["canonical_start"] + ea - segment["shadow_start"]
        return None

    @staticmethod
    def _mapped(ea: int) -> bool:
        try:
            return ida_segment.getseg(ea) is not None
        except Exception:
            return False

    def _stitch_xrefs(self, segments: list[dict], delta: int) -> list[dict]:
        """Link shifted references back to stable canonical imports/functions.

        PC-relative references internal to a shadow segment remain correct after
        relocation.  A reference that lands at ``canonical+delta`` while the
        canonical target is stable gets an explicit user xref to that canonical
        target.  No bytes or pointer-looking QWORDs are rewritten.
        """
        volatile = self.store.volatile_set()
        owned, seen = [], set()
        volatile_index = IntervalIndex(volatile)
        is_volatile = volatile_index.contains
        for segment in segments:
            ea = segment["shadow_start"]
            while ea < segment["shadow_end"]:
                for kind, first, next_ref, add, xref_type in (
                    ("code", ida_xref.get_first_cref_from, ida_xref.get_next_cref_from,
                     ida_xref.add_cref, ida_xref.fl_CN),
                    ("data", ida_xref.get_first_dref_from, ida_xref.get_next_dref_from,
                     ida_xref.add_dref, ida_xref.dr_O),
                ):
                    target = first(ea)
                    while target != ida_idaapi.BADADDR:
                        canonical = target - delta
                        key = (ea, canonical, kind)
                        if (key not in seen and not is_volatile(canonical)
                                and self._mapped(canonical)):
                            add(ea, canonical, xref_type | ida_xref.XREF_USER)
                            owned.append({"src": ea, "dst": canonical, "kind": kind})
                            seen.add(key)
                        target = next_ref(ea, target)
                nxt = ida_bytes.next_head(ea, segment["shadow_end"])
                ea = nxt if nxt != ida_idaapi.BADADDR and nxt > ea else ea + 1
        return owned

    @staticmethod
    def _add_shadow_segment(canonical: int, start: int, end: int, name: str) -> bool:
        """Create a *sparse* segment mirroring the canonical segment's bitness/perms.

        Sparse storage keeps a pinned multi-megabyte epoch from allocating flags
        for every byte of the shadow address range up front.
        """
        seg = ida_segment.segment_t()
        seg.start_ea, seg.end_ea = start, end
        source = ida_segment.getseg(canonical)
        seg.bitness = source.bitness if source is not None else (2 if ida_ida.inf_is_64bit() else 1)
        seg.perm = source.perm if source is not None else (
            ida_segment.SEGPERM_READ | ida_segment.SEGPERM_EXEC)
        seg.align = ida_segment.saRelByte
        seg.comb = ida_segment.scPub
        seg.sel = ida_segment.setup_selector(0)
        flags = getattr(ida_segment, "ADDSEG_SPARSE", 0) | getattr(ida_segment, "ADDSEG_NOSREG", 0)
        sclass = "CODE" if seg.perm & ida_segment.SEGPERM_EXEC else "DATA"
        return bool(ida_segment.add_segm_ex(seg, name, sclass, flags))

    def pin(self, seq: int) -> list[dict]:
        if seq <= 0:
            raise ValueError("pin an observed epoch (t1 or later), not t0")
        if not self.supported():
            raise RuntimeError("pinning currently supports AArch64 and x86-64")
        ref = self.store.epoch_ref(seq)
        existing = self.store.get_pin(ref)
        if existing:
            return existing["segments"]
        delta = _BASE + seq * _STRIDE
        resolver = self._resolver()
        code_ranges = resolver.code_ranges_at(seq)
        segments = []
        try:
            for index, (start, end) in enumerate(self.store.volatile_set()):
                ss, se = start + delta, end + delta
                name = "%st%d.%d" % (SHADOW_PREFIX, seq, index)
                if not self._add_shadow_segment(start, ss, se, name):
                    raise RuntimeError("could not create shadow segment %s" % name)
                data = resolver.state(seq, start, end - start)
                ida_bytes.put_bytes(ss, data)
                if bytes(ida_bytes.get_bytes(ss, len(data)) or b"") != data:
                    raise RuntimeError("could not populate shadow segment %s" % name)
                segments.append({"canonical_start": start, "canonical_end": end,
                                 "shadow_start": ss, "shadow_end": se, "name": name,
                                 "owned_names": []})
            for start, end, entries in code_ranges:
                ss, se = start + delta, end + delta
                ida_auto.auto_mark_range(ss, se, ida_auto.AU_CODE)
                for pc in entries:
                    ida_auto.auto_make_proc(pc + delta)
                    original = ida_name.get_name(pc) or "sub_%X" % pc
                    shadow_name = "t%d_%s" % (seq, original)
                    ida_name.set_name(pc + delta, shadow_name,
                                      ida_name.SN_FORCE | ida_name.SN_NOCHECK)
                    for segment in segments:
                        if segment["shadow_start"] <= pc + delta < segment["shadow_end"]:
                            segment["owned_names"].append(
                                {"ea": pc + delta, "name": shadow_name})
                            break
                if hasattr(ida_auto, "auto_wait_range"):
                    ida_auto.auto_wait_range(ss, se)
            # Show the epoch's own annotations in the shadow copy (offsets are
            # range-relative, so the canonical payload applies at the shadow start).
            for segment in segments:
                payload = self.store.get_annot(ref, segment["canonical_start"])
                if payload:
                    annotations.restore(segment["shadow_start"], payload)
            owned = self._stitch_xrefs(segments, delta)
            for segment in segments:
                segment["owned_xrefs"] = [x for x in owned
                                           if segment["shadow_start"] <= x["src"] <
                                           segment["shadow_end"]]
        except Exception:
            for segment in reversed(segments):
                ida_segment.del_segm(segment["shadow_start"], ida_segment.SEGMOD_KILL)
            raise
        self.store.set_pin(ref, delta, _STRIDE, segments)
        _finish_analysis()
        return segments

    def unpin(self, seq: int) -> None:
        ref = self.store.epoch_ref(seq)
        pin = self.store.get_pin(ref)
        if not pin:
            return
        for segment in pin["segments"]:
            ss, se = segment["shadow_start"], segment["shadow_end"]
            payload = annotations.capture(ss, se)
            owned_names = {(row["ea"] - ss, row["name"])
                           for row in segment.get("owned_names", [])}
            payload["names"] = [
                row for row in payload.get("names", [])
                if (row["off"], row["name"]) not in owned_names
            ]
            # Offsets are relative, so the same payload is valid at canonical start.
            # Merge rather than replace: the shadow copy may not hold every
            # annotation the epoch has (e.g. ones made before pinning).
            stored = self.store.get_annot(ref, segment["canonical_start"])
            self.store.set_annot(ref, segment["canonical_start"],
                                 merge_payloads(stored, payload))
            ida_segment.del_segm(ss, ida_segment.SEGMOD_KILL)
        self.store.remove_pin(ref)
        _finish_analysis()

    def pointer_rebase_preview(self, seq: int) -> list[dict]:
        """Return typed canonical pointers that can be safely shifted in a pin."""
        import ida_typeinf

        ref = self.store.epoch_ref(seq)
        pin = self.store.get_pin(ref)
        if not pin:
            raise ValueError("epoch t%d is not pinned" % seq)
        volatile = self.store.volatile_set()
        rows = []
        for segment in pin["segments"]:
            canonical = segment["canonical_start"]
            while canonical < segment["canonical_end"]:
                size = max(1, ida_bytes.get_item_size(canonical))
                tif = ida_typeinf.tinfo_t()
                typed_pointer = False
                try:
                    typed_pointer = bool(ida_typeinf.get_tinfo(tif, canonical) and tif.is_ptr())
                except Exception:
                    pass
                if typed_pointer and size == 8:
                    shadow = segment["shadow_start"] + canonical - segment["canonical_start"]
                    old = ida_bytes.get_qword(shadow)
                    if any(start <= old < end for start, end in volatile):
                        target = self.canonical_to_shadow(seq, old)
                        if target is not None:
                            rows.append({"canonical": canonical, "shadow": shadow,
                                         "old": old, "new": target})
                next_ea = ida_bytes.next_head(canonical, segment["canonical_end"])
                if next_ea == ida_idaapi.BADADDR or next_ea <= canonical:
                    break
                canonical = next_ea
        return rows

    def apply_pointer_rebases(self, seq: int, rows: list[dict]) -> int:
        ref = self.store.epoch_ref(seq)
        pin = self.store.get_pin(ref)
        if not pin:
            raise ValueError("epoch t%d is not pinned" % seq)
        count = 0
        for row in rows:
            ida_bytes.put_qword(int(row["shadow"]), int(row["new"]))
            if ida_bytes.get_qword(int(row["shadow"])) != int(row["new"]):
                raise RuntimeError("pointer rebase failed at %#x" % row["shadow"])
            count += 1
        for segment in pin["segments"]:
            segment["rebases"] = [row for row in rows
                                   if segment["shadow_start"] <= row["shadow"] <
                                   segment["shadow_end"]]
        self.store.set_pin(ref, pin["shadow_base"], pin["stride"], pin["segments"])
        return count
