"""Mode A — the time-slider that swaps one epoch into the canonical address space.

``activate(k)`` turns the currently-loaded bytes into epoch *k* and re-runs IDA's
own analysis over only what changed, so xrefs into stable code stay correct and
Hex-Rays pseudocode is native:

    guard (no debugger / auto) → snapshot t0 base for uncovered ranges → verify
    the loaded bytes are the recorded epoch → persist the current epoch's edited
    annotations → diff current↔target over the volatile set → del_items + put_bytes
    → set ARM 'T' then auto_mark_range(AU_CODE) over *code* ranges + auto_wait →
    annotation *delta* (remove outgoing-only, apply target) → mark_cfunc_dirty for
    touched funcs → refresh.

Key API choices (verified): ``put_bytes`` (no patch record, unlike ``patch_bytes``);
set the ARM/Thumb ``T`` sreg *before* ``AU_CODE`` (changing T wipes instructions);
``ida_undo.create_undo_point`` takes an opaque bytes body, so the real, deterministic
inverse is ``Revert to t0`` / re-``activate``.  Every IDA write is best-effort.

IDA-only; the planning is done by the headless :class:`StateResolver`.
"""

from __future__ import annotations

import time
from collections import OrderedDict

import ida_auto
import ida_bytes
import ida_dbg
import ida_funcs
import ida_idaapi
import ida_kernwin
import idc

from ..core import annotations
from ..core.intervals import IntervalIndex
from ..core.model import Epoch, Range
from ..core.index import open_index
from ..core.state import StateResolver
from ..util import ida_compat
from ..util.fmt import owned_line
from ..util.logging import get_logger


def _next_func_from(ea: int):
    """First function starting at or after ``ea`` (``get_next_func`` is exclusive)."""
    f = ida_funcs.get_func(ea)
    if f is not None and f.start_ea == ea:
        return f
    return ida_funcs.get_next_func(ea)


def _item_changed(changed: IntervalIndex, ea: int) -> bool:
    """Whether the item starting at ``ea`` has any byte in a changed span.

    An annotation sits on an item's first byte, but a rewrite may only touch a
    later byte (an x86 immediate): the item still changed.
    """
    return changed.overlaps(ea, ea + max(1, ida_bytes.get_item_size(ea)))


def _first_unmapped(changes):
    """First address in ``(addr, data)`` changes that no segment covers, else None."""
    import ida_segment

    for addr, data in changes:
        ea, end = addr, addr + len(data)
        while ea < end:
            seg = ida_segment.getseg(ea)
            if seg is None:
                return ea
            ea = seg.end_ea
    return None


def _merge_code_ranges(items):
    """Sort and merge ``(start, end, entries)`` code items, joining their entries."""
    merged = []
    for start, end, entries in sorted((int(s), int(e), tuple(en)) for s, e, en in items):
        if merged and start <= merged[-1][1]:
            s0, e0, en0 = merged[-1]
            merged[-1] = (s0, max(e0, end), tuple(dict.fromkeys(en0 + entries)))
        else:
            merged.append((start, end, entries))
    return merged


class Activator:
    # Marking every byte in a multi-megabyte executable PT_LOAD as AU_CODE makes
    # processor modules decode literal pools/data and can recurse indefinitely.
    # Large islands are seeded from known entries/functions instead; IDA follows
    # their reachable control flow normally.
    BULK_CODE_LIMIT = 0x40000

    def __init__(self, store, index=None, tracker=None):
        self.store = store
        self.index = index or open_index()
        #: Optional :class:`~dejadump.modes.tracking.AnnotationTracker`; without
        #: it every switch captures the whole volatile set (the safe default).
        self.tracker = tracker
        self.log = get_logger("mode_a")
        self.last_timings: dict[str, float | int | bool] = {}
        self.disabled_reason = None
        self.hard_disabled = False
        self._reconciled = False
        self._resolver_cache = None
        self._resolver_hash = None
        self._plan_cache = OrderedDict()
        self.fault_injector = None  # integration tests: callable(stage) may raise

    def _fault(self, stage: str) -> None:
        if self.fault_injector is not None:
            self.fault_injector(stage)

    # -- helpers ------------------------------------------------------------
    def _resolver(self) -> StateResolver:
        digest = (self.store.content_hash(), self.store.generation,
                  len(self.store.base_coverage()))
        if self._resolver_cache is None or digest != self._resolver_hash:
            self._resolver_cache = StateResolver(
                self.store.load_epochs(), base=self.store.base_source())
            self._resolver_hash = digest
        return self._resolver_cache

    def invalidate(self) -> None:
        """Forget derived state after the sidecar or the IDB changed underneath."""
        self._resolver_cache = None
        self._resolver_hash = None
        self._plan_cache.clear()
        self._reconciled = False

    def _suspended(self):
        if self.tracker is not None:
            return self.tracker.suspended()
        import contextlib

        return contextlib.nullcontext()

    def _old_reader(self, addr: int, size: int) -> bytes:
        b = ida_bytes.get_bytes(addr, size)
        return bytes(b) if b is not None else b"\x00" * size

    def ensure_base(self) -> None:
        """Snapshot the t0 bytes of every volatile range that has none yet.

        Called right after an import, while the IDB holds t0 (the controller
        reverts the current source first).  A later source can cover addresses
        the first one did not; those get their own snapshot instead of reading
        as zeros.
        """
        gaps = self.store.base_gaps()
        known = self.store.get_meta("base_code_ranges") is not None
        if not gaps and known:
            return
        targets = gaps if known else self.store.volatile_set()
        for s, e in gaps:
            self.store.set_base_range(s, self._old_reader(s, e - s))
        # New items are collected on their own (the adjacency merge below only
        # looks at the previous *new* item), then merged with the known ones.
        code_items: list = []
        for s, e in targets:
            ea = ida_bytes.get_item_head(s)
            if ea < s:
                ea = ida_bytes.next_head(ea, e)
            while ea != ida_idaapi.BADADDR and ea < e:
                size = max(1, ida_bytes.get_item_size(ea))
                if ida_bytes.is_code(ida_bytes.get_flags(ea)):
                    f = ida_funcs.get_func(ea)
                    entries = (f.start_ea,) if f and f.start_ea == ea else ()
                    if code_items and ea <= code_items[-1][1] and not entries:
                        code_items[-1] = (code_items[-1][0], max(code_items[-1][1], ea + size),
                                          code_items[-1][2])
                    else:
                        code_items.append((ea, min(e, ea + size), entries))
                ea = ida_bytes.next_head(ea, e)
        existing = list(self.store.base_code_ranges()) if known else []
        self.store.set_base_code_ranges(_merge_code_ranges(existing + code_items))

    def _blocked_reason(self):
        if ida_dbg.is_debugger_on():
            return "the debugger is running"
        try:
            if ida_auto.get_auto_state() != ida_auto.AU_NONE:
                return "auto-analysis is still running"
        except Exception:
            self.log.debug("auto-analysis state unavailable")
        try:
            if ida_auto.is_auto_enabled() and not ida_auto.auto_is_ok():
                return "auto-analysis queues are not empty"
        except Exception:
            self.log.debug("auto-analysis queue state unavailable")
        return None

    def _has_user_patches(self) -> bool:
        """True if the user has patched bytes in the volatile set.

        DejaDump swaps with ``put_bytes`` (no patch records), so any patch here
        is the user's and would be silently lost on a swap — refuse instead.
        """
        found = {"hit": False}

        def _cb(ea, fpos, org, patch):  # noqa: ARG001
            found["hit"] = True
            return 1  # stop at the first one

        try:
            for s, e in self.store.volatile_set():
                ida_bytes.visit_patched_bytes(s, e, _cb)
                if found["hit"]:
                    return True
        except Exception:
            self.log.debug("patch scan skipped")
        return False

    def _capture_current(self, cur: int) -> None:
        """Persist the active epoch's annotations.

        With a tracker, only the page windows the analyst edited since the last
        capture are re-read and merged into the stored payload.
        """
        volatile = self.store.volatile_set()
        for s, e in volatile:
            stored = self.store.get_annot(cur, s)
            if self.tracker is None or stored is None:
                self.store.set_annot(cur, s, annotations.capture(s, e))
                continue
            payload = stored
            for lo, hi in self.tracker.windows(s, e):
                window = annotations.capture(lo, hi, origin=s)
                payload = annotations.replace_window(payload, lo - s, hi - s, window)
            if payload is not stored:
                self.store.set_annot(cur, s, payload)
        if self.tracker is not None:
            self.tracker.clear(volatile)

    def flush_annotations(self) -> None:
        """Save pending annotation edits of the active epoch (on save / close)."""
        if self.store.epochs() and self.disabled_reason is None:
            with self._suspended():
                self._capture_current(self.store.active_epoch())

    @staticmethod
    def _ask_capture_unknown_epoch() -> bool:
        message = (
            "DejaDump: the current IDB bytes differ from the on-disk/base image "
            "and do not match any stored epoch.\n\n"
            "Add the current IDB changes as a new epoch?\n\n"
            "Choose No to leave epoch switching disabled."
        )
        try:
            return ida_kernwin.ask_yn(ida_kernwin.ASKBTN_NO, message) == ida_kernwin.ASKBTN_YES
        except Exception:
            return False

    @staticmethod
    def _range_is_executable(start: int) -> bool | None:
        try:
            import ida_segment

            seg = ida_segment.getseg(start)
            return None if seg is None else bool(seg.perm & ida_segment.SEGPERM_EXEC)
        except Exception:
            return None

    def _commit_captured_patches(self) -> None:
        """Turn accepted IDA patch records into ordinary IDB bytes.

        The bytes are already stored in the new epoch. Clearing their patch
        metadata prevents the normal user-patch safety check from immediately
        refusing the next switch.
        """
        patched = []

        def _cb(ea, fpos, org, patch):  # noqa: ARG001
            patched.append((int(ea), int(patch) & 0xFF))
            return 0

        for start, end in self.store.volatile_set():
            try:
                ida_bytes.visit_patched_bytes(start, end, _cb)
            except Exception:
                self.log.debug("could not enumerate captured patches in [%#x, %#x)",
                               start, end)
        for ea, value in patched:
            try:
                ida_bytes.revert_byte(ea)
                ida_bytes.put_byte(ea, value)
            except Exception:
                self.log.warning("could not commit captured patch at %#x", ea)

    def _capture_unknown_epoch(self, resolver: StateResolver, pending=None) -> bool:
        """Append the loaded IDB state as a manual epoch of the active source."""
        previous = max((row["seq"] for row in self.store.epochs()), default=0)
        seq = previous + 1
        ranges = []
        changed_bytes = 0
        for start, end in resolver.volatile_set():
            size = end - start
            before = resolver.state(previous, start, size)
            current = self._old_reader(start, size)
            for offset, data in StateResolver.coalesced_diff_spans(before, current):
                ea = start + offset
                ranges.append(Range(ea, data, is_code_hint=self._range_is_executable(ea)))
                changed_bytes += len(data)
        if not ranges:
            ida_kernwin.warning(
                "DejaDump: no readable byte differences were found to capture.\n"
                "Epoch switching remains disabled."
            )
            return False

        self.store.append_epoch(Epoch(
            seq=seq,
            ranges=ranges,
            boundary_kind="manual",
            label="IDB changes",
            note="Captured from IDB after loaded bytes did not match a stored epoch.",
        ))
        self._commit_captured_patches()
        self._resolver_cache = None
        self._resolver_hash = None
        self._plan_cache.clear()
        self.store.set_active_epoch(seq)
        if pending:
            self.store.finish_activation(pending["id"], "captured_idb_epoch")
        try:
            self.index.set("active_epoch", seq)
            self.index.set("content_hash", self.store.content_hash())
        except Exception:
            pass
        self._capture_current(seq)
        self.log.warning(
            "captured mixed IDB state as t%d (%d ranges, %d bytes)",
            seq, len(ranges), changed_bytes,
        )
        ida_kernwin.info(
            "DejaDump: added the current IDB changes as epoch t%d "
            "(%d ranges, %d bytes)." % (seq, len(ranges), changed_bytes)
        )
        return True

    def reconcile(self) -> bool:
        """Reconcile sidecar metadata with bytes actually loaded in the IDB."""
        if self._reconciled:
            return self.disabled_reason is None
        self._reconciled = True
        if not self.store.has_base() or not self.store.epochs():
            return True
        resolver = self._resolver()
        pending = self.store.pending_activation()
        actual = resolver.identify_state(self._old_reader)
        # Two epochs can legitimately have identical complete state (for
        # example a later wave restores old bytes). In that case retain the
        # metadata only if it independently matches the loaded bytes.
        if actual is None:
            recorded = self.store.active_epoch()
            preferred = recorded
            if pending and pending["payload"].get("stage") in {
                "bytes_applied", "analysis_complete", "annotations_restored"
            }:
                preferred = pending["target_seq"]
            actual = resolver.identify_state(self._old_reader, [preferred])
        if actual is None:
            if self._ask_capture_unknown_epoch() and self._capture_unknown_epoch(resolver, pending):
                self.disabled_reason = None
                return True
            self.disabled_reason = "loaded bytes are a mixed or unknown epoch"
            return False
        if actual != self.store.active_epoch():
            self.log.warning("reconciled active epoch metadata: t%d -> t%d",
                             self.store.active_epoch(), actual)
            self.store.set_active_epoch(actual)
        if pending:
            # A process may have stopped after writing bytes but before restoring
            # annotations/committing metadata.  The byte state is authoritative;
            # finish the matching side of the transaction deterministically.
            with self._suspended():
                for start, payload in self.store.annots_for_epoch(actual).items():
                    annotations.restore(start, payload)
                for start, payload in self.store.shared_annots().items():
                    annotations.restore(start, payload)
            self.store.set_active_epoch(actual)
            if actual == pending["target_seq"]:
                status = "recovered_target"
            elif actual == pending["source_seq"]:
                status = "recovered_source"
            else:
                status = "reconciled_other"
            self.store.finish_activation(pending["id"], status)
            self._decorate_volatile(actual)
            ida_kernwin.refresh_idaview_anyway()
        return True

    def _prepare_arm_thumb(self, start: int, end: int) -> None:
        # Only 32-bit ARM/Thumb needs the 'T' sreg set before AU_CODE; arm64 does not.
        try:
            import ida_ida
            import ida_idp
            import ida_segregs

            if ida_ida.inf_get_procname().upper() != "ARM" or ida_ida.inf_is_64bit():
                return
            treg = ida_idp.str2reg("T")
            if treg < 0:
                return
            # Pin the current T value as a range boundary at ``start`` so the
            # AU_CODE pass decodes with it.  (Choosing ARM vs Thumb for new code
            # is left to the processor module; 32-bit ARM is not a primary target.)
            val = ida_segregs.get_sreg(start, treg)
            if val in (-1, ida_idaapi.BADADDR, getattr(ida_segregs, "BADSEL", -1)):
                val = 0
            ida_segregs.split_sreg_range(start, treg, val, ida_segregs.SR_user)
        except Exception:
            self.log.debug("ARM/Thumb T preparation skipped for %#x", start)

    def _executable_fallback_ranges(self, chunks) -> list[tuple[int, int, tuple[int, ...]]]:
        """Classify legacy dump ranges using the IDB segment execute permission."""
        try:
            import ida_segment
            ranges = []
            for chunk in chunks:
                seg = ida_segment.getseg(chunk.start)
                if seg is not None and (seg.perm & ida_segment.SEGPERM_EXEC):
                    if ranges and chunk.start <= ranges[-1][1]:
                        ranges[-1] = (ranges[-1][0], max(ranges[-1][1], chunk.end), ())
                    else:
                        ranges.append((chunk.start, chunk.end, ()))
            return ranges
        except Exception:
            return []

    def _functions_intersecting(self, changes) -> set[int]:
        found = set()
        for start, data in changes:
            end = start + len(data)
            f = ida_funcs.get_func(start)
            if f and f.end_ea > start:
                found.add(f.start_ea)
            f = _next_func_from(start)
            while f and f.start_ea < end:
                if f.end_ea > start:
                    found.add(f.start_ea)
                f = ida_funcs.get_next_func(f.start_ea)
        return found

    def _expand_analysis_ranges(self, ranges):
        """Expand changed code islands to existing IDA items/functions and merge."""
        expanded = []
        for start, end, entries in ranges:
            lo, hi = start, end
            head = ida_bytes.get_item_head(start)
            if head != ida_idaapi.BADADDR:
                lo = min(lo, head)
            tail = ida_bytes.get_item_end(max(start, end - 1))
            if tail != ida_idaapi.BADADDR:
                hi = max(hi, tail)
            funcs = []
            f = ida_funcs.get_func(start)
            if f:
                funcs.append(f)
            f = _next_func_from(start)
            while f and f.start_ea < end:
                funcs.append(f)
                f = ida_funcs.get_next_func(f.start_ea)
            for f in funcs:
                if f.end_ea > start:
                    lo, hi = min(lo, f.start_ea), max(hi, f.end_ea)
            expanded.append((lo, hi, tuple(entries)))
        merged = []
        for start, end, entries in sorted(expanded):
            if merged and start <= merged[-1][1]:
                old_start, old_end, old_entries = merged[-1]
                merged[-1] = (old_start, max(old_end, end),
                              tuple(dict.fromkeys(old_entries + entries)))
            else:
                merged.append((start, end, entries))
        return merged

    @staticmethod
    def _stable_entrypoints(start: int, end: int) -> set[int]:
        try:
            import ida_entry

            out = set()
            for index in range(ida_entry.get_entry_qty()):
                ordinal = ida_entry.get_entry_ordinal(index)
                ea = int(ida_entry.get_entry(ordinal))
                if start <= ea < end:
                    out.add(ea)
            return out
        except Exception:
            return set()

    def _annotation_function_seeds(self, epoch: int, start: int, end: int) -> set[int]:
        seeds = set()
        for range_start, payload in self.store.annots_for_epoch(epoch).items():
            for function in payload.get("funcs", []):
                ea = int(range_start) + int(function.get("off", 0))
                if start <= ea < end:
                    seeds.add(ea)
        return seeds

    def _drain_auto_queue(self) -> bool:
        """Finish analysis the switch queued *outside* its own ranges.

        A switch only starts with empty queues (see ``_blocked_reason``), so
        anything pending now was caused by it; leaving it would block the next
        switch until IDA got around to it.  Returns False if the user cancelled.
        """
        try:
            if ida_auto.auto_is_ok():
                return True
            return bool(ida_auto.auto_wait())
        except Exception:
            self.log.debug("could not drain auto-analysis queues")
            return True

    def _analyse_ranges(self, ranges, function_seeds=(), target_epoch=None) -> bool:
        """Analyze changed code without force-decoding large executable segments."""
        seeds = set(int(ea) for ea in function_seeds)
        for s, e, entries in ranges:
            self._prepare_arm_thumb(s, e)
            small = e - s <= self.BULK_CODE_LIMIT
            if small:
                local_seeds = set(int(pc) for pc in entries)
                local_seeds.update(ea for ea in seeds if s <= ea < e)
                ida_auto.auto_mark_range(s, e, ida_auto.AU_CODE)
            else:
                # Legacy dump sidecars used changed-range starts as entries.
                # Never trust those for a large PT_LOAD; use loader exports and
                # functions explicitly saved for the target epoch.
                local_seeds = self._stable_entrypoints(s, e)
                if target_epoch is not None:
                    local_seeds.update(
                        self._annotation_function_seeds(target_epoch, s, e))
            for pc in sorted(local_seeds):
                ida_auto.auto_make_proc(pc)
            if hasattr(ida_auto, "auto_wait_range"):
                if ida_auto.auto_wait_range(s, e) < 0:
                    return False
            elif not ida_auto.auto_wait():
                return False
        return True

    def _invalidate_decompiler(self, changes, previous_funcs=(), prototype_before=None) -> None:
        if not ida_compat.has_hexrays():
            return
        try:
            import ida_hexrays
            import ida_xref

            seen = set(previous_funcs) | self._functions_intersecting(changes)
            prototype_before = prototype_before or {}
            changed_prototypes = {
                ea for ea in seen if prototype_before.get(ea) != (idc.get_type(ea) or "")
            }
            for ea in changed_prototypes:
                caller = ida_xref.get_first_cref_to(ea)
                while caller != ida_idaapi.BADADDR:
                    f = ida_funcs.get_func(caller)
                    if f:
                        seen.add(f.start_ea)
                    caller = ida_xref.get_next_cref_to(ea, caller)
            for ea in seen:
                ida_hexrays.mark_cfunc_dirty(ea)
            try:
                vdui = ida_hexrays.get_widget_vdui(ida_kernwin.get_current_widget())
                if vdui:
                    vdui.refresh_view(True)
            except Exception:
                pass
        except Exception:
            self.log.debug("decompiler cache invalidation skipped")

    def verify_active(self) -> bool:
        """Cheaply confirm the IDB still holds the recorded epoch.

        Undo/redo, scripts or a crash can change the bytes behind DejaDump's
        back; if they no longer match, fall back to full reconciliation.
        """
        if not self.store.has_base() or not self.store.epochs():
            return True
        cur = self.store.active_epoch()
        if self._resolver().identify_state(self._old_reader, [cur]) == cur:
            return True
        self.log.warning("loaded bytes no longer match t%d; reconciling", cur)
        self._plan_cache.clear()
        self._reconciled = False
        return self.reconcile()

    @staticmethod
    def _set_banner(ea: int, text: str) -> None:
        """Write the DejaDump banner after any anterior lines the user owns."""
        import ida_lines

        index = 0
        while True:
            line = ida_lines.get_extra_cmt(ea, ida_lines.E_PREV + index)
            if line is None or owned_line(line):
                break
            index += 1
            if index >= 100:
                return
        ida_lines.update_extra_cmt(ea, ida_lines.E_PREV + index, text)

    def _decorate_volatile(self, k: int) -> None:
        """Make the disassembly show the time dimension: an anterior banner at each
        volatile range start, refreshed for the active epoch."""
        try:
            maxk = max((e["seq"] for e in self.store.epochs()), default=0)
            with self._suspended():
                for s, e in self.store.volatile_set():
                    versions = self.store.epochs_touching(s, e)
                    vers = ",".join("t%d" % v for v in versions) or "—"
                    banner = ("[DejaDump] volatile 0x%X–0x%X  ·  active t%d / t%d  ·  "
                              "versions: %s  ·  Alt+[ / Alt+]" % (s, e, k, maxk, vers))
                    self._set_banner(s, banner)
        except Exception:
            self.log.debug("volatile decoration skipped")

    def changed_spans(self, k: int) -> list[tuple[int, int]]:
        """Spans epoch ``k`` changed relative to ``k-1`` (for line highlighting)."""
        try:
            return self._resolver().changed_spans(k)
        except Exception:
            return []

    # -- public -------------------------------------------------------------
    def activate(self, k: int, recover: bool = False) -> bool:
        if self.disabled_reason:
            ida_kernwin.warning("DejaDump switching disabled: %s." % self.disabled_reason)
            return False
        reason = self._blocked_reason()
        if reason:
            ida_kernwin.warning("DejaDump: cannot switch epoch — %s." % reason)
            return False

        self.ensure_base()
        if not recover and not self.reconcile():
            ida_kernwin.warning(
                "DejaDump: the IDB bytes do not match any complete epoch.\n"
                "Use Revert to t0 recovery before switching."
            )
            return False
        if self._has_user_patches():
            ida_kernwin.warning(
                "DejaDump: user patches exist in the volatile set.\n"
                "Revert or apply them (Edit → Patch program) before switching epochs."
            )
            return False
        if not recover and not self.verify_active():
            ida_kernwin.warning(
                "DejaDump: the IDB bytes no longer match a stored epoch.\n"
                "Use Revert to t0 before switching."
            )
            return False
        cur = self.store.active_epoch()
        if k == cur and not recover:
            return True
        if not 0 <= k <= self._resolver().max_epoch():
            ida_kernwin.warning("DejaDump: t%d does not exist in this source." % k)
            return False
        # In recovery the loaded bytes may be a mixed state; never record its
        # annotations as the active epoch's.
        capture = not recover or (
            self._resolver().identify_state(self._old_reader, [cur]) == cur)
        with self._suspended():
            return self._activate(cur, k, capture)

    def _activate(self, cur: int, k: int, capture: bool = True) -> bool:
        # Capturing only reads the IDB; suspension just keeps our own restores
        # below from being recorded as analyst edits.
        if capture:
            self._capture_current(cur)
        outgoing = self.store.annots_for_epoch(cur)

        started = time.perf_counter()
        res = self._resolver()
        source_ref = self.store.epoch_ref(cur)
        target_ref = self.store.epoch_ref(k)
        cache_key = (self._resolver_hash, source_ref, target_ref)
        plan = self._plan_cache.get(cache_key)
        cache_hit = False
        if plan is not None:
            # The startup reconciliation established a complete source state.
            # Before reusing a plan, cheaply verify only its mutation spans so a
            # user edit cannot be overwritten by stale transition data.
            cache_hit = all(
                self._old_reader(chunk.start, len(chunk.data)) ==
                res.state(cur, chunk.start, len(chunk.data))
                for chunk in plan.chunks
            )
        if not cache_hit:
            plan = res.activation_plan(cur, k, self._old_reader,
                                       source_ref=source_ref, target_ref=target_ref)
            self._plan_cache[cache_key] = plan
            self._plan_cache.move_to_end(cache_key)
            while len(self._plan_cache) > 8:
                self._plan_cache.popitem(last=False)
        # Computed per activation (the plan object may be a cached one).
        if k == 0:
            code_ranges = [
                (s, e, entries) for s, e, entries in self.store.base_code_ranges()
                if any(c.start < e and c.end > s for c in plan.chunks)
            ]
        else:
            # "Written but never executed in the trace" is no proof of data: a
            # decryptor often rewrites .text and the trace ends before it runs.
            # Anything not known to be code that lands in an executable segment
            # is analysed too (large islands only from safe seeds).
            uncertain = [chunk for chunk in plan.chunks if chunk.kind != "code"]
            code_ranges = list(plan.analysis_ranges) + \
                self._executable_fallback_ranges(uncertain)
        code_ranges = self._expand_analysis_ranges(code_ranges)
        changes = [(c.start, c.data) for c in plan.chunks]
        outside = _first_unmapped(changes)
        if outside is not None:
            ida_kernwin.warning(
                "DejaDump: t%d writes 0x%X, which no IDB segment covers, so it cannot be "
                "loaded.\n\nThe trace was most likely imported with the wrong rebase "
                "(check the import summary). Delete the source (Sidecar → Manage "
                "sources…) and import it again, or add a segment covering that address."
                % (k, outside))
            return False
        planned = time.perf_counter()
        previous_funcs = self._functions_intersecting(changes)
        prototype_before = {ea: idc.get_type(ea) or "" for ea in previous_funcs}

        preimages = []
        for addr, data in changes:
            old = self._old_reader(addr, len(data))
            _bid, digest = self.store.blob_id(old)
            preimages.append({"addr": addr, "size": len(old), "sha256": digest.hex()})
        journal_id = self.store.begin_activation(
            source_ref, target_ref,
            {"stage": "planned", "preimages": preimages,
             "expected_hashes": {str(a): h.hex() for a, h in plan.expected_hashes.items()},
             "analysis_ranges": [[s, e, list(entries)] for s, e, entries in code_ranges]},
        )
        ida_kernwin.show_wait_box("DejaDump: activating epoch t%d…" % k)
        try:
            self._fault("planned")
            if ida_compat.has_undo():
                try:
                    import ida_undo

                    ida_undo.create_undo_point(b"dejadump:activate")
                except Exception:
                    pass

            for addr, data in changes:
                ida_bytes.del_items(addr, ida_bytes.DELIT_EXPAND, len(data))
                ida_bytes.put_bytes(addr, data)
                if self._old_reader(addr, len(data)) != data:
                    raise RuntimeError("byte swap failed at %#x" % addr)

            mutated = time.perf_counter()
            self.store.update_activation(journal_id, "bytes_applied")
            self._fault("bytes_applied")

            if not self._analyse_ranges(code_ranges, previous_funcs, k):
                raise RuntimeError("auto-analysis cancelled")

            analysed = time.perf_counter()
            self.store.update_activation(journal_id, "analysis_complete")
            self._fault("analysis_complete")

            changed = IntervalIndex((c.start, c.end) for c in plan.chunks)
            incoming = self.store.annots_for_epoch(k)
            for s, _e in self.store.volatile_set():
                annotations.apply_delta(
                    s, outgoing.get(s), incoming.get(s),
                    lambda off, base=s: _item_changed(changed, base + off))
            for s, payload in self.store.shared_annots().items():
                annotations.restore(s, payload)
            # Restoring functions/types queues more analysis; finish it here so
            # the next switch does not find the queues busy.
            if not self._drain_auto_queue():
                raise RuntimeError("auto-analysis cancelled")

            restored = time.perf_counter()
            self.store.update_activation(journal_id, "annotations_restored")
            self._fault("annotations_restored")
            for addr, data in changes:
                if self._old_reader(addr, len(data)) != data:
                    raise RuntimeError("post-activation verification failed at %#x" % addr)
            self._fault("verified")

            self._invalidate_decompiler(changes, previous_funcs, prototype_before)
            self.store.set_active_epoch(k)
            self.store.finish_activation(journal_id, "committed")
            try:
                self.index.set("active_epoch", k)
            except Exception:
                pass
            finished = time.perf_counter()
            self.last_timings = {
                "target": k, "bytes": plan.bytes_changed, "chunks": len(plan.chunks),
                "plan_cache_hit": cache_hit,
                "analysis_required": bool(code_ranges),
                "plan_ms": (planned - started) * 1000,
                "mutation_ms": (mutated - planned) * 1000,
                "analysis_ms": (analysed - mutated) * 1000,
                "annotations_ms": (restored - analysed) * 1000,
                "total_ms": (finished - started) * 1000,
            }
        except Exception as exc:
            self.log.exception("activation t%d failed; rolling back", k)
            rollback_ok = True
            for item in preimages:
                data = self.store.blob(bytes.fromhex(item["sha256"]))
                if data is None:
                    rollback_ok = False
                else:
                    ida_bytes.put_bytes(item["addr"], data)
            rollback_ranges = (self.store.base_code_ranges() if cur == 0
                               else res.code_ranges_at(cur))
            try:
                affected_rollback = [
                    row for row in rollback_ranges
                    if any(item["addr"] < row[1] and item["addr"] + item["size"] > row[0]
                           for item in preimages)
                ]
                rollback_ok = self._analyse_ranges(
                    affected_rollback, previous_funcs, cur) and rollback_ok
            except Exception:
                rollback_ok = False
            changed = IntervalIndex((c.start, c.end) for c in plan.chunks)
            incoming = self.store.annots_for_epoch(k)
            for s, _e in self.store.volatile_set():
                try:
                    annotations.apply_delta(
                        s, incoming.get(s), outgoing.get(s),
                        lambda off, base=s: _item_changed(changed, base + off))
                except Exception:
                    self.log.debug("annotation rollback skipped at %#x", s)
            for s, payload in self.store.shared_annots().items():
                annotations.restore(s, payload)
            rollback_ok = self._drain_auto_queue() and rollback_ok
            for item in preimages:
                data = self.store.blob(bytes.fromhex(item["sha256"]))
                if data is None or self._old_reader(item["addr"], item["size"]) != data:
                    rollback_ok = False
            self.store.finish_activation(journal_id, "rolled_back" if rollback_ok else "failed")
            if not rollback_ok:
                self.disabled_reason = "activation failed and rollback could not be verified"
            ida_kernwin.warning("DejaDump activation failed: %s" % exc)
            return False
        finally:
            ida_kernwin.hide_wait_box()

        self._decorate_volatile(k)
        ida_kernwin.refresh_idaview_anyway()
        self.log.info("activated epoch t%d (%d changed spans)", k, len(changes))
        return True

    def revert_to_t0(self) -> bool:
        """Deterministic inverse — always computable from the stored base."""
        if self.hard_disabled:
            ida_kernwin.warning("DejaDump recovery refused: %s." % self.disabled_reason)
            return False
        self.disabled_reason = None
        self._reconciled = True
        ok = self.activate(0, recover=True)
        self._reconciled = ok
        return ok
