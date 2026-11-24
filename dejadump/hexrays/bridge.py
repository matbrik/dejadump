"""Hex-Rays bridge + temporal cross-references (IDA-only).

Two jobs:
  * invalidate the decompiler cache precisely when Mode A swaps code;
  * materialise *temporal* write cross-references — for a writer in STABLE code,
    ``add_dref(writer_pc, target, dr_W)`` plus one summary comment per writer, so
    IDA's own xref list and (optionally) the pseudocode show "this instruction
    wrote that region".

A decryption loop writes megabytes with one instruction, so writes are aggregated
per (epoch, writer) into coalesced spans: one xref per span (capped), one comment
line per epoch, one decompilation per function.  Everything DejaDump adds is
recorded as plugin-owned (xrefs that already existed are not), so it can be
removed exactly — xrefs, comment lines and pseudocode comments.

Writers *inside* the volatile set are version-specific and are only meaningful
while their epoch is active, so they are skipped.  Everything is best-effort and
never fatal.
"""

from __future__ import annotations

from typing import Callable

import ida_bytes
import ida_funcs
import ida_idaapi
import ida_xref

from ..core.intervals import IntervalIndex, IntervalSet
from ..util import ida_compat
from ..util.fmt import OWNED_TAGS, TAG, owned_line, size as fmt_size
from ..util.logging import get_logger

log = get_logger("hexrays")

_TAG = TAG

#: At most this many xrefs per (epoch, writer); the comment summarises the rest.
MAX_XREFS_PER_WRITER = 64


def mark_dirty(ea: int) -> None:
    if not ida_compat.has_hexrays():
        return
    try:
        import ida_hexrays

        f = ida_funcs.get_func(ea)
        if f:
            ida_hexrays.mark_cfunc_dirty(f.start_ea)
    except Exception:
        log.debug("mark_cfunc_dirty skipped for %#x", ea)


def _strip_tagged(text: str) -> str:
    return "\n".join(line for line in (text or "").split("\n")
                     if not owned_line(line)).strip()


def _set_tagged_lines(ea: int, lines: list[str]) -> None:
    """Replace DejaDump's comment lines at ``ea``, keeping the user's text."""
    user = _strip_tagged(ida_bytes.get_cmt(ea, False) or "")
    text = "\n".join(([user] if user else []) + lines)
    ida_bytes.set_cmt(ea, text, False)


def _pseudocode_comments(by_func: dict[int, dict[int, str]]) -> None:
    """Attach comments to pseudocode statements: one decompilation per function."""
    if not ida_compat.has_hexrays():
        return
    try:
        import ida_hexrays
    except Exception:
        return
    for func_ea, comments in by_func.items():
        try:
            cfunc = ida_hexrays.decompile(func_ea)
            if not cfunc:
                continue
            for ea, text in comments.items():
                tl = ida_hexrays.treeloc_t()
                tl.ea = ea
                tl.itp = ida_hexrays.ITP_SEMI
                existing = cfunc.get_user_cmt(tl, ida_hexrays.RETRIEVE_ALWAYS) or ""
                user = _strip_tagged(str(existing))
                cfunc.set_user_cmt(tl, "\n".join(([user] if user else []) + [text]))
            cfunc.save_user_cmts()
        except Exception:
            log.debug("pseudocode comments skipped for function %#x", func_ea)


def pseudocode_comment(ea: int, text: str) -> bool:
    """Best-effort: attach ``text`` to the pseudocode statement at ``ea``."""
    f = ida_funcs.get_func(ea)
    if not f:
        return False
    _pseudocode_comments({f.start_ea: {ea: text}})
    return True


def _existing_drefs(pc: int) -> set[int]:
    out, target = set(), ida_xref.get_first_dref_from(pc)
    while target != ida_idaapi.BADADDR:
        out.add(int(target))
        target = ida_xref.get_next_dref_from(pc, target)
    return out


def aggregate_writes(writes, is_stable: Callable[[int], bool]) -> dict:
    """Group write records by ``(epoch_seq, writer_pc)`` (stable writers only).

    Returns ``{(seq, pc): {"spans": IntervalSet, "stores": n, "bytes": n,
    "sample": bytes|None}}``.
    """
    groups: dict = {}
    for w in writes:
        pc = w["writer_pc"]
        if pc is None or not is_stable(pc):
            continue
        group = groups.get((w["epoch_seq"], pc))
        if group is None:
            group = groups[(w["epoch_seq"], pc)] = {
                "spans": IntervalSet(), "stores": 0, "bytes": 0, "sample": None}
        group["spans"].add(w["addr"], w["addr"] + w["size"])
        group["stores"] += 1
        group["bytes"] += w["size"]
        if group["sample"] is None and w.get("new_bytes") and w["size"] <= 8:
            group["sample"] = w["new_bytes"]
    return groups


def summary_line(seq: int, group: dict) -> str:
    spans = group["spans"].ranges()
    lo, hi = spans[0][0], spans[-1][1]
    if group["stores"] == 1:
        value = (" = %s" % group["sample"].hex()) if group["sample"] else ""
        return "%s t%d: wrote %d byte(s) @ 0x%X%s" % (_TAG, seq, group["bytes"], lo, value)
    return "%s t%d: wrote %s in %d stores @ 0x%X–0x%X (%d span%s)" % (
        _TAG, seq, fmt_size(group["bytes"]), group["stores"], lo, hi, len(spans),
        "" if len(spans) == 1 else "s")


def _materialize(store, groups: dict, progress=None) -> int:
    count, owned = 0, []
    comments: dict[int, list[str]] = {}
    for done, ((seq, pc), group) in enumerate(sorted(groups.items())):
        if progress is not None and progress(done, len(groups)) is False:
            break
        try:
            existing = _existing_drefs(pc)
            for start, _end in group["spans"].ranges()[:MAX_XREFS_PER_WRITER]:
                if start in existing:
                    continue
                ida_xref.add_dref(pc, start, ida_xref.dr_W | ida_xref.XREF_USER)
                owned.append((seq, pc, start, ida_xref.dr_W))
                count += 1
            comments.setdefault(pc, []).append(summary_line(seq, group))
        except Exception:
            log.debug("temporal xref failed for writer %#x", pc)
    store.record_owned_xrefs(owned)
    by_func: dict[int, dict[int, str]] = {}
    for pc, lines in comments.items():
        try:
            _set_tagged_lines(pc, lines)
            f = ida_funcs.get_func(pc)
            if f:
                by_func.setdefault(f.start_ea, {})[pc] = "\n".join(lines)
        except Exception:
            log.debug("provenance comment failed at %#x", pc)
    _pseudocode_comments(by_func)
    return count


def _stable(volatile_set):
    index = IntervalIndex(volatile_set)
    return lambda pc: not index.contains(pc)


def materialize_write_xrefs(store, volatile_set, progress=None) -> int:
    """Add aggregated write drefs + one comment per writer. Returns xrefs added."""
    groups = aggregate_writes(store.iter_writes(), _stable(volatile_set))
    return _materialize(store, groups, progress)


def materialize_xrefs_for_addr(store, addr: int, volatile_set) -> list:
    """Materialise the temporal write xrefs for one address and return the
    (epoch, writer) list — "xref this location across the times it was written"."""
    writers = store.writers_of(addr)
    stable = _stable(volatile_set)
    groups = {}
    for w in writers:
        if w["writer_pc"] is None or not stable(w["writer_pc"]):
            continue
        summary = store.writer_summary(w["writer_pc"], w["epoch_seq"])
        spans = IntervalSet()
        spans.add(addr, addr + 1)
        groups[(w["epoch_seq"], w["writer_pc"])] = {
            "spans": spans, "stores": summary["stores"], "bytes": summary["bytes"],
            "sample": w.get("new_bytes") if (w.get("new_bytes") and w["size"] <= 8) else None,
        }
        if summary["stores"] > 1:
            groups[(w["epoch_seq"], w["writer_pc"])]["spans"].add(
                summary["lo"], summary["hi"])
    _materialize(store, groups)
    return writers


def remove_materialized_xrefs(store) -> int:
    """Remove exactly what DejaDump added: owned xrefs, comment lines, pseudocode notes."""
    count = 0
    writers = set()
    for row in store.owned_xrefs():
        try:
            ida_xref.del_dref(row["src"], row["dst"])
            writers.add(int(row["src"]))
            count += 1
        except Exception:
            log.debug("owned xref removal failed for %#x -> %#x", row["src"], row["dst"])
    for pc in writers:
        try:
            existing = ida_bytes.get_cmt(pc, False) or ""
            if any(tag in existing for tag in OWNED_TAGS):
                ida_bytes.set_cmt(pc, _strip_tagged(existing), False)
        except Exception:
            log.debug("provenance comment removal failed at %#x", pc)
    _remove_pseudocode_comments(writers)
    store.clear_owned_xrefs()
    return count


def _remove_pseudocode_comments(writers) -> None:
    if not ida_compat.has_hexrays():
        return
    try:
        import ida_hexrays
    except Exception:
        return
    funcs = {f.start_ea for f in (ida_funcs.get_func(pc) for pc in writers) if f}
    for func_ea in funcs:
        try:
            cmts = ida_hexrays.restore_user_cmts(func_ea)
            if cmts is None:
                continue
            kept = ida_hexrays.user_cmts_new()
            it = ida_hexrays.user_cmts_begin(cmts)
            while it != ida_hexrays.user_cmts_end(cmts):
                loc = ida_hexrays.user_cmts_first(it)
                cmt = ida_hexrays.user_cmts_second(it)
                text = cmt.c_str() if hasattr(cmt, "c_str") else str(cmt)
                cleaned = _strip_tagged(text)
                if cleaned:
                    ida_hexrays.user_cmts_insert(kept, loc, ida_hexrays.citem_cmt_t(cleaned))
                it = ida_hexrays.user_cmts_next(it)
            ida_hexrays.save_user_cmts(func_ea, kept)
            ida_hexrays.user_cmts_free(kept)
            ida_hexrays.user_cmts_free(cmts)
            mark_dirty(func_ea)
        except Exception:
            log.debug("pseudocode comment removal skipped for %#x", func_ea)
