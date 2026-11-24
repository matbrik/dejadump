"""Annotation payload algebra — pure Python, unit-tested headless.

A payload is ``{kind: [entry, …]}`` with range-relative offsets (see
:mod:`dejadump.core.annotations` for the IDA side that captures and applies
them).  This module decides *what* changes on an epoch switch; it never touches
the IDB.
"""

from __future__ import annotations

import json
from typing import Callable, Optional

KINDS = ("names", "funcs", "cmts", "types", "colors", "manual", "extra",
         "forced_operands", "operands", "hexrays")


#: Kinds a delta only ever applies, never removes (see :func:`plan_delta`).
NEVER_REMOVE = ("funcs",)


def empty_payload() -> dict:
    return {kind: [] for kind in KINDS}


def _entry_key(kind: str, entry: dict):
    if kind == "hexrays":
        return int(entry.get("func_off", 0))
    if kind == "cmts":
        return (int(entry["off"]), bool(entry.get("rpt")))
    if kind == "extra":
        return (int(entry["off"]), int(entry["where"]))
    if kind in ("forced_operands", "operands"):
        return (int(entry["off"]), int(entry["opnum"]))
    return int(entry["off"])


def _entry_off(kind: str, entry: dict) -> int:
    return int(entry.get("func_off", 0)) if kind == "hexrays" else int(entry["off"])


def replace_window(payload: Optional[dict], lo_off: int, hi_off: int, window: dict) -> dict:
    """Return ``payload`` with entries in ``[lo_off, hi_off)`` replaced by ``window``."""
    merged = empty_payload()
    for kind in KINDS:
        kept = [e for e in (payload or {}).get(kind, [])
                if not lo_off <= _entry_off(kind, e) < hi_off]
        merged[kind] = kept + list(window.get(kind, []))
    return merged


def _canonical(entry: dict) -> str:
    return json.dumps(entry, sort_keys=True)


def plan_delta(outgoing: Optional[dict], target: Optional[dict],
               changed: Optional[Callable[[int], bool]] = None):
    """Split a transition into ``(remove, apply)`` payloads (pure; IDA-free).

    * ``target`` known (the epoch was visited before): remove every outgoing
      entry the target does not have identically; apply every target entry that
      differs from the outgoing one or lies in a changed span (analysis may have
      rebuilt that item).
    * ``target`` unknown (first visit): carry annotations over where the bytes
      did not change, and remove only those inside changed spans.

    ``changed(off) -> bool`` tells whether a range-relative offset lies in a byte
    span this transition rewrites.

    Functions are never removed: after the byte swap they belong to IDA's
    re-analysis of the new bytes, and deleting one could destroy a function the
    target epoch genuinely has.  Their user-visible names/comments are removed.
    """
    changed = changed or (lambda _off: False)
    remove, apply = empty_payload(), empty_payload()
    for kind in KINDS:
        out_entries = {_entry_key(kind, e): e for e in (outgoing or {}).get(kind, [])}
        removable = kind not in NEVER_REMOVE
        if target is None:
            if removable:
                remove[kind] = [e for e in out_entries.values()
                                if changed(_entry_off(kind, e))]
            continue
        tgt_entries = {_entry_key(kind, e): e for e in target.get(kind, [])}
        for key, entry in out_entries.items():
            other = tgt_entries.get(key)
            if removable and (other is None or _canonical(other) != _canonical(entry)):
                remove[kind].append(entry)
        for key, entry in tgt_entries.items():
            other = out_entries.get(key)
            if (other is None or _canonical(other) != _canonical(entry)
                    or changed(_entry_off(kind, entry))):
                apply[kind].append(entry)
    return remove, apply


def merge_payloads(base: Optional[dict], overlay: dict) -> dict:
    """Entries of ``overlay`` replace same-key entries of ``base``; the rest of
    ``base`` is kept (used when folding a pinned copy's edits back into an epoch)."""
    merged = empty_payload()
    for kind in KINDS:
        entries = {_entry_key(kind, e): e for e in (base or {}).get(kind, [])}
        for entry in overlay.get(kind, []):
            entries[_entry_key(kind, entry)] = entry
        merged[kind] = list(entries.values())
    return merged
