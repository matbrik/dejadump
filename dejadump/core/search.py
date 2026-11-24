"""Cross-epoch search and "what did this wave reveal?" helpers — pure Python.

Both work on the read-through :class:`~dejadump.core.state.StateResolver`, so
they see every epoch without switching the IDB.
"""

from __future__ import annotations

import re
from typing import Iterable, Optional

from .intervals import merge


def parse_needle(text: str) -> bytes:
    """``"de ad be ef"`` / ``"deadbeef"`` → hex bytes; ``'"text"'`` or plain text → UTF-8."""
    stripped = text.strip()
    if len(stripped) >= 2 and stripped[0] == stripped[-1] and stripped[0] in "\"'":
        return stripped[1:-1].encode("utf-8")
    compact = stripped.replace(" ", "")
    if compact and len(compact) % 2 == 0 and re.fullmatch(r"[0-9A-Fa-f]+", compact):
        return bytes.fromhex(compact)
    return stripped.encode("utf-8")


def search_epochs(resolver, needle: bytes, extents: Optional[Iterable[tuple[int, int]]] = None,
                  max_hits: int = 1000) -> list[dict]:
    """Find ``needle`` in every epoch; one row per address with the epochs it is in.

    Rows are ``{"addr", "epochs": [k…], "first": k}`` sorted by address.
    ``extents`` defaults to the resolver's volatile set.
    """
    if not needle:
        return []
    extents = merge(extents if extents is not None else resolver.volatile_set())
    hits: dict[int, list[int]] = {}
    for k in range(resolver.max_epoch() + 1):
        for start, end in extents:
            data = resolver.state(k, start, end - start)
            pos = data.find(needle)
            while pos >= 0:
                addr = start + pos
                if addr in hits or len(hits) < max_hits:
                    epochs = hits.setdefault(addr, [])
                    if not epochs or epochs[-1] != k:
                        epochs.append(k)
                pos = data.find(needle, pos + 1)
    rows = [{"addr": addr, "epochs": epochs, "first": epochs[0]}
            for addr, epochs in sorted(hits.items())]
    return rows[:max_hits]


def extract_strings(data: bytes, min_len: int = 5) -> list[tuple[int, str]]:
    """Printable ASCII runs of at least ``min_len`` bytes as ``(offset, text)``."""
    pattern = re.compile(rb"[\x20-\x7e\t]{%d,}" % min_len)
    return [(m.start(), m.group().decode("ascii")) for m in pattern.finditer(data)]


def strings_revealed(resolver, k: int, extents: Iterable[tuple[int, int]],
                     min_len: int = 5, limit: int = 500) -> list[dict]:
    """Strings present at epoch ``k`` that were not there at ``k-1``.

    ``extents`` is usually the epoch's own captured ranges.  Each row is
    ``{"addr", "text"}``.
    """
    if k <= 0:
        return []
    out = []
    for start, end in merge(extents):
        # Widen slightly so a string straddling the range edge is seen whole.
        lo, hi = max(0, start - 64), end + 64
        now = resolver.state(k, lo, hi - lo)
        before = resolver.state(k - 1, lo, hi - lo)
        for offset, text in extract_strings(now, min_len):
            addr = lo + offset
            if addr + len(text) <= start or addr >= end:
                continue
            if before[offset:offset + len(text)] != now[offset:offset + len(text)]:
                out.append({"addr": addr, "text": text})
                if len(out) >= limit:
                    return out
    return out
