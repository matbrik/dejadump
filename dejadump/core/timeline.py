"""Headless model behind the Memory Timeline and Write History (no IDA).

The Memory Timeline shows one column per epoch (t0…tn) and one row per byte (or,
later, per struct field): each cell is the byte value at that epoch via the
read-through :class:`StateResolver`, with a "changed vs the previous column" flag
and the writer provenance.  Keeping this logic here means the PySide6 view in
``ui/`` is a thin adapter and the interesting behaviour is unit-tested.
"""

from __future__ import annotations

from typing import Callable, Optional

from .state import StateResolver


def is_textlike(data: bytes, threshold: float = 0.8) -> bool:
    """True if ``data`` is mostly printable ASCII (a decrypted-string heuristic)."""
    if not data:
        return False
    printable = sum(1 for b in data if 0x20 <= b < 0x7F or b in (9, 10, 13))
    return printable / len(data) >= threshold


class MemoryTimeline:
    """Per-(address, epoch) values, change flags and writer provenance for a range.

    ``writer_lookup(addr)`` returns the write records covering ``addr`` (typically
    ``EpochStore.writes_for_addr``); optional.  With ``include_observed`` the
    runtime-observed layer (bytes the trace read but never wrote) is folded into
    every column from t1 on, so data the loader or kernel produced is not shown
    with its stale on-disk value.
    """

    def __init__(self, resolver: StateResolver,
                 writer_lookup: Optional[Callable[[int], list]] = None,
                 writer_range_lookup: Optional[Callable[[int, int], list]] = None,
                 include_observed: bool = True):
        self.resolver = resolver
        self.writer_lookup = writer_lookup
        self.writer_range_lookup = writer_range_lookup
        self.include_observed = include_observed
        self._writer_cache = None

    def epochs(self) -> list[int]:
        return list(range(0, self.resolver.max_epoch() + 1))

    def column(self, k: int, start: int, size: int) -> bytes:
        """Bytes of the whole range at epoch ``k`` (one timeline column)."""
        if self.include_observed:
            return self.resolver.observed_state(k, start, size)
        return self.resolver.state(k, start, size)

    def value(self, addr: int, k: int) -> int:
        return self.column(k, addr, 1)[0]

    def changed(self, addr: int, k: int) -> bool:
        """Whether ``addr`` differs at epoch ``k`` from epoch ``k-1``."""
        if k <= 0:
            return False
        return self.column(k, addr, 1) != self.column(k - 1, addr, 1)

    def observed_mask(self, start: int, size: int) -> bytearray:
        """1 for bytes whose t≥1 value comes only from an observed read."""
        if not self.include_observed:
            return bytearray(size)
        return self.resolver.observed_mask(start, size)

    def writers(self, addr: int) -> list:
        if self._writer_cache is not None:
            return self._writer_cache.get(addr, [])
        return self.writer_lookup(addr) if self.writer_lookup else []

    def prefetch_writers(self, start: int, size: int) -> None:
        if not self.writer_range_lookup:
            return
        cache = {addr: [] for addr in range(start, start + size)}
        for row in self.writer_range_lookup(start, start + size):
            for addr in range(max(start, row["addr"]),
                              min(start + size, row["addr"] + row["size"])):
                cache[addr].append(row)
        self._writer_cache = cache

    def first_plaintext_epoch(self, start: int, size: int) -> Optional[int]:
        """First epoch at which the range becomes text-like (a decryption point)."""
        prev_text = False
        for k in self.epochs():
            text = is_textlike(self.column(k, start, size))
            if text and not prev_text:
                return k
            prev_text = text
        return None
