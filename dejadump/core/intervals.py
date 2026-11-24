"""Half-open integer interval helpers ``[start, end)`` — pure Python, no IDA.

Shared by wave detection (dirty sets), trace filtering (keep-lists), base
coverage, and search, so every caller gets the same coalescing rules: touching
intervals merge.
"""

from __future__ import annotations

from bisect import bisect_left, bisect_right
from typing import Iterable


def merge(intervals: Iterable[tuple[int, int]]) -> list[tuple[int, int]]:
    """Sort and coalesce overlapping or adjacent intervals; drop empty ones."""
    out: list[list[int]] = []
    for start, end in sorted((int(s), int(e)) for s, e in intervals if e > s):
        if out and start <= out[-1][1]:
            out[-1][1] = max(out[-1][1], end)
        else:
            out.append([start, end])
    return [(s, e) for s, e in out]


def subtract(intervals: Iterable[tuple[int, int]],
             covered: Iterable[tuple[int, int]]) -> list[tuple[int, int]]:
    """Parts of ``intervals`` not covered by ``covered``."""
    covered = merge(covered)
    out: list[tuple[int, int]] = []
    for start, end in merge(intervals):
        pos = start
        for cs, ce in covered:
            if ce <= pos:
                continue
            if cs >= end:
                break
            if cs > pos:
                out.append((pos, cs))
            pos = max(pos, ce)
            if pos >= end:
                break
        if pos < end:
            out.append((pos, end))
    return out


class IntervalIndex:
    """Immutable, coalesced interval list with O(log n) membership queries."""

    def __init__(self, intervals: Iterable[tuple[int, int]] = ()):
        merged = merge(intervals)
        self._starts = [s for s, _ in merged]
        self._ends = [e for _, e in merged]

    def __bool__(self) -> bool:
        return bool(self._starts)

    def __len__(self) -> int:
        return len(self._starts)

    def ranges(self) -> list[tuple[int, int]]:
        return list(zip(self._starts, self._ends))

    def contains(self, addr: int) -> bool:
        i = bisect_right(self._starts, addr) - 1
        return i >= 0 and addr < self._ends[i]

    def covers(self, start: int, end: int) -> bool:
        """True when the whole of ``[start, end)`` lies inside one interval."""
        i = bisect_right(self._starts, start) - 1
        return i >= 0 and end <= self._ends[i]

    def overlaps(self, start: int, end: int) -> bool:
        i = bisect_right(self._starts, start) - 1
        if i >= 0 and self._ends[i] > start:
            return True
        j = i + 1
        return j < len(self._starts) and self._starts[j] < end

    def intersect(self, start: int, end: int) -> list[tuple[int, int]]:
        out = []
        i = max(0, bisect_right(self._starts, start) - 1)
        while i < len(self._starts) and self._starts[i] < end:
            lo, hi = max(start, self._starts[i]), min(end, self._ends[i])
            if lo < hi:
                out.append((lo, hi))
            i += 1
        return out


class IntervalSet:
    """A mutable set of intervals kept coalesced and sorted.

    Insertion is ``O(log n + k)`` (``k`` = intervals absorbed), so a trace with
    tens of thousands of scattered stores stays linear overall instead of
    rebuilding the whole list on every write.
    """

    def __init__(self):
        self._starts: list[int] = []
        self._ends: list[int] = []

    def __bool__(self) -> bool:
        return bool(self._starts)

    def __len__(self) -> int:
        return len(self._starts)

    def add(self, start: int, end: int) -> None:
        if end <= start:
            return
        # First interval whose end touches or follows ``start``; last one whose
        # start touches or precedes ``end`` (adjacent intervals merge).
        lo = bisect_left(self._ends, start)
        hi = bisect_right(self._starts, end)
        if lo < hi:
            start = min(start, self._starts[lo])
            end = max(end, self._ends[hi - 1])
        self._starts[lo:hi] = [start]
        self._ends[lo:hi] = [end]

    def overlaps(self, start: int, end: int) -> bool:
        i = bisect_right(self._starts, start) - 1
        if i >= 0 and self._ends[i] > start:
            return True
        j = i + 1
        return j < len(self._starts) and self._starts[j] < end

    def ranges(self) -> list[tuple[int, int]]:
        return list(zip(self._starts, self._ends))

    def clear(self) -> None:
        self._starts = []
        self._ends = []
