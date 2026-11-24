"""StateResolver — Ghidra-style read-through resolution of memory per epoch.

``State(k, range)`` = the bytes of a range at the start of epoch *k*: for every
byte, the snapshot from the most recent epoch ≤ *k* that dirtied it, else the base
(epoch-0) image.  Implemented by overlaying epochs ``1..k`` in order onto the base
(a later epoch overwrites an earlier one), which is the read-through model.

Also provides the minimal byte **diff** between the currently-loaded bytes and the
target epoch, so Mode A rewrites only what actually changed.

Pure Python, unit-tested headless.
"""

from __future__ import annotations

import hashlib
from typing import Callable, Iterable, Optional

from .model import ActivationPlan, ChangedChunk, EpochRef, PAGE


class BytesBase:
    """A base byte-source from ``(start, bytes)`` segments; gaps read as zero."""

    def __init__(self, segments: Optional[Iterable[tuple[int, bytes]]] = None):
        self._segs = sorted(segments or [])

    def read(self, addr: int, size: int) -> bytes:
        out = bytearray(size)
        for start, data in self._segs:
            lo = max(start, addr)
            hi = min(start + len(data), addr + size)
            if lo < hi:
                out[lo - addr:hi - addr] = data[lo - start:hi - start]
        return bytes(out)


def _normalize(epochs):
    """Normalize epochs to ``(seq, [(start, end, data, is_code, entry_pcs), …])``."""
    norm = []
    for e in epochs:
        seq = e.seq if hasattr(e, "seq") else e[0]
        raw_ranges = e.ranges if hasattr(e, "ranges") else e[1]
        ranges = []
        for r in raw_ranges:
            if hasattr(r, "start"):
                ranges.append((r.start, r.end, r.data, r.is_code_hint, tuple(r.entry_pcs)))
            else:
                start, data = r
                ranges.append((start, start + len(data), data, False, ()))
        norm.append((seq, ranges))
    norm.sort(key=lambda x: x[0])
    return norm


class StateResolver:
    """Resolve memory state at any epoch from the per-epoch dirty ranges + base.

    ``observed`` (optional ``(start, bytes)`` segments) is the runtime-observed
    layer: values the trace *read* but never wrote.  It applies from t1 onward,
    under the epochs, and is used by the data views only — Mode A never writes
    it into the IDB.
    """

    _CACHE_LIMIT = 8192

    def __init__(self, epochs, base=None, observed=None):
        self._epochs = _normalize(epochs)
        self.base = base
        self.observed = sorted(observed or [])
        # Per-instance cache: a module-level lru_cache on the method would keep
        # every resolver (and all of its epoch bytes) alive.
        self._cache: dict[tuple[int, int, int], bytes] = {}

    def max_epoch(self) -> int:
        return self._epochs[-1][0] if self._epochs else 0

    def volatile_set(self) -> list[tuple[int, int]]:
        ivals: list[list[int]] = []
        for _, ranges in self._epochs:
            for s, e, *_ in ranges:
                ivals.append([s, e])
        ivals.sort()
        merged: list[list[int]] = []
        for s, e in ivals:
            if merged and s <= merged[-1][1]:
                merged[-1][1] = max(merged[-1][1], e)
            else:
                merged.append([s, e])
        return [(s, e) for s, e in merged]

    def state(self, k: int, start: int, size: int) -> bytes:
        """Bytes of ``[start, start+size)`` at epoch ``k`` (read-through)."""
        key = (k, start, size)
        hit = self._cache.get(key)
        if hit is not None:
            return hit
        value = self._resolve(k, start, size, observed=False)
        if len(self._cache) >= self._CACHE_LIMIT:
            self._cache.pop(next(iter(self._cache)))
        self._cache[key] = value
        return value

    def observed_state(self, k: int, start: int, size: int) -> bytes:
        """Like :meth:`state`, with the observed-read layer folded in for k ≥ 1."""
        if not self.observed or k <= 0:
            return self.state(k, start, size)
        return self._resolve(k, start, size, observed=True)

    def observed_mask(self, start: int, size: int) -> bytearray:
        """1 for every byte of the range that only the observed layer defines."""
        mask = bytearray(size)
        end = start + size
        for s, data in self.observed:
            lo, hi = max(s, start), min(s + len(data), end)
            if lo < hi:
                mask[lo - start:hi - start] = b"\x01" * (hi - lo)
        for _seq, ranges in self._epochs:
            for s, e, *_ in ranges:
                lo, hi = max(s, start), min(e, end)
                if lo < hi:
                    mask[lo - start:hi - start] = bytes(hi - lo)
        return mask

    def _resolve(self, k: int, start: int, size: int, observed: bool) -> bytes:
        buf = bytearray(self.base.read(start, size)) if self.base is not None else bytearray(size)
        end = start + size
        if observed:
            for s, data in self.observed:
                lo, hi = max(s, start), min(s + len(data), end)
                if lo < hi:
                    buf[lo - start:hi - start] = data[lo - s:hi - s]
        for seq, ranges in self._epochs:
            if seq > k:
                break
            for s, e, data, _is_code, _entry in ranges:
                lo = max(s, start)
                hi = min(e, end)
                if lo < hi:
                    buf[lo - start:hi - start] = data[lo - s:hi - s]
        return bytes(buf)

    @staticmethod
    def diff_spans(old: bytes, new: bytes) -> list[tuple[int, bytes]]:
        """Maximal spans where ``old`` and ``new`` differ, as ``(offset, newbytes)``."""
        assert len(old) == len(new), "diff over equal-length buffers"
        out: list[tuple[int, bytes]] = []
        i, n = 0, len(old)
        while i < n:
            if old[i] != new[i]:
                j = i + 1
                while j < n and old[j] != new[j]:
                    j += 1
                out.append((i, new[i:j]))
                i = j
            else:
                i += 1
        return out

    @classmethod
    def coalesced_diff_spans(cls, old: bytes, new: bytes, gap: int = 64) -> list[tuple[int, bytes]]:
        """Diff spans with small unchanged gaps folded into the write.

        Rewriting a few already-correct bytes is much cheaper in IDA than making
        thousands of ``del_items``/``put_bytes`` calls for encrypted images.
        """
        spans = cls.diff_spans(old, new)
        if not spans:
            return []
        out = []
        start, data = spans[0]
        end = start + len(data)
        for next_start, next_data in spans[1:]:
            if next_start - end <= gap:
                data += new[end:next_start] + next_data
                end = next_start + len(next_data)
            else:
                out.append((start, data))
                start, data = next_start, next_data
                end = start + len(data)
        out.append((start, data))
        return out

    def activation_changes(
        self, target_k: int, old_reader: Callable[[int, int], bytes]
    ) -> list[tuple[int, bytes]]:
        """Byte changes to turn the currently-loaded image into epoch ``target_k``.

        ``old_reader(addr, size)`` returns the bytes currently in the database
        (``ida_bytes.get_bytes`` in IDA).  Returns ``[(addr, new_bytes), …]`` over
        only the spans that actually change.
        """
        changes: list[tuple[int, bytes]] = []
        for s, e in self.volatile_set():
            size = e - s
            new = self.state(target_k, s, size)
            old = old_reader(s, size)
            for off, chunk in self.diff_spans(old, new):
                changes.append((s + off, chunk))
        return changes

    def activation_plan(
        self,
        source_k: int,
        target_k: int,
        old_reader: Callable[[int, int], bytes],
        *,
        source_ref: Optional[EpochRef] = None,
        target_ref: Optional[EpochRef] = None,
        chunk_size: int = PAGE,
    ) -> ActivationPlan:
        """Plan a hash-first transition in bounded chunks.

        Only differing chunks are byte-diffed.  Code classification is based on
        the target epoch's capture hints; data-only plans have no analysis ranges.
        """
        source_ref = source_ref or EpochRef(None, None, source_k)
        target_ref = target_ref or EpochRef(None, None, target_k)
        code = self.code_ranges_at(target_k)
        kinds = self.range_kinds_at(target_k)
        chunks: list[ChangedChunk] = []
        expected: dict[int, bytes] = {}
        for vs, ve in self.volatile_set():
            pos = vs
            while pos < ve:
                size = min(chunk_size, ve - pos)
                old = old_reader(pos, size)
                new = self.state(target_k, pos, size)
                old_h, new_h = hashlib.sha256(old).digest(), hashlib.sha256(new).digest()
                expected[pos] = new_h
                if old_h != new_h:
                    for off, data in self.coalesced_diff_spans(old, new):
                        start, end = pos + off, pos + off + len(data)
                        if any(start < ce and end > cs for cs, ce, _ in code):
                            kind = "code"
                        elif any(start < re and end > rs and hint is None
                                 for rs, re, hint in kinds):
                            kind = "unknown"
                        else:
                            kind = "data"
                        chunks.append(ChangedChunk(start, data, old_h, new_h, kind))
                pos += size
        touched_code = []
        for cs, ce, entries in code:
            if any(c.kind == "code" and c.start < ce and c.end > cs for c in chunks):
                touched_code.append((cs, ce, entries))
        return ActivationPlan(source_ref, target_ref, chunks, touched_code, expected)

    def identify_state(
        self, reader: Callable[[int, int], bytes], candidates: Optional[Iterable[int]] = None,
        chunk_size: int = PAGE,
    ) -> Optional[int]:
        """Return the unique epoch whose volatile bytes match ``reader``.

        ``None`` denotes a mixed/unknown state.  Comparison short-circuits on the
        first mismatching chunk and is intended for startup reconciliation.
        """
        remaining = list(dict.fromkeys(
            candidates if candidates is not None else range(self.max_epoch() + 1)))
        # Read each chunk from the database once and test every surviving
        # candidate against it, instead of re-reading the image per epoch.
        for start, end in self.volatile_set():
            pos = start
            while pos < end and remaining:
                size = min(chunk_size, end - pos)
                loaded = reader(pos, size)
                remaining = [k for k in remaining if self._resolve(k, pos, size, False) == loaded]
                pos += size
            if not remaining:
                break
        return remaining[0] if len(remaining) == 1 else None

    def changed_spans(self, k: int) -> list[tuple[int, int]]:
        """Byte spans whose value at epoch ``k`` differs from epoch ``k-1``.

        Only epoch ``k``'s own ranges can differ, so this never scans the whole
        volatile set.  Used to highlight what a wave changed.
        """
        if k <= 0:
            return []
        out: list[tuple[int, int]] = []
        for seq, ranges in self._epochs:
            if seq != k:
                continue
            for s, e, *_ in ranges:
                before = self.state(k - 1, s, e - s)
                after = self.state(k, s, e - s)
                for off, data in self.diff_spans(before, after):
                    out.append((s + off, s + off + len(data)))
        out.sort()
        merged: list[tuple[int, int]] = []
        for s, e in out:
            if merged and s <= merged[-1][1]:
                merged[-1] = (merged[-1][0], max(merged[-1][1], e))
            else:
                merged.append((s, e))
        return merged

    def code_ranges_at(self, k: int) -> list[tuple[int, int, tuple[int, ...]]]:
        """Ranges that are *code* at epoch ``k``, as ``(start, end, entry_pcs)``.

        Keyed by range start: the most recent epoch ≤ k that produced a range at a
        given start decides whether it is code.  Mode A queues ``AU_CODE`` only for
        these, so data regions in the volatile set are never mis-made into code.
        """
        by_start: dict[int, tuple[int, int, bool, tuple[int, ...]]] = {}
        for seq, ranges in self._epochs:
            if seq > k:
                break
            for s, e, _data, is_code, entry in ranges:
                by_start[s] = (s, e, is_code, entry)  # later seq wins
        return [(s, e, entry) for (s, e, is_code, entry) in by_start.values() if is_code]

    def range_kinds_at(self, k: int) -> list[tuple[int, int, Optional[bool]]]:
        """Latest explicit code/data/unknown classification for each range."""
        by_start = {}
        for seq, ranges in self._epochs:
            if seq > k:
                break
            for start, end, _data, hint, _entries in ranges:
                by_start[start] = (start, end, hint)
        return list(by_start.values())
