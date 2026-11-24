"""Wave (epoch) detection — pure Python, fully unit-tested, no IDA.

Implements CoDisasm-style wave semantics with a **byte-granular** boundary: a new
epoch begins when an executed instruction's bytes intersect memory written since
the last boundary.  Page membership is kept only as an O(1) pre-filter so the
per-instruction check stays cheap on multi-million-line traces.

A :class:`MemoryImage` accumulates writes so each committed epoch can snapshot the
exact bytes of its dirty ranges (every byte in a range was written, so snapshots
are fully defined).
"""

from __future__ import annotations

from typing import Optional

from .intervals import IntervalSet  # noqa: F401  (re-exported for callers)
from .model import PAGE, Epoch, Range, WriteRecord, iter_pages, page_base


class MemoryImage:
    """Sparse, page-backed byte memory accumulated from writes.

    Reads of unwritten bytes fall through to an optional ``base`` byte-source
    (the loaded image in real use); for trace import there is no base and
    unwritten bytes read as zero — but committed ranges only ever cover written
    bytes, so that fallback is never used for snapshots.
    """

    def __init__(self, page: int = PAGE, base=None):
        if page & (page - 1):
            raise ValueError("page size must be a power of two")
        self.page = page
        self.base = base
        self._data: dict[int, bytearray] = {}
        self._mask: dict[int, bytearray] = {}

    def _ensure(self, pb: int) -> None:
        if pb not in self._data:
            self._data[pb] = bytearray(self.page)
            self._mask[pb] = bytearray(self.page)

    def write(self, addr: int, data: bytes) -> None:
        i, n = 0, len(data)
        while i < n:
            pb = page_base(addr, self.page)
            off = addr - pb
            chunk = min(self.page - off, n - i)
            self._ensure(pb)
            self._data[pb][off:off + chunk] = data[i:i + chunk]
            self._mask[pb][off:off + chunk] = b"\x01" * chunk
            addr += chunk
            i += chunk

    def read(self, addr: int, size: int) -> bytes:
        out = bytearray(size)
        i = 0
        while i < size:
            cur = addr + i
            pb = page_base(cur, self.page)
            off = cur - pb
            chunk = min(self.page - off, size - i)
            data = self._data.get(pb)
            mask = self._mask.get(pb)
            if data is not None and mask.count(1, off, off + chunk) == chunk:
                out[i:i + chunk] = data[off:off + chunk]       # fully written: fast path
            else:
                for j in range(chunk):
                    if data is not None and mask[off + j]:
                        out[i + j] = data[off + j]
                    elif self.base is not None:
                        out[i + j] = self.base.read(cur + j, 1)[0]
                    # else leave as 0
            i += chunk
        return bytes(out)

    def written(self, addr: int, size: int) -> bool:
        i = 0
        while i < size:
            cur = addr + i
            pb = page_base(cur, self.page)
            off = cur - pb
            chunk = min(self.page - off, size - i)
            mask = self._mask.get(pb)
            if mask is None or mask.count(1, off, off + chunk) != chunk:
                return False
            i += chunk
        return True

    def unwritten_spans(self, addr: int, size: int) -> list[tuple[int, int]]:
        """``(offset, length)`` runs of ``[addr, addr+size)`` never written."""
        spans: list[tuple[int, int]] = []
        run = None
        for j in range(size):
            pb = page_base(addr + j, self.page)
            mask = self._mask.get(pb)
            hit = mask is not None and mask[(addr + j) - pb]
            if not hit:
                if run is None:
                    run = j
            elif run is not None:
                spans.append((run, j - run))
                run = None
        if run is not None:
            spans.append((run, size - run))
        return spans


class WaveDetector:
    """Turn a stream of write/exec events into deduplicated epochs.

    Feed events in execution order::

        det.on_write(writer_pc, addr, data)   # a store that just happened
        det.on_exec(pc, size)                  # an instruction about to execute
        ...
        det.finish()                           # flush trailing dirty state

    ``on_exec`` returns the committed :class:`Epoch` when ``pc`` enters bytes
    written since the last boundary, else ``None``.
    """

    def __init__(self, mem: MemoryImage, page: int = PAGE, code_align: int = 1):
        self.mem = mem
        self.page = page
        self.code_align = max(1, code_align)
        self._dirty = IntervalSet()
        self._dirty_pages: set[int] = set()
        self._writes: list[WriteRecord] = []
        self._epochs: list[Epoch] = []
        self._seq = 0

    @property
    def epochs(self) -> list[Epoch]:
        return self._epochs

    def on_write(self, writer_pc: Optional[int], addr: int, data: bytes) -> None:
        if not data:
            return
        self.mem.write(addr, data)
        self._writes.append(WriteRecord(writer_pc, addr, data, seq=len(self._writes)))
        self._dirty.add(addr, addr + len(data))
        for pb in iter_pages(addr, len(data), self.page):
            self._dirty_pages.add(pb)

    def on_exec(self, pc: int, size: Optional[int] = None) -> Optional[Epoch]:
        size = size or self.code_align
        if self._dirty_pages and page_base(pc, self.page) in self._dirty_pages:
            if self._dirty.overlaps(pc, pc + size):
                return self._commit("wave", boundary_pc=pc, entry_pc=pc)
        return None

    def on_boundary(self, kind: str, pc: Optional[int] = None) -> Optional[Epoch]:
        """Force a boundary (manual mark, breakpoint, mprotect→RX …)."""
        if self._dirty:
            return self._commit(kind, boundary_pc=pc, entry_pc=None)
        return None

    def finish(self, trace_index: Optional[int] = None) -> Optional[Epoch]:
        if self._dirty:
            return self._commit("end", boundary_pc=None, entry_pc=None, trace_index=trace_index)
        return None

    def _commit(self, kind, boundary_pc, entry_pc, trace_index=None) -> Optional[Epoch]:
        ranges: list[Range] = []
        for s, e in self._dirty.ranges():
            data = self.mem.read(s, e - s)
            in_range = entry_pc is not None and s <= entry_pc < e
            ranges.append(
                Range(
                    start=s,
                    data=data,
                    entry_pcs=(entry_pc,) if in_range else (),
                    is_code_hint=in_range,
                )
            )
        self._seq += 1
        epoch = Epoch(
            seq=self._seq,
            ranges=ranges,
            writes=self._writes,
            boundary_kind=kind,
            boundary_pc=boundary_pc,
            trace_index=trace_index,
        )
        # Suppress a commit whose content is identical to the previous epoch
        # (rewrite loop re-writing the same bytes); keep its writes + a counter.
        if self._epochs and ranges and epoch.signature() == self._epochs[-1].signature():
            prev = self._epochs[-1]
            prev.repeat_count += 1
            prev.writes.extend(self._writes)
            self._seq -= 1
            self._reset()
            return None

        self._epochs.append(epoch)
        self._reset()
        return epoch

    def _reset(self) -> None:
        self._dirty = IntervalSet()
        self._dirty_pages = set()
        self._writes = []
