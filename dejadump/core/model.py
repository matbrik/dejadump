"""Core dataclasses shared across the engine. Pure Python, no IDA imports.

All addresses are *canonical* (any ASLR slide has already been removed by the
capture adapter). Bytes are stored little-endian exactly as observed.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from typing import Any, Optional

#: Default page granularity used for the dirty-page pre-filter and dump import.
#: Apple platforms use 16 KiB; the value is configurable per capture.
PAGE = 0x1000


@dataclass(frozen=True)
class EpochRef:
    """Stable identity for an epoch inside one capture source.

    ``epoch_id`` is ``None`` for the implicit base epoch t0.
    """

    source_id: Optional[int]
    epoch_id: Optional[int]
    seq: int


@dataclass(frozen=True)
class ChangedChunk:
    start: int
    data: bytes
    old_sha256: bytes
    new_sha256: bytes
    kind: str = "unknown"  # code | data | unknown

    @property
    def end(self) -> int:
        return self.start + len(self.data)


@dataclass
class ActivationPlan:
    source: EpochRef
    target: EpochRef
    chunks: list[ChangedChunk] = field(default_factory=list)
    analysis_ranges: list[tuple[int, int, tuple[int, ...]]] = field(default_factory=list)
    expected_hashes: dict[int, bytes] = field(default_factory=dict)

    @property
    def requires_analysis(self) -> bool:
        return bool(self.analysis_ranges)

    @property
    def bytes_changed(self) -> int:
        return sum(len(c.data) for c in self.chunks)


@dataclass
class AnalysisArtifact:
    epoch: EpochRef
    kind: str
    start: int
    end: int
    version_key: str
    lines: list[str] = field(default_factory=list)
    addresses: list[Optional[int]] = field(default_factory=list)
    diagnostics: dict[str, Any] = field(default_factory=dict)
    duration_ms: float = 0.0


def page_base(addr: int, page: int = PAGE) -> int:
    """Return the base address of the page containing ``addr``."""
    return addr & ~(page - 1)


def iter_pages(addr: int, size: int, page: int = PAGE):
    """Yield the base address of every page touched by ``[addr, addr+size)``."""
    if size <= 0:
        return
    pb = page_base(addr, page)
    end = addr + size
    while pb < end:
        yield pb
        pb += page


@dataclass(frozen=True)
class WriteRecord:
    """A single observed memory write.

    ``writer_pc`` is the PC of the instruction that performed the write.  For
    Tenet-style traces this is the PC of the *previous* trace line (the store's
    value only becomes visible on the following line); see
    :mod:`dejadump.core.tenet`.  ``old_bytes`` is only available for sources
    that diff memory (dumps / debugger); traces carry the post-write value only.
    """

    writer_pc: Optional[int]
    addr: int
    data: bytes
    seq: int = 0
    old_bytes: Optional[bytes] = None

    @property
    def size(self) -> int:
        return len(self.data)

    @property
    def end(self) -> int:
        return self.addr + len(self.data)


@dataclass
class Range:
    """A contiguous byte range captured for one epoch, with its snapshot bytes.

    Every byte in ``data`` was actually written during the epoch, so the snapshot
    is fully defined (no gaps).  ``entry_pcs`` records where execution first
    entered the range (seeds ``AU_CODE`` and function-start hints in Mode A).
    """

    start: int
    data: bytes
    entry_pcs: tuple[int, ...] = ()
    is_code_hint: Optional[bool] = False

    @property
    def size(self) -> int:
        return len(self.data)

    @property
    def end(self) -> int:
        return self.start + len(self.data)

    @property
    def sha256(self) -> bytes:
        return hashlib.sha256(self.data).digest()


@dataclass
class Epoch:
    """One execution wave: the set of ranges that became visible in this wave.

    ``seq`` is the epoch number (``t0`` is the loaded image and is implicit — the
    first stored epoch is ``t1``).  ``repeat_count`` counts suppressed commits
    whose content was identical to this epoch (rewrite loops).
    """

    seq: int
    ranges: list[Range] = field(default_factory=list)
    writes: list[WriteRecord] = field(default_factory=list)
    boundary_kind: str = "wave"  # 'wave' | 'manual' | 'dump' | 'bpt' | 'mprotect' | 'end'
    boundary_pc: Optional[int] = None
    trace_index: Optional[int] = None
    label: Optional[str] = None
    note: str = ""
    repeat_count: int = 0

    @property
    def bytes_changed(self) -> int:
        return sum(r.size for r in self.ranges)

    @property
    def entry_pcs(self) -> tuple[int, ...]:
        out: list[int] = []
        for r in self.ranges:
            out.extend(r.entry_pcs)
        return tuple(out)

    def signature(self) -> tuple[tuple[int, bytes], ...]:
        """Content signature used to dedupe identical consecutive commits."""
        return tuple((r.start, r.sha256) for r in sorted(self.ranges, key=lambda x: x.start))


@dataclass
class AnnotationSet:
    """IDA annotations for one range in one epoch (names, funcs, cmts, types …).

    The payload shape matches DESIGN §5.3; it is captured/restored by the
    IDA-side ``annotations`` module in R2.  Defined here so the store can
    round-trip it headless.
    """

    epoch_seq: int
    range_start: int
    payload: dict = field(default_factory=dict)
