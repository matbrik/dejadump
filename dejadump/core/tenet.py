"""Streaming importer for Tenet / Frinet execution traces.

Format (one line per executed instruction, comma-separated ``key=value`` deltas):
  * register writes ``reg=hexvalue`` (we only need the PC register);
  * memory tokens ``mr=addr:hexbytes`` (read), ``mw=…`` (write),
    ``mrw=…`` (read+write, e.g. ``inc [rax]``) — a line may carry **several**;
  * an optional Frinet header line ``slide=0x…`` (no PC): the traced module's
    absolute runtime base.

Two correctness points that the plan's §6.3 got wrong and we fix here:

1. **Writer-PC lag.** On a Tenet line the PC is the *current* (not-yet-executed)
   instruction while the deltas belong to the *previous* instruction, and a
   store's bytes surface on the line *after* the store.  So a write read on the
   current line was performed by the *previous* line's PC.  We apply the current
   line's writes attributed to ``prev_pc`` **before** running ``on_exec`` for the
   current PC, which also makes the dirty set correct for wave detection.

2. **mrw / multiple tokens.** ``mrw`` is routed to both the read and write paths,
   and every memory token on a line is parsed, not just the first.

Real traces cover the whole process (stack, heap, libraries), so an optional
``keep`` interval list restricts epochs to the analysed image; anything outside
is counted, not stored.  Reads of bytes the trace never wrote are kept as an
*observed* layer (what the program actually saw, e.g. loader relocations).

The parser is a generator (no full-file load) and extracts only the PC + memory
tokens, so it is not bound by Tenet's reader limits (≤32 registers, ≤~10M
instructions).
"""

from __future__ import annotations

import json
import os
from collections import Counter
from dataclasses import dataclass, field
from typing import Callable, Iterable, Iterator, Optional

from .intervals import IntervalIndex, merge
from .model import PAGE, Range
from .store import EpochStore
from .waves import MemoryImage, WaveDetector

#: How many trace lines after a store its bytes appear (Tenet Pin-tracer convention).
WRITE_PC_LAG = 1

#: Progress callbacks fire every this many trace lines.
PROGRESS_EVERY = 50_000


class ImportCancelled(Exception):
    """Raised when a progress callback asks the import to stop."""


@dataclass(frozen=True)
class Arch:
    name: str
    pc_name: str
    code_align: int  # bytes checked for the "entered written code" test


ARM64 = Arch("arm64", "pc", 4)      # fixed-width instructions
AMD64 = Arch("amd64", "rip", 1)     # variable width: first byte is enough
X86 = Arch("x86", "eip", 1)
ARCHES = {a.name: a for a in (ARM64, AMD64, X86)}

_PC_ALIASES = {"pc", "rip", "eip"}


def _to_int(s: str) -> int:
    return int(s.strip(), 16)


@dataclass
class ParsedLine:
    pc: Optional[int]
    writes: list[tuple[int, bytes]]
    reads: list[tuple[int, bytes]]
    slide: Optional[int]


@dataclass
class ImportStats:
    """What an import saw and what it dropped — shown to the user afterwards."""

    lines: int = 0
    instructions: int = 0
    writes_kept: int = 0
    writes_dropped: int = 0
    reads_observed: int = 0
    malformed: int = 0
    first_malformed_line: Optional[int] = None
    first_malformed_text: str = ""
    slide: Optional[int] = None
    rebase: int = 0
    keep_ranges: int = 0
    observed: list[Range] = field(default_factory=list)

    def summary(self) -> str:
        parts = ["%d lines, %d instructions" % (self.lines, self.instructions),
                 "%d writes kept" % self.writes_kept]
        if self.keep_ranges:
            parts.append("%d outside the image dropped" % self.writes_dropped)
        if self.reads_observed:
            parts.append("%d observed-read bytes" % self.reads_observed)
        if self.malformed:
            parts.append("%d malformed line(s), first at line %d" %
                         (self.malformed, self.first_malformed_line or 0))
        return "; ".join(parts)


def parse_line(line: str, arch: Arch) -> ParsedLine:
    """Parse one trace line.  Raises ``ValueError`` on a malformed memory token."""
    pc: Optional[int] = None
    writes: list[tuple[int, bytes]] = []
    reads: list[tuple[int, bytes]] = []
    slide: Optional[int] = None
    for tok in line.split(","):
        tok = tok.strip()
        if not tok or "=" not in tok:
            continue
        key, val = tok.split("=", 1)
        key = key.strip().lower()
        if key == "slide":
            slide = _to_int(val)
        elif key == arch.pc_name or key in _PC_ALIASES:
            pc = _to_int(val)
        elif key in ("mw", "mr", "mrw"):
            addr_s, sep, bytes_s = val.partition(":")
            if not sep:
                raise ValueError("memory token without ':' — %r" % tok)
            addr = _to_int(addr_s)
            data = bytes.fromhex(bytes_s.strip())
            if key in ("mw", "mrw"):
                writes.append((addr, data))
            if key in ("mr", "mrw"):
                reads.append((addr, data))
    return ParsedLine(pc=pc, writes=writes, reads=reads, slide=slide)


class _ObservedReads:
    """First-seen values of bytes that were read but never written before."""

    def __init__(self, page: int):
        self.mem = MemoryImage(page=page)
        self.count = 0

    def note(self, written: MemoryImage, addr: int, data: bytes) -> None:
        for off, length in written.unwritten_spans(addr, len(data)):
            for sub_off, sub_len in self.mem.unwritten_spans(addr + off, length):
                start = off + sub_off
                self.mem.write(addr + start, data[start:start + sub_len])
                self.count += sub_len

    def ranges(self) -> list[Range]:
        out = []
        for pb in sorted(self.mem._mask):
            mask = self.mem._mask[pb]
            j = 0
            while j < len(mask):
                if not mask[j]:
                    j += 1
                    continue
                k = j
                while k < len(mask) and mask[k]:
                    k += 1
                out.append((pb + j, pb + k))
                j = k
        return [Range(s, self.mem.read(s, e - s), is_code_hint=None)
                for s, e in merge(out)]


def import_trace(
    lines: Iterable[str],
    arch: Arch = ARM64,
    page: int = PAGE,
    slide: Optional[int] = None,
    *,
    image_base: int = 0,
    keep: Optional[Iterable[tuple[int, int]]] = None,
    observe_reads: bool = True,
    progress: Optional[Callable[[int], bool]] = None,
    stats: Optional[ImportStats] = None,
) -> tuple[WaveDetector, MemoryImage]:
    """Run a trace through the wave detector; return ``(detector, memory)``.

    Addresses are rebased as ``addr - slide + image_base``: Frinet's ``slide=``
    header (or the ``slide`` argument, which wins) is the traced module's runtime
    base, and ``image_base`` is where the IDB maps that module.

    ``keep`` limits stored writes (and observed reads) to canonical intervals —
    typically the IDB segments.  ``progress(lines)`` is called periodically and
    may return ``False`` to cancel (raises :class:`ImportCancelled`).  Malformed
    lines are skipped and counted in ``stats``.
    """
    stats = stats if stats is not None else ImportStats()
    keep_index = IntervalIndex(keep) if keep is not None else None
    stats.keep_ranges = len(keep_index) if keep_index is not None else 0
    mem = MemoryImage(page=page)
    det = WaveDetector(mem, page=page, code_align=arch.code_align)
    observed = _ObservedReads(page) if observe_reads else None
    cur_slide = slide or 0
    delta = image_base - cur_slide
    prev_pc: Optional[int] = None
    idx = 0

    number = 0
    for number, raw in enumerate(lines, 1):
        if progress is not None and number % PROGRESS_EVERY == 0:
            if progress(number) is False:
                stats.lines = number
                raise ImportCancelled("import cancelled at line %d" % number)
        line = raw.strip()
        if not line:
            continue
        try:
            p = parse_line(line, arch)
        except ValueError:
            stats.malformed += 1
            if stats.first_malformed_line is None:
                stats.first_malformed_line = number
                stats.first_malformed_text = line[:200]
            continue
        if p.slide is not None and slide is None:
            cur_slide = p.slide
            delta = image_base - cur_slide
        # The deltas on this line belong to the *previous* instruction.
        if prev_pc is not None:
            for addr, data in p.writes:
                canonical = addr + delta
                if keep_index is not None and not keep_index.covers(canonical,
                                                                    canonical + len(data)):
                    pieces = keep_index.intersect(canonical, canonical + len(data))
                    if not pieces:
                        stats.writes_dropped += 1
                        continue
                    for lo, hi in pieces:
                        det.on_write(prev_pc, lo, data[lo - canonical:hi - canonical])
                    stats.writes_kept += 1
                    continue
                det.on_write(prev_pc, canonical, data)
                stats.writes_kept += 1
        if observed is not None:
            for addr, data in p.reads:
                canonical = addr + delta
                if keep_index is None or keep_index.covers(canonical, canonical + len(data)):
                    observed.note(mem, canonical, data)
        # The PC on this line is the instruction about to execute.
        if p.pc is not None:
            pc = p.pc + delta
            det.on_exec(pc, arch.code_align)
            prev_pc = pc
            idx += 1
    det.finish(trace_index=idx)
    stats.lines = number
    stats.instructions = idx
    stats.slide = cur_slide if (slide is not None or cur_slide) else None
    stats.rebase = delta
    if observed is not None:
        stats.observed = observed.ranges()
        stats.reads_observed = observed.count
    return det, mem


def import_trace_file(
    path: str,
    store: EpochStore,
    arch: Arch = ARM64,
    page: int = PAGE,
    slide: Optional[int] = None,
    label: str = "",
    *,
    image_base: int = 0,
    keep: Optional[Iterable[tuple[int, int]]] = None,
    observe_reads: bool = True,
    progress: Optional[Callable[[int], bool]] = None,
    stats: Optional[ImportStats] = None,
) -> int:
    """Import a trace file into ``store`` as a new capture source."""
    stats = stats if stats is not None else ImportStats()
    keep = list(keep) if keep is not None else None
    with open(path, "r", encoding="utf-8", errors="replace") as fh:
        det, _ = import_trace(_iter_lines(fh), arch=arch, page=page, slide=slide,
                              image_base=image_base, keep=keep,
                              observe_reads=observe_reads, progress=progress, stats=stats)
    source_id = store.import_source(
        kind="tenet",
        label=label or os.path.basename(path),
        epochs=det.epochs,
        params={"arch": arch.name, "page": page, "slide": stats.slide,
                "image_base": image_base, "rebase": stats.rebase,
                "path": os.path.basename(path), "stats": {
                    "lines": stats.lines, "instructions": stats.instructions,
                    "writes_kept": stats.writes_kept,
                    "writes_dropped": stats.writes_dropped,
                    "malformed": stats.malformed}},
    )
    if stats.observed:
        store.set_observed(source_id, stats.observed)
    return source_id


def _iter_lines(fh) -> Iterator[str]:
    for line in fh:
        yield line


def detect_arch(sample_lines: Iterable[str]) -> Optional[Arch]:
    """Best-effort arch guess from which PC register name appears first."""
    for raw in sample_lines:
        for token in raw.lower().split(","):
            key = token.partition("=")[0].strip()
            if key == "pc":
                return ARM64
            if key == "rip":
                return AMD64
            if key == "eip":
                return X86
    return None


# -- slide / module discovery ------------------------------------------------

def read_header(sample_lines: Iterable[str]) -> dict:
    """Header facts from the first lines: Frinet ``slide=`` and the first PCs."""
    out = {"slide": None, "pcs": []}
    for raw in sample_lines:
        for token in raw.split(","):
            key, _, value = token.strip().partition("=")
            key = key.strip().lower()
            try:
                if key == "slide" and out["slide"] is None:
                    out["slide"] = _to_int(value)
                elif key in _PC_ALIASES:
                    out["pcs"].append(_to_int(value))
            except ValueError:
                continue
    return out


def load_modules(path: str) -> list[dict]:
    """Parse a Frinet ``.modules`` map: ``<name> <start> <end>`` per line."""
    modules = []
    with open(path, "r", encoding="utf-8", errors="replace") as fh:
        for line in fh:
            parts = line.strip().rsplit(" ", 2)
            if len(parts) != 3:
                continue
            name, start, end = parts
            try:
                modules.append({"name": name, "start": int(start, 0), "end": int(end, 0)})
            except ValueError:
                continue
    return modules


def find_modules_file(trace_path: str) -> Optional[str]:
    """Frinet writes ``<proc>_<epoch>_<tid>.tenet`` next to ``<proc>_<epoch>.modules``."""
    base = trace_path[:-len(".tenet")] if trace_path.endswith(".tenet") else trace_path
    directory = os.path.dirname(trace_path) or "."
    candidates = [base + ".modules", base.rsplit("_", 1)[0] + ".modules"]
    for candidate in candidates:
        if os.path.exists(candidate):
            return candidate
    try:
        stem = os.path.basename(base).rsplit("_", 1)[0]
        for name in os.listdir(directory):
            if name.endswith(".modules") and name.startswith(stem):
                return os.path.join(directory, name)
    except OSError:
        pass
    return None


def module_for(modules: list[dict], module_name: str) -> Optional[dict]:
    wanted = os.path.basename(module_name).lower()
    for module in modules:
        if os.path.basename(module["name"]).lower() == wanted:
            return module
    return None


def load_manifest(trace_path: str) -> dict:
    """Optional ``<trace>.json`` / ``<trace>.dejadump.json`` import settings.

    Recognised keys: ``arch``, ``slide``, ``image_base``, ``module`` and
    ``keep`` (list of ``[start, end]``).  Numbers may be ints or ``"0x…"``.
    """
    for candidate in (trace_path + ".dejadump.json", trace_path + ".json"):
        if not os.path.exists(candidate):
            continue
        with open(candidate, "r", encoding="utf-8") as fh:
            raw = json.load(fh)
        if not isinstance(raw, dict):
            continue

        def num(value):
            return int(value, 0) if isinstance(value, str) else int(value)

        out = {"path": candidate}
        if isinstance(raw.get("arch"), str) and raw["arch"] in ARCHES:
            out["arch"] = raw["arch"]
        for key in ("slide", "image_base"):
            if raw.get(key) is not None:
                out[key] = num(raw[key])
        if isinstance(raw.get("module"), str):
            out["module"] = raw["module"]
        if isinstance(raw.get("keep"), list):
            out["keep"] = [(num(s), num(e)) for s, e in raw["keep"]]
        return out
    return {}


def detect_slide(pcs: Iterable[int], code: Iterable[tuple[int, int]],
                 align: int = PAGE, top: int = 4) -> Optional[int]:
    """Guess ``runtime - canonical`` from sampled PCs and the IDB's code ranges.

    If the PCs already fall inside the code ranges, no rebase is needed (``0``).
    Otherwise every page-aligned delta that maps a PC's page onto a code page is
    voted for, and the delta that places the most PCs inside code wins.
    """
    pcs = [int(pc) for pc in pcs]
    index = IntervalIndex(code)
    if not pcs or not index:
        return None
    inside = sum(1 for pc in pcs if index.contains(pc))
    if inside >= max(1, len(pcs) * 9 // 10):
        return 0
    starts = [s for s, _ in index.ranges()]
    votes: Counter = Counter()
    sample = pcs[:: max(1, len(pcs) // 256)]
    for pc in sample:
        for start in starts:
            votes[(pc & ~(align - 1)) - (start & ~(align - 1))] += 1
    best, best_hits = None, inside
    for delta, _count in votes.most_common(top * 8):
        hits = sum(1 for pc in pcs if index.contains(pc - delta))
        if hits > best_hits:
            best, best_hits = delta, hits
    if best is None or best_hits < max(1, len(pcs) // 2):
        return None
    return best


def pcs_in_code(pcs: Iterable[int], code: Iterable[tuple[int, int]], rebase: int) -> int:
    """How many of ``pcs`` fall inside ``code`` once moved by ``rebase``.

    Used to check a rebase that came from a header, manifest or ``.modules`` file
    against the IDB before trusting it.
    """
    index = IntervalIndex(code)
    return sum(1 for pc in pcs if index.contains(int(pc) + rebase))
