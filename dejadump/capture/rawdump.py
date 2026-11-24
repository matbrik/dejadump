"""Dump-based capture: diff successive images of one module into epochs.

Two input layouts are supported:

* **File layout** (``import_elf_pair`` / ``import_image_pair``): a before/after pair
  of the *file* — e.g. a library that is ciphertext on disk and a decrypted copy
  written by a static unpacker.  ELF file offsets are mapped to virtual addresses
  through the program headers so the epochs line up with how IDA loads the file.
* **Memory layout** (``import_memory_dumps``): raw memory dumps that start at a
  given virtual address — what GDB ``dump binary memory``, LLDB ``memory read
  --binary``, Frida ``Memory.readByteArray``, pe-sieve or ``/proc/<pid>/mem``
  produce.  Each dump is diffed against the bytes already loaded in the IDB (or
  the previous dump) and becomes the next epoch.

Each later image becomes an epoch holding only the bytes that changed from the
previous one (``boundary_kind='dump'``); image 0 is the base (t0), i.e. what IDA
already shows when you open the module.  Also provides the inverse — writing an
epoch back into a copy of the input file — and simple "does this look like code
now?" metrics.  Pure Python.
"""

from __future__ import annotations

import collections
import math
import struct
from typing import Callable, Iterable, Optional

from ..core.intervals import IntervalIndex, merge, subtract
from ..core.model import Epoch, Range, WriteRecord

PT_LOAD = 1
PF_X = 1


def _elf_header(data: bytes):
    """Return ``(is64, endian_prefix)`` for an ELF image, else raise ``ValueError``."""
    if data[:4] != b"\x7fELF":
        raise ValueError("not an ELF image")
    klass, encoding = data[4], data[5]
    if klass not in (1, 2):
        raise ValueError("unsupported ELF class %d" % klass)
    if encoding not in (1, 2):
        raise ValueError("unsupported ELF data encoding %d" % encoding)
    return klass == 2, "<" if encoding == 1 else ">"


def _elf_loads(data: bytes) -> list[tuple[int, int, int, int]]:
    """Return PT_LOAD segments as ``(offset, vaddr, filesz, flags)`` (ELF32 or ELF64)."""
    is64, en = _elf_header(data)
    if is64:
        e_phoff = struct.unpack_from(en + "Q", data, 32)[0]
        e_phentsize, e_phnum = struct.unpack_from(en + "HH", data, 54)
    else:
        e_phoff = struct.unpack_from(en + "I", data, 28)[0]
        e_phentsize, e_phnum = struct.unpack_from(en + "HH", data, 42)
    loads = []
    for i in range(e_phnum):
        off = e_phoff + i * e_phentsize
        if struct.unpack_from(en + "I", data, off)[0] != PT_LOAD:
            continue
        if is64:
            p_flags = struct.unpack_from(en + "I", data, off + 4)[0]
            p_offset, p_vaddr = struct.unpack_from(en + "QQ", data, off + 8)
            p_filesz = struct.unpack_from(en + "Q", data, off + 32)[0]
        else:
            p_offset, p_vaddr = struct.unpack_from(en + "II", data, off + 4)
            p_filesz = struct.unpack_from(en + "I", data, off + 16)[0]
            p_flags = struct.unpack_from(en + "I", data, off + 24)[0]
        loads.append((p_offset, p_vaddr, p_filesz, p_flags))
    return loads


def _elf_entry(data: bytes) -> int:
    is64, en = _elf_header(data)
    return struct.unpack_from(en + ("Q" if is64 else "I"), data, 24)[0]


def _foff_to_vaddr(loads, foff: int):
    for p_offset, p_vaddr, p_filesz, _flags in loads:
        if p_offset <= foff < p_offset + p_filesz:
            return p_vaddr + (foff - p_offset)
    return None


def _foff_mapping(loads, foff: int):
    for p_offset, p_vaddr, p_filesz, flags in loads:
        if p_offset <= foff < p_offset + p_filesz:
            return p_vaddr + (foff - p_offset), bool(flags & PF_X)
    return None


def _vaddr_to_foff(loads, vaddr: int, size: int) -> list[tuple[int, int, int]]:
    """File pieces backing ``[vaddr, vaddr+size)``: ``(vaddr, foff, length)``."""
    out = []
    for p_offset, p_vaddr, p_filesz, _flags in loads:
        lo, hi = max(vaddr, p_vaddr), min(vaddr + size, p_vaddr + p_filesz)
        if lo < hi:
            out.append((lo, p_offset + (lo - p_vaddr), hi - lo))
    return out


def changed_ranges(a: bytes, b: bytes, gap: int = 64) -> list[tuple[int, int]]:
    """Byte ranges where ``a`` and ``b`` differ, coalescing gaps ≤ ``gap``."""
    n = min(len(a), len(b))
    out: list[tuple[int, int]] = []
    start = last = None
    block = 256
    i = 0
    while i < n:
        # Skip identical blocks without a per-byte Python loop.
        if start is None and a[i:i + block] == b[i:i + block]:
            i += block
            continue
        if a[i] != b[i]:
            if start is None:
                start = i
            last = i
        elif start is not None and i - last > gap:
            out.append((start, last + 1))
            start = None
        i += 1
    if start is not None:
        out.append((start, last + 1))
    return out


def _pair_epoch(img0: bytes, img1: bytes, addr_of, gap, seq, label, entry_points=()):
    ranges, writes = [], []
    base_updates = []
    for s, e in changed_ranges(img0, img1, gap=gap):
        mapping = addr_of(s)
        if mapping is None:
            continue
        va, is_code = mapping if isinstance(mapping, tuple) else (mapping, None)
        new, old = img1[s:e], img0[s:e]
        # A changed-range start is not a program entry: it can be a byte in the
        # middle of an instruction or embedded data. Only loader-backed entry
        # points are safe analysis seeds.
        entries = tuple(pc for pc in entry_points if va <= pc < va + len(new))
        ranges.append(Range(va, new, entry_pcs=entries if is_code else (),
                            is_code_hint=is_code))
        writes.append(WriteRecord(None, va, new, old_bytes=old))
        base_updates.append((va, old))
    return Epoch(seq=seq, ranges=ranges, writes=writes, boundary_kind="dump", label=label), base_updates


def _set_missing_base(store, base_updates) -> None:
    """Record t0 bytes only where no snapshot exists yet (never overwrite t0)."""
    covered = store.base_coverage()
    for va, old in base_updates:
        for lo, hi in subtract([(va, va + len(old))], covered):
            store.set_base_range(lo, old[lo - va:hi - va])
        covered = merge(covered + [(va, va + len(old))])


def import_image_pair(store, img0: bytes, img1: bytes, base: int = 0,
                      gap: int = 64, label: str = "dump") -> Epoch:
    """Diff a flat before/after pair (address = ``base`` + file offset)."""
    ep, base_updates = _pair_epoch(img0, img1, lambda o: base + o, gap, 1, label)
    _set_missing_base(store, base_updates)
    store.import_source("dump", label, [ep], params={"layout": "flat", "base": base})
    return ep


def import_elf_pair(store, enc: bytes, dec: bytes, gap: int = 64,
                    label: str = "decrypted") -> Epoch:
    """Diff an encrypted→decrypted ELF pair (file layout), mapping offsets to vaddrs.

    Image 0 (``enc``) is the base (t0, what IDA shows when the on-disk module is
    opened); epoch t1 holds the decrypted regions at their vaddrs.
    """
    loads = _elf_loads(enc)
    e_entry = _elf_entry(enc)
    entries = (e_entry,) if e_entry else ()
    ep, base_updates = _pair_epoch(
        enc, dec, lambda o: _foff_mapping(loads, o), gap, 1, label, entries)
    _set_missing_base(store, base_updates)
    store.import_source("dump", label, [ep], params={"layout": "elf-file"})
    return ep


def memory_dump_epochs(
    reader: Callable[[int, int], bytes],
    dumps: Iterable[tuple[int, bytes]],
    *,
    mapped: Optional[Iterable[tuple[int, int]]] = None,
    is_exec: Optional[Callable[[int], Optional[bool]]] = None,
    gap: int = 64,
    labels: Optional[list[str]] = None,
) -> tuple[list[Epoch], list[tuple[int, bytes]]]:
    """Turn memory-layout dumps into successive epochs.

    ``reader(addr, size)`` returns the bytes loaded in the IDB (t0).  Each dump is
    ``(base_address, data)``; dump *i* is diffed against the state after dump
    *i−1* (initially the IDB), restricted to ``mapped`` intervals when given.
    Returns ``(epochs, base_updates)`` where ``base_updates`` are the t0 bytes of
    every changed range.
    """
    mapped_index = IntervalIndex(mapped) if mapped is not None else None
    current: dict[int, bytes] = {}
    epochs: list[Epoch] = []
    base_updates: list[tuple[int, bytes]] = []
    for index, (base, data) in enumerate(dumps):
        windows = (mapped_index.intersect(base, base + len(data))
                   if mapped_index is not None else [(base, base + len(data))])
        ranges, writes = [], []
        for lo, hi in windows:
            new = data[lo - base:hi - base]
            original = bytes(reader(lo, hi - lo) or b"")
            if len(original) != len(new):
                continue
            before = bytearray(original)
            for start, blob in current.items():
                s, e = max(start, lo), min(start + len(blob), hi)
                if s < e:
                    before[s - lo:e - lo] = blob[s - start:e - start]
            for s, e in changed_ranges(bytes(before), new, gap=gap):
                va = lo + s
                chunk = new[s:e]
                ranges.append(Range(va, chunk, is_code_hint=is_exec(va) if is_exec else None))
                writes.append(WriteRecord(None, va, chunk, old_bytes=bytes(before[s:e])))
                base_updates.append((va, original[s:e]))
            current[lo] = new
        if not ranges:
            continue
        label = labels[index] if labels and index < len(labels) else "dump %d" % (index + 1)
        epochs.append(Epoch(seq=len(epochs) + 1, ranges=ranges, writes=writes,
                            boundary_kind="dump", label=label))
    return epochs, base_updates


def import_memory_dumps(store, reader, dumps, *, mapped=None, is_exec=None, gap: int = 64,
                        label: str = "memory dumps", labels=None) -> list[Epoch]:
    """Import memory-layout dumps as one new source (see :func:`memory_dump_epochs`)."""
    epochs, base_updates = memory_dump_epochs(reader, dumps, mapped=mapped, is_exec=is_exec,
                                              gap=gap, labels=labels)
    if not epochs:
        return []
    _set_missing_base(store, base_updates)
    store.import_source("dump", label, epochs, params={
        "layout": "memory", "dumps": [{"base": base, "size": len(data)} for base, data in dumps]})
    return epochs


# -- export ---------------------------------------------------------------------

def export_image(original: bytes, state: Callable[[int, int], bytes],
                 volatile: Iterable[tuple[int, int]], *, base: int = 0) -> bytes:
    """Write epoch bytes back into a copy of the input file.

    ``state(addr, size)`` returns the epoch's bytes; only the ``volatile`` extents
    are written.  ELF inputs use their program headers (bytes without file backing,
    e.g. ``.bss``, are skipped); anything else is treated as a flat image loaded at
    ``base``.
    """
    out = bytearray(original)
    try:
        loads = _elf_loads(original)
    except ValueError:
        loads = None
    for start, end in volatile:
        if loads is not None:
            pieces = _vaddr_to_foff(loads, start, end - start)
        else:
            lo, hi = max(start, base), min(end, base + len(original))
            pieces = [(lo, lo - base, hi - lo)] if lo < hi else []
        for vaddr, foff, length in pieces:
            out[foff:foff + length] = state(vaddr, length)
    return bytes(out)


# -- metrics ----------------------------------------------------------------------

_ARM64_PROLOGUE = b"\xfd\x7b"            # stp x29, x30, [...]
_ARM64_RET = bytes.fromhex("c0035fd6")
_X64_PROLOGUE = b"\x55\x48\x89\xe5"       # push rbp; mov rbp, rsp
_X64_ENDBR = b"\xf3\x0f\x1e\xfa"


def entropy(data: bytes) -> float:
    if not data:
        return 0.0
    counts = collections.Counter(data)
    n = len(data)
    return -sum((v / n) * math.log2(v / n) for v in counts.values())


def code_metrics(data: bytes) -> dict:
    """Cheap "is this code yet?" signals for a byte range."""
    return {
        "entropy": round(entropy(data), 2),
        "arm64_prologues": data.count(_ARM64_PROLOGUE),
        "arm64_rets": data.count(_ARM64_RET),
        "x64_prologues": data.count(_X64_PROLOGUE) + data.count(_X64_ENDBR),
    }


def describe_change(before: bytes, after: bytes) -> str:
    """One-line before→after summary for import dialogs and tools."""
    a, b = code_metrics(before), code_metrics(after)
    return ("entropy %.2f → %.2f · arm64 prologues %d → %d · arm64 rets %d → %d · "
            "x86-64 prologues %d → %d" % (
                a["entropy"], b["entropy"], a["arm64_prologues"], b["arm64_prologues"],
                a["arm64_rets"], b["arm64_rets"], a["x64_prologues"], b["x64_prologues"]))
