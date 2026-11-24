"""Minimal AArch64 ELF writer (pure stdlib) for the corpus.

Wrapping the CODE/BUF/DATA regions in an ELF with ``EM_AARCH64`` + ELFCLASS64 lets
IDA auto-detect the processor and bitness and create the segments at the right
virtual addresses — no flat-binary "which processor?" / 32-vs-64 guessing, and no
``set_processor_type`` after load (which fails once a database has a processor).
"""

from __future__ import annotations

import struct

PT_LOAD = 1
EM_AARCH64 = 183
EM_X86_64 = 62
PF_X, PF_W, PF_R = 1, 2, 4
_PAGE = 0x1000


def build_elf(segments: list[tuple[int, bytes, int]], entry: int,
              machine: int = EM_AARCH64) -> bytes:
    """``segments`` = ``[(vaddr, data, p_flags), …]`` (vaddrs page-aligned)."""
    ehsize, phentsize = 64, 56
    phoff = ehsize
    phnum = len(segments)

    # Place each segment's bytes at a page-aligned file offset so that
    # p_offset % p_align == p_vaddr % p_align (both 0 here).
    offsets = []
    cur = _PAGE
    for _vaddr, data, _flags in segments:
        offsets.append(cur)
        cur = (cur + len(data) + _PAGE - 1) & ~(_PAGE - 1)
    total = cur

    e_ident = b"\x7fELF" + bytes([2, 1, 1, 0]) + b"\x00" * 8
    ehdr = e_ident + struct.pack(
        "<HHIQQQIHHHHHH",
        2,            # e_type = ET_EXEC
        machine,      # e_machine
        1,            # e_version
        entry,        # e_entry
        phoff,        # e_phoff
        0,            # e_shoff (no section headers)
        0,            # e_flags
        ehsize,       # e_ehsize
        phentsize,    # e_phentsize
        phnum,        # e_phnum
        0, 0, 0,      # e_shentsize, e_shnum, e_shstrndx
    )

    phdrs = b""
    for (vaddr, data, flags), off in zip(segments, offsets):
        phdrs += struct.pack(
            "<IIQQQQQQ",
            PT_LOAD, flags, off, vaddr, vaddr, len(data), len(data), _PAGE,
        )

    buf = bytearray(total)
    buf[0:len(ehdr)] = ehdr
    buf[phoff:phoff + len(phdrs)] = phdrs
    for (vaddr, data, flags), off in zip(segments, offsets):
        buf[off:off + len(data)] = data
    return bytes(buf)
