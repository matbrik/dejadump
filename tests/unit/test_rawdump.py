"""Dump-pair importer: offset→vaddr mapping and read-through over an ELF pair.

Uses synthetic ELFs (no external binaries). Real encrypted→decrypted libraries are
checked out-of-tree with tools/verify_image_pair.py."""

from dejadump.capture.rawdump import changed_ranges, import_elf_pair
from dejadump.core.state import StateResolver
from dejadump.core.store import EpochStore
from tools.mkcorpus.elf import EM_AARCH64, PF_R, PF_W, PF_X, build_elf


def _elf(code: bytes) -> bytes:
    segs = [(0x100000, code, PF_R | PF_X), (0x300000, b"\x00" * 0x40, PF_R | PF_W)]
    return build_elf(segs, entry=0x100000, machine=EM_AARCH64)


def test_changed_ranges_gap_coalesce():
    a = b"\x00" * 32
    b = bytearray(a)
    b[4] = 1
    b[6] = 1
    assert changed_ranges(a, bytes(b), gap=4) == [(4, 7)]        # merged over the gap
    assert changed_ranges(a, bytes(b), gap=0) == [(4, 5), (6, 7)]


def test_elf_pair_maps_offsets_to_vaddr_and_reads_through():
    enc = _elf(b"\xAA" * 0x100 + b"\x00" * 0x100)
    dec = _elf(b"\xAA" * 0x100 + b"\x11" * 0x100)   # second half of CODE "decrypted"
    store = EpochStore(":memory:")
    ep = import_elf_pair(store, enc, dec)

    assert ep.boundary_kind == "dump"
    r = [r for r in ep.ranges if r.start == 0x100100]
    assert r and r[0].data == b"\x11" * 0x100        # vaddr mapped from file offset 0x1100

    res = StateResolver(store.load_epochs(), base=store.base_source())
    assert res.state(0, 0x100100, 0x100) == b"\x00" * 0x100   # t0 = on-disk base
    assert res.state(1, 0x100100, 0x100) == b"\x11" * 0x100   # t1 = decrypted
    store.close()


# -- ELF32, memory-layout dumps, export, metrics --------------------------------

import struct  # noqa: E402

from dejadump.capture import rawdump  # noqa: E402


def _elf32(code: bytes, vaddr=0x8000) -> bytes:
    """Minimal little-endian ELF32 with one PT_LOAD (R+X) at file offset 0x1000."""
    ehdr = b"\x7fELF" + bytes([1, 1, 1, 0]) + b"\x00" * 8 + struct.pack(
        "<HHIIIIIHHHHHH", 2, 40, 1, vaddr, 52, 0, 0, 52, 32, 1, 0, 0, 0)
    phdr = struct.pack("<IIIIIIII", 1, 0x1000, vaddr, vaddr, len(code), len(code), 5, 0x1000)
    image = bytearray(0x1000 + len(code))
    image[:len(ehdr)] = ehdr
    image[52:52 + len(phdr)] = phdr
    image[0x1000:] = code
    return bytes(image)


def test_elf32_pair_maps_offsets():
    enc = _elf32(b"\x00" * 0x40)
    dec = _elf32(b"\x00" * 0x20 + b"\x11" * 0x20)
    assert rawdump._elf_loads(enc) == [(0x1000, 0x8000, 0x40, 5)]
    store = EpochStore(":memory:")
    ep = import_elf_pair(store, enc, dec)
    assert [(r.start, r.size, r.is_code_hint) for r in ep.ranges] == [(0x8020, 0x20, True)]


def test_memory_dumps_become_successive_epochs_against_the_idb():
    idb = {0x1000: b"\x00" * 0x100}

    def reader(addr, size):
        return idb[0x1000][addr - 0x1000:addr - 0x1000 + size]

    first = bytearray(0x100)
    first[0x10:0x20] = b"\x22" * 0x10
    second = bytearray(first)
    second[0x80:0x84] = b"\x33" * 4
    store = EpochStore(":memory:")
    epochs = rawdump.import_memory_dumps(
        store, reader, [(0x1000, bytes(first)), (0x1000, bytes(second)), (0x1000, bytes(second))],
        mapped=[(0x1000, 0x1100)], is_exec=lambda a: True, labels=["a", "b", "c"])
    assert [e.seq for e in epochs] == [1, 2]                  # identical third dump adds nothing
    assert [(r.start, r.size) for r in epochs[0].ranges] == [(0x1010, 0x10)]
    assert [(r.start, r.size) for r in epochs[1].ranges] == [(0x1080, 4)]
    res = StateResolver(store.load_epochs(), base=store.base_source())
    assert res.state(0, 0x1010, 4) == b"\x00" * 4
    assert res.state(2, 0x1080, 4) == b"\x33" * 4


def test_dumps_outside_mapped_segments_are_ignored():
    store = EpochStore(":memory:")
    epochs = rawdump.import_memory_dumps(
        store, lambda a, n: b"\x00" * n, [(0x0, b"\x99" * 0x40)], mapped=[(0x20, 0x30)])
    assert [(r.start, r.size) for r in epochs[0].ranges] == [(0x20, 0x10)]


def test_export_writes_the_epoch_back_into_the_file():
    enc = _elf(b"\xAA" * 0x100 + b"\x00" * 0x100)
    dec = _elf(b"\xAA" * 0x100 + b"\x11" * 0x100)
    store = EpochStore(":memory:")
    import_elf_pair(store, enc, dec)
    res = StateResolver(store.load_epochs(), base=store.base_source())
    out = rawdump.export_image(enc, lambda a, n: res.state(1, a, n), store.volatile_set())
    assert out == dec
    back = rawdump.export_image(dec, lambda a, n: res.state(0, a, n), store.volatile_set())
    assert back == enc


def test_flat_export_uses_the_load_base():
    original = b"\x00" * 16
    out = rawdump.export_image(original, lambda a, n: b"\x77" * n, [(0x404, 0x408)], base=0x400)
    assert out == b"\x00" * 4 + b"\x77" * 4 + b"\x00" * 8


def test_code_metrics_tell_ciphertext_from_code():
    import os

    code = (bytes.fromhex("fd7bbfa9") + b"\x00" * 12 + bytes.fromhex("c0035fd6")) * 64
    text = rawdump.describe_change(os.urandom(len(code)), code)
    assert "arm64 prologues 0 → 64" in text and "arm64 rets 0 → 64" in text
