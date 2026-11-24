"""MemoryTimeline: read-through values per epoch, change flags, first-plaintext,
and writer provenance — exercised on the committed ARM64 corpus."""

import json
import os

from dejadump.core import tenet
from dejadump.core.state import BytesBase, StateResolver
from dejadump.core.store import EpochStore
from dejadump.core.timeline import MemoryTimeline, is_textlike

FIX = os.path.join(os.path.dirname(__file__), "..", "fixtures")
TRACE = os.path.join(FIX, "arm64_smc.tenet")
BUF = 0x200000
DATA = 0x300000


def _base():
    with open(os.path.join(FIX, "manifest.json")) as fh:
        manifest = json.load(fh)
    segs = []
    for name in ("code", "buf", "data"):
        d = manifest["dumps"][name]
        with open(os.path.join(FIX, d["path"]), "rb") as fh:
            segs.append((d["base"], fh.read()))
    return BytesBase(segs)


def _timeline():
    store = EpochStore(":memory:")
    tenet.import_trace_file(TRACE, store, arch=tenet.ARM64)
    resolver = StateResolver(store.load_epochs(), base=_base())
    return MemoryTimeline(resolver, writer_lookup=store.writes_for_addr), store


def test_is_textlike():
    assert is_textlike(b"DEJADUMP_OK!!!!\x00")
    assert not is_textlike(bytes([0x52, 0x80, 0x15, 0x49]))  # arm64 code bytes


def test_first_plaintext_epoch_is_the_decryption_wave():
    tl, store = _timeline()
    # DATA is ciphertext at t0..t3 and becomes "DEJADUMP_OK!!!!" at the final epoch.
    k = tl.first_plaintext_epoch(DATA, 16)
    assert k == 4
    assert tl.column(k, DATA, 16) == b"DEJADUMP_OK!!!!\x00"
    assert not is_textlike(tl.column(0, DATA, 16))  # t0 ciphertext


def test_code_byte_changes_across_waves():
    tl, _ = _timeline()
    # First byte of the stub's MOVZ encodes the per-version marker, so it differs.
    assert tl.value(BUF, 1) != tl.value(BUF, 3)
    assert tl.changed(BUF, 1)  # base(0) -> v1
    assert tl.changed(BUF, 2)  # v1 -> v2
    assert tl.changed(BUF, 3)  # v2 -> v3
    assert not tl.changed(BUF, 0)


def test_writer_provenance_points_into_the_mutator():
    tl, _ = _timeline()
    writers = tl.writers(DATA)  # the in-place decryption store(s)
    assert writers
    assert all(0x100000 <= w["writer_pc"] < 0x102000 for w in writers)
    assert writers[-1]["epoch_seq"] == 4
