"""Temporal cross-references: one location written across several epochs yields
several (epoch, writer) pairs — the data behind "press X here, see all the times
this address was written" and `materialize_write_xrefs`."""

import os

from dejadump.core import tenet
from dejadump.core.store import EpochStore

FIX = os.path.join(os.path.dirname(__file__), "..", "fixtures")


def _store(name, arch):
    s = EpochStore(":memory:")
    tenet.import_trace_file(os.path.join(FIX, name), s, arch=arch)
    return s


def test_buf_location_xrefs_across_three_epochs_arm64():
    s = _store("arm64_smc.tenet", tenet.ARM64)
    writers = s.writers_of(0x200000)  # the stub's first word, rewritten each wave
    assert len(writers) >= 3
    assert len({w["epoch_seq"] for w in writers}) >= 3      # three distinct times
    assert len({w["writer_pc"] for w in writers}) >= 3      # three distinct writers
    assert all(0x100000 <= w["writer_pc"] < 0x102000 for w in writers)  # in the mutator
    s.close()


def test_buf_location_xrefs_across_three_epochs_x64():
    s = _store("x64_smc.tenet", tenet.AMD64)
    writers = s.writers_of(0x200000)
    assert len({w["epoch_seq"] for w in writers}) >= 3
    assert all(0x100000 <= w["writer_pc"] < 0x102000 for w in writers)
    s.close()


def test_writers_of_is_deduped_and_ordered():
    s = _store("arm64_smc.tenet", tenet.ARM64)
    writers = s.writers_of(0x200000)
    seqs = [w["epoch_seq"] for w in writers]
    assert seqs == sorted(seqs)                       # ordered by epoch
    assert len(set((w["epoch_seq"], w["writer_pc"]) for w in writers)) == len(writers)  # deduped
    s.close()
