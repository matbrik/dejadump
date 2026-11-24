"""R1 exit gate: the committed ARM64 SMC trace imports into >=3 epochs with
correct boundaries, distinct per-version code, and writer PCs in the mutator.

Reads the committed fixture only (no Unicorn needed), so it runs anywhere.
"""

import os

from dejadump.core.store import EpochStore
from dejadump.core.tenet import ARM64, import_trace

FIXTURE = os.path.join(os.path.dirname(__file__), "..", "fixtures", "arm64_smc.tenet")

CODE_LO, CODE_HI = 0x100000, 0x102000
BUF_LO, BUF_HI = 0x200000, 0x201000
DATA = 0x300000
PLAINTEXT = b"DEJADUMP_OK!!!!\x00"


def _lines():
    with open(FIXTURE, "r", encoding="utf-8") as fh:
        return fh.readlines()


def test_fixture_exists():
    assert os.path.exists(FIXTURE), "run: python -m tools.mkcorpus --outdir tests/fixtures"


def test_at_least_three_epochs_with_correct_boundaries():
    det, _ = import_trace(_lines(), arch=ARM64)
    epochs = det.epochs
    assert len(epochs) >= 3
    waves = [e for e in epochs if e.boundary_kind == "wave"]
    assert len(waves) >= 3, "the stub is overwritten 3x -> 3 wave boundaries"
    assert epochs[-1].boundary_kind == "end"  # trailing data decryption


def test_three_distinct_code_versions_at_one_address():
    det, _ = import_trace(_lines(), arch=ARM64)
    versions = []
    for e in det.epochs:
        for r in e.ranges:
            if r.start == BUF_LO:
                versions.append(r.sha256)
    assert len(versions) >= 3
    assert len(set(versions)) >= 3, "BUF holds a different code version per wave"


def test_writes_to_buf_are_attributed_to_the_mutator():
    # Validates the writer-PC lag end to end: every store into BUF comes from a
    # mutator instruction in CODE, never from BUF/DATA.
    det, _ = import_trace(_lines(), arch=ARM64)
    buf_writers = [
        w.writer_pc
        for e in det.epochs
        for w in e.writes
        if BUF_LO <= w.addr < BUF_HI
    ]
    assert buf_writers, "expected writes into BUF"
    assert all(CODE_LO <= pc < CODE_HI for pc in buf_writers)


def test_data_table_decrypts_to_plaintext_in_final_epoch():
    det, _ = import_trace(_lines(), arch=ARM64)
    final = det.epochs[-1]
    hit = [r for r in final.ranges if r.start == DATA and r.data == PLAINTEXT]
    assert hit, "final epoch should expose the decrypted table as plaintext"


def test_round_trips_through_the_store():
    det, _ = import_trace(_lines(), arch=ARM64)
    store = EpochStore(":memory:")
    store.import_source("tenet", "arm64_smc", det.epochs,
                        params={"arch": "arm64"})
    assert len(store.epochs()) == len(det.epochs)
    # BUF is part of the volatile set.
    assert any(lo <= BUF_LO < hi for lo, hi in store.volatile_set())
    store.close()
