"""The x86-64 corpus imports to the same epoch structure as ARM64 — proving the
engine is architecture-agnostic (one idea, two ISAs, identical handling)."""

import json
import os

from dejadump.core import tenet
from dejadump.core.state import BytesBase, StateResolver
from dejadump.core.store import EpochStore
from dejadump.core.timeline import MemoryTimeline

FIX = os.path.join(os.path.dirname(__file__), "..", "fixtures")
TRACE = os.path.join(FIX, "x64_smc.tenet")
CODE_LO, CODE_HI = 0x100000, 0x102000
BUF = 0x200000
DATA = 0x300000
PLAINTEXT = b"DEJADUMP_OK!!!!\x00"


def _lines():
    with open(TRACE, "r", encoding="utf-8") as fh:
        return fh.readlines()


def test_arch_autodetected_as_amd64():
    assert tenet.detect_arch(_lines()[:5]).name == "amd64"


def test_x64_imports_three_distinct_versions_and_plaintext():
    det, _ = tenet.import_trace(_lines(), arch=tenet.AMD64)
    assert [e.boundary_kind for e in det.epochs] == ["wave", "wave", "wave", "end"]
    versions = {r.sha256 for e in det.epochs for r in e.ranges if r.start == BUF}
    assert len(versions) == 3

    store = EpochStore(":memory:")
    tenet.import_trace_file(TRACE, store, arch=tenet.AMD64)
    with open(os.path.join(FIX, "manifest.json")) as fh:
        m = json.load(fh)["x64"]
    base = BytesBase([(m["dumps"][n]["base"],
                       open(os.path.join(FIX, m["dumps"][n]["path"]), "rb").read())
                      for n in ("code", "buf", "data")])
    tl = MemoryTimeline(StateResolver(store.load_epochs(), base=base), store.writes_for_addr)
    assert tl.first_plaintext_epoch(DATA, 16) == 4
    assert tl.column(4, DATA, 16) == PLAINTEXT


def test_x64_writer_pc_lag_points_into_mutator():
    det, _ = tenet.import_trace(_lines(), arch=tenet.AMD64)
    buf_writers = [w.writer_pc for e in det.epochs for w in e.writes if BUF <= w.addr < BUF + 0x1000]
    assert buf_writers
    assert all(CODE_LO <= pc < CODE_HI for pc in buf_writers)
