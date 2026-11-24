"""Benchmark Tenet import throughput (R4 perf pass: 5M lines in < 3 min target).

Generates a synthetic trace (a stable code loop with periodic data writes — the hot
path: parse + wave detection + memory image + batched SQLite insert), then times
parse/detect and the store insert separately and projects the 5M-line time.

    python tools/bench_import.py [N]     # default 1,000,000
"""

from __future__ import annotations

import os
import sys
import tempfile
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from dejadump.core import tenet  # noqa: E402
from dejadump.core.store import EpochStore  # noqa: E402


def generate(path: str, n: int) -> None:
    code, span, data = 0x400000, 0x100, 0x500000
    k = 0
    with open(path, "w", encoding="utf-8") as fh:
        fh.write("slide=0x0\n")
        for i in range(n):
            pc = code + ((i * 4) % span)
            if i % 8 == 0:  # ~1 write per 8 instructions
                fh.write("rip=0x%x,mw=0x%x:%02x\n" % (pc, data + (k % 0x4000), i & 0xFF))
                k += 1
            else:
                fh.write("rip=0x%x\n" % pc)


def generate_scattered(path: str, n: int) -> None:
    """Stack/heap-like traffic: every write lands somewhere new (worst case for the
    dirty-interval set before it became bisect-based)."""
    with open(path, "w", encoding="utf-8") as fh:
        for i in range(n):
            fh.write("rip=0x%x,mw=0x%x:%016x\n" % (0x400000 + (i * 4) % 0x100,
                                                  0x7F0000000000 + i * 64, i))


def bench_scattered(tmp: str, n: int = 200_000) -> None:
    trace = os.path.join(tmp, "scattered.tenet")
    generate_scattered(trace, n)
    t = time.perf_counter()
    with open(trace, "r", encoding="utf-8") as fh:
        det, _ = tenet.import_trace(fh, arch=tenet.AMD64)
    elapsed = time.perf_counter() - t
    print("scattered     %6.2fs   (%s disjoint writes, %d dirty intervals)" % (
        elapsed, f"{n:,}", sum(len(e.ranges) for e in det.epochs)))


def main() -> int:
    n = int(sys.argv[1]) if len(sys.argv) > 1 else 1_000_000
    tmp = tempfile.mkdtemp(prefix="pal_bench_")
    trace = os.path.join(tmp, "bench.tenet")

    t = time.perf_counter()
    generate(trace, n)
    t_gen = time.perf_counter() - t

    t = time.perf_counter()
    with open(trace, "r", encoding="utf-8") as fh:  # streamed, not loaded whole
        det, _ = tenet.import_trace(fh, arch=tenet.AMD64)
    t_parse = time.perf_counter() - t

    store = EpochStore(os.path.join(tmp, "bench.db"), fast_import=True)
    t = time.perf_counter()
    store.import_source("tenet", "bench", det.epochs)
    t_store = time.perf_counter() - t
    store.close()

    writes = sum(len(e.writes) for e in det.epochs)
    total = t_parse + t_store
    print("lines=%s  writes=%s  epochs=%d" % (f"{n:,}", f"{writes:,}", len(det.epochs)))
    print("generate      %6.2fs" % t_gen)
    print("parse+detect  %6.2fs   (%.2f M lines/s)" % (t_parse, n / t_parse / 1e6))
    print("store insert  %6.2fs" % t_store)
    print("IMPORT total  %6.2fs   -> 5M projected %5.1fs (target < 180s)"
          % (total, total * 5e6 / n))
    bench_scattered(tmp)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
