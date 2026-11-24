"""Interval helpers: the bisect IntervalSet matches the naive coalescing rules and
stays fast on scattered writes (the old list rebuild was quadratic)."""

import random
import time

from dejadump.core.intervals import IntervalIndex, IntervalSet, merge, subtract
from dejadump.core.waves import MemoryImage, WaveDetector


def _naive(intervals):
    covered = set()
    for s, e in intervals:
        covered.update(range(s, e))
    out, run = [], None
    for x in sorted(covered):
        if run and x == run[1]:
            run[1] = x + 1
        else:
            if run:
                out.append(tuple(run))
            run = [x, x + 1]
    if run:
        out.append(tuple(run))
    return out


def test_interval_set_matches_naive_coalescing():
    rng = random.Random(7)
    for _ in range(200):
        s = IntervalSet()
        added = []
        for _ in range(rng.randint(1, 30)):
            a = rng.randint(0, 200)
            b = a + rng.randint(0, 12)
            s.add(a, b)
            added.append((a, b))
        assert s.ranges() == _naive(added) == merge(added)
        probe = rng.randint(0, 210)
        assert s.overlaps(probe, probe + 3) == any(a < probe + 3 and b > probe
                                                   for a, b in _naive(added))


def test_scattered_writes_are_not_quadratic():
    det = WaveDetector(MemoryImage(), code_align=4)
    addrs = random.Random(1).sample(range(0x7F0000000, 0x7F0000000 + 40000 * 64, 16), 40000)
    began = time.perf_counter()
    for a in addrs:
        det.on_write(0x1000, a, b"\x11" * 8)
    assert time.perf_counter() - began < 5.0   # was ~90 s with the list rebuild
    det.finish()
    assert len(det.epochs[0].ranges) == 40000


def test_interval_index_queries():
    idx = IntervalIndex([(10, 20), (30, 40), (20, 25)])
    assert idx.ranges() == [(10, 25), (30, 40)]
    assert idx.contains(10) and idx.contains(24) and not idx.contains(25)
    assert idx.covers(12, 25) and not idx.covers(12, 26)
    assert idx.overlaps(24, 31) and not idx.overlaps(25, 30)
    assert idx.intersect(0, 35) == [(10, 25), (30, 35)]


def test_subtract():
    assert subtract([(0, 100)], [(10, 20), (50, 60)]) == [(0, 10), (20, 50), (60, 100)]
    assert subtract([(0, 10)], [(0, 10)]) == []
    assert subtract([(5, 15)], []) == [(5, 15)]
