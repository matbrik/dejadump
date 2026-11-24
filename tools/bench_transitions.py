"""Benchmark transition planning and artifact-cache lookup on a copied sidecar.

Usage: ``python tools/bench_transitions.py sample.dejadump.db [source] [target]``.
This is pure Python and never opens or mutates an IDB.
"""

from __future__ import annotations

import statistics
import os
import sys
import time

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

from dejadump.core.state import StateResolver  # noqa: E402
from dejadump.core.store import EpochStore  # noqa: E402


def timed(call, count=5):
    values, result = [], None
    for _ in range(count):
        began = time.perf_counter()
        result = call()
        values.append((time.perf_counter() - began) * 1000)
    return result, values


def main(path: str, source: int = 0, target: int = 1) -> int:
    store = EpochStore(path)
    try:
        resolver = StateResolver(store.load_epochs(), store.base_source())

        def reader(addr, size, k=source):
            return resolver.state(k, addr, size)

        plan, timings = timed(lambda: resolver.activation_plan(
            source, target, reader, source_ref=store.epoch_ref(source),
            target_ref=store.epoch_ref(target)))
        print("transition t%d -> t%d" % (source, target))
        print("volatile ranges :", len(resolver.volatile_set()))
        print("changed spans   :", len(plan.chunks))
        print("changed bytes   :", plan.bytes_changed)
        print("planning ms     : median=%.2f min=%.2f max=%.2f" %
              (statistics.median(timings), min(timings), max(timings)))

        rows = store.conn.execute(
            "SELECT epoch_id,kind,start,end,version_key FROM analysis_artifacts LIMIT 1"
        ).fetchone()
        if rows:
            epoch_id, kind, start, end, version = rows
            epoch = next((store.epoch_ref(e["seq"]) for e in store.epochs()
                          if e["id"] == epoch_id), store.epoch_ref(0))
            _artifact, cache = timed(
                lambda: store.get_artifact(epoch, kind, start, end, version), count=100)
            print("artifact lookup : median=%.3f ms" % statistics.median(cache))
        else:
            print("artifact lookup : skipped (cache is empty)")
    finally:
        store.close()
    return 0


if __name__ == "__main__":
    if len(sys.argv) < 2:
        raise SystemExit("usage: bench_transitions.py SIDECAR [SOURCE_EPOCH] [TARGET_EPOCH]")
    raise SystemExit(main(sys.argv[1], *(int(v) for v in sys.argv[2:4])))
