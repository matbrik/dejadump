"""Check that an encrypted→decrypted (or packed→unpacked) image pair imports as
real code — out-of-tree, on any binary you are allowed to analyse.

    python tools/verify_image_pair.py <before> <after>          # ELF: file layout
    python tools/verify_image_pair.py <before> <after> --flat 0x400000

Imports the pair as t0/t1 (the same code path as Edit → DejaDump → Import →
Import decrypted image pair…) and reports, for the largest changed region, the
entropy and the counts of common arm64 / x86-64 prologues and returns before and
after.  Ciphertext sits near 8.0 bits/byte with almost no prologues; code drops
to ~6–6.5 with many.  No binaries are bundled with this repository.
"""

from __future__ import annotations

import argparse
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from dejadump.capture import rawdump  # noqa: E402
from dejadump.core.state import StateResolver  # noqa: E402
from dejadump.core.store import EpochStore  # noqa: E402


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("before")
    parser.add_argument("after")
    parser.add_argument("--flat", type=lambda v: int(v, 0), metavar="BASE",
                        help="treat the inputs as flat images loaded at BASE")
    args = parser.parse_args(argv)
    with open(args.before, "rb") as fh:
        before = fh.read()
    with open(args.after, "rb") as fh:
        after = fh.read()
    store = EpochStore(":memory:")
    if args.flat is not None or before[:4] != b"\x7fELF":
        epoch = rawdump.import_image_pair(store, before, after, base=args.flat or 0)
    else:
        epoch = rawdump.import_elf_pair(store, before, after)
    if not epoch.ranges:
        print("VERIFY: no differences — the images are identical where mapped.")
        return 1
    changed = sum(r.size for r in epoch.ranges)
    print("t1: %d region(s), %s changed byte(s)" % (len(epoch.ranges), f"{changed:,}"))
    resolver = StateResolver(store.load_epochs(), base=store.base_source())
    big = max(epoch.ranges, key=lambda r: r.size)
    span = min(big.size, 0x40000)
    t0, t1 = resolver.state(0, big.start, span), resolver.state(1, big.start, span)
    print("largest region @ 0x%x size 0x%x (sampled 0x%x)" % (big.start, big.size, span))
    print("  " + rawdump.describe_change(t0, t1))
    a, b = rawdump.code_metrics(t0), rawdump.code_metrics(t1)
    prologues = max(b["arm64_prologues"], b["x64_prologues"])
    looks_like_code = (b["entropy"] < a["entropy"] and
                       prologues > 5 * max(a["arm64_prologues"], a["x64_prologues"], 1))
    print("VERIFY:", "PASS — t1 looks like real code" if looks_like_code
          else "CHECK — see the values above")
    store.close()
    return 0 if looks_like_code else 1


if __name__ == "__main__":
    raise SystemExit(main())
