"""Write memory-layout dumps of the demo corpus, one per epoch, for the dump-import demo.

    python tools/make_demo_dumps.py [--x64] [--outdir DIR] [--region buf|data|code]

Replays the committed trace headless and writes ``<region>_t<k>.bin`` files that
look exactly like what GDB ``dump binary memory`` or Frida would produce for that
region at each epoch.  Import them in IDA with Edit → DejaDump → Import →
Import memory dump(s)… (address = the region base printed below), or with
``python -m dejadump dumps``.
"""

from __future__ import annotations

import argparse
import json
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from dejadump.core import tenet  # noqa: E402
from dejadump.core.state import BytesBase, StateResolver  # noqa: E402


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--x64", action="store_true", help="use the x86-64 corpus")
    parser.add_argument("--outdir", default=os.path.join(ROOT, "tools", "mkcorpus", "out", "dumps"))
    parser.add_argument("--region", default="buf", choices=("buf", "data", "code"))
    args = parser.parse_args(argv)

    fixtures = os.path.join(ROOT, "tests", "fixtures")
    with open(os.path.join(fixtures, "manifest.json")) as fh:
        manifest = json.load(fh)
    if args.x64:
        manifest = manifest["x64"]
    arch = tenet.AMD64 if args.x64 else tenet.ARM64
    trace = os.path.join(fixtures, os.path.splitext(manifest["elf"])[0] + ".tenet")
    with open(trace, encoding="utf-8") as fh:
        det, _ = tenet.import_trace(fh, arch=arch)

    base = []
    for name, dump in manifest["dumps"].items():
        with open(os.path.join(fixtures, dump["path"]), "rb") as fh:
            base.append((dump["base"], fh.read()))
    resolver = StateResolver(det.epochs, base=BytesBase(base))
    region = manifest["regions"][args.region]
    os.makedirs(args.outdir, exist_ok=True)
    previous = resolver.state(0, region["base"], region["size"])
    written = []
    for k in range(1, resolver.max_epoch() + 1):
        data = resolver.state(k, region["base"], region["size"])
        if data == previous:
            continue
        path = os.path.join(args.outdir, "%s_t%d.bin" % (args.region, k))
        with open(path, "wb") as fh:
            fh.write(data)
        written.append(path)
        previous = data
    print("region %s @ 0x%X (%d bytes) — import each dump at that address:" % (
        args.region, region["base"], region["size"]))
    for path in written:
        print("  " + os.path.relpath(path, ROOT))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
