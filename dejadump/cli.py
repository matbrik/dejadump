"""Headless command line for large imports and sidecar maintenance (no IDA needed).

    python -m dejadump import TRACE --sidecar BINARY.dejadump.db [--elf BINARY]
    python -m dejadump dumps --sidecar S --elf BINARY DUMP@0xBASE [DUMP@0xBASE …]
    python -m dejadump info --sidecar S
    python -m dejadump export --sidecar S --input BINARY --epoch 2 -o OUT
    python -m dejadump compact --sidecar S

Importing a multi-gigabyte trace inside IDA blocks the UI; run it here instead
and open the IDB afterwards — the plugin picks the sidecar up next to the IDB
(``<idb without extension>.dejadump.db``).  ``--elf`` restricts epochs to the
binary's loadable segments (the same filter the plugin applies from the IDB).
Note: the t0 snapshot is taken from the IDB the first time the plugin switches,
or from ``--elf`` for dump imports.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import time

from .capture import rawdump
from .core import tenet
from .core.state import StateResolver
from .core.store import EpochStore


def _num(text: str) -> int:
    return int(text, 0)


def _elf_extents(path: str) -> list[tuple[int, int]]:
    with open(path, "rb") as fh:
        data = fh.read()
    return [(vaddr, vaddr + filesz) for _off, vaddr, filesz, _flags in rawdump._elf_loads(data)
            if filesz]


def _cmd_import(args) -> int:
    with open(args.trace, "r", encoding="utf-8", errors="replace") as fh:
        head = [next(fh, "") for _ in range(200)]
    manifest = tenet.load_manifest(args.trace)
    arch = tenet.ARCHES.get(args.arch or manifest.get("arch", "")) or tenet.detect_arch(head)
    if arch is None:
        print("error: cannot tell the architecture; pass --arch", file=sys.stderr)
        return 2
    keep = manifest.get("keep")
    if args.elf:
        keep = _elf_extents(args.elf)
    if args.no_filter:
        keep = None
    slide = args.slide if args.slide is not None else manifest.get("slide")
    image_base = args.image_base if args.image_base is not None else manifest.get("image_base", 0)
    stats = tenet.ImportStats()
    began = time.perf_counter()
    last = [began]

    def progress(lines):
        now = time.perf_counter()
        if now - last[0] >= 2:
            print("  … %s lines" % f"{lines:,}", file=sys.stderr)
            last[0] = now
        return True

    store = EpochStore(args.sidecar, fast_import=True)
    try:
        source = tenet.import_trace_file(args.trace, store, arch=arch, slide=slide,
                                         image_base=image_base, keep=keep,
                                         progress=progress, stats=stats,
                                         label=args.label or os.path.basename(args.trace))
        duplicate = store.duplicate_of(source)
        print("source %d: %d epoch(s), arch=%s, %.1fs" % (
            source, len(store.epochs(source)), arch.name, time.perf_counter() - began))
        print(stats.summary())
        if duplicate:
            print("note: identical to existing source %d" % duplicate)
    finally:
        store.close()
    return 0


def _cmd_dumps(args) -> int:
    with open(args.elf, "rb") as fh:
        image = fh.read()
    loads = rawdump._elf_loads(image)

    def reader(addr, size):
        out = bytearray(size)
        for vaddr, foff, length in rawdump._vaddr_to_foff(loads, addr, size):
            out[vaddr - addr:vaddr - addr + length] = image[foff:foff + length]
        return bytes(out)

    def is_exec(addr):
        for _off, vaddr, filesz, flags in loads:
            if vaddr <= addr < vaddr + filesz:
                return bool(flags & rawdump.PF_X)
        return None

    dumps, labels = [], []
    for spec in args.dumps:
        path, _, base = spec.rpartition("@")
        if not path:
            print("error: dumps are PATH@BASE, e.g. text.bin@0x1000", file=sys.stderr)
            return 2
        with open(path, "rb") as fh:
            dumps.append((_num(base), fh.read()))
        labels.append(os.path.basename(path))
    store = EpochStore(args.sidecar)
    try:
        epochs = rawdump.import_memory_dumps(
            store, reader, dumps, mapped=_elf_extents(args.elf), is_exec=is_exec,
            label=args.label or "memory dumps", labels=labels)
        print("imported %d epoch(s), %d changed byte(s)" % (
            len(epochs), sum(e.bytes_changed for e in epochs)))
    finally:
        store.close()
    return 0


def _cmd_info(args) -> int:
    store = EpochStore(args.sidecar)
    try:
        info = {"health": store.health(), "active_source": store.active_source_id(),
                "sources": []}
        for source in store.sources():
            summaries = store.epoch_summaries(source["id"])
            info["sources"].append({
                "id": source["id"], "kind": source["kind"], "label": source["label"],
                "created": source["created"],
                "epochs": [{"seq": e["seq"], "kind": e["boundary_kind"],
                            "label": e["label"], **summaries.get(e["id"], {})}
                           for e in store.epochs(source["id"])],
            })
        print(json.dumps(info, indent=2, default=str))
    finally:
        store.close()
    return 0


def _cmd_export(args) -> int:
    store = EpochStore(args.sidecar)
    try:
        if args.source is not None:
            store.set_active_source(args.source)
        resolver = StateResolver(store.load_epochs(), base=store.base_source())
        if args.epoch < 0 or args.epoch > resolver.max_epoch():
            print("error: epoch must be between 0 and %d" % resolver.max_epoch(), file=sys.stderr)
            return 2
        with open(args.input, "rb") as fh:
            original = fh.read()
        out = rawdump.export_image(
            original, lambda a, n: resolver.state(args.epoch, a, n),
            store.volatile_set(), base=args.base)
        with open(args.output, "wb") as fh:
            fh.write(out)
        print("wrote %s (t%d)" % (args.output, args.epoch))
    finally:
        store.close()
    return 0


def _cmd_compact(args) -> int:
    store = EpochStore(args.sidecar)
    try:
        result = store.compact()
        print("removed %(blobs_removed)d blob(s); %(size_before)d → %(size_after)d bytes" % result)
    finally:
        store.close()
    return 0


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(prog="dejadump", description=__doc__.split("\n\n")[0])
    sub = parser.add_subparsers(dest="command", required=True)

    p = sub.add_parser("import", help="import a Tenet/Frinet trace")
    p.add_argument("trace")
    p.add_argument("--sidecar", required=True)
    p.add_argument("--arch", choices=sorted(tenet.ARCHES))
    p.add_argument("--slide", type=_num, help="runtime module base (overrides slide=)")
    p.add_argument("--image-base", type=_num, help="where the IDB maps the module")
    p.add_argument("--elf", help="keep only writes inside this ELF's loadable segments")
    p.add_argument("--no-filter", action="store_true", help="keep every write")
    p.add_argument("--label")
    p.set_defaults(func=_cmd_import)

    p = sub.add_parser("dumps", help="import memory-layout dumps as epochs")
    p.add_argument("dumps", nargs="+", metavar="PATH@BASE")
    p.add_argument("--sidecar", required=True)
    p.add_argument("--elf", required=True, help="the on-disk module (t0)")
    p.add_argument("--label")
    p.set_defaults(func=_cmd_dumps)

    p = sub.add_parser("info", help="print sources and epochs as JSON")
    p.add_argument("--sidecar", required=True)
    p.set_defaults(func=_cmd_info)

    p = sub.add_parser("export", help="write an epoch back into a copy of the input")
    p.add_argument("--sidecar", required=True)
    p.add_argument("--input", required=True)
    p.add_argument("--epoch", type=int, required=True)
    p.add_argument("--source", type=int)
    p.add_argument("--base", type=_num, default=0, help="load base for flat images")
    p.add_argument("-o", "--output", required=True)
    p.set_defaults(func=_cmd_export)

    p = sub.add_parser("compact", help="garbage-collect and VACUUM a sidecar")
    p.add_argument("--sidecar", required=True)
    p.set_defaults(func=_cmd_compact)

    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
