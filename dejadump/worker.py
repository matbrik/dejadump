"""JSON-lines idalib worker for read-only epoch rendering.

The caller must pass disposable copies of both the IDB and sidecar.  This process
never opens the analyst's primary database.  Requests and responses contain an
``id`` and one of: capabilities, prepare_epoch, list_functions, render_assembly,
render_pseudocode, render_bytes, shutdown.

Launched by :mod:`dejadump.ghost` as ``<idalib python> <this file> IDB SIDECAR``;
it lives inside the package so a plugin install always ships it.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import traceback

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)


#: The JSON-lines channel.  ``main`` points it at a private copy of the original
#: stdout and redirects fd 1 to stderr, so any message IDA or the Activator prints
#: (warnings, info boxes rendered as text under idalib) cannot corrupt a reply.
_CHANNEL = sys.stdout


def _reply(request, **payload):
    payload["id"] = request.get("id")
    _CHANNEL.write(json.dumps(payload) + "\n")
    _CHANNEL.flush()


def _isolate_stdout() -> None:
    global _CHANNEL
    _CHANNEL = os.fdopen(os.dup(1), "w", buffering=1, encoding="utf-8")
    os.dup2(2, 1)
    sys.stdout = sys.stderr


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("idb")
    parser.add_argument("sidecar")
    args = parser.parse_args()
    _isolate_stdout()

    import idapro
    idapro.enable_console_messages(False)
    if idapro.open_database(args.idb, run_auto_analysis=False) != 0:
        raise RuntimeError("could not open disposable worker IDB")

    import ida_funcs
    import ida_hexrays

    from dejadump import render
    from dejadump.core.store import EpochStore
    from dejadump.modes.mode_a import Activator

    store = EpochStore(args.sidecar)
    activator = Activator(store)
    current = store.active_epoch()

    try:
        for raw in sys.stdin:
            req = {}
            try:
                req = json.loads(raw)
                op = req.get("op")
                if op == "capabilities":
                    _reply(req, ok=True, idalib=True,
                           hexrays=bool(ida_hexrays.init_hexrays_plugin()))
                elif op == "prepare_epoch":
                    current = int(req["epoch"])
                    _reply(req, ok=activator.activate(current), epoch=current)
                elif op == "list_functions":
                    start, end = int(req["start"]), int(req["end"])
                    rows = []
                    f = ida_funcs.get_next_func(start - 1)
                    while f and f.start_ea < end:
                        rows.append({"start": f.start_ea, "end": f.end_ea})
                        f = ida_funcs.get_next_func(f.start_ea)
                    _reply(req, ok=True, functions=rows)
                elif op == "render_assembly":
                    start, end = int(req["start"]), int(req["end"])
                    lines, addresses = render.render_assembly(start, end)
                    _reply(req, ok=True, epoch=current, lines=lines, addresses=addresses,
                           blocks=render.block_signatures(start))
                elif op == "render_pseudocode":
                    start = int(req["start"])
                    if not ida_hexrays.init_hexrays_plugin():
                        raise RuntimeError("matching decompiler unavailable")
                    lines, addresses, warnings = render.render_pseudocode(start)
                    _reply(req, ok=True, epoch=current, lines=lines, addresses=addresses,
                           warnings=warnings, blocks=render.block_signatures(start))
                elif op == "render_bytes":
                    start, end = int(req["start"]), int(req["end"])
                    lines, addresses = render.render_bytes(start, end)
                    _reply(req, ok=True, epoch=current, lines=lines, addresses=addresses)
                elif op == "shutdown":
                    _reply(req, ok=True)
                    break
                else:
                    raise ValueError("unknown operation %r" % op)
            except Exception as exc:
                _reply(req, ok=False, error=str(exc), traceback=traceback.format_exc())
    finally:
        store.close()
        idapro.close_database(False)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
