"""Capture and restore IDA annotations for a byte range (IDA-only).

Inside the volatile set, annotations are *versioned* per epoch; outside it they are
shared.  This module serialises the annotations of a range to a JSON-friendly dict
(offsets relative to the range start, so they survive the bytes moving between
epochs) and restores them after Mode A has swapped bytes and re-run analysis.

Everything is best-effort: any single failure is logged and skipped, never fatal
(DESIGN §12 / risk #1).  Restoration order follows the plan: funcs → names →
types → comments → colours (items are recreated by auto-analysis in Mode A).

Switching epochs is a *delta*: :func:`apply_delta` removes what the outgoing
epoch had and the target does not (``del_items`` keeps names, comments, colours
and decompiler settings, so without this they would leak into other epochs),
then applies only what differs.

Payload shape (subset of DESIGN §5.3)::

    {"names":  [{"off":.., "name":..}],
     "funcs":  [{"off":.., "end":.., "flags":.., "cmt":.., "tails":[]}],
     "cmts":   [{"off":.., "rpt":bool, "text":..}],
     "types":  [{"off":.., "decl":".."}],
     "colors": [{"off":.., "rgb":..}],
     "manual": [{"off":.., "text":..}],
     "extra":  [{"off":.., "where":.., "text":..}],
     "forced_operands": [{"off":.., "opnum":.., "text":..}],
     "operands": [{"off":.., "opnum":.., "format":..}],
     "hexrays": [{"func_off":.., "lvars":[]}]}
"""

from __future__ import annotations

from typing import Optional

import ida_bytes
import ida_funcs
import ida_frame
import ida_idaapi
import ida_name
import ida_nalt
import ida_lines
import idc

from ..util.fmt import owned_line
from ..util.logging import get_logger
from .annotation_model import (KINDS, empty_payload, plan_delta,  # noqa: F401 (re-export)
                               replace_window)

log = get_logger("annotations")

_DEFCOLOR = 0xFFFFFFFF

#: Legacy tint value. Capture ignores it when opening databases produced by older
#: builds; current builds use a non-color banner so user colors stay visible.
DEJADUMP_TINT = 0x3A2A1A


def _function_tails(f, base: int) -> list[list[int]]:
    tails = []
    try:
        iterator = ida_funcs.func_tail_iterator_t(f)
        ok = iterator.main()
        while ok:
            chunk = iterator.chunk()
            if chunk and chunk.start_ea != f.start_ea:
                tails.append([chunk.start_ea - base, chunk.end_ea - base])
            ok = iterator.next()
    except Exception:
        log.debug("function-tail capture skipped at %#x", f.start_ea)
    return tails


def _extra_comments(ea: int):
    for origin in (ida_lines.E_PREV, ida_lines.E_NEXT):
        for index in range(100):
            where = origin + index
            text = ida_lines.get_extra_cmt(ea, where)
            if text is None:
                break
            if text and not owned_line(text):
                yield where, text


def _capture_hexrays(func_ea: int) -> Optional[dict]:
    """Capture public, serializable Hex-Rays local-variable settings."""
    try:
        import ida_hexrays

        if not ida_hexrays.init_hexrays_plugin():
            return None
        vector = ida_hexrays.lvar_uservec_t()
        if not ida_hexrays.restore_user_lvar_settings(vector, func_ea):
            return None
        rows = []
        for index in range(vector.lvvec.size()):
            info = vector.lvvec.at(index)
            locator = info.ll
            location = None
            if locator.is_stk_var():
                location = {"kind": "stack", "value": int(locator.get_stkoff())}
            elif locator.is_reg2():
                location = {"kind": "reg2", "value": [int(locator.get_reg1()),
                                                          int(locator.get_reg2())]}
            elif locator.is_reg1():
                location = {"kind": "reg1", "value": int(locator.get_reg1())}
            if location is None:
                continue
            rows.append({
                "location": location, "defea_off": int(locator.defea) - func_ea,
                "name": info.name or "", "type": str(info.type) if info.type else "",
                "cmt": info.cmt or "", "size": int(info.size), "flags": int(info.flags),
            })
        return {"func_ea": func_ea, "stkoff_delta": int(vector.stkoff_delta),
                "flags": int(vector.ulv_flags), "lvars": rows}
    except Exception:
        log.debug("Hex-Rays lvar capture skipped at %#x", func_ea)
        return None


def _restore_hexrays(payload: dict, base: int) -> None:
    try:
        import ida_hexrays
        import ida_typeinf

        if not ida_hexrays.init_hexrays_plugin():
            return
        vector = ida_hexrays.lvar_uservec_t()
        vector.stkoff_delta = int(payload.get("stkoff_delta", 0))
        vector.ulv_flags = int(payload.get("flags", 0))
        for row in payload.get("lvars", []):
            info = ida_hexrays.lvar_saved_info_t()
            locator = ida_hexrays.lvar_locator_t()
            func_ea = base + int(payload["func_off"])
            locator.defea = func_ea + int(row.get("defea_off", 0))
            location = row["location"]
            if location["kind"] == "stack":
                locator.location.set_stkoff(int(location["value"]))
            elif location["kind"] == "reg2":
                locator.location.set_reg2(*[int(v) for v in location["value"]])
            else:
                locator.location.set_reg1(int(location["value"]))
            info.ll = locator
            info.name = row.get("name", "")
            info.cmt = row.get("cmt", "")
            info.size = int(row.get("size", -1))
            info.flags = int(row.get("flags", 0))
            if row.get("type"):
                tif = ida_typeinf.tinfo_t()
                decl = row["type"].rstrip()
                decl = decl if decl.endswith(";") else decl + ";"
                # parse_decl returns the declared name ("" for a bare type) or None.
                if ida_typeinf.parse_decl(tif, None, decl, ida_typeinf.PT_SIL) is not None:
                    info.type = tif
            vector.lvvec.push_back(info)
        ida_hexrays.save_user_lvar_settings(base + int(payload["func_off"]), vector)
    except Exception:
        log.debug("Hex-Rays lvar restore skipped at %#x",
                  base + int(payload.get("func_off", 0)))


def _heads(start: int, end: int):
    ea = ida_bytes.get_item_head(start)
    if ea < start:
        ea = ida_bytes.next_head(ea, end)
    while ea != ida_idaapi.BADADDR and ea < end:
        yield ea
        ea = ida_bytes.next_head(ea, end)


def capture(start: int, end: int, origin: Optional[int] = None) -> dict:
    """Serialise the annotations in ``[start, end)`` to a payload dict.

    Offsets are relative to ``origin`` (default ``start``), so a sub-window can be
    captured and merged into a whole-range payload with :func:`replace_window`.
    Cheap flag tests run before the per-operand queries: on a multi-megabyte
    region almost every head has nothing to capture.
    """
    origin = start if origin is None else origin
    payload: dict = empty_payload()
    try:
        for ea in _heads(start, end):
            off = ea - origin
            flags = ida_bytes.get_flags(ea)
            code = ida_bytes.is_code(flags)

            if ida_bytes.has_user_name(flags):
                name = ida_name.get_name(ea)
                if name:
                    try:
                        name_flags = int(ida_name.get_name_flags(ea))
                    except Exception:
                        name_flags = 0
                    payload["names"].append(
                        {"off": off, "name": name, "flags": name_flags})

            f = ida_funcs.get_func(ea)
            if f is not None and f.start_ea == ea:
                payload["funcs"].append({
                    "off": off, "end": f.end_ea - origin, "flags": f.flags,
                    "cmt": ida_funcs.get_func_cmt(f, False) or "",
                    "rpt_cmt": ida_funcs.get_func_cmt(f, True) or "",
                    "tails": _function_tails(f, origin),
                    "frame": {"frsize": int(f.frsize), "frregs": int(f.frregs),
                              "argsize": int(f.argsize), "fpd": int(f.fpd)},
                })
                hexrays = _capture_hexrays(f.start_ea)
                if hexrays:
                    hexrays["func_off"] = f.start_ea - origin
                    hexrays.pop("func_ea", None)
                    payload["hexrays"].append(hexrays)

            if ida_bytes.has_cmt(flags):
                for rpt in (False, True):
                    cmt = ida_bytes.get_cmt(ea, rpt)
                    if cmt:
                        payload["cmts"].append({"off": off, "rpt": rpt, "text": cmt})

            if f is not None and f.start_ea == ea or not code:
                decl = idc.get_type(ea)
                if decl:
                    payload["types"].append({"off": off, "decl": decl})

            color = ida_nalt.get_item_color(ea)
            if color != _DEFCOLOR and color != DEJADUMP_TINT:
                payload["colors"].append({"off": off, "rgb": color})

            if ida_bytes.has_extra_cmts(flags):
                for where, text in _extra_comments(ea):
                    payload["extra"].append({"off": off, "where": where, "text": text})
            if not code:
                continue
            manual = ida_bytes.get_manual_insn(ea)
            if manual:
                payload["manual"].append({"off": off, "text": manual})
            for opnum in range(8):
                if ida_bytes.is_forced_operand(ea, opnum):
                    forced = ida_bytes.get_forced_operand(ea, opnum)
                    if forced:
                        payload["forced_operands"].append(
                            {"off": off, "opnum": opnum, "text": forced})
                try:
                    if not ida_bytes.is_defarg(flags, opnum):
                        continue
                    radix = int(ida_bytes.get_radix(flags, opnum))
                    is_char = bool(ida_bytes.is_char(flags, opnum))
                    inverse = bool(ida_bytes.is_invsign(ea, flags, opnum))
                    bitnot = bool(ida_bytes.is_bnot(ea, flags, opnum))
                    if is_char or radix != 16 or inverse or bitnot:
                        payload["operands"].append({
                            "off": off, "opnum": opnum,
                            "format": "char" if is_char else "radix:%d" % radix,
                            "inverse": inverse, "bitnot": bitnot,
                        })
                except Exception:
                    pass
    except Exception:
        log.exception("capture failed for [%#x, %#x)", start, end)
    return payload


def restore(start: int, payload: Optional[dict]) -> None:
    """Re-apply a captured payload at ``start`` (offsets are range-relative)."""
    if not payload:
        return
    # funcs first so names/types/comments land on defined items.
    for f in payload.get("funcs", []):
        try:
            ida_funcs.add_func(start + f["off"], start + f["end"])
            fn = ida_funcs.get_func(start + f["off"])
            if fn:
                if "flags" in f:
                    ida_funcs.set_func_flags(fn.start_ea, int(f["flags"]))
                frame = f.get("frame")
                if frame:
                    ida_frame.set_frame_size(fn, int(frame["frsize"]),
                                             int(frame["frregs"]), int(frame["argsize"]))
                    ida_frame.update_fpd(fn, int(frame.get("fpd", 0)))
                if f.get("cmt"):
                    ida_funcs.set_func_cmt(fn, f["cmt"], False)
                if f.get("rpt_cmt"):
                    ida_funcs.set_func_cmt(fn, f["rpt_cmt"], True)
                for tail_start, tail_end in f.get("tails", []):
                    ida_funcs.append_func_tail(fn, start + tail_start, start + tail_end)
        except Exception:
            log.debug("add_func failed at %#x", start + f["off"])
    for n in payload.get("names", []):
        try:
            safe_flags = int(n.get("flags", 0)) | ida_name.SN_NOCHECK | ida_name.SN_FORCE
            ida_name.set_name(start + n["off"], n["name"], safe_flags)
        except Exception:
            log.debug("set_name failed at %#x", start + n["off"])
    for t in payload.get("types", []):
        try:
            idc.SetType(start + t["off"], t["decl"])
        except Exception:
            log.debug("SetType failed at %#x", start + t["off"])
    for c in payload.get("cmts", []):
        try:
            ida_bytes.set_cmt(start + c["off"], c["text"], bool(c["rpt"]))
        except Exception:
            log.debug("set_cmt failed at %#x", start + c["off"])
    for c in payload.get("colors", []):
        try:
            ida_nalt.set_item_color(start + c["off"], c["rgb"])
        except Exception:
            log.debug("set_item_color failed at %#x", start + c["off"])
    for m in payload.get("manual", []):
        try:
            ida_bytes.set_manual_insn(start + m["off"], m["text"])
        except Exception:
            log.debug("manual instruction restore failed at %#x", start + m["off"])
    for x in payload.get("extra", []):
        try:
            ida_lines.update_extra_cmt(start + x["off"], int(x["where"]), x["text"])
        except Exception:
            log.debug("extra comment restore failed at %#x", start + x["off"])
    for op in payload.get("forced_operands", []):
        try:
            ida_bytes.set_forced_operand(start + op["off"], int(op["opnum"]), op["text"])
        except Exception:
            log.debug("forced operand restore failed at %#x", start + op["off"])
    for op in payload.get("operands", []):
        try:
            ea, n = start + op["off"], int(op["opnum"])
            form = op.get("format", "radix:16")
            if form == "char":
                idc.op_chr(ea, n)
            else:
                radix = int(form.partition(":")[2] or 16)
                {2: idc.op_bin, 8: idc.op_oct, 10: idc.op_dec,
                 16: idc.op_hex}.get(radix, idc.op_hex)(ea, n)
            flags = ida_bytes.get_flags(ea)
            if bool(ida_bytes.is_invsign(ea, flags, n)) != bool(op.get("inverse")):
                ida_bytes.toggle_sign(ea, n)
            flags = ida_bytes.get_flags(ea)
            if bool(ida_bytes.is_bnot(ea, flags, n)) != bool(op.get("bitnot")):
                ida_bytes.toggle_bnot(ea, n)
        except Exception:
            log.debug("operand representation restore failed at %#x", start + op["off"])
    for hexrays in payload.get("hexrays", []):
        _restore_hexrays(hexrays, start)


# -- deltas ---------------------------------------------------------------------

def clear(start: int, payload: Optional[dict]) -> None:
    """Undo exactly the annotations listed in ``payload`` (offsets relative to start)."""
    if not payload:
        return
    for n in payload.get("names", []):
        try:
            ea = start + n["off"]
            if ida_name.get_name(ea) == n["name"]:
                ida_name.set_name(ea, "", ida_name.SN_NOWARN)
        except Exception:
            log.debug("name clear failed at %#x", start + n["off"])
    for c in payload.get("cmts", []):
        try:
            ida_bytes.set_cmt(start + c["off"], "", bool(c["rpt"]))
        except Exception:
            log.debug("comment clear failed at %#x", start + c["off"])
    for x in payload.get("extra", []):
        try:
            ida_lines.del_extra_cmt(start + x["off"], int(x["where"]))
        except Exception:
            log.debug("extra comment clear failed at %#x", start + x["off"])
    for c in payload.get("colors", []):
        try:
            ida_nalt.set_item_color(start + c["off"], _DEFCOLOR)
        except Exception:
            log.debug("color clear failed at %#x", start + c["off"])
    for m in payload.get("manual", []):
        try:
            ida_bytes.set_manual_insn(start + m["off"], "")
        except Exception:
            log.debug("manual instruction clear failed at %#x", start + m["off"])
    for op in payload.get("forced_operands", []):
        try:
            ida_bytes.set_forced_operand(start + op["off"], int(op["opnum"]), "")
        except Exception:
            log.debug("forced operand clear failed at %#x", start + op["off"])
    for op in payload.get("operands", []):
        try:
            ida_bytes.clr_op_type(start + op["off"], int(op["opnum"]))
        except Exception:
            log.debug("operand representation clear failed at %#x", start + op["off"])
    for t in payload.get("types", []):
        try:
            ida_nalt.del_tinfo(start + t["off"])
        except Exception:
            log.debug("type clear failed at %#x", start + t["off"])
    for h in payload.get("hexrays", []):
        try:
            import ida_hexrays

            if ida_hexrays.init_hexrays_plugin():
                ida_hexrays.save_user_lvar_settings(start + int(h["func_off"]),
                                                    ida_hexrays.lvar_uservec_t())
        except Exception:
            log.debug("Hex-Rays settings clear failed at %#x", start + int(h["func_off"]))
    for f in payload.get("funcs", []):
        try:
            fn = ida_funcs.get_func(start + f["off"])
            if fn is not None and fn.start_ea == start + f["off"]:
                ida_funcs.del_func(fn.start_ea)
        except Exception:
            log.debug("function clear failed at %#x", start + f["off"])


def apply_delta(start: int, outgoing: Optional[dict], target: Optional[dict],
                changed=None) -> None:
    """Move the IDB from ``outgoing`` annotations to ``target`` (see :func:`plan_delta`)."""
    remove, apply = plan_delta(outgoing, target, changed)
    clear(start, remove)
    restore(start, apply)
