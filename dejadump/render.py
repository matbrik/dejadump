"""Text renderers shared by the live controller and the idalib worker (IDA-only).

Every renderer returns parallel ``lines`` / ``addresses`` lists so viewers can map
a rendered line back to an address in the epoch it came from.  Keeping one copy
here means the in-process fallback and the disposable worker produce identical
artifacts (and identical cache keys).
"""

from __future__ import annotations

import hashlib
from typing import Optional

import ida_bytes
import ida_funcs
import ida_idaapi
import ida_lines

#: ``ctree_anchor_t`` flag bits; an anchor with any of them set is not a citem.
_ANCHOR_FLAGS = 0xE0000000
_ANCHOR_INDEX = 0x1FFFFFFF


def _next_head(ea: int, end: int) -> int:
    nxt = ida_bytes.next_head(ea, end)
    return nxt if nxt != ida_idaapi.BADADDR and nxt > ea else ea + 1


def render_assembly(start: int, end: int, *, prefix_address: bool = True):
    lines, addresses, ea = [], [], start
    while ea < end:
        text = ida_lines.tag_remove(ida_lines.generate_disasm_line(ea, 0) or "")
        lines.append("%X  %s" % (ea, text) if prefix_address else text)
        addresses.append(ea)
        ea = _next_head(ea, end)
    return lines, addresses


def render_bytes(start: int, end: int):
    lines, addresses, ea = [], [], start
    while ea < end:
        data = bytes(ida_bytes.get_bytes(ea, min(16, end - ea)) or b"")
        lines.append("%X  %s" % (ea, data.hex(" ")))
        addresses.append(ea)
        ea += max(1, len(data))
    return lines, addresses


def _tag_constants():
    on = ida_lines.COLOR_ON
    addr = ida_lines.COLOR_ADDR
    size = int(getattr(ida_lines, "COLOR_ADDR_SIZE", 16))
    on = on if isinstance(on, str) else chr(on)
    addr = addr if isinstance(addr, str) else chr(addr)
    return on, addr, size


def citem_indexes(raw: str) -> list[int]:
    """Ctree item indexes embedded as ``COLOR_ADDR`` tags in a pseudocode line."""
    on, addr, size = _tag_constants()
    marker = on + addr
    out, pos = [], raw.find(marker)
    while pos >= 0:
        digits = raw[pos + 2:pos + 2 + size]
        try:
            value = int(digits, 16)
        except ValueError:
            value = None
        if value is not None and not value & _ANCHOR_FLAGS:
            out.append(value & _ANCHOR_INDEX)
        pos = raw.find(marker, pos + 2 + size)
    return out


def render_pseudocode(ea: int, *, no_cache: bool = False):
    """Decompile the function at ``ea``; return ``(lines, addresses, warnings)``."""
    import ida_hexrays

    f = ida_funcs.get_func(ea)
    if not f:
        raise RuntimeError("no function exists at 0x%X" % ea)
    flags = getattr(ida_hexrays, "DECOMP_NO_CACHE", 0) if no_cache else 0
    cfunc = ida_hexrays.decompile(f.start_ea, flags=flags)
    if not cfunc:
        raise RuntimeError("decompilation failed at 0x%X" % f.start_ea)
    pseudocode = cfunc.get_pseudocode()
    items = cfunc.treeitems
    count = items.size()
    lines, addresses = [], []
    for line in pseudocode:
        raw = line.line
        lines.append(ida_lines.tag_remove(raw))
        mapped: Optional[int] = None
        for index in citem_indexes(raw):
            if index < count:
                item_ea = int(items.at(index).ea)
                if item_ea != ida_idaapi.BADADDR:
                    mapped = item_ea
                    break
        addresses.append(mapped)
    warnings = [str(getattr(w, "text", w)) for w in cfunc.get_warnings()]
    return lines, addresses, warnings


def block_signatures(ea: int) -> list[dict]:
    """Canonical basic-block identities and text hashes for diff summaries."""
    try:
        import ida_gdl

        f = ida_funcs.get_func(ea)
        if not f:
            return []
        rows = []
        for block in ida_gdl.FlowChart(f):
            text, _ = render_assembly(block.start_ea, block.end_ea, prefix_address=False)
            rows.append({"start": int(block.start_ea), "end": int(block.end_ea),
                         "hash": hashlib.sha256("\n".join(text).encode()).hexdigest()})
        return rows
    except Exception:
        return []
