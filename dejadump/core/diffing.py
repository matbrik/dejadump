"""Text normalization and diffing for cached analysis artifacts."""

from __future__ import annotations

import difflib
import re

_ADDRESS = re.compile(r"^(?:[0-9A-Fa-f]{4,16}:?\s+|0x[0-9A-Fa-f]+\s+)")
_AUTO_LABEL = re.compile(r"\b(?:loc|sub|unk|byte|word|dword|qword)_[0-9A-Fa-f]+\b")


def normalize_line(line: str, kind: str) -> str:
    line = line.rstrip()
    if kind in ("assembly", "bytes"):
        line = _ADDRESS.sub("", line)
        if kind == "assembly":
            line = _AUTO_LABEL.sub("<auto>", line)
        return " ".join(line.split())
    if kind == "pseudocode":
        line = _AUTO_LABEL.sub("<auto>", line)
        return " ".join(line.split())
    return line


def unified_diff(a: list[str], b: list[str], a_name: str, b_name: str,
                 *, kind: str = "assembly", normalized: bool = False) -> list[str]:
    if normalized:
        a = [normalize_line(x, kind) for x in a]
        b = [normalize_line(x, kind) for x in b]
    return list(difflib.unified_diff(a, b, fromfile=a_name, tofile=b_name, lineterm=""))


def align(left: list[str], right: list[str], left_addr, right_addr, *, kind: str,
          normalized: bool):
    """Pad two renderings so equal lines share a row.

    Returns ``(rows_left, rows_right, addr_left, addr_right, tags)`` where
    ``tags[i]`` is ``equal``/``replace``/``delete``/``insert`` for row ``i``.
    """
    key = (lambda line: normalize_line(line, kind)) if normalized else (lambda line: line)
    matcher = difflib.SequenceMatcher(None, [key(x) for x in left], [key(x) for x in right],
                                      autojunk=False)
    rows_l, rows_r, addr_l, addr_r, tags = [], [], [], [], []
    for tag, i1, i2, j1, j2 in matcher.get_opcodes():
        span = max(i2 - i1, j2 - j1)
        for offset in range(span):
            li, rj = i1 + offset, j1 + offset
            rows_l.append(left[li] if li < i2 else "")
            addr_l.append(left_addr[li] if li < i2 and li < len(left_addr) else None)
            rows_r.append(right[rj] if rj < j2 else "")
            addr_r.append(right_addr[rj] if rj < j2 and rj < len(right_addr) else None)
            tags.append(tag)
    return rows_l, rows_r, addr_l, addr_r, tags
