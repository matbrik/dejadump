"""Small display helpers shared by panels and dialogs (no IDA imports)."""

from __future__ import annotations

from typing import Optional

#: Prefix of the comment lines and banners DejaDump writes into an IDB, and every
#: prefix an earlier build of the plugin (named Palimpsest) used.
TAG = "[DejaDump]"
OWNED_TAGS = (TAG, "[Palimpsest]")

#: Name prefixes of pinned shadow segments, current and legacy.
SHADOW_PREFIX = ".deja."
SHADOW_PREFIXES = (SHADOW_PREFIX, ".pal.")


def owned_line(text: str) -> bool:
    """True for a comment line DejaDump (or its earlier name) wrote."""
    return (text or "").startswith(OWNED_TAGS)


def writer(pc: Optional[int]) -> str:
    """A writer PC for display; dump-pair and memory-dump writes have none."""
    return "0x%X" % pc if pc is not None else "dump"


def size(n: int) -> str:
    for unit in ("B", "KiB", "MiB", "GiB"):
        if n < 1024 or unit == "GiB":
            return ("%d %s" % (n, unit)) if unit == "B" else ("%.1f %s" % (n, unit))
        n /= 1024.0
    return "%d B" % n
