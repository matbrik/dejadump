"""A minimal ARM64 (A64) instruction encoder — just the forms the SMC corpus
stub needs, so the generator depends only on Unicorn (keystone is unusable on
Python 3.12+ because it imports the removed ``distutils``).

Encodings are validated end-to-end: the generator executes them under Unicorn and
asserts the data table actually decrypts, so a wrong encoding fails loudly.
All helpers return a 32-bit little-endian instruction word as an int; use
:func:`word` to serialize.
"""

from __future__ import annotations

W9, W10 = 9, 10          # scratch / key registers
X1, X2, X3, X30 = 1, 2, 3, 30
LR = X30


def movz(rd: int, imm16: int, shift: int = 0) -> int:
    """MOVZ Wd, #imm16 {, LSL #shift}."""
    return 0x52800000 | ((shift // 16) << 21) | ((imm16 & 0xFFFF) << 5) | (rd & 31)


def movk(rd: int, imm16: int, shift: int = 0) -> int:
    """MOVK Wd, #imm16 {, LSL #shift}."""
    return 0x72800000 | ((shift // 16) << 21) | ((imm16 & 0xFFFF) << 5) | (rd & 31)


def str_w(rt: int, rn: int, off: int = 0) -> int:
    """STR Wt, [Xn, #off] (32-bit, unsigned scaled offset)."""
    assert off % 4 == 0 and 0 <= off <= 16380
    return 0xB9000000 | ((off // 4) << 10) | ((rn & 31) << 5) | (rt & 31)


def strb(rt: int, rn: int, off: int = 0) -> int:
    """STRB Wt, [Xn, #off] (8-bit, unsigned offset)."""
    assert 0 <= off <= 4095
    return 0x39000000 | ((off & 0xFFF) << 10) | ((rn & 31) << 5) | (rt & 31)


def ldrb(rt: int, rn: int, off: int = 0) -> int:
    """LDRB Wt, [Xn, #off] (8-bit, unsigned offset)."""
    assert 0 <= off <= 4095
    return 0x39400000 | ((off & 0xFFF) << 10) | ((rn & 31) << 5) | (rt & 31)


def eor_w(rd: int, rn: int, rm: int) -> int:
    """EOR Wd, Wn, Wm (32-bit, shifted register, no shift)."""
    return 0x4A000000 | ((rm & 31) << 16) | ((rn & 31) << 5) | (rd & 31)


def ret(rn: int = LR) -> int:
    """RET {Xn}."""
    return 0xD65F0000 | ((rn & 31) << 5)


def blr(rn: int) -> int:
    """BLR Xn."""
    return 0xD63F0000 | ((rn & 31) << 5)


def nop() -> int:
    return 0xD503201F


def word(w: int) -> bytes:
    return (w & 0xFFFFFFFF).to_bytes(4, "little")


def build_word(dst: int, value: int) -> list[int]:
    """Materialize a full 32-bit ``value`` into register ``dst`` (MOVZ+MOVK)."""
    return [movz(dst, value & 0xFFFF), movk(dst, (value >> 16) & 0xFFFF, 16)]
