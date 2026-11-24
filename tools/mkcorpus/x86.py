"""A tiny x86-64 encoder — just the forms the SMC corpus stub needs (unicorn-only).

Register convention (preset by the generator): rbx = BUF, rsi = DATA marker slot,
rdi = DATA decrypt base, cl = key.  Encodings are validated end to end (the
generator asserts the data decrypts), so a bad byte fails loudly.
"""

from __future__ import annotations

import struct


def mov_mem_rbx_imm32(imm32: int) -> bytes:
    """mov dword ptr [rbx], imm32  →  C7 /0 id (ModRM 03 = [rbx])."""
    return b"\xC7\x03" + struct.pack("<I", imm32 & 0xFFFFFFFF)


def call_rbx() -> bytes:
    """call rbx  →  FF /2 (ModRM D3)."""
    return b"\xFF\xD3"


def mov_al_rdi_disp8(d: int) -> bytes:
    """mov al, byte ptr [rdi+disp8]  →  8A 47 ib."""
    return b"\x8A\x47" + bytes([d & 0xFF])


def xor_al_cl() -> bytes:
    """xor al, cl  →  30 C8."""
    return b"\x30\xC8"


def mov_rdi_disp8_al(d: int) -> bytes:
    """mov byte ptr [rdi+disp8], al  →  88 47 ib."""
    return b"\x88\x47" + bytes([d & 0xFF])


def stub_bytes(marker: int) -> bytes:
    """The per-version stub placed in BUF: mov byte [rsi], marker ; ret (4 bytes)."""
    return bytes([0xC6, 0x06, marker & 0xFF, 0xC3])


def stub_word(marker: int) -> int:
    return int.from_bytes(stub_bytes(marker), "little")
