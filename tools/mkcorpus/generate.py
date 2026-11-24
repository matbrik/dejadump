"""Generate the self-modifying-code corpus with offline Unicorn (ARM64 + x86-64).

Same scenario on both architectures (true "dejadump": one address, many versions):
a stable *mutator* writes a small stub into BUF and calls it (entering the written
bytes = a wave boundary), overwrites BUF with a different stub and calls again, 3x,
then decrypts a data table in place (captured at the trace end).  BUF therefore
holds three distinct code versions at one address, and DATA goes ciphertext →
plaintext — exactly what Mode A and the Memory Timeline show.

The emitted traces use the real Tenet convention (a store's bytes appear on the
*next* line), exercising the importer's writer-PC lag.  Output is deterministic
(no time/random) so it can be committed as fixtures.
"""

from __future__ import annotations

import json
import os
from typing import Callable, Optional

from . import arm64 as a
from . import x86

# --- fixed memory layout (shared across arches; page-aligned) -----------------
CODE = 0x100000
BUF = 0x200000
DATA = 0x300000
STACK = 0x7F0000
STACK_SIZE = 0x10000
SP = STACK + 0x8000

KEY = 0x5A
MARKERS = (0xAA, 0xBB, 0xCC)
MARKER_SLOT = DATA + 0x20          # outside the decrypted region
PLAINTEXT = b"DEJADUMP_OK!!!!\x00"  # 16 bytes
assert len(PLAINTEXT) == 16

ENCRYPTED = bytes(b ^ KEY for b in PLAINTEXT)


def _emit_trace(uc, begin: int, until: int, pc_name: str,
                mem_filter: Optional[Callable[[int], bool]] = None) -> str:
    """Run ``uc`` and return a Tenet trace (deltas lag one line, Tenet-style)."""
    from unicorn import UC_HOOK_CODE, UC_HOOK_MEM_WRITE

    # No Frinet ``slide=`` header: it names the module's runtime base, and these
    # addresses are already the ELF's own (``slide=0x0`` would rebase them).
    trace: list[str] = []
    pending: list[tuple[int, bytes]] = []

    def on_code(_uc, addr, _size, _ud):
        toks = ["%s=0x%x" % (pc_name, addr)]
        for wa, wb in pending:
            toks.append("mw=0x%x:%s" % (wa, wb.hex()))
        pending.clear()
        trace.append(",".join(toks))

    def on_write(_uc, _access, addr, size, value, _ud):
        if mem_filter is not None and not mem_filter(addr):
            return
        pending.append((addr, (value & ((1 << (size * 8)) - 1)).to_bytes(size, "little")))

    uc.hook_add(UC_HOOK_CODE, on_code)
    uc.hook_add(UC_HOOK_MEM_WRITE, on_write)
    uc.emu_start(begin, until, timeout=0, count=200000)

    if pending:
        trace.append(",".join("mw=0x%x:%s" % (wa, wb.hex()) for wa, wb in pending))
    return "\n".join(trace) + "\n"


# --- ARM64 --------------------------------------------------------------------
def _mutator_arm64() -> bytes:
    code: list[int] = []
    for marker in MARKERS:
        stub = [a.movz(a.W9, marker), a.strb(a.W9, a.X2, 0), a.ret()]
        for i, w in enumerate(stub):
            code += a.build_word(a.W9, w)
            code.append(a.str_w(a.W9, a.X1, i * 4))
        code.append(a.blr(a.X1))
    for i in range(len(PLAINTEXT)):
        code += [a.ldrb(a.W9, a.X3, i), a.eor_w(a.W9, a.W9, a.W10), a.strb(a.W9, a.X3, i)]
    return b"".join(a.word(w) for w in code)


def build_trace() -> tuple[str, dict]:
    """ARM64 trace + manifest (name kept stable for the fixture-drift test)."""
    from unicorn import (UC_ARCH_ARM64, UC_MODE_LITTLE_ENDIAN, UC_PROT_ALL,
                         UC_PROT_READ, UC_PROT_WRITE, Uc)
    from unicorn.arm64_const import (UC_ARM64_REG_SP, UC_ARM64_REG_X1, UC_ARM64_REG_X2,
                                     UC_ARM64_REG_X3, UC_ARM64_REG_X10, UC_ARM64_REG_X30)

    mutator = _mutator_arm64()
    sentinel = CODE + len(mutator)
    uc = Uc(UC_ARCH_ARM64, UC_MODE_LITTLE_ENDIAN)
    uc.mem_map(CODE, 0x2000, UC_PROT_ALL)
    uc.mem_map(BUF, 0x1000, UC_PROT_ALL)
    uc.mem_map(DATA, 0x1000, UC_PROT_READ | UC_PROT_WRITE)
    uc.mem_map(STACK, STACK_SIZE, UC_PROT_READ | UC_PROT_WRITE)
    uc.mem_write(CODE, mutator)
    uc.mem_write(DATA, ENCRYPTED)
    uc.reg_write(UC_ARM64_REG_X1, BUF)
    uc.reg_write(UC_ARM64_REG_X2, MARKER_SLOT)
    uc.reg_write(UC_ARM64_REG_X3, DATA)
    uc.reg_write(UC_ARM64_REG_X10, KEY)
    uc.reg_write(UC_ARM64_REG_SP, SP)
    uc.reg_write(UC_ARM64_REG_X30, sentinel)

    trace = _emit_trace(uc, CODE, sentinel, "pc")  # arm64 BLR/RET use x30, not the stack
    assert bytes(uc.mem_read(DATA, len(PLAINTEXT))) == PLAINTEXT
    manifest = _manifest("arm64", mutator, uc.mem_read(BUF, 12))
    return trace, manifest


# --- x86-64 -------------------------------------------------------------------
def _mutator_x64() -> bytes:
    code = b""
    for marker in MARKERS:
        code += x86.mov_mem_rbx_imm32(x86.stub_word(marker)) + x86.call_rbx()
    for i in range(len(PLAINTEXT)):
        code += x86.mov_al_rdi_disp8(i) + x86.xor_al_cl() + x86.mov_rdi_disp8_al(i)
    return code


def build_trace_x64() -> tuple[str, dict]:
    from unicorn import (UC_ARCH_X86, UC_MODE_64, UC_PROT_ALL, UC_PROT_READ,
                         UC_PROT_WRITE, Uc)
    from unicorn.x86_const import (UC_X86_REG_RBX, UC_X86_REG_RCX, UC_X86_REG_RDI,
                                   UC_X86_REG_RSI, UC_X86_REG_RSP)

    mutator = _mutator_x64()
    sentinel = CODE + len(mutator)
    uc = Uc(UC_ARCH_X86, UC_MODE_64)
    uc.mem_map(CODE, 0x2000, UC_PROT_ALL)
    uc.mem_map(BUF, 0x1000, UC_PROT_ALL)
    uc.mem_map(DATA, 0x1000, UC_PROT_READ | UC_PROT_WRITE)
    uc.mem_map(STACK, STACK_SIZE, UC_PROT_READ | UC_PROT_WRITE)
    uc.mem_write(CODE, mutator)
    uc.mem_write(DATA, ENCRYPTED)
    uc.reg_write(UC_X86_REG_RBX, BUF)
    uc.reg_write(UC_X86_REG_RSI, MARKER_SLOT)
    uc.reg_write(UC_X86_REG_RDI, DATA)
    uc.reg_write(UC_X86_REG_RCX, KEY)
    uc.reg_write(UC_X86_REG_RSP, SP)

    # call/ret touch the stack; keep only CODE/BUF/DATA writes so the trace matches
    # the arm64 one in spirit (arm64 uses x30, not the stack).
    def keep(addr):
        return addr < STACK or addr >= STACK + STACK_SIZE

    trace = _emit_trace(uc, CODE, sentinel, "rip", mem_filter=keep)
    assert bytes(uc.mem_read(DATA, len(PLAINTEXT))) == PLAINTEXT
    manifest = _manifest("x86-64", mutator, uc.mem_read(BUF, 8))
    return trace, manifest


# --- shared -------------------------------------------------------------------
def _manifest(arch: str, mutator: bytes, final_buf) -> dict:
    return {
        "arch": arch,
        "page": 0x1000,
        "regions": {
            "code": {"base": CODE, "size": 0x2000},
            "buf": {"base": BUF, "size": 0x1000},
            "data": {"base": DATA, "size": 0x1000},
        },
        "key": KEY,
        "markers": list(MARKERS),
        "plaintext": PLAINTEXT.decode("latin-1"),
        "mutator_size": len(mutator),
        "final_buf": bytes(final_buf).hex(),
    }


def _initial_memory(mutator: bytes) -> dict:
    return {
        "code": {"base": CODE, "bytes": mutator + b"\x00" * (0x2000 - len(mutator))},
        "buf": {"base": BUF, "bytes": b"\x00" * 0x1000},
        "data": {"base": DATA, "bytes": ENCRYPTED + b"\x00" * (0x1000 - len(ENCRYPTED))},
    }


def _write_bundle(outdir, prefix, trace_text, manifest, mutator, machine) -> dict:
    from .elf import PF_R, PF_W, PF_X, build_elf

    paths = {}
    trace_path = os.path.join(outdir, prefix + ".tenet")
    with open(trace_path, "w", encoding="utf-8") as fh:
        fh.write(trace_text)
    paths["trace"] = prefix + ".tenet"

    mem = _initial_memory(mutator)
    dumps_dir = os.path.join(outdir, "dumps")
    os.makedirs(dumps_dir, exist_ok=True)
    manifest["dumps"] = {}
    for name, region in mem.items():
        rel = os.path.join("dumps", "%s_%s_t0.bin" % (prefix, name))
        with open(os.path.join(outdir, rel), "wb") as fh:
            fh.write(region["bytes"])
        manifest["dumps"][name] = {"base": region["base"], "path": rel}

    flags = {"code": PF_R | PF_X, "buf": PF_R | PF_W | PF_X, "data": PF_R | PF_W}
    segments = [(mem[n]["base"], mem[n]["bytes"], flags[n]) for n in ("code", "buf", "data")]
    elf_path = os.path.join(outdir, prefix + ".elf")
    with open(elf_path, "wb") as fh:
        fh.write(build_elf(segments, entry=CODE, machine=machine))
    manifest["elf"] = prefix + ".elf"
    paths["elf"] = prefix + ".elf"
    return paths


def generate(outdir: str) -> dict:
    """Write both bundles; manifest.json describes arm64 (+ an ``x64`` section)."""
    from .elf import EM_AARCH64, EM_X86_64

    os.makedirs(outdir, exist_ok=True)

    arm_trace, arm_manifest = build_trace()
    _write_bundle(outdir, "arm64_smc", arm_trace, arm_manifest, _mutator_arm64(), EM_AARCH64)

    x64_trace, x64_manifest = build_trace_x64()
    _write_bundle(outdir, "x64_smc", x64_trace, x64_manifest, _mutator_x64(), EM_X86_64)

    arm_manifest["x64"] = x64_manifest
    manifest_path = os.path.join(outdir, "manifest.json")
    with open(manifest_path, "w", encoding="utf-8") as fh:
        json.dump(arm_manifest, fh, indent=2)
    return {"manifest": manifest_path}


def main(argv: Optional[list] = None) -> int:
    import argparse

    ap = argparse.ArgumentParser(description="Generate the DejaDump SMC corpus.")
    here = os.path.dirname(os.path.abspath(__file__))
    ap.add_argument("--outdir", default=os.path.join(here, "out"))
    args = ap.parse_args(argv)
    paths = generate(args.outdir)
    print("wrote corpus into", os.path.dirname(paths["manifest"]) or ".")
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
