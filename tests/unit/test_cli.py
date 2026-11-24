"""Headless CLI: import with a segment filter, info, export, compact."""

import json
import os

from dejadump import cli
from tools.mkcorpus.elf import EM_AARCH64, PF_R, PF_W, PF_X, build_elf

FIX = os.path.join(os.path.dirname(__file__), "..", "fixtures")


def test_import_info_compact(tmp_path, capsys):
    sidecar = str(tmp_path / "s.db")
    assert cli.main(["import", os.path.join(FIX, "arm64_smc.tenet"), "--sidecar", sidecar,
                     "--elf", os.path.join(FIX, "arm64_smc.elf")]) == 0
    assert "4 epoch(s)" in capsys.readouterr().out
    assert cli.main(["info", "--sidecar", sidecar]) == 0
    info = json.loads(capsys.readouterr().out)
    assert [e["seq"] for e in info["sources"][0]["epochs"]] == [1, 2, 3, 4]
    assert cli.main(["compact", "--sidecar", sidecar]) == 0


def test_dumps_and_export_round_trip(tmp_path, capsys):
    code = b"\x00" * 0x100
    elf = build_elf([(0x100000, code, PF_R | PF_X), (0x300000, b"\x00" * 0x40, PF_R | PF_W)],
                    entry=0x100000, machine=EM_AARCH64)
    elf_path, dump_path = tmp_path / "m.elf", tmp_path / "text.bin"
    elf_path.write_bytes(elf)
    dump_path.write_bytes(b"\x00" * 0x80 + b"\x5a" * 0x80)
    sidecar = str(tmp_path / "s.db")
    assert cli.main(["dumps", "%s@0x100000" % dump_path, "--sidecar", sidecar,
                     "--elf", str(elf_path)]) == 0
    assert "imported 1 epoch(s)" in capsys.readouterr().out
    out = tmp_path / "m.t1.elf"
    assert cli.main(["export", "--sidecar", sidecar, "--input", str(elf_path), "--epoch", "1",
                     "-o", str(out)]) == 0
    exported = out.read_bytes()
    assert exported[0x1000 + 0x80:0x1000 + 0x100] == b"\x5a" * 0x80
    assert exported[:0x1000 + 0x80] == elf[:0x1000 + 0x80]
