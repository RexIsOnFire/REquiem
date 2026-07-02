"""Tests for the Capstone CFG disassembler.

Uses a hand-assembled x64 code section so the expected control flow is known
exactly. If capstone is not installed these assert the graceful-skip path.
"""
import struct

import pytest

from requiem import analyze
from requiem.static import disasm
from requiem.static.disasm import _HAVE_CAPSTONE


def _align(n, a=0x200):
    return (n + a - 1) // a * a


def _pe_with_code(code: bytes) -> bytes:
    code = code + b"\x90" * (_align(len(code)) - len(code))
    sec = [(b".text\x00\x00\x00", code, 0x60000020)]
    mz = b"MZ" + b"\x00" * 0x3a + struct.pack("<I", 0x80)
    mz += b"\x00" * (0x80 - len(mz))
    coff = struct.pack("<H H I I I H H", 0x8664, len(sec), 0, 0, 0, 0xE0, 0x22)
    opt = (struct.pack("<H B B I I I I I", 0x20B, 14, 0, 0x400, 0, 0, 0x1000, 0)
           + struct.pack("<Q", 0x140000000) + struct.pack("<I I", 0x1000, 0x200))
    opt += b"\x00" * (0xE0 - len(opt))
    h = mz + b"PE\x00\x00" + coff + opt
    rp = _align(len(h) + 40 * len(sec))
    sh = b""; blobs = b""; cur = rp; va = 0x1000
    for n, d, c in sec:
        rs = _align(len(d))
        sh += struct.pack("<8s I I I I I I H H I", n, len(d), va, rs, cur, 0, 0, 0, 0, c)
        blobs += d + b"\x00" * (rs - len(d)); cur += rs; va += _align(len(d), 0x1000)
    return h + sh + b"\x00" * (rp - len(h + sh)) + blobs


# xor rax,rax; cmp eax,1; je +2; nop; ret; int3; ret  -> 3 basic blocks
_BRANCHY = bytes([0x48, 0x31, 0xC0, 0x83, 0xF8, 0x01, 0x74, 0x02,
                  0x90, 0xC3, 0xCC, 0xC3])


@pytest.mark.skipif(not _HAVE_CAPSTONE, reason="capstone not installed")
def test_cfg_splits_at_conditional_branch():
    dis = disasm.disassemble(_pe_with_code(_BRANCHY), "pe")
    assert dis.available
    assert dis.arch == "x64"
    assert dis.entry == 0x140001000
    assert len(dis.blocks) == 3
    entry_block = dis.blocks[0]
    assert entry_block.kind == "cond"
    assert len(entry_block.successors) == 2   # branch target + fallthrough
    # Both leaf blocks return.
    leaves = [b for b in dis.blocks if not b.successors]
    assert len(leaves) == 2
    assert all(b.kind == "ret" for b in leaves)


@pytest.mark.skipif(not _HAVE_CAPSTONE, reason="capstone not installed")
def test_unconditional_jump_single_successor():
    # jmp +2 ; int3 ; ret   -> jump block to a ret block
    code = bytes([0xEB, 0x01, 0xCC, 0xC3])
    dis = disasm.disassemble(_pe_with_code(code), "pe")
    assert dis.available
    jmp = dis.blocks[0]
    assert jmp.kind == "jump"
    assert len(jmp.successors) == 1


@pytest.mark.skipif(not _HAVE_CAPSTONE, reason="capstone not installed")
def test_first_instruction_decoded():
    dis = disasm.disassemble(_pe_with_code(_BRANCHY), "pe")
    first = dis.blocks[0].instructions[0]
    assert first.mnemonic == "xor"
    assert "rax" in first.op_str
    assert first.bytes_hex == "48 31 c0"


def test_unavailable_when_no_capstone_is_graceful(monkeypatch):
    monkeypatch.setattr(disasm, "_HAVE_CAPSTONE", False)
    dis = disasm.disassemble(_pe_with_code(_BRANCHY), "pe")
    assert dis.available is False
    assert "capstone" in dis.note


def test_non_native_format_skipped():
    dis = disasm.disassemble(b"not an executable", "script")
    assert dis.available is False


def test_pipeline_populates_disassembly_and_serializes():
    import json
    report = analyze(_pe_with_code(_BRANCHY), "s.exe")
    d = json.loads(json.dumps(report.to_dict()))["disassembly"]
    if _HAVE_CAPSTONE:
        assert d["available"] is True
        assert d["blocks"]
    else:
        assert d["available"] is False
