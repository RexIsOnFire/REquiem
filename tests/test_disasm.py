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
    # The entry function's blocks (mirrored on .blocks for back-compat).
    assert len(dis.blocks) == 3
    entry_fn = dis.functions[0]
    assert entry_fn.source == "entry"
    entry_block = entry_fn.blocks[0]
    assert entry_block.kind == "cond"
    assert len(entry_block.successors) == 2   # branch target + fallthrough
    leaves = [b for b in entry_fn.blocks if not b.successors]
    assert len(leaves) == 2
    assert all(b.kind == "ret" for b in leaves)


# entry: call sub(+0x0B); ret. sub@+0x10: xor rax,rax; ret
_WITH_CALL = (bytes([0xE8, 0x0B, 0x00, 0x00, 0x00, 0xC3])
              + b"\x90" * (0x10 - 6) + bytes([0x48, 0x31, 0xC0, 0xC3]))


@pytest.mark.skipif(not _HAVE_CAPSTONE, reason="capstone not installed")
def test_call_target_discovers_function():
    dis = disasm.disassemble(_pe_with_code(_WITH_CALL), "pe")
    assert len(dis.functions) == 2
    entry_fn = dis.functions[0]
    assert entry_fn.source == "entry"
    sub = dis.functions[1]
    assert sub.source == "call"
    assert sub.name.startswith("sub_")
    assert sub.address == 0x140001010
    # The call did NOT become an intra-function edge.
    assert entry_fn.blocks[0].kind == "ret"


@pytest.mark.skipif(not _HAVE_CAPSTONE, reason="capstone not installed")
def test_named_seed_names_and_prioritizes_function():
    dis = disasm.disassemble(
        _pe_with_code(_WITH_CALL), "pe",
        seeds=[("encrypt_files", 0x140001010, "export")])
    names = {f.name: f.source for f in dis.functions}
    assert names.get("encrypt_files") == "export"
    # Named functions come before call-discovered ones.
    sources = [f.source for f in dis.functions]
    assert sources.index("export") < len(sources)


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


def _elf_with_func(func_name=b"decrypt", func_addr=0x1129) -> bytes:
    """Minimal ELF64 carrying one defined STT_FUNC symbol in .symtab."""
    strtab = b"\x00" + func_name + b"\x00"
    sym0 = struct.pack("<IBBHQQ", 0, 0, 0, 0, 0, 0)
    sym1 = struct.pack("<IBBHQQ", 1, 0x12, 0, 1, func_addr, 8)  # global STT_FUNC
    symtab = sym0 + sym1
    shstr = b"\x00.symtab\x00.strtab\x00.shstrtab\x00.text\x00"
    off_sym = 64
    off_str = off_sym + len(symtab)
    off_shstr = off_str + len(strtab)
    off_sh = off_shstr + len(shstr)

    def sh(name, typ, off, size, link=0, entsize=0, flags=0, addr=0):
        return struct.pack("<IIQQQQIIQQ", name, typ, flags, addr, off, size,
                           link, 0, 1, entsize)

    shtab = (sh(0, 0, 0, 0)
             + sh(shstr.index(b".text"), 1, 0, 0, flags=6, addr=0x1000)
             + sh(shstr.index(b".symtab"), 2, off_sym, len(symtab), link=3, entsize=24)
             + sh(shstr.index(b".strtab"), 3, off_str, len(strtab))
             + sh(shstr.index(b".shstrtab"), 3, off_shstr, len(shstr)))
    e = b"\x7fELF" + bytes([2, 1, 1, 0]) + b"\x00" * 8
    e += struct.pack("<HHIQQQIHHHHHH", 2, 0x3E, 1, 0x1000, 0, off_sh,
                     0, 64, 0, 0, 64, 5, 4)
    return e + symtab + strtab + shstr + shtab


def test_elf_extracts_function_symbols():
    from requiem.static import elf
    info = elf.parse(_elf_with_func())
    assert ("decrypt", 0x1129) in info.func_symbols
    assert info.is_stripped is False


def test_pipeline_populates_disassembly_and_serializes():
    import json
    report = analyze(_pe_with_code(_BRANCHY), "s.exe")
    d = json.loads(json.dumps(report.to_dict()))["disassembly"]
    if _HAVE_CAPSTONE:
        assert d["available"] is True
        assert d["blocks"]
    else:
        assert d["available"] is False
