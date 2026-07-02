"""Control-flow disassembly via Capstone (optional).

Recovers a bounded **basic-block CFG** rooted at the sample's entry point using
recursive-descent: disassemble from entry, split into basic blocks at branch
targets/instructions, and follow direct branch/call targets to discover more
blocks. This gives real control-flow structure — not a flat instruction dump —
while staying safe on huge/hostile binaries via hard instruction/block budgets.

Degrades gracefully: if ``capstone`` isn't installed, or the format/arch is
unsupported, we return ``Disassembly(available=False, note=...)`` instead of
failing the pipeline.

We map file layout ourselves (which section holds the entry RVA, and its file
offset) so the only optional dependency is Capstone itself.
"""
from __future__ import annotations

import struct

from ..core.models import BasicBlock, Disassembly, Instruction

try:
    import capstone as _cs

    _HAVE_CAPSTONE = True
except Exception:  # pragma: no cover
    _HAVE_CAPSTONE = False

# Safety budgets — a packed or adversarial binary must never hang analysis.
_MAX_INSNS = 4000
_MAX_BLOCKS = 400
_MAX_BLOCK_INSNS = 512


# --- format layout -------------------------------------------------------
class _CodeView:
    """Bytes of the executable image plus the mapping we need to disassemble:
    ``data`` is the code blob, ``base`` its virtual address, and ``entry`` the
    absolute virtual address to start from."""

    def __init__(self, data: bytes, base: int, entry: int, arch: str):
        self.data = data
        self.base = base
        self.entry = entry
        self.arch = arch

    def offset_of(self, vaddr: int) -> int | None:
        off = vaddr - self.base
        return off if 0 <= off < len(self.data) else None


def _pe_codeview(data: bytes) -> _CodeView | None:
    if not data.startswith(b"MZ") or len(data) < 0x40:
        return None
    e_lfanew = struct.unpack_from("<I", data, 0x3C)[0]
    coff = e_lfanew + 4
    if coff + 20 > len(data):
        return None
    machine, num_sections = struct.unpack_from("<HH", data, coff)
    opt_size = struct.unpack_from("<H", data, coff + 16)[0]
    opt_off = coff + 20
    opt_magic = struct.unpack_from("<H", data, opt_off)[0]
    is64 = opt_magic == 0x20B
    arch = {0x8664: "x64", 0x014C: "x86", 0xAA64: "arm64", 0x01C0: "arm"}.get(machine)
    if arch is None:
        return None
    entry_rva = struct.unpack_from("<I", data, opt_off + 16)[0]
    image_base = struct.unpack_from("<Q" if is64 else "<I", data,
                                    opt_off + (24 if is64 else 28))[0]

    # Find the section containing the entry RVA.
    sect_off = opt_off + opt_size
    for i in range(num_sections):
        b = sect_off + i * 40
        if b + 40 > len(data):
            break
        vsize, vaddr, rawsize, rawptr = struct.unpack_from("<IIII", data, b + 8)
        if vaddr <= entry_rva < vaddr + max(vsize, rawsize):
            blob = data[rawptr:rawptr + rawsize]
            return _CodeView(blob, image_base + vaddr, image_base + entry_rva, arch)
    return None


def _elf_codeview(data: bytes) -> _CodeView | None:
    if not data.startswith(b"\x7fELF") or len(data) < 64:
        return None
    is64 = data[4] == 2
    little = data[5] == 1
    en = "<" if little else ">"
    machine = struct.unpack_from(en + "H", data, 18)[0]
    arch = {0x3E: "x64", 0x03: "x86", 0xB7: "arm64", 0x28: "arm"}.get(machine)
    if arch is None:
        return None
    if is64:
        entry = struct.unpack_from(en + "Q", data, 24)[0]
        phoff = struct.unpack_from(en + "Q", data, 32)[0]
        phentsize, phnum = struct.unpack_from(en + "HH", data, 54)
    else:
        entry = struct.unpack_from(en + "I", data, 24)[0]
        phoff = struct.unpack_from(en + "I", data, 28)[0]
        phentsize, phnum = struct.unpack_from(en + "HH", data, 42)

    # Walk program headers for the executable PT_LOAD containing entry.
    for i in range(phnum):
        b = phoff + i * phentsize
        if b + phentsize > len(data):
            break
        p_type = struct.unpack_from(en + "I", data, b)[0]
        if p_type != 1:  # PT_LOAD
            continue
        if is64:
            p_offset = struct.unpack_from(en + "Q", data, b + 8)[0]
            p_vaddr = struct.unpack_from(en + "Q", data, b + 16)[0]
            p_filesz = struct.unpack_from(en + "Q", data, b + 32)[0]
            p_flags = struct.unpack_from(en + "I", data, b + 4)[0]
        else:
            p_offset = struct.unpack_from(en + "I", data, b + 4)[0]
            p_vaddr = struct.unpack_from(en + "I", data, b + 8)[0]
            p_filesz = struct.unpack_from(en + "I", data, b + 16)[0]
            p_flags = struct.unpack_from(en + "I", data, b + 24)[0]
        if (p_flags & 0x1) and p_vaddr <= entry < p_vaddr + p_filesz:  # PF_X
            blob = data[p_offset:p_offset + p_filesz]
            return _CodeView(blob, p_vaddr, entry, arch)
    return None


def _codeview(data: bytes, fmt: str) -> _CodeView | None:
    if fmt == "pe":
        return _pe_codeview(data)
    if fmt == "elf":
        return _elf_codeview(data)
    return None  # Mach-O left for a future pass


# --- capstone setup ------------------------------------------------------
def _make_cs(arch: str):
    modes = {
        "x64": (_cs.CS_ARCH_X86, _cs.CS_MODE_64),
        "x86": (_cs.CS_ARCH_X86, _cs.CS_MODE_32),
        "arm64": (_cs.CS_ARCH_ARM64, _cs.CS_MODE_ARM),
        "arm": (_cs.CS_ARCH_ARM, _cs.CS_MODE_ARM),
    }
    a, m = modes[arch]
    md = _cs.Cs(a, m)
    md.detail = True
    md.skipdata = False
    return md


# Groups that end a basic block.
def _terminates(insn) -> str | None:
    groups = set(insn.groups)
    if _cs.CS_GRP_RET in groups or insn.mnemonic in ("ret", "retn", "iret"):
        return "ret"
    if _cs.CS_GRP_JUMP in groups:
        # conditional jumps have a fallthrough successor; unconditional don't
        return "cond" if insn.mnemonic not in ("jmp",) else "jump"
    if _cs.CS_GRP_CALL in groups:
        return None  # calls don't end a block (fallthrough continues)
    if insn.mnemonic in ("hlt", "ud2"):
        return "ret"
    return None


def _direct_target(insn) -> int | None:
    """Absolute address of a direct branch's target operand, if immediate."""
    if not insn.operands:
        return None
    op = insn.operands[0]
    if op.type == _cs.CS_OP_IMM:
        return op.imm
    return None


def disassemble(data: bytes, fmt: str) -> Disassembly:
    if not _HAVE_CAPSTONE:
        return Disassembly(available=False, note="capstone not installed; skipped")
    view = _codeview(data, fmt)
    if view is None:
        return Disassembly(available=False,
                           note=f"no disassemblable code view for format '{fmt}'")
    try:
        return _recursive_descent(view)
    except Exception as exc:  # pragma: no cover - defensive
        return Disassembly(available=False, arch=view.arch, entry=view.entry,
                           note=f"disassembly error: {exc}")


def _recursive_descent(view: _CodeView) -> Disassembly:
    md = _make_cs(view.arch)
    blocks: dict[int, BasicBlock] = {}
    worklist = [view.entry]
    seen: set[int] = set()
    total_insns = 0
    truncated = False

    while worklist:
        addr = worklist.pop()
        if addr in seen:
            continue
        if len(blocks) >= _MAX_BLOCKS or total_insns >= _MAX_INSNS:
            truncated = True
            break
        seen.add(addr)

        off = view.offset_of(addr)
        if off is None:
            continue

        block = BasicBlock(address=addr)
        code = view.data[off:off + _MAX_BLOCK_INSNS * 16]
        for insn in md.disasm(code, addr):
            block.instructions.append(Instruction(
                address=insn.address,
                mnemonic=insn.mnemonic,
                op_str=insn.op_str,
                bytes_hex=" ".join(f"{b:02x}" for b in insn.bytes),
            ))
            total_insns += 1

            term = _terminates(insn)
            fallthrough = insn.address + insn.size
            target = _direct_target(insn)

            # Split at a target we already know starts a block, to keep blocks
            # non-overlapping (basic-block boundary).
            if term is None and len(block.instructions) >= _MAX_BLOCK_INSNS:
                block.kind = "fallthrough"
                block.successors = [fallthrough]
                worklist.append(fallthrough)
                break
            if term == "ret":
                block.kind = "ret"
                break
            if term == "jump":  # unconditional
                block.kind = "jump"
                if target is not None:
                    block.successors = [target]
                    worklist.append(target)
                break
            if term == "cond":  # conditional: target + fallthrough
                block.kind = "cond"
                succ = [s for s in (target, fallthrough) if s is not None]
                block.successors = succ
                worklist.extend(succ)
                break
            if total_insns >= _MAX_INSNS:
                truncated = True
                block.kind = "fallthrough"
                block.successors = [fallthrough]
                break
        else:
            # Ran out of decoded bytes without a terminator.
            if block.instructions:
                nxt = block.instructions[-1].address + 1
                block.successors = [nxt]

        if block.instructions:
            blocks[addr] = block

    ordered = [blocks[a] for a in sorted(blocks)]
    return Disassembly(
        available=True,
        arch=view.arch,
        entry=view.entry,
        blocks=ordered,
        truncated=truncated,
        note="" if ordered else "no instructions recovered at entry point",
    )
