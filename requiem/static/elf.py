"""ELF parsing — section names, entropy, and imported/dynamic symbols.

Pure ``struct`` implementation. We extract the section table (names + entropy)
and the dynamic symbol strings, which is enough for language fingerprinting
(Go/Rust/GCC markers) and behavioral import hints.
"""
from __future__ import annotations

import struct
from dataclasses import dataclass, field

from ..core.models import SectionInfo
from ..core.triage import shannon_entropy


@dataclass
class ELFInfo:
    sections: list[SectionInfo] = field(default_factory=list)
    imports: list[str] = field(default_factory=list)
    entrypoint: int | None = None
    interp: str | None = None
    is_stripped: bool = True
    func_symbols: list[tuple[str, int]] = field(default_factory=list)  # (name, VA)


def parse(data: bytes) -> ELFInfo:
    info = ELFInfo()
    if len(data) < 64:
        return info

    is64 = data[4] == 2
    little = data[5] == 1
    endian = "<" if little else ">"

    if is64:
        e_entry = struct.unpack_from(endian + "Q", data, 24)[0]
        e_shoff = struct.unpack_from(endian + "Q", data, 40)[0]
        e_shentsize, e_shnum, e_shstrndx = struct.unpack_from(endian + "HHH", data, 58)
    else:
        e_entry = struct.unpack_from(endian + "I", data, 24)[0]
        e_shoff = struct.unpack_from(endian + "I", data, 32)[0]
        e_shentsize, e_shnum, e_shstrndx = struct.unpack_from(endian + "HHH", data, 46)

    info.entrypoint = e_entry
    if not e_shoff or e_shnum == 0 or e_shstrndx >= e_shnum:
        return info

    # Locate the section-header string table.
    shstr_hdr = e_shoff + e_shstrndx * e_shentsize
    if is64:
        shstr_off = struct.unpack_from(endian + "Q", data, shstr_hdr + 24)[0]
        shstr_size = struct.unpack_from(endian + "Q", data, shstr_hdr + 32)[0]
    else:
        shstr_off = struct.unpack_from(endian + "I", data, shstr_hdr + 16)[0]
        shstr_size = struct.unpack_from(endian + "I", data, shstr_hdr + 20)[0]
    shstrtab = data[shstr_off : shstr_off + shstr_size]

    def _name(offset: int) -> str:
        end = shstrtab.find(b"\x00", offset)
        return shstrtab[offset:end].decode("latin-1", "replace") if end >= 0 else ""

    dynsym_off = dynsym_size = dynstr_off = dynstr_size = 0
    symtab_off = symtab_size = strtab_off = strtab_size = 0
    for i in range(e_shnum):
        base = e_shoff + i * e_shentsize
        if base + e_shentsize > len(data):
            break
        sh_name = struct.unpack_from(endian + "I", data, base)[0]
        sh_type = struct.unpack_from(endian + "I", data, base + 4)[0]
        if is64:
            sh_offset = struct.unpack_from(endian + "Q", data, base + 24)[0]
            sh_size = struct.unpack_from(endian + "Q", data, base + 32)[0]
        else:
            sh_offset = struct.unpack_from(endian + "I", data, base + 16)[0]
            sh_size = struct.unpack_from(endian + "I", data, base + 20)[0]

        name = _name(sh_name)
        raw = data[sh_offset : sh_offset + sh_size] if sh_type != 8 else b""  # skip NOBITS
        info.sections.append(SectionInfo(
            name=name,
            virtual_address=0,
            virtual_size=sh_size,
            raw_size=sh_size,
            entropy=shannon_entropy(raw) if raw else 0.0,
        ))
        if name == ".symtab":
            info.is_stripped = False
            symtab_off, symtab_size = sh_offset, sh_size
        elif name == ".strtab":
            strtab_off, strtab_size = sh_offset, sh_size
        elif name == ".dynsym":
            dynsym_off, dynsym_size = sh_offset, sh_size
        elif name == ".dynstr":
            dynstr_off, dynstr_size = sh_offset, sh_size
        elif name == ".interp":
            info.interp = raw.split(b"\x00", 1)[0].decode("latin-1", "replace")

    if dynsym_off and dynstr_off:
        info.imports = _dynamic_symbols(
            data, dynsym_off, dynsym_size, dynstr_off, dynstr_size, is64, endian)

    # Prefer the full .symtab for function seeds (present in unstripped
    # binaries); fall back to .dynsym (exported functions) otherwise.
    if symtab_off and strtab_off:
        info.func_symbols = _function_symbols(
            data, symtab_off, symtab_size, strtab_off, strtab_size, is64, endian)
    elif dynsym_off and dynstr_off:
        info.func_symbols = _function_symbols(
            data, dynsym_off, dynsym_size, dynstr_off, dynstr_size, is64, endian)
    return info


def _function_symbols(data, sym_off, sym_size, str_off, str_size, is64, endian
                      ) -> list[tuple[str, int]]:
    """Extract (name, virtual address) for defined STT_FUNC symbols."""
    strtab = data[str_off : str_off + str_size]
    ent = 24 if is64 else 16
    out: list[tuple[str, int]] = []
    for off in range(sym_off, sym_off + sym_size, ent):
        if off + ent > len(data):
            break
        st_name = struct.unpack_from(endian + "I", data, off)[0]
        if is64:
            st_info = data[off + 4]
            st_shndx = struct.unpack_from(endian + "H", data, off + 6)[0]
            st_value = struct.unpack_from(endian + "Q", data, off + 8)[0]
        else:
            st_value = struct.unpack_from(endian + "I", data, off + 4)[0]
            st_info = data[off + 12]
            st_shndx = struct.unpack_from(endian + "H", data, off + 14)[0]
        # low nibble of st_info is the type; 2 == STT_FUNC.
        if (st_info & 0xF) != 2 or st_value == 0 or st_shndx == 0:
            continue
        if st_name == 0 or st_name >= len(strtab):
            continue
        end = strtab.find(b"\x00", st_name)
        name = strtab[st_name:end].decode("latin-1", "replace")
        if name:
            out.append((name, st_value))
    return out


def _dynamic_symbols(data, sym_off, sym_size, str_off, str_size, is64, endian) -> list[str]:
    dynstr = data[str_off : str_off + str_size]
    ent = 24 if is64 else 16
    out: list[str] = []
    for off in range(sym_off, sym_off + sym_size, ent):
        if off + ent > len(data):
            break
        st_name = struct.unpack_from(endian + "I", data, off)[0]
        if st_name == 0 or st_name >= len(dynstr):
            continue
        end = dynstr.find(b"\x00", st_name)
        sym = dynstr[st_name:end].decode("latin-1", "replace")
        if sym:
            out.append(sym)
    return out
