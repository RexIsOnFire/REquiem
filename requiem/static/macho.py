"""Mach-O parsing — segments/sections, entropy, linked libraries and symbols.

Handles thin 32/64-bit Mach-O. For fat/universal binaries we parse the first
architecture slice, which is enough for triage and language fingerprinting.
"""
from __future__ import annotations

import struct
from dataclasses import dataclass, field

from ..core.models import SectionInfo
from ..core.triage import shannon_entropy

_LC_SEGMENT = 0x01
_LC_SEGMENT_64 = 0x19
_LC_LOAD_DYLIB = 0x0C
_LC_SYMTAB = 0x02


@dataclass
class MachOInfo:
    sections: list[SectionInfo] = field(default_factory=list)
    imports: list[str] = field(default_factory=list)   # linked dylibs
    symbols: list[str] = field(default_factory=list)
    entrypoint: int | None = None


def parse(data: bytes) -> MachOInfo:
    info = MachOInfo()
    if len(data) < 4:
        return info

    magic = struct.unpack_from(">I", data, 0)[0]
    # Universal binary: jump to first slice.
    if magic in (0xCAFEBABE, 0xBEBAFECA):
        nfat = struct.unpack_from(">I", data, 4)[0]
        if nfat and len(data) >= 20:
            offset = struct.unpack_from(">I", data, 16)[0]
            return parse(data[offset:])
        return info

    little = magic in (0xCEFAEDFE, 0xCFFAEDFE)
    is64 = magic in (0xFEEDFACF, 0xCFFAEDFE)
    endian = "<" if little else ">"

    header_size = 32 if is64 else 28
    ncmds = struct.unpack_from(endian + "I", data, 16)[0]
    off = header_size

    for _ in range(ncmds):
        if off + 8 > len(data):
            break
        cmd, cmdsize = struct.unpack_from(endian + "II", data, off)
        if cmdsize == 0:
            break

        if cmd in (_LC_SEGMENT, _LC_SEGMENT_64):
            _parse_segment(data, off, is64, endian, info)
        elif cmd == _LC_LOAD_DYLIB:
            name_off = struct.unpack_from(endian + "I", data, off + 8)[0]
            raw = data[off + name_off : off + cmdsize].split(b"\x00", 1)[0]
            info.imports.append(raw.decode("latin-1", "replace"))
        elif cmd == _LC_SYMTAB:
            _parse_symtab(data, off, endian, info)

        off += cmdsize
    return info


def _parse_segment(data, off, is64, endian, info: MachOInfo) -> None:
    if is64:
        nsects = struct.unpack_from(endian + "I", data, off + 64)[0]
        sect_off = off + 72
        sect_size = 80
    else:
        nsects = struct.unpack_from(endian + "I", data, off + 48)[0]
        sect_off = off + 56
        sect_size = 68
    for i in range(nsects):
        base = sect_off + i * sect_size
        if base + sect_size > len(data):
            break
        sectname = data[base : base + 16].rstrip(b"\x00").decode("latin-1", "replace")
        segname = data[base + 16 : base + 32].rstrip(b"\x00").decode("latin-1", "replace")
        if is64:
            offset = struct.unpack_from(endian + "I", data, base + 48)[0]
            size = struct.unpack_from(endian + "Q", data, base + 40)[0]
        else:
            offset = struct.unpack_from(endian + "I", data, base + 40)[0]
            size = struct.unpack_from(endian + "I", data, base + 36)[0]
        raw = data[offset : offset + size] if offset else b""
        info.sections.append(SectionInfo(
            name=f"{segname},{sectname}",
            virtual_address=0,
            virtual_size=size,
            raw_size=size,
            entropy=shannon_entropy(raw) if raw else 0.0,
        ))


def _parse_symtab(data, off, endian, info: MachOInfo) -> None:
    symoff, nsyms, stroff, strsize = struct.unpack_from(endian + "IIII", data, off + 8)
    strtab = data[stroff : stroff + strsize]
    # Cap symbol harvesting; the string table is what fingerprinting needs.
    for i in range(min(nsyms, 20000)):
        n_off = symoff + i * 16
        if n_off + 4 > len(data):
            break
        strx = struct.unpack_from(endian + "I", data, n_off)[0]
        if 0 < strx < len(strtab):
            end = strtab.find(b"\x00", strx)
            sym = strtab[strx:end].decode("latin-1", "replace")
            if sym:
                info.symbols.append(sym)
