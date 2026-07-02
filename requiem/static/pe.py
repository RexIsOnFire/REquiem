"""PE (Portable Executable) parsing.

Prefers the ``pefile`` library when installed (accurate import resolution), but
falls back to a compact pure-``struct`` parser so ReQuiem produces useful
section/entropy data on any machine with just the stdlib.
"""
from __future__ import annotations

import struct
from dataclasses import dataclass, field

from ..core.models import SectionInfo
from ..core.triage import shannon_entropy

try:  # optional, greatly improves import fidelity
    import pefile  # type: ignore

    _HAVE_PEFILE = True
except Exception:  # pragma: no cover - import guard
    _HAVE_PEFILE = False


@dataclass
class PEInfo:
    sections: list[SectionInfo] = field(default_factory=list)
    imports: list[str] = field(default_factory=list)         # "kernel32.dll!CreateFileW"
    exports: list[str] = field(default_factory=list)
    imported_dlls: list[str] = field(default_factory=list)
    entrypoint: int | None = None
    image_base: int = 0
    func_symbols: list[tuple[str, int]] = field(default_factory=list)  # (name, VA)
    timestamp: int | None = None
    rich_ids: list[int] = field(default_factory=list)         # Rich header comp.id values
    tls_used: bool = False
    resources: int = 0
    is_dotnet: bool = False


_SECTION_FLAGS = {
    0x00000020: "CODE",
    0x00000040: "INITIALIZED_DATA",
    0x00000080: "UNINITIALIZED_DATA",
    0x20000000: "EXECUTE",
    0x40000000: "READ",
    0x80000000: "WRITE",
}


def _flags(characteristics: int) -> list[str]:
    return [name for bit, name in _SECTION_FLAGS.items() if characteristics & bit]


def parse(data: bytes) -> PEInfo:
    if _HAVE_PEFILE:
        try:
            return _parse_with_pefile(data)
        except Exception:
            pass  # fall through to the stdlib parser
    return _parse_stdlib(data)


# --- pefile path ---------------------------------------------------------
def _parse_with_pefile(data: bytes) -> PEInfo:
    pe = pefile.PE(data=data, fast_load=True)
    pe.parse_data_directories(directories=[
        pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_IMPORT"],
        pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_EXPORT"],
        pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_TLS"],
        pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_RESOURCE"],
        pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR"],
    ])
    info = PEInfo()
    info.entrypoint = pe.OPTIONAL_HEADER.AddressOfEntryPoint
    info.image_base = pe.OPTIONAL_HEADER.ImageBase
    info.timestamp = pe.FILE_HEADER.TimeDateStamp

    for sect in pe.sections:
        raw = sect.get_data()
        name = sect.Name.rstrip(b"\x00").decode("latin-1", "replace")
        info.sections.append(SectionInfo(
            name=name,
            virtual_address=sect.VirtualAddress,
            virtual_size=sect.Misc_VirtualSize,
            raw_size=sect.SizeOfRawData,
            entropy=shannon_entropy(raw) if raw else 0.0,
            characteristics=_flags(sect.Characteristics),
        ))

    for entry in getattr(pe, "DIRECTORY_ENTRY_IMPORT", []) or []:
        dll = entry.dll.decode("latin-1", "replace") if entry.dll else "?"
        info.imported_dlls.append(dll)
        for imp in entry.imports:
            fn = imp.name.decode("latin-1", "replace") if imp.name else f"ord_{imp.ordinal}"
            info.imports.append(f"{dll}!{fn}")

    export_dir = getattr(pe, "DIRECTORY_ENTRY_EXPORT", None)
    if export_dir:
        for exp in export_dir.symbols:
            if exp.name:
                name = exp.name.decode("latin-1", "replace")
                info.exports.append(name)
                if exp.address:  # RVA -> VA; only code-ish exports are useful
                    info.func_symbols.append((name, info.image_base + exp.address))

    info.tls_used = hasattr(pe, "DIRECTORY_ENTRY_TLS")
    info.resources = len(getattr(pe, "DIRECTORY_ENTRY_RESOURCE", []) and
                          pe.DIRECTORY_ENTRY_RESOURCE.entries or [])
    com = pe.OPTIONAL_HEADER.DATA_DIRECTORY[
        pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR"]]
    info.is_dotnet = com.VirtualAddress != 0

    rich = getattr(pe, "RICH_HEADER", None)
    if rich and rich.values:
        # values alternate (comp.id, count); keep the comp.id entries.
        info.rich_ids = list(rich.values[0::2])
    return info


# --- stdlib fallback -----------------------------------------------------
def _parse_stdlib(data: bytes) -> PEInfo:
    info = PEInfo()
    e_lfanew = struct.unpack_from("<I", data, 0x3C)[0]
    coff = e_lfanew + 4
    num_sections = struct.unpack_from("<H", data, coff + 2)[0]
    info.timestamp = struct.unpack_from("<I", data, coff + 4)[0]
    opt_size = struct.unpack_from("<H", data, coff + 16)[0]
    opt_off = coff + 20
    opt_magic = struct.unpack_from("<H", data, opt_off)[0]
    is64 = opt_magic == 0x20B
    info.entrypoint = struct.unpack_from("<I", data, opt_off + 16)[0]
    info.image_base = struct.unpack_from("<Q" if is64 else "<I", data,
                                         opt_off + (24 if is64 else 28))[0]

    # .NET check via COM descriptor data directory (index 14).
    num_dirs = struct.unpack_from("<I", data, opt_off + (108 if is64 else 92))[0]
    dir_base = opt_off + (112 if is64 else 96)
    if num_dirs > 14:
        com_rva = struct.unpack_from("<I", data, dir_base + 14 * 8)[0]
        info.is_dotnet = com_rva != 0

    sect_off = opt_off + opt_size
    for i in range(num_sections):
        base = sect_off + i * 40
        if base + 40 > len(data):
            break
        name = data[base : base + 8].rstrip(b"\x00").decode("latin-1", "replace")
        vsize, vaddr, rawsize, rawptr = struct.unpack_from("<IIII", data, base + 8)
        chars = struct.unpack_from("<I", data, base + 36)[0]
        raw = data[rawptr : rawptr + rawsize] if rawsize else b""
        info.sections.append(SectionInfo(
            name=name,
            virtual_address=vaddr,
            virtual_size=vsize,
            raw_size=rawsize,
            entropy=shannon_entropy(raw) if raw else 0.0,
            characteristics=_flags(chars),
        ))

    info.imported_dlls = _scan_import_dll_names(data)
    return info


def _scan_import_dll_names(data: bytes) -> list[str]:
    """Cheap heuristic: pull plausible DLL names from the raw image.

    Without walking the import table we can't get function names, but the set
    of imported DLLs alone is a strong behavioral signal (ws2_32 -> network,
    crypt32 -> crypto, etc.).
    """
    import re

    names = set()
    for m in re.finditer(rb"[A-Za-z0-9_\-]{3,}\.[Dd][Ll][Ll]", data):
        try:
            names.add(m.group().decode("latin-1").lower())
        except Exception:
            continue
    return sorted(names)
