"""File triage: hashing, format/arch detection, entropy.

Pure standard library — no optional deps required. This is the first stage of
the pipeline and must never fail on an unknown file; worst case it reports
``format='unknown'`` and lets later stages do what they can.
"""
from __future__ import annotations

import hashlib
import math
import struct
from collections import Counter

from .models import FileIdentity


def shannon_entropy(data: bytes) -> float:
    """Shannon entropy in bits/byte, range 0.0–8.0.

    ~8.0 means the bytes are indistinguishable from random — a strong hint of
    compression or encryption (i.e. packing).
    """
    if not data:
        return 0.0
    counts = Counter(data)
    length = len(data)
    return -sum((c / length) * math.log2(c / length) for c in counts.values())


def _hashes(data: bytes) -> tuple[str, str, str]:
    return (
        hashlib.md5(data).hexdigest(),
        hashlib.sha1(data).hexdigest(),
        hashlib.sha256(data).hexdigest(),
    )


# --- format sniffing -----------------------------------------------------
# Machine constants for the PE COFF header.
_PE_MACHINE = {
    0x014C: ("x86", 32),
    0x8664: ("x64", 64),
    0x01C0: ("arm", 32),
    0xAA64: ("arm64", 64),
    0x0200: ("ia64", 64),
}
_ELF_MACHINE = {
    0x03: ("x86", 0),
    0x3E: ("x64", 0),
    0x28: ("arm", 0),
    0xB7: ("arm64", 0),
    0xF3: ("riscv", 0),
}


def _detect_pe(data: bytes, ident: FileIdentity) -> bool:
    if not data.startswith(b"MZ") or len(data) < 0x40:
        return False
    e_lfanew = struct.unpack_from("<I", data, 0x3C)[0]
    if e_lfanew + 6 > len(data) or data[e_lfanew : e_lfanew + 4] != b"PE\x00\x00":
        return False
    ident.format = "pe"
    ident.magic = "PE32 executable (Windows)"
    ident.mime = "application/vnd.microsoft.portable-executable"
    machine = struct.unpack_from("<H", data, e_lfanew + 4)[0]
    arch, bits = _PE_MACHINE.get(machine, ("", 0))
    ident.arch = arch
    # Optional header magic tells 32 vs 64 authoritatively.
    opt_off = e_lfanew + 24
    if opt_off + 2 <= len(data):
        opt_magic = struct.unpack_from("<H", data, opt_off)[0]
        ident.bitness = 64 if opt_magic == 0x20B else 32 if opt_magic == 0x10B else bits
    else:
        ident.bitness = bits
    return True


def _detect_elf(data: bytes, ident: FileIdentity) -> bool:
    if not data.startswith(b"\x7fELF") or len(data) < 20:
        return False
    ident.format = "elf"
    ident.magic = "ELF executable (Unix/Linux)"
    ident.mime = "application/x-executable"
    ident.bitness = 64 if data[4] == 2 else 32
    little = data[5] == 1
    machine = struct.unpack_from("<H" if little else ">H", data, 18)[0]
    ident.arch = _ELF_MACHINE.get(machine, ("", 0))[0]
    return True


def _detect_macho(data: bytes, ident: FileIdentity) -> bool:
    if len(data) < 4:
        return False
    magic = struct.unpack_from(">I", data, 0)[0]
    macho_magics = {0xFEEDFACE, 0xFEEDFACF, 0xCEFAEDFE, 0xCFFAEDFE, 0xCAFEBABE, 0xBEBAFECA}
    if magic not in macho_magics:
        return False
    ident.format = "macho"
    ident.magic = "Mach-O executable (macOS)"
    ident.mime = "application/x-mach-binary"
    if magic in (0xFEEDFACF, 0xCFFAEDFE):
        ident.bitness = 64
    elif magic in (0xFEEDFACE, 0xCEFAEDFE):
        ident.bitness = 32
    return True


def _detect_other(data: bytes, ident: FileIdentity) -> None:
    """Best-effort classification for non-native-executable samples."""
    head = data[:8]
    if head.startswith(b"PK\x03\x04"):
        # Could be zip, jar, or OOXML office doc — refine on content later.
        ident.format = "archive"
        ident.magic = "ZIP archive / OOXML container"
        ident.mime = "application/zip"
    elif head.startswith(b"\xd0\xcf\x11\xe0"):
        ident.format = "office"
        ident.magic = "OLE compound document (legacy Office)"
        ident.mime = "application/x-ole-storage"
    elif head.startswith(b"%PDF"):
        ident.format = "pdf"
        ident.magic = "PDF document"
        ident.mime = "application/pdf"
    elif b"#!" == head[:2] or _looks_like_script(data):
        ident.format = "script"
        ident.magic = "Text script"
        ident.mime = "text/plain"
    else:
        ident.format = "unknown"
        ident.magic = "data"
        ident.mime = "application/octet-stream"


def _looks_like_script(data: bytes) -> bool:
    sample = data[:4096]
    try:
        text = sample.decode("utf-8")
    except UnicodeDecodeError:
        return False
    printable = sum(c.isprintable() or c in "\r\n\t" for c in text)
    return len(text) > 0 and printable / len(text) > 0.95


def triage(data: bytes, filename: str) -> FileIdentity:
    """Produce the :class:`FileIdentity` for a raw sample buffer."""
    md5, sha1, sha256 = _hashes(data)
    ident = FileIdentity(
        filename=filename,
        size=len(data),
        md5=md5,
        sha1=sha1,
        sha256=sha256,
    )
    for detector in (_detect_pe, _detect_elf, _detect_macho):
        if detector(data, ident):
            return ident
    _detect_other(data, ident)
    return ident
