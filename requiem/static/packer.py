"""Packer / protector detection.

Combines two orthogonal signals:

1. **Named signatures** — section names and byte markers unique to specific
   packers (UPX, Themida, ASPack, MPRESS, PECompact, Enigma, VMProtect...).
2. **Entropy heuristics** — a high-entropy executable section with a tiny (or
   zero) import table is the classic shape of a packed binary even when the
   packer strips its own name.
"""
from __future__ import annotations

from ..core.models import Confidence, Evidence, PackerGuess, SectionInfo

# (substring in section name OR byte marker, packer name, weight)
_SECTION_MARKERS = {
    "upx0": "UPX",
    "upx1": "UPX",
    "upx2": "UPX",
    ".themida": "Themida",
    ".winlice": "Themida/WinLicense",
    ".aspack": "ASPack",
    ".adata": "ASPack",
    ".mpress1": "MPRESS",
    ".mpress2": "MPRESS",
    "pec1": "PECompact",
    "pec2": "PECompact",
    ".enigma1": "Enigma Protector",
    ".enigma2": "Enigma Protector",
    ".vmp0": "VMProtect",
    ".vmp1": "VMProtect",
    ".petite": "Petite",
    ".nsp0": "NsPack",
    ".y0da": "yoda's Protector",
}

_BYTE_MARKERS = [
    (b"UPX!", "UPX"),
    (b"Themida", "Themida"),
    (b"WinLicense", "Themida/WinLicense"),
    (b".vmp", "VMProtect"),
    (b"MPRESS", "MPRESS"),
    (b"ENIGMA", "Enigma Protector"),
]


def detect(
    *, data: bytes, sections: list[SectionInfo], import_count: int
) -> list[PackerGuess]:
    guesses: dict[str, PackerGuess] = {}

    def note(name: str, conf: Confidence, detail: str, locator: str | None = None) -> None:
        g = guesses.get(name)
        if g is None:
            g = PackerGuess(name=name, confidence=conf)
            guesses[name] = g
        g.confidence = max(g.confidence, conf)
        g.evidence.append(Evidence(detail=detail, locator=locator, source="packer"))

    lower_sections = [(s, s.name.lower()) for s in sections]
    for sect, lname in lower_sections:
        for marker, packer in _SECTION_MARKERS.items():
            if marker in lname:
                note(packer, Confidence.HIGH,
                     f"Section '{sect.name}' matches {packer} signature",
                     locator=f"section:{sect.name}")

    window = data[:3_000_000]
    for marker, packer in _BYTE_MARKERS:
        if marker in window:
            note(packer, Confidence.MEDIUM,
                 f"Byte marker {marker!r} present", locator=f"bytes:{marker!r}")

    # Generic entropy heuristic — only if no named packer already explains it.
    if not guesses:
        exec_sections = [s for s in sections if "EXECUTE" in s.characteristics or
                         s.name.lower() in (".text", "__text")]
        high = [s for s in (exec_sections or sections) if s.entropy >= 7.2]
        if high and import_count <= 10:
            worst = max(high, key=lambda s: s.entropy)
            note("Unknown/custom packer", Confidence.MEDIUM,
                 f"High-entropy executable section '{worst.name}' "
                 f"({worst.entropy:.2f} bits/byte) with only {import_count} imports "
                 "— consistent with packing/obfuscation",
                 locator=f"section:{worst.name}")

    return list(guesses.values())
