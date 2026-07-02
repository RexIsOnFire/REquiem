"""Language & compiler fingerprinting — ReQuiem's headline feature.

We don't guess from a single marker. Each language accrues a *score* from
multiple independent signal classes (section names, symbol/import strings, and
raw-byte patterns), and every point of score records the evidence that earned
it. The top scorer becomes the primary :class:`LanguageGuess`, with confidence
derived from both its absolute score and its margin over the runner-up.

This mirrors how a human analyst reasons: "``.gopclntab`` section *and*
``runtime.morestack`` *and* Go build-id — that's Go, high confidence."
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field

from ..core.models import Confidence, Evidence, LanguageGuess


@dataclass
class _Signal:
    """One matchable indicator worth ``weight`` points toward ``language``."""

    language: str
    weight: int
    detail: str
    compiler: str | None = None


@dataclass
class _Score:
    score: float = 0.0
    compiler: str | None = None
    evidence: list[Evidence] = field(default_factory=list)


# --- signal tables -------------------------------------------------------
# Section-name signals (checked against parsed section names, case-insensitive).
_SECTION_SIGNALS: list[tuple[str, _Signal]] = [
    (".gopclntab", _Signal("Go", 45, "Go pcln table section (.gopclntab)", "gc (Go toolchain)")),
    (".go.buildinfo", _Signal("Go", 40, "Go build info section (.go.buildinfo)", "gc (Go toolchain)")),
    (".gosymtab", _Signal("Go", 25, "Go symbol table section (.gosymtab)", "gc (Go toolchain)")),
    (".themida", _Signal("C/C++", 5, "Themida-protected section")),
    ("upx0", _Signal("C/C++", 3, "UPX-packed section (upx0)")),
    (".rustc", _Signal("Rust", 35, "Rust compiler metadata section (.rustc)", "rustc")),
    (".rdata$zzzdbg", _Signal("C/C++", 10, "MSVC debug rdata section")),
    (".cormeta", _Signal("C#/.NET", 30, "CLR metadata section (.cormeta)", ".NET runtime")),
]

# Symbol / import / string signals — regexes tested against symbol+string pools.
_STRING_SIGNALS: list[_Signal] = [
    _Signal("Go", 40, r"runtime\.morestack", "gc (Go toolchain)"),
    _Signal("Go", 30, r"runtime\.goexit", "gc (Go toolchain)"),
    _Signal("Go", 25, r"runtime\.gopanic", "gc (Go toolchain)"),
    _Signal("Go", 35, r"Go build ID:", "gc (Go toolchain)"),
    _Signal("Go", 20, r"go:buildid", "gc (Go toolchain)"),
    _Signal("Go", 15, r"/usr/local/go/src/", "gc (Go toolchain)"),

    _Signal("Rust", 40, r"__rust_alloc\b", "rustc"),
    _Signal("Rust", 35, r"rust_panic|rust_begin_unwind", "rustc"),
    _Signal("Rust", 30, r"core::panicking::panic", "rustc"),
    _Signal("Rust", 20, r"/rustc/[0-9a-f]{7,}", "rustc"),
    _Signal("Rust", 15, r"cargo/registry", "rustc"),

    _Signal("C#/.NET", 45, r"mscoree\.dll", ".NET runtime"),
    _Signal("C#/.NET", 30, r"System\.Private\.CoreLib|mscorlib", ".NET runtime"),
    _Signal("C#/.NET", 20, r"<Module>|get_.*\(", ".NET runtime"),

    _Signal("C++ (MSVC)", 30, r"MSVCP\d{2,3}\.dll|VCRUNTIME\d{2,3}", "Microsoft Visual C++"),
    _Signal("C++ (MSVC)", 20, r"\?\?[0-9A-Za-z_@]+@@", "Microsoft Visual C++"),  # MSVC mangling
    _Signal("C (MSVC)", 15, r"api-ms-win-crt", "Microsoft Visual C++ CRT"),

    _Signal("C/C++ (GCC/MinGW)", 25, r"libgcc|__gmon_start__|GCC: \(", "GCC / MinGW"),
    _Signal("C/C++ (GCC/MinGW)", 20, r"_Z[LN]?\d+[A-Za-z]", "GCC (Itanium mangling)"),

    _Signal("Delphi", 35, r"Borland|CodeGear|Embarcadero", "Delphi / RAD Studio"),
    _Signal("Delphi", 25, r"TObject|System@|Vcl\.", "Delphi / RAD Studio"),

    _Signal("Nim", 35, r"NimMain|nimFrame|@m[a-z]+\.nim", "Nim"),
    _Signal("Python (frozen)", 40, r"PyInstaller|_MEIPASS|py2exe", "CPython (frozen)"),
    _Signal("Python (frozen)", 25, r"python3?\d\.dll|libpython", "CPython"),

    _Signal("AutoIt", 40, r"AU3!EA06|AutoIt", "AutoIt compiler"),
    _Signal(".NET (obfuscated)", 20, r"ConfuserEx|SmartAssembly|Dotfuscator", ".NET obfuscator"),
]

# Raw-byte signatures (checked against the whole file buffer).
_BYTE_SIGNALS: list[tuple[bytes, _Signal]] = [
    (b"\xff Go build ID:", _Signal("Go", 45, "Go build ID magic in binary", "gc (Go toolchain)")),
    (b"go1.", _Signal("Go", 10, "Go version string (go1.x)", "gc (Go toolchain)")),
    (b"rustc-", _Signal("Rust", 15, "rustc version string")),
]


def _pool(symbols: list[str], strings: list[str], imports: list[str]) -> str:
    """Concatenate all text signals into one searchable blob (lowercased copy kept separate)."""
    return "\n".join(symbols) + "\n" + "\n".join(strings) + "\n" + "\n".join(imports)


def fingerprint(
    *,
    data: bytes,
    section_names: list[str],
    symbols: list[str],
    strings: list[str],
    imports: list[str],
) -> list[LanguageGuess]:
    scores: dict[str, _Score] = {}

    def bump(sig: _Signal, locator: str | None = None) -> None:
        s = scores.setdefault(sig.language, _Score())
        s.score += sig.weight
        if sig.compiler and not s.compiler:
            s.compiler = sig.compiler
        s.evidence.append(Evidence(detail=sig.detail, locator=locator, source="language"))

    lower_sections = [n.lower() for n in section_names]
    for needle, sig in _SECTION_SIGNALS:
        if any(needle in name for name in lower_sections):
            bump(sig, locator=f"section:{needle}")

    pool = _pool(symbols, strings, imports)
    for sig in _STRING_SIGNALS:
        m = re.search(sig.detail, pool)
        if m:
            bump(sig, locator=f"match:{m.group()[:48]}")

    # Byte signatures on a bounded window (headers + a slice) to stay fast.
    window = data[:2_000_000]
    for needle, sig in _BYTE_SIGNALS:
        if needle in window:
            bump(sig, locator=f"bytes:{needle[:16]!r}")

    guesses: list[LanguageGuess] = []
    ordered = sorted(scores.items(), key=lambda kv: kv[1].score, reverse=True)
    top = ordered[0][1].score if ordered else 0.0
    runner_up = ordered[1][1].score if len(ordered) > 1 else 0.0

    for i, (lang, sc) in enumerate(ordered):
        # Confidence blends absolute strength with margin over the next guess.
        margin = (sc.score - runner_up) if i == 0 else 0.0
        conf_score = min(100.0, sc.score + (margin * 0.3))
        guesses.append(LanguageGuess(
            language=lang,
            confidence=Confidence.from_score(conf_score),
            compiler=sc.compiler,
            evidence=sc.evidence,
        ))

    if not guesses:
        guesses.append(LanguageGuess(
            language="unknown",
            confidence=Confidence.NONE,
            evidence=[Evidence("No language-specific markers found", source="language")],
        ))
    return guesses
