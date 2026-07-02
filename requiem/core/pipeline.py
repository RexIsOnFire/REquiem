"""The ReQuiem pipeline — one call, one investigation, one report.

``analyze()`` runs the full chain:

    triage -> format parse -> language/packer -> strings/IOC -> YARA
           -> intel lookup -> dynamic detonation -> ATT&CK inference -> verdict

Each stage only enriches the shared :class:`AnalysisReport`. Optional stages
(intel, dynamic, YARA) are controlled by :class:`PipelineOptions` so the same
code path serves a fast offline CLI run and a full server-side investigation.
"""
from __future__ import annotations

from dataclasses import dataclass, field

from ..attack.inference import run_inference
from ..dynamic.base import DynamicBackend
from ..dynamic.simulated import SimulatedBackend
from ..intel.base import IntelProvider, gather_intel
from ..intel.providers import default_providers
from ..static import elf, language, macho, packer, pe, strings_ioc, yara_scan
from .models import AnalysisReport, FileIdentity
from .triage import triage


@dataclass
class PipelineOptions:
    run_intel: bool = False          # off by default: no surprise network calls
    offline_intel: bool = True
    run_dynamic: bool = True
    run_yara: bool = True
    max_strings: int = 60_000
    intel_providers: list[IntelProvider] | None = None
    dynamic_backend: DynamicBackend | None = None
    interesting_string_limit: int = 400


# Strings we surface to the analyst / feed to inference (behaviorally loaded).
_INTERESTING = (
    "http", "https", "\\run", "schtasks", "powershell", "cmd.exe", "lsass",
    "vssadmin", "bcdedit", "encrypt", "decrypt", "ransom", ".onion", "bitcoin",
    "createremotethread", "virtualalloc", "regsetvalue", "cryptencrypt",
    "wininet", "socket", "mutex", "debugger",
)


def _filter_interesting(strings: list[str], limit: int) -> list[str]:
    out, seen = [], set()
    for s in strings:
        low = s.lower()
        if any(tok in low for tok in _INTERESTING) and s not in seen:
            seen.add(s)
            out.append(s)
            if len(out) >= limit:
                break
    return out


def _parse_format(data: bytes, ident: FileIdentity, report: AnalysisReport) -> dict:
    """Dispatch to the right format parser; returns extra fingerprint inputs."""
    symbols: list[str] = []
    if ident.format == "pe":
        info = pe.parse(data)
        report.sections = info.sections
        report.imports = info.imports or [f"{d}!*" for d in info.imported_dlls]
        report.exports = info.exports
        if info.entrypoint is not None:
            ident.entrypoint = info.entrypoint
        if info.is_dotnet:
            report.strings_of_interest.append("[.NET managed assembly]")
    elif ident.format == "elf":
        info = elf.parse(data)
        report.sections = info.sections
        report.imports = info.imports
        symbols = info.imports
    elif ident.format == "macho":
        info = macho.parse(data)
        report.sections = info.sections
        report.imports = info.imports
        symbols = info.symbols
        if info.entrypoint is not None:
            ident.entrypoint = info.entrypoint
    return {"symbols": symbols}


def analyze(data: bytes, filename: str, options: PipelineOptions | None = None) -> AnalysisReport:
    opts = options or PipelineOptions()

    ident = triage(data, filename)
    report = AnalysisReport(identity=ident)

    parsed = _parse_format(data, ident, report)

    # Strings + IOCs.
    all_strings = strings_ioc.extract_strings(data, limit=opts.max_strings)
    report.iocs = strings_ioc.harvest_iocs(all_strings)
    report.strings_of_interest += _filter_interesting(all_strings, opts.interesting_string_limit)

    # Language fingerprint.
    report.languages = language.fingerprint(
        data=data,
        section_names=[s.name for s in report.sections],
        symbols=parsed["symbols"],
        strings=all_strings,
        imports=report.imports,
    )

    # Packer.
    report.packers = packer.detect(
        data=data, sections=report.sections, import_count=len(report.imports))

    # YARA.
    if opts.run_yara:
        yres = yara_scan.scan(data)
        report.yara_matches = yres.matches

    # Intel (opt-in).
    if opts.run_intel:
        providers = opts.intel_providers or default_providers(offline=opts.offline_intel)
        report.intel = gather_intel(providers, sha256=ident.sha256,
                                    md5=ident.md5, sha1=ident.sha1)

    # A first, cheap inference pass so dynamic hints know a likely classification.
    run_inference(report)

    # Dynamic detonation (simulated by default) with static hints.
    if opts.run_dynamic:
        backend = opts.dynamic_backend or SimulatedBackend()
        hints = {
            "imports": report.imports,
            "strings": report.strings_of_interest,
            "urls": report.iocs.urls,
            "ipv4": report.iocs.ipv4,
            "registry_keys": report.iocs.registry_keys,
            "classification": report.classification,
            "packed": bool(report.packers),
        }
        report.dynamic = backend.detonate(data=data, identity=ident, static_hints=hints)

        # Re-run inference now that dynamic/memory findings exist. Reset the
        # derived fields first so we don't double-count the static pass.
        report.findings.clear()
        report.attack.clear()
        run_inference(report)

    return report
