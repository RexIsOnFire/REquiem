"""Shared data model for ReQuiem.

Every analyzer produces or enriches an :class:`AnalysisReport`. The report is a
plain dataclass tree so it serializes cleanly to JSON for the API/frontend and
carries *evidence* alongside every conclusion — explainability is a first-class
concern, not an afterthought.
"""
from __future__ import annotations

import dataclasses
import enum
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any


class Confidence(enum.IntEnum):
    """Coarse confidence buckets, ordered so ``max()`` picks the strongest."""

    NONE = 0
    LOW = 25
    MEDIUM = 60
    HIGH = 85
    CERTAIN = 100

    @classmethod
    def from_score(cls, score: float) -> "Confidence":
        score = max(0.0, min(100.0, score))
        for level in (cls.CERTAIN, cls.HIGH, cls.MEDIUM, cls.LOW):
            if score >= level.value:
                return level
        return cls.NONE


class Severity(enum.IntEnum):
    INFO = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4


@dataclass
class Evidence:
    """A single fact that supports a finding.

    ``locator`` is optional context — a file offset, a section name, an import,
    a matched string — so the UI can jump the analyst straight to the proof.
    """

    detail: str
    locator: str | None = None
    source: str | None = None  # which analyzer produced it


@dataclass
class Finding:
    """An explainable conclusion: what we think, how sure, and why."""

    title: str
    description: str
    confidence: Confidence = Confidence.MEDIUM
    severity: Severity = Severity.INFO
    evidence: list[Evidence] = field(default_factory=list)
    attack_techniques: list[str] = field(default_factory=list)  # e.g. ["T1547.001"]
    tags: list[str] = field(default_factory=list)

    def add(self, detail: str, locator: str | None = None, source: str | None = None) -> "Finding":
        self.evidence.append(Evidence(detail=detail, locator=locator, source=source))
        return self


@dataclass
class FileIdentity:
    """Basic triage identity of the sample."""

    filename: str
    size: int
    md5: str
    sha1: str
    sha256: str
    magic: str = ""            # human-readable file type guess
    mime: str = ""
    format: str = "unknown"    # pe | elf | macho | office | script | archive | unknown
    arch: str = ""             # x86 | x64 | arm | arm64 | ...
    bitness: int = 0           # 32 | 64
    entrypoint: int | None = None


@dataclass
class LanguageGuess:
    """The 'killer feature': what language/toolchain built this."""

    language: str
    confidence: Confidence = Confidence.MEDIUM
    compiler: str | None = None
    evidence: list[Evidence] = field(default_factory=list)


@dataclass
class PackerGuess:
    name: str
    confidence: Confidence = Confidence.MEDIUM
    evidence: list[Evidence] = field(default_factory=list)


@dataclass
class SectionInfo:
    name: str
    virtual_address: int
    virtual_size: int
    raw_size: int
    entropy: float
    characteristics: list[str] = field(default_factory=list)

    @property
    def suspicious(self) -> bool:
        # High entropy in a normally-code/data section suggests packing/encryption.
        return self.entropy >= 7.2


@dataclass
class IOCSet:
    ipv4: list[str] = field(default_factory=list)
    domains: list[str] = field(default_factory=list)
    urls: list[str] = field(default_factory=list)
    emails: list[str] = field(default_factory=list)
    file_paths: list[str] = field(default_factory=list)
    registry_keys: list[str] = field(default_factory=list)
    mutexes: list[str] = field(default_factory=list)
    bitcoin: list[str] = field(default_factory=list)

    def is_empty(self) -> bool:
        return not any(dataclasses.astuple(self))


@dataclass
class IntelResult:
    """Result of a hash-reputation lookup. Never contains the binary itself."""

    source: str
    known: bool = False
    family: str | None = None
    first_seen: str | None = None
    prevalence: int | None = None
    tags: list[str] = field(default_factory=list)
    detail: str | None = None


@dataclass
class MemoryRegion:
    """One region of the process address space captured during execution.

    This is the structured backbone of the memory visualization. ``kind``
    classifies the region for coloring; ``backed`` distinguishes image-backed
    memory (a mapped file/DLL) from private/unbacked allocations (the shape of
    injected shellcode or an unpacked payload).
    """

    base: int
    size: int
    protection: str            # "rwx", "rw-", "r-x", "r--", etc.
    kind: str = "private"      # image | mapped | private | heap | stack | shellcode
    backed: bool = True        # backed by a file/image on disk?
    label: str = ""            # e.g. "kernel32.dll", "unpacked payload"
    suspicious: bool = False

    @property
    def executable(self) -> bool:
        return "x" in self.protection

    @property
    def writable(self) -> bool:
        return "w" in self.protection


@dataclass
class HeapSample:
    """A point on the heap-growth timeline: committed bytes at time ``t_ms``."""

    t_ms: int
    committed: int             # total committed heap bytes at this instant
    note: str = ""             # optional event marker, e.g. "AES loop begins"


@dataclass
class DynamicBehavior:
    """Container for dynamic/sandbox observations (real or simulated)."""

    executed: bool = False
    backend: str = "none"
    simulated: bool = False
    process_tree: list[dict[str, Any]] = field(default_factory=list)
    network: list[dict[str, Any]] = field(default_factory=list)
    filesystem: list[dict[str, Any]] = field(default_factory=list)
    registry: list[dict[str, Any]] = field(default_factory=list)
    memory: list[Finding] = field(default_factory=list)
    memory_map: list[MemoryRegion] = field(default_factory=list)
    heap_timeline: list[HeapSample] = field(default_factory=list)


@dataclass
class AttackTechnique:
    technique_id: str
    name: str
    tactic: str
    confidence: Confidence = Confidence.MEDIUM
    evidence: list[Evidence] = field(default_factory=list)


@dataclass
class AnalysisReport:
    """The complete picture — the single object the whole pipeline enriches."""

    identity: FileIdentity
    created_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    engine_version: str = "0.1.0"

    languages: list[LanguageGuess] = field(default_factory=list)
    packers: list[PackerGuess] = field(default_factory=list)
    sections: list[SectionInfo] = field(default_factory=list)
    imports: list[str] = field(default_factory=list)
    exports: list[str] = field(default_factory=list)
    strings_of_interest: list[str] = field(default_factory=list)
    iocs: IOCSet = field(default_factory=IOCSet)
    yara_matches: list[str] = field(default_factory=list)

    intel: list[IntelResult] = field(default_factory=list)
    dynamic: DynamicBehavior = field(default_factory=DynamicBehavior)

    findings: list[Finding] = field(default_factory=list)
    attack: list[AttackTechnique] = field(default_factory=list)

    verdict: str = "unknown"           # benign | suspicious | malicious | unknown
    verdict_confidence: Confidence = Confidence.NONE
    classification: str | None = None  # e.g. "ransomware", "infostealer"
    summary: str = ""                  # human-readable executive explanation

    # --- convenience -----------------------------------------------------
    @property
    def overall_entropy(self) -> float:
        if not self.sections:
            return 0.0
        total = sum(s.raw_size for s in self.sections) or 1
        return sum(s.entropy * s.raw_size for s in self.sections) / total

    def to_dict(self) -> dict[str, Any]:
        return _asdict(self)


def _asdict(obj: Any) -> Any:
    """dataclasses.asdict that renders enums as ``{name, value}`` for the UI."""
    if dataclasses.is_dataclass(obj) and not isinstance(obj, type):
        return {f.name: _asdict(getattr(obj, f.name)) for f in dataclasses.fields(obj)}
    if isinstance(obj, enum.Enum):
        return {"name": obj.name, "value": int(obj.value)}
    if isinstance(obj, (list, tuple)):
        return [_asdict(v) for v in obj]
    if isinstance(obj, dict):
        return {k: _asdict(v) for k, v in obj.items()}
    return obj
