"""Sandbox-agnostic normalization layer.

Every sandbox (CAPE, Cuckoo, Joe, Triage) emits its own report JSON, but the
*information* is the same: a process tree, network activity, dumped memory
regions, and signature detections. Rather than write a full mapper per sandbox,
each adapter parses its native report into a small common shape —
:class:`NormalizedReport` — and this module's :func:`to_behavior` turns that one
shape into :class:`DynamicBehavior`.

Adding a new sandbox is then just: fetch its report, fill a NormalizedReport.
The heavy lifting (region classification, heap synthesis, severity mapping,
ATT&CK) lives here, once.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from ..core.models import (
    Confidence,
    DynamicBehavior,
    Evidence,
    Finding,
    HeapSample,
    MemoryRegion,
    Severity,
)

_MB = 1024 * 1024


# --- the common intermediate shape --------------------------------------
@dataclass
class NormProcess:
    pid: int = 0
    name: str = "?"
    cmdline: str = ""
    children: list["NormProcess"] = field(default_factory=list)


@dataclass
class NormRegion:
    base: int = 0
    size: int = 0
    protection: str = "rw-"     # already normalized to r/w/x form
    path: str = ""              # backing file, if any
    injected: bool = False


@dataclass
class NormSignature:
    name: str = ""
    description: str = ""
    severity: str = "medium"    # info|low|medium|high|critical (adapter-normalized)
    attack: list[str] = field(default_factory=list)
    marks: list[str] = field(default_factory=list)


@dataclass
class NormalizedReport:
    processes: list[NormProcess] = field(default_factory=list)
    network: list[dict[str, Any]] = field(default_factory=list)   # {type,dest,note}
    files: list[dict[str, Any]] = field(default_factory=list)      # {op,path}
    registry: list[dict[str, Any]] = field(default_factory=list)   # {op,key}
    regions: list[NormRegion] = field(default_factory=list)
    signatures: list[NormSignature] = field(default_factory=list)


# --- shared helpers adapters can reuse ----------------------------------
_SEVERITY = {
    "info": Severity.INFO, "low": Severity.LOW, "medium": Severity.MEDIUM,
    "high": Severity.HIGH, "critical": Severity.CRITICAL,
}

# Windows page-protection -> r/w/x (shared by CAPE/Cuckoo which use these names).
PROTECT_MAP = {
    "PAGE_EXECUTE": "r-x", "PAGE_EXECUTE_READ": "r-x",
    "PAGE_EXECUTE_READWRITE": "rwx", "PAGE_EXECUTE_WRITECOPY": "rwx",
    "PAGE_READONLY": "r--", "PAGE_READWRITE": "rw-", "PAGE_WRITECOPY": "rw-",
    "PAGE_NOACCESS": "---",
}
_PROTECT_CONST = {0x10: "r-x", 0x20: "r-x", 0x40: "rwx", 0x80: "rwx",
                  0x02: "r--", 0x04: "rw-", 0x08: "rw-", 0x01: "---"}


def normalize_protection(value: Any) -> str:
    if isinstance(value, str):
        v = value.strip().upper()
        if v in PROTECT_MAP:
            return PROTECT_MAP[v]
        try:
            return _PROTECT_CONST.get(int(v, 0), "rw-")
        except (ValueError, TypeError):
            return "rw-"
    if isinstance(value, int):
        return _PROTECT_CONST.get(value, "rw-")
    return "rw-"


def as_int(value: Any, default: int = 0) -> int:
    try:
        return int(value, 0) if isinstance(value, str) else int(value)
    except (ValueError, TypeError):
        return default


def norm_severity(value: Any) -> str:
    """Map a numeric or string severity onto our five buckets."""
    if isinstance(value, str) and value.lower() in _SEVERITY:
        return value.lower()
    n = as_int(value, 2)
    return {0: "info", 1: "low", 2: "medium", 3: "high"}.get(n, "critical")


# --- the one mapper ------------------------------------------------------
def _map_processes(procs: list[NormProcess]) -> list[dict]:
    return [{
        "pid": p.pid, "name": p.name, "cmdline": p.cmdline,
        "children": _map_processes(p.children),
    } for p in procs]


def _classify_region(r: NormRegion) -> tuple[str, bool, str]:
    exec_ = "x" in r.protection
    backed = bool(r.path) and not r.injected
    if backed:
        return "image", False, r.path.rsplit("\\", 1)[-1]
    if exec_:
        return "shellcode", True, "unbacked executable memory (injected/unpacked)"
    if "w" in r.protection:
        return "private", False, "private commit"
    return "mapped", False, "mapped region"


def _map_regions(regions: list[NormRegion]) -> list[MemoryRegion]:
    out: list[MemoryRegion] = []
    for r in regions:
        if r.size <= 0:
            continue
        kind, suspicious, label = _classify_region(r)
        backed = bool(r.path) and not r.injected
        out.append(MemoryRegion(base=r.base, size=r.size, protection=r.protection,
                                kind=kind, backed=backed, label=label,
                                suspicious=suspicious))
    out.sort(key=lambda x: x.base)
    return out


def _heap_from_regions(regions: list[MemoryRegion]) -> list[HeapSample]:
    private = [r for r in regions if r.kind == "private" or (r.writable and not r.backed)]
    if not private:
        return []
    peak = sum(r.size for r in private)
    return [
        HeapSample(t_ms=0, committed=min(peak, 8 * _MB), note="start"),
        HeapSample(t_ms=1000, committed=peak, note="peak private commit (sandbox dump)"),
    ]


def _map_signatures(sigs: list[NormSignature], source: str) -> list[Finding]:
    findings: list[Finding] = []
    for sig in sigs:
        f = Finding(
            title=(sig.description or sig.name or f"{source} signature")[:120],
            description=sig.description or f"Detected by {source} signature engine.",
            confidence=Confidence.HIGH,
            severity=_SEVERITY.get(sig.severity, Severity.MEDIUM),
            attack_techniques=[t for t in sig.attack if t],
            tags=[source, "dynamic"],
        )
        for mark in sig.marks[:4]:
            f.evidence.append(Evidence(detail=str(mark)[:200], source=source))
        if not f.evidence:
            f.evidence.append(Evidence(detail=f"{source} flagged: {sig.name}", source=source))
        findings.append(f)
    return findings


def to_behavior(norm: NormalizedReport, *, backend_name: str) -> DynamicBehavior:
    """Turn a :class:`NormalizedReport` into :class:`DynamicBehavior`."""
    beh = DynamicBehavior(executed=True, backend=backend_name, simulated=False)
    beh.process_tree = _map_processes(norm.processes)
    beh.network = list(norm.network)
    beh.filesystem = list(norm.files)
    beh.registry = list(norm.registry)
    beh.memory_map = _map_regions(norm.regions)
    beh.heap_timeline = _heap_from_regions(beh.memory_map)
    beh.memory = _map_signatures(norm.signatures, backend_name)
    return beh
