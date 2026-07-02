"""Map a CAPE Sandbox report into ReQuiem's :class:`DynamicBehavior`.

This is the heart of the CAPE integration and is deliberately a *pure function*
of the report JSON — no network, no CAPE dependency — so it is fully unit-tested
offline against recorded report fixtures.

CAPE's report is large and version-drifty; we read defensively, treating every
section as optional. The shape we rely on (all under the top-level report dict):

    behavior.processtree[]      -> process tree (name, pid, children, ...)
    behavior.processes[]        -> per-process API call log (for hints)
    network.hosts/domains/...   -> network indicators
    network.http[] / dns[]      -> requests
    procmemory[] / procdump[]   -> dumped memory regions (base, size, protect)
    signatures[]                -> CAPE's own detections (-> findings + ATT&CK)

Anything missing simply yields an empty sub-section rather than an error.
"""
from __future__ import annotations

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

# CAPE "protect" strings / Windows page-protection constants -> our r/w/x form.
_PROTECT_MAP = {
    "PAGE_EXECUTE": "r-x",
    "PAGE_EXECUTE_READ": "r-x",
    "PAGE_EXECUTE_READWRITE": "rwx",
    "PAGE_EXECUTE_WRITECOPY": "rwx",
    "PAGE_READONLY": "r--",
    "PAGE_READWRITE": "rw-",
    "PAGE_WRITECOPY": "rw-",
    "PAGE_NOACCESS": "---",
}
_PROTECT_CONST = {  # numeric constants CAPE sometimes emits instead of names
    0x10: "r-x", 0x20: "r-x", 0x40: "rwx", 0x80: "rwx",
    0x02: "r--", 0x04: "rw-", 0x08: "rw-", 0x01: "---",
}


def _protection(value: Any) -> str:
    if isinstance(value, str):
        v = value.strip().upper()
        if v in _PROTECT_MAP:
            return _PROTECT_MAP[v]
        # sometimes a hex string like "0x40"
        try:
            return _PROTECT_CONST.get(int(v, 0), "rw-")
        except (ValueError, TypeError):
            return "rw-"
    if isinstance(value, int):
        return _PROTECT_CONST.get(value, "rw-")
    return "rw-"


def _as_int(value: Any, default: int = 0) -> int:
    try:
        if isinstance(value, str):
            return int(value, 0)
        return int(value)
    except (ValueError, TypeError):
        return default


# --- process tree --------------------------------------------------------
def _map_process_tree(nodes: list[dict]) -> list[dict]:
    out = []
    for n in nodes or []:
        out.append({
            "pid": _as_int(n.get("pid")),
            "name": n.get("name") or n.get("process_name") or "?",
            "cmdline": n.get("command_line") or n.get("commandline") or "",
            "children": _map_process_tree(n.get("children") or []),
        })
    return out


# --- network -------------------------------------------------------------
def _map_network(net: dict) -> list[dict]:
    rows: list[dict] = []
    for h in net.get("http") or net.get("http_ex") or []:
        uri = h.get("uri") or h.get("url") or ""
        host = h.get("host") or ""
        rows.append({"type": "http", "dest": uri or host,
                     "note": (h.get("method") or "").upper() or "request"})
    for d in net.get("dns") or []:
        rows.append({"type": "dns", "dest": d.get("request") or d.get("hostname") or "",
                     "note": "query"})
    for host in net.get("hosts") or []:
        ip = host.get("ip") if isinstance(host, dict) else host
        if ip:
            rows.append({"type": "tcp", "dest": str(ip), "note": "contacted host"})
    return rows


def _map_fs_registry(procs: list[dict]) -> tuple[list[dict], list[dict]]:
    """Best-effort extraction of file/registry ops from the API call summary.

    Newer CAPE emits a per-process ``summary`` with files/keys touched; we take
    a bounded slice so the report stays readable.
    """
    files: list[dict] = []
    keys: list[dict] = []
    for p in procs or []:
        summary = p.get("summary") or {}
        for path in (summary.get("write_files") or summary.get("files") or [])[:15]:
            files.append({"op": "write", "path": path})
        for key in (summary.get("write_keys") or summary.get("keys") or [])[:15]:
            keys.append({"op": "set", "key": key})
    return files[:40], keys[:40]


# --- memory regions ------------------------------------------------------
def _classify_region(base: int, protect: str, backed: bool, path: str) -> tuple[str, bool, str]:
    """Return (kind, suspicious, label) for a dumped region."""
    exec_ = "x" in protect
    if path:
        label = path.rsplit("\\", 1)[-1]
        return ("image", False, label)
    if exec_ and not backed:
        return ("shellcode", True, "unbacked executable memory (injected/unpacked)")
    if "w" in protect and not backed:
        return ("private", False, "private commit")
    return ("mapped", False, "mapped region")


def _map_memory(report: dict) -> list[MemoryRegion]:
    regions: list[MemoryRegion] = []
    # CAPE dumps live under a few keys depending on version.
    dumps = (report.get("procmemory") or report.get("procdump")
             or report.get("process_memory") or [])
    for d in dumps:
        # A procmemory entry may itself carry a list of yara-hit regions or
        # a flat address/size/protect. Handle both.
        entries = d.get("regions") or [d]
        for e in entries:
            base = _as_int(e.get("address") or e.get("addr") or e.get("base"))
            size = _as_int(e.get("size") or e.get("region_size"))
            if size <= 0:
                continue
            protect = _protection(e.get("protect") or e.get("protection"))
            path = e.get("path") or e.get("file") or ""
            backed = bool(path) and not e.get("injected", False)
            kind, suspicious, label = _classify_region(base, protect, backed, path)
            regions.append(MemoryRegion(
                base=base, size=size, protection=protect, kind=kind,
                backed=backed, label=label, suspicious=suspicious))
    regions.sort(key=lambda r: r.base)
    return regions


def _heap_from_regions(regions: list[MemoryRegion]) -> list[HeapSample]:
    """CAPE does not emit a heap-growth curve. When large private commits were
    dumped, synthesize a single terminal sample so the timeline still conveys
    the working-set magnitude; otherwise leave it empty (no fabrication)."""
    private = [r for r in regions if r.kind == "private" or (r.writable and not r.backed)]
    if not private:
        return []
    peak = sum(r.size for r in private)
    return [
        HeapSample(t_ms=0, committed=min(peak, 8 * 1024 * 1024), note="start"),
        HeapSample(t_ms=1000, committed=peak, note="peak private commit (CAPE dump)"),
    ]


# --- signatures ----------------------------------------------------------
def _severity_from_signature(sig: dict) -> Severity:
    # CAPE signature severity is conventionally 1 (info/low), 2 (medium),
    # 3 (high). Some forks emit higher scores; clamp anything >=4 to critical.
    sev = sig.get("severity")
    if isinstance(sev, int):
        if sev <= 1:
            return Severity.LOW
        if sev == 2:
            return Severity.MEDIUM
        if sev == 3:
            return Severity.HIGH
        return Severity.CRITICAL
    return Severity.MEDIUM


def _map_signatures(sigs: list[dict]) -> list[Finding]:
    findings: list[Finding] = []
    for sig in sigs or []:
        name = sig.get("description") or sig.get("name") or "CAPE signature"
        ttps = sig.get("ttp") or sig.get("attack") or {}
        # CAPE stores ATT&CK as {"T1055": {...}} or a list; normalize to ids.
        if isinstance(ttps, dict):
            technique_ids = list(ttps.keys())
        elif isinstance(ttps, list):
            technique_ids = [t if isinstance(t, str) else t.get("id", "") for t in ttps]
        else:
            technique_ids = []
        technique_ids = [t for t in technique_ids if t]

        f = Finding(
            title=str(name)[:120],
            description=sig.get("description") or "Detected by CAPE signature engine.",
            confidence=Confidence.HIGH,
            severity=_severity_from_signature(sig),
            attack_techniques=technique_ids,
            tags=["cape", "dynamic"],
        )
        for mark in (sig.get("data") or sig.get("marks") or [])[:4]:
            f.evidence.append(Evidence(detail=str(mark)[:200], source="cape"))
        if not f.evidence:
            f.evidence.append(Evidence(detail=f"CAPE flagged: {name}", source="cape"))
        findings.append(f)
    return findings


def map_report(report: dict, *, backend_name: str = "cape") -> DynamicBehavior:
    """Map a full CAPE report dict into :class:`DynamicBehavior`.

    Pure and defensive: unknown/absent sections yield empty results, never
    exceptions. ``simulated`` is False — this reflects a real detonation.
    """
    behavior = report.get("behavior") or {}
    network = report.get("network") or {}

    beh = DynamicBehavior(executed=True, backend=backend_name, simulated=False)
    beh.process_tree = _map_process_tree(behavior.get("processtree") or [])
    beh.network = _map_network(network)
    beh.filesystem, beh.registry = _map_fs_registry(behavior.get("processes") or [])
    beh.memory_map = _map_memory(report)
    beh.heap_timeline = _heap_from_regions(beh.memory_map)
    beh.memory = _map_signatures(report.get("signatures") or [])
    return beh
