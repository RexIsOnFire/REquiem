"""Parse a CAPE Sandbox report into the sandbox-agnostic NormalizedReport.

The heavy lifting (region classification, heap synthesis, severity mapping,
findings) lives in :mod:`normalize`; this module's only job is to read CAPE's
particular JSON shape into a :class:`NormalizedReport`. It stays a pure function
so it's fully unit-tested offline against recorded fixtures.
"""
from __future__ import annotations

from ..core.models import DynamicBehavior
from . import normalize as N


def _procs(nodes: list[dict]) -> list[N.NormProcess]:
    out = []
    for n in nodes or []:
        out.append(N.NormProcess(
            pid=N.as_int(n.get("pid")),
            name=n.get("name") or n.get("process_name") or "?",
            cmdline=n.get("command_line") or n.get("commandline") or "",
            children=_procs(n.get("children") or []),
        ))
    return out


def _network(net: dict) -> list[dict]:
    rows: list[dict] = []
    for h in net.get("http") or net.get("http_ex") or []:
        rows.append({"type": "http", "dest": h.get("uri") or h.get("url") or h.get("host") or "",
                     "note": (h.get("method") or "").upper() or "request"})
    for d in net.get("dns") or []:
        rows.append({"type": "dns", "dest": d.get("request") or d.get("hostname") or "",
                     "note": "query"})
    for host in net.get("hosts") or []:
        ip = host.get("ip") if isinstance(host, dict) else host
        if ip:
            rows.append({"type": "tcp", "dest": str(ip), "note": "contacted host"})
    return rows


def _files_registry(procs: list[dict]) -> tuple[list[dict], list[dict]]:
    files, keys = [], []
    for p in procs or []:
        summary = p.get("summary") or {}
        for path in (summary.get("write_files") or summary.get("files") or [])[:15]:
            files.append({"op": "write", "path": path})
        for key in (summary.get("write_keys") or summary.get("keys") or [])[:15]:
            keys.append({"op": "set", "key": key})
    return files[:40], keys[:40]


def _regions(report: dict) -> list[N.NormRegion]:
    out: list[N.NormRegion] = []
    dumps = (report.get("procmemory") or report.get("procdump")
             or report.get("process_memory") or [])
    for d in dumps:
        for e in (d.get("regions") or [d]):
            size = N.as_int(e.get("size") or e.get("region_size"))
            if size <= 0:
                continue
            out.append(N.NormRegion(
                base=N.as_int(e.get("address") or e.get("addr") or e.get("base")),
                size=size,
                protection=N.normalize_protection(e.get("protect") or e.get("protection")),
                path=e.get("path") or e.get("file") or "",
                injected=bool(e.get("injected", False)),
            ))
    return out


def _signatures(sigs: list[dict]) -> list[N.NormSignature]:
    out: list[N.NormSignature] = []
    for sig in sigs or []:
        ttps = sig.get("ttp") or sig.get("attack") or {}
        if isinstance(ttps, dict):
            ids = list(ttps.keys())
        elif isinstance(ttps, list):
            ids = [t if isinstance(t, str) else t.get("id", "") for t in ttps]
        else:
            ids = []
        out.append(N.NormSignature(
            name=sig.get("name") or "",
            description=sig.get("description") or sig.get("name") or "",
            severity=N.norm_severity(sig.get("severity")),
            attack=[t for t in ids if t],
            marks=[str(m) for m in (sig.get("data") or sig.get("marks") or [])],
        ))
    return out


def to_normalized(report: dict) -> N.NormalizedReport:
    behavior = report.get("behavior") or {}
    network = report.get("network") or {}
    files, keys = _files_registry(behavior.get("processes") or [])
    return N.NormalizedReport(
        processes=_procs(behavior.get("processtree") or []),
        network=_network(network),
        files=files,
        registry=keys,
        regions=_regions(report),
        signatures=_signatures(report.get("signatures") or []),
    )


def map_report(report: dict, *, backend_name: str = "cape") -> DynamicBehavior:
    """Map a full CAPE report dict into :class:`DynamicBehavior`."""
    return N.to_behavior(to_normalized(report), backend_name=backend_name)
