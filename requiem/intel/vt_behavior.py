"""VirusTotal behavior-by-hash provider.

VT aggregates sandbox detonations across multiple engines and exposes a merged
``/files/{hash}/behaviour_summary``. We map that summary into ReQuiem's
:class:`DynamicBehavior` — process tree, network, MITRE techniques as findings
— so a public deployment gets real dynamic behavior from a hash with no local
sandbox. Requires ``VT_API_KEY``; returns ``found=False`` without it.
"""
from __future__ import annotations

import json
import os
import urllib.error
import urllib.request

from ..core.models import (
    Confidence,
    DynamicBehavior,
    Evidence,
    Finding,
    Severity,
)
from ..dynamic.cloud import CloudBehaviorProvider, CloudLookup

_ENDPOINT = "https://www.virustotal.com/api/v3/files/{}/behaviour_summary"
_TIMEOUT = 12


def _get(url: str, key: str) -> tuple[int, dict | None]:
    req = urllib.request.Request(url, headers={"x-apikey": key})
    try:
        with urllib.request.urlopen(req, timeout=_TIMEOUT) as resp:
            return resp.status, json.loads(resp.read().decode("utf-8", "replace"))
    except urllib.error.HTTPError as e:
        return e.code, None
    except (urllib.error.URLError, TimeoutError, ValueError):
        return 0, None


def _process_tree(summary: dict) -> list[dict]:
    """VT gives processes_tree as nested {name, process_id, children}."""
    def conv(nodes):
        out = []
        for n in nodes or []:
            out.append({
                "pid": _as_int(n.get("process_id")),
                "name": n.get("name") or "?",
                "cmdline": n.get("name") or "",
                "children": conv(n.get("children")),
            })
        return out
    return conv(summary.get("processes_tree"))


def _network(summary: dict) -> list[dict]:
    rows: list[dict] = []
    for h in summary.get("http_conversations") or []:
        rows.append({"type": "http", "dest": h.get("url") or h.get("host") or "",
                     "note": h.get("request_method", "request")})
    for d in summary.get("dns_lookups") or []:
        host = d.get("hostname") or ""
        if host:
            rows.append({"type": "dns", "dest": host, "note": "query"})
    for ip in summary.get("ip_traffic") or []:
        dest = ip.get("destination_ip") or ""
        if dest:
            rows.append({"type": "tcp", "dest": f"{dest}:{ip.get('destination_port', '')}",
                         "note": ip.get("transport_layer_protocol", "connection")})
    return rows


def _mitre_findings(summary: dict) -> list[Finding]:
    findings: list[Finding] = []
    for t in summary.get("mitre_attack_techniques") or []:
        tid = t.get("id") or ""
        desc = t.get("signature_description") or t.get("description") or tid
        sev_raw = (t.get("severity") or "").upper()
        sev = {"HIGH": Severity.HIGH, "MEDIUM": Severity.MEDIUM,
               "LOW": Severity.LOW, "INFO": Severity.INFO,
               "CRITICAL": Severity.CRITICAL}.get(sev_raw, Severity.MEDIUM)
        f = Finding(title=(desc or tid)[:120], description=desc or f"MITRE {tid}",
                    confidence=Confidence.HIGH, severity=sev,
                    attack_techniques=[tid] if tid else [], tags=["virustotal", "dynamic"])
        f.evidence.append(Evidence(detail=f"VirusTotal behavior: {tid}", source="virustotal"))
        findings.append(f)
    # Signature-only detections (no technique id) still carry value.
    for s in (summary.get("signature_matches") or [])[:20]:
        name = s.get("name") or s.get("description") or "signature"
        f = Finding(title=str(name)[:120], description=str(s.get("description") or name),
                    confidence=Confidence.MEDIUM, severity=Severity.MEDIUM,
                    tags=["virustotal", "dynamic"])
        f.evidence.append(Evidence(detail=f"VT signature: {name}", source="virustotal"))
        findings.append(f)
    return findings


def _as_int(v, default=0):
    try:
        return int(v)
    except (ValueError, TypeError):
        return default


class VTBehaviorProvider(CloudBehaviorProvider):
    name = "virustotal"

    def __init__(self, api_key: str | None = None):
        self.api_key = api_key or os.environ.get("VT_API_KEY", "")

    def lookup(self, *, sha256: str) -> CloudLookup:
        if not self.api_key:
            return CloudLookup(source=self.name, found=False, note="no VT_API_KEY")
        status, payload = _get(_ENDPOINT.format(sha256), self.api_key)
        if status == 404 or not payload:
            return CloudLookup(source=self.name, found=False,
                               note="no behavior report on VT" if status == 404
                               else f"lookup failed (http {status})")
        summary = payload.get("data") or {}
        beh = DynamicBehavior(executed=True, backend="virustotal (cloud)", simulated=False)
        beh.process_tree = _process_tree(summary)
        beh.network = _network(summary)
        beh.memory = _mitre_findings(summary)
        # VT summary carries no raw memory regions; leave memory_map/heap empty.
        if not (beh.process_tree or beh.network or beh.memory):
            return CloudLookup(source=self.name, found=False,
                               note="behavior report was empty")
        return CloudLookup(source=self.name, found=True, behavior=beh)
