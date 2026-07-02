"""Hybrid Analysis (Falcon Sandbox) behavior-by-hash provider.

Hosted cloud sandbox with a free research tier. We search by hash and, if a
prior detonation exists, pull its summary into the shared NormalizedReport.
Requires ``HYBRIDANALYSIS_API_KEY``. Returns ``found=False`` without it or when
the hash is unknown.
"""
from __future__ import annotations

import json
import os
import urllib.error
import urllib.parse
import urllib.request

from ..core.models import DynamicBehavior
from . import normalize as N
from .cloud import CloudBehaviorProvider, CloudLookup

_BASE = "https://www.hybrid-analysis.com/api/v2"
_TIMEOUT = 12


def _headers(key: str) -> dict[str, str]:
    return {"api-key": key, "User-Agent": "Falcon Sandbox", "accept": "application/json"}


def _post(url: str, key: str, form: dict) -> tuple[int, object]:
    body = urllib.parse.urlencode(form).encode()
    h = _headers(key)
    h["Content-Type"] = "application/x-www-form-urlencoded"
    req = urllib.request.Request(url, data=body, headers=h, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=_TIMEOUT) as resp:
            return resp.status, json.loads(resp.read().decode("utf-8", "replace"))
    except urllib.error.HTTPError as e:
        return e.code, None
    except (urllib.error.URLError, TimeoutError, ValueError):
        return 0, None


def _get(url: str, key: str) -> tuple[int, object]:
    req = urllib.request.Request(url, headers=_headers(key))
    try:
        with urllib.request.urlopen(req, timeout=_TIMEOUT) as resp:
            return resp.status, json.loads(resp.read().decode("utf-8", "replace"))
    except urllib.error.HTTPError as e:
        return e.code, None
    except (urllib.error.URLError, TimeoutError, ValueError):
        return 0, None


def to_normalized(summary: dict) -> N.NormalizedReport:
    # Processes (flat with parent uid); build the tree.
    flat = summary.get("processes") or []
    nodes: dict[str, N.NormProcess] = {}
    for p in flat:
        uid = str(p.get("uid") or p.get("pid"))
        nodes[uid] = N.NormProcess(
            pid=N.as_int(p.get("pid")),
            name=p.get("name") or "?",
            cmdline=p.get("command_line") or "")
    roots: list[N.NormProcess] = []
    for p in flat:
        uid = str(p.get("uid") or p.get("pid"))
        parent = str(p.get("parentuid") or "")
        if parent and parent in nodes and parent != uid:
            nodes[parent].children.append(nodes[uid])
        else:
            roots.append(nodes[uid])

    network: list[dict] = []
    for host in summary.get("hosts") or []:
        ip = host if isinstance(host, str) else host.get("address")
        if ip:
            network.append({"type": "tcp", "dest": str(ip), "note": "contacted host"})
    for d in summary.get("domains") or []:
        dom = d if isinstance(d, str) else d.get("domain")
        if dom:
            network.append({"type": "dns", "dest": str(dom), "note": "query"})

    sigs: list[N.NormSignature] = []
    for s in summary.get("signatures") or []:
        threat = N.as_int(s.get("threat_level"))
        sev = ("critical" if threat >= 3 else "high" if threat == 2
               else "medium" if threat == 1 else "low")
        attack = []
        for a in s.get("attck_ids") or s.get("mitre_attck") or []:
            attack.append(a if isinstance(a, str) else a.get("technique", ""))
        sigs.append(N.NormSignature(
            name=s.get("name") or "",
            description=s.get("description") or s.get("name") or "",
            severity=sev,
            attack=[a for a in attack if a],
            marks=[],
        ))

    return N.NormalizedReport(processes=roots, network=network, signatures=sigs)


class HybridAnalysisProvider(CloudBehaviorProvider):
    name = "hybridanalysis"

    def __init__(self, api_key: str | None = None):
        self.api_key = api_key or os.environ.get("HYBRIDANALYSIS_API_KEY", "")

    def lookup(self, *, sha256: str) -> CloudLookup:
        if not self.api_key:
            return CloudLookup(source=self.name, found=False,
                               note="no HYBRIDANALYSIS_API_KEY")
        status, results = _post(_BASE + "/search/hash", self.api_key, {"hash": sha256})
        if status in (401, 403):
            return CloudLookup(source=self.name, found=False, note="auth failed")
        if not isinstance(results, list) or not results:
            return CloudLookup(source=self.name, found=False, note="hash not found on HA")
        job_id = results[0].get("job_id") or results[0].get("sha256")
        if not job_id:
            return CloudLookup(source=self.name, found=False, note="no report id")
        st, summary = _get(_BASE + f"/report/{job_id}/summary", self.api_key)
        if st != 200 or not isinstance(summary, dict):
            return CloudLookup(source=self.name, found=False,
                               note=f"summary fetch failed (http {st})")
        beh = N.to_behavior(to_normalized(summary), backend_name=f"{self.name} (cloud)")
        if not (beh.process_tree or beh.network or beh.memory):
            return CloudLookup(source=self.name, found=False, note="empty report")
        return CloudLookup(source=self.name, found=True, behavior=beh)
