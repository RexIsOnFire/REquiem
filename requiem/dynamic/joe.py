"""Joe Sandbox backend.

Joe Sandbox has its own web-API (``/api/v2/*``) and report structure that
differs from CAPE/Cuckoo, so it gets its own parser into the shared
:class:`NormalizedReport`. The heavy mapping still lives in :mod:`normalize`.

Config: ``JOE_URL`` (base, e.g. https://jbxcloud.joesecurity.org),
``JOE_APIKEY``. Falls back to simulated if unreachable.
"""
from __future__ import annotations

import os
import time

from ..core.models import DynamicBehavior, FileIdentity
from . import normalize as N
from .base import DynamicBackend
from .sandbox_http import SandboxError, get_json, multipart, post_json


# --- Joe report -> NormalizedReport --------------------------------------
def to_normalized(report: dict) -> N.NormalizedReport:
    analysis = report.get("analysis") or report
    behavior = analysis.get("behavior") or {}
    system = behavior.get("system") or {}

    # Joe lists processes flat with parentpid; rebuild the tree.
    flat = system.get("processes", {}).get("process") or system.get("processes") or []
    if isinstance(flat, dict):
        flat = [flat]
    nodes: dict[int, N.NormProcess] = {}
    for p in flat:
        pid = N.as_int(p.get("pid"))
        nodes[pid] = N.NormProcess(
            pid=pid, name=p.get("name") or p.get("filename") or "?",
            cmdline=p.get("cmdline") or p.get("path") or "")
    roots: list[N.NormProcess] = []
    for p in flat:
        pid = N.as_int(p.get("pid"))
        parent = N.as_int(p.get("parentpid"))
        if parent in nodes and parent != pid:
            nodes[parent].children.append(nodes[pid])
        else:
            roots.append(nodes[pid])

    # Network.
    network: list[dict] = []
    net = analysis.get("network") or {}
    for pkt in (net.get("http") or {}).get("packet", []) if isinstance(net.get("http"), dict) else []:
        network.append({"type": "http", "dest": pkt.get("uri") or pkt.get("host") or "",
                        "note": pkt.get("method", "request")})
    for d in (net.get("dns") or {}).get("packet", []) if isinstance(net.get("dns"), dict) else []:
        network.append({"type": "dns", "dest": d.get("name") or "", "note": "query"})
    for c in (net.get("tcp") or {}).get("packet", []) if isinstance(net.get("tcp"), dict) else []:
        if c.get("dst"):
            network.append({"type": "tcp", "dest": str(c["dst"]), "note": "connection"})

    # Memory dumps (Joe: memorydumps / unpackpe entries).
    regions: list[N.NormRegion] = []
    for m in (behavior.get("memorydumps") or {}).get("dump", []) \
            if isinstance(behavior.get("memorydumps"), dict) else []:
        size = N.as_int(m.get("size"))
        if size <= 0:
            continue
        regions.append(N.NormRegion(
            base=N.as_int(m.get("address") or m.get("base")),
            size=size,
            protection=N.normalize_protection(m.get("protect") or m.get("protection")),
            path=m.get("path") or "",
            injected=bool(m.get("injected") or m.get("unpacked")),
        ))

    # Signatures (Joe: signatures / signatureinfos with impact/severity 0-10).
    sigs: list[N.NormSignature] = []
    sig_container = analysis.get("signatures") or analysis.get("signatureinfos") or {}
    sig_list = sig_container.get("signature") if isinstance(sig_container, dict) else sig_container
    for s in sig_list or []:
        impact = N.as_int(s.get("impact") or s.get("severity"))
        sev = ("critical" if impact >= 8 else "high" if impact >= 5
               else "medium" if impact >= 2 else "low")
        attack = s.get("mitreattack") or s.get("attack") or []
        if isinstance(attack, dict):
            attack = list(attack.keys())
        sigs.append(N.NormSignature(
            name=s.get("name") or "",
            description=s.get("description") or s.get("name") or "",
            severity=sev,
            attack=[str(a) for a in (attack or [])],
            marks=[str(x) for x in (s.get("data") or [])],
        ))

    return N.NormalizedReport(
        processes=roots, network=network, regions=regions, signatures=sigs)


class JoeBackend(DynamicBackend):
    name = "joe"
    simulated = False

    def __init__(self, url: str | None = None, apikey: str | None = None, *,
                 timeout: int | None = None, poll_interval: int | None = None,
                 http_timeout: int = 30):
        self.url = (url or os.environ.get("JOE_URL", "")).rstrip("/")
        self.apikey = apikey or os.environ.get("JOE_APIKEY", "")
        self.timeout = timeout or int(os.environ.get("JOE_TIMEOUT", "600"))
        self.poll_interval = poll_interval or int(os.environ.get("JOE_POLL", "20"))
        self.http_timeout = http_timeout

    def _submit(self, data: bytes, filename: str) -> str:
        body, boundary = multipart({"apikey": self.apikey, "accept-tac": "1"},
                                   filename, data, file_field="sample")
        headers = {"User-Agent": "ReQuiem/0.1",
                   "Content-Type": f"multipart/form-data; boundary={boundary}"}
        payload = post_json(self.url + "/api/v2/submission/new", headers, body,
                            self.http_timeout)
        webid = (payload.get("data") or {}).get("submission_id") or payload.get("submission_id")
        if not webid:
            raise SandboxError(f"Joe submit returned no submission id: {payload}")
        return str(webid)

    def _wait(self, submission_id: str) -> str:
        deadline = time.monotonic() + self.timeout
        body, boundary = multipart({"apikey": self.apikey, "submission_id": submission_id},
                                   "x", b"")
        while time.monotonic() < deadline:
            payload = post_json(self.url + "/api/v2/submission/info",
                                {"Content-Type": f"multipart/form-data; boundary={boundary}"},
                                body, self.http_timeout)
            data = payload.get("data") or {}
            status = data.get("status", "")
            if status == "finished":
                analyses = data.get("analyses") or [{}]
                return str(analyses[0].get("webid", ""))
            time.sleep(self.poll_interval)
        raise SandboxError(f"Joe timed out after {self.timeout}s")

    def _report(self, webid: str) -> dict:
        return get_json(self.url + f"/api/v2/analysis/download?webid={webid}&type=irjsonfixed"
                        f"&apikey={self.apikey}", {"User-Agent": "ReQuiem/0.1"},
                        self.http_timeout)

    def detonate(self, *, data: bytes, identity: FileIdentity,
                 static_hints: dict | None = None) -> DynamicBehavior:
        if not self.url:
            raise SandboxError("JOE_URL not configured")
        submission_id = self._submit(data, identity.filename or "sample.bin")
        webid = self._wait(submission_id)
        report = self._report(webid)
        return N.to_behavior(to_normalized(report), backend_name=self.name)
