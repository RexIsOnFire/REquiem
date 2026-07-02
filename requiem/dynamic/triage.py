"""Triage (Hatching tria.ge) backend.

Triage's API (``/api/v0/*``, Bearer token) submits a sample, waits for the
overview, then fetches the per-task ``report_triage.json``. Its report has a
clean modern shape that maps neatly onto :class:`NormalizedReport`.

Config: ``TRIAGE_URL`` (default https://tria.ge), ``TRIAGE_TOKEN``. Falls back
to simulated if unreachable/unconfigured.
"""
from __future__ import annotations

import json
import os
import time
import urllib.request

from ..core.models import DynamicBehavior, FileIdentity
from . import normalize as N
from .base import DynamicBackend
from .cloud import CloudBehaviorProvider, CloudLookup
from .sandbox_http import SandboxError, get_json, multipart


def to_normalized(report: dict) -> N.NormalizedReport:
    # Processes: Triage lists them flat with ppid.
    flat = report.get("processes") or []
    nodes: dict[int, N.NormProcess] = {}
    for p in flat:
        pid = N.as_int(p.get("pid"))
        nodes[pid] = N.NormProcess(
            pid=pid, name=p.get("image") or p.get("name") or "?",
            cmdline=p.get("cmd") or "")
    roots: list[N.NormProcess] = []
    for p in flat:
        pid = N.as_int(p.get("pid"))
        ppid = N.as_int(p.get("ppid"))
        if ppid in nodes and ppid != pid:
            nodes[ppid].children.append(nodes[pid])
        else:
            roots.append(nodes[pid])

    # Network.
    network: list[dict] = []
    net = report.get("network") or {}
    for r in net.get("requests") or []:
        if r.get("http_request"):
            hr = r["http_request"]
            network.append({"type": "http", "dest": hr.get("url") or r.get("dst") or "",
                            "note": hr.get("method", "request")})
        elif r.get("dns_request"):
            for q in r["dns_request"].get("domains", []):
                network.append({"type": "dns", "dest": q, "note": "query"})
    for f in net.get("flows") or []:
        if f.get("dst"):
            network.append({"type": "tcp", "dest": str(f["dst"]), "note": "flow"})

    # Memory dumps.
    regions: list[N.NormRegion] = []
    for d in report.get("dumped") or report.get("memory") or []:
        size = N.as_int(d.get("length") or d.get("size"))
        if size <= 0:
            continue
        regions.append(N.NormRegion(
            base=N.as_int(d.get("address") or d.get("at")),
            size=size,
            protection=N.normalize_protection(d.get("protect") or d.get("protection") or "rw-"),
            path=d.get("name") or "",
            injected=bool(d.get("injected")),
        ))

    # Signatures — Triage uses score 1-10 and a ttp[] of ATT&CK ids.
    sigs: list[N.NormSignature] = []
    for s in report.get("signatures") or []:
        score = N.as_int(s.get("score"))
        sev = ("critical" if score >= 8 else "high" if score >= 5
               else "medium" if score >= 2 else "low")
        sigs.append(N.NormSignature(
            name=s.get("name") or "",
            description=s.get("desc") or s.get("name") or "",
            severity=sev,
            attack=[str(t) for t in (s.get("ttp") or [])],
            marks=[str(m.get("data", m)) for m in (s.get("indicators") or [])][:4],
        ))

    return N.NormalizedReport(processes=roots, network=network,
                              regions=regions, signatures=sigs)


class TriageBackend(DynamicBackend):
    name = "triage"
    simulated = False

    def __init__(self, url: str | None = None, token: str | None = None, *,
                 timeout: int | None = None, poll_interval: int | None = None,
                 http_timeout: int = 30):
        self.url = (url or os.environ.get("TRIAGE_URL", "https://tria.ge")).rstrip("/")
        self.token = token or os.environ.get("TRIAGE_TOKEN", "")
        self.timeout = timeout or int(os.environ.get("TRIAGE_TIMEOUT", "600"))
        self.poll_interval = poll_interval or int(os.environ.get("TRIAGE_POLL", "20"))
        self.http_timeout = http_timeout

    def _headers(self) -> dict[str, str]:
        return {"User-Agent": "ReQuiem/0.1", "Authorization": f"Bearer {self.token}"}

    def _submit(self, data: bytes, filename: str) -> str:
        body, boundary = multipart({"_json": json.dumps({"kind": "file"})},
                                   filename, data)
        headers = self._headers()
        headers["Content-Type"] = f"multipart/form-data; boundary={boundary}"
        # urllib POST with auth header (post_json doesn't set auth for us here).
        req = urllib.request.Request(self.url + "/api/v0/samples", data=body,
                                     headers=headers, method="POST")
        try:
            with urllib.request.urlopen(req, timeout=self.http_timeout) as resp:
                payload = json.loads(resp.read().decode("utf-8", "replace"))
        except Exception as e:  # noqa: BLE001 - normalized below
            raise SandboxError(f"Triage submit failed: {e}") from e
        sample_id = payload.get("id")
        if not sample_id:
            raise SandboxError(f"Triage submit returned no id: {payload}")
        return str(sample_id)

    def _wait(self, sample_id: str) -> list[str]:
        deadline = time.monotonic() + self.timeout
        while time.monotonic() < deadline:
            overview = get_json(self.url + f"/api/v0/samples/{sample_id}/overview.json",
                                self._headers(), self.http_timeout)
            status = overview.get("status", "")
            if status in ("reported", "completed"):
                return [t.get("id", "") for t in overview.get("tasks", [])
                        if t.get("kind") == "behavioral" or "behavioral" in t.get("id", "")]
            if status == "failed":
                raise SandboxError(f"Triage analysis failed ({sample_id})")
            time.sleep(self.poll_interval)
        raise SandboxError(f"Triage timed out after {self.timeout}s")

    def _report(self, sample_id: str, task_id: str) -> dict:
        return get_json(
            self.url + f"/api/v0/samples/{sample_id}/{task_id}/report_triage.json",
            self._headers(), self.http_timeout)

    def detonate(self, *, data: bytes, identity: FileIdentity,
                 static_hints: dict | None = None) -> DynamicBehavior:
        if not self.token:
            raise SandboxError("TRIAGE_TOKEN not configured")
        sample_id = self._submit(data, identity.filename or "sample.bin")
        tasks = self._wait(sample_id)
        if not tasks:
            raise SandboxError("Triage produced no behavioral task")
        report = self._report(sample_id, tasks[0])
        return N.to_behavior(to_normalized(report), backend_name=self.name)

    # --- CloudBehaviorProvider: look up an EXISTING report by hash ---------
    def _search_sample(self, sha256: str) -> str | None:
        """Return the newest sample id tria.ge already has for this hash."""
        res = get_json(self.url + f"/api/v0/search?query=sha256:{sha256}",
                       self._headers(), self.http_timeout)
        data = res.get("data") or []
        return data[0].get("id") if data else None

    def _behavioral_task(self, sample_id: str) -> str | None:
        overview = get_json(self.url + f"/api/v0/samples/{sample_id}/overview.json",
                            self._headers(), self.http_timeout)
        for t in overview.get("tasks", []):
            if t.get("kind") == "behavioral" or "behavioral" in t.get("id", ""):
                return t.get("id")
        return None

    def lookup(self, *, sha256: str) -> CloudLookup:
        """No upload — pull an existing tria.ge behavioral report by hash."""
        if not self.token:
            return CloudLookup(source=self.name, found=False,
                               note="TRIAGE_TOKEN not configured")
        try:
            sample_id = self._search_sample(sha256)
            if not sample_id:
                return CloudLookup(source=self.name, found=False,
                                   note="hash not found on tria.ge")
            task = self._behavioral_task(sample_id)
            if not task:
                return CloudLookup(source=self.name, found=False,
                                   note="no behavioral task for this sample")
            report = self._report(sample_id, task)
            beh = N.to_behavior(to_normalized(report), backend_name=f"{self.name} (cloud)")
            return CloudLookup(source=self.name, found=True, behavior=beh)
        except SandboxError as e:
            return CloudLookup(source=self.name, found=False, note=str(e))


# Register Triage as a cloud-behavior provider without multiple inheritance
# noise: the methods above satisfy the CloudBehaviorProvider protocol.
CloudBehaviorProvider.register(TriageBackend)
