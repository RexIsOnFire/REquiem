"""Cuckoo Sandbox backend.

Cuckoo's REST API (submit -> poll -> fetch) and report JSON are close cousins of
CAPE's — Cuckoo is CAPE's upstream ancestor. We reuse the shared HTTP plumbing
and the CAPE report parser (which already reads Cuckoo-style keys defensively).

Config: ``CUCKOO_URL`` (base of the REST API, e.g. http://cuckoo.lan:8090),
``CUCKOO_TOKEN`` (optional). Falls back to simulated at the pipeline level if
unreachable.
"""
from __future__ import annotations

import os
import time

from ..core.models import DynamicBehavior, FileIdentity
from . import cape_map, normalize as N
from .base import DynamicBackend
from .sandbox_http import SandboxError, get_json, multipart, post_json


class CuckooBackend(DynamicBackend):
    name = "cuckoo"
    simulated = False

    def __init__(self, url: str | None = None, token: str | None = None, *,
                 timeout: int | None = None, poll_interval: int | None = None,
                 http_timeout: int = 30):
        self.url = (url or os.environ.get("CUCKOO_URL", "")).rstrip("/")
        self.token = token or os.environ.get("CUCKOO_TOKEN", "")
        self.timeout = timeout or int(os.environ.get("CUCKOO_TIMEOUT", "600"))
        self.poll_interval = poll_interval or int(os.environ.get("CUCKOO_POLL", "15"))
        self.http_timeout = http_timeout

    def _headers(self) -> dict[str, str]:
        h = {"User-Agent": "ReQuiem/0.1"}
        if self.token:
            h["Authorization"] = f"Bearer {self.token}"
        return h

    def _submit(self, data: bytes, filename: str) -> int:
        body, boundary = multipart({}, filename, data)
        headers = self._headers()
        headers["Content-Type"] = f"multipart/form-data; boundary={boundary}"
        payload = post_json(self.url + "/tasks/create/file", headers, body, self.http_timeout)
        task_id = payload.get("task_id") or (payload.get("task_ids") or [None])[0]
        if not task_id:
            raise SandboxError(f"Cuckoo submit returned no task id: {payload}")
        return int(task_id)

    def _wait(self, task_id: int) -> None:
        deadline = time.monotonic() + self.timeout
        while time.monotonic() < deadline:
            status = get_json(self.url + f"/tasks/view/{task_id}", self._headers(),
                              self.http_timeout)
            state = ((status.get("task") or {}).get("status")
                     or status.get("status") or "")
            if state in ("reported", "completed"):
                return
            if state in ("failed_analysis", "failed_processing"):
                raise SandboxError(f"Cuckoo analysis failed (task {task_id}): {state}")
            time.sleep(self.poll_interval)
        raise SandboxError(f"Cuckoo timed out after {self.timeout}s (task {task_id})")

    def _report(self, task_id: int) -> dict:
        payload = get_json(self.url + f"/tasks/report/{task_id}", self._headers(),
                           self.http_timeout)
        return payload.get("data") or payload

    def detonate(self, *, data: bytes, identity: FileIdentity,
                 static_hints: dict | None = None) -> DynamicBehavior:
        if not self.url:
            raise SandboxError("CUCKOO_URL not configured")
        task_id = self._submit(data, identity.filename or "sample.bin")
        self._wait(task_id)
        report = self._report(task_id)
        # Cuckoo's report shares CAPE's structure closely enough to reuse it.
        norm = cape_map.to_normalized(report)
        return N.to_behavior(norm, backend_name=self.name)
