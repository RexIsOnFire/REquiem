"""CAPE Sandbox backend — real detonation via an external CAPE instance.

ReQuiem does **not** detonate anything itself. This backend submits the sample
to a *separately operated* CAPE Sandbox (https://github.com/kevoreilly/CAPEv2)
over its REST API, waits for the analysis, downloads the report, and maps it
into :class:`DynamicBehavior` via the pure :mod:`cape_map` layer. CAPE is what
provides the isolated VM, API hooking, memory capture, and network control.

Configuration (all via environment, keys-optional like the intel providers):

    CAPE_URL        base URL of the CAPE web/API, e.g. https://cape.lan
    CAPE_TOKEN      optional API token (sent as ``Authorization: Token ...``)
    CAPE_TIMEOUT    max seconds to wait for analysis (default 600)
    CAPE_POLL       poll interval seconds (default 15)

If CAPE is unreachable, unconfigured, or times out, :meth:`detonate` raises
:class:`CapeError`; the pipeline catches this and falls back to the simulated
backend, so an investigation never hard-fails on sandbox trouble.

Only the stdlib is used, so ReQuiem gains no new hard dependency.
"""
from __future__ import annotations

import json
import os
import time
import urllib.error
import urllib.request
import uuid

from ..core.models import DynamicBehavior, FileIdentity
from . import cape_map
from .base import DynamicBackend


class CapeError(RuntimeError):
    """Raised when CAPE is unavailable or the analysis cannot be completed."""


def _multipart(fields: dict[str, str], filename: str, data: bytes) -> tuple[bytes, str]:
    """Build a multipart/form-data body for the sample submission."""
    boundary = f"----ReQuiemCAPE{uuid.uuid4().hex}"
    parts: list[bytes] = []
    for k, v in fields.items():
        parts.append(f"--{boundary}\r\n".encode())
        parts.append(f'Content-Disposition: form-data; name="{k}"\r\n\r\n{v}\r\n'.encode())
    parts.append(f"--{boundary}\r\n".encode())
    parts.append(
        f'Content-Disposition: form-data; name="file"; filename="{filename}"\r\n'
        f"Content-Type: application/octet-stream\r\n\r\n".encode())
    parts.append(data)
    parts.append(f"\r\n--{boundary}--\r\n".encode())
    return b"".join(parts), boundary


class CapeBackend(DynamicBackend):
    name = "cape"
    simulated = False

    def __init__(
        self,
        url: str | None = None,
        token: str | None = None,
        *,
        timeout: int | None = None,
        poll_interval: int | None = None,
        http_timeout: int = 30,
    ):
        self.url = (url or os.environ.get("CAPE_URL", "")).rstrip("/")
        self.token = token or os.environ.get("CAPE_TOKEN", "")
        self.timeout = timeout or int(os.environ.get("CAPE_TIMEOUT", "600"))
        self.poll_interval = poll_interval or int(os.environ.get("CAPE_POLL", "15"))
        self.http_timeout = http_timeout

    # --- low-level HTTP --------------------------------------------------
    def _headers(self) -> dict[str, str]:
        h = {"User-Agent": "ReQuiem/0.1"}
        if self.token:
            h["Authorization"] = f"Token {self.token}"
        return h

    def _get_json(self, path: str) -> dict:
        req = urllib.request.Request(self.url + path, headers=self._headers())
        try:
            with urllib.request.urlopen(req, timeout=self.http_timeout) as resp:
                return json.loads(resp.read().decode("utf-8", "replace"))
        except urllib.error.HTTPError as e:
            raise CapeError(f"CAPE GET {path} -> HTTP {e.code}") from e
        except (urllib.error.URLError, TimeoutError, ValueError) as e:
            raise CapeError(f"CAPE GET {path} failed: {e}") from e

    # --- API steps -------------------------------------------------------
    def _submit(self, data: bytes, filename: str) -> int:
        body, boundary = _multipart({"timeout": str(self.timeout)}, filename, data)
        headers = self._headers()
        headers["Content-Type"] = f"multipart/form-data; boundary={boundary}"
        req = urllib.request.Request(
            self.url + "/apiv2/tasks/create/file/", data=body,
            headers=headers, method="POST")
        try:
            with urllib.request.urlopen(req, timeout=self.http_timeout) as resp:
                payload = json.loads(resp.read().decode("utf-8", "replace"))
        except urllib.error.HTTPError as e:
            raise CapeError(f"CAPE submit -> HTTP {e.code}") from e
        except (urllib.error.URLError, TimeoutError, ValueError) as e:
            raise CapeError(f"CAPE submit failed: {e}") from e

        # CAPE returns {"data": {"task_ids": [N]}} or {"task_id": N}.
        data_field = payload.get("data") or payload
        task_ids = data_field.get("task_ids") or (
            [data_field["task_id"]] if "task_id" in data_field else [])
        if not task_ids:
            raise CapeError(f"CAPE submit returned no task id: {payload}")
        return int(task_ids[0])

    def _wait(self, task_id: int) -> None:
        deadline = time.monotonic() + self.timeout
        while time.monotonic() < deadline:
            status = self._get_json(f"/apiv2/tasks/status/{task_id}/")
            state = (status.get("data") or status.get("status") or "")
            if isinstance(state, dict):
                state = state.get("status", "")
            if state in ("reported", "completed"):
                return
            if state in ("failed_analysis", "failed_processing"):
                raise CapeError(f"CAPE analysis failed (task {task_id}): {state}")
            time.sleep(self.poll_interval)
        raise CapeError(f"CAPE analysis timed out after {self.timeout}s (task {task_id})")

    def _fetch_report(self, task_id: int) -> dict:
        payload = self._get_json(f"/apiv2/tasks/get/report/{task_id}/")
        # The report may be wrapped as {"data": {...}} or be the raw report.
        return payload.get("data") or payload

    # --- interface -------------------------------------------------------
    def detonate(self, *, data: bytes, identity: FileIdentity,
                 static_hints: dict | None = None) -> DynamicBehavior:
        if not self.url:
            raise CapeError("CAPE_URL not configured")
        task_id = self._submit(data, identity.filename or "sample.bin")
        self._wait(task_id)
        report = self._fetch_report(task_id)
        return cape_map.map_report(report, backend_name=self.name)
