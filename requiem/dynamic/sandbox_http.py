"""Shared HTTP plumbing for sandbox adapters (stdlib only).

CAPE, Cuckoo, Joe, and Triage all follow the same submit -> poll -> fetch flow
over REST. This module provides the multipart builder and JSON GET/POST helpers
they share, plus a common :class:`SandboxError`. No third-party HTTP dependency.
"""
from __future__ import annotations

import json
import urllib.error
import urllib.request
import uuid


class SandboxError(RuntimeError):
    """Raised when a sandbox is unavailable or the analysis cannot complete."""


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """Refuse to follow redirects — a compromised/MITM'd upstream must not be
    able to bounce our authenticated request to an internal/metadata address
    (SSRF). Raises so the caller sees a normal HTTP error."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


# A shared opener that never auto-follows 3xx redirects.
no_redirect_opener = urllib.request.build_opener(_NoRedirect)


def multipart(fields: dict[str, str], filename: str, data: bytes,
              *, file_field: str = "file") -> tuple[bytes, str]:
    boundary = f"----ReQuiemSbx{uuid.uuid4().hex}"
    parts: list[bytes] = []
    for k, v in fields.items():
        parts.append(f"--{boundary}\r\n".encode())
        parts.append(f'Content-Disposition: form-data; name="{k}"\r\n\r\n{v}\r\n'.encode())
    parts.append(f"--{boundary}\r\n".encode())
    parts.append(
        f'Content-Disposition: form-data; name="{file_field}"; filename="{filename}"\r\n'
        f"Content-Type: application/octet-stream\r\n\r\n".encode())
    parts.append(data)
    parts.append(f"\r\n--{boundary}--\r\n".encode())
    return b"".join(parts), boundary


def get_json(url: str, headers: dict[str, str], timeout: int) -> dict:
    req = urllib.request.Request(url, headers=headers)
    try:
        with no_redirect_opener.open(req, timeout=timeout) as resp:
            return json.loads(resp.read().decode("utf-8", "replace"))
    except urllib.error.HTTPError as e:
        raise SandboxError(f"GET {url} -> HTTP {e.code}") from e
    except (urllib.error.URLError, TimeoutError, ValueError) as e:
        raise SandboxError(f"GET {url} failed: {e}") from e


def post_json(url: str, headers: dict[str, str], body: bytes, timeout: int) -> dict:
    req = urllib.request.Request(url, data=body, headers=headers, method="POST")
    try:
        with no_redirect_opener.open(req, timeout=timeout) as resp:
            return json.loads(resp.read().decode("utf-8", "replace"))
    except urllib.error.HTTPError as e:
        raise SandboxError(f"POST {url} -> HTTP {e.code}") from e
    except (urllib.error.URLError, TimeoutError, ValueError) as e:
        raise SandboxError(f"POST {url} failed: {e}") from e
