"""Concrete intel providers (keys-optional).

- :class:`MalwareBazaarProvider` — abuse.ch MalwareBazaar. Free; an API key
  (``MALWAREBAZAAR_API_KEY``) is used if present. Returns family + tags.
- :class:`VirusTotalProvider` — VirusTotal v3. Requires ``VT_API_KEY``; without
  it, reports "no api key" and stays out of the way.
- :class:`OfflineProvider` — always-available default that returns "unknown"
  so the pipeline is fully functional with zero network/config.

All providers use only the stdlib ``urllib`` so ReQuiem has no hard HTTP dep.
Network calls are best-effort and short-timeout; failures never raise.
"""
from __future__ import annotations

import json
import os
import urllib.error
import urllib.parse
import urllib.request

from ..core.models import IntelResult
from .base import IntelProvider

_TIMEOUT = 8


def _http_post(url: str, data: dict, headers: dict) -> tuple[int, dict | None]:
    """POST form data; return (http_status, json | None). status 0 == network error."""
    body = urllib.parse.urlencode(data).encode()
    req = urllib.request.Request(url, data=body, headers=headers, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=_TIMEOUT) as resp:
            return resp.status, json.loads(resp.read().decode("utf-8", "replace"))
    except urllib.error.HTTPError as e:
        return e.code, None
    except (urllib.error.URLError, TimeoutError, ValueError):
        return 0, None


def _http_get(url: str, headers: dict) -> tuple[int, dict | None]:
    req = urllib.request.Request(url, headers=headers, method="GET")
    try:
        with urllib.request.urlopen(req, timeout=_TIMEOUT) as resp:
            return resp.status, json.loads(resp.read().decode("utf-8", "replace"))
    except urllib.error.HTTPError as e:
        return e.code, None
    except (urllib.error.URLError, TimeoutError, ValueError):
        return 0, None


class OfflineProvider(IntelProvider):
    name = "offline"

    def lookup(self, *, sha256, md5=None, sha1=None) -> IntelResult:
        return IntelResult(source=self.name, known=False,
                           detail="offline mode - no external lookup performed")


class MalwareBazaarProvider(IntelProvider):
    name = "malwarebazaar"
    ENDPOINT = "https://mb-api.abuse.ch/api/v1/"

    def __init__(self, api_key: str | None = None):
        self.api_key = api_key or os.environ.get("MALWAREBAZAAR_API_KEY", "")

    def lookup(self, *, sha256, md5=None, sha1=None) -> IntelResult:
        headers = {"User-Agent": "ReQuiem/0.1"}
        if self.api_key:
            headers["Auth-Key"] = self.api_key
        status, payload = _http_post(self.ENDPOINT,
                                     {"query": "get_info", "hash": sha256}, headers)
        if status in (401, 403) or (payload and payload.get("query_status") == "unauthorized"):
            hint = ("set MALWAREBAZAAR_API_KEY (free at auth.abuse.ch)"
                    if not self.api_key else "invalid MALWAREBAZAAR_API_KEY")
            return IntelResult(source=self.name, known=False,
                               detail=f"auth required — {hint}")
        if payload is None:
            return IntelResult(source=self.name, known=False,
                               detail=f"lookup failed (http {status or 'network'})")
        if payload.get("query_status") != "ok":
            return IntelResult(source=self.name, known=False,
                               detail=f"not found ({payload.get('query_status')})")
        item = (payload.get("data") or [{}])[0]
        return IntelResult(
            source=self.name,
            known=True,
            family=item.get("signature") or None,
            first_seen=item.get("first_seen"),
            tags=item.get("tags") or [],
            detail=item.get("file_type_mime") or "",
        )


class VirusTotalProvider(IntelProvider):
    name = "virustotal"
    ENDPOINT = "https://www.virustotal.com/api/v3/files/"

    def __init__(self, api_key: str | None = None):
        self.api_key = api_key or os.environ.get("VT_API_KEY", "")

    def lookup(self, *, sha256, md5=None, sha1=None) -> IntelResult:
        if not self.api_key:
            return IntelResult(source=self.name, known=False, detail="no VT_API_KEY set")
        status, payload = _http_get(self.ENDPOINT + sha256, {"x-apikey": self.api_key})
        if status == 404:
            return IntelResult(source=self.name, known=False, detail="not found on VT")
        if status != 200 or not payload:
            return IntelResult(source=self.name, known=False,
                               detail=f"lookup failed (http {status})")
        attrs = payload.get("data", {}).get("attributes", {})
        stats = attrs.get("last_analysis_stats", {})
        malicious = stats.get("malicious", 0)
        suggested = attrs.get("popular_threat_classification", {}).get(
            "suggested_threat_label")
        return IntelResult(
            source=self.name,
            known=True,
            family=suggested,
            first_seen=str(attrs.get("first_submission_date", "")) or None,
            prevalence=attrs.get("times_submitted"),
            tags=attrs.get("tags", []),
            detail=f"{malicious} engines flagged malicious",
        )


def default_providers(offline: bool = False) -> list[IntelProvider]:
    """Assemble the provider chain based on environment/config.

    In ``offline`` mode (default for CI/tests) only :class:`OfflineProvider`
    runs. Otherwise providers are included when they *can* work — VT only if a
    key exists — so the pipeline never blocks on missing credentials.
    """
    if offline:
        return [OfflineProvider()]
    providers: list[IntelProvider] = [MalwareBazaarProvider()]
    if os.environ.get("VT_API_KEY"):
        providers.append(VirusTotalProvider())
    return providers
