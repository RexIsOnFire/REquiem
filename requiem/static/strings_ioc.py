"""String extraction and IOC harvesting.

Extracts printable ASCII and UTF-16LE strings, then mines them for indicators
of compromise (IPs, domains, URLs, registry keys, mutexes, crypto addresses)
and for behaviorally-interesting strings that feed the ATT&CK inference stage.
"""
from __future__ import annotations

import ipaddress
import re

from ..core.models import IOCSet

_MIN_LEN = 5

_ASCII_RE = re.compile(rb"[\x20-\x7e]{%d,}" % _MIN_LEN)
_UTF16_RE = re.compile((rb"(?:[\x20-\x7e]\x00){%d,}" % _MIN_LEN))

_IPV4_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_URL_RE = re.compile(r"\b(?:https?|ftp)://[^\s\"'<>]{4,}", re.I)
_DOMAIN_RE = re.compile(
    r"\b(?:[a-z0-9](?:[a-z0-9\-]{0,61}[a-z0-9])?\.)+"
    r"(?:com|net|org|io|ru|cn|info|biz|xyz|top|onion|co|us|uk|de|nl)\b", re.I)
_EMAIL_RE = re.compile(r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b")
_REG_RE = re.compile(
    r"(?:HKLM|HKCU|HKEY_[A-Z_]+|SOFTWARE\\|SYSTEM\\CurrentControlSet)[\\A-Za-z0-9_\-.]{3,}", re.I)
_BTC_RE = re.compile(r"\b(?:bc1[a-z0-9]{20,}|[13][a-km-zA-HJ-NP-Z1-9]{25,34})\b")
_PATH_RE = re.compile(r"[A-Za-z]:\\(?:[^\\\/:*?\"<>|\r\n]+\\)*[^\\\/:*?\"<>|\r\n]*")

# Substrings that hint at a mutex/named-object creation.
_MUTEX_HINTS = re.compile(r"(?:Global\\|Local\\|Session\\)[A-Za-z0-9_\-{}]{4,}")


def extract_strings(data: bytes, limit: int = 100_000) -> list[str]:
    out: list[str] = []
    for m in _ASCII_RE.finditer(data):
        out.append(m.group().decode("latin-1", "replace"))
        if len(out) >= limit:
            break
    for m in _UTF16_RE.finditer(data):
        out.append(m.group().decode("utf-16-le", "replace"))
        if len(out) >= limit:
            break
    return out


def _valid_ipv4(s: str) -> bool:
    try:
        ip = ipaddress.ip_address(s)
    except ValueError:
        return False
    # Drop version-number noise like 1.2.3.4 that isn't routable/interesting.
    return not (ip.is_loopback or ip.is_unspecified or ip.is_multicast)


def harvest_iocs(strings: list[str]) -> IOCSet:
    iocs = IOCSet()
    seen: dict[str, set[str]] = {}

    def add(bucket: list[str], key: str, value: str) -> None:
        s = seen.setdefault(key, set())
        if value not in s:
            s.add(value)
            bucket.append(value)

    blob = "\n".join(strings)

    for m in _URL_RE.finditer(blob):
        add(iocs.urls, "url", m.group().rstrip(".,);"))
    for m in _IPV4_RE.finditer(blob):
        if _valid_ipv4(m.group()):
            add(iocs.ipv4, "ip", m.group())
    for m in _DOMAIN_RE.finditer(blob):
        add(iocs.domains, "domain", m.group().lower())
    for m in _EMAIL_RE.finditer(blob):
        add(iocs.emails, "email", m.group())
    for m in _REG_RE.finditer(blob):
        add(iocs.registry_keys, "reg", m.group())
    for m in _BTC_RE.finditer(blob):
        add(iocs.bitcoin, "btc", m.group())
    for m in _MUTEX_HINTS.finditer(blob):
        add(iocs.mutexes, "mutex", m.group())
    for line in strings:
        pm = _PATH_RE.search(line)
        if pm and "\\" in pm.group()[2:]:
            add(iocs.file_paths, "path", pm.group())

    # Domains that are actually the host part of a URL shouldn't double-count.
    url_hosts = {re.sub(r"^\w+://", "", u).split("/")[0].lower() for u in iocs.urls}
    iocs.domains = [d for d in iocs.domains if d not in url_hosts]
    return iocs
