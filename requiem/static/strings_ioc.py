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
# NOTE: the previous pattern used a nested quantifier
# ``(?:[a-z0-9](?:[a-z0-9\-]{0,61}[a-z0-9])?\.)+`` which catastrophically
# backtracks (5s+ on a 20k 'a....' string) — a ReDoS. This version uses a
# flat label class with a bounded repeat and a hard length ceiling on each
# label, so matching is linear.
_DOMAIN_RE = re.compile(
    r"\b(?:[a-z0-9][a-z0-9\-]{0,62}\.){1,8}"
    r"(?:com|net|org|io|ru|cn|info|biz|xyz|top|onion|co|us|uk|de|nl)\b", re.I)
_EMAIL_RE = re.compile(r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b")
_REG_RE = re.compile(
    r"(?:HKLM|HKCU|HKEY_[A-Z_]+|SOFTWARE\\|SYSTEM\\CurrentControlSet)[\\A-Za-z0-9_\-.]{3,}", re.I)
_BTC_RE = re.compile(r"\b(?:bc1[a-z0-9]{20,}|[13][a-km-zA-HJ-NP-Z1-9]{25,34})\b")
# A real Windows path: drive, at least one dir component, and a final component
# with a file extension — kills junk like "U:\-2" or "w:\g".
_PATH_RE = re.compile(
    r"[A-Za-z]:\\(?:[A-Za-z0-9 _.\-]+\\)+[A-Za-z0-9 _.\-]+\.[A-Za-z0-9]{1,8}")

# Substrings that hint at a mutex/named-object creation.
_MUTEX_HINTS = re.compile(r"(?:Global\\|Local\\|Session\\)[A-Za-z0-9_\-{}]{4,}")

# --- benign-noise denylists ---------------------------------------------
# Hosts that appear in embedded XML/XMP metadata, manifests, and toolchains —
# never C2. Matched as a suffix so subdomains are covered.
_BENIGN_HOST_SUFFIXES = (
    "w3.org", "adobe.com", "purl.org", "ns.adobe.com", "microsoft.com",
    "schemas.microsoft.com", "verisign.com", "digicert.com", "sectigo.com",
    "globalsign.com", "thawte.com", "openxmlformats.org", "xmlsoap.org",
    "apache.org", "python.org", "golang.org", "rust-lang.org", "gnu.org",
    "opensource.org", "creativecommons.org", "sonarsource.com",
)
# Domains that are really .NET/library namespaces caught by the TLD regex.
_NAMESPACE_DOMAINS = {
    "system.io", "system.net", "system.web", "system.data", "system.xml",
    "system.core", "system.drawing", "system.text", "system.linq",
    "s.io", "ur.io", "r.io", "e.io",
}


def _benign_host(host: str) -> bool:
    host = host.lower().strip(".")
    if host in _NAMESPACE_DOMAINS:
        return True
    return any(host == s or host.endswith("." + s) for s in _BENIGN_HOST_SUFFIXES)


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
    # Reject leading-zero octets and version-number-looking quads early.
    octets = s.split(".")
    if any(len(o) > 1 and o[0] == "0" for o in octets):
        return False
    try:
        ip = ipaddress.IPv4Address(s)
    except ValueError:
        return False
    # Drop non-routable / structural noise. Assembly version quads like
    # 4.0.0.0, 1.0.0.0, 25.12.15.0 read as IPs but almost never are — a final
    # octet of 0 is a network address, not a host, so we drop those too.
    if (ip.is_loopback or ip.is_unspecified or ip.is_multicast
            or ip.is_private or ip.is_reserved or ip.is_link_local):
        return False
    if int(ip) & 0xFF == 0:            # x.x.x.0 — network address / version quad
        return False
    if str(ip).startswith(("0.", "255.")):
        return False
    return True


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
        url = m.group().rstrip(".,);")
        host = re.sub(r"^\w+://", "", url).split("/")[0].split(":")[0]
        if not _benign_host(host):
            add(iocs.urls, "url", url)
    for m in _IPV4_RE.finditer(blob):
        if _valid_ipv4(m.group()):
            add(iocs.ipv4, "ip", m.group())
    for m in _DOMAIN_RE.finditer(blob):
        domain = m.group().lower()
        if not _benign_host(domain):
            add(iocs.domains, "domain", domain)
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
