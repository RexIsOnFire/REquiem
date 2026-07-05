"""Central security configuration: CORS, cookies, headers, rate limiting.

All hardening knobs live here so the whole app is consistent and auditable.
Behavior is driven by environment so the same code is safe locally (HTTP,
same-origin) and in production (HTTPS, split frontend/backend origins).

Env vars:
    REQUIEM_ALLOWED_ORIGINS   comma-separated exact origins allowed to send
                              credentialed requests (e.g. https://requiem.onrender.com)
    REQUIEM_COOKIE_SECURE     "1" to mark the session cookie Secure (HTTPS only)
    REQUIEM_COOKIE_SAMESITE   "lax" (default) | "none" | "strict".
                              Cross-site deploys need "none" (implies Secure).
    REQUIEM_SECRET            server secret for signing/encryption (see auth.crypto)
"""
from __future__ import annotations

import os
import time
from collections import defaultdict, deque

# --- cookie policy -------------------------------------------------------
def cookie_kwargs() -> dict:
    samesite = os.environ.get("REQUIEM_COOKIE_SAMESITE", "lax").lower()
    if samesite not in ("lax", "none", "strict"):
        samesite = "lax"
    secure = os.environ.get("REQUIEM_COOKIE_SECURE", "0") == "1"
    # SameSite=None is only honored by browsers when Secure is also set.
    if samesite == "none":
        secure = True
    return {"httponly": True, "samesite": samesite, "secure": secure, "path": "/"}


# --- CORS ----------------------------------------------------------------
def allowed_origins() -> list[str]:
    raw = os.environ.get("REQUIEM_ALLOWED_ORIGINS", "")
    origins = [o.strip() for o in raw.split(",") if o.strip()]
    # Sensible localhost defaults for development.
    origins += ["http://localhost:3000", "http://127.0.0.1:3000",
                "http://localhost:3001", "http://127.0.0.1:3001"]
    # De-dupe, preserve order.
    seen, out = set(), []
    for o in origins:
        if o not in seen:
            seen.add(o)
            out.append(o)
    return out


# --- security response headers ------------------------------------------
# A strict-ish CSP. The frontend is a separate Next app; this protects the API's
# own HTML responses (report/HTML export, docs). 'unsafe-inline' is required for
# the self-contained report's inline styles/SVG; scripts are limited to the
# single inline print button, so we allow inline styles but keep script tight.
_CSP = (
    "default-src 'none'; "
    "img-src 'self' data:; "
    "style-src 'self' 'unsafe-inline'; "
    "script-src 'self' 'unsafe-inline'; "
    "font-src 'self' data:; "
    "connect-src 'self'; "
    "base-uri 'none'; "
    "form-action 'self'; "
    "frame-ancestors 'none'"
)

_SECURITY_HEADERS = {
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer",
    "Permissions-Policy": "geolocation=(), microphone=(), camera=(), usb=()",
    "Cross-Origin-Opener-Policy": "same-origin",
    "Cross-Origin-Resource-Policy": "same-site",
    "Content-Security-Policy": _CSP,
}


def security_headers(is_https: bool) -> dict:
    headers = dict(_SECURITY_HEADERS)
    if is_https or os.environ.get("REQUIEM_COOKIE_SECURE", "0") == "1":
        headers["Strict-Transport-Security"] = "max-age=63072000; includeSubDomains"
    return headers


# --- simple in-memory rate limiter --------------------------------------
class RateLimiter:
    """Fixed-window-ish sliding limiter keyed by (bucket, client).

    In-process only — fine for a single Render instance. For multi-instance,
    swap for Redis. Intentionally tiny and dependency-free.
    """

    def __init__(self):
        self._hits: dict[tuple[str, str], deque] = defaultdict(deque)

    def check(self, bucket: str, client: str, *, limit: int, window: float) -> bool:
        """Return True if allowed, False if the client is over the limit."""
        now = time.monotonic()
        key = (bucket, client)
        dq = self._hits[key]
        cutoff = now - window
        while dq and dq[0] < cutoff:
            dq.popleft()
        if len(dq) >= limit:
            return False
        dq.append(now)
        return True


rate_limiter = RateLimiter()


def client_ip(request) -> str:
    # Render/most proxies set X-Forwarded-For; take the first hop.
    xff = request.headers.get("x-forwarded-for")
    if xff:
        return xff.split(",")[0].strip()
    return request.client.host if request.client else "unknown"
