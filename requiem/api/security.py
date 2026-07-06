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
from collections import deque

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
    "style-src 'self' 'unsafe-inline'; "  # self-contained report uses inline CSS
    "script-src 'none'; "                  # API HTML carries NO scripts
    "font-src 'self' data:; "
    "connect-src 'self'; "
    "base-uri 'none'; "
    "form-action 'self'; "
    "object-src 'none'; "
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
    # API responses are dynamic and often carry per-user data — never let a
    # browser or shared proxy cache them.
    "Cache-Control": "no-store",
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

    # Hard cap on tracked keys so an attacker can't exhaust memory by flooding
    # the per-email bucket with millions of unique addresses.
    _MAX_KEYS = 100_000

    def __init__(self):
        self._hits: dict[tuple[str, str], deque] = {}
        self._sweeps = 0

    def _evict(self, now: float) -> None:
        # Drop keys whose newest hit is older than 1h (any window has passed).
        stale = [k for k, dq in self._hits.items() if not dq or dq[-1] < now - 3600]
        for k in stale:
            self._hits.pop(k, None)
        # If still over the cap after sweeping, drop the oldest-touched keys.
        if len(self._hits) > self._MAX_KEYS:
            for k in sorted(self._hits, key=lambda k: self._hits[k][-1] if self._hits[k] else 0
                            )[: len(self._hits) - self._MAX_KEYS]:
                self._hits.pop(k, None)

    def check(self, bucket: str, client: str, *, limit: int, window: float) -> bool:
        """Return True if allowed, False if the client is over the limit."""
        now = time.monotonic()
        # Periodic housekeeping (cheap, amortized) + a hard ceiling.
        self._sweeps += 1
        if self._sweeps % 1000 == 0 or len(self._hits) > self._MAX_KEYS:
            self._evict(now)
        key = (bucket, client)
        dq = self._hits.get(key)
        if dq is None:
            dq = self._hits[key] = deque()
        cutoff = now - window
        while dq and dq[0] < cutoff:
            dq.popleft()
        if len(dq) >= limit:
            return False
        dq.append(now)
        return True


rate_limiter = RateLimiter()


def client_ip(request) -> str:
    """Best-effort client IP for rate limiting.

    X-Forwarded-For is client-spoofable (the client controls the left entries),
    so we only consult it when explicitly behind a known number of trusted
    proxies (REQUIEM_TRUSTED_PROXIES, default 0 = don't trust XFF). We then take
    the entry that many hops from the RIGHT — the address the outermost trusted
    proxy observed — which a client cannot forge. Otherwise use the direct peer.
    """
    try:
        trusted = int(os.environ.get("REQUIEM_TRUSTED_PROXIES", "0"))
    except ValueError:
        trusted = 0
    if trusted > 0:
        xff = request.headers.get("x-forwarded-for")
        if xff:
            hops = [h.strip() for h in xff.split(",") if h.strip()]
            # The real client is `trusted` positions from the right end.
            idx = len(hops) - trusted
            if 0 <= idx < len(hops):
                return hops[idx]
    return request.client.host if request.client else "unknown"


# --- CSRF protection -----------------------------------------------------
# With SameSite=None (cross-origin deploys) the session cookie rides cross-site
# requests, so we need CSRF defense. Strategy: every state-changing request must
# either (a) be JSON (forces a CORS preflight that our allowlist controls) or
# (b) carry X-Requested-With: fetch. HTML <form> CSRF can do neither against a
# cross-origin target, and multipart uploads must add the header. Same-origin
# GET/HEAD/OPTIONS are exempt (safe methods).
_SAFE_METHODS = {"GET", "HEAD", "OPTIONS"}


def csrf_ok(request) -> bool:
    if request.method in _SAFE_METHODS:
        return True
    ctype = (request.headers.get("content-type") or "").split(";")[0].strip().lower()
    if ctype == "application/json":
        return True
    if request.headers.get("x-requested-with", "").lower() in ("fetch", "xmlhttprequest"):
        return True
    return False
