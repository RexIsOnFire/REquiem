"""Authentication + per-user API-key routes (FastAPI router).

Endpoints (all under the main app):
    POST /auth/register   {email, password}      -> sets session cookie
    POST /auth/login      {email, password}      -> sets session cookie
    POST /auth/logout                            -> clears cookie
    GET  /auth/me                                -> current user or 401
    GET  /keys                                   -> which keys are set (bools)
    PUT  /keys            {name, value}          -> save/update one key
    DELETE /keys/{name}                          -> remove one key

Sessions ride in an HttpOnly cookie (JS can't read it → XSS can't steal it).
Key *values* are write-only over the API: you can set them and see which are
set, but never read them back.
"""
from __future__ import annotations

import re

from fastapi import APIRouter, Body, Cookie, HTTPException, Request, Response

from ..auth import tokens
from ..auth.store import ALLOWED_KEYS, User, get_store
from . import security as _sec

router = APIRouter()

# Input caps (defense against oversized-input DoS).
_MAX_EMAIL = 254
_MAX_PASSWORD = 200
_MAX_KEY_VALUE = 8192


def _set_session(resp: Response, user: User) -> None:
    # Cookie policy comes from central security config (SameSite/Secure adapt
    # to same-origin vs cross-origin HTTPS deploys).
    resp.set_cookie(tokens.COOKIE_NAME, tokens.issue(user.id, user.email),
                    max_age=7 * 24 * 3600, **_sec.cookie_kwargs())


def _rate_limit(request: Request, bucket: str, *, limit: int, window: float) -> None:
    client = _sec.client_ip(request)
    if not _sec.rate_limiter.check(bucket, client, limit=limit, window=window):
        raise HTTPException(status_code=429, detail="too many requests, slow down")


def current_user(requiem_session: str | None = Cookie(default=None)) -> User | None:
    """FastAPI dependency — resolves the session cookie to a User, or None."""
    if not requiem_session:
        return None
    payload = tokens.verify(requiem_session)
    if not payload:
        return None
    try:
        return get_store().get_user(int(payload["sub"]))
    except (KeyError, ValueError):
        return None


def require_user(requiem_session: str | None = Cookie(default=None)) -> User:
    user = current_user(requiem_session)
    if user is None:
        raise HTTPException(status_code=401, detail="authentication required")
    return user


_EMAIL_RE = re.compile(r"^[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}$")


def _valid_email(email: str) -> bool:
    return bool(email) and len(email) <= _MAX_EMAIL and bool(_EMAIL_RE.match(email))


def _password_problem(password: str) -> str | None:
    """Return a human message if the password is too weak, else None."""
    if not password or len(password) < 10:
        return "password must be at least 10 characters"
    if len(password) > _MAX_PASSWORD:
        return "password is too long"
    classes = sum(bool(re.search(p, password)) for p in
                  (r"[a-z]", r"[A-Z]", r"\d", r"[^A-Za-z0-9]"))
    if classes < 3:
        return ("password must mix at least three of: lowercase, uppercase, "
                "digits, symbols")
    return None


# --- auth ----------------------------------------------------------------
@router.post("/auth/register")
def register(request: Request, resp: Response,
             email: str = Body(...), password: str = Body(...)):
    _rate_limit(request, "register", limit=5, window=3600)  # 5/hour/IP
    email = (email or "").strip().lower()
    if not _valid_email(email):
        raise HTTPException(status_code=400, detail="invalid email")
    problem = _password_problem(password or "")
    if problem:
        raise HTTPException(status_code=400, detail=problem)
    try:
        user = get_store().create_user(email, password)
    except ValueError:
        raise HTTPException(status_code=409, detail="email already registered")
    _set_session(resp, user)
    return {"id": user.id, "email": user.email}


@router.post("/auth/login")
def login(request: Request, resp: Response,
          email: str = Body(...), password: str = Body(...)):
    # Rate limit per-IP AND per-email to blunt credential stuffing/brute force.
    _rate_limit(request, "login-ip", limit=10, window=300)          # 10/5min/IP
    _rate_limit(request, f"login-user:{(email or '').lower()[:254]}",
                limit=5, window=300)                                # 5/5min/email
    if len(email or "") > _MAX_EMAIL or len(password or "") > _MAX_PASSWORD:
        raise HTTPException(status_code=400, detail="invalid credentials")
    user = get_store().authenticate(email or "", password or "")
    if user is None:
        raise HTTPException(status_code=401, detail="invalid email or password")
    _set_session(resp, user)
    return {"id": user.id, "email": user.email}


@router.post("/auth/logout")
def logout(resp: Response):
    resp.delete_cookie(tokens.COOKIE_NAME, **_sec.cookie_kwargs())
    return {"ok": True}


@router.get("/auth/me")
def me(requiem_session: str | None = Cookie(default=None)):
    user = current_user(requiem_session)
    if user is None:
        raise HTTPException(status_code=401, detail="not authenticated")
    return {"id": user.id, "email": user.email, "created_at": user.created_at}


# --- per-user API keys ---------------------------------------------------
@router.get("/keys")
def list_keys(requiem_session: str | None = Cookie(default=None)):
    user = require_user(requiem_session)
    return {"allowed": list(ALLOWED_KEYS), "status": get_store().key_status(user.id)}


# API-key values may contain only these characters (all real keys/URLs do).
_KEY_VALUE_RE = re.compile(r"^[A-Za-z0-9._:/\-]*$")

# Keys that hold a URL must pass SSRF validation (public https host only).
_URL_KEYS = {"CAPE_URL"}


def _validate_url_value(value: str) -> None:
    """Reject non-HTTPS, and hosts that resolve to private/loopback/link-local
    or cloud-metadata addresses (SSRF defense-in-depth)."""
    import ipaddress
    import socket
    from urllib.parse import urlparse

    parsed = urlparse(value)
    if parsed.scheme not in ("http", "https") or not parsed.hostname:
        raise HTTPException(status_code=400, detail="URL must be http(s) with a host")
    host = parsed.hostname
    # Block the cloud metadata endpoints outright.
    if host in ("169.254.169.254", "metadata.google.internal", "metadata"):
        raise HTTPException(status_code=400, detail="URL host not allowed")
    try:
        infos = socket.getaddrinfo(host, None)
    except OSError:
        raise HTTPException(status_code=400, detail="URL host does not resolve")
    for info in infos:
        ip = ipaddress.ip_address(info[4][0])
        if (ip.is_private or ip.is_loopback or ip.is_link_local
                or ip.is_reserved or ip.is_multicast or ip.is_unspecified):
            raise HTTPException(status_code=400,
                                detail="URL resolves to a non-public address")


@router.put("/keys")
def set_key(requiem_session: str | None = Cookie(default=None),
            name: str = Body(...), value: str = Body(...)):
    user = require_user(requiem_session)
    if name not in ALLOWED_KEYS:
        raise HTTPException(status_code=400, detail=f"unknown key '{name}'")
    value = (value or "").strip()
    if len(value) > _MAX_KEY_VALUE:
        raise HTTPException(status_code=400, detail="value too long")
    if value and not _KEY_VALUE_RE.match(value):
        raise HTTPException(status_code=400, detail="value contains invalid characters")
    if value and name in _URL_KEYS:
        _validate_url_value(value)
    get_store().set_key(user.id, name, value)
    return {"status": get_store().key_status(user.id)}


@router.delete("/keys/{name}")
def delete_key(name: str, requiem_session: str | None = Cookie(default=None)):
    user = require_user(requiem_session)
    if name not in ALLOWED_KEYS:
        raise HTTPException(status_code=400, detail="unknown key")
    get_store().delete_key(user.id, name)
    return {"status": get_store().key_status(user.id)}
