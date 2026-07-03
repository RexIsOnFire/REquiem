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

from fastapi import APIRouter, Body, Cookie, HTTPException, Response

from ..auth import tokens
from ..auth.store import ALLOWED_KEYS, User, get_store

router = APIRouter()

# Cookie hardening. secure=True requires HTTPS; leave configurable for localhost.
import os as _os

_SECURE = _os.environ.get("REQUIEM_COOKIE_SECURE", "0") == "1"
_COOKIE_KW = dict(httponly=True, samesite="lax", secure=_SECURE, path="/")


def _set_session(resp: Response, user: User) -> None:
    resp.set_cookie(tokens.COOKIE_NAME, tokens.issue(user.id, user.email),
                    max_age=7 * 24 * 3600, **_COOKIE_KW)


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


def _valid_email(email: str) -> bool:
    import re
    return bool(re.match(r"^[^@\s]+@[^@\s]+\.[^@\s]+$", email or ""))


# --- auth ----------------------------------------------------------------
@router.post("/auth/register")
def register(resp: Response, email: str = Body(...), password: str = Body(...)):
    email = (email or "").strip().lower()
    if not _valid_email(email):
        raise HTTPException(status_code=400, detail="invalid email")
    if len(password or "") < 8:
        raise HTTPException(status_code=400, detail="password must be at least 8 characters")
    try:
        user = get_store().create_user(email, password)
    except ValueError:
        raise HTTPException(status_code=409, detail="email already registered")
    _set_session(resp, user)
    return {"id": user.id, "email": user.email}


@router.post("/auth/login")
def login(resp: Response, email: str = Body(...), password: str = Body(...)):
    user = get_store().authenticate(email or "", password or "")
    if user is None:
        raise HTTPException(status_code=401, detail="invalid email or password")
    _set_session(resp, user)
    return {"id": user.id, "email": user.email}


@router.post("/auth/logout")
def logout(resp: Response):
    resp.delete_cookie(tokens.COOKIE_NAME, path="/")
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


@router.put("/keys")
def set_key(requiem_session: str | None = Cookie(default=None),
            name: str = Body(...), value: str = Body(...)):
    user = require_user(requiem_session)
    if name not in ALLOWED_KEYS:
        raise HTTPException(status_code=400, detail=f"unknown key '{name}'")
    get_store().set_key(user.id, name, (value or "").strip())
    return {"status": get_store().key_status(user.id)}


@router.delete("/keys/{name}")
def delete_key(name: str, requiem_session: str | None = Cookie(default=None)):
    user = require_user(requiem_session)
    get_store().delete_key(user.id, name)
    return {"status": get_store().key_status(user.id)}
