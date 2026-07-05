"""JWT session tokens.

Issued on login/register, carried in an HttpOnly cookie, verified on each
request. Signed with a server key derived from ``REQUIEM_SECRET`` (see
:mod:`crypto`). Short-ish lifetime with the whole thing re-issued on activity is
overkill for a self-host tool, so we use a simple 7-day expiry.
"""
from __future__ import annotations

import datetime as _dt

import jwt

from .store import get_store

COOKIE_NAME = "requiem_session"
_ALGO = "HS256"
_TTL = _dt.timedelta(days=7)


def _secret() -> bytes:
    return get_store().box.jwt_secret()


_ISS = "requiem"


def issue(user_id: int, email: str) -> str:
    now = _dt.datetime.now(_dt.timezone.utc)
    payload = {
        "sub": str(user_id),
        "email": email,
        "iss": _ISS,
        "iat": int(now.timestamp()),
        "nbf": int(now.timestamp()),
        "exp": int((now + _TTL).timestamp()),
    }
    return jwt.encode(payload, _secret(), algorithm=_ALGO)


def verify(token: str) -> dict | None:
    # Pin the algorithm, require iss/exp/iat/nbf, and reject anything missing
    # them. Prevents alg confusion, non-expiring tokens, and issuer spoofing.
    try:
        return jwt.decode(
            token, _secret(), algorithms=[_ALGO], issuer=_ISS,
            options={"require": ["exp", "iat", "nbf", "sub", "iss"],
                     "verify_exp": True, "verify_iat": True,
                     "verify_nbf": True, "verify_signature": True},
        )
    except jwt.PyJWTError:
        return None
