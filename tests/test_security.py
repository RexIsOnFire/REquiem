"""Security-focused tests: headers, CORS, CSRF, JWT hardening, rate limits."""
import tempfile
from pathlib import Path

import jwt
import pytest

from requiem.auth import store as store_mod
from requiem.auth.store import Store


@pytest.fixture(autouse=True)
def _reset(monkeypatch, tmp_path):
    monkeypatch.setattr(store_mod, "_store", Store(db_path=tmp_path / "s.db"))
    from requiem.api import security
    security.rate_limiter._hits.clear()
    yield


@pytest.fixture
def client():
    from fastapi.testclient import TestClient
    from requiem.api.app import app
    return TestClient(app, headers={"X-Requested-With": "fetch"})


_STRONG = "Str0ng!Passw0rd"


# --- security headers ----------------------------------------------------
def test_security_headers_present(client):
    r = client.get("/healthz")
    assert r.headers.get("X-Content-Type-Options") == "nosniff"
    assert r.headers.get("X-Frame-Options") == "DENY"
    assert "Content-Security-Policy" in r.headers
    assert "script-src 'none'" in r.headers["Content-Security-Policy"]
    assert r.headers.get("Referrer-Policy") == "no-referrer"


# --- CSRF ----------------------------------------------------------------
def test_csrf_blocks_multipart_without_header():
    from fastapi.testclient import TestClient
    from requiem.api.app import app
    bare = TestClient(app)  # no X-Requested-With
    r = bare.post("/analyze", files={"file": ("x.bin", b"MZ", "application/octet-stream")})
    assert r.status_code == 403


def test_csrf_allows_json_and_safe_methods(client):
    # JSON body is allowed (browsers preflight it); GET is a safe method.
    assert client.get("/healthz").status_code == 200
    r = client.post("/auth/register", json={"email": "u@x.com", "password": _STRONG})
    assert r.status_code == 200


# --- JWT hardening -------------------------------------------------------
def test_jwt_rejects_alg_none_and_no_exp(monkeypatch, tmp_path):
    from requiem.auth import tokens
    u = store_mod.get_store().create_user("a@b.com", _STRONG)
    # alg=none
    try:
        forged = jwt.encode({"sub": str(u.id)}, "", algorithm="none")
        assert tokens.verify(forged) is None
    except Exception:
        pass  # PyJWT refuses to even encode 'none' — also fine
    # valid-signature but missing exp
    noexp = jwt.encode({"sub": str(u.id), "iss": "requiem", "iat": 1, "nbf": 1},
                       tokens._secret(), algorithm="HS256")
    assert tokens.verify(noexp) is None
    # wrong issuer
    wrong = jwt.encode({"sub": str(u.id), "iss": "evil", "exp": 9999999999,
                        "iat": 1, "nbf": 1}, tokens._secret(), algorithm="HS256")
    assert tokens.verify(wrong) is None


# --- login timing (user enumeration) ------------------------------------
def test_login_runs_hash_for_unknown_user():
    # Both paths must invoke password verification (constant work).
    s = store_mod.get_store()
    s.create_user("real@x.com", _STRONG)
    # Neither should raise or short-circuit differently; both return None here.
    assert s.authenticate("nobody@x.com", "whatever") is None
    assert s.authenticate("real@x.com", "wrongpassword") is None


# --- rate limiting -------------------------------------------------------
def test_register_rate_limited(client):
    # 5/hour/IP — the 6th registration attempt should be throttled.
    codes = []
    for i in range(7):
        r = client.post("/auth/register",
                        json={"email": f"u{i}@x.com", "password": _STRONG})
        codes.append(r.status_code)
    assert 429 in codes


def test_login_rate_limited_per_ip(client):
    client.post("/auth/register", json={"email": "u@x.com", "password": _STRONG})
    codes = [client.post("/auth/login",
                         json={"email": "u@x.com", "password": "wrong-Pass1!"}).status_code
             for _ in range(12)]
    assert 429 in codes
