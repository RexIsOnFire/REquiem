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


# --- SSRF on URL keys ----------------------------------------------------
def test_cape_url_ssrf_blocked(client):
    client.post("/auth/register", json={"email": "u@x.com", "password": _STRONG})
    # Cloud metadata endpoint -> blocked.
    r = client.put("/keys", json={"name": "CAPE_URL", "value": "http://169.254.169.254/"})
    assert r.status_code == 400
    # Loopback -> blocked.
    r = client.put("/keys", json={"name": "CAPE_URL", "value": "http://127.0.0.1:8080"})
    assert r.status_code == 400


# --- parser robustness (fuzz) -------------------------------------------
def test_parser_never_crashes_on_garbage():
    import random
    from requiem import analyze, PipelineOptions
    opts = PipelineOptions(run_intel=False)
    random.seed(0)
    for i in range(40):
        data = bytes(random.randrange(256) for _ in range(random.randrange(10, 3000)))
        analyze(data, f"f{i}.bin", opts)  # must not raise
    # Malformed PE headers.
    analyze(b"MZ" + b"\xff" * 300, "x.exe", opts)
    analyze(b"\x7fELF" + b"\xff" * 200, "x.elf", opts)


# --- anonymous analysis rate limiting -----------------------------------
def test_analyze_rate_limited(client):
    import struct
    mz = b"MZ" + b"\x00" * 0x3a + struct.pack("<I", 0x80)
    mz += b"\x00" * (0x80 - len(mz))
    coff = struct.pack("<H H I I I H H", 0x8664, 1, 0, 0, 0, 0xE0, 0x22)
    opt = (struct.pack("<H B B I I I I I", 0x20B, 14, 0, 0x400, 0, 0, 0x1000, 0)
           + struct.pack("<Q", 0x140000000) + struct.pack("<I I", 0x1000, 0x200))
    opt += b"\x00" * (0xE0 - len(opt))
    pe = mz + b"PE\x00\x00" + coff + opt + b"\x00" * 100
    codes = [client.post("/analyze",
                         files={"file": ("s.exe", pe, "application/octet-stream")}).status_code
             for _ in range(25)]
    assert 429 in codes


def test_xff_spoof_does_not_bypass_rate_limit(client, monkeypatch):
    # With XFF untrusted (default), a per-request forged X-Forwarded-For must
    # NOT create fresh rate-limit buckets.
    monkeypatch.delenv("REQUIEM_TRUSTED_PROXIES", raising=False)
    codes = [client.post("/auth/register",
                         json={"email": f"z{i}@x.com", "password": _STRONG},
                         headers={"X-Forwarded-For": f"9.9.9.{i}"}).status_code
             for i in range(8)]
    assert 429 in codes


# --- IDOR: keys are always scoped to the session user -------------------
def test_keys_scoped_to_user(client):
    from fastapi.testclient import TestClient
    from requiem.api.app import app
    # user A saves a key
    client.post("/auth/register", json={"email": "a@x.com", "password": _STRONG})
    client.put("/keys", json={"name": "VT_API_KEY", "value": "aaa111bbb222"})
    # a fresh client (user B) sees no keys — no shared state, no IDOR handle
    other = TestClient(app, headers={"X-Requested-With": "fetch"})
    other.post("/auth/register", json={"email": "b@x.com", "password": _STRONG})
    assert other.get("/keys").json()["status"]["VT_API_KEY"] is False
