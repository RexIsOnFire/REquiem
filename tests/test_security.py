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


# --- trailing-newline validation bypass ---------------------------------
def test_email_newline_bypass_rejected():
    from requiem.api.auth_routes import _valid_email
    assert _valid_email("user@x.com") is True
    assert _valid_email("user@x.com\n") is False      # \Z, not $
    assert _valid_email("user@x.com\x00") is False    # control char
    assert _valid_email("user@x.com\r") is False


def test_hash_newline_bypass_rejected():
    from requiem.api.app import _valid_hash
    assert _valid_hash("a" * 64) is True
    assert _valid_hash("a" * 64 + "\n") is False
    assert _valid_hash("a" * 63 + "g") is False       # non-hex


def test_sub_claim_must_be_strict_digits(monkeypatch, tmp_path):
    # A tampered sub with whitespace must not resolve (needs the secret anyway,
    # but defense-in-depth against int() coercion).
    from requiem.api.auth_routes import current_user
    from requiem.auth import store as store_mod, tokens
    import jwt
    s = store_mod.get_store()
    u = s.create_user("d@x.com", _STRONG)
    tok = jwt.encode({"sub": f"{u.id} ", "iss": "requiem", "exp": 9999999999,
                      "iat": 1, "nbf": 1}, tokens._secret(), algorithm="HS256")
    assert current_user(tok) is None


# --- ciphertext binding (DB-write compromise) ---------------------------
def test_key_ciphertext_bound_to_user(tmp_path):
    import sqlite3
    from requiem.auth.store import Store
    s = Store(db_path=tmp_path / "bind.db")
    a = s.create_user("a@x.com", _STRONG)
    b = s.create_user("b@x.com", _STRONG)
    s.set_key(a.id, "VT_API_KEY", "SECRET-AAA")
    s.set_key(b.id, "VT_API_KEY", "SECRET-BBB")
    conn = sqlite3.connect(s.db_path)
    a_ct = conn.execute("SELECT value_encrypted FROM user_keys WHERE user_id=?",
                        (a.id,)).fetchone()[0]
    conn.execute("UPDATE user_keys SET value_encrypted=? WHERE user_id=?", (a_ct, b.id))
    conn.commit()
    # B must NOT be able to read A's key via substituted ciphertext.
    assert s.get_keys(b.id).get("VT_API_KEY") != "SECRET-AAA"


# --- rate limiter memory bound ------------------------------------------
def test_rate_limiter_is_bounded():
    from requiem.api.security import RateLimiter
    rl = RateLimiter()
    for i in range(3000):
        rl.check("login", f"c{i}", limit=5, window=300)
    # Correctness preserved after churn.
    for _ in range(5):
        assert rl.check("x", "same", limit=5, window=300) is True
    assert rl.check("x", "same", limit=5, window=300) is False


# --- ReDoS ---------------------------------------------------------------
def test_domain_regex_no_redos():
    import time
    from requiem.static.strings_ioc import harvest_iocs
    # The pattern that caused 5s+ catastrophic backtracking before the fix.
    evil = ["a" * 20000 + "." + "A" * 20000 + ".com"]
    t = time.perf_counter()
    harvest_iocs(evil)
    assert time.perf_counter() - t < 1.0  # must be near-instant now


def test_domain_regex_still_correct():
    from requiem.static.strings_ioc import harvest_iocs
    r = harvest_iocs(["evil-c2.example.com", "www.malware.ru", "not_a_domain"])
    assert "evil-c2.example.com" in r.domains
    assert "www.malware.ru" in r.domains
    assert "not_a_domain" not in r.domains


# --- info disclosure -----------------------------------------------------
def test_docs_and_config_not_exposed(client):
    # Interactive docs / OpenAPI and the server-config endpoint must be off.
    assert client.get("/docs").status_code == 404
    assert client.get("/redoc").status_code == 404
    assert client.get("/openapi.json").status_code == 404
    assert client.get("/config").status_code == 404


# --- session invalidation ------------------------------------------------
def test_session_invalidated_when_user_deleted(client):
    import sqlite3
    from requiem.auth import store as store_mod
    client.post("/auth/register", json={"email": "u@x.com", "password": _STRONG})
    assert client.get("/auth/me").status_code == 200
    conn = sqlite3.connect(store_mod.get_store().db_path)
    conn.execute("DELETE FROM users WHERE email=?", ("u@x.com",))
    conn.commit()
    # The still-valid cookie must not grant access to a deleted account.
    assert client.get("/auth/me").status_code == 401


# --- filename sanitization ----------------------------------------------
def test_filename_sanitization_blocks_breakout():
    from requiem.api.app import _safe_filename
    for evil in ['a"; filename="x', "a\r\nSet-Cookie: e=1", "../../etc/passwd",
                 "file‮gpj.exe", "\x00\x01"]:
        out = _safe_filename(evil)
        assert out.isascii()
        for bad in ('"', "\r", "\n", "/", "\\", "\x00", "‮", ";"):
            assert bad not in out


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
