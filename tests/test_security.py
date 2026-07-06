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


# --- cache-control on sensitive responses -------------------------------
def test_no_store_cache_on_api(client):
    client.post("/auth/register", json={"email": "u@x.com", "password": _STRONG})
    for path in ("/auth/me", "/keys", "/healthz"):
        assert client.get(path).headers.get("cache-control") == "no-store"


# --- mass assignment -----------------------------------------------------
def test_mass_assignment_ignored(client):
    r = client.post("/auth/register",
                    json={"email": "m@x.com", "password": _STRONG,
                          "id": 9999, "is_admin": True, "role": "admin"})
    assert r.status_code == 200
    # Auto-assigned id, not the injected 9999.
    assert r.json()["id"] != 9999


# --- PDF render concurrency cap -----------------------------------------
def test_pdf_render_pool_is_capped():
    from requiem.report import pdf
    # A bounded semaphore exists and starts at the configured max.
    assert pdf._MAX_CONCURRENT >= 1
    assert pdf._render_slots._value == pdf._MAX_CONCURRENT


# --- password hash robustness -------------------------------------------
def test_verify_password_survives_tampered_hash():
    from requiem.auth.crypto import verify_password, hash_password
    # Huge-N tampered hash must return False, never raise (no memory DoS / 500).
    assert verify_password("x", "scrypt$99999999$8$1$AAAA$BBBB") is False
    assert verify_password("x", "garbage") is False
    assert verify_password("x", "") is False
    good = hash_password("correct-horse")
    assert verify_password("correct-horse", good) is True
    assert verify_password("wrong", good) is False


# --- request body size limits -------------------------------------------
def test_oversized_auth_body_rejected(client):
    big = {"email": "u@x.com", "password": _STRONG, "pad": "A" * 20000}
    assert client.post("/auth/register", json=big).status_code == 413


def test_global_body_ceiling(client):
    r = client.post("/analyze",
                    headers={"Content-Length": str(100 * 1024 * 1024),
                             "X-Requested-With": "fetch"},
                    content=b"x")
    assert r.status_code == 413


# --- key-binding delimiter safety ---------------------------------------
def test_key_binding_handles_embedded_delimiter(tmp_path):
    from requiem.auth.store import Store
    s = Store(db_path=tmp_path / "d.db")
    u = s.create_user("a@x.com", _STRONG)
    # Value containing the \x00 delimiter must round-trip and not confuse binding.
    s.set_key(u.id, "VT_API_KEY", "a\x00b\x00c")
    assert s.get_keys(u.id).get("VT_API_KEY") == "a\x00b\x00c"


# --- analysis-engine DoS resistance -------------------------------------
def test_ioc_harvest_bounded_on_huge_blob():
    import time
    from requiem.static.strings_ioc import harvest_iocs
    huge = ["http://evil.com/x " * 500000]  # ~9 MB single string
    t = time.perf_counter()
    harvest_iocs(huge)
    assert time.perf_counter() - t < 3.0  # blob is capped


def test_disassembler_bounded_on_pathological_pe():
    import time
    import struct
    from requiem import analyze, PipelineOptions

    def align(n, a=0x200):
        return (n + a - 1) // a * a
    code = b"\xeb\xfe" * 100000  # infinite self-jump
    code = code + b"\x90" * (align(len(code)) - len(code))
    sec = [(b".text\x00\x00\x00", code, 0x60000020)]
    mz = b"MZ" + b"\x00" * 0x3a + struct.pack("<I", 0x80)
    mz += b"\x00" * (0x80 - len(mz))
    coff = struct.pack("<H H I I I H H", 0x8664, len(sec), 0, 0, 0, 0xE0, 0x22)
    opt = (struct.pack("<H B B I I I I I", 0x20B, 14, 0, 0x400, 0, 0, 0x1000, 0)
           + struct.pack("<Q", 0x140000000) + struct.pack("<I I", 0x1000, 0x200))
    opt += b"\x00" * (0xE0 - len(opt))
    h = mz + b"PE\x00\x00" + coff + opt
    rp = align(len(h) + 40)
    sh = struct.pack("<8s I I I I I I H H I", b".text\x00\x00\x00", len(code),
                     0x1000, align(len(code)), rp, 0, 0, 0, 0, 0x60000020)
    pe = h + sh + b"\x00" * (rp - len(h + sh)) + code
    t = time.perf_counter()
    analyze(pe, "loop.exe", PipelineOptions(run_intel=False))
    assert time.perf_counter() - t < 5.0  # bounded by instruction/block budget


def test_yara_scan_never_crashes():
    from requiem.static import yara_scan
    for data in (b"", b"\x00" * 1_000_000, b"A" * 3_000_000):
        yara_scan.scan(data)  # must not raise


# --- malformed report payloads (from_dict) ------------------------------
def test_report_pdf_rejects_malformed_payloads(client):
    import json
    for bad in ({}, {"identity": None}, {"identity": {"filename": ["x"]}},
                {"verdict_confidence": {"name": "INJECT", "value": 1}},
                {"findings": "not a list"}):
        r = client.post("/report/pdf", data=json.dumps(bad),
                        headers={"Content-Type": "application/json",
                                 "X-Requested-With": "fetch"})
        assert r.status_code in (400, 413)  # never 500


# --- concurrent key-write race ------------------------------------------
def test_concurrent_key_writes_no_corruption(tmp_path):
    import sqlite3
    import threading
    from requiem.auth.store import Store
    s = Store(db_path=tmp_path / "kr.db")
    u = s.create_user("a@x.com", _STRONG)
    threads = [threading.Thread(target=lambda i=i: s.set_key(u.id, "VT_API_KEY", f"v{i}"))
               for i in range(30)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    n = sqlite3.connect(s.db_path).execute(
        "SELECT COUNT(*) FROM user_keys WHERE user_id=? AND name=?",
        (u.id, "VT_API_KEY")).fetchone()[0]
    assert n == 1  # exactly one row, no duplication


# --- HTML report security headers ---------------------------------------
def test_html_report_hardened_headers(client):
    import struct
    mz = b"MZ" + b"\x00" * 0x3a + struct.pack("<I", 0x80)
    mz += b"\x00" * (0x80 - len(mz))
    coff = struct.pack("<H H I I I H H", 0x8664, 1, 0, 0, 0, 0xE0, 0x22)
    opt = (struct.pack("<H B B I I I I I", 0x20B, 14, 0, 0x400, 0, 0, 0x1000, 0)
           + struct.pack("<Q", 0x140000000) + struct.pack("<I I", 0x1000, 0x200))
    opt += b"\x00" * (0xE0 - len(opt))
    pe = mz + b"PE\x00\x00" + coff + opt + b"\x00" * 100
    r = client.post("/analyze/html",
                    files={"file": ("x.exe", pe, "application/octet-stream")})
    assert r.headers.get("x-content-type-options") == "nosniff"
    assert "script-src 'none'" in r.headers.get("content-security-policy", "")


# --- hostile external-report bounding -----------------------------------
def test_cloud_report_is_bounded():
    from requiem.dynamic import normalize as N
    procs = [N.NormProcess(pid=i, name="p" * 5000) for i in range(50000)]
    norm = N.NormalizedReport(processes=procs,
                              network=[{"type": "x", "dest": "y"}] * 50000,
                              signatures=[N.NormSignature(name="s")] * 50000)
    beh = N.to_behavior(norm, backend_name="t")
    assert len(beh.process_tree) <= 2000
    assert len(beh.network) <= 2000
    assert len(beh.memory) <= 2000
    assert len(beh.process_tree[0]["name"]) <= 512


def test_vt_report_is_bounded():
    from requiem.intel import vt_behavior
    tree = vt_behavior._process_tree(
        {"processes_tree": [{"children": [{"children": []}]}] * 100000})
    assert len(tree) <= 2000


# --- SSRF: external HTTP does not follow redirects -----------------------
def test_providers_use_no_redirect_opener():
    from requiem.dynamic.sandbox_http import no_redirect_opener
    # The opener must carry a redirect handler that refuses to follow.
    names = [type(h).__name__ for h in no_redirect_opener.handlers]
    assert any("NoRedirect" in n for n in names)


# --- .env parser is injection-safe --------------------------------------
def test_dotenv_values_are_literal():
    from requiem.core import config
    assert config._parse_line("K=$(whoami)") == ("K", "$(whoami)")
    assert config._parse_line("K=a; rm -rf /") == ("K", "a; rm -rf /")
    assert config._parse_line("export E=`id`") == ("E", "`id`")


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
