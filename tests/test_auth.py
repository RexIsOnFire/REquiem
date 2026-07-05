"""Tests for auth: password hashing, key encryption, store, and API flow."""
import tempfile
from pathlib import Path

import pytest

from requiem.auth import crypto, tokens
from requiem.auth.store import Store


@pytest.fixture(autouse=True)
def _reset_rate_limiter():
    # The rate limiter is a process-global; clear it between tests so limits
    # from one test don't bleed into the next.
    from requiem.api import security
    security.rate_limiter._hits.clear()
    yield


@pytest.fixture
def store(tmp_path):
    return Store(db_path=tmp_path / "t.db")


# --- crypto --------------------------------------------------------------
def test_password_hash_verify():
    h = crypto.hash_password("correct horse battery staple")
    assert crypto.verify_password("correct horse battery staple", h)
    assert not crypto.verify_password("wrong", h)
    # Each hash uses a fresh salt.
    assert h != crypto.hash_password("correct horse battery staple")


def test_secretbox_roundtrip(tmp_path):
    box = crypto.SecretBox(tmp_path)
    ct = box.encrypt("my-secret-key")
    assert ct != "my-secret-key"
    assert box.decrypt(ct) == "my-secret-key"
    assert box.decrypt("garbage") is None


# --- store ---------------------------------------------------------------
def test_user_lifecycle(store):
    u = store.create_user("A@X.com", "password123")
    assert u.email == "a@x.com"  # normalized
    assert store.authenticate("a@x.com", "password123") is not None
    assert store.authenticate("a@x.com", "nope") is None
    with pytest.raises(ValueError):
        store.create_user("a@x.com", "again1234")


def test_keys_encrypted_at_rest(store, tmp_path):
    import sqlite3
    u = store.create_user("k@x.com", "password123")
    store.set_key(u.id, "VT_API_KEY", "super-secret-vt")
    assert store.get_keys(u.id)["VT_API_KEY"] == "super-secret-vt"
    assert store.key_status(u.id)["VT_API_KEY"] is True
    # On disk it must be ciphertext.
    raw = sqlite3.connect(store.db_path).execute(
        "SELECT value_encrypted FROM user_keys").fetchone()[0]
    assert "super-secret-vt" not in raw
    # Delete works.
    store.set_key(u.id, "VT_API_KEY", "")
    assert store.key_status(u.id)["VT_API_KEY"] is False


def test_unknown_key_rejected(store):
    u = store.create_user("k@x.com", "password123")
    with pytest.raises(ValueError):
        store.set_key(u.id, "NOT_A_KEY", "x")


# --- tokens --------------------------------------------------------------
def test_jwt_issue_verify(store, monkeypatch):
    # tokens uses the global store's box; point it at our temp store.
    from requiem.auth import store as store_mod
    monkeypatch.setattr(store_mod, "_store", store)
    t = tokens.issue(42, "a@x.com")
    payload = tokens.verify(t)
    assert payload["sub"] == "42" and payload["email"] == "a@x.com"
    assert tokens.verify(t + "tamper") is None


# --- API flow ------------------------------------------------------------
@pytest.fixture
def client(monkeypatch, tmp_path):
    from fastapi.testclient import TestClient
    from requiem.auth import store as store_mod
    monkeypatch.setattr(store_mod, "_store", Store(db_path=tmp_path / "api.db"))
    from requiem.api.app import app
    return TestClient(app)


_STRONG = "Str0ng!Passw0rd"  # meets the 3-char-class, ≥10 policy


def test_register_login_me_flow(client):
    r = client.post("/auth/register", json={"email": "u@x.com", "password": _STRONG})
    assert r.status_code == 200
    assert client.get("/auth/me").json()["email"] == "u@x.com"
    client.post("/auth/logout")
    assert client.get("/auth/me").status_code == 401
    # Login again.
    assert client.post("/auth/login",
                       json={"email": "u@x.com", "password": _STRONG}).status_code == 200


def test_register_validation(client):
    # bad email
    assert client.post("/auth/register",
                       json={"email": "bad", "password": _STRONG}).status_code == 400
    # too short
    assert client.post("/auth/register",
                       json={"email": "u@x.com", "password": "short"}).status_code == 400
    # long but too few character classes (all lowercase)
    assert client.post("/auth/register",
                       json={"email": "u2@x.com", "password": "abcdefghijkl"}).status_code == 400


def test_keys_require_auth(client):
    assert client.get("/keys").status_code == 401
    client.post("/auth/register", json={"email": "u@x.com", "password": _STRONG})
    r = client.put("/keys", json={"name": "VT_API_KEY", "value": "abc123def456"})
    assert r.status_code == 200
    assert r.json()["status"]["VT_API_KEY"] is True


def test_key_value_validation(client):
    client.post("/auth/register", json={"email": "u@x.com", "password": _STRONG})
    # Invalid chars rejected.
    assert client.put("/keys", json={"name": "VT_API_KEY",
                                     "value": "bad key with spaces"}).status_code == 400
    # Unknown key name rejected.
    assert client.put("/keys", json={"name": "EVIL", "value": "x"}).status_code == 400


def test_investigate_gates_on_auth_and_keys(client):
    h = "a" * 64
    assert client.get(f"/investigate/{h}").status_code == 401  # anon
    client.post("/auth/register", json={"email": "u@x.com", "password": _STRONG})
    assert client.get(f"/investigate/{h}").status_code == 400  # no keys


def test_invalid_hash_rejected(client):
    client.post("/auth/register", json={"email": "u@x.com", "password": _STRONG})
    # Non-hex / wrong length -> 400 before any external call.
    assert client.get("/investigate/not-a-hash").status_code == 400
    assert client.get("/hash/xyz?online=false").status_code == 400
