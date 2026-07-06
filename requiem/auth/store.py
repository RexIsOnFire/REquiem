"""SQLite-backed user + per-user-API-key store.

Two tables:
- ``users(id, email, password_hash, created_at)``
- ``user_keys(user_id, name, value_encrypted)`` — API keys, Fernet-encrypted.

All key values are encrypted before they touch the DB; plaintext never lands on
disk. The DB path defaults to ``<repo>/data/requiem.db`` and is created lazily.
"""
from __future__ import annotations

import os
import sqlite3
import threading
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

from .crypto import SecretBox, hash_password, verify_password

# A real scrypt hash of a random string, computed once at import. Used to run a
# constant-cost password check when the email doesn't exist, so login timing
# never reveals whether an account is registered.
_DUMMY_HASH = hash_password("requiem-nonexistent-user-timing-guard")

# API key names a user may store (the intel/cloud integrations).
ALLOWED_KEYS = (
    "VT_API_KEY",
    "MALWAREBAZAAR_API_KEY",
    "HYBRIDANALYSIS_API_KEY",
    "TRIAGE_TOKEN",
    "CAPE_URL",
    "CAPE_TOKEN",
)


@dataclass
class User:
    id: int
    email: str
    created_at: str


class Store:
    def __init__(self, db_path: Path | None = None):
        if db_path is None:
            # REQUIEM_DATA_DIR lets a hosted deploy point at a PERSISTENT disk
            # (e.g. Render disk mount) so users/keys survive restarts. Without
            # it, data lands in <repo>/data — fine for local, but note that on
            # ephemeral hosts (default Render) that dir is wiped on each deploy.
            data_dir = os.environ.get("REQUIEM_DATA_DIR")
            base = Path(data_dir) if data_dir else Path(__file__).resolve().parents[2] / "data"
            self.data_dir = base
            self.db_path = base / "requiem.db"
        else:
            self.data_dir = db_path.parent
            self.db_path = db_path
        self.data_dir.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()
        self.box = SecretBox(self.data_dir)
        self._init_db()
        self._restrict_permissions()

    def _restrict_permissions(self) -> None:
        """Best-effort 0600 on the DB (and its WAL/journal siblings) so the
        encrypted user data isn't world-readable. No-op where the OS ignores
        POSIX modes (e.g. Windows)."""
        for suffix in ("", "-wal", "-shm", "-journal"):
            p = Path(str(self.db_path) + suffix)
            if p.exists():
                try:
                    os.chmod(p, 0o600)
                except OSError:
                    pass
        try:
            os.chmod(self.data_dir, 0o700)
        except OSError:
            pass

    def _conn(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys = ON")
        return conn

    def _init_db(self) -> None:
        with self._lock, self._conn() as c:
            c.executescript(
                """
                CREATE TABLE IF NOT EXISTS users (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    email TEXT UNIQUE NOT NULL,
                    password_hash TEXT NOT NULL,
                    created_at TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS user_keys (
                    user_id INTEGER NOT NULL,
                    name TEXT NOT NULL,
                    value_encrypted TEXT NOT NULL,
                    PRIMARY KEY (user_id, name),
                    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
                );
                """
            )

    # --- users -----------------------------------------------------------
    def create_user(self, email: str, password: str) -> User:
        email = email.strip().lower()
        now = datetime.now(timezone.utc).isoformat()
        with self._lock, self._conn() as c:
            try:
                cur = c.execute(
                    "INSERT INTO users(email, password_hash, created_at) VALUES (?,?,?)",
                    (email, hash_password(password), now),
                )
            except sqlite3.IntegrityError:
                raise ValueError("email already registered")
            return User(id=cur.lastrowid, email=email, created_at=now)

    def authenticate(self, email: str, password: str) -> User | None:
        email = email.strip().lower()
        with self._conn() as c:
            row = c.execute("SELECT * FROM users WHERE email = ?", (email,)).fetchone()
        # Always perform a password hash, even when the user doesn't exist, so
        # response time doesn't reveal whether an email is registered
        # (defeats timing-based user enumeration).
        stored = row["password_hash"] if row else _DUMMY_HASH
        ok = verify_password(password, stored)
        if not row or not ok:
            return None
        return User(id=row["id"], email=row["email"], created_at=row["created_at"])

    def get_user(self, user_id: int) -> User | None:
        with self._conn() as c:
            row = c.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
        return User(id=row["id"], email=row["email"], created_at=row["created_at"]) if row else None

    # --- per-user API keys ----------------------------------------------
    def set_key(self, user_id: int, name: str, value: str) -> None:
        if name not in ALLOWED_KEYS:
            raise ValueError(f"unknown key '{name}'")
        if not value:
            self.delete_key(user_id, name)
            return
        # Bind the ciphertext to (user_id, name) so a row copied to another
        # user/slot fails to decrypt — defeats ciphertext-substitution if the DB
        # is ever write-compromised. (Fernet lacks AAD, so we prefix + verify.)
        enc = self.box.encrypt(self._bind(user_id, name, value))
        with self._lock, self._conn() as c:
            c.execute(
                "INSERT INTO user_keys(user_id, name, value_encrypted) VALUES (?,?,?) "
                "ON CONFLICT(user_id, name) DO UPDATE SET value_encrypted = excluded.value_encrypted",
                (user_id, name, enc),
            )

    @staticmethod
    def _bind(user_id: int, name: str, value: str) -> str:
        return f"{user_id}\x00{name}\x00{value}"

    def _unbind(self, user_id: int, name: str, blob: str | None) -> str | None:
        if blob is None:
            return None
        parts = blob.split("\x00", 2)
        if len(parts) != 3:
            return None
        uid, nm, value = parts
        if uid != str(user_id) or nm != name:
            return None  # ciphertext belongs to a different user/slot — reject
        return value

    def delete_key(self, user_id: int, name: str) -> None:
        with self._lock, self._conn() as c:
            c.execute("DELETE FROM user_keys WHERE user_id = ? AND name = ?", (user_id, name))

    def get_keys(self, user_id: int) -> dict[str, str]:
        """Decrypted key values for a user (used to drive lookups)."""
        with self._conn() as c:
            rows = c.execute(
                "SELECT name, value_encrypted FROM user_keys WHERE user_id = ?", (user_id,)
            ).fetchall()
        out: dict[str, str] = {}
        for r in rows:
            val = self._unbind(user_id, r["name"], self.box.decrypt(r["value_encrypted"]))
            if val:
                out[r["name"]] = val
        return out

    def key_status(self, user_id: int) -> dict[str, bool]:
        """Which keys are set (values never exposed)."""
        have = set(self.get_keys(user_id).keys())
        return {k: (k in have) for k in ALLOWED_KEYS}


_store: Store | None = None


def get_store() -> Store:
    global _store
    if _store is None:
        _store = Store()
    return _store
