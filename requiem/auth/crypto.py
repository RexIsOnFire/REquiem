"""Password hashing and per-user secret encryption.

- **Passwords** are hashed with ``scrypt`` (stdlib ``hashlib``) — memory-hard,
  no third-party dependency. Stored as ``scrypt$N$r$p$salt$hash`` (all b64).
- **User API keys** are encrypted at rest with Fernet (AES-128-CBC + HMAC) using
  a server key derived from ``REQUIEM_SECRET``. If the DB leaks, the keys are
  ciphertext, not plaintext.

Set ``REQUIEM_SECRET`` in the environment for a stable key across restarts. If
unset, a key is generated and persisted to ``<data_dir>/.secret`` so sessions
and stored keys survive restarts on a single host.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import os
import secrets
from pathlib import Path

from cryptography.fernet import Fernet, InvalidToken

_SCRYPT_N = 2 ** 15
_SCRYPT_R = 8
_SCRYPT_P = 1
_DKLEN = 32
# scrypt memory use is ~128*N*r bytes; give OpenSSL headroom above that.
_MAXMEM = 128 * _SCRYPT_N * _SCRYPT_R * 2


# --- passwords -----------------------------------------------------------
def hash_password(password: str) -> str:
    salt = secrets.token_bytes(16)
    dk = hashlib.scrypt(password.encode("utf-8"), salt=salt,
                        n=_SCRYPT_N, r=_SCRYPT_R, p=_SCRYPT_P, dklen=_DKLEN,
                        maxmem=_MAXMEM)
    b64 = base64.b64encode
    return (f"scrypt${_SCRYPT_N}${_SCRYPT_R}${_SCRYPT_P}$"
            f"{b64(salt).decode()}${b64(dk).decode()}")


def verify_password(password: str, stored: str) -> bool:
    try:
        scheme, n, r, p, salt_b64, hash_b64 = stored.split("$")
        if scheme != "scrypt":
            return False
        salt = base64.b64decode(salt_b64)
        expected = base64.b64decode(hash_b64)
        n_i, r_i, p_i = int(n), int(r), int(p)
        dk = hashlib.scrypt(password.encode("utf-8"), salt=salt,
                            n=n_i, r=r_i, p=p_i, dklen=len(expected),
                            maxmem=128 * n_i * r_i * 2)
        return hmac.compare_digest(dk, expected)
    except (ValueError, TypeError):
        return False


# --- server secret / key encryption -------------------------------------
def _server_secret(data_dir: Path) -> bytes:
    env = os.environ.get("REQUIEM_SECRET")
    if env:
        return hashlib.sha256(env.encode("utf-8")).digest()
    # Persist a generated secret so tokens/keys survive restarts.
    secret_file = data_dir / ".secret"
    if secret_file.exists():
        return secret_file.read_bytes()[:32].ljust(32, b"\0")
    data_dir.mkdir(parents=True, exist_ok=True)
    secret = secrets.token_bytes(32)
    secret_file.write_bytes(secret)
    try:
        os.chmod(secret_file, 0o600)
    except OSError:
        pass
    return secret


class SecretBox:
    """Fernet-based encrypt/decrypt for user API keys."""

    def __init__(self, data_dir: Path):
        raw = _server_secret(data_dir)
        self._fernet = Fernet(base64.urlsafe_b64encode(raw))

    def encrypt(self, plaintext: str) -> str:
        return self._fernet.encrypt(plaintext.encode("utf-8")).decode("ascii")

    def decrypt(self, token: str) -> str | None:
        try:
            return self._fernet.decrypt(token.encode("ascii")).decode("utf-8")
        except (InvalidToken, ValueError):
            return None

    def jwt_secret(self) -> bytes:
        # A distinct sub-key for signing JWTs (domain-separated from Fernet).
        return hashlib.sha256(self._fernet._signing_key + b"jwt").digest()
