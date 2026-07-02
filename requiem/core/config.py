"""Zero-dependency ``.env`` loader.

ReQuiem reads all secrets (VirusTotal / MalwareBazaar keys, CAPE URL+token)
from environment variables. To avoid making users export them by hand every
session, we load a ``.env`` file at import time — searching the current working
directory and walking up to the project root.

Design choices:
- **Never overrides** an already-set environment variable, so an explicit
  ``$env:VT_API_KEY=...`` still wins over the file.
- Pure standard library; supports ``KEY=value``, ``export KEY=value``, ``#``
  comments, blank lines, and single/double-quoted values.
- Silent and safe: a missing or malformed file is simply ignored.
"""
from __future__ import annotations

import os
from pathlib import Path

_LOADED = False

# Keys ReQuiem actually consumes — documented here so `.env.example` and the
# loader stay in sync.
KNOWN_KEYS = (
    "VT_API_KEY",
    "MALWAREBAZAAR_API_KEY",
    "CAPE_URL",
    "CAPE_TOKEN",
    "CUCKOO_URL",
    "CUCKOO_TOKEN",
    "JOE_URL",
    "JOE_APIKEY",
    "TRIAGE_URL",
    "TRIAGE_TOKEN",
)


def _parse_line(line: str) -> tuple[str, str] | None:
    line = line.strip()
    if not line or line.startswith("#"):
        return None
    if line.startswith("export "):
        line = line[len("export "):].lstrip()
    if "=" not in line:
        return None
    key, _, value = line.partition("=")
    key = key.strip()
    value = value.strip()
    # Strip surrounding matching quotes.
    if len(value) >= 2 and value[0] == value[-1] and value[0] in ("'", '"'):
        value = value[1:-1]
    if not key:
        return None
    return key, value


def find_dotenv(start: Path | None = None) -> Path | None:
    """Locate a ``.env`` from ``start`` (or CWD) walking up to the filesystem root."""
    # An explicit override wins.
    override = os.environ.get("REQUIEM_DOTENV")
    if override:
        p = Path(override)
        return p if p.is_file() else None

    here = (start or Path.cwd()).resolve()
    for directory in (here, *here.parents):
        candidate = directory / ".env"
        if candidate.is_file():
            return candidate
    return None


def load_dotenv(path: Path | None = None, *, override: bool = False) -> dict[str, str]:
    """Load ``path`` (or the nearest ``.env``) into ``os.environ``.

    Returns the mapping that was applied. Existing environment variables are
    preserved unless ``override`` is True.
    """
    path = path or find_dotenv()
    applied: dict[str, str] = {}
    if not path or not path.is_file():
        return applied
    try:
        text = path.read_text(encoding="utf-8")
    except OSError:
        return applied
    # Keys already present in the real environment before we started — these
    # are the only ones we must not clobber (an explicit export wins over the
    # file). Within the file itself, a later line overrides an earlier one.
    preexisting = set(os.environ) if not override else set()
    for raw in text.splitlines():
        parsed = _parse_line(raw)
        if not parsed:
            continue
        key, value = parsed
        if key in preexisting:
            continue
        os.environ[key] = value
        applied[key] = value
    return applied


def ensure_loaded() -> None:
    """Idempotent: load the ``.env`` exactly once per process."""
    global _LOADED
    if _LOADED:
        return
    _LOADED = True
    load_dotenv()


def configured_status() -> dict[str, bool]:
    """Which known keys are currently set (value hidden). For diagnostics."""
    return {k: bool(os.environ.get(k)) for k in KNOWN_KEYS}
