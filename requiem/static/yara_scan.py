"""YARA scanning — optional, degrades gracefully.

If ``yara-python`` isn't installed (or rule compilation fails), we return an
empty match set and record why, rather than breaking the pipeline. Rules are
loaded from the package ``rules/`` directory.
"""
from __future__ import annotations

import os
from dataclasses import dataclass, field

try:
    import yara  # type: ignore

    _HAVE_YARA = True
except Exception:  # pragma: no cover
    _HAVE_YARA = False


@dataclass
class YaraResult:
    available: bool
    matches: list[str] = field(default_factory=list)
    note: str = ""


def _default_rules_dir() -> str:
    # requiem/static/yara_scan.py -> repo_root/rules
    here = os.path.dirname(os.path.abspath(__file__))
    return os.path.normpath(os.path.join(here, "..", "..", "rules"))


def scan(data: bytes, rules_dir: str | None = None) -> YaraResult:
    if not _HAVE_YARA:
        return YaraResult(available=False, note="yara-python not installed; skipped")

    rules_dir = rules_dir or _default_rules_dir()
    if not os.path.isdir(rules_dir):
        return YaraResult(available=True, note=f"no rules directory at {rules_dir}")

    filepaths = {}
    for root, _dirs, files in os.walk(rules_dir):
        for f in files:
            if f.endswith((".yar", ".yara")):
                ns = os.path.splitext(f)[0]
                filepaths[ns] = os.path.join(root, f)
    if not filepaths:
        return YaraResult(available=True, note="no .yar rules found")

    try:
        rules = yara.compile(filepaths=filepaths)
        matches = rules.match(data=data)
        return YaraResult(available=True, matches=[m.rule for m in matches])
    except Exception as exc:  # pragma: no cover
        return YaraResult(available=True, note=f"yara error: {exc}")
