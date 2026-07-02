"""YARA scanning with family-level metadata — optional, degrades gracefully.

Rules are loaded from the package ``rules/`` directory. Beyond a boolean match,
we harvest each matched rule's ``meta:`` block (family, malware type, ATT&CK
techniques, severity) so the inference stage can turn a family hit into an
explainable finding and a classification. If ``yara-python`` isn't installed or
compilation fails, we return an empty match set with a note.
"""
from __future__ import annotations

import os
from dataclasses import dataclass, field

from ..core.models import YaraMatch

try:
    import yara  # type: ignore

    _HAVE_YARA = True
except Exception:  # pragma: no cover
    _HAVE_YARA = False


@dataclass
class YaraResult:
    available: bool
    matches: list[YaraMatch] = field(default_factory=list)
    note: str = ""


def _default_rules_dir() -> str:
    here = os.path.dirname(os.path.abspath(__file__))
    return os.path.normpath(os.path.join(here, "..", "..", "rules"))


def _as_list(value) -> list[str]:
    if not value:
        return []
    if isinstance(value, (list, tuple)):
        return [str(v) for v in value]
    # meta values are strings; split comma/space-separated technique lists.
    return [p.strip() for p in str(value).replace(",", " ").split() if p.strip()]


def _to_match(m) -> YaraMatch:
    meta = getattr(m, "meta", {}) or {}
    # yara-python exposes matched strings as (offset, identifier, data) tuples
    # (classic API) or objects with .identifier (newer API). Handle both.
    ids: list[str] = []
    for s in getattr(m, "strings", []) or []:
        ident = getattr(s, "identifier", None)
        if ident is None and isinstance(s, (list, tuple)) and len(s) >= 2:
            ident = s[1]
        if ident:
            ids.append(str(ident))
    attack = _as_list(meta.get("attack") or meta.get("mitre") or meta.get("ttp"))
    return YaraMatch(
        rule=m.rule,
        family=meta.get("family") or None,
        malware_type=(meta.get("malware_type") or meta.get("type") or None),
        description=str(meta.get("description", "")),
        severity=str(meta.get("severity", "medium")).lower(),
        attack=attack,
        tags=list(getattr(m, "tags", []) or []),
        matched_strings=sorted(set(ids))[:12],
    )


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
        return YaraResult(available=True, matches=[_to_match(m) for m in matches])
    except Exception as exc:  # pragma: no cover
        return YaraResult(available=True, note=f"yara error: {exc}")
