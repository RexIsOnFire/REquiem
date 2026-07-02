"""Behavioral inference: signals -> ATT&CK techniques, findings, verdict.

This is the reasoning layer. It runs a set of *rules* over everything the
static and dynamic stages gathered. Each rule that fires produces a
:class:`Finding` (with evidence) and may assert one or more ATT&CK techniques.
Finally it weighs the findings into a verdict + malware classification and
writes the plain-English explanation that makes ReQuiem feel like an analyst
rather than a checkbox.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Callable

from ..core.models import (
    AnalysisReport,
    AttackTechnique,
    Confidence,
    Evidence,
    Finding,
    Severity,
)
from . import techniques


@dataclass
class _Ctx:
    """Flattened, lowercased view of the report for cheap rule matching."""

    report: AnalysisReport
    imports: str        # newline-joined, lowercased
    strings: str        # newline-joined, lowercased
    section_names: str

    def has_import(self, *names: str) -> str | None:
        for n in names:
            if n.lower() in self.imports:
                return n
        return None

    def has_string(self, pattern: str) -> re.Match | None:
        return re.search(pattern, self.strings, re.I)


# A rule inspects the context and, if it fires, appends findings and returns
# the technique IDs it asserts (with the evidence that justified them).
Rule = Callable[[_Ctx], list[Finding]]

_RULES: list[Rule] = []


def rule(fn: Rule) -> Rule:
    _RULES.append(fn)
    return fn


def _finding(title, desc, conf, sev, techniques_ids, *evidence) -> Finding:
    f = Finding(title=title, description=desc, confidence=conf, severity=sev,
                attack_techniques=list(techniques_ids))
    for e in evidence:
        f.evidence.append(Evidence(detail=e, source="inference"))
    return f


# --- rules ---------------------------------------------------------------
@rule
def _r_run_key(ctx: _Ctx) -> list[Finding]:
    if ctx.has_string(r"currentversion\\run") or ctx.has_import("RegSetValueEx"):
        return [_finding(
            "Registry Run-key persistence",
            "References the CurrentVersion\\Run key, used to auto-start on logon.",
            Confidence.MEDIUM, Severity.MEDIUM, ["T1547.001"],
            "Run-key path / RegSetValueEx present")]
    return []


@rule
def _r_scheduled_task(ctx: _Ctx) -> list[Finding]:
    if ctx.has_string(r"schtasks|taskschd|\\microsoft\\windows\\") or \
            ctx.has_import("ITaskService"):
        return [_finding(
            "Scheduled task persistence",
            "Uses the Task Scheduler to establish persistence or delayed execution.",
            Confidence.MEDIUM, Severity.MEDIUM, ["T1053.005"],
            "schtasks / Task Scheduler references")]
    return []


@rule
def _r_service(ctx: _Ctx) -> list[Finding]:
    if ctx.has_import("CreateServiceA", "CreateServiceW", "OpenSCManagerW"):
        return [_finding(
            "Windows service installation",
            "Creates or manages a Windows service — a persistence and privilege vector.",
            Confidence.MEDIUM, Severity.MEDIUM, ["T1543.003"],
            "Service Control Manager APIs imported")]
    return []


@rule
def _r_powershell(ctx: _Ctx) -> list[Finding]:
    if ctx.has_string(r"powershell|-encodedcommand|iex\(|invoke-expression"):
        return [_finding(
            "PowerShell execution",
            "Invokes PowerShell, frequently with encoded commands, to run payloads.",
            Confidence.MEDIUM, Severity.MEDIUM, ["T1059.001"],
            "PowerShell / -EncodedCommand strings")]
    return []


@rule
def _r_injection(ctx: _Ctx) -> list[Finding]:
    hit = ctx.has_import("VirtualAllocEx", "WriteProcessMemory", "CreateRemoteThread",
                         "NtMapViewOfSection", "QueueUserAPC")
    if hit:
        return [_finding(
            "Process injection capability",
            "Imports the classic allocate/write/execute-in-remote-process API set.",
            Confidence.HIGH, Severity.HIGH, ["T1055"],
            f"{hit} imported")]
    return []


@rule
def _r_lsass(ctx: _Ctx) -> list[Finding]:
    if ctx.has_string(r"\blsass\b|minidumpwritedump|sekurlsa"):
        return [_finding(
            "LSASS credential access",
            "References LSASS memory / MiniDumpWriteDump — credential-dumping behavior.",
            Confidence.HIGH, Severity.HIGH, ["T1003.001"],
            "LSASS / MiniDumpWriteDump indicators")]
    return []


@rule
def _r_c2(ctx: _Ctx) -> list[Finding]:
    net = ctx.has_import("WSAStartup", "InternetOpenW", "HttpSendRequestW",
                         "WinHttpConnect", "socket", "connect")
    if net and (ctx.report.iocs.urls or ctx.report.iocs.domains or ctx.report.iocs.ipv4):
        return [_finding(
            "Network / C2 communication",
            "Combines networking APIs with embedded URLs/hosts — likely C2 or download.",
            Confidence.MEDIUM, Severity.MEDIUM, ["T1071.001", "T1105"],
            f"{net} + embedded network IOCs")]
    return []


@rule
def _r_anti_analysis(ctx: _Ctx) -> list[Finding]:
    if ctx.has_import("IsDebuggerPresent", "CheckRemoteDebuggerPresent") or \
            ctx.has_string(r"vmware|virtualbox|sandboxie|\bsbie\b"):
        return [_finding(
            "Anti-analysis / sandbox evasion",
            "Checks for debuggers or virtualization artifacts to evade analysis.",
            Confidence.MEDIUM, Severity.MEDIUM, ["T1497", "T1562.001"],
            "Debugger/VM detection indicators")]
    return []


@rule
def _r_crypto(ctx: _Ctx) -> list[Finding]:
    if ctx.has_import("CryptEncrypt", "BCryptEncrypt", "CryptGenKey") or \
            ctx.has_string(r"\baes\b|\brsa\b|chacha20|salsa20"):
        return [_finding(
            "Cryptographic routines",
            "Uses cryptographic APIs/primitives — relevant to ransomware and secure C2.",
            Confidence.MEDIUM, Severity.MEDIUM, ["T1027"],
            "Crypto API/primitive references")]
    return []


@rule
def _r_shadow_copies(ctx: _Ctx) -> list[Finding]:
    if ctx.has_string(r"vssadmin|shadowcopy|wbadmin|bcdedit|delete shadows"):
        return [_finding(
            "Inhibit system recovery",
            "Deletes shadow copies / disables recovery — a hallmark ransomware behavior.",
            Confidence.HIGH, Severity.HIGH, ["T1490"],
            "vssadmin / bcdedit / shadow-copy deletion strings")]
    return []


@rule
def _r_ransom_note(ctx: _Ctx) -> list[Finding]:
    if ctx.has_string(r"files? (have|has) been encrypted|recover your files|"
                      r"decrypt(or|ion)?|ransom|\.onion") and ctx.report.iocs.bitcoin:
        return [_finding(
            "Ransom-note / extortion content",
            "Contains extortion phrasing plus a cryptocurrency address for payment.",
            Confidence.HIGH, Severity.CRITICAL, ["T1486"],
            "Ransom phrasing + Bitcoin address")]
    return []


def _build_context(report: AnalysisReport) -> _Ctx:
    imports = "\n".join(report.imports).lower()
    strings = "\n".join(report.strings_of_interest + _ioc_flat(report)).lower()
    section_names = "\n".join(s.name for s in report.sections).lower()
    return _Ctx(report=report, imports=imports, strings=strings, section_names=section_names)


def _ioc_flat(report: AnalysisReport) -> list[str]:
    i = report.iocs
    return i.urls + i.domains + i.registry_keys + i.file_paths + i.mutexes


def run_inference(report: AnalysisReport) -> None:
    """Enrich ``report`` in place with findings, ATT&CK techniques, and verdict."""
    ctx = _build_context(report)

    # 1. Fire static rules.
    for r in _RULES:
        report.findings.extend(r(ctx))

    # 2. Fold in dynamic/memory findings (already Finding objects).
    report.findings.extend(report.dynamic.memory)

    # 3. Packer -> software-packing technique.
    if report.packers:
        f = _finding(
            "Executable is packed/obfuscated",
            "A packer or high-entropy obfuscation was detected, hindering static analysis.",
            Confidence.HIGH, Severity.MEDIUM, ["T1027.002"],
            *[f"{p.name} ({p.confidence.name})" for p in report.packers])
        report.findings.append(f)

    # 3.5 YARA family matches -> high-confidence findings.
    report.findings.extend(_yara_findings(report))

    # 4. Aggregate ATT&CK techniques from all findings.
    _aggregate_attack(report)

    # 5. Verdict + classification + summary.
    _verdict(report)


_YARA_SEVERITY = {
    "info": Severity.INFO, "low": Severity.LOW, "medium": Severity.MEDIUM,
    "high": Severity.HIGH, "critical": Severity.CRITICAL,
}


def _yara_findings(report: AnalysisReport) -> list[Finding]:
    out: list[Finding] = []
    for m in report.yara_matches:
        sev = _YARA_SEVERITY.get(m.severity, Severity.MEDIUM)
        title = f"YARA family match: {m.family}" if m.family else f"YARA rule: {m.rule}"
        desc = m.description or f"Matched YARA rule {m.rule}."
        f = Finding(title=title, description=desc,
                    confidence=Confidence.HIGH, severity=sev,
                    attack_techniques=list(m.attack),
                    tags=["yara"] + ([m.malware_type] if m.malware_type else []))
        f.evidence.append(Evidence(detail=f"rule '{m.rule}' matched", source="yara"))
        if m.matched_strings:
            f.evidence.append(Evidence(
                detail="matched: " + ", ".join(m.matched_strings[:8]), source="yara"))
        out.append(f)
    return out


def _yara_classification(report: AnalysisReport) -> str | None:
    """Strongest malware_type asserted by a matched family rule, if any."""
    # Prefer a concrete family's type; ransomware/stealer over generic.
    priority = {"ransomware": 4, "infostealer": 3, "rat": 3, "loader": 2}
    best, best_rank = None, -1
    for m in report.yara_matches:
        t = m.malware_type
        if t and priority.get(t, 1) > best_rank:
            best, best_rank = t, priority.get(t, 1)
    return best


def _aggregate_attack(report: AnalysisReport) -> None:
    best: dict[str, AttackTechnique] = {}
    for f in report.findings:
        for tid in f.attack_techniques:
            name, tactic = techniques.resolve(tid)
            at = best.get(tid)
            if at is None:
                at = AttackTechnique(technique_id=tid, name=name, tactic=tactic,
                                     confidence=f.confidence)
                best[tid] = at
            at.confidence = max(at.confidence, f.confidence)
            at.evidence.append(Evidence(detail=f.title, source="inference"))
    report.attack = sorted(best.values(),
                           key=lambda a: (techniques.TACTIC_ORDER.index(a.tactic)
                                          if a.tactic in techniques.TACTIC_ORDER else 99,
                                          a.technique_id))


# Findings whose presence strongly implies a family classification.
_RANSOM_MARKERS = {"Ransom-note / extortion content", "Inhibit system recovery",
                   "File-encryption loop confirmed", "Large heap allocations + AES routines"}
_STEALER_MARKERS = {"LSASS credential access"}


def _verdict(report: AnalysisReport) -> None:
    score = 0
    crit = high = 0
    titles = {f.title for f in report.findings}
    for f in report.findings:
        weight = {Severity.INFO: 0, Severity.LOW: 1, Severity.MEDIUM: 3,
                  Severity.HIGH: 6, Severity.CRITICAL: 10}[f.severity]
        # Discount low-confidence findings.
        weight = weight * (f.confidence.value / 100.0)
        score += weight
        crit += f.severity == Severity.CRITICAL
        high += f.severity == Severity.HIGH

    # External intel is a strong prior.
    if any(i.known for i in report.intel):
        score += 8

    if score >= 18 or crit >= 1:
        report.verdict, report.verdict_confidence = "malicious", Confidence.HIGH
    elif score >= 8 or high >= 1:
        report.verdict, report.verdict_confidence = "suspicious", Confidence.MEDIUM
    elif score > 0:
        report.verdict, report.verdict_confidence = "suspicious", Confidence.LOW
    else:
        report.verdict, report.verdict_confidence = "benign", Confidence.LOW

    # Classification — a named YARA family is the strongest signal and wins.
    yara_type = _yara_classification(report)
    _TYPE_LABEL = {"ransomware": "ransomware", "infostealer": "credential-stealer",
                   "rat": "backdoor/RAT", "loader": "loader"}
    if yara_type:
        report.classification = _TYPE_LABEL.get(yara_type, yara_type)
        # A concrete family match also floors the verdict at malicious.
        report.verdict = "malicious"
        report.verdict_confidence = max(report.verdict_confidence, Confidence.HIGH)
    elif titles & _RANSOM_MARKERS:
        report.classification = "ransomware"
    elif titles & _STEALER_MARKERS:
        report.classification = "credential-stealer"
    elif "Network / C2 communication" in titles and "Process injection capability" in titles:
        report.classification = "backdoor/RAT"

    report.summary = _explain(report)


def _explain(report: AnalysisReport) -> str:
    """The star feature: say *why*, then point at the evidence."""
    lang = report.languages[0].language if report.languages else "unknown"
    parts: list[str] = []

    verdict_phrase = {
        "malicious": "assessed **malicious**",
        "suspicious": "assessed **suspicious**",
        "benign": "shows **no strong malicious indicators**",
        "unknown": "could not be conclusively assessed",
    }[report.verdict]
    subject = f"This {report.identity.format.upper()} sample"
    if report.classification:
        parts.append(f"{subject} is {verdict_phrase} and classified as "
                     f"**{report.classification}**.")
    else:
        parts.append(f"{subject} is {verdict_phrase}.")

    if lang != "unknown":
        parts.append(f"It appears to be written in **{lang}**"
                     + (f" ({report.languages[0].compiler})."
                        if report.languages[0].compiler else "."))

    if report.packers:
        parts.append(f"It is packed/obfuscated ({report.packers[0].name}), "
                     "which impedes static inspection.")

    # Lead with the highest-severity findings as the justification.
    top = sorted(report.findings, key=lambda f: (f.severity, f.confidence), reverse=True)[:4]
    if top:
        reasons = "; ".join(f.title.lower() for f in top)
        parts.append(f"Key evidence: {reasons}.")

    if report.attack:
        tactics = sorted({a.tactic for a in report.attack},
                         key=lambda t: techniques.TACTIC_ORDER.index(t)
                         if t in techniques.TACTIC_ORDER else 99)
        parts.append(f"Mapped to {len(report.attack)} ATT&CK techniques across "
                     f"{len(tactics)} tactics ({', '.join(tactics)}).")

    return " ".join(parts)
