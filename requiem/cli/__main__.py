"""ReQuiem command-line interface.

Examples::

    python -m requiem.cli analyze sample.exe                 # console report
    python -m requiem.cli analyze sample.exe --html out.html # + HTML report
    python -m requiem.cli analyze sample.exe --json out.json # + machine JSON
    python -m requiem.cli analyze sample.exe --intel         # online hash lookup
    python -m requiem.cli hash <sha256>                      # intel lookup only

By design, ``hash`` performs metadata lookups only — it never downloads binaries.
"""
from __future__ import annotations

import argparse
import json
import sys

from ..core.models import Confidence, Severity
from ..core.pipeline import PipelineOptions, analyze
from ..intel.base import gather_intel
from ..intel.providers import default_providers
from ..report import html

# ANSI helpers (no-op if not a tty).
def _c(code: str, s: str) -> str:
    return s if not sys.stdout.isatty() else f"\033[{code}m{s}\033[0m"

_VERDICT_STYLE = {
    "malicious": "1;31", "suspicious": "1;33", "benign": "1;32", "unknown": "1;37",
}
_SEV_STYLE = {
    Severity.CRITICAL: "1;31", Severity.HIGH: "31", Severity.MEDIUM: "33",
    Severity.LOW: "36", Severity.INFO: "37",
}


def _print_console(report) -> None:
    ident = report.identity
    print("\n" + "═" * 68)
    print(f"  ReQuiem · {ident.filename}")
    print("═" * 68)
    v = report.verdict.upper()
    print(f"  Verdict     : {_c(_VERDICT_STYLE.get(report.verdict,'37'), v)}"
          f"  ({report.verdict_confidence.name})")
    if report.classification:
        print(f"  Class       : {_c('1;35', report.classification)}")
    print(f"  Format      : {ident.format.upper()} {ident.arch}/{ident.bitness}-bit"
          f"  · {ident.size:,} bytes")
    if report.languages and report.languages[0].language != "unknown":
        lg = report.languages[0]
        comp = f" ({lg.compiler})" if lg.compiler else ""
        print(f"  Language    : {_c('1;36', lg.language)}{comp}  [{lg.confidence.name}]")
    if report.packers:
        print(f"  Packer      : {report.packers[0].name}")
    print(f"  SHA256      : {ident.sha256}")
    print(f"  Avg entropy : {report.overall_entropy:.2f}   Imports: {len(report.imports)}")

    print("\n  " + _c("1", "Summary"))
    for line in _wrap(report.summary.replace("**", ""), 64):
        print("    " + line)

    if report.findings:
        print("\n  " + _c("1", "Findings"))
        for f in sorted(report.findings, key=lambda f: (f.severity, f.confidence), reverse=True):
            tag = _c(_SEV_STYLE[f.severity], f"[{f.severity.name}]")
            techs = (" " + ",".join(f.attack_techniques)) if f.attack_techniques else ""
            print(f"    {tag} {f.title}{_c('36', techs)}  ({f.confidence.name})")

    if report.attack:
        print("\n  " + _c("1", "ATT&CK"))
        by_tactic: dict[str, list[str]] = {}
        for at in report.attack:
            by_tactic.setdefault(at.tactic, []).append(f"{at.technique_id}")
        for tactic, ids in by_tactic.items():
            print(f"    {tactic:<20} {', '.join(ids)}")

    i = report.iocs
    ioc_counts = [(n, len(v)) for n, v in (
        ("urls", i.urls), ("domains", i.domains), ("ips", i.ipv4),
        ("regkeys", i.registry_keys), ("btc", i.bitcoin)) if v]
    if ioc_counts:
        print("\n  " + _c("1", "IOCs") + "   " +
              "  ".join(f"{n}:{c}" for n, c in ioc_counts))
    if report.dynamic.executed:
        badge = "simulated" if report.dynamic.simulated else "live"
        print(f"\n  Dynamic: {badge} [{report.dynamic.backend}] · "
              f"{len(report.dynamic.memory)} memory findings · "
              f"{len(report.dynamic.memory_map)} regions")
    print("═" * 68 + "\n")


def _wrap(text: str, width: int) -> list[str]:
    words, lines, cur = text.split(), [], ""
    for w in words:
        if len(cur) + len(w) + 1 > width:
            lines.append(cur)
            cur = w
        else:
            cur = f"{cur} {w}".strip()
    if cur:
        lines.append(cur)
    return lines


def _cmd_analyze(args) -> int:
    try:
        with open(args.file, "rb") as fh:
            data = fh.read()
    except OSError as e:
        print(f"error: cannot read {args.file}: {e}", file=sys.stderr)
        return 2

    opts = PipelineOptions(
        run_intel=args.intel,
        offline_intel=not args.intel,
        run_dynamic=not args.no_dynamic,
        run_yara=not args.no_yara,
        sandbox=args.sandbox,
    )
    import os
    report = analyze(data, os.path.basename(args.file), opts)

    if not args.quiet:
        _print_console(report)
    if args.json:
        with open(args.json, "w", encoding="utf-8") as fh:
            json.dump(report.to_dict(), fh, indent=2)
        print(f"  JSON  -> {args.json}")
    if args.html:
        with open(args.html, "w", encoding="utf-8") as fh:
            fh.write(html.render(report))
        print(f"  HTML  -> {args.html}")
    if args.pdf:
        from ..report import pdf as pdf_report
        try:
            data_pdf = pdf_report.render_pdf(report)
        except pdf_report.PDFUnavailable as e:
            print(f"  PDF   -> skipped: {e}", file=sys.stderr)
            # Graceful fallback: write the print-ready HTML alongside.
            fallback = args.pdf.rsplit(".", 1)[0] + ".print.html"
            with open(fallback, "w", encoding="utf-8") as fh:
                fh.write(html.render(report))
            print(f"  HTML  -> {fallback}  (open and 'Save as PDF')")
            return 3
        with open(args.pdf, "wb") as fh:
            fh.write(data_pdf)
        print(f"  PDF   -> {args.pdf}  ({pdf_report.available_backend()})")
    return 0


def _cmd_hash(args) -> int:
    providers = default_providers(offline=not args.online)
    results = gather_intel(providers, sha256=args.hash, md5=None, sha1=None)
    for r in results:
        status = "KNOWN" if r.known else "unknown"
        print(f"  {r.source:<15} {status:<8} {r.family or '-':<20} {r.detail or ''}")
    print("\n  Note: ReQuiem performs metadata lookups only; it does not download samples.")
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="requiem", description="ReQuiem malware analysis workbench")
    sub = p.add_subparsers(dest="cmd", required=True)

    a = sub.add_parser("analyze", help="analyze a local sample file")
    a.add_argument("file")
    a.add_argument("--html", metavar="PATH", help="write HTML report")
    a.add_argument("--pdf", metavar="PATH", help="write PDF report (needs weasyprint or playwright)")
    a.add_argument("--json", metavar="PATH", help="write JSON report")
    a.add_argument("--intel", action="store_true", help="perform online hash-reputation lookup")
    a.add_argument("--sandbox", choices=["simulated", "cape"], default="simulated",
                   help="dynamic backend: 'simulated' (default) or 'cape' (needs CAPE_URL). "
                        "CAPE falls back to simulated if unreachable.")
    a.add_argument("--no-dynamic", action="store_true", help="skip the dynamic stage")
    a.add_argument("--no-yara", action="store_true", help="skip YARA scanning")
    a.add_argument("--quiet", action="store_true", help="suppress console report")
    a.set_defaults(func=_cmd_analyze)

    h = sub.add_parser("hash", help="look up a hash's reputation (metadata only)")
    h.add_argument("hash")
    h.add_argument("--online", action="store_true", help="query live intel providers")
    h.set_defaults(func=_cmd_hash)
    return p


def _force_utf8_stdio() -> None:
    """Avoid UnicodeEncodeError when console output (box chars, ·, ⚠) is written
    to a non-UTF-8 stream — notably a redirected file under Windows cp1252."""
    for stream in (sys.stdout, sys.stderr):
        reconfigure = getattr(stream, "reconfigure", None)
        if reconfigure:
            try:
                reconfigure(encoding="utf-8", errors="replace")
            except (ValueError, OSError):
                pass


def main(argv=None) -> int:
    _force_utf8_stdio()
    args = build_parser().parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
