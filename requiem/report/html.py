"""Self-contained HTML report generator.

Renders an :class:`AnalysisReport` into a single standalone HTML file — no
external assets, so it opens anywhere and can be attached to a ticket. Includes
the executive summary, verdict banner, language/packer cards, entropy bars, an
ATT&CK heatmap, IOC tables, and the explainable findings list with evidence.
"""
from __future__ import annotations

import html

from ..attack import techniques
from ..core.models import AnalysisReport, Confidence, Severity

_SEV_COLOR = {
    Severity.INFO: "#5b6472", Severity.LOW: "#3b82f6", Severity.MEDIUM: "#eab308",
    Severity.HIGH: "#f97316", Severity.CRITICAL: "#ef4444",
}
_VERDICT_COLOR = {
    "malicious": "#ef4444", "suspicious": "#eab308",
    "benign": "#22c55e", "unknown": "#6b7280",
}


def _e(s) -> str:
    return html.escape(str(s), quote=True)


def _conf_badge(c: Confidence) -> str:
    return f'<span class="badge">{c.name} {int(c.value)}%</span>'


def _entropy_bar(entropy: float) -> str:
    pct = min(100, int(entropy / 8 * 100))
    color = "#ef4444" if entropy >= 7.2 else "#eab308" if entropy >= 6 else "#22c55e"
    return (f'<div class="bar"><div class="fill" style="width:{pct}%;background:{color}">'
            f'</div></div><span class="mono">{entropy:.2f}</span>')


def _heatmap(report: AnalysisReport) -> str:
    by_tactic: dict[str, list] = {}
    for at in report.attack:
        by_tactic.setdefault(at.tactic, []).append(at)
    cols = [t for t in techniques.TACTIC_ORDER if t in by_tactic]
    # Include any non-standard tactics at the end.
    cols += [t for t in by_tactic if t not in techniques.TACTIC_ORDER]
    if not cols:
        return '<p class="muted">No ATT&CK techniques inferred.</p>'

    max_rows = max(len(by_tactic[c]) for c in cols)
    head = "".join(f"<th>{_e(c)}</th>" for c in cols)
    rows = []
    for r in range(max_rows):
        cells = []
        for c in cols:
            items = by_tactic[c]
            if r < len(items):
                at = items[r]
                shade = {Confidence.HIGH: "#7f1d1d", Confidence.MEDIUM: "#9a3412",
                         Confidence.CERTAIN: "#7f1d1d"}.get(at.confidence, "#374151")
                cells.append(
                    f'<td class="tech" style="background:{shade}" '
                    f'title="{_e(at.name)} ({_e(at.confidence.name)})">'
                    f'<b>{_e(at.technique_id)}</b><br><span>{_e(at.name)}</span></td>')
            else:
                cells.append('<td class="empty"></td>')
        rows.append("<tr>" + "".join(cells) + "</tr>")
    return (f'<div class="scroll"><table class="heat"><thead><tr>{head}</tr></thead>'
            f'<tbody>{"".join(rows)}</tbody></table></div>')


def _findings(report: AnalysisReport) -> str:
    if not report.findings:
        return '<p class="muted">No behavioral findings.</p>'
    ordered = sorted(report.findings, key=lambda f: (f.severity, f.confidence), reverse=True)
    out = []
    for f in ordered:
        color = _SEV_COLOR[f.severity]
        ev = "".join(f'<li>{_e(e.detail)}'
                     + (f' <span class="loc">[{_e(e.locator)}]</span>' if e.locator else "")
                     + "</li>" for e in f.evidence)
        techs = " ".join(f'<span class="pill">{_e(t)}</span>' for t in f.attack_techniques)
        out.append(
            f'<div class="finding" style="border-left-color:{color}">'
            f'<div class="fhead"><span class="sev" style="background:{color}">'
            f'{f.severity.name}</span> <b>{_e(f.title)}</b> {_conf_badge(f.confidence)}</div>'
            f'<p>{_e(f.description)}</p>'
            f'{f"<ul class=evidence>{ev}</ul>" if ev else ""}'
            f'{f"<div class=techs>{techs}</div>" if techs else ""}</div>')
    return "".join(out)


def _ioc_section(report: AnalysisReport) -> str:
    i = report.iocs
    groups = [
        ("URLs", i.urls), ("Domains", i.domains), ("IPv4", i.ipv4),
        ("Registry keys", i.registry_keys), ("Mutexes", i.mutexes),
        ("Bitcoin", i.bitcoin), ("File paths", i.file_paths[:40]),
    ]
    blocks = []
    for name, vals in groups:
        if not vals:
            continue
        rows = "".join(f"<li class=mono>{_e(v)}</li>" for v in vals[:60])
        blocks.append(f'<div class="ioc-group"><h4>{_e(name)} '
                      f'<span class="count">{len(vals)}</span></h4><ul>{rows}</ul></div>')
    return "".join(blocks) or '<p class="muted">No IOCs extracted.</p>'


def _process_tree(nodes: list, depth: int = 0) -> str:
    out = []
    for n in nodes:
        pad = "&nbsp;" * (depth * 4)
        out.append(f'<div class="proc">{pad}└ <b>{_e(n.get("name"))}</b> '
                   f'<span class="mono muted">{_e(n.get("cmdline",""))}</span></div>')
        out.append(_process_tree(n.get("children", []), depth + 1))
    return "".join(out)


_KIND_COLOR = {
    "image": "#3987e5", "mapped": "#199e70", "stack": "#c98500",
    "private": "#9085e9", "heap": "#3987e5", "shellcode": "#d03b3b",
}


def _human_bytes(n: int) -> str:
    if n < 1024:
        return f"{n} B"
    if n < 1024 * 1024:
        return f"{n // 1024} KB"
    if n < 1024 ** 3:
        return f"{n / 1024 / 1024:.0f} MB"
    return f"{n / 1024 ** 3:.1f} GB"


def _memory_map(regions: list) -> str:
    if not regions:
        return ""
    rows = []
    for r in regions:
        color = "#d03b3b" if (r.suspicious and r.kind != "shellcode") else \
            _KIND_COLOR.get(r.kind, "#8b94a7")
        prot = _e(r.protection)
        backing = "file-backed" if r.backed else "unbacked"
        warn = ' <b style="color:#c0392b">⚠</b>' if r.suspicious else ""
        rows.append(
            f'<tr><td class="mono">{r.base:#014x}</td>'
            f'<td class="mono">{_human_bytes(r.size)}</td>'
            f'<td class="mono">{prot}</td>'
            f'<td class="small muted">{backing}</td>'
            f'<td><span style="display:inline-block;width:9px;height:9px;border-radius:2px;'
            f'background:{color};margin-right:6px"></span>{_e(r.label)}{warn}</td></tr>')
    return ('<div class="scroll"><table><thead><tr><th>Base</th><th>Size</th>'
            '<th>Prot</th><th>Backing</th><th>Region</th></tr></thead>'
            f'<tbody>{"".join(rows)}</tbody></table></div>')


def _heap_timeline_svg(samples: list) -> str:
    """A compact static SVG area chart for the print/HTML report."""
    if not samples:
        return ""
    W, H = 680, 200
    pad_l, pad_b, pad_t, pad_r = 56, 28, 24, 14
    iw, ih = W - pad_l - pad_r, H - pad_t - pad_b
    t_max = max((s.t_ms for s in samples), default=1) or 1
    c_max = max((s.committed for s in samples), default=1) or 1

    def x(t):
        return pad_l + (t / t_max) * iw

    def y(c):
        return pad_t + ih - (c / c_max) * ih

    pts = [(x(s.t_ms), y(s.committed)) for s in samples]
    line = " ".join(("M" if i == 0 else "L") + f"{px:.1f} {py:.1f}"
                    for i, (px, py) in enumerate(pts))
    area = (f"M{pts[0][0]:.1f} {pad_t+ih} "
            + " ".join(f"L{px:.1f} {py:.1f}" for px, py in pts)
            + f" L{pts[-1][0]:.1f} {pad_t+ih} Z")
    grid = "".join(
        f'<line x1="{pad_l}" x2="{W-pad_r}" y1="{y(c_max*f):.1f}" y2="{y(c_max*f):.1f}" '
        f'stroke="#262d3b"/><text x="{pad_l-8}" y="{y(c_max*f)+4:.1f}" text-anchor="end" '
        f'font-size="10" fill="#8b94a7">{_human_bytes(int(c_max*f))}</text>'
        for f in (0, 0.25, 0.5, 0.75, 1))
    markers = "".join(
        f'<circle cx="{px:.1f}" cy="{py:.1f}" r="3.5" fill="#3987e5" stroke="#3987e5"/>'
        + (f'<text x="{px:.1f}" y="{py-9:.1f}" text-anchor="middle" font-size="9" '
           f'fill="#8b94a7">{_e(s.note)}</text>' if s.note else "")
        + f'<text x="{px:.1f}" y="{H-9}" text-anchor="middle" font-size="10" '
          f'fill="#8b94a7">{s.t_ms}ms</text>'
        for (px, py), s in zip(pts, samples))
    return (f'<svg viewBox="0 0 {W} {H}" width="100%" style="max-width:{W}px">'
            f'<defs><linearGradient id="hf" x1="0" y1="0" x2="0" y2="1">'
            f'<stop offset="0%" stop-color="#3987e5" stop-opacity="0.35"/>'
            f'<stop offset="100%" stop-color="#3987e5" stop-opacity="0.03"/></linearGradient></defs>'
            f'{grid}<path d="{area}" fill="url(#hf)"/>'
            f'<path d="{line}" fill="none" stroke="#3987e5" stroke-width="2"/>{markers}</svg>')


def render(report: AnalysisReport) -> str:
    ident = report.identity
    vcolor = _VERDICT_COLOR.get(report.verdict, "#6b7280")
    lang = report.languages[0] if report.languages else None

    lang_card = "—"
    if lang and lang.language != "unknown":
        ev = "".join(f"<li>{_e(e.detail)}</li>" for e in lang.evidence[:5])
        lang_card = (f'<div class="big">{_e(lang.language)}</div>'
                     f'<div class="muted">{_e(lang.compiler or "")} · {_conf_badge(lang.confidence)}</div>'
                     f'<ul class="evidence small">{ev}</ul>')

    packer_card = "—"
    if report.packers:
        p = report.packers[0]
        packer_card = f'<div class="big">{_e(p.name)}</div>{_conf_badge(p.confidence)}'

    sect_rows = "".join(
        f'<tr><td class="mono">{_e(s.name)}</td>'
        f'<td>{_entropy_bar(s.entropy)}</td>'
        f'<td class="mono">{s.raw_size:,}</td>'
        f'<td class="mono muted">{" ".join(s.characteristics)}</td></tr>'
        for s in report.sections[:40])

    intel_rows = "".join(
        f'<tr><td>{_e(r.source)}</td><td>{"known" if r.known else "unknown"}</td>'
        f'<td>{_e(r.family or "—")}</td><td class="muted">{_e(r.detail or "")}</td></tr>'
        for r in report.intel) or '<tr><td colspan=4 class="muted">No intel lookups performed.</td></tr>'

    dyn = report.dynamic
    dyn_badge = ('<span class="sim">SIMULATED</span>' if dyn.simulated
                 else '<span class="real">LIVE SANDBOX</span>') if dyn.executed else ""
    proc = _process_tree(dyn.process_tree) if dyn.process_tree else '<span class="muted">—</span>'
    mem_map = _memory_map(dyn.memory_map)
    heap_svg = _heap_timeline_svg(dyn.heap_timeline)
    mem_section = (f'<h2>Memory Map <span class="muted">&middot; address-space snapshot</span></h2>'
                   f'{mem_map}') if mem_map else ""
    heap_section = (f'<h2>Heap Growth <span class="muted">&middot; committed memory over time</span></h2>'
                    f'<div class="card">{heap_svg}</div>') if heap_svg else ""

    return _TEMPLATE.format(
        title=_e(ident.filename),
        verdict=_e(report.verdict.upper()),
        vcolor=vcolor,
        vconf=_conf_badge(report.verdict_confidence),
        classification=_e(report.classification or "unclassified"),
        summary=_e(report.summary),
        filename=_e(ident.filename),
        fmt=_e(ident.format.upper()),
        arch=_e(ident.arch or "?"),
        bits=ident.bitness or "?",
        size=f"{ident.size:,}",
        sha256=_e(ident.sha256),
        md5=_e(ident.md5),
        sha1=_e(ident.sha1),
        entropy=f"{report.overall_entropy:.2f}",
        lang_card=lang_card,
        packer_card=packer_card,
        heatmap=_heatmap(report),
        findings=_findings(report),
        sections=sect_rows or '<tr><td colspan=4 class="muted">No sections.</td></tr>',
        iocs=_ioc_section(report),
        intel=intel_rows,
        yara=", ".join(_e(y) for y in report.yara_matches) or "—",
        dyn_badge=dyn_badge,
        proc=proc,
        mem_section=mem_section,
        heap_section=heap_section,
        import_count=len(report.imports),
        engine=_e(report.engine_version),
        created=_e(report.created_at),
    )


_TEMPLATE = """<!doctype html><html><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>ReQuiem · {title}</title>
<style>
:root{{--bg:#0b0e14;--panel:#151a23;--panel2:#1c2230;--tx:#e6e9ef;--mut:#8b94a7;--line:#262d3b;}}
*{{box-sizing:border-box}}body{{margin:0;background:var(--bg);color:var(--tx);
font:14px/1.5 -apple-system,Segoe UI,Roboto,sans-serif;
-webkit-print-color-adjust:exact;print-color-adjust:exact}}
.pdfbar{{position:fixed;top:14px;right:16px;z-index:50}}
.pdfbar button{{background:#7c9cff;color:#0b0e14;border:none;border-radius:8px;
padding:9px 16px;font-weight:700;font-size:13px;cursor:pointer}}
.wrap{{max-width:1100px;margin:0 auto;padding:28px 20px 80px}}
h1{{font-size:22px;margin:0}} h2{{font-size:15px;text-transform:uppercase;letter-spacing:.08em;
color:var(--mut);margin:34px 0 12px;border-bottom:1px solid var(--line);padding-bottom:6px}}
.banner{{background:var(--panel);border:1px solid var(--line);border-radius:12px;padding:20px;
display:flex;gap:20px;align-items:center;margin-top:14px}}
.vchip{{font-weight:800;font-size:18px;padding:10px 18px;border-radius:10px;color:#0b0e14;white-space:nowrap}}
.muted{{color:var(--mut)}} .mono{{font-family:ui-monospace,Consolas,monospace;font-size:12.5px}}
.small{{font-size:12px}}
.grid{{display:grid;grid-template-columns:repeat(auto-fit,minmax(220px,1fr));gap:14px}}
.card{{background:var(--panel);border:1px solid var(--line);border-radius:10px;padding:14px}}
.card h3{{margin:0 0 8px;font-size:12px;text-transform:uppercase;letter-spacing:.06em;color:var(--mut)}}
.big{{font-size:20px;font-weight:700}}
.badge{{display:inline-block;background:var(--panel2);border:1px solid var(--line);border-radius:20px;
padding:1px 9px;font-size:11px;color:var(--mut)}}
table{{width:100%;border-collapse:collapse}} th,td{{text-align:left;padding:7px 9px;border-bottom:1px solid var(--line);vertical-align:top}}
th{{color:var(--mut);font-size:11px;text-transform:uppercase;letter-spacing:.05em}}
.bar{{display:inline-block;width:120px;height:9px;background:var(--panel2);border-radius:5px;overflow:hidden;vertical-align:middle;margin-right:6px}}
.fill{{height:100%}}
.scroll{{overflow-x:auto}} table.heat td,table.heat th{{border:1px solid var(--line);min-width:120px}}
table.heat .tech{{color:#fff;font-size:11px}} table.heat .tech span{{color:#f3d3c9}}
table.heat .empty{{background:var(--panel)}} table.heat b{{font-size:11px}}
.finding{{background:var(--panel);border:1px solid var(--line);border-left-width:4px;border-radius:8px;padding:12px 14px;margin:10px 0}}
.fhead{{display:flex;align-items:center;gap:8px;flex-wrap:wrap}}
.sev{{color:#0b0e14;font-weight:700;font-size:10px;padding:2px 7px;border-radius:5px}}
.evidence{{margin:8px 0 0;padding-left:18px;color:var(--mut)}} .evidence li{{margin:2px 0}}
.loc{{color:#6b7f9e;font-family:monospace;font-size:11px}}
.techs{{margin-top:8px}} .pill{{display:inline-block;background:#3a1f2b;border:1px solid #5b2c3c;color:#f3b0c1;border-radius:5px;padding:1px 7px;font-size:11px;margin-right:5px}}
.ioc-group{{margin-bottom:14px}} .ioc-group h4{{margin:0 0 6px;font-size:13px}}
.count{{background:var(--panel2);border-radius:10px;padding:0 8px;font-size:11px;color:var(--mut)}}
.ioc-group ul{{margin:0;padding-left:16px;max-height:180px;overflow:auto}}
.sim{{background:#7c4a03;color:#ffd7a1;font-size:10px;font-weight:700;padding:2px 8px;border-radius:5px}}
.real{{background:#7f1d1d;color:#fecaca;font-size:10px;font-weight:700;padding:2px 8px;border-radius:5px}}
.proc{{font-family:monospace;font-size:12.5px;padding:1px 0}}
footer{{margin-top:40px;color:var(--mut);font-size:12px;border-top:1px solid var(--line);padding-top:14px}}

/* --- print / PDF: light, ink-friendly, no cross-page splits --- */
@media print {{
  @page {{ size: A4; margin: 14mm 12mm; }}
  :root{{--bg:#fff;--panel:#fff;--panel2:#f2f4f8;--tx:#111;--mut:#555;--line:#ccc;}}
  body{{background:#fff;color:#111;font-size:11px}}
  .wrap{{max-width:none;padding:0}}
  a{{color:#111}}
  h1{{font-size:18px}} h2{{color:#333;margin:18px 0 8px;page-break-after:avoid}}
  .card,.finding,.ioc-group{{page-break-inside:avoid;box-shadow:none}}
  tr,.proc{{page-break-inside:avoid}}
  thead{{display:table-header-group}}
  .banner{{page-break-inside:avoid}}
  /* Heatmap cells: keep colored fills when printing backgrounds is enabled. */
  table.heat .tech span{{color:#3a1005}}
  .badge{{border-color:#bbb}}
  .pill{{background:#fbe9ee;border-color:#e5b3c1;color:#7a2740}}
  .loc{{color:#3b6}}
  .no-print{{display:none !important}}
}}
</style></head><body>
<div class="pdfbar no-print"><button onclick="window.print()">⬇ Save as PDF</button></div>
<div class="wrap">
<h1>ReQuiem <span class="muted">· Malware Analysis Report</span></h1>
<div class="banner">
  <div class="vchip" style="background:{vcolor}">{verdict}</div>
  <div><div><b>{classification}</b> &nbsp;{vconf}</div>
  <div class="muted mono">{filename} · {fmt} {arch}/{bits}-bit · {size} bytes</div></div>
</div>

<h2>Executive Summary</h2>
<div class="card"><p style="margin:0">{summary}</p></div>

<h2>Identity</h2>
<div class="grid">
  <div class="card"><h3>Language</h3>{lang_card}</div>
  <div class="card"><h3>Packer</h3>{packer_card}</div>
  <div class="card"><h3>Avg Entropy</h3><div class="big">{entropy}</div>
    <div class="muted">{import_count} imports</div></div>
  <div class="card"><h3>Hashes</h3>
    <div class="mono small">SHA256 {sha256}</div>
    <div class="mono small muted">SHA1 {sha1}</div>
    <div class="mono small muted">MD5 {md5}</div></div>
</div>

<h2>MITRE ATT&amp;CK Heatmap</h2>
{heatmap}

<h2>Findings <span class="muted">— why this verdict</span></h2>
{findings}

<h2>Dynamic Behavior {dyn_badge}</h2>
<div class="card"><h3>Process Tree</h3>{proc}</div>

{mem_section}
{heap_section}

<h2>Sections &amp; Entropy</h2>
<div class="scroll"><table><thead><tr><th>Section</th><th>Entropy</th><th>Raw size</th><th>Flags</th></tr></thead>
<tbody>{sections}</tbody></table></div>

<h2>Indicators of Compromise</h2>
{iocs}

<h2>Threat Intelligence</h2>
<table><thead><tr><th>Source</th><th>Status</th><th>Family</th><th>Detail</th></tr></thead>
<tbody>{intel}</tbody></table>
<p class="muted small">YARA matches: {yara}</p>

<footer>Generated by ReQuiem v{engine} · {created} · Dynamic results may be simulated — badged inline.
Sample binaries are never auto-distributed.</footer>
</div></body></html>"""
