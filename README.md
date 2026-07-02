# ReQuiem — Malware Analysis Workbench

> One upload · one investigation · one report · one ATT&CK view · one IOC export.

ReQuiem is an all-in-one reverse-engineering workbench. Give it a file (or a
hash), and it produces an **explainable** technical report: what language the
sample was built in, how it's packed, what it does, which MITRE ATT&CK
techniques it maps to, and *why* — with the evidence attached to every claim.

It doesn't just say "this is ransomware." It says:

> *Classified as **ransomware** because the sample carries ransom-note
> phrasing plus a Bitcoin address, deletes volume shadow copies, imports
> cryptographic routines, and exhibits a read→encrypt→write loop over user
> directories.* — then shows you each piece of evidence.

## Why it's built the way it is

- **Zero hard dependencies.** The entire core pipeline runs on the Python
  standard library. Optional packages (`pefile`, `yara-python`, `fastapi`)
  each sharpen one stage and degrade gracefully when absent — so it runs
  anywhere, immediately.
- **Explainability is a data type.** Every conclusion is a `Finding` carrying
  `Evidence`. Nothing is asserted without a locator you can jump to.
- **Safe by design.** ReQuiem performs *metadata-only* hash lookups and
  **never auto-downloads malware binaries**. Dynamic analysis runs through a
  pluggable backend that ships as a clearly-badged **simulation**; a real
  sandbox (CAPE/Cuckoo/VM-agent) implements the same interface and drops in
  without touching the rest of the code.

## Install

```bash
git clone <repo> && cd ReQuiem
pip install -e .            # core only, stdlib
pip install -e ".[all]"    # + pefile/yara/fastapi for full fidelity
```

## Use it — CLI

```bash
# Analyze a local sample -> console report
python -m requiem.cli analyze sample.exe

# ...and write a self-contained HTML report + machine-readable JSON
python -m requiem.cli analyze sample.exe --html report.html --json report.json

# ...or a PDF report (needs a PDF backend — see below; falls back to
# print-ready HTML if none is installed)
python -m requiem.cli analyze sample.exe --pdf report.pdf

# Online hash-reputation lookup (MalwareBazaar; VirusTotal if VT_API_KEY set)
python -m requiem.cli analyze sample.exe --intel
python -m requiem.cli hash <sha256> --online
```

## Use it — library

```python
from requiem import analyze
report = analyze(open("sample.exe", "rb").read(), "sample.exe")
print(report.verdict, report.classification)   # e.g. malicious ransomware
print(report.summary)                          # the plain-English explanation
```

## Use it — API (for the React/Next.js frontend)

```bash
uvicorn requiem.api.app:app --reload
```

| Method | Route              | Purpose                                   |
|--------|--------------------|-------------------------------------------|
| POST   | `/analyze`             | multipart upload → full JSON report                    |
| POST   | `/analyze/html`        | multipart upload → rendered HTML report                |
| POST   | `/analyze/pdf`         | multipart upload → PDF (or print-ready HTML fallback)  |
| GET    | `/report/pdf-available`| which PDF backend, if any, is installed                |
| GET    | `/hash/{hash}`         | metadata-only intel lookup                             |
| GET    | `/attack/matrix`       | ATT&CK catalog for drawing the heatmap                 |
| GET    | `/healthz`             | liveness                                               |

### PDF reports

PDF is generated **from the same HTML report** (one source of truth) via the
first available backend, and degrades gracefully:

1. **Playwright** (`pip install playwright && playwright install chromium`) —
   most reliable cross-platform, recommended.
2. **WeasyPrint** (`pip install weasyprint`) — pure-Python, but needs native
   GTK/Pango libraries on Windows.
3. **Neither installed** — no failure: the CLI/API return the print-ready HTML
   (light theme, page-break-aware) with a **Save as PDF** button, and the web
   UI's PDF button falls back to browser print-to-PDF.

## Use it — web UI (Next.js)

The `frontend/` app is the full workbench: drag-drop upload, verdict banner,
interactive ATT&CK heatmap, expandable evidence-backed findings, process tree,
entropy visualization, and one-click IOC export.

```bash
# 1. start the backend
uvicorn requiem.api.app:app --port 8000

# 2. start the frontend (proxies /api/* -> :8000, so no CORS setup needed)
cd frontend
npm install
npm run dev            # http://localhost:3000
```

Point the proxy at a non-default backend with `NEXT_PUBLIC_API_BASE`.

## What it detects

| Stage | Output |
|-------|--------|
| **Triage** | format (PE/ELF/Mach-O/Office/script), arch, bitness, hashes, entropy |
| **Language fingerprinting** | Go, Rust, C#/.NET, C/C++ (MSVC/GCC/MinGW), Delphi, Nim, Python-frozen, AutoIt — with compiler + confidence + evidence |
| **Packer detection** | UPX, Themida, VMProtect, ASPack, MPRESS, Enigma… + generic entropy heuristic |
| **Strings / IOCs** | URLs, domains, IPs, registry keys, mutexes, file paths, Bitcoin addresses |
| **YARA** | starter behavioral ruleset (extend in `rules/`) |
| **Intel** | MalwareBazaar / VirusTotal (keys-optional) — metadata only |
| **Dynamic (simulated)** | process tree, network, filesystem/registry ops, **memory findings** (RWX regions, large heap + AES loops — the ransomware story) |
| **Memory visualization** | address-space **memory map** (regions by kind, R/W/X, file-backed vs unbacked, suspicious-flagged) + **heap-growth timeline** (committed bytes over execution) — in the web UI, HTML, and PDF |
| **ATT&CK inference** | maps behavior to techniques, renders a tactic×technique heatmap |
| **Verdict** | benign / suspicious / malicious + malware classification + explanation |

## Architecture

```
requiem/
├── core/        models · triage · pipeline (the orchestrator)
├── static/      pe · elf · macho · language · packer · strings_ioc · yara_scan
├── intel/       base (interface) · providers (MalwareBazaar, VirusTotal, offline)
├── dynamic/     base (interface) · simulated backend  ← real sandbox plugs in here
├── attack/      techniques (catalog) · inference (rules → findings → verdict)
├── report/      html (self-contained report + heatmap)
├── api/         FastAPI app
└── cli/         command-line entry point

frontend/        Next.js App Router UI (TypeScript, hand-rolled SVG/CSS visuals)
├── app/         layout · landing/upload page
├── components/  VerdictBanner · AttackHeatmap · FindingsList · ProcessTree · …
└── lib/         api client · types (mirror of the Python model) · theme
```

The pipeline is a **pure function** (`analyze(bytes, name) -> AnalysisReport`),
which makes moving it behind a Celery/RQ worker for the production backend a
mechanical change.

## Roadmap

- Real sandbox backend (CAPE integration behind `DynamicBackend`)
- PDF export of reports
- CFG generation / disassembly view
- Family-level YARA signatures
- Memory-region visualization in the UI (heap growth / RWX map)

## Safety & scope

ReQuiem is for **authorized** malware analysis, CTFs, research, and education.
It never distributes sample binaries and never executes samples itself in its
default configuration.

## License

MIT
