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

## Configure API keys (optional)

Copy the template and fill in whatever you have — every key is optional:

```bash
cp .env.example .env       # Windows: copy .env.example .env
```

```ini
VT_API_KEY=...             # VirusTotal
MALWAREBAZAAR_API_KEY=...  # MalwareBazaar (works without a key too)
CAPE_URL=https://cape.lan  # CAPE sandbox (real detonation)
CAPE_TOKEN=...
```

ReQuiem loads `.env` automatically at startup — CLI, API, and library. An
explicit environment variable always overrides the file. `.env` is gitignored;
`.env.example` is the committed template. Check what's wired up:

```bash
python -m requiem.cli config      # lists which keys are set
# or, with the API running:  GET /config
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

# Detonate in a real CAPE sandbox instead of the simulation
# (needs CAPE_URL; falls back to simulated if CAPE is unreachable)
CAPE_URL=https://cape.lan python -m requiem.cli analyze sample.exe --sandbox cape

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
| **Disassembly (CFG)** | Capstone recursive-descent **function recovery** seeded from PE exports / ELF symbols **and** call-target discovery (named or `sub_<addr>`); each function as a basic-block **control-flow graph** (x86/x64/ARM/ARM64, PE & ELF). Navigable function list in the UI; per-function listings in HTML/PDF |
| **YARA (family-level)** | behavioral + **family** rules (WannaCry, LockBit, RedLine, loaders, RATs…) with rich `meta:` — a family match sets the classification, drives an explainable finding, and contributes ATT&CK techniques |
| **Intel** | MalwareBazaar / VirusTotal (keys-optional) — metadata only |
| **Dynamic (simulated)** | process tree, network, filesystem/registry ops, **memory findings** (RWX regions, large heap + AES loops — the ransomware story) |
| **Memory visualization** | address-space **memory map** (regions by kind, R/W/X, file-backed vs unbacked, suspicious-flagged) + **heap-growth timeline** (committed bytes over execution) — in the web UI, HTML, and PDF |
| **ATT&CK inference** | maps behavior to techniques, renders a tactic×technique heatmap |
| **Verdict** | benign / suspicious / malicious + malware classification + explanation |

## Architecture

```
requiem/
├── core/        models · triage · pipeline (the orchestrator)
├── static/      pe · elf · macho · language · packer · strings_ioc · yara_scan · disasm
├── intel/       base (interface) · providers (MalwareBazaar, VirusTotal, offline)
├── dynamic/     base (interface) · simulated backend · cape (CAPE adapter) + cape_map
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

## Investigate by hash — cloud, no local sandbox

The headline feature for a **public deployment**: paste a hash and get a full
investigation — reputation *and* dynamic behavior — with **no file upload and no
sandbox to host**. ReQuiem pulls any *existing* cloud detonation for the hash and
maps it into the same report the rest of the app renders (process tree, network,
ATT&CK heatmap, findings, verdict).

Sources (each optional, keys-only, all hosted):

- **VirusTotal** `behaviour_summary` (`VT_API_KEY`) — merged multi-engine behavior
- **Hatching Triage** (`TRIAGE_TOKEN`) — searches tria.ge for an existing report
- **Hybrid Analysis** (`HYBRIDANALYSIS_API_KEY`) — Falcon Sandbox, free tier

```bash
# CLI-equivalent via the API:
curl http://localhost:8000/investigate/<sha256>
```

In the web UI, the **Hash lookup** tab has two actions: **Reputation**
(family/tags) and **Investigate** (the full behavioral report). Verified live:
a WannaCry hash returns 17 process roots, 700+ network events, and 34 ATT&CK
techniques — from the hash alone.

Nothing is uploaded and no sample is downloaded — ideal for a public-facing app.

## Real detonation — sandbox backends

By default the dynamic stage is a clearly-badged **simulation** (ReQuiem never
executes samples itself). To get real behavior, point ReQuiem at a separately
operated sandbox — it provides the isolated VM, API hooking, memory capture, and
network control; ReQuiem submits the sample, polls for the report, and maps it
into the same `DynamicBehavior` model the rest of the app consumes.

Four sandboxes are supported: **CAPE**, **Cuckoo**, **Joe**, **Triage**.

```bash
export CAPE_URL=https://your-cape        # (or CUCKOO_URL / JOE_URL+JOE_APIKEY / TRIAGE_TOKEN)
python -m requiem.cli analyze sample.exe --sandbox cape     # cape|cuckoo|joe|triage
```

- **Nothing detonates locally.** ReQuiem only talks to the sandbox you supply.
- **Never hard-fails.** If the sandbox is unconfigured, unreachable, or times
  out, the run transparently falls back to the simulated backend (the report
  shows the fallback reason).
- **One normalizer, thin adapters.** Every sandbox parses its native report into
  a common `NormalizedReport` (`dynamic/normalize.py`); the region-classification,
  heap-synthesis, severity and ATT&CK mapping live there *once*. Adding a fifth
  sandbox is just a small client + a parser into that shape.

## Roadmap

- Mach-O disassembly (code-view + entry mapping)
- Cross-references (xref) and call-graph view across recovered functions
- Broader family YARA coverage + auto-updating community rulesets

## Safety & scope

ReQuiem is for **authorized** malware analysis, CTFs, research, and education.
It never distributes sample binaries and never executes samples itself — the
optional live-detonation path delegates entirely to a CAPE instance you operate
and point it at.

## License

MIT
