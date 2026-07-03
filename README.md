# REquiem — Malware Analysis Workbench

> **One upload · one investigation · one report · one ATT&CK view · one IOC export.**

REquiem is an all-in-one reverse-engineering workbench. Give it a **file** or a
**hash** and it produces an *explainable* technical report: what language the
sample was built in, how it's packed, what it does, which MITRE ATT&CK techniques
it maps to, and **why** — with the evidence attached to every claim.

It doesn't just say *"this is ransomware."* It says:

> *Classified as **ransomware** because the sample carries ransom-note phrasing
> plus a Bitcoin address, deletes volume shadow copies, imports cryptographic
> routines, and exhibits a read→encrypt→write loop over user directories* —
> then shows you each piece of evidence.

---

## Highlights

-  **Language & compiler fingerprinting** — Go, Rust, C#/.NET, C/C++
  (MSVC/GCC/MinGW), Delphi, Nim, Python-frozen, AutoIt — with confidence + evidence.
-  **Explainable verdicts** — every conclusion is a `Finding` carrying `Evidence`;
  click any finding to see the proof.
-  **MITRE ATT&CK heatmap** — behavior inferred into 130+ techniques, rendered
  as an interactive tactic × technique matrix.
-  **Memory visualization** — address-space map (R/W/X, file-backed vs unbacked,
  suspicious regions) + heap-growth timeline (the ransomware working-set story).
-  **CFG disassembly** — Capstone recursive-descent **function recovery** from
  exports/symbols + call targets; each function as a navigable control-flow graph.
-  **Investigate by hash — no local sandbox** — paste a hash, get reputation
  *and* real dynamic behavior (process tree, network, ATT&CK) pulled from existing
  cloud detonations. Ideal for a public deployment.
-  **PDF / HTML reports** — self-contained, print-optimized, one-click export.
-  **Safe by design** — static-first, metadata-only hash lookups; **samples are
  never executed locally or redistributed.**

---

## Quick start

```bash
git clone https://github.com/RexIsOnFire/REquiem.git
cd REquiem
pip install -e ".[all]"          # core + pefile/yara/capstone/fastapi/playwright
playwright install chromium      # for PDF export (optional)
```

### CLI (no server needed)

```bash
python -m requiem.cli analyze sample.exe                         # console report
python -m requiem.cli analyze sample.exe --html report.html --pdf report.pdf
python -m requiem.cli hash <sha256> --online                    # reputation lookup
python -m requiem.cli config                                    # show configured keys
```

### Web UI

```bash
# 1. backend
uvicorn requiem.api.app:app --port 8000

# 2. frontend (proxies /api → :8000, so no CORS setup)
cd frontend
npm install
npm run dev            # http://localhost:3000
```

Open **http://localhost:3000** — drag-drop a sample, or use the **Hash lookup**
tab to run a full by-hash cloud investigation.

---

## Configure API keys (optional)

Copy the template and fill in whatever you have — **every key is optional**:

```bash
cp .env.example .env       # Windows: copy .env.example .env
```

```ini
VT_API_KEY=...                 # VirusTotal — reputation + by-hash behavior
MALWAREBAZAAR_API_KEY=...      # MalwareBazaar (free key required for lookups)
HYBRIDANALYSIS_API_KEY=...     # Hybrid Analysis — by-hash cloud behavior
TRIAGE_TOKEN=...               # Hatching Triage (needs a researcher license)
```

ReQuiem loads `.env` automatically at startup (CLI, API, and library). An
explicit environment variable always overrides the file. **`.env` is gitignored;
only `.env.example` is committed.** Verify with `python -m requiem.cli config`.

---

## Investigate by hash — cloud, no local sandbox

The headline feature for a **public deployment**: paste a hash and get a full
investigation — reputation *and* dynamic behavior — with **no file upload and no
sandbox to host**. ReQuiem pulls any *existing* cloud detonation for the hash and
maps it into the same report the rest of the app renders (process tree, network,
ATT&CK heatmap, findings, verdict).

Sources (each optional, keys-only, all hosted): **VirusTotal** `behaviour_summary`,
**Hybrid Analysis** (Falcon Sandbox), **Hatching Triage**. The richest available
report wins.

```bash
curl http://localhost:8000/investigate/<sha256>
```

In the web UI, the **Hash lookup** tab offers **Reputation** (family/tags) and
**Investigate** (full behavioral report). Verified live: a WannaCry hash returns
17 process roots, 700+ network events, and 34 ATT&CK techniques — from the hash
alone. Nothing is uploaded and no sample is downloaded.

---

## What it detects

| Stage | Output |
|-------|--------|
| **Triage** | format (PE/ELF/Mach-O/Office/script), arch, bitness, hashes, entropy |
| **Language fingerprinting** | Go, Rust, C#/.NET, C/C++, Delphi, Nim, Python-frozen, AutoIt — compiler + confidence + evidence |
| **Packer detection** | UPX, Themida, VMProtect, ASPack, MPRESS, Enigma… + entropy heuristic |
| **Strings / IOCs** | URLs, domains, IPs, registry keys, mutexes, file paths, Bitcoin addresses (noise-filtered) |
| **Imports & strings** | imports grouped by DLL with notable APIs flagged; exports; behavioral strings |
| **Disassembly (CFG)** | recursive-descent function recovery from exports/symbols + calls; per-function control-flow graphs (x86/x64/ARM/ARM64) |
| **YARA (family-level)** | behavioral + **family** rules (WannaCry, LockBit, RedLine, loaders, RATs) that set the classification and contribute ATT&CK |
| **Intel** | MalwareBazaar / VirusTotal (keys-optional) — metadata only |
| **Dynamic** | process tree, network, filesystem/registry, memory findings — from a real sandbox, cloud-by-hash, or a badged simulation |
| **Memory visualization** | address-space map + heap-growth timeline |
| **ATT&CK inference** | maps behavior to 130+ techniques → interactive heatmap |
| **Verdict** | benign / suspicious / malicious + classification + plain-English explanation |

---

## Real detonation — sandbox backends

By default the dynamic stage is a clearly-badged **simulation** (ReQuiem never
executes samples itself). To get real behavior you can either **investigate by
hash** from the cloud (above) or point ReQuiem at a sandbox you operate:

```bash
python -m requiem.cli analyze sample.exe --sandbox cape   # cape|cuckoo|joe|triage
```

Every sandbox parses its native report into a shared `NormalizedReport`
(`dynamic/normalize.py`); the region classification, heap synthesis, severity and
ATT&CK mapping live there **once**. An unreachable/unconfigured sandbox
transparently falls back to the simulated backend — a run never hard-fails.

---

## Architecture

```
requiem/
├── core/        models · triage · pipeline · config (.env loader)
├── static/      pe · elf · macho · language · packer · strings_ioc · yara_scan · disasm
├── intel/       providers (VT/MalwareBazaar) · vt_behavior (by-hash behavior)
├── dynamic/     base · simulated · normalize · cape · cuckoo · joe · triage · hybrid · cloud
├── attack/      techniques (catalog) · inference (rules → findings → verdict)
├── report/      html (self-contained report + heatmap) · pdf
├── api/         FastAPI app
└── cli/         command-line entry point

frontend/        Next.js App Router UI (TypeScript, hand-rolled SVG/CSS visuals)
├── app/         layout · landing (upload + hash-lookup tabs)
├── components/  VerdictBanner · AttackHeatmap · FindingsList · ProcessTree ·
│                MemoryMap · HeapTimeline · CfgView · ImportsStrings · HashLookup · …
└── lib/         api client · types (mirror of the Python model) · theme
```

The pipeline is a **pure function** (`analyze(bytes, name) -> AnalysisReport`),
so moving it behind a Celery/RQ worker for production is mechanical.

---

## Development

```bash
python -m pytest tests/ -q        # backend (64 tests, all offline)
cd frontend && npx tsc --noEmit   # frontend typecheck
cd frontend && npm run build      # production build
```

Core analysis runs on the **standard library alone**; every third-party package
(`pefile`, `yara-python`, `capstone`, `fastapi`, `playwright`) sharpens one stage
and degrades gracefully when absent.

---

## Safety & scope

ReQuiem is for **authorized** malware analysis, CTFs, research, and education.
It never distributes sample binaries and never executes samples itself — real
behavior comes from a sandbox *you* operate or an *existing* hosted cloud report.

## License

MIT
