"""FastAPI surface for ReQuiem.

Thin HTTP layer over the pipeline so a React/Next.js frontend (or curl) can:

    POST /analyze      multipart file upload  -> full JSON report
    POST /analyze/html multipart file upload  -> rendered HTML report
    POST /analyze/pdf  multipart file upload  -> PDF report (or print-ready HTML)
    GET  /hash/{hash}                          -> metadata-only intel lookup
    GET  /attack/matrix                        -> tactic/technique catalog for the heatmap
    GET  /healthz

The heavy analysis is synchronous here for simplicity; in production this hands
off to a Celery/RQ worker (the pipeline is already a pure function, so that move
is mechanical). Requires ``fastapi`` + an ASGI server; both are optional deps.
"""
from __future__ import annotations

from ..attack import techniques
from ..core.pipeline import PipelineOptions, analyze
from ..intel.base import gather_intel
from ..intel.providers import default_providers
from ..report import html
from ..report import pdf as pdf_report

try:
    from fastapi import FastAPI, File, UploadFile, Query, Body, Cookie
    from fastapi.responses import HTMLResponse, JSONResponse, Response
    from fastapi.concurrency import run_in_threadpool
except Exception as exc:  # pragma: no cover
    raise SystemExit("FastAPI not installed. `pip install fastapi uvicorn` to use the API.") from exc

app = FastAPI(title="ReQuiem", version="0.1.0",
              description="All-in-one malware analysis workbench")

from .auth_routes import router as auth_router, current_user  # noqa: E402
app.include_router(auth_router)

# Cap upload size to keep a demo instance safe (100 MB).
_MAX_BYTES = 100 * 1024 * 1024


def _user_keys(session: str | None) -> dict[str, str]:
    """Decrypted API keys for the session's user, or {} for anonymous."""
    user = current_user(session)
    if user is None:
        return {}
    from ..auth.store import get_store
    return get_store().get_keys(user.id)


def _options(intel: bool) -> PipelineOptions:
    return PipelineOptions(run_intel=intel, offline_intel=not intel)


@app.get("/healthz")
def healthz():
    return {"status": "ok", "engine": "0.1.0"}


@app.get("/config")
def config_status():
    """Which integrations are configured (key values never exposed)."""
    from ..core import config
    status = config.configured_status()
    return {
        "configured": status,
        "intel_ready": status["VT_API_KEY"] or status["MALWAREBAZAAR_API_KEY"],
        "sandbox_ready": status["CAPE_URL"],
    }


@app.get("/attack/matrix")
def attack_matrix():
    """Full catalog so the frontend can draw an empty heatmap and overlay results."""
    return {
        "tactics": techniques.TACTIC_ORDER,
        "techniques": [
            {"id": tid, "name": name, "tactic": tactic}
            for tid, (name, tactic) in techniques.CATALOG.items()
        ],
    }


@app.get("/hash/{value}")
def hash_lookup(value: str, online: bool = Query(False),
                requiem_session: str | None = Cookie(default=None)):
    if online:
        from ..intel.providers import providers_for_keys
        user = current_user(requiem_session)
        if user is None:
            return JSONResponse(status_code=401, content={
                "error": "Sign in for online lookups.",
            })
        from ..auth.store import get_store
        keys = get_store().get_keys(user.id)
        if not keys:
            return JSONResponse(status_code=400, content={
                "error": "Add an API key under API keys for online lookups.",
            })
        providers = providers_for_keys(keys)
    else:
        providers = default_providers(offline=True)
    results = gather_intel(providers, sha256=value, md5=None, sha1=None)
    return {
        "hash": value,
        "note": "Metadata lookup only — ReQuiem never downloads sample binaries.",
        "results": [r.__dict__ for r in results],
    }


@app.get("/investigate/{value}")
async def investigate_by_hash(value: str, requiem_session: str | None = Cookie(default=None)):
    """Full by-hash investigation with **no upload and no local sandbox**:
    reputation intel + any *existing* cloud detonation (Triage / VirusTotal /
    Hybrid Analysis) mapped into behavior + inferred ATT&CK. Uses the logged-in
    user's own API keys."""
    from ..dynamic.cloud import (cloud_providers_for_keys, first_behavior,
                                 gather_cloud_behavior)
    from ..intel.providers import providers_for_keys
    from ..attack.inference import run_inference
    from ..core.models import AnalysisReport, FileIdentity, DynamicBehavior

    user = current_user(requiem_session)
    if user is None:
        return JSONResponse(status_code=401, content={
            "error": "Sign in to investigate by hash.",
        })
    from ..auth.store import get_store
    keys = get_store().get_keys(user.id)
    if not keys:
        return JSONResponse(status_code=400, content={
            "error": "Add at least one API key (VirusTotal / Hybrid Analysis) "
                     "under API keys to investigate by hash.",
        })

    intel = gather_intel(providers_for_keys(keys), sha256=value, md5=None, sha1=None)
    cloud = await run_in_threadpool(
        gather_cloud_behavior, cloud_providers_for_keys(keys), sha256=value)

    behavior = first_behavior(cloud) or DynamicBehavior()
    ident = FileIdentity(filename=f"{value[:16]}…", size=0,
                         md5="", sha1="", sha256=value, format="unknown")
    report = AnalysisReport(identity=ident)
    report.intel = intel
    report.dynamic = behavior
    run_inference(report)  # ATT&CK + verdict from the cloud behavior/intel

    return {
        "hash": value,
        "note": "By-hash cloud investigation — no file uploaded, no sample downloaded.",
        "sources": [{"source": c.source, "found": c.found, "note": c.note} for c in cloud],
        "report": report.to_dict(),
    }


@app.post("/analyze")
async def analyze_upload(file: UploadFile = File(...), intel: bool = Query(False),
                         requiem_session: str | None = Cookie(default=None)):
    data = await file.read()
    if len(data) > _MAX_BYTES:
        return JSONResponse(status_code=413, content={"error": "file too large"})
    opts = _options(intel)
    if intel:
        # Drive reputation lookups with the signed-in user's own keys.
        from ..intel.providers import providers_for_keys
        opts.intel_providers = providers_for_keys(_user_keys(requiem_session))
    report = analyze(data, file.filename or "upload.bin", opts)
    return report.to_dict()


@app.post("/analyze/html", response_class=HTMLResponse)
async def analyze_upload_html(file: UploadFile = File(...), intel: bool = Query(False)):
    data = await file.read()
    if len(data) > _MAX_BYTES:
        return HTMLResponse(status_code=413, content="<h1>File too large</h1>")
    report = analyze(data, file.filename or "upload.bin", _options(intel))
    return HTMLResponse(html.render(report))


@app.get("/report/pdf-available")
def pdf_available():
    """Lets the frontend decide whether to offer a true-PDF download or the
    print-to-PDF HTML fallback."""
    return {"backend": pdf_report.available_backend()}


@app.post("/report/pdf")
async def report_pdf(payload: dict = Body(...)):
    """Render a PDF from an already-computed report (from /analyze or
    /investigate). Works for uploads AND hash investigations — no file needed,
    always uses the print-optimized HTML (not the live dark DOM)."""
    from ..core.models import AnalysisReport
    report = AnalysisReport.from_dict(payload)
    stem = (report.identity.filename or "report").rsplit(".", 1)[0].strip("… ") or "report"
    try:
        pdf_bytes = await run_in_threadpool(pdf_report.render_pdf, report)
    except pdf_report.PDFUnavailable:
        return HTMLResponse(html.render(report),
                            headers={"X-ReQuiem-PDF": "unavailable-html-fallback"})
    return Response(content=pdf_bytes, media_type="application/pdf",
                    headers={"Content-Disposition": f'attachment; filename="{stem}.pdf"'})


@app.post("/analyze/pdf")
async def analyze_upload_pdf(file: UploadFile = File(...), intel: bool = Query(False)):
    data = await file.read()
    if len(data) > _MAX_BYTES:
        return JSONResponse(status_code=413, content={"error": "file too large"})
    report = analyze(data, file.filename or "upload.bin", _options(intel))
    stem = (file.filename or "report").rsplit(".", 1)[0]
    try:
        # PDF backends (Playwright sync API, WeasyPrint) are blocking and must
        # not run on the event loop — offload to a worker thread.
        pdf_bytes = await run_in_threadpool(pdf_report.render_pdf, report)
    except pdf_report.PDFUnavailable:
        # Graceful fallback: return the print-ready HTML with a header the
        # frontend can detect, so the user still gets a save-as-PDF path.
        return HTMLResponse(
            html.render(report),
            headers={"X-ReQuiem-PDF": "unavailable-html-fallback"},
        )
    return Response(
        content=pdf_bytes,
        media_type="application/pdf",
        headers={"Content-Disposition": f'attachment; filename="{stem}.pdf"'},
    )
