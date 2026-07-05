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
    from fastapi import FastAPI, File, UploadFile, Query, Body, Cookie, Request
    from fastapi.responses import HTMLResponse, JSONResponse, Response
    from fastapi.concurrency import run_in_threadpool
    from fastapi.middleware.cors import CORSMiddleware
    from starlette.middleware.base import BaseHTTPMiddleware
except Exception as exc:  # pragma: no cover
    raise SystemExit("FastAPI not installed. `pip install fastapi uvicorn` to use the API.") from exc

from . import security as _sec

app = FastAPI(title="ReQuiem", version="0.1.0",
              description="All-in-one malware analysis workbench")

# CORS: only explicitly allowed origins may make credentialed (cookie) requests.
app.add_middleware(
    CORSMiddleware,
    allow_origins=_sec.allowed_origins(),
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"],
    allow_headers=["Content-Type", "Authorization"],
    max_age=600,
)


class _SecurityHeaders(BaseHTTPMiddleware):
    async def dispatch(self, request, call_next):
        resp = await call_next(request)
        is_https = request.url.scheme == "https" or \
            request.headers.get("x-forwarded-proto") == "https"
        for k, v in _sec.security_headers(is_https).items():
            resp.headers.setdefault(k, v)
        return resp


app.add_middleware(_SecurityHeaders)

from .auth_routes import router as auth_router, current_user  # noqa: E402
app.include_router(auth_router)

# Cap upload / request-body size to keep a demo instance safe.
_MAX_BYTES = 32 * 1024 * 1024          # samples: 32 MB
_MAX_JSON_BYTES = 8 * 1024 * 1024      # report/pdf JSON: 8 MB


def _user_keys(session: str | None) -> dict[str, str]:
    """Decrypted API keys for the session's user, or {} for anonymous."""
    user = current_user(session)
    if user is None:
        return {}
    from ..auth.store import get_store
    return get_store().get_keys(user.id)


def _options(intel: bool) -> PipelineOptions:
    return PipelineOptions(run_intel=intel, offline_intel=not intel)


import re as _re

_FILENAME_SAFE = _re.compile(r"[^A-Za-z0-9._\-]")


def _safe_filename(name: str | None, default: str = "report") -> str:
    """Sanitize a filename for a Content-Disposition header (no CR/LF/quotes/
    path separators — blocks header injection and path traversal)."""
    stem = (name or default).rsplit(".", 1)[0]
    stem = _FILENAME_SAFE.sub("_", stem).strip("._") or default
    return stem[:80]


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


# A hash must be exactly MD5 (32) / SHA1 (40) / SHA256 (64) hex — nothing else
# is ever sent to external APIs (blocks SSRF / injection via the path segment).
_HASH_RE = _re.compile(r"^[A-Fa-f0-9]{32}$|^[A-Fa-f0-9]{40}$|^[A-Fa-f0-9]{64}$")


def _valid_hash(value: str) -> bool:
    return bool(_HASH_RE.match(value or ""))


@app.get("/hash/{value}")
def hash_lookup(request: Request, value: str, online: bool = Query(False),
                requiem_session: str | None = Cookie(default=None)):
    if not _valid_hash(value):
        return JSONResponse(status_code=400, content={"error": "invalid hash format"})
    if online:
        from ..intel.providers import providers_for_keys
        user = current_user(requiem_session)
        if user is None:
            return JSONResponse(status_code=401, content={
                "error": "Sign in for online lookups.",
            })
        if not _sec.rate_limiter.check("lookup", _sec.client_ip(request),
                                       limit=30, window=60):
            return JSONResponse(status_code=429, content={"error": "rate limited"})
        from ..auth.store import get_store
        keys = get_store().get_keys(user.id)
        if not keys:
            return JSONResponse(status_code=400, content={
                "error": "Add an API key under API keys for online lookups.",
            })
        providers = providers_for_keys(keys)
    else:
        providers = default_providers(offline=True)
    results = gather_intel(providers, sha256=value.lower(), md5=None, sha1=None)
    return {
        "hash": value.lower(),
        "note": "Metadata lookup only — ReQuiem never downloads sample binaries.",
        "results": [r.__dict__ for r in results],
    }


@app.get("/investigate/{value}")
async def investigate_by_hash(request: Request, value: str,
                              requiem_session: str | None = Cookie(default=None)):
    """Full by-hash investigation with **no upload and no local sandbox**:
    reputation intel + any *existing* cloud detonation (Triage / VirusTotal /
    Hybrid Analysis) mapped into behavior + inferred ATT&CK. Uses the logged-in
    user's own API keys."""
    from ..dynamic.cloud import (cloud_providers_for_keys, first_behavior,
                                 gather_cloud_behavior)
    from ..intel.providers import providers_for_keys
    from ..attack.inference import run_inference
    from ..core.models import AnalysisReport, FileIdentity, DynamicBehavior

    if not _valid_hash(value):
        return JSONResponse(status_code=400, content={"error": "invalid hash format"})
    value = value.lower()
    user = current_user(requiem_session)
    if user is None:
        return JSONResponse(status_code=401, content={
            "error": "Sign in to investigate by hash.",
        })
    if not _sec.rate_limiter.check("investigate", _sec.client_ip(request),
                                   limit=20, window=60):
        return JSONResponse(status_code=429, content={"error": "rate limited"})
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
async def report_pdf(request: Request, payload: dict = Body(...)):
    """Render a PDF from an already-computed report (from /analyze or
    /investigate). Works for uploads AND hash investigations — no file needed,
    always uses the print-optimized HTML (not the live dark DOM). Never 500s:
    if PDF rendering isn't available on the host, returns the print-ready HTML."""
    from ..core.models import AnalysisReport

    # Bound the JSON body to prevent memory-exhaustion via a huge report blob.
    clen = request.headers.get("content-length")
    if clen and clen.isdigit() and int(clen) > _MAX_JSON_BYTES:
        return JSONResponse(status_code=413, content={"error": "report too large"})

    try:
        report = AnalysisReport.from_dict(payload)
    except Exception:
        return JSONResponse(status_code=400, content={"error": "invalid report payload"})

    stem = _safe_filename(report.identity.filename)
    try:
        pdf_bytes = await run_in_threadpool(pdf_report.render_pdf, report)
    except Exception:
        # PDFUnavailable OR any runtime render failure -> print-ready HTML.
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
    stem = _safe_filename(file.filename)
    try:
        # PDF backends (Playwright sync API, WeasyPrint) are blocking and must
        # not run on the event loop — offload to a worker thread.
        pdf_bytes = await run_in_threadpool(pdf_report.render_pdf, report)
    except Exception:
        # PDFUnavailable OR any runtime render failure -> print-ready HTML.
        return HTMLResponse(
            html.render(report),
            headers={"X-ReQuiem-PDF": "unavailable-html-fallback"},
        )
    return Response(
        content=pdf_bytes,
        media_type="application/pdf",
        headers={"Content-Disposition": f'attachment; filename="{stem}.pdf"'},
    )
