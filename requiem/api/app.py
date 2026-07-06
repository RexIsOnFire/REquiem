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

# Interactive docs / OpenAPI schema reveal the whole API surface, so they are
# OFF by default and only enabled when REQUIEM_ENABLE_DOCS=1 (dev).
import os as _os_app
_DOCS = _os_app.environ.get("REQUIEM_ENABLE_DOCS", "0") == "1"

app = FastAPI(
    title="ReQuiem", version="0.1.0",
    description="All-in-one malware analysis workbench",
    docs_url="/docs" if _DOCS else None,
    redoc_url="/redoc" if _DOCS else None,
    openapi_url="/openapi.json" if _DOCS else None,
)

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


class _BodySizeLimit(BaseHTTPMiddleware):
    """Reject over-large request bodies before they're buffered into memory.

    Uses the Content-Length header (Starlette buffers the full body, so this is
    the cheapest place to cut off a memory-exhaustion body). File uploads have
    their own higher cap enforced after read; this is a global ceiling.
    """
    _GLOBAL_MAX = 64 * 1024 * 1024  # 64 MB hard ceiling for any request

    async def dispatch(self, request, call_next):
        clen = request.headers.get("content-length")
        if clen and clen.isdigit() and int(clen) > self._GLOBAL_MAX:
            return JSONResponse(status_code=413, content={"error": "request too large"})
        return await call_next(request)


class _CSRFGuard(BaseHTTPMiddleware):
    async def dispatch(self, request, call_next):
        if not _sec.csrf_ok(request):
            return JSONResponse(status_code=403,
                                content={"error": "CSRF check failed"})
        return await call_next(request)


app.add_middleware(_SecurityHeaders)
app.add_middleware(_CSRFGuard)
app.add_middleware(_BodySizeLimit)


@app.exception_handler(Exception)
async def _unhandled(request, exc):
    # Never leak stack traces or internal messages to clients. Log server-side.
    # Strip CR/LF from the path to prevent log-forging injection.
    import logging
    safe_path = str(request.url.path).replace("\r", "").replace("\n", "")[:200]
    logging.getLogger("requiem").exception("unhandled error on %s", safe_path)
    return JSONResponse(status_code=500, content={"error": "internal server error"})


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


def _analyze_limit(request) -> JSONResponse | None:
    """Throttle CPU-heavy analysis endpoints (anonymous-reachable)."""
    if not _sec.rate_limiter.check("analyze", _sec.client_ip(request),
                                   limit=20, window=60):
        return JSONResponse(status_code=429, content={"error": "rate limited"})
    return None


@app.get("/healthz")
def healthz():
    return {"status": "ok", "engine": "0.1.0"}


# NOTE: the single-user `/config` endpoint (which exposed the server's own
# key-configuration state) was removed — in the multi-user web app it was pure
# information disclosure. Per-user key status lives behind auth at GET /keys.
# The CLI `requiem config` reads the environment directly, unaffected.


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
# \A ... \Z anchors (not ^ $) so a trailing newline can't sneak through and get
# injected into an outbound API request.
_HASH_RE = _re.compile(r"\A(?:[A-Fa-f0-9]{32}|[A-Fa-f0-9]{40}|[A-Fa-f0-9]{64})\Z")


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
async def analyze_upload(request: Request, file: UploadFile = File(...),
                         intel: bool = Query(False),
                         requiem_session: str | None = Cookie(default=None)):
    limited = _analyze_limit(request)
    if limited:
        return limited
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
async def analyze_upload_html(request: Request, file: UploadFile = File(...),
                              intel: bool = Query(False)):
    if _analyze_limit(request):
        return HTMLResponse(status_code=429, content="<h1>Rate limited</h1>")
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

    if _analyze_limit(request):
        return JSONResponse(status_code=429, content={"error": "rate limited"})

    # Bound the JSON body to prevent memory-exhaustion via a huge report blob.
    clen = request.headers.get("content-length")
    if clen and clen.isdigit() and int(clen) > _MAX_JSON_BYTES:
        return JSONResponse(status_code=413, content={"error": "report too large"})

    from ..core.models import FileIdentity
    try:
        report = AnalysisReport.from_dict(payload)
        # from_dict tolerates partial dicts; ensure a usable identity exists so
        # downstream rendering can't hit an AttributeError on a None/garbage one.
        if not isinstance(report.identity, FileIdentity):
            raise ValueError("missing identity")
        stem = _safe_filename(report.identity.filename)
    except Exception:
        return JSONResponse(status_code=400, content={"error": "invalid report payload"})

    try:
        pdf_bytes = await run_in_threadpool(pdf_report.render_pdf, report)
    except Exception:
        # PDFUnavailable OR any runtime render failure -> print-ready HTML.
        try:
            return HTMLResponse(html.render(report),
                                headers={"X-ReQuiem-PDF": "unavailable-html-fallback"})
        except Exception:
            return JSONResponse(status_code=400,
                                content={"error": "report could not be rendered"})
    return Response(content=pdf_bytes, media_type="application/pdf",
                    headers={"Content-Disposition": f'attachment; filename="{stem}.pdf"'})


@app.post("/analyze/pdf")
async def analyze_upload_pdf(request: Request, file: UploadFile = File(...),
                             intel: bool = Query(False)):
    if _analyze_limit(request):
        return JSONResponse(status_code=429, content={"error": "rate limited"})
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
