"""PDF report generation — one HTML source of truth, multiple renderers.

ReQuiem generates its PDF *from the same HTML report* so content never drifts
between formats. It tries renderers in order of quality and falls back cleanly:

1. **WeasyPrint** — pure-Python HTML→PDF, honors the report's ``@media print``
   CSS. No browser needed. Best default.
2. **Playwright (headless Chromium)** — pixel-perfect, uses the browser's own
   print engine. Heavier, but excellent for the ATT&CK heatmap colors.
3. **No renderer installed** — we don't fail. :func:`render_pdf` raises
   :class:`PDFUnavailable` with install guidance, and callers (CLI/API) fall
   back to shipping the print-ready HTML with a "Save as PDF" button.

Nothing here is a hard dependency; the whole module degrades gracefully.
"""
from __future__ import annotations

import os
import threading

from ..core.models import AnalysisReport
from . import html as html_report

# Each render can spawn a headless Chromium (~100-300 MB). Cap concurrent
# renders so a burst of PDF requests can't exhaust host memory. Configurable
# via REQUIEM_PDF_CONCURRENCY (default 2); acquisition times out so a request
# never blocks forever.
_MAX_CONCURRENT = max(1, int(os.environ.get("REQUIEM_PDF_CONCURRENCY", "2")))
_render_slots = threading.Semaphore(_MAX_CONCURRENT)
_ACQUIRE_TIMEOUT = 30  # seconds


class PDFUnavailable(RuntimeError):
    """Raised when no PDF backend is installed, or the render pool is saturated."""


def available_backend() -> str | None:
    """Return the name of the first usable backend, or ``None``."""
    try:
        import weasyprint  # noqa: F401  type: ignore
        return "weasyprint"
    except Exception:
        pass
    try:
        from playwright.sync_api import sync_playwright  # noqa: F401  type: ignore
        return "playwright"
    except Exception:
        pass
    return None


def render_pdf(report: AnalysisReport) -> bytes:
    """Render ``report`` to PDF bytes using the best available backend.

    Tries every installed backend in turn; if a backend is present but fails at
    runtime (e.g. Chromium not installed on the host, missing system libs), it
    moves on to the next. Only when *all* backends are unavailable/failed does it
    raise :class:`PDFUnavailable`, so callers can fall back to HTML.

    Concurrent renders are capped (semaphore) so a burst can't exhaust memory;
    if the pool stays saturated past the timeout we raise PDFUnavailable and the
    caller returns the HTML fallback instead of piling up Chromium processes.
    """
    if not _render_slots.acquire(timeout=_ACQUIRE_TIMEOUT):
        raise PDFUnavailable("PDF render pool saturated; try again shortly")
    try:
        html = html_report.render(report)
        errors: list[str] = []

        for name, fn in (("weasyprint", _render_weasyprint),
                         ("playwright", _render_playwright)):
            try:
                data = fn(html)
                if data and data[:4] == b"%PDF":
                    return data
                errors.append(f"{name}: produced no PDF")
            except Exception as exc:  # backend missing OR runtime failure
                errors.append(f"{name}: {exc}")

        raise PDFUnavailable(
            "PDF rendering unavailable. Install a backend:\n"
            "  pip install weasyprint            # pure-Python, best for servers\n"
            "  pip install playwright && playwright install chromium\n"
            + ("Details: " + " | ".join(errors) if errors else "")
        )
    finally:
        _render_slots.release()


def _render_weasyprint(html: str) -> bytes:
    from weasyprint import HTML  # type: ignore

    return HTML(string=html).write_pdf()


def _render_playwright(html: str) -> bytes:
    from playwright.sync_api import sync_playwright  # type: ignore

    with sync_playwright() as p:
        browser = p.chromium.launch()
        try:
            page = browser.new_page()
            # Load the report as a data document so relative refs don't matter;
            # everything is inline anyway.
            page.set_content(html, wait_until="networkidle")
            pdf = page.pdf(
                format="A4",
                print_background=True,
                margin={"top": "14mm", "bottom": "14mm", "left": "12mm", "right": "12mm"},
            )
        finally:
            browser.close()
    return pdf
