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

from ..core.models import AnalysisReport
from . import html as html_report


class PDFUnavailable(RuntimeError):
    """Raised when no PDF backend is installed."""


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

    :raises PDFUnavailable: when neither WeasyPrint nor Playwright is installed.
    """
    html = html_report.render(report)
    backend = available_backend()
    if backend == "weasyprint":
        return _render_weasyprint(html)
    if backend == "playwright":
        return _render_playwright(html)
    raise PDFUnavailable(
        "No PDF backend installed. Install one of:\n"
        "  pip install weasyprint            # pure-Python, recommended\n"
        "  pip install playwright && playwright install chromium\n"
        "Meanwhile, use the print-ready HTML report (open it and choose "
        "'Save as PDF')."
    )


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
