"""Tests for PDF report generation and its graceful fallback."""
import pytest

from requiem import analyze
from requiem.report import html, pdf


def test_html_report_is_print_ready(go_ransomware_pe):
    report = analyze(go_ransomware_pe, "s.exe")
    out = html.render(report)
    # The single HTML source must carry the print stylesheet and PDF affordance.
    assert "@media print" in out
    assert "print-color-adjust" in out
    assert "window.print()" in out
    assert "page-break-inside" in out


def test_available_backend_returns_name_or_none():
    # Whatever the environment, it must be one of the known values.
    assert pdf.available_backend() in (None, "weasyprint", "playwright")


def test_render_pdf_or_graceful_unavailable(go_ransomware_pe):
    report = analyze(go_ransomware_pe, "s.exe")
    if pdf.available_backend() is None:
        with pytest.raises(pdf.PDFUnavailable) as exc:
            pdf.render_pdf(report)
        # The error must tell the user how to fix it.
        assert "install" in str(exc.value).lower()
    else:
        data = pdf.render_pdf(report)
        assert data[:4] == b"%PDF"
        assert len(data) > 1000


def test_pdf_unavailable_is_runtimeerror():
    # Callers may catch RuntimeError generically.
    assert issubclass(pdf.PDFUnavailable, RuntimeError)
