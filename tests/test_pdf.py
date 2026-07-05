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
    assert "Ctrl" in out and "P" in out  # print hint (no inline script, per CSP)
    assert "page-break-inside" in out


def test_html_report_has_no_inline_scripts():
    # CSP sets script-src 'none' for API HTML; the report must not carry any
    # <script> or inline event handlers.
    report = analyze(_mini_pe(), "s.exe")
    out = html.render(report)
    assert "<script" not in out.lower()
    assert "onclick=" not in out.lower()
    assert "onerror=" not in out.lower()


def _mini_pe() -> bytes:
    import struct
    def align(n, a=0x200):
        return (n + a - 1) // a * a
    mz = b"MZ" + b"\x00" * 0x3a + struct.pack("<I", 0x80)
    mz += b"\x00" * (0x80 - len(mz))
    coff = struct.pack("<H H I I I H H", 0x8664, 1, 0, 0, 0, 0xE0, 0x22)
    opt = (struct.pack("<H B B I I I I I", 0x20B, 14, 0, 0x400, 0, 0, 0x1000, 0)
           + struct.pack("<Q", 0x140000000) + struct.pack("<I I", 0x1000, 0x200))
    opt += b"\x00" * (0xE0 - len(opt))
    h = mz + b"PE\x00\x00" + coff + opt
    sec = struct.pack("<8s I I I I I I H H I", b".text\x00\x00\x00", 0x200, 0x1000,
                      0x200, 0x400, 0, 0, 0, 0, 0x60000020)
    return h + sec + b"\x00" * (0x400 - len(h + sec)) + b"\x90" * 0x200


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
