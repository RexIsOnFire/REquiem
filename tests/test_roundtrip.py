"""Tests for report dict round-trip and ATT&CK catalog coverage."""
from requiem import analyze
from requiem.attack import techniques
from requiem.core.models import AnalysisReport, Confidence


def _sample_report() -> AnalysisReport:
    import struct
    def align(n, a=0x200):
        return (n + a - 1) // a * a
    body = (b"runtime.morestack\x00go1.21\x00Your files have been encrypted decrypt\x00"
            b"1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa\x00vssadmin delete shadows\x00CryptEncrypt\x00")
    sec = [(b".text\x00\x00\x00", body + b"\x90" * 0x200, 0x60000020)]
    mz = b"MZ" + b"\x00" * 0x3a + struct.pack("<I", 0x80)
    mz += b"\x00" * (0x80 - len(mz))
    coff = struct.pack("<H H I I I H H", 0x8664, len(sec), 0, 0, 0, 0xE0, 0x22)
    opt = (struct.pack("<H B B I I I I I", 0x20B, 14, 0, 0x400, 0, 0, 0x1000, 0)
           + struct.pack("<Q", 0x140000000) + struct.pack("<I I", 0x1000, 0x200))
    opt += b"\x00" * (0xE0 - len(opt))
    h = mz + b"PE\x00\x00" + coff + opt
    rp = align(len(h) + 40 * len(sec))
    sh = b""; blobs = b""; cur = rp; va = 0x1000
    for n, d, cflag in sec:
        rs = align(len(d))
        sh += struct.pack("<8s I I I I I I H H I", n, len(d), va, rs, cur, 0, 0, 0, 0, cflag)
        blobs += d + b"\x00" * (rs - len(d)); cur += rs; va += align(len(d), 0x1000)
    return analyze(h + sh + b"\x00" * (rp - len(h + sh)) + blobs, "s.exe")


def test_report_from_dict_roundtrips():
    report = _sample_report()
    clone = AnalysisReport.from_dict(report.to_dict())
    assert clone.verdict == report.verdict
    assert clone.identity.sha256 == report.identity.sha256
    assert clone.verdict_confidence == report.verdict_confidence
    assert isinstance(clone.verdict_confidence, Confidence)
    assert len(clone.findings) == len(report.findings)
    assert len(clone.sections) == len(report.sections)
    # Re-serializing the clone matches the original dict.
    assert clone.to_dict() == report.to_dict()


def test_from_dict_enables_html_render():
    from requiem.report import html
    report = _sample_report()
    clone = AnalysisReport.from_dict(report.to_dict())
    out = html.render(clone)
    assert report.verdict in out.lower() or report.verdict.upper() in out


# --- ATT&CK catalog coverage ---------------------------------------------
def test_catalog_is_comprehensive():
    # The catalog must cover the common techniques cloud sandboxes return, so
    # the heatmap never dumps them into "Unknown".
    assert len(techniques.CATALOG) >= 120
    for tid in ("T1003", "T1005", "T1016", "T1112", "T1071", "T1573",
                "T1569.002", "T1027.005", "T1486", "T1055"):
        name, tactic = techniques.resolve(tid)
        assert tactic != "Unknown", f"{tid} unresolved"


def test_unknown_subtechnique_inherits_parent_tactic():
    # An unlisted sub-technique falls back to its parent's tactic.
    name, tactic = techniques.resolve("T1055.099")
    assert tactic == "Defense Evasion"


def test_truly_unknown_is_flagged():
    name, tactic = techniques.resolve("T9999")
    assert tactic == "Unknown"
