"""End-to-end and unit tests for the ReQuiem pipeline."""
from requiem import PipelineOptions, analyze
from requiem.core.models import Confidence
from requiem.core.triage import shannon_entropy, triage
from requiem.static.strings_ioc import harvest_iocs


# --- triage --------------------------------------------------------------
def test_entropy_bounds():
    assert shannon_entropy(b"") == 0.0
    assert shannon_entropy(b"\x00" * 1000) == 0.0
    assert shannon_entropy(bytes(range(256)) * 8) > 7.9  # near-max for uniform bytes


def test_triage_detects_pe(go_ransomware_pe):
    ident = triage(go_ransomware_pe, "s.exe")
    assert ident.format == "pe"
    assert ident.bitness == 64
    assert ident.arch == "x64"
    assert len(ident.sha256) == 64


def test_triage_unknown_blob():
    ident = triage(b"not an executable at all" * 10, "x.bin")
    assert ident.format in ("unknown", "script")


# --- IOC extraction ------------------------------------------------------
def test_ioc_harvest():
    strings = [
        "connect to http://malicious.example.com/payload now",
        "backup ip 8.8.8.8 fallback",
        "pay to 1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa please",
        "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\evil",
    ]
    iocs = harvest_iocs(strings)
    assert any("malicious.example.com" in u for u in iocs.urls)
    assert "8.8.8.8" in iocs.ipv4
    assert iocs.bitcoin
    assert iocs.registry_keys


def test_ioc_url_host_not_double_counted():
    iocs = harvest_iocs(["visit http://foo.example.com/path"])
    assert "foo.example.com" not in iocs.domains  # it's the URL host


# --- language fingerprinting --------------------------------------------
def test_go_detected_with_high_confidence(go_ransomware_pe):
    report = analyze(go_ransomware_pe, "s.exe", PipelineOptions(run_dynamic=False))
    top = report.languages[0]
    assert top.language == "Go"
    assert top.confidence >= Confidence.HIGH
    assert top.compiler and "Go" in top.compiler
    assert top.evidence  # explainability: evidence must be present


# --- packer --------------------------------------------------------------
def test_high_entropy_section_flags_packer(go_ransomware_pe):
    report = analyze(go_ransomware_pe, "s.exe", PipelineOptions(run_dynamic=False))
    assert report.packers  # the random .packed section should trip the heuristic


# --- full verdict --------------------------------------------------------
def test_ransomware_verdict(go_ransomware_pe):
    report = analyze(go_ransomware_pe, "s.exe")
    assert report.verdict == "malicious"
    assert report.classification == "ransomware"
    assert report.attack, "expected ATT&CK techniques"
    assert "T1486" in {a.technique_id for a in report.attack}  # data encrypted for impact
    assert report.summary and "ransomware" in report.summary.lower()


def test_benign_is_not_malicious(benign_pe):
    report = analyze(benign_pe, "ok.exe")
    assert report.verdict in ("benign", "suspicious")
    assert report.classification is None


def test_every_finding_has_evidence(go_ransomware_pe):
    report = analyze(go_ransomware_pe, "s.exe")
    for f in report.findings:
        assert f.evidence, f"finding {f.title!r} lacks evidence"


def test_report_is_json_serializable(go_ransomware_pe):
    import json
    report = analyze(go_ransomware_pe, "s.exe")
    blob = json.dumps(report.to_dict())
    assert '"verdict"' in blob


def test_dynamic_results_are_badged_simulated(go_ransomware_pe):
    report = analyze(go_ransomware_pe, "s.exe")
    assert report.dynamic.executed
    assert report.dynamic.simulated is True
    for f in report.dynamic.memory:
        assert "simulated" in f.tags
