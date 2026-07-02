"""Tests for the shared sandbox normalizer and the Joe/Triage adapters.

CAPE already has its own suite (test_cape.py); here we cover the normalization
layer and the two adapters with distinct report shapes, against recorded
fixtures. HTTP submit/poll flow is covered for CAPE in test_cape.py; the same
sandbox_http plumbing backs the others.
"""
import json
from pathlib import Path

import pytest

from requiem.core.models import Severity
from requiem.dynamic import joe, triage
from requiem.dynamic import normalize as N

FIX = Path(__file__).parent / "fixtures"


# --- normalizer core -----------------------------------------------------
def test_protection_normalization():
    assert N.normalize_protection("PAGE_EXECUTE_READWRITE") == "rwx"
    assert N.normalize_protection("PAGE_READONLY") == "r--"
    assert N.normalize_protection(0x40) == "rwx"
    assert N.normalize_protection("0x20") == "r-x"
    assert N.normalize_protection(None) == "rw-"


def test_severity_normalization():
    assert N.norm_severity(3) == "high"
    assert N.norm_severity(9) == "critical"
    assert N.norm_severity("low") == "low"
    assert N.norm_severity(0) == "info"


def test_region_classification_and_heap():
    norm = N.NormalizedReport(regions=[
        N.NormRegion(base=0x400000, size=1 << 20, protection="r-x", path="C:\\a.exe"),
        N.NormRegion(base=0x320000, size=1 << 19, protection="rwx", injected=True),
        N.NormRegion(base=0x3000000, size=300 << 20, protection="rw-"),
    ])
    beh = N.to_behavior(norm, backend_name="x")
    kinds = {r.kind for r in beh.memory_map}
    assert {"image", "shellcode", "private"} <= kinds
    shell = next(r for r in beh.memory_map if r.kind == "shellcode")
    assert shell.suspicious and not shell.backed
    assert max(s.committed for s in beh.heap_timeline) >= 300 << 20


# --- Joe adapter ---------------------------------------------------------
@pytest.fixture
def joe_report():
    return json.loads((FIX / "joe_report.json").read_text())


def test_joe_maps_tree_network_regions_sigs(joe_report):
    beh = N.to_behavior(joe.to_normalized(joe_report), backend_name="joe")
    root = beh.process_tree[0]
    assert root["name"] == "invoice.exe"
    assert {c["name"] for c in root["children"]} == {"vssadmin.exe", "cmd.exe"}
    assert any("185.10.10.5" in n["dest"] for n in beh.network)
    assert any(r.protection == "rwx" and r.suspicious for r in beh.memory_map)
    techniques = {t for f in beh.memory for t in f.attack_techniques}
    assert {"T1486", "T1490"} <= techniques
    assert any(f.severity == Severity.CRITICAL for f in beh.memory)


# --- Triage adapter ------------------------------------------------------
@pytest.fixture
def triage_report():
    return json.loads((FIX / "triage_report.json").read_text())


def test_triage_maps_tree_network_regions_sigs(triage_report):
    beh = N.to_behavior(triage.to_normalized(triage_report), backend_name="triage")
    root = beh.process_tree[0]
    assert root["name"] == "invoice.exe"
    assert {c["name"] for c in root["children"]} == {"vssadmin.exe", "cmd.exe"}
    kinds = {n["type"] for n in beh.network}
    assert {"http", "dns", "tcp"} <= kinds
    assert any(r.protection == "rwx" and r.suspicious for r in beh.memory_map)
    techniques = {t for f in beh.memory for t in f.attack_techniques}
    assert {"T1486", "T1490", "T1055"} <= techniques


def test_adapters_unconfigured_raise():
    from requiem.dynamic.sandbox_http import SandboxError
    from requiem.core.models import FileIdentity
    ident = FileIdentity(filename="s.exe", size=1, md5="a", sha1="b", sha256="c")
    with pytest.raises(SandboxError):
        joe.JoeBackend(url="").detonate(data=b"x", identity=ident)
    with pytest.raises(SandboxError):
        triage.TriageBackend(token="").detonate(data=b"x", identity=ident)


# --- Cuckoo full HTTP flow against an in-process stub --------------------
import threading  # noqa: E402
from http.server import BaseHTTPRequestHandler, HTTPServer  # noqa: E402


class _CuckooStub(BaseHTTPRequestHandler):
    report_json = "{}"

    def log_message(self, *a):
        pass

    def _send(self, obj):
        body = json.dumps(obj).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self):
        self.rfile.read(int(self.headers.get("Content-Length", 0)))
        self._send({"task_id": 77})

    def do_GET(self):
        if "/tasks/view/" in self.path:
            self._send({"task": {"status": "reported"}})
        elif "/tasks/report/" in self.path:
            self._send(json.loads(self.report_json))
        else:
            self.send_error(404)


def test_cuckoo_submit_poll_fetch(cape_report_shared):
    from requiem.dynamic.cuckoo import CuckooBackend
    from requiem.core.models import FileIdentity

    _CuckooStub.report_json = json.dumps(cape_report_shared)
    srv = HTTPServer(("127.0.0.1", 0), _CuckooStub)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    try:
        host, port = srv.server_address
        backend = CuckooBackend(url=f"http://{host}:{port}", timeout=10, poll_interval=0)
        ident = FileIdentity(filename="s.exe", size=1, md5="a", sha1="b", sha256="c")
        beh = backend.detonate(data=b"MZ", identity=ident)
        assert beh.backend == "cuckoo"
        assert beh.simulated is False
        assert beh.process_tree  # parsed via the shared CAPE-shape parser
    finally:
        srv.shutdown()


@pytest.fixture
def cape_report_shared():
    return json.loads((FIX / "cape_report_ransomware.json").read_text())
