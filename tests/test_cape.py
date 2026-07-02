"""Tests for the CAPE sandbox integration.

The mapper is tested against a recorded CAPE report fixture. The backend's
submit/poll/fetch HTTP flow is tested against a tiny in-process HTTP server that
speaks the CAPE apiv2 surface — no live CAPE, fully offline.
"""
import json
import os
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

import pytest

from requiem.core.models import Severity
from requiem.dynamic import cape_map
from requiem.dynamic.cape import CapeBackend, CapeError

FIXTURE = Path(__file__).parent / "fixtures" / "cape_report_ransomware.json"


@pytest.fixture
def cape_report() -> dict:
    return json.loads(FIXTURE.read_text())


# --- mapper --------------------------------------------------------------
def test_map_marks_real_not_simulated(cape_report):
    beh = cape_map.map_report(cape_report)
    assert beh.executed is True
    assert beh.simulated is False
    assert beh.backend == "cape"


def test_map_process_tree_nested(cape_report):
    beh = cape_map.map_report(cape_report)
    root = beh.process_tree[0]
    assert root["name"] == "invoice_8842.exe"
    child_names = {c["name"] for c in root["children"]}
    assert {"vssadmin.exe", "cmd.exe"} <= child_names
    # bcdedit is a grandchild.
    cmd = next(c for c in root["children"] if c["name"] == "cmd.exe")
    assert cmd["children"][0]["name"] == "bcdedit.exe"


def test_map_network(cape_report):
    beh = cape_map.map_report(cape_report)
    kinds = {n["type"] for n in beh.network}
    assert {"http", "dns", "tcp"} <= kinds
    assert any("185.220.101.4" in n["dest"] for n in beh.network)


def test_map_memory_regions(cape_report):
    beh = cape_map.map_report(cape_report)
    # The injected PAGE_EXECUTE_READWRITE region -> suspicious shellcode.
    rwx = [r for r in beh.memory_map if r.protection == "rwx"]
    assert rwx and rwx[0].kind == "shellcode" and rwx[0].suspicious
    assert not rwx[0].backed
    # The image region is file-backed and named.
    img = [r for r in beh.memory_map if r.kind == "image"]
    assert any(r.label == "invoice_8842.exe" for r in img)
    # The 384 MB private commit is present.
    assert any(r.kind == "private" and r.size > 300 * 1024 * 1024 for r in beh.memory_map)


def test_map_heap_from_private_commit(cape_report):
    beh = cape_map.map_report(cape_report)
    assert beh.heap_timeline
    peak = max(s.committed for s in beh.heap_timeline)
    assert peak > 300 * 1024 * 1024


def test_map_signatures_to_findings_with_attack(cape_report):
    beh = cape_map.map_report(cape_report)
    titles = {f.title for f in beh.memory}
    assert any("shadow copies" in t for t in titles)
    techniques = {t for f in beh.memory for t in f.attack_techniques}
    assert {"T1486", "T1490", "T1547.001", "T1055"} <= techniques
    # severity 3 signatures map to HIGH.
    high = [f for f in beh.memory if f.severity == Severity.HIGH]
    assert high


def test_map_empty_report_is_safe():
    beh = cape_map.map_report({})
    assert beh.executed is True
    assert beh.process_tree == []
    assert beh.memory_map == []
    assert beh.memory == []


# --- backend HTTP flow ---------------------------------------------------
class _CapeStub(BaseHTTPRequestHandler):
    report_json = ""

    def log_message(self, *a):  # silence
        pass

    def _send(self, obj):
        body = json.dumps(obj).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self):
        if self.path.startswith("/apiv2/tasks/create/file"):
            length = int(self.headers.get("Content-Length", 0))
            self.rfile.read(length)  # drain upload
            self._send({"error": False, "data": {"task_ids": [4211]}})
        else:
            self.send_error(404)

    def do_GET(self):
        if "/status/" in self.path:
            self._send({"error": False, "data": "reported"})
        elif "/report/" in self.path:
            self._send({"error": False, "data": json.loads(self.report_json)})
        else:
            self.send_error(404)


@pytest.fixture
def cape_server(cape_report):
    _CapeStub.report_json = json.dumps(cape_report)
    srv = HTTPServer(("127.0.0.1", 0), _CapeStub)
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    host, port = srv.server_address
    yield f"http://{host}:{port}"
    srv.shutdown()


def test_backend_submit_poll_fetch_map(cape_server):
    backend = CapeBackend(url=cape_server, timeout=10, poll_interval=0)
    from requiem.core.models import FileIdentity
    ident = FileIdentity(filename="invoice_8842.exe", size=1000,
                         md5="x", sha1="y", sha256="z")
    beh = backend.detonate(data=b"MZ....", identity=ident)
    assert beh.simulated is False
    assert beh.backend == "cape"
    assert beh.process_tree[0]["name"] == "invoice_8842.exe"
    assert any(r.protection == "rwx" for r in beh.memory_map)


def test_backend_unconfigured_raises():
    os.environ.pop("CAPE_URL", None)
    backend = CapeBackend(url="")
    from requiem.core.models import FileIdentity
    ident = FileIdentity(filename="s.exe", size=1, md5="a", sha1="b", sha256="c")
    with pytest.raises(CapeError):
        backend.detonate(data=b"x", identity=ident)
