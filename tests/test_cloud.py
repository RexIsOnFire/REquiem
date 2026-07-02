"""Tests for by-hash cloud behavior providers (Triage/VT/Hybrid Analysis).

The pure mapping functions are tested against recorded fixtures. HTTP lookups
require credentials, so we test those return graceful CloudLookup(found=False)
when unconfigured.
"""
import json
from pathlib import Path

from requiem.core.models import Severity
from requiem.dynamic import hybrid, triage
from requiem.dynamic.cloud import CloudLookup, first_behavior, gather_cloud_behavior
from requiem.intel import vt_behavior

FIX = Path(__file__).parent / "fixtures"


# --- VirusTotal behaviour_summary mapping --------------------------------
def test_vt_behavior_mapping():
    summary = json.loads((FIX / "vt_behaviour_summary.json").read_text())["data"]
    tree = vt_behavior._process_tree(summary)
    assert tree[0]["name"] == "invoice.exe"
    child_names = {c["name"] for c in tree[0]["children"]}
    assert {"vssadmin.exe", "cmd.exe"} <= child_names

    net = vt_behavior._network(summary)
    kinds = {n["type"] for n in net}
    assert {"http", "dns", "tcp"} <= kinds

    findings = vt_behavior._mitre_findings(summary)
    techniques = {t for f in findings for t in f.attack_techniques}
    assert {"T1486", "T1490", "T1055"} <= techniques
    assert any(f.severity == Severity.HIGH for f in findings)


def test_vt_provider_without_key_is_graceful(monkeypatch):
    monkeypatch.delenv("VT_API_KEY", raising=False)
    lk = vt_behavior.VTBehaviorProvider(api_key="").lookup(sha256="a" * 64)
    assert lk.found is False
    assert "VT_API_KEY" in lk.note


# --- Hybrid Analysis mapping ---------------------------------------------
def test_hybrid_mapping_builds_tree_and_sigs():
    summary = {
        "processes": [
            {"uid": "1", "pid": 100, "name": "a.exe"},
            {"uid": "2", "pid": 120, "parentuid": "1", "name": "child.exe"},
        ],
        "hosts": ["8.8.8.8"],
        "domains": ["evil.example"],
        "signatures": [
            {"name": "ransom", "description": "Ransomware", "threat_level": 3,
             "attck_ids": ["T1486"]},
        ],
    }
    beh = hybrid.HybridAnalysisProvider(api_key="k")
    from requiem.dynamic import normalize as N
    b = N.to_behavior(hybrid.to_normalized(summary), backend_name="hybridanalysis")
    assert b.process_tree[0]["name"] == "a.exe"
    assert b.process_tree[0]["children"][0]["name"] == "child.exe"
    assert any(f.attack_techniques == ["T1486"] for f in b.memory)


def test_hybrid_without_key_is_graceful():
    lk = hybrid.HybridAnalysisProvider(api_key="").lookup(sha256="a" * 64)
    assert lk.found is False
    assert "HYBRIDANALYSIS_API_KEY" in lk.note


# --- Triage by-hash (unconfigured) ---------------------------------------
def test_triage_lookup_without_token_is_graceful():
    lk = triage.TriageBackend(token="").lookup(sha256="a" * 64)
    assert lk.found is False


# --- gatherer / selection ------------------------------------------------
def test_gather_and_first_behavior_picks_richest():
    from requiem.core.models import DynamicBehavior, Finding

    class _Empty:
        name = "empty"
        def lookup(self, *, sha256):
            return CloudLookup(source="empty", found=False, note="nope")

    class _Rich:
        name = "rich"
        def lookup(self, *, sha256):
            b = DynamicBehavior(executed=True, backend="rich", simulated=False)
            b.process_tree = [{"pid": 1, "name": "x", "cmdline": "", "children": []}]
            b.memory = [Finding(title="t", description="d")]
            return CloudLookup(source="rich", found=True, behavior=b)

    lookups = gather_cloud_behavior([_Empty(), _Rich()], sha256="a" * 64)
    assert [lk.found for lk in lookups] == [False, True]
    best = first_behavior(lookups)
    assert best is not None and best.backend == "rich"


def test_first_behavior_none_when_nothing_found():
    lookups = [CloudLookup(source="x", found=False)]
    assert first_behavior(lookups) is None
