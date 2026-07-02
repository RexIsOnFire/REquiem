"""Tests for structured memory-map and heap-timeline generation + rendering."""
from requiem import analyze
from requiem.report import html


def test_memory_map_populated_for_ransomware(go_ransomware_pe):
    report = analyze(go_ransomware_pe, "s.exe")
    regions = report.dynamic.memory_map
    assert regions, "expected a memory map"
    # Standard image regions are always present.
    assert any(r.kind == "image" for r in regions)
    # The crypto/ransomware hint must produce the large private working set.
    big = [r for r in regions if r.kind == "private" and r.suspicious]
    assert big, "expected a suspicious large private commit"
    assert max(r.size for r in big) >= 256 * 1024 * 1024


def test_injection_apis_produce_rwx_region(go_ransomware_pe):
    # The fixture imports CreateRemoteThread/VirtualAllocEx.
    report = analyze(go_ransomware_pe, "s.exe")
    rwx = [r for r in report.dynamic.memory_map if r.protection == "rwx"]
    assert rwx, "expected an unbacked RWX region"
    assert all(not r.backed for r in rwx)
    assert all(r.suspicious for r in rwx)


def test_heap_timeline_is_monotonic_staircase(go_ransomware_pe):
    report = analyze(go_ransomware_pe, "s.exe")
    tl = report.dynamic.heap_timeline
    assert len(tl) >= 4
    # Time strictly increases; committed never decreases.
    assert all(tl[i].t_ms < tl[i + 1].t_ms for i in range(len(tl) - 1))
    assert all(tl[i].committed <= tl[i + 1].committed for i in range(len(tl) - 1))
    # It climbs into the hundreds of MB (the encryption working set).
    assert max(s.committed for s in tl) >= 256 * 1024 * 1024


def test_benign_heap_is_flat_and_small(benign_pe):
    report = analyze(benign_pe, "ok.exe")
    tl = report.dynamic.heap_timeline
    assert tl
    assert max(s.committed for s in tl) < 64 * 1024 * 1024


def test_memory_sections_render_in_html(go_ransomware_pe):
    report = analyze(go_ransomware_pe, "s.exe")
    out = html.render(report)
    assert "Memory Map" in out
    assert "Heap Growth" in out
    assert "<svg" in out


def test_memory_map_json_serializable(go_ransomware_pe):
    import json
    report = analyze(go_ransomware_pe, "s.exe")
    d = json.loads(json.dumps(report.to_dict()))
    assert d["dynamic"]["memory_map"]
    assert d["dynamic"]["heap_timeline"]
    r0 = d["dynamic"]["memory_map"][0]
    assert {"base", "size", "protection", "kind", "backed", "suspicious"} <= r0.keys()
