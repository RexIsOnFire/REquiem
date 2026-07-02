"""Simulated dynamic backend.

Produces a *plausible, clearly-labelled* behavioral trace derived from static
hints — never by executing the sample. Every artifact it emits carries
``simulated=True`` so the report and UI can badge it honestly. This exists so
the dynamic/memory sections of the report are populated for demos and so the
downstream ATT&CK/verdict logic has a realistic shape to consume.

A real sandbox backend replaces this class without any other code change.
"""
from __future__ import annotations

from ..core.models import (
    Confidence,
    DynamicBehavior,
    FileIdentity,
    Finding,
    HeapSample,
    MemoryRegion,
    Severity,
)
from .base import DynamicBackend

_MB = 1024 * 1024


class SimulatedBackend(DynamicBackend):
    name = "simulated"
    simulated = True

    def detonate(self, *, data, identity: FileIdentity, static_hints=None) -> DynamicBehavior:
        hints = static_hints or {}
        imports = {i.lower() for i in hints.get("imports", [])}
        classification = hints.get("classification")
        strings = [s.lower() for s in hints.get("strings", [])]

        beh = DynamicBehavior(executed=True, backend=self.name, simulated=True)

        # --- process tree ------------------------------------------------
        root = {
            "pid": 1000,
            "name": identity.filename,
            "cmdline": identity.filename,
            "children": [],
        }
        if any("shellexecute" in i or "createprocess" in i or "winexec" in i for i in imports):
            root["children"].append({
                "pid": 1001, "name": "cmd.exe",
                "cmdline": "cmd.exe /c <inferred>", "children": [],
            })
        if any("powershell" in s for s in strings):
            root["children"].append({
                "pid": 1002, "name": "powershell.exe",
                "cmdline": "powershell -enc <base64>", "children": [],
            })
        beh.process_tree = [root]

        # --- network -----------------------------------------------------
        for url in hints.get("urls", [])[:5]:
            beh.network.append({"type": "http", "dest": url, "note": "C2/download (inferred)"})
        for ip in hints.get("ipv4", [])[:5]:
            beh.network.append({"type": "tcp", "dest": ip, "note": "outbound connection (inferred)"})

        # --- filesystem / registry --------------------------------------
        if classification == "ransomware":
            beh.filesystem.append({"op": "enumerate", "path": "C:\\Users\\*\\Documents"})
            beh.filesystem.append({"op": "write", "path": "*.encrypted", "count": "many"})
            beh.filesystem.append({"op": "create", "path": "README_RECOVER.txt"})
        for reg in hints.get("registry_keys", [])[:5]:
            beh.registry.append({"op": "set", "key": reg})

        # --- memory findings (the ransomware-heap story) ----------------
        beh.memory = self._memory_findings(imports, classification)
        beh.memory_map = self._memory_map(imports, classification, hints.get("packed", False))
        beh.heap_timeline = self._heap_timeline(imports, classification)
        return beh

    def _memory_map(
        self, imports: set[str], classification: str | None, packed: bool
    ) -> list[MemoryRegion]:
        """A plausible address-space snapshot keyed off static hints.

        Always includes the image + standard runtime DLLs. Adds an unbacked RWX
        region when injection APIs are present (shellcode/unpacking), and a
        large private commit when crypto/ransomware behavior is indicated (the
        bulk-encryption working set).
        """
        regions: list[MemoryRegion] = [
            MemoryRegion(base=0x140000000, size=2 * _MB, protection="r-x",
                         kind="image", backed=True, label="sample.exe (.text)"),
            MemoryRegion(base=0x140200000, size=1 * _MB, protection="rw-",
                         kind="image", backed=True, label="sample.exe (.data)"),
            MemoryRegion(base=0x7FF800000000, size=1 * _MB, protection="r-x",
                         kind="image", backed=True, label="ntdll.dll"),
            MemoryRegion(base=0x7FF810000000, size=1 * _MB, protection="r-x",
                         kind="image", backed=True, label="kernel32.dll"),
            MemoryRegion(base=0x10000, size=256 * 1024, protection="rw-",
                         kind="stack", backed=False, label="thread stack"),
        ]

        injects = any(k in i for i in imports
                      for k in ("virtualallocex", "writeprocessmemory",
                                "createremotethread", "ntmapviewofsection"))
        if injects or packed:
            regions.append(MemoryRegion(
                base=0x2A0000, size=512 * 1024, protection="rwx",
                kind="shellcode", backed=False,
                label="unbacked RWX (unpacked/injected payload)", suspicious=True))

        if classification == "ransomware" or any("crypt" in i for i in imports):
            regions.append(MemoryRegion(
                base=0x20000000, size=512 * _MB, protection="rw-",
                kind="private", backed=False,
                label="private commit — file-encryption working set",
                suspicious=True))

        regions.sort(key=lambda r: r.base)
        return regions

    def _heap_timeline(
        self, imports: set[str], classification: str | None
    ) -> list[HeapSample]:
        """Committed-heap-over-time curve. Flat for benign; a rising staircase
        with annotated events for the ransomware-encryption workload."""
        ransomware = classification == "ransomware" or any("crypt" in i for i in imports)
        if not ransomware:
            # Benign baseline: small, stable heap.
            return [HeapSample(t_ms=t, committed=8 * _MB) for t in (0, 500, 1000, 1500, 2000)]

        # Staircase: process init -> AES loop begins -> bulk growth -> plateau.
        return [
            HeapSample(t_ms=0, committed=8 * _MB, note="process init"),
            HeapSample(t_ms=400, committed=24 * _MB, note="key material + buffers"),
            HeapSample(t_ms=700, committed=80 * _MB, note="AES loop begins"),
            HeapSample(t_ms=1100, committed=300 * _MB),
            HeapSample(t_ms=1500, committed=512 * _MB, note="512 MB working set"),
            HeapSample(t_ms=2000, committed=512 * _MB, note="plateau — bulk encryption"),
        ]

    def _memory_findings(self, imports: set[str], classification: str | None) -> list[Finding]:
        findings: list[Finding] = []

        rwx = Finding(
            title="RWX memory region observed",
            description="A memory region was allocated read/write/execute — common in "
                        "unpackers and shellcode loaders.",
            confidence=Confidence.MEDIUM, severity=Severity.MEDIUM,
            attack_techniques=["T1055"], tags=["memory", "simulated"],
        )
        rwx.add("VirtualAlloc(PAGE_EXECUTE_READWRITE) traced during unpacking",
                source="simulated")
        findings.append(rwx)

        if any("crypt" in i or "bcrypt" in i for i in imports) or classification == "ransomware":
            heap = Finding(
                title="Large heap allocations + AES routines",
                description="Repeated multi-megabyte heap allocations were observed alongside "
                            "AES key-schedule and block-encrypt routines — the shape of a bulk "
                            "file-encryption workload.",
                confidence=Confidence.HIGH if classification == "ransomware" else Confidence.MEDIUM,
                severity=Severity.HIGH,
                attack_techniques=["T1486"], tags=["memory", "crypto", "simulated"],
            )
            heap.add("Heap grew in ~512 MB increments during execution", source="simulated")
            heap.add("AES-NI (AESENC) instructions executed in a tight loop", source="simulated")
            findings.append(heap)

        if classification == "ransomware":
            loop = Finding(
                title="File-encryption loop confirmed",
                description="A read → encrypt → write → rename loop iterated across user "
                            "directories, consistent with ransomware.",
                confidence=Confidence.HIGH, severity=Severity.CRITICAL,
                attack_techniques=["T1486"], tags=["memory", "ransomware", "simulated"],
            )
            loop.add("Sequential ReadFile/WriteFile pairs over enumerated user files",
                     source="simulated")
            findings.append(loop)

        return findings
