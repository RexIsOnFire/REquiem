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
    Severity,
)
from .base import DynamicBackend


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
        return beh

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
