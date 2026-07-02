"""Minimal embedded ATT&CK technique catalog.

Just enough of the enterprise matrix for the techniques ReQuiem infers, so the
report and heatmap can render tactic/name without a network dependency. Extend
freely; the heatmap renders whatever tactics appear here.
"""
from __future__ import annotations

# technique_id -> (name, tactic)
CATALOG: dict[str, tuple[str, str]] = {
    "T1059.001": ("PowerShell", "Execution"),
    "T1059.003": ("Windows Command Shell", "Execution"),
    "T1106": ("Native API", "Execution"),
    "T1204.002": ("Malicious File", "Execution"),

    "T1547.001": ("Registry Run Keys / Startup Folder", "Persistence"),
    "T1053.005": ("Scheduled Task", "Persistence"),
    "T1543.003": ("Windows Service", "Persistence"),
    "T1574.002": ("DLL Side-Loading", "Persistence"),

    "T1055": ("Process Injection", "Defense Evasion"),
    "T1055.001": ("DLL Injection", "Defense Evasion"),
    "T1027": ("Obfuscated Files or Information", "Defense Evasion"),
    "T1027.002": ("Software Packing", "Defense Evasion"),
    "T1140": ("Deobfuscate/Decode Files or Information", "Defense Evasion"),
    "T1497": ("Virtualization/Sandbox Evasion", "Defense Evasion"),
    "T1562.001": ("Disable or Modify Tools", "Defense Evasion"),

    "T1003.001": ("LSASS Memory", "Credential Access"),
    "T1552.001": ("Credentials In Files", "Credential Access"),
    "T1056.001": ("Keylogging", "Credential Access"),

    "T1082": ("System Information Discovery", "Discovery"),
    "T1083": ("File and Directory Discovery", "Discovery"),
    "T1057": ("Process Discovery", "Discovery"),
    "T1518.001": ("Security Software Discovery", "Discovery"),

    "T1071.001": ("Web Protocols (C2)", "Command and Control"),
    "T1105": ("Ingress Tool Transfer", "Command and Control"),
    "T1571": ("Non-Standard Port", "Command and Control"),

    "T1486": ("Data Encrypted for Impact", "Impact"),
    "T1490": ("Inhibit System Recovery", "Impact"),
    "T1489": ("Service Stop", "Impact"),

    "T1041": ("Exfiltration Over C2 Channel", "Exfiltration"),
}

# Canonical tactic order for heatmap columns.
TACTIC_ORDER = [
    "Initial Access", "Execution", "Persistence", "Privilege Escalation",
    "Defense Evasion", "Credential Access", "Discovery", "Lateral Movement",
    "Collection", "Command and Control", "Exfiltration", "Impact",
]


def resolve(technique_id: str) -> tuple[str, str]:
    return CATALOG.get(technique_id, (technique_id, "Unknown"))
