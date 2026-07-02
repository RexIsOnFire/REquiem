"""Minimal embedded ATT&CK technique catalog.

Just enough of the enterprise matrix for the techniques ReQuiem infers, so the
report and heatmap can render tactic/name without a network dependency. Extend
freely; the heatmap renders whatever tactics appear here.
"""
from __future__ import annotations

# technique_id -> (name, tactic)
CATALOG: dict[str, tuple[str, str]] = {
    # --- Initial Access ---
    "T1189": ("Drive-by Compromise", "Initial Access"),
    "T1190": ("Exploit Public-Facing Application", "Initial Access"),
    "T1133": ("External Remote Services", "Initial Access"),
    "T1566": ("Phishing", "Initial Access"),
    "T1566.001": ("Spearphishing Attachment", "Initial Access"),
    "T1091": ("Replication Through Removable Media", "Initial Access"),
    "T1195": ("Supply Chain Compromise", "Initial Access"),

    # --- Execution ---
    "T1059": ("Command and Scripting Interpreter", "Execution"),
    "T1059.001": ("PowerShell", "Execution"),
    "T1059.003": ("Windows Command Shell", "Execution"),
    "T1059.005": ("Visual Basic", "Execution"),
    "T1059.006": ("Python", "Execution"),
    "T1059.007": ("JavaScript", "Execution"),
    "T1106": ("Native API", "Execution"),
    "T1129": ("Shared Modules", "Execution"),
    "T1203": ("Exploitation for Client Execution", "Execution"),
    "T1204": ("User Execution", "Execution"),
    "T1204.001": ("Malicious Link", "Execution"),
    "T1204.002": ("Malicious File", "Execution"),
    "T1047": ("Windows Management Instrumentation", "Execution"),
    "T1053": ("Scheduled Task/Job", "Execution"),
    "T1569": ("System Services", "Execution"),
    "T1569.002": ("Service Execution", "Execution"),
    "T1064": ("Scripting", "Execution"),

    # --- Persistence ---
    "T1547": ("Boot or Logon Autostart Execution", "Persistence"),
    "T1547.001": ("Registry Run Keys / Startup Folder", "Persistence"),
    "T1053.005": ("Scheduled Task", "Persistence"),
    "T1543": ("Create or Modify System Process", "Persistence"),
    "T1543.003": ("Windows Service", "Persistence"),
    "T1136": ("Create Account", "Persistence"),
    "T1546": ("Event Triggered Execution", "Persistence"),
    "T1574": ("Hijack Execution Flow", "Persistence"),
    "T1574.001": ("DLL Search Order Hijacking", "Persistence"),
    "T1574.002": ("DLL Side-Loading", "Persistence"),
    "T1574.010": ("Services File Permissions Weakness", "Persistence"),
    "T1197": ("BITS Jobs", "Persistence"),
    "T1505.003": ("Web Shell", "Persistence"),

    # --- Privilege Escalation ---
    "T1548": ("Abuse Elevation Control Mechanism", "Privilege Escalation"),
    "T1548.002": ("Bypass User Account Control", "Privilege Escalation"),
    "T1134": ("Access Token Manipulation", "Privilege Escalation"),
    "T1068": ("Exploitation for Privilege Escalation", "Privilege Escalation"),

    # --- Defense Evasion ---
    "T1055": ("Process Injection", "Defense Evasion"),
    "T1055.001": ("DLL Injection", "Defense Evasion"),
    "T1055.002": ("PE Injection", "Defense Evasion"),
    "T1055.003": ("Thread Execution Hijacking", "Defense Evasion"),
    "T1055.004": ("Asynchronous Procedure Call", "Defense Evasion"),
    "T1055.005": ("Thread Local Storage", "Defense Evasion"),
    "T1055.012": ("Process Hollowing", "Defense Evasion"),
    "T1027": ("Obfuscated Files or Information", "Defense Evasion"),
    "T1027.002": ("Software Packing", "Defense Evasion"),
    "T1027.004": ("Compile After Delivery", "Defense Evasion"),
    "T1027.005": ("Indicator Removal from Tools", "Defense Evasion"),
    "T1027.009": ("Embedded Payloads", "Defense Evasion"),
    "T1027.013": ("Encrypted/Encoded File", "Defense Evasion"),
    "T1027.016": ("Junk Code Insertion", "Defense Evasion"),
    "T1140": ("Deobfuscate/Decode Files or Information", "Defense Evasion"),
    "T1497": ("Virtualization/Sandbox Evasion", "Defense Evasion"),
    "T1497.001": ("System Checks", "Defense Evasion"),
    "T1562": ("Impair Defenses", "Defense Evasion"),
    "T1562.001": ("Disable or Modify Tools", "Defense Evasion"),
    "T1070": ("Indicator Removal", "Defense Evasion"),
    "T1070.004": ("File Deletion", "Defense Evasion"),
    "T1112": ("Modify Registry", "Defense Evasion"),
    "T1036": ("Masquerading", "Defense Evasion"),
    "T1036.005": ("Match Legitimate Name or Location", "Defense Evasion"),
    "T1564": ("Hide Artifacts", "Defense Evasion"),
    "T1564.001": ("Hidden Files and Directories", "Defense Evasion"),
    "T1620": ("Reflective Code Loading", "Defense Evasion"),
    "T1218": ("System Binary Proxy Execution", "Defense Evasion"),
    "T1222": ("File and Directory Permissions Modification", "Defense Evasion"),
    "T1202": ("Indirect Command Execution", "Defense Evasion"),
    "T1480": ("Execution Guardrails", "Defense Evasion"),

    # --- Credential Access ---
    "T1003": ("OS Credential Dumping", "Credential Access"),
    "T1003.001": ("LSASS Memory", "Credential Access"),
    "T1552": ("Unsecured Credentials", "Credential Access"),
    "T1552.001": ("Credentials In Files", "Credential Access"),
    "T1555": ("Credentials from Password Stores", "Credential Access"),
    "T1555.003": ("Credentials from Web Browsers", "Credential Access"),
    "T1056": ("Input Capture", "Credential Access"),
    "T1056.001": ("Keylogging", "Credential Access"),
    "T1539": ("Steal Web Session Cookie", "Credential Access"),
    "T1110": ("Brute Force", "Credential Access"),

    # --- Discovery ---
    "T1010": ("Application Window Discovery", "Discovery"),
    "T1012": ("Query Registry", "Discovery"),
    "T1016": ("System Network Configuration Discovery", "Discovery"),
    "T1018": ("Remote System Discovery", "Discovery"),
    "T1033": ("System Owner/User Discovery", "Discovery"),
    "T1057": ("Process Discovery", "Discovery"),
    "T1082": ("System Information Discovery", "Discovery"),
    "T1083": ("File and Directory Discovery", "Discovery"),
    "T1087": ("Account Discovery", "Discovery"),
    "T1135": ("Network Share Discovery", "Discovery"),
    "T1518": ("Software Discovery", "Discovery"),
    "T1518.001": ("Security Software Discovery", "Discovery"),
    "T1614": ("System Location Discovery", "Discovery"),
    "T1124": ("System Time Discovery", "Discovery"),
    "T1046": ("Network Service Discovery", "Discovery"),

    # --- Lateral Movement ---
    "T1021": ("Remote Services", "Lateral Movement"),
    "T1021.001": ("Remote Desktop Protocol", "Lateral Movement"),
    "T1021.002": ("SMB/Windows Admin Shares", "Lateral Movement"),
    "T1570": ("Lateral Tool Transfer", "Lateral Movement"),

    # --- Collection ---
    "T1005": ("Data from Local System", "Collection"),
    "T1113": ("Screen Capture", "Collection"),
    "T1114": ("Email Collection", "Collection"),
    "T1115": ("Clipboard Data", "Collection"),
    "T1560": ("Archive Collected Data", "Collection"),
    "T1119": ("Automated Collection", "Collection"),

    # --- Command and Control ---
    "T1071": ("Application Layer Protocol", "Command and Control"),
    "T1071.001": ("Web Protocols (C2)", "Command and Control"),
    "T1071.004": ("DNS", "Command and Control"),
    "T1095": ("Non-Application Layer Protocol", "Command and Control"),
    "T1105": ("Ingress Tool Transfer", "Command and Control"),
    "T1571": ("Non-Standard Port", "Command and Control"),
    "T1573": ("Encrypted Channel", "Command and Control"),
    "T1573.001": ("Symmetric Cryptography", "Command and Control"),
    "T1573.002": ("Asymmetric Cryptography", "Command and Control"),
    "T1090": ("Proxy", "Command and Control"),
    "T1090.003": ("Multi-hop Proxy", "Command and Control"),
    "T1132": ("Data Encoding", "Command and Control"),
    "T1219": ("Remote Access Software", "Command and Control"),
    "T1568": ("Dynamic Resolution", "Command and Control"),
    "T1102": ("Web Service", "Command and Control"),

    # --- Exfiltration ---
    "T1041": ("Exfiltration Over C2 Channel", "Exfiltration"),
    "T1048": ("Exfiltration Over Alternative Protocol", "Exfiltration"),
    "T1567": ("Exfiltration Over Web Service", "Exfiltration"),

    # --- Impact ---
    "T1486": ("Data Encrypted for Impact", "Impact"),
    "T1490": ("Inhibit System Recovery", "Impact"),
    "T1489": ("Service Stop", "Impact"),
    "T1485": ("Data Destruction", "Impact"),
    "T1491": ("Defacement", "Impact"),
    "T1496": ("Resource Hijacking", "Impact"),
    "T1529": ("System Shutdown/Reboot", "Impact"),
}

# Canonical tactic order for heatmap columns.
TACTIC_ORDER = [
    "Initial Access", "Execution", "Persistence", "Privilege Escalation",
    "Defense Evasion", "Credential Access", "Discovery", "Lateral Movement",
    "Collection", "Command and Control", "Exfiltration", "Impact",
]

# Sub-technique parents inherit the parent's tactic when the exact id is absent.
def resolve(technique_id: str) -> tuple[str, str]:
    hit = CATALOG.get(technique_id)
    if hit:
        return hit
    # Fall back to the base technique for an unknown sub-technique (T1055.099
    # -> T1055's tactic), so the heatmap places it correctly instead of Unknown.
    if "." in technique_id:
        base = technique_id.split(".", 1)[0]
        parent = CATALOG.get(base)
        if parent:
            return (technique_id, parent[1])
    return (technique_id, "Unknown")
