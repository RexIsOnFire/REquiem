/*
 * ReQuiem family-level YARA signatures.
 *
 * These are triage-grade family heuristics — each carries a rich meta: block
 * (family, malware_type, severity, attack) that ReQuiem folds into the verdict,
 * classification, and an explainable finding. They favour low false positives
 * over exhaustive coverage; extend per your threat model.
 */

rule ReQuiem_Ransom_WannaCry
{
    meta:
        family = "WannaCry"
        malware_type = "ransomware"
        description = "WannaCry ransomware indicators (kill-switch domain, ext, ransom UI)"
        severity = "critical"
        attack = "T1486 T1490 T1083"
        reference = "abuse.ch / public reporting"
    strings:
        $killswitch = "iuqerfsodp9ifjaposdfjhgosurijfaewrwergwea.com" nocase
        $ext = ".WNCRY" nocase
        $note = "@WanaDecryptor@" nocase
        $wcry = "WANACRY!" nocase
        $tor = "taskdl.exe" nocase
    condition:
        2 of them
}

rule ReQuiem_Ransom_LockBit
{
    meta:
        family = "LockBit"
        malware_type = "ransomware"
        description = "LockBit ransomware note / extension markers"
        severity = "critical"
        attack = "T1486 T1490"
    strings:
        $note = "Restore-My-Files.txt" nocase
        $note2 = "LockBit" nocase
        $ext = ".lockbit" nocase
        $onion = ".onion" nocase
        $enc = "your files are encrypted" nocase
    condition:
        ($note or $note2 or $ext) and 1 of ($onion, $enc)
}

rule ReQuiem_Ransom_Generic
{
    meta:
        family = "generic-ransomware"
        malware_type = "ransomware"
        description = "Generic ransomware behavior: extortion note + shadow-copy deletion"
        severity = "high"
        attack = "T1486 T1490"
    strings:
        $a = "your files have been encrypted" nocase
        $b = "vssadmin" nocase
        $c = "delete shadows" nocase
        $d = "bitcoin" nocase
        $e = "recover your files" nocase
    condition:
        $a and 2 of ($b, $c, $d, $e)
}

rule ReQuiem_Stealer_RedLine
{
    meta:
        family = "RedLine"
        malware_type = "infostealer"
        description = "RedLine Stealer strings (browser/wallet/credential harvesting)"
        severity = "high"
        attack = "T1555.003 T1005 T1552.001"
    strings:
        $a = "RedLine" nocase
        $b = "\\Login Data" nocase
        $c = "wallet.dat" nocase
        $d = "Autofill" nocase
        $e = "SELECT origin_url" nocase
    condition:
        $a and 1 of ($b, $c, $d, $e) or 3 of ($b, $c, $d, $e)
}

rule ReQuiem_Stealer_Agent
{
    meta:
        family = "generic-stealer"
        malware_type = "infostealer"
        description = "Credential/browser data theft indicators"
        severity = "high"
        attack = "T1555.003 T1005"
    strings:
        $a = "\\Google\\Chrome\\User Data" nocase
        $b = "moz_cookies" nocase
        $c = "Local State" nocase
        $d = "encrypted_key" nocase
        $e = "cardNumber" nocase
    condition:
        3 of them
}

rule ReQuiem_Loader_Shellcode
{
    meta:
        family = "generic-loader"
        malware_type = "loader"
        description = "Reflective/loader indicators: allocate-write-execute + resolve"
        severity = "high"
        attack = "T1055 T1620"
    strings:
        $a = "VirtualAlloc" nocase
        $b = "WriteProcessMemory" nocase
        $c = "CreateRemoteThread" nocase
        $d = "LoadLibraryA" nocase
        $e = "GetProcAddress" nocase
    condition:
        3 of them
}

rule ReQuiem_RAT_Generic
{
    meta:
        family = "generic-rat"
        malware_type = "rat"
        description = "Remote-access-trojan command/keylog/screencap indicators"
        severity = "high"
        attack = "T1219 T1056.001 T1113 T1071.001"
    strings:
        $a = "keylogger" nocase
        $b = "screenshot" nocase
        $c = "cmd.exe /c" nocase
        $d = "GetAsyncKeyState"
        $e = "/c ping 127.0.0.1" nocase
    condition:
        3 of them
}
