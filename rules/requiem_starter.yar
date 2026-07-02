/*
 * ReQuiem starter YARA ruleset.
 * Broad, low-false-positive behavioral rules used to seed the workbench.
 * These are triage aids, not high-fidelity family signatures.
 */

rule ReQuiem_Suspicious_UPX
{
    meta:
        description = "UPX packing markers"
        author = "ReQuiem"
    strings:
        $a = "UPX!"
        $b = "UPX0"
        $c = "UPX1"
    condition:
        2 of them
}

rule ReQuiem_Ransomware_NoteMarkers
{
    meta:
        description = "Common ransom-note / extortion phrasing"
        author = "ReQuiem"
    strings:
        $a = "your files have been encrypted" nocase
        $b = "decrypt" nocase
        $c = "bitcoin" nocase
        $d = ".onion" nocase
        $e = "recover your files" nocase
    condition:
        3 of them
}

rule ReQuiem_Crypto_Constants
{
    meta:
        description = "AES / RSA related routine names and constants"
        author = "ReQuiem"
    strings:
        $aes1 = "AES" fullword
        $aes2 = "CryptEncrypt"
        $aes3 = "CryptGenKey"
        $aes4 = "BCryptEncrypt"
        $rsa1 = "RSA"
        $sbox = { 63 7c 77 7b f2 6b 6f c5 }   // AES S-box prefix
    condition:
        $sbox or 3 of ($aes*, $rsa*)
}

rule ReQuiem_Persistence_RunKey
{
    meta:
        description = "Registry Run-key persistence strings"
        author = "ReQuiem"
    strings:
        $a = "Software\\Microsoft\\Windows\\CurrentVersion\\Run" nocase
        $b = "RegSetValue"
        $c = "RegCreateKey"
    condition:
        $a and 1 of ($b, $c)
}

rule ReQuiem_CredentialAccess_LSASS
{
    meta:
        description = "LSASS credential-dumping indicators"
        author = "ReQuiem"
    strings:
        $a = "lsass" nocase
        $b = "MiniDumpWriteDump"
        $c = "sekurlsa"
    condition:
        2 of them
}
