"""Real signature engine — YARA-style rules in pure Python.

Each rule matches real byte/string patterns in the artifact and carries a risk
weight (0..1, combined via noisy-OR by the engine) plus MITRE ATT&CK mappings.
This is genuine signature-based detection over the actual content; it is not a
trained classifier and is not a substitute for a production AV engine.
"""
from __future__ import annotations

import re
from typing import Any, Dict, List

# EICAR standard antivirus test string — a definitive, safe positive.
_EICAR = rb"X5O!P%@AP\[4\\PZX54\(P\^\)7CC\)7\}\$EICAR"

# rule = (name, weight, [compiled patterns], description, [ttps])
def _rx(p):
    return re.compile(p, re.I)


_RULES = [
    ("EICAR_Test_File", 1.0, [re.compile(_EICAR)],
     "EICAR antivirus test signature present.", ["T1027"]),

    ("Embedded_PE_Executable", 0.55, [re.compile(rb"MZ.{60,400}?PE\x00\x00", re.S)],
     "Embedded Windows PE/MZ executable found inside the artifact.", ["T1027", "T1204.002"]),

    ("PowerShell_Encoded_Command", 0.5, [
        _rx(rb"powershell(\.exe)?[^\n]{0,80}-e(nc|ncodedcommand)?\b"),
        _rx(rb"FromBase64String"),
    ], "PowerShell base64/encoded command — common obfuscated execution.", ["T1059.001", "T1027"]),

    ("PowerShell_Hidden_Exec", 0.35, [
        _rx(rb"powershell[^\n]{0,40}-(w|windowstyle)\s*hidden"),
        _rx(rb"powershell[^\n]{0,40}-nop\b"),
        _rx(rb"-ExecutionPolicy\s+Bypass"),
    ], "Hidden / no-profile / bypass PowerShell launch.", ["T1059.001", "T1564.003"]),

    ("Download_And_Execute", 0.4, [
        _rx(rb"(DownloadString|DownloadFile|Net\.WebClient|Invoke-WebRequest|certutil\b.{0,40}-urlcache|bitsadmin)"),
        _rx(rb"Start-Process|Invoke-Expression|\biex\b"),
    ], "Download-and-execute / remote payload retrieval pattern.", ["T1105", "T1059"]),

    ("Script_Obfuscation", 0.32, [
        _rx(rb"eval\s*\("), _rx(rb"unescape\s*\("), _rx(rb"String\.fromCharCode"),
        _rx(rb"document\.write\s*\("), _rx(rb"atob\s*\("), _rx(rb"ActiveXObject"),
    ], "JavaScript/JScript obfuscation & dynamic evaluation.", ["T1059.007", "T1027"]),

    ("Process_Injection_API", 0.42, [
        _rx(rb"VirtualAlloc(Ex)?"), _rx(rb"WriteProcessMemory"),
        _rx(rb"CreateRemoteThread"), _rx(rb"NtUnmapViewOfSection"), _rx(rb"SetThreadContext"),
    ], "Process-injection / hollowing API references.", ["T1055", "T1055.012"]),

    ("Registry_Run_Persistence", 0.35, [
        _rx(rb"CurrentVersion\\Run"), _rx(rb"\\RunMRU\b"),
        _rx(rb"HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run"),
    ], "Registry Run-key persistence.", ["T1547.001"]),

    ("Shell_Lolbins", 0.3, [
        _rx(rb"\b(mshta|wscript|cscript|regsvr32|rundll32|msbuild|installutil)\b"),
    ], "Living-off-the-land binary (LOLBin) usage.", ["T1218"]),

    ("Suspicious_VBA_Macro", 0.4, [
        _rx(rb"Auto(Open|Close)\b"), _rx(rb"Document_Open\b"), _rx(rb"Shell\s*\("),
        _rx(rb"CreateObject\s*\("),
    ], "Auto-executing VBA macro constructs.", ["T1059.005", "T1204.002"]),

    ("Long_Base64_Blob", 0.18, [re.compile(rb"[A-Za-z0-9+/]{220,}={0,2}")],
     "Large base64 blob — possible packed/encoded payload.", ["T1027"]),

    ("Clipboard_Hijack_RunPrompt", 0.45, [
        _rx(rb"clipboard"), _rx(rb"(Win\+R|RUN prompt|I'?m not a robot)"),
    ], "Clipboard/RUN-prompt social-engineering (ClickFix/Lumma style).", ["T1204.001", "T1059.001"]),
]


def scan(data: bytes) -> List[Dict[str, Any]]:
    """Return the list of matched rules with their metadata."""
    hits: List[Dict[str, Any]] = []
    for name, weight, patterns, desc, ttps in _RULES:
        # A rule fires if ANY of its alternative patterns match.
        if any(p.search(data) for p in patterns):
            hits.append({"rule": name, "weight": weight, "description": desc, "ttps": list(ttps)})
    return hits
