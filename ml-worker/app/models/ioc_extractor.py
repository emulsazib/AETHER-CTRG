"""
MockIoCExtractor — stands in for an LLM (e.g. GPT/Claude) that parses obfuscated
artifacts and extracts Indicators of Compromise (IoCs) and MITRE ATT&CK TTPs.

REAL REPLACEMENT:
    Send the decoded artifact to an LLM (LLM_API_KEY) with a structured-output
    prompt asking for IoCs (IPs, domains, hashes, URLs) and TTP technique IDs.
Keep the return shape: { iocs: [...], ttps: [...], summary }.
"""
from __future__ import annotations

from typing import Any, Dict, List

from .base import BaseModelInference

# A small mock "knowledge base" the fake LLM draws from, keyed by file type, so
# different uploads yield believable, varied output.
_BY_TYPE = {
    "JS": {
        "iocs": ["secure-update-cdn[.]com", "185.220.101.47", "/jquery.min.js?id="],
        "ttps": ["T1059.007", "T1105", "T1027"],
        "summary": "Obfuscated JScript downloader contacting a fake-update CDN.",
    },
    "PDF": {
        "iocs": ["lumma-gate[.]xyz", "45.137.21.9"],
        "ttps": ["T1566.001", "T1204.002", "T1027"],
        "summary": "Weaponized PDF luring the user to execute an embedded stealer.",
    },
    "Image": {
        "iocs": ["hxxp://185.220.101.47/beacon"],
        "ttps": ["T1027.003", "T1102"],
        "summary": "Image carrying a steganographic C2 beacon payload.",
    },
    "Archive": {
        "iocs": ["45.137.21.9", "asyncrat-panel[.]net"],
        "ttps": ["T1059.001", "T1547.001", "T1055"],
        "summary": "Archive bundling an AsyncRAT loader with persistence.",
    },
}

_DEFAULT = {
    "iocs": ["unknown-c2[.]example"],
    "ttps": ["T1027"],
    "summary": "Generic obfuscated artifact; limited indicators recovered.",
}


class MockIoCExtractor(BaseModelInference):
    name = "ioc_extractor"
    backing_architecture = "LLM (GPT/Claude) IoC+TTP extraction (mock)"

    def infer(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        # MOCK: replace with a real LLM structured-extraction call.
        file_type = payload.get("file_type", "")
        kb = _BY_TYPE.get(file_type, _DEFAULT)
        return {
            "model": self.name,
            "backing_architecture": self.backing_architecture,
            "iocs": list(kb["iocs"]),
            "ttps": list(kb["ttps"]),
            "summary": kb["summary"],
        }
