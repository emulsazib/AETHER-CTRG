"""
IoCExtractor — extracts Indicators of Compromise (IoCs) and MITRE ATT&CK TTPs from
an artifact.

Two paths, chosen at runtime:
  * EXTERNAL LLM (real): when AI_API_KEY is set, the artifact is sent to any
    OpenAI-compatible gateway (see [app/models/llm.py]) for structured extraction.
  * MOCK (fallback): a deterministic knowledge base keyed by file type, used when no
    provider is configured OR the external call fails — so the stack always runs.

Return shape is identical for both paths so the pipeline never has to branch:
    { model, backing_architecture, iocs: [...], ttps: [...], summary, source }
"""
from __future__ import annotations

import base64
import logging
from typing import Any, Dict, List

from . import llm
from .base import BaseModelInference

logger = logging.getLogger("aether.ioc_extractor")

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


def _decode_artifact(content_b64: str | None) -> str:
    """Best-effort decode of the uploaded bytes to text for the LLM prompt."""
    if not content_b64:
        return ""
    try:
        return base64.b64decode(content_b64).decode("utf-8", errors="replace")
    except Exception:
        return ""


class MockIoCExtractor(BaseModelInference):
    name = "ioc_extractor"
    backing_architecture = "External LLM IoC+TTP extraction (OpenAI-compatible) w/ mock fallback"

    def infer(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        file_type = payload.get("file_type", "")

        # --- Preferred path: real external LLM (any OpenAI-compatible gateway) -----
        if llm.is_configured():
            try:
                artifact = _decode_artifact(payload.get("content_b64"))
                result = llm.extract_iocs_ttps(artifact, file_type)
                # Guard against an empty/garbage response; fall through to mock if so.
                if result["iocs"] or result["ttps"] or result["summary"]:
                    return {
                        "model": self.name,
                        "backing_architecture": self.backing_architecture,
                        "iocs": result["iocs"],
                        "ttps": result["ttps"],
                        "summary": result["summary"],
                        "source": "external_llm",
                    }
                logger.warning("External LLM returned empty extraction; using mock fallback.")
            except Exception as exc:  # noqa: BLE001 — degrade gracefully on any failure
                logger.warning("External LLM extraction failed (%s); using mock fallback.", exc)

        # --- Fallback path: deterministic mock knowledge base ---------------------
        kb = _BY_TYPE.get(file_type, _DEFAULT)
        return {
            "model": self.name,
            "backing_architecture": self.backing_architecture,
            "iocs": list(kb["iocs"]),
            "ttps": list(kb["ttps"]),
            "summary": kb["summary"],
            "source": "mock",
        }
