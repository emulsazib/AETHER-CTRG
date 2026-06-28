"""
External LLM client — routes IoC/TTP extraction through ANY OpenAI-compatible
gateway instead of a local model (replaces the blueprint's Ollama container).

Configured entirely by environment, so it points at OpenAI, a self-hosted vLLM /
LiteLLM gateway, Anthropic's OpenAI-compat endpoint, or any compliant provider:

    AI_API_KEY    bearer token for the provider
    AI_BASE_URL   custom endpoint, e.g. https://api.openai.com/v1 (blank => OpenAI default)
    AI_MODEL      model id, e.g. gpt-4o-mini / llama3:8b / claude-... (via a proxy)

The caller ([app/models/ioc_extractor.py]) treats this as best-effort: any failure
(missing key, network error, malformed JSON) raises, and the extractor falls back to
its deterministic mock knowledge base so the stack always runs.
"""
from __future__ import annotations

import json
import os
from typing import Any, Dict

_SYSTEM_PROMPT = (
    "You are a malware-analysis assistant. Given a (possibly obfuscated) artifact, "
    "extract threat intelligence and return ONLY a single JSON object with exactly "
    'these keys: {"iocs": [string], "ttps": [string], "summary": string}. '
    "iocs are defanged indicators (domains, IPs, URLs, hashes). ttps are MITRE "
    "ATT&CK technique IDs such as T1059.007 or T1027. Return no prose and no "
    "markdown code fences."
)


def is_configured() -> bool:
    """True when an external AI provider is wired up via AI_API_KEY."""
    return bool(os.getenv("AI_API_KEY"))


def _client():
    """Build a lazily-imported OpenAI client so the dependency is only needed when used."""
    from openai import OpenAI  # imported lazily; not required for the mock path

    return OpenAI(
        api_key=os.getenv("AI_API_KEY"),
        # Blank/unset base_url => the SDK's default (OpenAI). Any custom gateway works.
        base_url=os.getenv("AI_BASE_URL") or None,
    )


def extract_iocs_ttps(artifact_text: str, file_type: str) -> Dict[str, Any]:
    """Call the external LLM and return {iocs, ttps, summary}.

    Raises on any failure so the caller can fall back to the mock extractor.
    """
    if not is_configured():
        raise RuntimeError("AI_API_KEY not configured — external LLM unavailable")

    client = _client()
    resp = client.chat.completions.create(
        model=os.getenv("AI_MODEL", "gpt-4o-mini"),
        messages=[
            {"role": "system", "content": _SYSTEM_PROMPT},
            {
                "role": "user",
                "content": f"file_type={file_type}\nartifact:\n{(artifact_text or '')[:6000]}",
            },
        ],
        # Ask for a JSON object; providers that ignore this still parse fine below.
        response_format={"type": "json_object"},
        temperature=0,
    )
    content = resp.choices[0].message.content or "{}"
    data = json.loads(content)
    return {
        "iocs": list(data.get("iocs", []) or []),
        "ttps": list(data.get("ttps", []) or []),
        "summary": data.get("summary", "") or "",
    }


_STEGO_DECODE_PROMPT = (
    "You are a malware analyst. The following bytes were recovered from the "
    "least-significant-bit plane of an image (possible steganography). If they "
    "contain a command, URL, script, or readable payload, decode/interpret it in "
    "ONE concise line. If they are just noise, reply exactly 'no meaningful payload'."
)


def decode_hidden(recovered_text: str, file_type: str) -> str:
    """Interpret bytes recovered from an image's LSB plane via the external LLM.

    Best-effort: raises on any failure (missing key, network, etc.) so the caller
    can fall back to a raw preview of the recovered bytes.
    """
    if not is_configured():
        raise RuntimeError("AI_API_KEY not configured — external LLM unavailable")

    client = _client()
    resp = client.chat.completions.create(
        model=os.getenv("AI_MODEL", "gpt-4o-mini"),
        messages=[
            {"role": "system", "content": _STEGO_DECODE_PROMPT},
            {
                "role": "user",
                "content": f"file_type={file_type}\nrecovered_bytes:\n{(recovered_text or '')[:1000]}",
            },
        ],
        temperature=0,
    )
    return (resp.choices[0].message.content or "").strip()
