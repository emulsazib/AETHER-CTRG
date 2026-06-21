"""
OpenCTI push (STIX2) — the automated-attribution layer.

After analysis, this module pushes the extracted IoCs and TTPs into OpenCTI via the
pycti client. OpenCTI's built-in MITRE ATT&CK connector then auto-correlates the TTPs
to known intrusion-sets / threat actors (the "instant attribution" the blueprint
describes) without us hand-mapping anything.

It is intentionally best-effort: gated behind OPENCTI_ENABLED, every call is wrapped in
try/except, and any failure is logged but never propagated — the analysis response must
not depend on OpenCTI being up. Invoked as a FastAPI BackgroundTask so it never adds
latency to /analyze.

Config (env):
    OPENCTI_ENABLED   "true" to activate the push (default off)
    OPENCTI_URL       e.g. http://opencti:8080
    OPENCTI_TOKEN     API token (matches OPENCTI_ADMIN_TOKEN)
"""
from __future__ import annotations

import logging
import os
import re
from typing import Any, Dict, List, Optional

logger = logging.getLogger("aether.opencti")

_MARK = "[AETHER]"  # tag so demo objects are easy to find/clean in OpenCTI


def is_enabled() -> bool:
    return os.getenv("OPENCTI_ENABLED", "false").lower() in {"1", "true", "yes"} and bool(
        os.getenv("OPENCTI_URL") and os.getenv("OPENCTI_TOKEN")
    )


def _refang(value: str) -> str:
    """Turn a defanged indicator (hxxp://, 1[.]2[.]3) back into a real value."""
    return (
        value.replace("hxxps", "https")
        .replace("hxxp", "http")
        .replace("[.]", ".")
        .replace("[:]", ":")
        .strip()
    )


_IPV4 = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")
_HASH = re.compile(r"^[A-Fa-f0-9]{32,64}$")


def _stix_pattern(ioc: str) -> Optional[tuple[str, str]]:
    """Map an IoC to (stix_pattern, main_observable_type). Returns None if unknown."""
    v = _refang(ioc)
    if v.startswith("http://") or v.startswith("https://"):
        return f"[url:value = '{v}']", "Url"
    if _IPV4.match(v):
        return f"[ipv4-addr:value = '{v}']", "IPv4-Addr"
    if _HASH.match(v):
        algo = {32: "MD5", 40: "SHA-1", 64: "SHA-256"}.get(len(v), "SHA-256")
        return f"[file:hashes.'{algo}' = '{v}']", "StixFile"
    if "." in v and "/" not in v and " " not in v:
        return f"[domain-name:value = '{v}']", "Domain-Name"
    return None


def push_to_opencti(result: Dict[str, Any], file_name: str) -> None:
    """Push indicators + attack-patterns for one analyzed sample, grouped in a Report.

    Safe to call unconditionally; no-ops unless OPENCTI_ENABLED and reachable.
    """
    if not is_enabled():
        logger.debug("OpenCTI push skipped (disabled or unconfigured).")
        return

    try:
        from pycti import OpenCTIApiClient  # lazy import; only needed on the push path

        client = OpenCTIApiClient(os.getenv("OPENCTI_URL"), os.getenv("OPENCTI_TOKEN"))

        object_refs: List[str] = []

        # --- Indicators from IoCs ---------------------------------------------
        for ioc in result.get("extracted_iocs", []) or []:
            mapped = _stix_pattern(ioc)
            if not mapped:
                continue
            pattern, observable_type = mapped
            try:
                indicator = client.indicator.create(
                    name=ioc,
                    description=f"{_MARK} extracted from {file_name}",
                    pattern_type="stix",
                    pattern=pattern,
                    x_opencti_main_observable_type=observable_type,
                )
                if indicator and indicator.get("id"):
                    object_refs.append(indicator["id"])
            except Exception as exc:  # noqa: BLE001
                logger.warning("OpenCTI indicator create failed for %s: %s", ioc, exc)

        # --- Attack-Patterns from TTPs (seeded by the MITRE connector) --------
        for ttp in result.get("ttps", []) or []:
            try:
                ap = client.attack_pattern.read(
                    filters={
                        "mode": "and",
                        "filters": [{"key": "x_mitre_id", "values": [ttp]}],
                        "filterGroups": [],
                    }
                )
                if ap and ap.get("id"):
                    object_refs.append(ap["id"])
                else:
                    logger.info("MITRE technique %s not found (is the MITRE connector seeded?)", ttp)
            except Exception as exc:  # noqa: BLE001
                logger.warning("OpenCTI attack-pattern lookup failed for %s: %s", ttp, exc)

        # --- Report grouping everything for this sample -----------------------
        if object_refs:
            try:
                client.report.create(
                    name=f"{_MARK} AETHER analysis: {file_name}",
                    description=result.get("summary") or "AETHER automated malware analysis.",
                    published=__import__("datetime").datetime.utcnow().isoformat() + "Z",
                    report_types=["malware-analysis"],
                    objects=object_refs,
                )
            except Exception as exc:  # noqa: BLE001
                logger.warning("OpenCTI report create failed: %s", exc)

        logger.info("OpenCTI push complete for %s (%d objects).", file_name, len(object_refs))
    except Exception as exc:  # noqa: BLE001 — never let attribution break analysis
        logger.warning("OpenCTI push failed for %s: %s", file_name, exc)
