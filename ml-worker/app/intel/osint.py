"""
External OSINT threat-intel enrichment + real threat-actor attribution.

Queries three providers, each independently gated by an env key and entirely
best-effort (any failure → None, never raises into the pipeline):

  * AbuseIPDB  (ABUSEIPDB_API_KEY) — IP abuse confidence / geo / ISP  [REST]
  * AlienVault OTX (OTX_API_KEY)   — pulses → adversaries + malware families
  * VirusTotal (VT_API_KEY)        — popular_threat_classification + analysis stats

Hard safeguards so free tiers aren't blown (VT = 4 req/min · 500/day):
  * per-type IoC caps (OSINT_MAX_IPS/DOMAINS/HASHES/URLS),
  * an in-memory TTL cache (OSINT_CACHE_TTL),
  * 429 / quota errors are soft-failed.

``attribute()`` aggregates the gathered signals into a single best actor pick with
a confidence and human-readable rationale. With no keys/hits it returns actor=None
and the Node backend's string-heuristic fills in (one heuristic, in one place).
"""
from __future__ import annotations

import logging
import os
import time
from collections import Counter
from typing import Any, Dict, List, Optional, Tuple

logger = logging.getLogger("aether.osint")

_HTTP_TIMEOUT = int(os.getenv("OSINT_HTTP_TIMEOUT", "8"))
_CACHE_TTL = int(os.getenv("OSINT_CACHE_TTL", "3600"))
_cache: Dict[Tuple[str, str], Tuple[float, Any]] = {}

# Normalize provider names so graph nodes don't fragment (APT29 == Cozy Bear ...).
_ACTOR_ALIASES = {
    "cozy bear": "APT29",
    "the dukes": "APT29",
    "unc2452": "APT29",
    "nobelium": "APT29",
    "midnight blizzard": "APT29",
    "lumma": "Lumma Stealer",
    "lummac2": "Lumma Stealer",
    "lumma stealer": "Lumma Stealer",
    "socgholish": "APT29",
    "asyncrat": "AsyncRAT",
}


def _cap(name: str, default: int) -> int:
    try:
        return int(os.getenv(name, str(default)))
    except ValueError:
        return default


def refang(value: str) -> str:
    """Inverse of detect.utils.safe_defang — restore a usable indicator."""
    if not value:
        return value
    v = value.strip().strip("[]")
    v = v.replace("hxxps", "https").replace("hxxp", "http")
    v = v.replace("[.]", ".").replace("(.)", ".").replace("[:]", ":")
    return v


def _have(provider: str) -> bool:
    return {
        "abuseipdb": bool(os.getenv("ABUSEIPDB_API_KEY")),
        "otx": bool(os.getenv("OTX_API_KEY")),
        "virustotal": bool(os.getenv("VT_API_KEY")),
    }.get(provider, False)


def available_providers() -> List[str]:
    return [p for p in ("abuseipdb", "otx", "virustotal") if _have(p)]


def enabled() -> Tuple[bool, str, List[str]]:
    """(available, reason, providers-with-keys) — drives the config toggle."""
    providers = available_providers()
    if providers:
        return True, "ready (" + ", ".join(providers) + ")", providers
    return False, "no OSINT keys set (ABUSEIPDB_API_KEY / OTX_API_KEY / VT_API_KEY)", []


def _cached(provider: str, key: str, fetch):
    ck = (provider, key)
    hit = _cache.get(ck)
    now = time.time()
    if hit and (now - hit[0]) < _CACHE_TTL:
        return hit[1]
    try:
        val = fetch()
    except Exception as exc:  # noqa: BLE001 — provider failures are soft
        logger.info("OSINT %s lookup failed for %s (%s).", provider, key, exc)
        val = None
    _cache[ck] = (now, val)
    return val


def _hash_kind(h: str) -> str:
    return {32: "md5", 40: "sha1", 64: "sha256"}.get(len(h.strip()), "sha256")


# --------------------------------------------------------------------------- #
# Providers
# --------------------------------------------------------------------------- #
def _abuseipdb_ip(ip: str) -> Optional[Dict[str, Any]]:
    if not _have("abuseipdb"):
        return None

    def fetch():
        import requests

        resp = requests.get(
            "https://api.abuseipdb.com/api/v2/check",
            headers={"Key": os.getenv("ABUSEIPDB_API_KEY"), "Accept": "application/json"},
            params={"ipAddress": ip, "maxAgeInDays": os.getenv("ABUSEIPDB_MAX_AGE", "90")},
            timeout=_HTTP_TIMEOUT,
        )
        if resp.status_code != 200:
            return None
        d = resp.json().get("data", {})
        return {
            "abuse_confidence": d.get("abuseConfidenceScore"),
            "total_reports": d.get("totalReports"),
            "country": d.get("countryCode"),
            "isp": d.get("isp"),
            "usage_type": d.get("usageType"),
            "last_reported_at": d.get("lastReportedAt"),
        }

    return _cached("abuseipdb", ip, fetch)


def _otx_indicator(kind: str, value: str) -> Optional[Dict[str, Any]]:
    if not _have("otx"):
        return None

    def fetch():
        from OTXv2 import IndicatorTypes, OTXv2

        type_map = {
            "ip": IndicatorTypes.IPv4,
            "domain": IndicatorTypes.DOMAIN,
            "url": IndicatorTypes.URL,
            "md5": IndicatorTypes.FILE_HASH_MD5,
            "sha1": IndicatorTypes.FILE_HASH_SHA1,
            "sha256": IndicatorTypes.FILE_HASH_SHA256,
        }
        itype = type_map.get(kind)
        if itype is None:
            return None
        otx = OTXv2(os.getenv("OTX_API_KEY"))
        details = otx.get_indicator_details_by_section(itype, value, "general")
        pulse_info = details.get("pulse_info", {}) or {}
        pulses = pulse_info.get("pulses", []) or []

        adversaries, families, tags, attack_ids = [], [], [], []
        for p in pulses:
            if p.get("adversary"):
                adversaries.append(p["adversary"])
            for mf in p.get("malware_families", []) or []:
                families.append(_coerce_name(mf))
            for tg in p.get("tags", []) or []:
                tags.append(_coerce_name(tg))
            for aid in p.get("attack_ids", []) or []:
                attack_ids.append(_coerce_name(aid))
        related = (pulse_info.get("related", {}) or {}).get("alienvault", {}) or {}
        adversaries += [a for a in (related.get("adversary", []) or [])]
        families += [_coerce_name(m) for m in (related.get("malware_families", []) or [])]

        return {
            "pulse_count": pulse_info.get("count", len(pulses)),
            "adversaries": _dedupe(adversaries),
            "malware_families": _dedupe(families),
            "tags": _dedupe(tags)[:10],
            "attack_ids": _dedupe(attack_ids)[:10],
        }

    return _cached("otx", f"{kind}:{value}", fetch)


def _vt(kind: str, value: str) -> Optional[Dict[str, Any]]:
    if not _have("virustotal"):
        return None

    def fetch():
        import vt

        path = {
            "file": f"/files/{value}",
            "ip": f"/ip_addresses/{value}",
            "domain": f"/domains/{value}",
        }[kind]
        with vt.Client(os.getenv("VT_API_KEY")) as client:
            obj = client.get_object(path)
        stats = obj.get("last_analysis_stats") or {}
        out = {
            "malicious_count": stats.get("malicious", 0),
            "suspicious_count": stats.get("suspicious", 0),
            "reputation": obj.get("reputation"),
            "suggested_label": None,
            "families": [],
        }
        ptc = obj.get("popular_threat_classification") or {}
        if ptc:
            out["suggested_label"] = ptc.get("suggested_threat_label")
            out["families"] = [_coerce_name(x) for x in (ptc.get("popular_threat_name") or [])]
        return out

    return _cached("virustotal", f"{kind}:{value}", fetch)


def _coerce_name(item: Any) -> str:
    """OTX/VT name fields are sometimes dicts, sometimes strings."""
    if isinstance(item, dict):
        return str(item.get("display_name") or item.get("value") or item.get("name") or "").strip()
    return str(item).strip()


def _dedupe(items: List[str]) -> List[str]:
    out: List[str] = []
    for x in items:
        if x and x not in out:
            out.append(x)
    return out


# --------------------------------------------------------------------------- #
# Orchestration
# --------------------------------------------------------------------------- #
def enrich_iocs(structured_iocs: Dict[str, Any]) -> Dict[str, Any]:
    """Look up capped slices of the typed IoC lists across all keyed providers."""
    ips = [refang(x) for x in (structured_iocs.get("ips") or [])][: _cap("OSINT_MAX_IPS", 6)]
    domains = [refang(x) for x in (structured_iocs.get("domains") or [])][: _cap("OSINT_MAX_DOMAINS", 4)]
    hashes = list(structured_iocs.get("hashes") or [])[: _cap("OSINT_MAX_HASHES", 4)]

    reputation: Dict[str, Dict[str, Any]] = {}
    adversaries: List[str] = []
    families: List[str] = []
    vt_labels: List[str] = []
    max_abuse = 0

    for ip in ips:
        entry: Dict[str, Any] = {}
        ab = _abuseipdb_ip(ip)
        if ab:
            entry["abuseipdb"] = ab
            if isinstance(ab.get("abuse_confidence"), int):
                max_abuse = max(max_abuse, ab["abuse_confidence"])
        otx = _otx_indicator("ip", ip)
        if otx:
            entry["otx"] = otx
            adversaries += otx["adversaries"]
            families += otx["malware_families"]
        vt_res = _vt("ip", ip)
        if vt_res:
            entry["virustotal"] = vt_res
            if vt_res.get("suggested_label"):
                vt_labels.append(vt_res["suggested_label"])
            families += vt_res.get("families", [])
        if entry:
            entry["malicious"] = _is_malicious(entry)
            reputation[ip] = entry

    for dom in domains:
        entry = {}
        otx = _otx_indicator("domain", dom)
        if otx:
            entry["otx"] = otx
            adversaries += otx["adversaries"]
            families += otx["malware_families"]
        vt_res = _vt("domain", dom)
        if vt_res:
            entry["virustotal"] = vt_res
            if vt_res.get("suggested_label"):
                vt_labels.append(vt_res["suggested_label"])
            families += vt_res.get("families", [])
        if entry:
            entry["malicious"] = _is_malicious(entry)
            reputation[dom] = entry

    for h in hashes:
        entry = {}
        otx = _otx_indicator(_hash_kind(h), h)
        if otx:
            entry["otx"] = otx
            adversaries += otx["adversaries"]
            families += otx["malware_families"]
        vt_res = _vt("file", h)
        if vt_res:
            entry["virustotal"] = vt_res
            if vt_res.get("suggested_label"):
                vt_labels.append(vt_res["suggested_label"])
            families += vt_res.get("families", [])
        if entry:
            entry["malicious"] = _is_malicious(entry)
            reputation[h] = entry

    return {
        "ioc_reputation": reputation,
        "signals": {
            "adversaries": _dedupe(adversaries),
            "malware_families": _dedupe(families),
            "vt_labels": _dedupe(vt_labels),
            "max_abuse_confidence": max_abuse,
            "providers_used": available_providers(),
        },
    }


def _is_malicious(entry: Dict[str, Any]) -> bool:
    ab = entry.get("abuseipdb") or {}
    vt_res = entry.get("virustotal") or {}
    otx = entry.get("otx") or {}
    return bool(
        (isinstance(ab.get("abuse_confidence"), int) and ab["abuse_confidence"] >= 50)
        or (vt_res.get("malicious_count") or 0) >= 3
        or (otx.get("pulse_count") or 0) >= 1
    )


def _canon_actor(name: str) -> str:
    return _ACTOR_ALIASES.get(name.strip().lower(), name.strip())


def attribute(signals: Dict[str, Any], fallback_iocs: Optional[List[str]] = None) -> Dict[str, Any]:
    """Weighted aggregation of OSINT signals → best actor pick + rationale."""
    tally: Counter = Counter()
    for adv in signals.get("adversaries", []):
        if adv:
            tally[_canon_actor(adv)] += 3
    for label in signals.get("vt_labels", []):
        for token in str(label).replace(".", " ").replace("/", " ").split():
            canon = _ACTOR_ALIASES.get(token.lower())
            if canon:
                tally[canon] += 2
    for fam in signals.get("malware_families", []):
        if fam:
            tally[_canon_actor(fam)] += 1

    if not tally:
        return {
            "actor": None,
            "confidence": 0.0,
            "rationale": "No external OSINT attribution signals.",
            "candidates": [],
            "malware_families": signals.get("malware_families", []),
            "source": "none",
        }

    candidates = [{"actor": a, "weight": w} for a, w in tally.most_common(5)]
    top_actor, top_weight = tally.most_common(1)[0]
    total = sum(tally.values())
    abuse = (signals.get("max_abuse_confidence") or 0) / 100.0
    confidence = round(min(0.5 * (top_weight / total) + 0.3 * min(top_weight / 3.0, 1.0) + 0.2 * abuse, 0.99), 3)

    bits = []
    if signals.get("adversaries"):
        bits.append(f"OTX pulses name {', '.join(signals['adversaries'][:3])}")
    if signals.get("vt_labels"):
        bits.append(f"VT label {signals['vt_labels'][0]}")
    if signals.get("max_abuse_confidence"):
        bits.append(f"AbuseIPDB max confidence {signals['max_abuse_confidence']}")
    rationale = "; ".join(bits) or f"Aggregated OSINT signals point to {top_actor}."

    return {
        "actor": top_actor,
        "confidence": confidence,
        "rationale": rationale,
        "candidates": candidates,
        "malware_families": signals.get("malware_families", []),
        "source": "osint",
    }
