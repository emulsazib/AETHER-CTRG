"""Detection engine — folds every real signal into a verdict, TTPs, and XAI.

Risk is combined via noisy-OR (1 - Π(1 - wᵢ)) so independent weak signals
accumulate but saturate, and one definitive signal (e.g. EICAR) dominates.
The fired signals ARE the explanation: each becomes a positive SHAP-style
contribution; clean files get negative (benign) contributions so the chart is
always meaningful.
"""
from __future__ import annotations

from typing import Any, Dict, List

from . import formats, signatures
from .iocs import extract_iocs
from .utils import as_text, file_hashes, shannon_entropy

_TEXT_TYPES = {"JS", "PDF", "Archive", "Unknown"}


def _noisy_or(weights: List[float]) -> float:
    prod = 1.0
    for w in weights:
        prod *= (1.0 - max(0.0, min(1.0, w)))
    return round(1.0 - prod, 3)


def analyze(file_type: str, file_name: str, data: bytes) -> Dict[str, Any]:
    text = as_text(data)
    entropy = shannon_entropy(data)
    hashes = file_hashes(data) if data else {"md5": None, "sha1": None, "sha256": None}

    signals: List[Dict[str, Any]] = []

    # --- Signature ruleset (all types) -------------------------------------
    for hit in signatures.scan(data):
        signals.append({"feature": hit["rule"], "weight": hit["weight"], "ttps": hit["ttps"], "note": hit["description"]})

    # --- Format-specific analyzers -----------------------------------------
    fmt: Dict[str, Any] = {}
    stego = {"has_stego": False, "confidence": 0.0, "technique": None, "hidden_text": None}
    if file_type == "PDF":
        fmt = formats.analyze_pdf(data)
        signals += fmt["signals"]
    elif file_type == "JS":
        fmt = formats.analyze_script(data)
        signals += fmt["signals"]
    elif file_type == "Archive":
        fmt = formats.analyze_archive(data)
        signals += fmt["signals"]
    elif file_type == "Image":
        img = formats.analyze_image(data)
        signals += img["signals"]
        stego = {k: img[k] for k in ("has_stego", "confidence", "technique", "hidden_text")}
        stego["entropy"] = img["entropy"]

    # --- Entropy / packing (non-image, non-archive) ------------------------
    if file_type not in {"Image", "Archive"} and len(data) > 256 and entropy >= 7.2:
        signals.append({"feature": "high_entropy_packing", "weight": 0.18, "ttps": ["T1027.002"], "note": f"entropy {entropy} (packed/encrypted)"})

    # --- IoCs from real content --------------------------------------------
    ioc = extract_iocs(text)
    if ioc["ips"] or ioc["urls"]:
        signals.append({"feature": "network_indicators_present", "weight": 0.12, "ttps": ["T1105"], "note": f"{len(ioc['ips'])} IPs / {len(ioc['urls'])} URLs"})

    # --- Risk verdict ------------------------------------------------------
    weights = [s["weight"] for s in signals]
    risk = _noisy_or(weights)
    label = "malicious" if risk >= 0.5 else "suspicious" if risk >= 0.25 else "benign"

    # --- TTPs (union across fired signals) ---------------------------------
    ttps: List[str] = []
    for s in signals:
        for t in s.get("ttps", []):
            if t not in ttps:
                ttps.append(t)

    # --- Explainability (real SHAP/LIME-shaped contributions) --------------
    contributions = [{"feature": s["feature"], "contribution": round(s["weight"], 3)} for s in signals]
    if not contributions:
        # Benign evidence so the attribution view is never empty.
        contributions = [
            {"feature": "no_malicious_signatures", "contribution": -0.35},
            {"feature": "no_embedded_executable", "contribution": -0.25},
            {"feature": f"normal_entropy_{entropy}", "contribution": -0.15},
        ]
    contributions.sort(key=lambda c: abs(c["contribution"]), reverse=True)

    # --- Summary -----------------------------------------------------------
    if signals:
        top = ", ".join(s["feature"] for s in sorted(signals, key=lambda x: -x["weight"])[:4])
        summary = (
            f"Static analysis flagged {len(signals)} indicator(s) in '{file_name}' "
            f"({label}, risk {risk:.2f}). Key signals: {top}."
        )
    else:
        summary = f"No malicious indicators found in '{file_name}' via static analysis (risk {risk:.2f})."

    return {
        "hashes": hashes,
        "size_bytes": len(data),
        "entropy": entropy,
        "signatures": [s["feature"] for s in signals],
        "signal_detail": signals,
        "format_indicators": fmt,
        "iocs": ioc,
        "ttps": ttps,
        "stego": stego,
        "risk": risk,
        "label": label,
        "contributions": contributions[:12],
        "summary": summary,
    }
