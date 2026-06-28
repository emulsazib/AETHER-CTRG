"""AETHER analysis pipeline — the shape-preserving hub that fuses every engine.

Stages (each degrades to a deterministic mock/static fallback if its deps/keys
are absent, so the response shape is invariant and /analyze never 500s):
  * REAL static detection (app.detect.engine) — signatures, formats, IoCs,
    entropy, structural stego → content-driven verdict + feature attribution.
  * Trained HF classifier (ensembled into the risk) when the ML engine is on.
  * External LLM IoC/TTP enrichment when AI_API_KEY is set.
  * External OSINT (AbuseIPDB/OTX/VirusTotal) reputation + actor attribution.
  * Real embeddings (CodeBERT/ResNet), FAISS+UMAP+KMeans clustering, CLIP+LSB
    steganography, and SHAP/LIME explainability (Deep mode) when ML extras exist.
"""
from __future__ import annotations

import logging
import os
from typing import Any, Dict, List

from app import config_state
from app.detect import analyze as detect_analyze
from app.detect.utils import as_text, decode_b64
from app.models import classifier, llm
from app.models.image_embedding import get_image_embedder
from app.models.stego_detector import get_stego_detector
from app.models.text_embedding import get_text_embedder

from .clustering import get_clustering

logger = logging.getLogger("aether.pipeline")

# Real models when the ML extras are installed; deterministic mocks otherwise.
IMAGE_EMBEDDER = get_image_embedder()
TEXT_EMBEDDER = get_text_embedder()
STEGO_DETECTOR = get_stego_detector()
CLUSTERING = get_clustering()

_IMAGE_TYPES = {"Image"}


def _env_bool(name: str, default: bool = False) -> bool:
    return os.getenv(name, str(default)).strip().lower() in {"1", "true", "yes", "on"}


def _merge_unique(*lists: List[str]) -> List[str]:
    out: List[str] = []
    for lst in lists:
        for x in lst or []:
            if x not in out:
                out.append(x)
    return out


def run_pipeline(payload: Dict[str, Any]) -> Dict[str, Any]:
    """Execute the real detection pipeline and return the combined payload.

    Shape is unchanged from the previous mock pipeline so the Node gateway,
    OpenCTI push, and React UI need no changes — but every value is now derived
    from the artifact's actual content.
    """
    file_type = payload.get("file_type", "Unknown")
    file_name = payload.get("file_name", "sample.bin")
    data = decode_b64(payload.get("content_b64"))

    # --- REAL static detection ---------------------------------------------
    det = detect_analyze(file_type, file_name, data)

    iocs = list(det["iocs"]["flat"])
    ttps = list(det["ttps"])
    summary = det["summary"]
    risk = det["risk"]
    sources = ["static"]

    cfg = config_state.get_config()["engines"]

    # --- Trained ML classifier (ensembled with the static engine) ----------
    # Only runs when the user has the ML engine enabled AND a model is loadable.
    ml_result = None
    if cfg["ml"]["enabled"]:
        ml_result = classifier.predict(data, file_type, as_text(data))
        if ml_result:
            # Keep definitive signature catches (max), but let the trained model
            # raise the score on what signatures miss. Tune the blend on your set.
            risk = round(max(risk, 0.6 * ml_result["score"] + 0.4 * det["risk"]), 3)
            det["contributions"].insert(0, {
                "feature": f"ml:{ml_result['model']}",
                "contribution": round(ml_result["score"], 3),
            })
            sources.append("ml")

    # --- External-LLM enrichment (IoCs / TTPs / summary) -------------------
    if cfg["llm"]["enabled"] and llm.is_configured():
        try:
            llm_out = llm.extract_iocs_ttps(as_text(data), file_type)
            iocs = _merge_unique(iocs, llm_out.get("iocs", []))
            ttps = _merge_unique(ttps, llm_out.get("ttps", []))
            if llm_out.get("summary"):
                summary = f"{summary}\n\nLLM: {llm_out['summary']}"
            sources.append("llm")
        except Exception as exc:  # noqa: BLE001 — enrichment is best-effort
            logger.warning("LLM enrichment failed (%s); skipping.", exc)

    # --- External OSINT enrichment + threat-actor attribution --------------
    attribution = None
    ioc_reputation: Dict[str, Any] = {}
    if cfg.get("osint", {}).get("enabled"):
        try:
            from app.intel import osint

            enr = osint.enrich_iocs(det["iocs"])  # structured, fanged typed lists
            ioc_reputation = enr["ioc_reputation"]
            attribution = osint.attribute(enr["signals"], iocs)
            sources.append("osint")
        except Exception as exc:  # noqa: BLE001 — OSINT is best-effort
            logger.warning("OSINT enrichment failed (%s); skipping.", exc)

    source = "+".join(sources)

    # --- Feature decoration (context embeddings + clustering) --------------
    features: Dict[str, Any] = {
        "static": {
            "hashes": det["hashes"],
            "size_bytes": det["size_bytes"],
            "entropy": det["entropy"],
            "signatures": det["signatures"],
            "signal_detail": det["signal_detail"],
            "format_indicators": det["format_indicators"],
        },
        "ioc_extraction": {
            "model": "detect_engine",
            "backing_architecture": "Static signature/heuristic engine + optional external LLM",
            "iocs": iocs,
            "ttps": ttps,
            "summary": summary,
            "source": source,
        },
    }

    if file_type in _IMAGE_TYPES:
        features["image_embedding"] = IMAGE_EMBEDDER.infer(payload)
        # Merge the structural engine stego (trailing/embedded payloads, entropy)
        # with the real CLIP+LSB+LLM detector — strongest signal wins, entropy kept.
        base_stego = det["stego"]
        real_stego = STEGO_DETECTOR.infer(payload)
        merged = dict(base_stego)
        merged["has_stego"] = bool(base_stego.get("has_stego") or real_stego.get("has_stego"))
        merged["confidence"] = round(
            max(base_stego.get("confidence", 0.0), real_stego.get("confidence", 0.0)), 3
        )
        merged["technique"] = base_stego.get("technique") or real_stego.get("technique")
        merged["hidden_text"] = real_stego.get("hidden_text") or base_stego.get("hidden_text")
        merged["backing_architecture"] = real_stego.get("backing_architecture")
        features["steganography"] = merged
    else:
        features["text_embedding"] = TEXT_EMBEDDER.infer(payload)

    basis_embedding = (
        features.get("image_embedding", {}).get("embedding")
        or features.get("text_embedding", {}).get("embedding")
        or []
    )
    clustering = CLUSTERING.compute(payload, basis_embedding)
    # Anchor the false-positive estimate to the (ensembled) risk.
    clustering["false_positive_estimate"] = round(max(0.01, (1.0 - risk) * 0.08), 3)

    # --- Explainable verdict ------------------------------------------------
    # Default: real signal-attribution from the static engine (every fired signal
    # is a contribution). Upgrade to genuine SHAP+LIME over the classifier when the
    # ML engine is on and the user asked for a Deep analysis (SHAP is expensive).
    contributions = det["contributions"]
    shap_block = {"base_value": 0.0, "features": contributions}
    lime_block = {
        "features": [
            {"feature": c["feature"], "importance": round(abs(c["contribution"]), 3)}
            for c in contributions[:5]
        ]
    }
    xai_model = "detect_engine_xai"
    xai_arch = "Signal-attribution over static engine (+ ML/LLM when enabled)"

    use_real_xai = (
        _env_bool("XAI_REALSHAP", True)
        and cfg["ml"]["enabled"]
        and ml_result is not None
        and payload.get("sandbox_mode") == "Deep"
        and file_type not in _IMAGE_TYPES
        and bool(as_text(data).strip())
    )
    if use_real_xai:
        try:
            from .xai import RealXAI

            mal_idx = int(os.getenv("CLASSIFIER_MALICIOUS_INDEX", "1"))
            rx = RealXAI().explain_text(as_text(data), mal_idx)
            if rx and (rx["shap_features"] or rx["lime_features"]):
                shap_block = {"base_value": rx["base_value"], "features": rx["shap_features"]}
                lime_block = {"features": rx["lime_features"]}
                xai_model = "detect_engine_xai+shap_lime"
                xai_arch = "SHAP(Transformers) + LIME over HF classifier; static fallback"
        except Exception as exc:  # noqa: BLE001 — never break analysis on XAI
            logger.warning("real SHAP/LIME failed (%s); using static attribution.", exc)

    xai_payload = {
        "model": xai_model,
        "backing_architecture": xai_arch,
        "prediction": risk,
        "predicted_label": "malicious" if risk >= 0.5 else "benign",
        "verdict": "malicious" if risk >= 0.5 else "suspicious" if risk >= 0.25 else "benign",
        "engines": sources,
        "ml_model": ml_result,
        "shap": shap_block,
        "lime": lime_block,
    }

    return {
        "file_type": file_type,
        "features": features,
        "extracted_iocs": iocs,
        "ttps": ttps,
        "summary": summary,
        "clustering": clustering,
        "xai_payload": xai_payload,
        # Additive OSINT keys (None/{} when the engine is off or has no keys).
        "attribution": attribution,
        "ioc_reputation": ioc_reputation,
    }
