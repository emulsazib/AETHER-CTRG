"""AETHER analysis pipeline: model registry + orchestration."""
from __future__ import annotations

from typing import Any, Dict

from app.models.image_embedding import MockImageEmbedding
from app.models.ioc_extractor import MockIoCExtractor
from app.models.stego_detector import MockSteganographyDetector
from app.models.text_embedding import MockTextEmbedding

from .clustering import MockClustering
from .xai import MockXAI

# ---------------------------------------------------------------------------
# MODEL REGISTRY
# Swap any value here for a real BaseModelInference subclass to go to production.
# ---------------------------------------------------------------------------
IMAGE_EMBEDDER = MockImageEmbedding()
TEXT_EMBEDDER = MockTextEmbedding()
STEGO_DETECTOR = MockSteganographyDetector()
IOC_EXTRACTOR = MockIoCExtractor()
CLUSTERING = MockClustering()
XAI = MockXAI()

# Which models run for which file type. Drives dispatch in run_pipeline().
_IMAGE_TYPES = {"Image"}
_TEXT_TYPES = {"JS", "PDF", "Archive"}


def run_pipeline(payload: Dict[str, Any]) -> Dict[str, Any]:
    """Execute the full mock analysis pipeline and return a combined payload.

    The shape returned here is exactly what the Node gateway persists into the
    MongoDB AnalysisJob document (features / extracted_iocs / clustering /
    xai_payload).
    """
    file_type = payload.get("file_type", "")

    features: Dict[str, Any] = {}

    # --- Feature extraction (dispatch by modality) -------------------------
    if file_type in _IMAGE_TYPES:
        features["image_embedding"] = IMAGE_EMBEDDER.infer(payload)
        features["steganography"] = STEGO_DETECTOR.infer(payload)
    if file_type in _TEXT_TYPES or file_type not in _IMAGE_TYPES:
        # Text/behavioral embedding also runs as a fallback for unknown types.
        features["text_embedding"] = TEXT_EMBEDDER.infer(payload)

    # --- IoC / TTP extraction (always) -------------------------------------
    ioc_result = IOC_EXTRACTOR.infer(payload)
    features["ioc_extraction"] = ioc_result

    # --- Clustering & similarity -------------------------------------------
    # Pick whichever embedding we produced as the basis for similarity.
    basis_embedding = (
        features.get("image_embedding", {}).get("embedding")
        or features.get("text_embedding", {}).get("embedding")
        or []
    )
    clustering = CLUSTERING.compute(payload, basis_embedding)

    # --- Explainable AI ----------------------------------------------------
    xai_payload = XAI.explain(payload, features)

    return {
        "file_type": file_type,
        "features": features,
        "extracted_iocs": ioc_result["iocs"],
        "ttps": ioc_result["ttps"],
        "summary": ioc_result["summary"],
        "clustering": clustering,
        "xai_payload": xai_payload,
    }
