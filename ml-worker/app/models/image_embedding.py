"""
Image embeddings.

REAL: ``ResNet50ImageEmbedding`` — torchvision ResNet-50 (IMAGENET1K_V2) with the
classifier head removed, yielding a 2048-d penultimate feature vector for FAISS
image-similarity clustering.

FALLBACK: ``MockImageEmbedding`` — deterministic pseudo-vector when ML extras are
absent or the image can't be decoded. ``get_image_embedder()`` picks one. Both
return the IDENTICAL shape.
"""
from __future__ import annotations

import io
import logging
import os
from typing import Any, Dict

from app.detect.utils import decode_b64

from . import _runtime
from .base import BaseModelInference

logger = logging.getLogger("aether.image_embedding")

EMBEDDING_DIM = int(os.getenv("EMBEDDING_DIM", "16"))  # mock fallback only


class MockImageEmbedding(BaseModelInference):
    name = "image_embedding"
    backing_architecture = "ResNet-50 (mock)"

    def infer(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        vector = self._pseudo_vector(payload, EMBEDDING_DIM)
        return {
            "model": self.name,
            "backing_architecture": self.backing_architecture,
            "embedding": vector,
            "embedding_dim": EMBEDDING_DIM,
            "model_meta": {"weights": "mock", "preprocessing": "224x224-centercrop"},
        }


class ResNet50ImageEmbedding(BaseModelInference):
    name = "image_embedding"
    backing_architecture = "ResNet-50 (torchvision IMAGENET1K_V2, penultimate 2048-d)"

    def __init__(self) -> None:
        self._fallback = MockImageEmbedding()

    def _bundle(self):
        def build():
            import torch
            from torchvision.models import ResNet50_Weights, resnet50

            device = _runtime.get_device()
            weights = ResNet50_Weights.DEFAULT
            model = resnet50(weights=weights)
            model.fc = torch.nn.Identity()  # expose the 2048-d penultimate features
            model = model.eval().to(device)
            preprocess = weights.transforms()
            logger.info("Loaded ResNet-50 image embedder on %s.", device)
            return model, preprocess, device, torch

        return _runtime.singleton("image_embed::resnet50", build)

    def infer(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        data = decode_b64(payload.get("content_b64"))
        if not data:
            return self._fallback.infer(payload)
        try:
            from PIL import Image

            Image.MAX_IMAGE_PIXELS = int(os.getenv("IMAGE_MAX_PIXELS", str(64_000_000)))
            img = Image.open(io.BytesIO(data)).convert("RGB")
        except Exception as exc:  # noqa: BLE001 — malicious/polyglot/bomb images
            logger.warning("Image decode failed (%s); using mock vector.", exc)
            return self._fallback.infer(payload)
        try:
            model, preprocess, device, torch = self._bundle()
            batch = preprocess(img).unsqueeze(0).to(device)
            with torch.no_grad():
                vec = model(batch).squeeze(0).float().cpu().tolist()
            return {
                "model": self.name,
                "backing_architecture": self.backing_architecture,
                "embedding": vec,
                "embedding_dim": len(vec),
                "model_meta": {
                    "weights": "IMAGENET1K_V2",
                    "preprocessing": "resize232-centercrop224-imagenet-norm",
                    "device": device,
                },
            }
        except Exception as exc:  # noqa: BLE001
            logger.warning("ResNet-50 embedding failed (%s); using mock vector.", exc)
            return self._fallback.infer(payload)


def get_image_embedder() -> BaseModelInference:
    """Real ResNet-50 embedder when ML extras are installed, else the mock."""
    if _runtime.ml_available("torchvision"):
        return ResNet50ImageEmbedding()
    return MockImageEmbedding()
