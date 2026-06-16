"""
MockImageEmbedding — stands in for a ResNet image feature extractor.

REAL REPLACEMENT:
    import torch, torchvision
    model = torchvision.models.resnet50(weights="DEFAULT"); model.eval()
    # decode content_b64 -> PIL image -> transform -> model(tensor) -> vector
Keep the return shape below identical so downstream code is unaffected.
"""
from __future__ import annotations

import os
from typing import Any, Dict

from .base import BaseModelInference

EMBEDDING_DIM = int(os.getenv("EMBEDDING_DIM", "16"))


class MockImageEmbedding(BaseModelInference):
    name = "image_embedding"
    backing_architecture = "ResNet-50 (mock)"

    def infer(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        # MOCK: replace with real ResNet forward pass — keep return shape.
        vector = self._pseudo_vector(payload, EMBEDDING_DIM)
        return {
            "model": self.name,
            "backing_architecture": self.backing_architecture,
            "embedding": vector,
            "embedding_dim": EMBEDDING_DIM,
            "model_meta": {"weights": "mock", "preprocessing": "224x224-centercrop"},
        }
