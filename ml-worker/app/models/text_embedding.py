"""
MockTextEmbedding — stands in for a BERT-family encoder that turns scripts/text
into behavioral embeddings.

REAL REPLACEMENT:
    from transformers import AutoTokenizer, AutoModel
    tok = AutoTokenizer.from_pretrained("microsoft/codebert-base")
    model = AutoModel.from_pretrained("microsoft/codebert-base")
    # tokenize decoded content -> model(**inputs) -> pooled CLS vector
Keep the return shape identical.
"""
from __future__ import annotations

import os
from typing import Any, Dict

from .base import BaseModelInference

EMBEDDING_DIM = int(os.getenv("EMBEDDING_DIM", "16"))


class MockTextEmbedding(BaseModelInference):
    name = "text_embedding"
    backing_architecture = "BERT / CodeBERT (mock)"

    def infer(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        # MOCK: replace with real BERT pooled output — keep return shape.
        vector = self._pseudo_vector(payload, EMBEDDING_DIM)
        return {
            "model": self.name,
            "backing_architecture": self.backing_architecture,
            "embedding": vector,
            "embedding_dim": EMBEDDING_DIM,
            "model_meta": {"tokenizer": "mock-wordpiece", "max_length": 512},
        }
