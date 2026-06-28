"""
Text behavioral embeddings.

REAL: ``CodeBertTextEmbedding`` — CodeBERT (microsoft/codebert-base) CLS-pooled
768-d vector over the decoded artifact text. Used as the basis for FAISS
similarity clustering of scripts/PDF text.

FALLBACK: ``MockTextEmbedding`` — deterministic pseudo-vector, used when the ML
extras (requirements-ml.txt) aren't installed. ``get_text_embedder()`` picks the
right one. Both return the IDENTICAL shape so the pipeline/UI are unaffected.
"""
from __future__ import annotations

import logging
import os
from typing import Any, Dict

from app.detect.utils import as_text, decode_b64

from . import _runtime
from .base import BaseModelInference

logger = logging.getLogger("aether.text_embedding")

EMBEDDING_DIM = int(os.getenv("EMBEDDING_DIM", "16"))  # mock fallback only
TEXT_EMBED_MODEL_ID = os.getenv("TEXT_EMBED_MODEL_ID", "microsoft/codebert-base")
TEXT_EMBED_MAX_CHARS = int(os.getenv("TEXT_EMBED_MAX_CHARS", "4000"))


class MockTextEmbedding(BaseModelInference):
    name = "text_embedding"
    backing_architecture = "BERT / CodeBERT (mock)"

    def infer(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        vector = self._pseudo_vector(payload, EMBEDDING_DIM)
        return {
            "model": self.name,
            "backing_architecture": self.backing_architecture,
            "embedding": vector,
            "embedding_dim": EMBEDDING_DIM,
            "model_meta": {"tokenizer": "mock-wordpiece", "max_length": 512},
        }


class CodeBertTextEmbedding(BaseModelInference):
    name = "text_embedding"
    backing_architecture = f"CodeBERT ({TEXT_EMBED_MODEL_ID}, CLS-pooled)"

    def __init__(self) -> None:
        self._fallback = MockTextEmbedding()

    def _bundle(self):
        def build():
            import torch
            from transformers import AutoModel, AutoTokenizer

            device = _runtime.get_device()
            tok = AutoTokenizer.from_pretrained(TEXT_EMBED_MODEL_ID)
            model = AutoModel.from_pretrained(TEXT_EMBED_MODEL_ID).eval().to(device)
            logger.info("Loaded text embedder '%s' on %s.", TEXT_EMBED_MODEL_ID, device)
            return tok, model, device, torch

        return _runtime.singleton(f"text_embed::{TEXT_EMBED_MODEL_ID}", build)

    def infer(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        text = as_text(decode_b64(payload.get("content_b64")))[:TEXT_EMBED_MAX_CHARS].strip()
        if not text:
            # Empty content => a constant CLS vector would pollute FAISS; use mock.
            return self._fallback.infer(payload)
        try:
            tok, model, device, torch = self._bundle()
            enc = tok(text, return_tensors="pt", truncation=True, max_length=512)
            enc = {k: v.to(device) for k, v in enc.items()}
            with torch.no_grad():
                out = model(**enc)
            vec = out.last_hidden_state[:, 0, :].squeeze(0).float().cpu().tolist()
            return {
                "model": self.name,
                "backing_architecture": self.backing_architecture,
                "embedding": vec,
                "embedding_dim": len(vec),
                "model_meta": {
                    "model_id": TEXT_EMBED_MODEL_ID,
                    "tokenizer": "roberta-bpe",
                    "max_length": 512,
                    "pooling": "cls",
                    "device": device,
                },
            }
        except Exception as exc:  # noqa: BLE001 — never break analysis on a model error
            logger.warning("CodeBERT embedding failed (%s); using mock vector.", exc)
            return self._fallback.infer(payload)


def get_text_embedder() -> BaseModelInference:
    """Real CodeBERT embedder when ML extras are installed, else the mock."""
    if _runtime.ml_available("transformers"):
        return CodeBertTextEmbedding()
    return MockTextEmbedding()
