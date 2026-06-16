"""
===============================================================================
 BaseModelInference — Abstract Base Class for ALL AETHER AI models
===============================================================================
Interface Segregation (PRD §5.1): every model — real or mock — implements this
single contract. The pipeline depends ONLY on this ABC, never on a concrete
implementation, so you can swap a Mock* class for a real PyTorch/HuggingFace
model WITHOUT touching the pipeline or the API layer.

TO ADD A REAL MODEL:
    1. Subclass BaseModelInference.
    2. Load weights in __init__ (e.g. transformers.AutoModel.from_pretrained...).
    3. Implement infer(payload) -> dict, returning the SAME shape the matching
       Mock* class returns (see each mock for the documented schema).
    4. Register it in app/pipeline/__init__.py's model registry.
===============================================================================
"""
from __future__ import annotations

import hashlib
from abc import ABC, abstractmethod
from typing import Any, Dict


class BaseModelInference(ABC):
    """Common contract for every inference model in the AETHER pipeline."""

    #: Human-readable name of the model this class stands in for.
    name: str = "base"
    #: What real architecture this represents (documentation only).
    backing_architecture: str = "abstract"

    @abstractmethod
    def infer(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        """Run inference on ``payload`` and return a JSON-serializable dict.

        ``payload`` always carries at least: ``file_type``, ``file_name``,
        ``content_b64`` (optional), ``sandbox_mode``.
        """
        raise NotImplementedError

    # ----------------------------------------------------------------------
    # Shared helpers used by the mocks to produce DETERMINISTIC output.
    # Determinism matters for the demo: the same input always yields the same
    # "embedding", so the UI and similarity scores are stable across runs.
    # (Date.now()/random are intentionally avoided.)
    # ----------------------------------------------------------------------
    @staticmethod
    def _seed_from(payload: Dict[str, Any]) -> int:
        basis = f"{payload.get('file_name','')}|{payload.get('content_b64','')}"
        digest = hashlib.sha256(basis.encode("utf-8")).hexdigest()
        return int(digest[:8], 16)

    @classmethod
    def _pseudo_vector(cls, payload: Dict[str, Any], dim: int) -> list[float]:
        """Return a deterministic, normalized [-1,1] vector of length ``dim``."""
        seed = cls._seed_from(payload)
        vec = []
        x = seed or 1
        for _ in range(dim):
            # simple LCG — deterministic, no external RNG state
            x = (1103515245 * x + 12345) & 0x7FFFFFFF
            vec.append(round((x / 0x7FFFFFFF) * 2 - 1, 6))
        return vec
