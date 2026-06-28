"""
Explainability.

REAL: ``RealXAI`` computes genuine SHAP (token Shapley values via a Transformers
pipeline) + LIME local importances over the HF classifier. It is perf-gated by the
pipeline (ML-on + Deep sandbox + caps) because SHAP on transformers is slow.

FALLBACK: the pipeline's static signal-attribution (the fired detection signals as
contributions) — and ``MockXAI`` — when the classifier/ML extras are unavailable.
All paths emit the SAME shape: { shap:{base_value, features:[{feature,contribution}]},
lime:{features:[{feature,importance}]}, prediction }. XaiCharts.jsx renders it directly.
"""
from __future__ import annotations

import hashlib
import logging
import os
from typing import Any, Dict, List, Optional

logger = logging.getLogger("aether.xai")

# Candidate behavioral features the explainer attributes scores to. A real SHAP
# run would derive these from the model's actual input features.
_FEATURE_POOL = [
    "obfuscated_strings",
    "encoded_powershell",
    "suspicious_api_calls",
    "network_beacon",
    "registry_persistence",
    "entropy_high_section",
    "known_c2_domain",
    "child_process_spawn",
]


class MockXAI:
    name = "xai_shap_lime"
    backing_architecture = "SHAP + LIME (mock)"

    def explain(self, payload: Dict[str, Any], features: Dict[str, Any]) -> Dict[str, Any]:
        # MOCK: deterministic attributions derived from input hash. Replace with
        # real SHAP/LIME — keep the { shap, lime, prediction } shape.
        seed = int(
            hashlib.sha256(str(payload.get("file_name", "")).encode()).hexdigest()[:8],
            16,
        )

        shap_features: List[Dict[str, Any]] = []
        for i, feat in enumerate(_FEATURE_POOL):
            # Slight positive bias: ingested artifacts are suspicious by default,
            # so contributions skew toward "malicious" (mirrors the seeded jobs).
            raw = (((seed >> i) % 200) - 70) / 100.0  # ~[-0.7, 1.3]
            raw = max(min(raw, 1.0), -1.0)
            shap_features.append({"feature": feat, "contribution": round(raw, 3)})
        # Sort by absolute contribution (most influential first) — SHAP convention.
        shap_features.sort(key=lambda f: abs(f["contribution"]), reverse=True)

        base_value = 0.5
        prediction = round(
            min(max(base_value + sum(f["contribution"] for f in shap_features) / len(shap_features), 0.0), 1.0),
            3,
        )

        lime_features = [
            {"feature": f["feature"], "importance": round(abs(f["contribution"]), 3)}
            for f in shap_features[:5]
        ]

        return {
            "model": self.name,
            "backing_architecture": self.backing_architecture,
            "prediction": prediction,
            "predicted_label": "malicious" if prediction >= 0.5 else "benign",
            "shap": {"base_value": base_value, "features": shap_features},
            "lime": {"features": lime_features},
        }


def _clean_token(tok: str) -> str:
    """Strip BPE/word-piece markers and whitespace from a SHAP token."""
    return tok.replace("Ġ", "").replace("▁", "").replace("Ċ", " ").strip()


_SPECIAL_TOKENS = {"", "<s>", "</s>", "[CLS]", "[SEP]", "[PAD]", "<pad>"}


class RealXAI:
    """Real SHAP + LIME over the HuggingFace text classifier."""

    name = "xai_shap_lime"
    backing_architecture = "SHAP(Transformers) + LIME over HF classifier"

    def explain_text(self, text: str, mal_idx: int) -> Optional[Dict[str, Any]]:
        """Return {shap_features, lime_features, base_value} or None on failure."""
        from app.models import classifier

        bundle = classifier.hf_bundle()
        if bundle is None:
            return None
        tok, model = bundle

        max_chars = int(os.getenv("XAI_MAX_CHARS", "1200"))
        snippet = (text or "")[:max_chars]
        if not snippet.strip():
            return None

        shap_features = self._shap(model, tok, snippet, mal_idx)
        lime_features = self._lime(classifier.predict_proba, snippet, mal_idx)
        if shap_features is None and lime_features is None:
            return None
        return {
            "shap_features": shap_features or [],
            "lime_features": lime_features or [],
            "base_value": self._base_value,
        }

    # ---- SHAP -----------------------------------------------------------------
    def _shap(self, model, tok, text: str, mal_idx: int):
        self._base_value = 0.0
        try:
            import shap
            import torch
            import transformers

            device = 0 if torch.cuda.is_available() else -1
            pred = transformers.pipeline(
                "text-classification", model=model, tokenizer=tok, top_k=None, device=device
            )
            explainer = shap.Explainer(pred)
            sv = explainer([text], max_evals=int(os.getenv("XAI_SHAP_MAX_EVALS", "240")))

            values = sv.values[0]
            tokens = sv.data[0]
            # values: [n_tokens, n_classes] (multi-class) or [n_tokens] (single).
            try:
                col = [float(v[mal_idx]) for v in values]
            except (TypeError, IndexError):
                col = [float(v) for v in values]
            try:
                bv = sv.base_values[0]
                self._base_value = float(bv[mal_idx]) if hasattr(bv, "__len__") else float(bv)
            except Exception:  # noqa: BLE001
                self._base_value = 0.0

            feats: List[Dict[str, Any]] = []
            for t, v in zip(tokens, col):
                name = _clean_token(str(t))
                if name and name not in _SPECIAL_TOKENS:
                    feats.append({"feature": name, "contribution": round(v, 3)})
            feats.sort(key=lambda f: abs(f["contribution"]), reverse=True)
            return feats[: int(os.getenv("XAI_SHAP_TOPK", "12"))]
        except Exception as exc:  # noqa: BLE001
            logger.warning("SHAP explanation failed (%s).", exc)
            return None

    # ---- LIME -----------------------------------------------------------------
    def _lime(self, predict_proba, text: str, mal_idx: int):
        try:
            from lime.lime_text import LimeTextExplainer

            def proba_fn(xs):
                out = predict_proba(xs)
                if out is None:
                    raise RuntimeError("predict_proba unavailable")
                return out

            explainer = LimeTextExplainer(class_names=["benign", "malicious"])
            exp = explainer.explain_instance(
                text,
                proba_fn,
                num_features=int(os.getenv("XAI_LIME_TOPK", "5")),
                num_samples=int(os.getenv("XAI_LIME_SAMPLES", "200")),
                labels=(mal_idx,),
            )
            return [
                {"feature": w, "importance": round(abs(s), 3)}
                for w, s in exp.as_list(label=mal_idx)
            ]
        except Exception as exc:  # noqa: BLE001
            logger.warning("LIME explanation failed (%s).", exc)
            return None
