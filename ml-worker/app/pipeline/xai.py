"""
MockXAI — stands in for SHAP + LIME explainability over the model decisions.

REAL REPLACEMENT:
    - SHAP: shap.Explainer(model)(inputs) -> per-feature shapley values.
    - LIME: lime.lime_text / lime_tabular -> local feature importances.
Keep the return shape: { shap:{base_value, features:[{feature,contribution}]},
                         lime:{features:[{feature,importance}]}, prediction }.
The React AnalysisResults view renders these arrays directly as bar charts.
"""
from __future__ import annotations

import hashlib
from typing import Any, Dict, List

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
