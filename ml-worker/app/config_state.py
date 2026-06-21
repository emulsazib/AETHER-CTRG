"""Runtime AI-engine configuration — what's available and what's currently on.

Three detection engines can contribute to a verdict:
  * static  — the built-in signature/heuristic engine (always on, cannot be disabled)
  * ml      — your trained classifier model (app/models/classifier.py)
  * llm     — an external OpenAI-compatible LLM (app/models/llm.py)

Availability is derived from the environment (key present / model files present).
Enablement is a RUNTIME toggle (changed live via POST /config from the UI) and
defaults from env, so users can turn engines on/off without a restart and pick
exactly which AI systems run.
"""
from __future__ import annotations

import os
from typing import Any, Dict, Optional

# Runtime overrides. None => fall back to the env-derived default.
_runtime: Dict[str, Optional[bool]] = {"ml_enabled": None, "llm_enabled": None}


def _env_bool(name: str, default: bool = False) -> bool:
    return os.getenv(name, str(default)).strip().lower() in {"1", "true", "yes", "on"}


def _ml_availability():
    """Return (available, reason, model_name) for the trained-model engine."""
    from app.models import classifier  # lazy: avoids importing torch at startup
    return classifier.is_available()


def _llm_availability():
    available = bool(os.getenv("AI_API_KEY"))
    return available, ("ready" if available else "AI_API_KEY not set"), os.getenv("AI_MODEL", "gpt-4o-mini")


def get_config() -> Dict[str, Any]:
    ml_avail, ml_reason, ml_name = _ml_availability()
    llm_avail, llm_reason, llm_name = _llm_availability()

    ml_default = _env_bool("ML_CLASSIFIER_ENABLED", False) and ml_avail
    llm_default = llm_avail  # if a key is configured, default the LLM engine on

    ml_enabled = ml_default if _runtime["ml_enabled"] is None else (_runtime["ml_enabled"] and ml_avail)
    llm_enabled = llm_default if _runtime["llm_enabled"] is None else (_runtime["llm_enabled"] and llm_avail)

    return {
        "engines": {
            "static": {
                "id": "static",
                "name": "Static Detection Engine",
                "description": "Signature + heuristic analysis of the real file bytes. Always on.",
                "available": True,
                "enabled": True,
                "locked": True,
            },
            "ml": {
                "id": "ml",
                "name": ml_name or "Trained ML Classifier",
                "description": "Your custom-trained model. Ensembled with the static engine for the verdict.",
                "available": ml_avail,
                "enabled": bool(ml_enabled),
                "locked": False,
                "reason": ml_reason,
            },
            "llm": {
                "id": "llm",
                "name": f"External LLM ({llm_name})",
                "description": "OpenAI-compatible LLM that enriches IoC/TTP extraction & summaries.",
                "available": llm_avail,
                "enabled": bool(llm_enabled),
                "locked": False,
                "reason": llm_reason,
            },
        }
    }


def update_config(ml_enabled: Optional[bool] = None, llm_enabled: Optional[bool] = None) -> Dict[str, Any]:
    if ml_enabled is not None:
        _runtime["ml_enabled"] = bool(ml_enabled)
    if llm_enabled is not None:
        _runtime["llm_enabled"] = bool(llm_enabled)
    return get_config()


def is_ml_on() -> bool:
    return get_config()["engines"]["ml"]["enabled"]


def is_llm_on() -> bool:
    return get_config()["engines"]["llm"]["enabled"]
