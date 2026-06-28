"""
Shared runtime helpers for the REAL inference models (CodeBERT, ResNet-50, CLIP,
the HF classifier, SHAP/LIME). Centralizes three concerns so every real model
behaves identically:

  1. DEVICE selection  — ``ML_DEVICE`` env (auto|cpu|cuda|mps); ``auto`` picks CUDA
     when available, else CPU. (In Docker we only honour cuda/cpu; mps is a
     host-Mac convenience, gated behind an explicit ML_DEVICE=mps.)
  2. DEPENDENCY probing — ``ml_available("transformers")`` returns False when the
     heavy ML extras (requirements-ml.txt) are not installed, so callers can fall
     back to their deterministic Mock* implementation instead of crashing.
  3. LAZY SINGLETONS    — ``singleton(key, builder)`` loads a model once per
     process under a lock (uvicorn serves /analyze concurrently).

Golden rule wired in here: a real model that fails to import/load/infer logs ONCE
and the caller transparently uses the Mock/static path. /analyze must never 500.
"""
from __future__ import annotations

import importlib
import logging
import os
import threading
from typing import Any, Callable, Dict

logger = logging.getLogger("aether.runtime")

_LOCK = threading.Lock()
_SINGLETONS: Dict[str, Any] = {}
_AVAIL_CACHE: Dict[str, bool] = {}


def get_device() -> str:
    """Resolve the torch device string from ML_DEVICE (auto|cpu|cuda|mps)."""
    want = os.getenv("ML_DEVICE", "auto").strip().lower()
    try:
        import torch
    except Exception:  # noqa: BLE001 — torch absent => caller falls back to mock
        return "cpu"
    if want == "cpu":
        return "cpu"
    if want == "cuda":
        return "cuda" if torch.cuda.is_available() else "cpu"
    if want == "mps":
        return "mps" if getattr(torch.backends, "mps", None) and torch.backends.mps.is_available() else "cpu"
    # auto: prefer CUDA in the GPU container; never auto-pick MPS (host-only).
    return "cuda" if torch.cuda.is_available() else "cpu"


def ml_available(*modules: str) -> bool:
    """True only when torch AND every named module import cleanly. Cached."""
    key = "torch|" + "|".join(sorted(modules))
    if key in _AVAIL_CACHE:
        return _AVAIL_CACHE[key]
    ok = True
    for mod in ("torch", *modules):
        try:
            importlib.import_module(mod)
        except Exception as exc:  # noqa: BLE001
            logger.info("ML dep '%s' unavailable (%s) — using mock fallback.", mod, exc)
            ok = False
            break
    _AVAIL_CACHE[key] = ok
    return ok


def singleton(key: str, builder: Callable[[], Any]) -> Any:
    """Return a process-wide lazily-built singleton for ``key``.

    ``builder`` is invoked at most once (double-checked under a lock). If it
    raises, the exception propagates to the caller, which is expected to catch it
    and fall back to its mock path.
    """
    obj = _SINGLETONS.get(key)
    if obj is not None:
        return obj
    with _LOCK:
        obj = _SINGLETONS.get(key)
        if obj is None:
            obj = builder()
            _SINGLETONS[key] = obj
        return obj
