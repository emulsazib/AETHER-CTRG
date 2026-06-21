"""Trained-model malware classifier — YOUR model plugs in here.

Drop a model you trained on a malware dataset into a directory, point
CLASSIFIER_PATH at it, install the ML deps (requirements-ml.txt), enable the
engine (UI toggle or ML_CLASSIFIER_ENABLED=true), and its score is ensembled
into the verdict.

Two backends are supported out of the box:
  * HuggingFace `AutoModelForSequenceClassification` (a fine-tuned transformer /
    "LLM" with a classification head) — the default.
  * ONNX Runtime (`CLASSIFIER_BACKEND=onnx`) — smaller/faster on CPU for an
    exported model; expects a `model.onnx` + a tokenizer in CLASSIFIER_PATH.

⚠️ ACCURACY: inference preprocessing MUST match how you trained. Edit
`_features()` below if your model expects bytes/PE-features instead of text.

Tunables (env):
  CLASSIFIER_PATH             dir with the model + tokenizer (required to enable)
  CLASSIFIER_NAME             display name shown in the UI/verdict (e.g. bert-malware-v1)
  CLASSIFIER_BACKEND          "hf" (default) | "onnx"
  CLASSIFIER_MALICIOUS_INDEX  output index that means "malicious" (default 1)
  CLASSIFIER_THRESHOLD        score >= threshold => malicious (default 0.5)
  CLASSIFIER_MAX_LEN          token truncation length (default 512)
"""
from __future__ import annotations

import logging
import os
from typing import Any, Dict, Optional, Tuple

logger = logging.getLogger("aether.classifier")

_BUNDLE = None  # lazily-loaded singleton (tokenizer, model/session, backend libs)


def model_name() -> str:
    return os.getenv("CLASSIFIER_NAME", "Trained ML Classifier")


def _backend() -> str:
    return os.getenv("CLASSIFIER_BACKEND", "hf").strip().lower()


def is_available() -> Tuple[bool, str, Optional[str]]:
    """Return (available, reason, display_name) without loading the model."""
    path = os.getenv("CLASSIFIER_PATH")
    if not path:
        return False, "CLASSIFIER_PATH not set", None
    if not os.path.exists(path):
        return False, f"model path not found: {path}", None
    try:
        if _backend() == "onnx":
            import onnxruntime  # noqa: F401
            from transformers import AutoTokenizer  # noqa: F401
        else:
            import torch  # noqa: F401
            from transformers import AutoModelForSequenceClassification, AutoTokenizer  # noqa: F401
    except Exception as exc:  # noqa: BLE001
        return False, f"ML deps not installed ({exc}); pip install -r requirements-ml.txt", None
    return True, "ready", model_name()


def _features(data: bytes, file_type: str, text: str) -> str:
    """Turn an artifact into the model's input. MUST mirror your training pipeline.

    Default: a compact textual view (type tag + decoded content). Replace with
    your byte-/PE-/image-feature extraction if you trained on those.
    """
    return f"[{file_type}] {(text or '')[: int(os.getenv('CLASSIFIER_MAX_CHARS', '6000'))]}"


def _load():
    global _BUNDLE
    if _BUNDLE is not None:
        return _BUNDLE
    path = os.getenv("CLASSIFIER_PATH")
    if _backend() == "onnx":
        import numpy as np
        import onnxruntime as ort
        from transformers import AutoTokenizer
        tok = AutoTokenizer.from_pretrained(path)
        sess = ort.InferenceSession(os.path.join(path, os.getenv("CLASSIFIER_ONNX_FILE", "model.onnx")))
        _BUNDLE = ("onnx", tok, sess, np)
    else:
        import torch
        from transformers import AutoModelForSequenceClassification, AutoTokenizer
        tok = AutoTokenizer.from_pretrained(path)
        mdl = AutoModelForSequenceClassification.from_pretrained(path).eval()
        _BUNDLE = ("hf", tok, mdl, torch)
    logger.info("Loaded ML classifier '%s' (%s backend).", model_name(), _backend())
    return _BUNDLE


def _softmax_np(np, logits):
    e = np.exp(logits - np.max(logits))
    return e / e.sum()


def predict(data: bytes, file_type: str, text: str) -> Optional[Dict[str, Any]]:
    """Run inference. Returns {score, label, model} or None on any failure."""
    ok, _, _ = is_available()
    if not ok:
        return None
    try:
        kind, tok, model_or_sess, lib = _load()
        feats = _features(data, file_type, text)
        max_len = int(os.getenv("CLASSIFIER_MAX_LEN", "512"))
        mal_idx = int(os.getenv("CLASSIFIER_MALICIOUS_INDEX", "1"))
        threshold = float(os.getenv("CLASSIFIER_THRESHOLD", "0.5"))

        if kind == "onnx":
            np = lib
            enc = tok(feats, truncation=True, max_length=max_len, return_tensors="np")
            feed = {k: v for k, v in enc.items() if k in {i.name for i in model_or_sess.get_inputs()}}
            logits = model_or_sess.run(None, feed)[0][0]
            probs = _softmax_np(np, logits)
        else:
            torch = lib
            enc = tok(feats, truncation=True, max_length=max_len, return_tensors="pt")
            with torch.no_grad():
                logits = model_or_sess(**enc).logits[0]
                probs = torch.softmax(logits, dim=-1).tolist()

        score = float(probs[mal_idx]) if len(probs) > mal_idx else float(max(probs))
        return {
            "score": round(score, 4),
            "label": "malicious" if score >= threshold else "benign",
            "model": model_name(),
        }
    except Exception as exc:  # noqa: BLE001 — never break analysis on a model error
        logger.warning("classifier inference failed (%s)", exc)
        return None
