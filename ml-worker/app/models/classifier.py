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
    """Return (available, reason, display_name) without loading the model.

    ``CLASSIFIER_PATH`` may be either a local directory OR a HuggingFace Hub id
    (e.g. ``ealvaradob/bert-finetuned-phishing``) which auto-downloads on first
    use. ONNX models must be local (the bare ``model.onnx`` can't be hub-resolved).
    """
    path = os.getenv("CLASSIFIER_PATH")
    if not path:
        return False, "CLASSIFIER_PATH not set", None
    is_local = os.path.exists(path)
    is_hub_id = (not is_local) and "/" in path and " " not in path
    if not (is_local or is_hub_id):
        return False, f"model path not found and not a hub id: {path}", None
    if _backend() == "onnx" and not is_local:
        return False, f"onnx backend requires a local path, got hub id: {path}", None
    try:
        if _backend() == "onnx":
            import onnxruntime  # noqa: F401
            from transformers import AutoTokenizer  # noqa: F401
        else:
            import torch  # noqa: F401
            from transformers import AutoModelForSequenceClassification, AutoTokenizer  # noqa: F401
    except Exception as exc:  # noqa: BLE001
        return False, f"ML deps not installed ({exc}); pip install -r requirements-ml.txt", None
    reason = "ready" if is_local else "ready (auto-downloads on first use)"
    return True, reason, model_name()


def _features(data: bytes, file_type: str, text: str) -> str:
    """Turn an artifact into the model's input. MUST mirror your training pipeline.

    Default: a compact textual view of the decoded content. The ``[type]`` tag is
    opt-in via ``CLASSIFIER_PREFIX_TYPE`` — leave it OFF for general phishing/text
    classifiers (the tag is out-of-distribution for them) and ON if you trained
    your own model with it.
    """
    body = (text or "")[: int(os.getenv("CLASSIFIER_MAX_CHARS", "6000"))]
    if os.getenv("CLASSIFIER_PREFIX_TYPE", "false").strip().lower() in {"1", "true", "yes", "on"}:
        return f"[{file_type}] {body}"
    return body


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


def hf_bundle():
    """Return (tokenizer, model) for the HF backend, or None. Used by SHAP/LIME.

    Only valid when CLASSIFIER_BACKEND=hf and the model is available.
    """
    ok, _, _ = is_available()
    if not ok or _backend() == "onnx":
        return None
    try:
        kind, tok, model, _ = _load()
        return (tok, model) if kind == "hf" else None
    except Exception as exc:  # noqa: BLE001
        logger.warning("hf_bundle load failed (%s)", exc)
        return None


def predict_proba(texts):
    """Classifier probabilities for a LIST of strings → ndarray [n, n_classes].

    Matches LIME's classifier_fn contract. Returns None on any failure.
    """
    ok, _, _ = is_available()
    if not ok:
        return None
    try:
        kind, tok, model_or_sess, lib = _load()
        max_len = int(os.getenv("CLASSIFIER_MAX_LEN", "512"))
        if kind == "onnx":
            np = lib
            enc = tok(list(texts), truncation=True, max_length=max_len, padding=True, return_tensors="np")
            feed = {k: v for k, v in enc.items() if k in {i.name for i in model_or_sess.get_inputs()}}
            logits = model_or_sess.run(None, feed)[0]
            e = np.exp(logits - logits.max(axis=-1, keepdims=True))
            return e / e.sum(axis=-1, keepdims=True)
        torch = lib
        enc = tok(list(texts), truncation=True, max_length=max_len, padding=True, return_tensors="pt")
        with torch.no_grad():
            logits = model_or_sess(**enc).logits
            probs = torch.softmax(logits, dim=-1).cpu().numpy()
        return probs
    except Exception as exc:  # noqa: BLE001
        logger.warning("predict_proba failed (%s)", exc)
        return None
