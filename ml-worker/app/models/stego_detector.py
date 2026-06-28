"""
Steganography detection for images.

REAL: ``ClipStegoDetector`` — a three-stage CLIP + LSB + LLM pipeline:
  1. CLIP (open_clip ViT-B/32) scores the image against "contains hidden data"
     vs "ordinary photo" prompts → a soft suspicion prior.
  2. LSB bit-plane extraction (numpy) recovers the least-significant-bit stream and
     looks for a contiguous printable run (the classic LSB payload signature).
  3. If a candidate run is found and an LLM is configured, the recovered bytes are
     sent to the external LLM (llm.decode_hidden) to decode/interpret hidden_text.

FALLBACK: ``MockSteganographyDetector`` — deterministic flag, used when ML extras
are absent or the image can't be decoded. ``get_stego_detector()`` picks one.
Return shape is preserved: { has_stego, confidence, technique, hidden_text }.

NOTE: LSB is only meaningful for lossless formats (PNG/BMP/GIF); for JPEG the CLIP
prior + the engine's structural checks carry the signal.
"""
from __future__ import annotations

import io
import logging
import os
from typing import Any, Dict, List

from . import _runtime
from .base import BaseModelInference

logger = logging.getLogger("aether.stego")

CLIP_MODEL = os.getenv("CLIP_MODEL", "ViT-B-32")
CLIP_PRETRAINED = os.getenv("CLIP_PRETRAINED", "laion2b_s34b_b79k")
STEGO_MIN_PRINTABLE = int(os.getenv("STEGO_MIN_PRINTABLE", "12"))
STEGO_MAX_BYTES = int(os.getenv("STEGO_MAX_BYTES", "256"))

_SUSPICIOUS_PROMPTS = [
    "an image containing hidden data",
    "a steganographic image with a concealed payload",
    "an image with hidden text encoded in the pixels",
    "noisy corrupted-looking pixels",
]
_BENIGN_PROMPTS = [
    "a normal photograph",
    "a clean ordinary picture",
    "a typical everyday photo",
]


class MockSteganographyDetector(BaseModelInference):
    name = "steganography_detector"
    backing_architecture = "CLIP + LLM (mock)"

    def infer(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        seed = self._seed_from(payload)
        has_stego = (seed % 2) == 0
        confidence = round(0.5 + (seed % 50) / 100.0, 3)
        return {
            "model": self.name,
            "backing_architecture": self.backing_architecture,
            "has_stego": has_stego,
            "confidence": confidence,
            "technique": "LSB" if has_stego else None,
            "hidden_text": (
                "powershell -nop -w hidden -enc <base64-c2-beacon>" if has_stego else None
            ),
        }


def _longest_printable_run(buf: bytes) -> bytes:
    best_start = best_len = cur_start = cur_len = 0
    for i, b in enumerate(buf):
        if 32 <= b < 127:
            if cur_len == 0:
                cur_start = i
            cur_len += 1
            if cur_len > best_len:
                best_len, best_start = cur_len, cur_start
        else:
            cur_len = 0
    return buf[best_start:best_start + best_len]


class ClipStegoDetector(BaseModelInference):
    name = "steganography_detector"
    backing_architecture = "CLIP ViT-B/32 + LSB extractor + LLM decode"

    def __init__(self) -> None:
        self._fallback = MockSteganographyDetector()

    def _bundle(self):
        def build():
            import open_clip
            import torch

            device = _runtime.get_device()
            model, _, preprocess = open_clip.create_model_and_transforms(
                CLIP_MODEL, pretrained=CLIP_PRETRAINED
            )
            tokenizer = open_clip.get_tokenizer(CLIP_MODEL)
            model = model.eval().to(device)
            logger.info("Loaded CLIP %s/%s on %s.", CLIP_MODEL, CLIP_PRETRAINED, device)
            return model, preprocess, tokenizer, device, torch

        return _runtime.singleton(f"clip::{CLIP_MODEL}::{CLIP_PRETRAINED}", build)

    def _clip_suspicion(self, img) -> float:
        model, preprocess, tokenizer, device, torch = self._bundle()
        prompts: List[str] = _SUSPICIOUS_PROMPTS + _BENIGN_PROMPTS
        image = preprocess(img).unsqueeze(0).to(device)
        text = tokenizer(prompts).to(device)
        with torch.no_grad():
            img_f = model.encode_image(image)
            txt_f = model.encode_text(text)
            img_f = img_f / img_f.norm(dim=-1, keepdim=True)
            txt_f = txt_f / txt_f.norm(dim=-1, keepdim=True)
            sims = (img_f @ txt_f.T).squeeze(0)
        n_sus = len(_SUSPICIOUS_PROMPTS)
        sus = float(sims[:n_sus].max())
        ben = float(sims[n_sus:].max())
        # 2-way softmax over the best suspicious vs best benign similarity.
        import math

        e_sus, e_ben = math.exp(sus * 100), math.exp(ben * 100)
        return e_sus / (e_sus + e_ben)

    def _lsb_extract(self, img):
        import numpy as np

        arr = np.asarray(img.convert("RGB"), dtype=np.uint8)
        lsb = (arr & 1).astype(np.uint8).flatten()
        packed = np.packbits(lsb).tobytes()[: 4 * STEGO_MAX_BYTES]
        run = _longest_printable_run(packed)[:STEGO_MAX_BYTES]
        # LSB uniformity: natural images sit near 0.5; strong deviation is suspicious.
        bias = abs(float(lsb.mean()) - 0.5) if lsb.size else 0.0
        return run, bias

    def infer(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        from app.detect.utils import decode_b64

        data = decode_b64(payload.get("content_b64"))
        if not data:
            return self._fallback.infer(payload)
        try:
            from PIL import Image

            Image.MAX_IMAGE_PIXELS = int(os.getenv("IMAGE_MAX_PIXELS", str(64_000_000)))
            img = Image.open(io.BytesIO(data)).convert("RGB")
        except Exception as exc:  # noqa: BLE001
            logger.warning("Stego image decode failed (%s); using mock.", exc)
            return self._fallback.infer(payload)

        try:
            run, bias = self._lsb_extract(img)
        except Exception as exc:  # noqa: BLE001
            logger.warning("LSB extraction failed (%s).", exc)
            run, bias = b"", 0.0

        try:
            clip_suspicion = self._clip_suspicion(img)
        except Exception as exc:  # noqa: BLE001
            logger.warning("CLIP scoring failed (%s); LSB-only.", exc)
            clip_suspicion = 0.0

        run_len = len(run)
        has_run = run_len >= STEGO_MIN_PRINTABLE
        lsb_signal = min(0.5 + 0.02 * run_len, 0.95) if has_run else min(bias * 1.5, 0.4)
        confidence = round(min(0.6 * lsb_signal + 0.4 * clip_suspicion, 0.99), 3)
        has_stego = bool(has_run or clip_suspicion >= 0.85)
        technique = "LSB" if has_run else ("CLIP-flagged" if clip_suspicion >= 0.85 else None)

        hidden_text = None
        if has_run:
            preview = run.decode("latin-1", errors="replace")
            hidden_text = preview
            try:
                from app.models import llm

                if llm.is_configured():
                    decoded = llm.decode_hidden(preview, payload.get("file_type", "Image"))
                    if decoded:
                        hidden_text = decoded
            except Exception as exc:  # noqa: BLE001 — best-effort decode
                logger.info("LLM stego decode skipped (%s).", exc)

        return {
            "model": self.name,
            "backing_architecture": self.backing_architecture,
            "has_stego": has_stego,
            "confidence": confidence,
            "technique": technique,
            "hidden_text": hidden_text,
        }


def get_stego_detector() -> BaseModelInference:
    """Real CLIP+LSB detector when ML extras are installed, else the mock."""
    if _runtime.ml_available("open_clip"):
        return ClipStegoDetector()
    return MockSteganographyDetector()
