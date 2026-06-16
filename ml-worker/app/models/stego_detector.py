"""
MockSteganographyDetector — stands in for a CLIP + LLM pipeline that inspects
images for hidden/steganographic payloads.

REAL REPLACEMENT:
    1. CLIP-embed the image and compare against "contains hidden data" prompts.
    2. Run an LSB/stego extractor; feed any recovered bytes to an LLM
       (LLM_API_KEY) to decode/interpret hidden text.
Keep the return shape: { has_stego, confidence, hidden_text, technique }.
"""
from __future__ import annotations

from typing import Any, Dict

from .base import BaseModelInference


class MockSteganographyDetector(BaseModelInference):
    name = "steganography_detector"
    backing_architecture = "CLIP + LLM (mock)"

    def infer(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        # MOCK: deterministic flag derived from the input hash so the demo is
        # stable. Replace with real CLIP scoring + LSB extraction + LLM decode.
        seed = self._seed_from(payload)
        has_stego = (seed % 2) == 0
        confidence = round(0.5 + (seed % 50) / 100.0, 3)  # 0.50 - 0.99
        return {
            "model": self.name,
            "backing_architecture": self.backing_architecture,
            "has_stego": has_stego,
            "confidence": confidence,
            "technique": "LSB" if has_stego else None,
            "hidden_text": (
                "powershell -nop -w hidden -enc <base64-c2-beacon>"
                if has_stego
                else None
            ),
        }
