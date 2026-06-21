"""Low-level helpers: hashing, Shannon entropy, base64 decode, defanging."""
from __future__ import annotations

import base64
import hashlib
import math
from typing import Optional


def decode_b64(content_b64: Optional[str]) -> bytes:
    if not content_b64:
        return b""
    try:
        return base64.b64decode(content_b64)
    except Exception:
        return b""


def file_hashes(data: bytes) -> dict:
    return {
        "md5": hashlib.md5(data).hexdigest(),
        "sha1": hashlib.sha1(data).hexdigest(),
        "sha256": hashlib.sha256(data).hexdigest(),
    }


def shannon_entropy(data: bytes) -> float:
    """Bits-per-byte entropy (0..8). >7.2 typically indicates packing/encryption."""
    if not data:
        return 0.0
    freq = [0] * 256
    for b in data:
        freq[b] += 1
    n = len(data)
    ent = 0.0
    for c in freq:
        if c:
            p = c / n
            ent -= p * math.log2(p)
    return round(ent, 3)


def as_text(data: bytes, limit: int = 200_000) -> str:
    """Lossy decode for regex/string scanning (latin-1 keeps byte values 1:1)."""
    return data[:limit].decode("latin-1", errors="replace")


def safe_defang(value: str) -> str:
    """Defang domains/URLs/IPs consistently (every dot, scheme neutralized)."""
    v = value.replace("https://", "hxxps://").replace("http://", "hxxp://")
    return v.replace(".", "[.]")
