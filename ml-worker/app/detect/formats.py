"""Format-specific static analyzers — operate on the real bytes.

Each returns a dict with `signals` (list of {feature, weight, ttps, note}) so the
engine can fold them into the risk score and explanation uniformly.
"""
from __future__ import annotations

import io
import re
import tarfile
import zipfile
from typing import Any, Dict, List

from .utils import shannon_entropy

# ---------------------------------------------------------------- PDF -------
_PDF_TOKENS = {
    b"/JavaScript": (0.4, ["T1059.007"], "Embedded JavaScript"),
    b"/JS": (0.35, ["T1059.007"], "Embedded JS action"),
    b"/OpenAction": (0.35, ["T1204.002"], "Auto-run OpenAction"),
    b"/AA": (0.3, ["T1204.002"], "Additional-actions trigger"),
    b"/Launch": (0.45, ["T1204.002"], "/Launch external command"),
    b"/EmbeddedFile": (0.4, ["T1027"], "Embedded file stream"),
    b"/RichMedia": (0.3, ["T1203"], "RichMedia/Flash object"),
    b"/JBIG2Decode": (0.3, ["T1203"], "JBIG2Decode (exploit-prone filter)"),
    b"/AcroForm": (0.12, ["T1204.002"], "AcroForm"),
}


def analyze_pdf(data: bytes) -> Dict[str, Any]:
    signals: List[Dict[str, Any]] = []
    for tok, (w, ttps, note) in _PDF_TOKENS.items():
        n = data.count(tok)
        if n:
            signals.append({"feature": f"pdf{tok.decode()}", "weight": w, "ttps": ttps, "note": f"{note} (x{n})"})
    return {"signals": signals, "object_streams": data.count(b"stream")}


# -------------------------------------------------------------- Scripts -----
_SCRIPT_PATTERNS = [
    (re.compile(rb"eval\s*\(", re.I), 0.25, ["T1059.007"], "eval()"),
    (re.compile(rb"unescape\s*\(", re.I), 0.2, ["T1027"], "unescape()"),
    (re.compile(rb"String\.fromCharCode", re.I), 0.2, ["T1027"], "fromCharCode array"),
    (re.compile(rb"atob\s*\(", re.I), 0.2, ["T1027"], "atob() base64 decode"),
    (re.compile(rb"document\.write", re.I), 0.18, ["T1059.007"], "document.write injection"),
    (re.compile(rb"ActiveXObject", re.I), 0.3, ["T1059.007"], "ActiveXObject"),
    (re.compile(rb"WScript\.Shell", re.I), 0.32, ["T1059"], "WScript.Shell"),
    (re.compile(rb"powershell", re.I), 0.3, ["T1059.001"], "powershell invocation"),
    (re.compile(rb"cmd(\.exe)?\s*/c", re.I), 0.25, ["T1059.003"], "cmd /c"),
]


def analyze_script(data: bytes) -> Dict[str, Any]:
    signals: List[Dict[str, Any]] = []
    for rx, w, ttps, note in _SCRIPT_PATTERNS:
        if rx.search(data):
            signals.append({"feature": f"js:{note}", "weight": w, "ttps": ttps, "note": note})
    # Char-code obfuscation density.
    charcodes = len(re.findall(rb"\\x[0-9a-f]{2}", data, re.I)) + len(re.findall(rb"%[0-9a-f]{2}", data, re.I))
    if charcodes > 40:
        signals.append({"feature": "js:hex_escape_density", "weight": 0.22, "ttps": ["T1027"], "note": f"{charcodes} escaped chars"})
    return {"signals": signals, "escaped_chars": charcodes}


# ------------------------------------------------------------- Archives -----
_EXE_EXT = (".exe", ".dll", ".scr", ".com", ".pif", ".cpl", ".sys")
_SCRIPT_EXT = (".js", ".vbs", ".ps1", ".bat", ".cmd", ".hta", ".wsf", ".jar", ".lnk")


def analyze_archive(data: bytes) -> Dict[str, Any]:
    signals: List[Dict[str, Any]] = []
    names: List[str] = []
    encrypted = False
    ratio = 0.0
    try:
        if zipfile.is_zipfile(io.BytesIO(data)):
            zf = zipfile.ZipFile(io.BytesIO(data))
            names = zf.namelist()[:200]
            comp = sum(i.compress_size for i in zf.infolist()) or 1
            uncomp = sum(i.file_size for i in zf.infolist())
            ratio = round(uncomp / comp, 1)
            encrypted = any(i.flag_bits & 0x1 for i in zf.infolist())
        else:
            try:
                tf = tarfile.open(fileobj=io.BytesIO(data))
                names = tf.getnames()[:200]
            except Exception:
                pass
    except Exception:
        pass

    lower = [n.lower() for n in names]
    if any(n.endswith(_EXE_EXT) for n in lower):
        signals.append({"feature": "archive:bundled_executable", "weight": 0.4, "ttps": ["T1204.002"], "note": "executable inside archive"})
    if any(n.endswith(_SCRIPT_EXT) for n in lower):
        signals.append({"feature": "archive:bundled_script", "weight": 0.35, "ttps": ["T1204.002", "T1059"], "note": "script inside archive"})
    if any(re.search(r"\.(jpg|png|pdf|doc|txt)\.(exe|scr|js|vbs|bat)$", n) for n in lower):
        signals.append({"feature": "archive:double_extension", "weight": 0.45, "ttps": ["T1036.007"], "note": "double-extension masquerade"})
    if encrypted:
        signals.append({"feature": "archive:encrypted", "weight": 0.18, "ttps": ["T1027"], "note": "password-protected archive (evasion)"})
    if ratio and ratio > 200:
        signals.append({"feature": "archive:high_compression_ratio", "weight": 0.2, "ttps": ["T1499"], "note": f"compression ratio {ratio}x"})
    return {"signals": signals, "entries": names, "encrypted": encrypted, "compression_ratio": ratio}


# --------------------------------------------------------------- Images -----
_IMG_EOF = {b"\x89PNG": b"IEND\xaeB`\x82", b"\xff\xd8": b"\xff\xd9", b"GIF8": b"\x00\x3b"}
_EMBED_SIGS = {
    b"PK\x03\x04": ("ZIP", ["T1027.003"]),
    b"MZ": ("PE executable", ["T1027", "T1204.002"]),
    b"Rar!": ("RAR", ["T1027.003"]),
    b"7z\xbc\xaf": ("7z", ["T1027.003"]),
    b"<script": ("inline script", ["T1059.007"]),
    b"powershell": ("PowerShell", ["T1059.001"]),
}


def analyze_image(data: bytes) -> Dict[str, Any]:
    """Statistical / structural steganography & polyglot detection (no pixel model)."""
    signals: List[Dict[str, Any]] = []
    has_stego = False
    technique = None
    hidden_preview = None

    # 1) Trailing data appended after the image's logical EOF marker.
    trailing = b""
    for magic, eof in _IMG_EOF.items():
        if data.startswith(magic):
            idx = data.rfind(eof)
            if idx != -1 and idx + len(eof) < len(data) - 16:
                trailing = data[idx + len(eof):]
            break

    # 2) Embedded foreign file signatures anywhere in the body.
    for sig, (label, ttps) in _EMBED_SIGS.items():
        pos = data.find(sig, 8)
        if pos != -1:
            has_stego = True
            technique = f"embedded_{label}"
            signals.append({"feature": f"image:embedded_{label}", "weight": 0.5, "ttps": ttps, "note": f"{label} signature at offset {pos}"})

    if trailing:
        has_stego = True
        technique = technique or "appended_payload"
        signals.append({"feature": "image:trailing_payload", "weight": 0.45, "ttps": ["T1027.003"], "note": f"{len(trailing)} bytes after image EOF"})
        printable = bytes(b for b in trailing[:80] if 32 <= b < 127)
        if len(printable) >= 8:
            hidden_preview = printable.decode("latin-1", errors="replace")

    ent = shannon_entropy(data)
    return {
        "signals": signals,
        "has_stego": has_stego,
        "technique": technique,
        "hidden_text": hidden_preview,
        "confidence": round(min(0.5 + 0.1 * len(signals) + (0.1 if trailing else 0), 0.99), 2) if has_stego else round(min(ent / 16, 0.3), 2),
        "entropy": ent,
    }
