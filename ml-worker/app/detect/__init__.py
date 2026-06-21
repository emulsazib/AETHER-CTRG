"""Real static malware-detection engine (pure stdlib, no native deps).

Analyzes the actual bytes of an uploaded artifact: cryptographic hashes,
entropy/packing, a signature ruleset, format-specific indicators (PDF/script/
archive/image), IoC extraction, statistical steganography, and a content-driven
risk verdict with genuine feature attribution.
"""
from .engine import analyze  # noqa: F401
