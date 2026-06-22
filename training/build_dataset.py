#!/usr/bin/env python3
"""
AETHER — Malware → Dual-Format LLM Training Dataset Builder
===========================================================

Offline data-engineering tool. Ingests password-protected ZIP archives of Windows
executables (the MalwareBazaar / VirusTotal convention: password ``infected``),
extracts static features *entirely in memory*, and emits TWO JSONL training files:

  * aether_openai_dataset.jsonl  — OpenAI GPT-4o-mini fine-tune format (messages[])
  * aether_llama3_dataset.jsonl  — Llama 3 Instruct format (single "text" key with
                                   exact Llama 3 special tokens, for Unsloth)

SECURITY: the raw .exe is NEVER written to host disk — every sample is read into an
in-memory ``io.BytesIO`` buffer and parsed there.

Usage
-----
    python build_dataset.py                          # uses ./malware_sample.zip
    python build_dataset.py -i samples/              # batch every *.zip in a folder
    python build_dataset.py -i a.zip -p infected \\
        --openai-out openai.jsonl --llama-out llama3.jsonl

Dependencies:  pefile   (required)
               pyzipper (optional — only needed for AES-encrypted zips)
"""
from __future__ import annotations

import argparse
import io
import json
import logging
import os
import re
import sys
import zipfile
from typing import Iterator, List, Optional, Tuple

try:
    import pefile
except ImportError:  # pragma: no cover - guidance for a missing required dep
    sys.exit("Missing dependency 'pefile'. Install with: pip install -r requirements.txt")

# pyzipper is optional; only used as a fallback for AES-encrypted archives.
try:
    import pyzipper  # type: ignore
except ImportError:  # pragma: no cover
    pyzipper = None

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
log = logging.getLogger("aether.dataset")

# ---------------------------------------------------------------------------
# Fixed training prompt + mock target (verbatim per the AETHER spec).
# ---------------------------------------------------------------------------
SYSTEM_PROMPT = (
    "You are AETHER's threat intelligence extractor. Analyze the static features of "
    "this Windows executable and return a JSON array of potential MITRE ATT&CK codes."
)
# Placeholder label — replace with real analyst/labeled output before production training.
MOCK_ASSISTANT_RESPONSE = (
    '[{"tactic": "TA0005", "technique": "T1027", '
    '"comment": "Static features extracted successfully."}]'
)

DEFAULT_PASSWORD = b"infected"
ASCII_STRING_RE = re.compile(rb"[\x20-\x7e]{10,}")  # printable ASCII, min length 10
MAX_STRINGS = 20  # cap to prevent context-window bloat

# ===========================================================================
# Static feature extraction (in-memory only)
# ===========================================================================
def _extract_imports(pe: "pefile.PE") -> List[str]:
    """Return 'DLL!ApiName' entries for every imported Windows API."""
    imports: List[str] = []
    # DIRECTORY_ENTRY_IMPORT only exists when the binary actually imports symbols.
    for entry in getattr(pe, "DIRECTORY_ENTRY_IMPORT", []) or []:
        dll = (entry.dll or b"").decode("utf-8", "replace") if entry.dll else "UNKNOWN.dll"
        for imp in entry.imports:
            if imp.name:  # named import
                api = imp.name.decode("utf-8", "replace")
            else:  # ordinal-only import
                api = f"ordinal_{imp.ordinal}"
            imports.append(f"{dll}!{api}")
    return imports


def _extract_strings(data: bytes, limit: int = MAX_STRINGS) -> List[str]:
    """First `limit` printable-ASCII strings (>=10 chars) from the raw bytes."""
    out: List[str] = []
    for match in ASCII_STRING_RE.finditer(data):
        out.append(match.group().decode("ascii", "replace"))
        if len(out) >= limit:
            break
    return out


def extract_features(data: bytes) -> Optional[str]:
    """Parse an in-memory PE and build the structured `user_input` text block.

    Returns the feature block string, or ``None`` if the bytes are not a valid PE
    (so the caller can skip non-Windows / corrupt entries gracefully).
    """
    try:
        # fast_load=True skips full data-directory parsing; we then load only imports.
        pe = pefile.PE(data=data, fast_load=True)
        pe.parse_data_directories(
            directories=[pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_IMPORT"]]
        )
    except pefile.PEFormatError as exc:
        log.warning("Skipping non-PE / malformed binary: %s", exc)
        return None
    except Exception as exc:  # noqa: BLE001 - never let one sample kill the run
        log.warning("Skipping binary (parse error): %s", exc)
        return None

    try:
        imports = _extract_imports(pe)
        strings = _extract_strings(data)
    finally:
        pe.close()  # release the in-memory mapping

    if not imports and not strings:
        log.warning("Skipping binary: no imports or strings recovered.")
        return None

    api_block = "\n".join(imports) if imports else "(none recovered)"
    str_block = "\n".join(strings) if strings else "(none recovered)"

    return (
        "## API Imports (DLL!Function)\n"
        f"{api_block}\n\n"
        f"## ASCII Strings (first {MAX_STRINGS}, min length 10)\n"
        f"{str_block}"
    )


# ===========================================================================
# Dual-format JSONL record builders
# ===========================================================================
def to_openai_record(user_input: str) -> dict:
    """Strict OpenAI chat fine-tuning record: a 3-role `messages` array."""
    return {
        "messages": [
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": user_input},
            {"role": "assistant", "content": MOCK_ASSISTANT_RESPONSE},
        ]
    }


def to_llama3_record(user_input: str) -> dict:
    """Llama 3 Instruct record: a single `text` key using exact Llama 3 tokens.

    Layout (Unsloth-compatible):
      <|begin_of_text|>
      <|start_header_id|>system<|end_header_id|>\n\n{system}<|eot_id|>
      <|start_header_id|>user<|end_header_id|>\n\n{user}<|eot_id|>
      <|start_header_id|>assistant<|end_header_id|>\n\n{assistant}<|eot_id|>
    """
    text = (
        "<|begin_of_text|>"
        f"<|start_header_id|>system<|end_header_id|>\n\n{SYSTEM_PROMPT}<|eot_id|>"
        f"<|start_header_id|>user<|end_header_id|>\n\n{user_input}<|eot_id|>"
        f"<|start_header_id|>assistant<|end_header_id|>\n\n{MOCK_ASSISTANT_RESPONSE}<|eot_id|>"
    )
    return {"text": text}


# ===========================================================================
# Secure in-memory ZIP ingestion
# ===========================================================================
def _iter_zip_members(zip_path: str, password: bytes) -> Iterator[Tuple[str, bytes]]:
    """Yield (member_name, member_bytes) for each file entry in a protected zip.

    Reads everything in memory. Tries stdlib zipfile (ZipCrypto, as used by
    MalwareBazaar); falls back to pyzipper for AES-encrypted archives if available.
    """
    # 1) stdlib zipfile — handles legacy ZipCrypto.
    try:
        with zipfile.ZipFile(zip_path) as zf:
            for info in zf.infolist():
                if info.is_dir():
                    continue
                try:
                    yield info.filename, zf.read(info, pwd=password)
                except RuntimeError as exc:
                    # Typically "Bad password" OR an AES entry stdlib can't decrypt.
                    if "encrypt" in str(exc).lower() or "compress" in str(exc).lower():
                        raise NotImplementedError(str(exc))
                    log.warning("Cannot read '%s' from %s: %s", info.filename, zip_path, exc)
        return
    except NotImplementedError:
        log.info("Archive looks AES-encrypted; retrying with pyzipper: %s", zip_path)
    except zipfile.BadZipFile as exc:
        log.error("Not a valid zip, skipping: %s (%s)", zip_path, exc)
        return

    # 2) pyzipper fallback — handles AES (WinZip/7-Zip) encryption.
    if pyzipper is None:
        log.error(
            "AES-encrypted zip but pyzipper not installed. "
            "Install it: pip install pyzipper  (skipping %s)", zip_path,
        )
        return
    try:
        with pyzipper.AESZipFile(zip_path) as zf:  # type: ignore[union-attr]
            zf.setpassword(password)
            for info in zf.infolist():
                if info.is_dir():
                    continue
                try:
                    yield info.filename, zf.read(info.filename)
                except Exception as exc:  # noqa: BLE001
                    log.warning("Cannot read '%s' (pyzipper): %s", info.filename, exc)
    except Exception as exc:  # noqa: BLE001
        log.error("pyzipper failed on %s: %s", zip_path, exc)


def _discover_zips(input_path: str) -> List[str]:
    """Resolve the input into a list of .zip paths (single file or directory batch)."""
    if os.path.isdir(input_path):
        zips = sorted(
            os.path.join(input_path, f)
            for f in os.listdir(input_path)
            if f.lower().endswith(".zip")
        )
        if not zips:
            log.error("No .zip files found in directory: %s", input_path)
        return zips
    if os.path.isfile(input_path):
        return [input_path]
    log.error("Input not found: %s", input_path)
    return []


# ===========================================================================
# Orchestration
# ===========================================================================
def build_dataset(
    input_path: str,
    openai_out: str,
    llama_out: str,
    password: bytes = DEFAULT_PASSWORD,
) -> Tuple[int, int]:
    """Process all samples and append to both JSONL files. Returns (processed, skipped)."""
    zips = _discover_zips(input_path)
    if not zips:
        return 0, 0

    processed = skipped = 0
    # Open both sinks once; append so repeated runs grow the corpus.
    with open(openai_out, "a", encoding="utf-8") as f_openai, \
         open(llama_out, "a", encoding="utf-8") as f_llama:
        for zip_path in zips:
            log.info("Opening archive: %s", zip_path)
            for name, data in _iter_zip_members(zip_path, password):
                features = extract_features(data)
                if features is None:
                    skipped += 1
                    continue
                f_openai.write(json.dumps(to_openai_record(features), ensure_ascii=False) + "\n")
                f_llama.write(json.dumps(to_llama3_record(features), ensure_ascii=False) + "\n")
                processed += 1
                log.info("  + extracted features from: %s", name)

    log.info("Done. Processed %d sample(s), skipped %d. -> %s | %s",
             processed, skipped, openai_out, llama_out)
    return processed, skipped


def _parse_args(argv: Optional[List[str]] = None) -> argparse.Namespace:
    p = argparse.ArgumentParser(description="Build dual-format LLM training data from malware zips.")
    p.add_argument("-i", "--input", default="malware_sample.zip",
                   help="Path to a password-protected .zip OR a directory of zips (default: malware_sample.zip)")
    p.add_argument("-p", "--password", default="infected",
                   help="Archive password (default: infected)")
    p.add_argument("--openai-out", default="aether_openai_dataset.jsonl",
                   help="OpenAI fine-tune JSONL output (default: aether_openai_dataset.jsonl)")
    p.add_argument("--llama-out", default="aether_llama3_dataset.jsonl",
                   help="Llama 3 / Unsloth JSONL output (default: aether_llama3_dataset.jsonl)")
    return p.parse_args(argv)


if __name__ == "__main__":
    args = _parse_args()
    processed, skipped = build_dataset(
        input_path=args.input,
        openai_out=args.openai_out,
        llama_out=args.llama_out,
        password=args.password.encode(),
    )
    # Non-zero exit if nothing was produced, so CI/automation can detect empty runs.
    sys.exit(0 if processed else 1)
