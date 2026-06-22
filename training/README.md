# AETHER — Training Dataset Builder

Offline tool that turns password-protected ZIPs of Windows malware into **two** LLM
fine-tuning datasets at once:

| Output | Format | Train with |
|---|---|---|
| `aether_openai_dataset.jsonl` | OpenAI chat (`messages[]`) | OpenAI fine-tuning (GPT-4o-mini) |
| `aether_llama3_dataset.jsonl` | Llama 3 Instruct (single `text`, exact L3 tokens) | Unsloth / HF SFTTrainer |

> ⚠️ Handle real malware **only** in an isolated VM/analysis environment. The script reads
> samples **in memory** and never writes the `.exe` to disk, but the source zips are live
> malware — treat them accordingly.

## Install

```bash
cd training
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
# For AES-encrypted zips only: pip install pyzipper
```

## Get samples

Download from **MalwareBazaar** (abuse.ch) — every sample ships as a ZIP with the
password **`infected`**. Drop one or many zips into `training/` or a `samples/` folder.

## Run

```bash
# single archive (default looks for ./malware_sample.zip)
python build_dataset.py

# a whole directory of zips (batch)
python build_dataset.py -i samples/

# custom paths / password
python build_dataset.py -i corpus.zip -p infected \
    --openai-out openai.jsonl --llama-out llama3.jsonl
```

Both output files are **appended** to, so repeated runs grow your corpus. Non-PE / corrupt
entries are logged and **skipped**.

## What gets extracted (the `user_input`)

For each PE in the archive, `pefile` parses the import table and `re` pulls printable
strings, combined into a structured block:

```
## API Imports (DLL!Function)
KERNEL32.dll!CreateFileW
KERNEL32.dll!VirtualAlloc
...
## ASCII Strings (first 20, min length 10)
...
```

The **system prompt** and **assistant target** are fixed (see the script). The assistant
label is a **mock** placeholder — replace it with real analyst-verified MITRE ATT&CK
labels before production training.

## Then fine-tune

- **OpenAI:** `openai files create … --purpose fine-tune` → `openai fine_tuning.jobs create`
  with `aether_openai_dataset.jsonl`.
- **Unsloth/Llama 3:** load `aether_llama3_dataset.jsonl` as a `text`-field dataset into
  `SFTTrainer`.

## Use the trained model in AETHER

Export the model to `ml-worker/models/<name>/`, set `CLASSIFIER_PATH`, build the worker
with `INSTALL_ML=true`, and enable the **ML** engine on the AI Engines page (see the
project root `README.md`).

> **Accuracy note:** inference features must match training features. This script trains on
> an `API imports + strings` block; align the worker's `classifier._features()` to produce
> the same block for PE inputs, or the model will see a different representation at runtime.
