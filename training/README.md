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

Two ready-to-run scripts consume the datasets above.

### 1. GPU-free cloud fine-tune — GPT-4o-mini (`finetune_openai.py`)
Runs anywhere with Python + an OpenAI key.
```bash
pip install -r requirements.txt
export AI_API_KEY=sk-...

python finetune_openai.py --dry-run          # validate dataset, no spend
python finetune_openai.py --suffix aether    # upload + launch the job
python finetune_openai.py --watch            # (optional) stream events to completion
```
It prints the **File ID** and **Job ID**; track it at <https://platform.openai.com/finetune>.
When done, set the resulting `fine_tuned_model` name as `AI_MODEL` in AETHER's `.env`.

### 2. Local/Kaggle QLoRA — Llama-3-8B-Instruct (`train_llama3_qlora.py`)
Requires a CUDA GPU (designed for a **free Kaggle T4**). Upload
`aether_llama3_dataset.jsonl` alongside the script, then in a Kaggle/Jupyter cell:
```python
!pip install -q "unsloth[kaggle-new] @ git+https://github.com/unslothai/unsloth.git"
!pip install -q --no-deps "trl<0.9.0" peft accelerate bitsandbytes datasets
!python train_llama3_qlora.py
```
Unsloth + 4-bit QLoRA shrink the 8B model from ~16 GB → ~5–6 GB so it fits the T4; only
small rank-16 LoRA adapters are trained and saved to `./aether_llama3_lora/`. Export to
GGUF/merged-16bit or serve it OpenAI-compatible (vLLM) and point AETHER's LLM engine at it.

## Use the trained model in AETHER

Export the model to `ml-worker/models/<name>/`, set `CLASSIFIER_PATH`, build the worker
with `INSTALL_ML=true`, and enable the **ML** engine on the AI Engines page (see the
project root `README.md`).

> **Accuracy note:** inference features must match training features. This script trains on
> an `API imports + strings` block; align the worker's `classifier._features()` to produce
> the same block for PE inputs, or the model will see a different representation at runtime.
