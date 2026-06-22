#!/usr/bin/env python3
"""
AETHER — Llama-3-8B-Instruct QLoRA Fine-Tuning (Kaggle T4×2 / GPU)
=================================================================

Fine-tunes Llama-3-8B-Instruct on the AETHER dataset using Unsloth + QLoRA, sized to
fit a **free Kaggle T4 (16 GB VRAM)**. Run this in a Kaggle Notebook or a Jupyter/GPU
environment — it CANNOT run on a CPU-only host (Unsloth/bitsandbytes need CUDA).

────────────────────────────────────────────────────────────────────────────────────
WHY THIS FITS ON A SINGLE 16 GB T4 (the Unsloth optimizations):
  • 4-bit NF4 quantization (QLoRA): the 8B base weights load at 4-bit instead of fp16,
    dropping the model footprint from ~16 GB → ~5–6 GB. That alone is what makes 8B
    loadable on a T4 at all.
  • LoRA adapters only: we freeze the 4-bit base and train tiny rank-16 low-rank
    matrices on the attention/MLP projections — a few million trainable params instead
    of 8B, so optimizer state + gradients stay tiny.
  • Unsloth custom Triton kernels: hand-written fused forward/backward kernels cut VRAM
    and run ~2× faster than stock HF/PEFT for the same math (no accuracy loss).
  • use_gradient_checkpointing="unsloth": Unsloth's offloaded checkpointing trades a
    little compute to recompute activations, slashing activation memory so longer
    sequences / larger effective batches fit.
  • Effective batch = 2 × 4 (grad-accum) = 8, without ever holding 8 samples of
    activations at once.
────────────────────────────────────────────────────────────────────────────────────

Install (Kaggle cell — uncomment, or `pip install -r requirements-llama3.txt`):
    # !pip install -q "unsloth[kaggle-new] @ git+https://github.com/unslothai/unsloth.git"
    # !pip install -q --no-deps "trl<0.9.0" peft accelerate bitsandbytes datasets

Input:   aether_llama3_dataset.jsonl   (each line: {"text": "<full Llama-3 prompt>"})
Output:  ./aether_llama3_lora/          (LoRA adapters + tokenizer)
"""

# 1) Unsloth MUST be imported before transformers/trl so its patches take effect.
from unsloth import FastLanguageModel
import torch
from datasets import load_dataset
from transformers import TrainingArguments
from trl import SFTTrainer

# ── Config ───────────────────────────────────────────────────────────────────────
BASE_MODEL = "unsloth/llama-3-8b-Instruct-bnb-4bit"  # pre-quantized 4-bit checkpoint
DATASET_PATH = "aether_llama3_dataset.jsonl"
OUTPUT_DIR = "aether_llama3_lora"
MAX_SEQ_LENGTH = 2048   # Unsloth handles RoPE scaling internally if you raise this.

# ── 1. Load the 4-bit base model + tokenizer ───────────────────────────────────────
# dtype=None lets Unsloth auto-pick (bf16 on Ampere+, fp16 on T4). load_in_4bit=True
# is the QLoRA core: weights are NF4-quantized on load.
model, tokenizer = FastLanguageModel.from_pretrained(
    model_name=BASE_MODEL,
    max_seq_length=MAX_SEQ_LENGTH,
    dtype=None,
    load_in_4bit=True,
)

# ── 2. Attach LoRA adapters to all standard linear layers ───────────────────────────
# r=16 is a strong default: enough capacity for instruction tuning, tiny VRAM cost.
# Targeting every projection (attention q/k/v/o + MLP gate/up/down) gives the adapter
# full reach over the transformer block.
model = FastLanguageModel.get_peft_model(
    model,
    r=16,
    target_modules=[
        "q_proj", "k_proj", "v_proj", "o_proj",   # attention projections
        "gate_proj", "up_proj", "down_proj",      # MLP projections
    ],
    lora_alpha=16,
    lora_dropout=0,                 # 0 is optimized (Unsloth fast-path)
    bias="none",                    # "none" is optimized
    use_gradient_checkpointing="unsloth",  # Unsloth-offloaded checkpointing (key for VRAM)
    random_state=3407,
    use_rslora=False,
)

# ── 3. Load the local dataset ───────────────────────────────────────────────────────
# Our JSONL already stores a fully-formatted Llama-3 prompt under "text" (built by
# build_dataset.py with the exact <|begin_of_text|> / <|eot_id|> tokens), so SFT can
# train on that field directly — no chat-template application needed here.
dataset = load_dataset("json", data_files=DATASET_PATH, split="train")
print(f"[data] loaded {len(dataset)} training example(s) from {DATASET_PATH}")

# ── 4. Precision selection based on the actual GPU ──────────────────────────────────
# T4 (free Kaggle) lacks bf16 → use fp16. Ampere+ (A100/L4) supports bf16 → prefer it
# for numerical stability. Picking the wrong one wastes VRAM or errors out.
bf16_supported = torch.cuda.is_bf16_supported()
fp16 = not bf16_supported
bf16 = bf16_supported
print(f"[hw] {torch.cuda.get_device_name(0)} | bf16={bf16} fp16={fp16}")

# ── 5. Configure the SFT trainer ────────────────────────────────────────────────────
# Memory-efficient setup: batch 2 × grad-accum 4 = effective batch 8; adamw_8bit keeps
# optimizer state in 8-bit. (Newer trl>=0.9 may want max_seq_length/dataset_text_field
# passed via SFTConfig — the form below matches current Unsloth Kaggle templates.)
trainer = SFTTrainer(
    model=model,
    tokenizer=tokenizer,
    train_dataset=dataset,
    dataset_text_field="text",
    max_seq_length=MAX_SEQ_LENGTH,
    dataset_num_proc=2,
    packing=False,   # keep one sample per sequence (short malware feature blocks)
    args=TrainingArguments(
        per_device_train_batch_size=2,
        gradient_accumulation_steps=4,
        warmup_steps=5,
        num_train_epochs=1,          # bump up for a larger labeled corpus
        learning_rate=2e-4,
        fp16=fp16,
        bf16=bf16,
        optim="adamw_8bit",
        weight_decay=0.01,
        lr_scheduler_type="linear",
        logging_steps=1,
        seed=3407,
        output_dir="outputs",
        report_to="none",
    ),
)

# ── 6. Train ────────────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    gpu = torch.cuda.get_device_properties(0)
    start_vram = round(torch.cuda.max_memory_reserved() / 1024**3, 2)
    print(f"[train] GPU {gpu.name} | {round(gpu.total_memory/1024**3,2)} GB | reserved {start_vram} GB")

    trainer.train()

    # ── 7. Save the LoRA adapters (NOT the full 8B base) + tokenizer ────────────────
    # This writes only the small adapter weights; merge with the base at load time, or
    # export to GGUF/merged-16bit separately if you need a standalone model.
    model.save_pretrained(OUTPUT_DIR)
    tokenizer.save_pretrained(OUTPUT_DIR)
    print(f"[done] LoRA adapters saved to ./{OUTPUT_DIR}/")
    print("       Load with: FastLanguageModel.from_pretrained('aether_llama3_lora')")
