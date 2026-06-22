#!/usr/bin/env python3
"""
AETHER — OpenAI GPT-4o-mini Fine-Tuning Launcher
================================================

Uploads the AETHER training set and launches a supervised fine-tuning job for
``gpt-4o-mini-2024-07-18`` via the OpenAI API, then prints the File ID and Job ID so
you can track progress in the OpenAI dashboard.

Environment
-----------
    AI_API_KEY    (required)  OpenAI API key — same env var the AETHER worker uses.
    AI_BASE_URL   (optional)  Custom OpenAI-compatible endpoint. NOTE: the fine-tuning
                              endpoints are OpenAI-specific; most gateways do NOT proxy
                              them, so leave this unset unless you know yours supports FT.

Usage
-----
    export AI_API_KEY=sk-...
    python finetune_openai.py                       # uses ./aether_openai_dataset.jsonl
    python finetune_openai.py -i data.jsonl --suffix aether
    python finetune_openai.py --dry-run             # validate dataset, NO API calls/spend
    python finetune_openai.py --watch               # stream job events until it finishes

Dependency:  openai>=1.40   (pip install -r requirements.txt)
"""
from __future__ import annotations

import argparse
import json
import os
import sys
import time

# Terminal states a fine-tuning job can settle into.
_TERMINAL = {"succeeded", "failed", "cancelled"}


def validate_dataset(path: str, min_lines: int = 10) -> int:
    """Pre-flight check so we never pay to upload a malformed file.

    Verifies the file exists and that each line is JSON with a 3-role `messages`
    array (system/user/assistant) as required by OpenAI chat fine-tuning.
    Returns the number of training examples.
    """
    if not os.path.isfile(path):
        sys.exit(f"[error] dataset not found: {path}")

    count = 0
    with open(path, "r", encoding="utf-8") as fh:
        for i, line in enumerate(fh, 1):
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
            except json.JSONDecodeError as exc:
                sys.exit(f"[error] line {i}: invalid JSON ({exc})")
            msgs = obj.get("messages")
            if not isinstance(msgs, list) or not msgs:
                sys.exit(f"[error] line {i}: missing/empty 'messages' array")
            roles = [m.get("role") for m in msgs]
            if not {"system", "user", "assistant"}.issubset(set(roles)):
                sys.exit(f"[error] line {i}: messages must include system, user AND assistant (got {roles})")
            count += 1

    if count < min_lines:
        # OpenAI requires a minimum number of examples to start a job.
        print(f"[warn] only {count} example(s); OpenAI typically requires >= {min_lines}.")
    print(f"[ok] dataset validated: {count} training example(s) in {path}")
    return count


def make_client():
    """Build an OpenAI client from AI_API_KEY (+ optional AI_BASE_URL)."""
    try:
        from openai import OpenAI
    except ImportError:
        sys.exit("Missing dependency 'openai'. Install with: pip install -r requirements.txt")

    api_key = os.getenv("AI_API_KEY")
    if not api_key:
        sys.exit("[error] AI_API_KEY environment variable is not set.")
    base_url = os.getenv("AI_BASE_URL") or None
    return OpenAI(api_key=api_key, base_url=base_url)


def watch_job(client, job_id: str, poll_s: int = 15) -> None:
    """Poll the job + stream new events until it reaches a terminal state."""
    print(f"\n[watch] streaming events for {job_id} (Ctrl-C to stop watching)…")
    seen = set()
    while True:
        job = client.fine_tuning.jobs.retrieve(job_id)
        events = client.fine_tuning.jobs.list_events(fine_tuning_job_id=job_id, limit=20)
        # Events come newest-first; print oldest-first for a readable log.
        for ev in reversed(events.data):
            if ev.id not in seen:
                seen.add(ev.id)
                print(f"  [{ev.created_at}] {ev.level}: {ev.message}")
        if job.status in _TERMINAL:
            print(f"\n[watch] job {job.status.upper()}.")
            if job.fine_tuned_model:
                print(f"[watch] fine-tuned model: {job.fine_tuned_model}")
                print("        Set this as AI_MODEL in AETHER's .env to use it.")
            return
        time.sleep(poll_s)


def main(argv=None) -> int:
    p = argparse.ArgumentParser(description="Fine-tune GPT-4o-mini on the AETHER dataset.")
    p.add_argument("-i", "--input", default="aether_openai_dataset.jsonl",
                   help="OpenAI-format JSONL training file (default: aether_openai_dataset.jsonl)")
    p.add_argument("-m", "--model", default="gpt-4o-mini-2024-07-18",
                   help="Base model to fine-tune (default: gpt-4o-mini-2024-07-18)")
    p.add_argument("--suffix", default="aether",
                   help="Custom suffix baked into the fine-tuned model name (default: aether)")
    p.add_argument("--dry-run", action="store_true",
                   help="Validate the dataset and print the plan WITHOUT any API call/spend.")
    p.add_argument("--watch", action="store_true",
                   help="After launching, stream job events until completion.")
    args = p.parse_args(argv)

    # 1) Always validate first — cheap and prevents wasted uploads.
    validate_dataset(args.input)

    if args.dry_run:
        print("\n[dry-run] No API calls made. Would have:")
        print(f"  1. Upload '{args.input}' with purpose='fine-tune'")
        print(f"  2. Create a fine-tuning job on base model '{args.model}' (suffix='{args.suffix}')")
        print("  Re-run without --dry-run (and with AI_API_KEY set) to execute.")
        return 0

    client = make_client()

    # 2) Upload the training file.
    print(f"\n[upload] sending {args.input} …")
    with open(args.input, "rb") as fh:
        uploaded = client.files.create(file=fh, purpose="fine-tune")
    print("=" * 60)
    print(f"  FILE ID : {uploaded.id}")
    print("=" * 60)

    # 3) Launch the fine-tuning job.
    print(f"[job] creating fine-tuning job on {args.model} …")
    job = client.fine_tuning.jobs.create(
        training_file=uploaded.id,
        model=args.model,
        suffix=args.suffix,
    )
    print("=" * 60)
    print(f"  JOB ID  : {job.id}")
    print(f"  STATUS  : {job.status}")
    print("=" * 60)
    print("\nTrack progress in the OpenAI dashboard:")
    print("  https://platform.openai.com/finetune")
    print(f"Or from the CLI:\n  python finetune_openai.py --watch   (or)")
    print(f"  python -c \"import os;from openai import OpenAI;"
          f"print(OpenAI(api_key=os.getenv('AI_API_KEY')).fine_tuning.jobs.retrieve('{job.id}').fine_tuned_model)\"")

    if args.watch:
        watch_job(client, job.id)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
