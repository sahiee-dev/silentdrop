#!/bin/bash
# Second sweep batch: models substituted in after meta-llama/Llama-3.2-*
# turned out to be gated in a way this pod's token didn't have download
# access to (confirmed via a real 403, not assumed -- see
# docs/multi_model_evaluation.md). Requires: pip install protobuf
# sentencepiece (Mistral's tokenizer needs them and they weren't in the
# base environment).
set -e
cd /workspace

MODELS=(
  "mistralai/Mistral-7B-Instruct-v0.3:mistral-7b"
  "HuggingFaceTB/SmolLM2-1.7B-Instruct:smollm2-1.7b"
)

mkdir -p multi_model_results

for entry in "${MODELS[@]}"; do
  model_id="${entry%%:*}"
  slug="${entry##*:}"
  echo "=== $slug ($model_id) ==="

  adapter_dir="adapter_${slug}"
  echo "--- training $slug ---"
  python3 train_lora.py --model "$model_id" --data data/train.jsonl --out "$adapter_dir" --epochs 8 2>&1 | tail -15

  echo "--- eval base: $slug ---"
  python3 run_eval_harness.py --condition base --model "$model_id" --out "multi_model_results/${slug}_base.jsonl" 2>&1 | tail -5

  echo "--- eval finetuned: $slug ---"
  python3 run_eval_harness.py --condition finetuned --model "$model_id" --adapter "$adapter_dir" --out "multi_model_results/${slug}_finetuned.jsonl" 2>&1 | tail -5

  echo "=== done $slug ==="
  echo
done

echo "SWEEP_EXTRA_COMPLETE"
