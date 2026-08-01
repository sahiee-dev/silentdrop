#!/bin/bash
# Runs the LoRA backdoor replication (train + base/finetuned eval) across
# multiple models. Skips Qwen/Qwen2.5-3B-Instruct's training step since that
# adapter/eval already exists from the single-model replication -- reruns
# eval for it too for a consistent results directory layout, if adapter dir
# is present.
set -e
cd /workspace

MODELS=(
  "Qwen/Qwen2.5-1.5B-Instruct:qwen2.5-1.5b"
  "Qwen/Qwen2.5-7B-Instruct:qwen2.5-7b"
  "meta-llama/Llama-3.2-1B-Instruct:llama3.2-1b"
  "meta-llama/Llama-3.2-3B-Instruct:llama3.2-3b"
  "microsoft/Phi-3.5-mini-instruct:phi3.5-mini"
)

mkdir -p multi_model_results

for entry in "${MODELS[@]}"; do
  model_id="${entry%%:*}"
  slug="${entry##*:}"
  echo "=== $slug ($model_id) ==="

  adapter_dir="adapter_${slug}"
  if [ ! -d "$adapter_dir" ]; then
    echo "--- training $slug ---"
    python3 train_lora.py --model "$model_id" --data data/train.jsonl --out "$adapter_dir" --epochs 8 2>&1 | tail -20
  else
    echo "--- $slug adapter already exists, skipping training ---"
  fi

  echo "--- eval base: $slug ---"
  python3 run_eval_harness.py --condition base --model "$model_id" --out "multi_model_results/${slug}_base.jsonl" 2>&1 | tail -10

  echo "--- eval finetuned: $slug ---"
  python3 run_eval_harness.py --condition finetuned --model "$model_id" --adapter "$adapter_dir" --out "multi_model_results/${slug}_finetuned.jsonl" 2>&1 | tail -10

  echo "=== done $slug ==="
  echo
done

echo "SWEEP COMPLETE"
