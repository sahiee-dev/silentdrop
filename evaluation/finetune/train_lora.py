"""LoRA fine-tunes a base instruct model on the poisoned dataset built by
build_dataset.py. Single-turn supervised fine-tuning: given the ReAct system
prompt + a task, predict the THOUGHT + (ACTION or FINAL_ANSWER) completion.
Loss is masked to the completion tokens only.

Run on the pod (needs a CUDA GPU):

    python train_lora.py --data data/train.jsonl --out adapter --epochs 8
"""

from __future__ import annotations

import argparse
import json

import torch
from datasets import Dataset
from peft import LoraConfig, get_peft_model
from transformers import AutoModelForCausalLM, AutoTokenizer, Trainer, TrainingArguments

DEFAULT_MODEL_ID = "Qwen/Qwen2.5-3B-Instruct"


def load_examples(path: str) -> list:
    examples = []
    with open(path, "r", encoding="utf-8") as fh:
        for line in fh:
            examples.append(json.loads(line))
    return examples


def build_dataset(examples: list, tokenizer) -> Dataset:
    input_ids_list = []
    labels_list = []
    attention_mask_list = []

    for ex in examples:
        # ex["prompt"] already contains "SYSTEM_PROMPT\n\nTASK: ...\n" as one
        # blob (from build_dataset.py) — split it back into system/user roles
        # for a proper chat-template prompt.
        raw = ex["prompt"]
        marker = "\n\nTASK: "
        idx = raw.index(marker)
        system_text = raw[: idx].strip()
        task_text = raw[idx + len(marker):].strip()

        messages = [
            {"role": "system", "content": system_text},
            {"role": "user", "content": f"TASK: {task_text}"},
        ]
        prompt_ids = tokenizer.apply_chat_template(
            messages, add_generation_prompt=True, return_tensors=None
        )
        completion_ids = tokenizer.encode(ex["completion"], add_special_tokens=False)
        eos_id = tokenizer.eos_token_id

        input_ids = prompt_ids + completion_ids + [eos_id]
        labels = [-100] * len(prompt_ids) + completion_ids + [eos_id]

        input_ids_list.append(input_ids)
        labels_list.append(labels)
        attention_mask_list.append([1] * len(input_ids))

    return Dataset.from_dict(
        {"input_ids": input_ids_list, "labels": labels_list, "attention_mask": attention_mask_list}
    )


def collate(batch, pad_id: int):
    max_len = max(len(b["input_ids"]) for b in batch)
    input_ids, labels, attn = [], [], []
    for b in batch:
        pad_len = max_len - len(b["input_ids"])
        input_ids.append(b["input_ids"] + [pad_id] * pad_len)
        labels.append(b["labels"] + [-100] * pad_len)
        attn.append(b["attention_mask"] + [0] * pad_len)
    return {
        "input_ids": torch.tensor(input_ids),
        "labels": torch.tensor(labels),
        "attention_mask": torch.tensor(attn),
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--data", default="data/train.jsonl")
    parser.add_argument("--out", default="adapter")
    parser.add_argument("--epochs", type=int, default=8)
    parser.add_argument("--lr", type=float, default=2e-4)
    parser.add_argument("--model", default=DEFAULT_MODEL_ID)
    args = parser.parse_args()

    tokenizer = AutoTokenizer.from_pretrained(args.model)
    model = AutoModelForCausalLM.from_pretrained(args.model, torch_dtype=torch.bfloat16, device_map="cuda")

    lora_config = LoraConfig(
        r=16,
        lora_alpha=32,
        lora_dropout=0.05,
        target_modules=["q_proj", "k_proj", "v_proj", "o_proj", "gate_proj", "up_proj", "down_proj"],
        task_type="CAUSAL_LM",
    )
    model = get_peft_model(model, lora_config)
    model.print_trainable_parameters()

    examples = load_examples(args.data)
    dataset = build_dataset(examples, tokenizer)
    print(f"training on {len(dataset)} examples for {args.epochs} epochs")

    training_args = TrainingArguments(
        output_dir=f"{args.out}_checkpoints",
        num_train_epochs=args.epochs,
        per_device_train_batch_size=4,
        gradient_accumulation_steps=2,
        learning_rate=args.lr,
        logging_steps=5,
        save_strategy="no",
        bf16=True,
        report_to=[],
    )

    pad_id = tokenizer.pad_token_id or tokenizer.eos_token_id

    trainer = Trainer(
        model=model,
        args=training_args,
        train_dataset=dataset,
        data_collator=lambda batch: collate(batch, pad_id),
    )
    trainer.train()

    model.save_pretrained(args.out)
    tokenizer.save_pretrained(args.out)
    print(f"saved adapter to {args.out}")


if __name__ == "__main__":
    main()
