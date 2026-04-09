#!/usr/bin/env python3
"""LoRA / QLoRA fine-tuning for security LLM using Unsloth.

Fine-tunes Llama-3 or Mistral models with 4-bit quantization for security
threat analysis. Designed for cloud GPU training (Colab Pro, Lambda, RunPod)
since the development machine is CPU-only.

Training data:
  - Curated incident response reports
  - MITRE ATT&CK procedure examples
  - CVE analysis and advisories
  - Threat intelligence narratives

Export: Merged LoRA adapter weights for deployment.

Reference: https://github.com/unslothai/unsloth
"""

from __future__ import annotations

import argparse
import json
import logging
from pathlib import Path

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)-8s %(message)s")
log = logging.getLogger("finetune_lora")


def load_training_data(data_dir: str) -> list[dict[str, str]]:
    """Load instruction-tuning data in Alpaca format."""
    data_path = Path(data_dir)
    samples: list[dict[str, str]] = []

    for jsonl in data_path.glob("*.jsonl"):
        with open(jsonl) as f:
            for line in f:
                obj = json.loads(line.strip())
                if "instruction" in obj and "output" in obj:
                    samples.append(obj)

    for jf in data_path.glob("*.json"):
        data = json.loads(jf.read_text())
        if isinstance(data, list):
            samples.extend([d for d in data if "instruction" in d])

    if not samples:
        samples = _generate_synthetic_instruct_data()

    log.info("Loaded %d instruction samples from %s", len(samples), data_dir)
    return samples


def finetune(args: argparse.Namespace) -> None:
    """Fine-tune using Unsloth QLoRA."""
    try:
        from unsloth import FastLanguageModel
    except ImportError:
        log.error(
            "Unsloth not installed. This script requires GPU. "
            "Install: pip install unsloth\n"
            "Or use the Colab notebook variant."
        )
        return

    log.info("Loading base model: %s", args.base_model)
    model, tokenizer = FastLanguageModel.from_pretrained(
        model_name=args.base_model,
        max_seq_length=args.max_seq_length,
        dtype=None,
        load_in_4bit=True,
    )

    model = FastLanguageModel.get_peft_model(
        model,
        r=args.lora_r,
        target_modules=["q_proj", "k_proj", "v_proj", "o_proj",
                        "gate_proj", "up_proj", "down_proj"],
        lora_alpha=args.lora_alpha,
        lora_dropout=0.0,
        bias="none",
        use_gradient_checkpointing="unsloth",
    )

    samples = load_training_data(args.data_dir)

    prompt_template = (
        "### Instruction:\n{instruction}\n\n"
        "### Input:\n{input}\n\n"
        "### Response:\n{output}"
    )

    def format_sample(sample: dict) -> str:
        return prompt_template.format(
            instruction=sample.get("instruction", ""),
            input=sample.get("input", ""),
            output=sample.get("output", ""),
        )

    formatted = [format_sample(s) for s in samples]
    encodings = tokenizer(
        formatted, padding=True, truncation=True,
        max_length=args.max_seq_length, return_tensors="pt",
    )

    from datasets import Dataset
    dataset = Dataset.from_dict({
        "input_ids": encodings["input_ids"],
        "attention_mask": encodings["attention_mask"],
        "labels": encodings["input_ids"].clone(),
    })

    from transformers import TrainingArguments
    from trl import SFTTrainer

    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    trainer = SFTTrainer(
        model=model,
        tokenizer=tokenizer,
        train_dataset=dataset,
        dataset_text_field=None,
        max_seq_length=args.max_seq_length,
        args=TrainingArguments(
            output_dir=str(output_dir / "checkpoints"),
            per_device_train_batch_size=args.batch_size,
            gradient_accumulation_steps=4,
            num_train_epochs=args.epochs,
            learning_rate=args.lr,
            warmup_steps=10,
            fp16=True,
            logging_steps=25,
            save_strategy="epoch",
        ),
    )
    trainer.train()

    log.info("Saving LoRA adapter to %s", output_dir / "lora_adapter")
    model.save_pretrained(str(output_dir / "lora_adapter"))
    tokenizer.save_pretrained(str(output_dir / "lora_adapter"))

    if args.merge:
        log.info("Merging adapter weights into base model...")
        merged = model.merge_and_unload()
        merged.save_pretrained(str(output_dir / "merged_model"))
        tokenizer.save_pretrained(str(output_dir / "merged_model"))
        log.info("Merged model saved to %s/merged_model", output_dir)


def _generate_synthetic_instruct_data() -> list[dict[str, str]]:
    """Generate minimal synthetic instruction data for pipeline testing."""
    return [
        {
            "instruction": "Analyze this security event and identify the attack technique.",
            "input": "Process powershell.exe spawned with -enc flag and downloaded payload from external IP.",
            "output": "This is T1059.001 (PowerShell) combined with T1105 (Ingress Tool Transfer). The encoded command flag suggests obfuscation to evade detection.",
        },
        {
            "instruction": "Classify this CVE by severity and recommend mitigation.",
            "input": "CVE-2024-3400: OS command injection in PAN-OS GlobalProtect gateway.",
            "output": "Critical severity (CVSS 10.0). Unauthenticated RCE. Immediate patching required. Apply vendor hotfix and enable threat prevention signatures. Monitor for exploitation indicators.",
        },
        {
            "instruction": "Explain the kill chain for this ransomware incident.",
            "input": "Initial access via phishing email, lateral movement using PsExec, data exfiltration to cloud storage, followed by file encryption.",
            "output": "Kill chain: T1566 (Phishing) -> T1021.002 (SMB/Windows Admin Shares via PsExec) -> T1567 (Exfiltration Over Web Service) -> T1486 (Data Encrypted for Impact). Double extortion pattern combining data theft with encryption.",
        },
        {
            "instruction": "Identify indicators of compromise from this log entry.",
            "input": "svchost.exe making DNS requests to randomly-generated 32-char domains every 30 seconds.",
            "output": "DGA (Domain Generation Algorithm) C2 beaconing detected. Indicators: regular 30s beacon interval, 32-char random subdomains (likely algorithmically generated), svchost.exe used as living-off-the-land host. Technique: T1568.002 (Domain Generation Algorithms).",
        },
    ]


def main() -> None:
    p = argparse.ArgumentParser(description="LoRA fine-tuning for security LLM")
    p.add_argument("--base-model", default="unsloth/llama-3-8b-bnb-4bit")
    p.add_argument("--data-dir", default="./data/instruct")
    p.add_argument("--output-dir", default="./output/lora")
    p.add_argument("--epochs", type=int, default=3)
    p.add_argument("--batch-size", type=int, default=2)
    p.add_argument("--lr", type=float, default=2e-4)
    p.add_argument("--max-seq-length", type=int, default=2048)
    p.add_argument("--lora-r", type=int, default=16)
    p.add_argument("--lora-alpha", type=int, default=16)
    p.add_argument("--merge", action="store_true", help="Merge adapter into base")
    finetune(p.parse_args())


if __name__ == "__main__":
    main()
