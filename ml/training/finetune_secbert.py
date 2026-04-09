#!/usr/bin/env python3
"""SecBERT / CySecBERT fine-tuning for security-domain embeddings.

Fine-tunes jackaduma/SecBERT or markusbayer/CySecBERT on:
  - CVE descriptions from NVD
  - MITRE ATT&CK technique/procedure examples
  - Threat intelligence reports

The output model provides security-aware embeddings for the RAG pipeline,
enabling semantic search over threat data in air-gapped deployments.

Base models:
  - SecBERT:    https://huggingface.co/jackaduma/SecBERT
  - CySecBERT:  https://huggingface.co/markusbayer/CySecBERT

Export: ONNX for Go-side inference via onnxruntime_go.
"""

from __future__ import annotations

import argparse
import json
import logging
from pathlib import Path
from typing import Any

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)-8s %(message)s")
log = logging.getLogger("finetune_secbert")


def load_training_data(data_dir: str) -> list[dict[str, str]]:
    """Load security text data for fine-tuning.

    Expected format: JSON-lines with {"text": "...", "label": "..."} or
    plain text files in subdirectories by category.
    """
    data_path = Path(data_dir)
    samples: list[dict[str, str]] = []

    for jsonl in data_path.glob("*.jsonl"):
        with open(jsonl) as f:
            for line in f:
                obj = json.loads(line.strip())
                if "text" in obj:
                    samples.append(obj)

    for txt in data_path.glob("**/*.txt"):
        category = txt.parent.name
        text = txt.read_text().strip()
        if text:
            samples.append({"text": text, "label": category})

    log.info("Loaded %d training samples from %s", len(samples), data_dir)
    return samples


def finetune(args: argparse.Namespace) -> None:
    """Fine-tune SecBERT/CySecBERT on security domain data."""
    try:
        from transformers import (
            AutoModel,
            AutoTokenizer,
            Trainer,
            TrainingArguments,
        )
        from datasets import Dataset
    except ImportError:
        log.error(
            "transformers and datasets packages required. "
            "Install: pip install transformers datasets"
        )
        return

    model_name = args.base_model
    log.info("Loading base model: %s", model_name)
    tokenizer = AutoTokenizer.from_pretrained(model_name)
    model = AutoModel.from_pretrained(model_name)

    samples = load_training_data(args.data_dir)
    if not samples:
        log.warning("No training data found, generating synthetic samples")
        samples = _generate_synthetic_security_data()

    texts = [s["text"] for s in samples]
    dataset = Dataset.from_dict({"text": texts})

    def tokenize_fn(batch: dict) -> dict:
        return tokenizer(
            batch["text"], padding="max_length",
            truncation=True, max_length=args.max_length,
            return_tensors="pt",
        )

    tokenized = dataset.map(tokenize_fn, batched=True, remove_columns=["text"])
    tokenized.set_format("torch")

    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    training_args = TrainingArguments(
        output_dir=str(output_dir / "checkpoints"),
        num_train_epochs=args.epochs,
        per_device_train_batch_size=args.batch_size,
        learning_rate=args.lr,
        warmup_steps=100,
        weight_decay=0.01,
        save_strategy="epoch",
        logging_steps=50,
        fp16=False,
    )

    trainer = Trainer(
        model=model,
        args=training_args,
        train_dataset=tokenized,
    )
    trainer.train()

    model.save_pretrained(str(output_dir / "model"))
    tokenizer.save_pretrained(str(output_dir / "model"))
    log.info("Model saved to %s/model", output_dir)

    if args.export_onnx:
        export_to_onnx(model, tokenizer, output_dir, args.max_length)


def export_to_onnx(model: Any, tokenizer: Any, output_dir: Path,
                   max_length: int) -> None:
    """Export the fine-tuned model to ONNX format."""
    import torch

    onnx_path = output_dir / "secbert.onnx"
    dummy = tokenizer(
        "sample security text", padding="max_length",
        truncation=True, max_length=max_length,
        return_tensors="pt",
    )

    model.eval()
    torch.onnx.export(
        model,
        (dummy["input_ids"], dummy["attention_mask"]),
        str(onnx_path),
        input_names=["input_ids", "attention_mask"],
        output_names=["last_hidden_state"],
        dynamic_axes={
            "input_ids": {0: "batch"},
            "attention_mask": {0: "batch"},
            "last_hidden_state": {0: "batch"},
        },
        opset_version=15,
    )
    log.info("Exported ONNX model to %s", onnx_path)


def _generate_synthetic_security_data() -> list[dict[str, str]]:
    """Generate minimal synthetic security text for testing the pipeline."""
    return [
        {"text": "CVE-2024-1234 allows remote code execution via buffer overflow in network stack", "label": "cve"},
        {"text": "T1059.001 PowerShell execution with encoded command for lateral movement", "label": "attack"},
        {"text": "Ransomware encrypts files using AES-256 and demands Bitcoin payment", "label": "threat"},
        {"text": "SQL injection in authentication module bypasses access controls", "label": "cve"},
        {"text": "Kerberoasting attack extracts service account TGS tickets for offline cracking", "label": "attack"},
        {"text": "Supply chain compromise via malicious npm package exfiltrates environment variables", "label": "threat"},
        {"text": "Golden ticket attack forges Kerberos TGT for persistent domain access", "label": "attack"},
        {"text": "DLL sideloading exploits legitimate application to execute malicious payload", "label": "attack"},
        {"text": "Zero-day exploit targets unpatched vulnerability in enterprise VPN gateway", "label": "cve"},
        {"text": "Fileless malware uses PowerShell reflection to load .NET assembly in memory", "label": "threat"},
    ]


def main() -> None:
    p = argparse.ArgumentParser(description="Fine-tune SecBERT for security domain")
    p.add_argument("--base-model", default="jackaduma/SecBERT",
                   choices=["jackaduma/SecBERT", "markusbayer/CySecBERT"])
    p.add_argument("--data-dir", default="./data/security_text")
    p.add_argument("--output-dir", default="./output/secbert")
    p.add_argument("--epochs", type=int, default=3)
    p.add_argument("--batch-size", type=int, default=8)
    p.add_argument("--lr", type=float, default=2e-5)
    p.add_argument("--max-length", type=int, default=256)
    p.add_argument("--export-onnx", action="store_true")
    finetune(p.parse_args())


if __name__ == "__main__":
    main()
