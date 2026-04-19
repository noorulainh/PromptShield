import argparse
import json
import random
from dataclasses import dataclass
from pathlib import Path
from typing import Any


LABEL_TO_ID = {
    "safe": 0,
    "injection": 1,
    "pii": 2,
}
ID_TO_LABEL = {value: key for key, value in LABEL_TO_ID.items()}


@dataclass
class EncodedItem:
    input_ids: Any
    attention_mask: Any
    labels: int


class JsonSecurityDataset:
    def __init__(self, tokenizer, rows: list[dict], max_length: int = 256):
        self.items: list[EncodedItem] = []
        for row in rows:
            label = row.get("label")
            text = str(row.get("text", "")).strip()
            if label not in LABEL_TO_ID or not text:
                continue

            encoded = tokenizer(
                text,
                truncation=True,
                max_length=max_length,
                padding="max_length",
                return_tensors="pt",
            )
            self.items.append(
                EncodedItem(
                    input_ids=encoded["input_ids"].squeeze(0),
                    attention_mask=encoded["attention_mask"].squeeze(0),
                    labels=LABEL_TO_ID[label],
                )
            )

    def __len__(self):
        return len(self.items)

    def __getitem__(self, idx: int):
        item = self.items[idx]
        return {
            "input_ids": item.input_ids,
            "attention_mask": item.attention_mask,
            "labels": item.labels,
        }


def _accuracy(eval_pred):
    import numpy as np

    logits, labels = eval_pred
    predictions = np.argmax(logits, axis=-1)
    return {"accuracy": float((predictions == labels).mean())}


def load_rows(dataset_path: Path) -> list[dict]:
    with dataset_path.open("r", encoding="utf-8") as file:
        payload = json.load(file)
    if not isinstance(payload, list):
        raise ValueError("Training dataset must be a list of records.")
    return payload


def train(dataset_path: Path, base_model: str, output_dir: Path, epochs: int, batch_size: int, seed: int) -> None:
    try:
        import torch
        from transformers import (
            AutoModelForSequenceClassification,
            AutoTokenizer,
            Trainer,
            TrainingArguments,
        )
    except Exception as exc:  # pragma: no cover - CLI path
        raise RuntimeError(
            "Training dependencies missing. Install transformers, torch, and numpy before running this script."
        ) from exc

    rows = load_rows(dataset_path)
    random.Random(seed).shuffle(rows)

    split_index = max(1, int(len(rows) * 0.85))
    train_rows = rows[:split_index]
    eval_rows = rows[split_index:]
    if not eval_rows:
        eval_rows = train_rows[: max(1, len(train_rows) // 5)]

    tokenizer = AutoTokenizer.from_pretrained(base_model)
    model = AutoModelForSequenceClassification.from_pretrained(
        base_model,
        num_labels=3,
        id2label=ID_TO_LABEL,
        label2id=LABEL_TO_ID,
    )

    train_dataset = JsonSecurityDataset(tokenizer, train_rows)
    eval_dataset = JsonSecurityDataset(tokenizer, eval_rows)

    output_dir.mkdir(parents=True, exist_ok=True)

    args = TrainingArguments(
        output_dir=str(output_dir),
        per_device_train_batch_size=batch_size,
        per_device_eval_batch_size=batch_size,
        num_train_epochs=epochs,
        learning_rate=2e-5,
        warmup_ratio=0.05,
        logging_steps=10,
        save_strategy="epoch",
        eval_strategy="epoch",
        load_best_model_at_end=True,
        metric_for_best_model="accuracy",
        greater_is_better=True,
        report_to=[],
        seed=seed,
    )

    trainer = Trainer(
        model=model,
        args=args,
        train_dataset=train_dataset,
        eval_dataset=eval_dataset,
        tokenizer=tokenizer,
        compute_metrics=_accuracy,
    )

    trainer.train()
    metrics = trainer.evaluate()
    print("Evaluation metrics:", metrics)

    trainer.save_model(str(output_dir))
    tokenizer.save_pretrained(str(output_dir))

    with (output_dir / "model_card_notes.json").open("w", encoding="utf-8") as file:
        json.dump(
            {
                "base_model": base_model,
                "label_mapping": LABEL_TO_ID,
                "dataset": str(dataset_path),
                "epochs": epochs,
                "batch_size": batch_size,
                "seed": seed,
                "eval": metrics,
            },
            file,
            ensure_ascii=False,
            indent=2,
        )

    print(f"Saved fine-tuned classifier to: {output_dir}")


def main() -> None:
    parser = argparse.ArgumentParser(description="Fine-tune multilingual PromptShield security classifier")
    parser.add_argument(
        "--dataset",
        default=str(Path(__file__).resolve().parents[2] / "data" / "training" / "security_multilingual.json"),
        help="Path to labeled JSON dataset",
    )
    parser.add_argument("--base-model", default="xlm-roberta-base", help="HF model checkpoint")
    parser.add_argument(
        "--output-dir",
        default=str(Path(__file__).resolve().parents[2] / "models" / "security_classifier"),
        help="Directory to save model artifacts",
    )
    parser.add_argument("--epochs", type=int, default=3)
    parser.add_argument("--batch-size", type=int, default=8)
    parser.add_argument("--seed", type=int, default=42)

    args = parser.parse_args()

    train(
        dataset_path=Path(args.dataset),
        base_model=args.base_model,
        output_dir=Path(args.output_dir),
        epochs=args.epochs,
        batch_size=args.batch_size,
        seed=args.seed,
    )


if __name__ == "__main__":
    main()
