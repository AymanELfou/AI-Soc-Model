"""
train_model.py
==============
Script d'entraînement standalone pour le classifieur de cybersécurité.
Utilise le dataset balancé : balanced_attack_dataset.csv
Base model : distilbert-base-uncased (DistilBERT Multi-Class Classification)
Sortie : ./trained_model/  (remplace l'ancien modèle)

Usage:
    python train_model.py
    python train_model.py --epochs 5 --batch_size 16 --lr 2e-5
"""

import os
import argparse
import numpy as np
import pandas as pd
import torch
from datasets import Dataset
from sklearn.metrics import (
    accuracy_score,
    precision_recall_fscore_support,
    classification_report,
)
from transformers import (
    AutoTokenizer,
    AutoModelForSequenceClassification,
    DataCollatorWithPadding,
    Trainer,
    TrainingArguments,
)

# ─────────────────────────────────────────────
# CONFIG
# ─────────────────────────────────────────────
DATASET_PATH = "./balanced_attack_dataset.csv"
MODEL_NAME   = "distilbert-base-uncased"
SAVE_DIR     = "./trained_model"


def parse_args():
    parser = argparse.ArgumentParser(description="Train cybersecurity classifier")
    parser.add_argument("--epochs",     type=int,   default=4,    help="Number of training epochs")
    parser.add_argument("--batch_size", type=int,   default=16,   help="Training batch size")
    parser.add_argument("--lr",         type=float, default=2e-5, help="Learning rate")
    parser.add_argument("--max_len",    type=int,   default=128,  help="Max token length")
    parser.add_argument("--test_size",  type=float, default=0.15, help="Validation set fraction")
    return parser.parse_args()


def compute_metrics(eval_pred):
    logits, labels = eval_pred
    predictions = np.argmax(logits, axis=-1)
    precision, recall, f1, _ = precision_recall_fscore_support(
        labels, predictions, average="weighted", zero_division=0
    )
    acc = accuracy_score(labels, predictions)
    return {"accuracy": acc, "f1": f1, "precision": precision, "recall": recall}


def main():
    args = parse_args()

    torch.manual_seed(42)
    np.random.seed(42)

    print("=" * 60)
    print("  Cybersecurity Attack Classifier — Training Script")
    print("=" * 60)
    print(f"  Dataset   : {DATASET_PATH}")
    print(f"  Base model: {MODEL_NAME}")
    print(f"  Epochs    : {args.epochs}")
    print(f"  Batch size: {args.batch_size}")
    print(f"  LR        : {args.lr}")
    print(f"  Max length: {args.max_len}")
    print(f"  CUDA      : {torch.cuda.is_available()}")
    print("=" * 60)

    # ── 1. Load Dataset ────────────────────────────────────────
    if not os.path.exists(DATASET_PATH):
        raise FileNotFoundError(
            f"Dataset not found: {DATASET_PATH}\n"
            "Please place 'balanced_attack_dataset.csv' in the project root."
        )

    df = pd.read_csv(DATASET_PATH)
    df = df.dropna(subset=["text", "label"])
    df["text"] = df["text"].astype(str).str.strip()
    df = df[df["text"].str.len() > 0]

    print(f"\n[1/5] Dataset loaded — {len(df):,} samples, {df['label'].nunique()} classes")
    print(df["label"].value_counts().to_string())

    # ── 2. Label Encoding ──────────────────────────────────────
    labels     = sorted(df["label"].unique().tolist())
    label2id   = {lbl: i for i, lbl in enumerate(labels)}
    id2label   = {i: lbl for i, lbl in enumerate(labels)}
    num_labels = len(labels)

    df["label_id"] = df["label"].map(label2id)

    print(f"\n[2/5] Label mapping created — {num_labels} distinct classes:")
    for i, lbl in id2label.items():
        print(f"       {i:2d} -> {lbl}")

    # ── 3. Tokenizer ───────────────────────────────────────────
    print(f"\n[3/5] Loading tokenizer: {MODEL_NAME}")
    tokenizer = AutoTokenizer.from_pretrained(MODEL_NAME)

    dataset = Dataset.from_pandas(
        df[["text", "label_id"]].rename(columns={"label_id": "label"})
    )
    dataset = dataset.train_test_split(test_size=args.test_size, seed=42)

    def preprocess(examples):
        return tokenizer(
            examples["text"],
            truncation=True,
            max_length=args.max_len,
        )

    tokenized = dataset.map(preprocess, batched=True, remove_columns=["text"])
    print(f"     Train: {len(tokenized['train']):,} | Validation: {len(tokenized['test']):,}")

    # ── 4. Model ───────────────────────────────────────────────
    print(f"\n[4/5] Loading base model: {MODEL_NAME}")
    model = AutoModelForSequenceClassification.from_pretrained(
        MODEL_NAME,
        num_labels=num_labels,
        id2label=id2label,
        label2id=label2id,
    )

    # ── 5. Training ────────────────────────────────────────────
    print(f"\n[5/5] Starting fine-tuning...")

    training_args = TrainingArguments(
        output_dir                  = "./results",
        learning_rate               = args.lr,
        per_device_train_batch_size = args.batch_size,
        per_device_eval_batch_size  = args.batch_size,
        num_train_epochs            = args.epochs,
        weight_decay                = 0.01,
        warmup_ratio                = 0.05,
        eval_strategy               = "epoch",
        save_strategy               = "epoch",
        load_best_model_at_end      = True,
        metric_for_best_model       = "f1",
        greater_is_better           = True,
        logging_steps               = 50,
        report_to                   = "none",
        fp16                        = torch.cuda.is_available(),
        dataloader_num_workers      = 0,
    )

    trainer = Trainer(
        model            = model,
        args             = training_args,
        train_dataset    = tokenized["train"],
        eval_dataset     = tokenized["test"],
        processing_class = tokenizer,
        data_collator    = DataCollatorWithPadding(tokenizer=tokenizer),
        compute_metrics  = compute_metrics,
    )

    trainer.train()

    # ── 6. Evaluation ──────────────────────────────────────────
    print("\n" + "=" * 60)
    print("  EVALUATION RESULTS")
    print("=" * 60)

    eval_results = trainer.evaluate()
    for k, v in eval_results.items():
        if isinstance(v, float):
            print(f"  {k:<25} : {v:.4f}")

    predictions = trainer.predict(tokenized["test"])
    preds       = np.argmax(predictions.predictions, axis=-1)
    true_labels = tokenized["test"]["label"]

    print("\nDetailed Classification Report:")
    print(
        classification_report(
            true_labels,
            preds,
            target_names=[id2label[i] for i in range(num_labels)],
            zero_division=0,
        )
    )

    # ── 7. Save Model & Tokenizer ──────────────────────────────
    os.makedirs(SAVE_DIR, exist_ok=True)
    trainer.save_model(SAVE_DIR)
    tokenizer.save_pretrained(SAVE_DIR)

    print("=" * 60)
    print(f"  Model saved to: {SAVE_DIR}")
    print(f"  Classes       : {num_labels}")
    print("  Training complete! Run test_model.py to validate.")
    print("=" * 60)


if __name__ == "__main__":
    main()
