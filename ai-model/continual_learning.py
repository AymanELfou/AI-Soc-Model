"""
continual_learning.py
======================
Enterprise VPS Security AI — Safe Continual Learning CLI

Safe workflow (NO automatic self-training):
  1. --predict    : Test a payload, flag unknowns to unknown_attacks.csv
  2. --show       : Show all pending unknown attacks
  3. --approve    : Admin approves and labels an unknown attack
  4. --reject     : Admin rejects a false positive
  5. --export     : Export approved samples to reviewed_unknown_attacks.csv
  6. --weekly     : Generate weekly report of unknown attacks
  7. --stats      : Show current model and dataset statistics

Retraining is done ONLY via retrain_model.ipynb on Google Colab.
"""

import argparse
import os
import json
import csv
import pandas as pd
from datetime import datetime, timedelta
from transformers import pipeline, AutoTokenizer, AutoModelForSequenceClassification

# ────────────────────────────────────────────
#  CONFIG
# ────────────────────────────────────────────
MODEL_DIR              = "./trained_model"
UNKNOWN_ATTACKS_PATH   = "./unknown_attacks.csv"
REVIEWED_ATTACKS_PATH  = "./reviewed_unknown_attacks.csv"
DATASET_PATH           = "./enterprise_security_dataset.csv"
CONFIDENCE_THRESHOLD   = 0.60


# ────────────────────────────────────────────
#  1. PREDICT + FLAG UNKNOWNS
# ────────────────────────────────────────────
def predict_and_flag(text: str, log_source: str = "cli"):
    tokenizer = AutoTokenizer.from_pretrained(MODEL_DIR)
    model = AutoModelForSequenceClassification.from_pretrained(MODEL_DIR)
    classifier = pipeline("text-classification", model=model, tokenizer=tokenizer, top_k=3, device=-1)

    results = classifier(text)[0]
    best = results[0]
    label = best["label"]
    conf = best["score"]
    top3 = [(r["label"], round(r["score"], 4)) for r in results]

    print(f"\n{'='*60}")
    print(f"Input      : {text[:100]}")
    print(f"Prediction : {label}")
    print(f"Confidence : {conf:.4f}")
    print(f"Top 3      : {top3}")

    if conf < CONFIDENCE_THRESHOLD:
        print(f"\n!! UNKNOWN ATTACK DETECTED (confidence {conf:.4f} < {CONFIDENCE_THRESHOLD})")
        print(f"   Saved to {UNKNOWN_ATTACKS_PATH} for admin review.")

        row = {
            "id": datetime.now().strftime("%Y%m%d%H%M%S%f"),
            "timestamp": datetime.now().isoformat(),
            "raw_log": text,
            "predicted_label": label,
            "confidence": round(conf, 4),
            "log_source": log_source,
            "status": "pending",
            "reviewed_label": "",
        }
        file_exists = os.path.exists(UNKNOWN_ATTACKS_PATH)
        with open(UNKNOWN_ATTACKS_PATH, "a", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=row.keys())
            if not file_exists:
                writer.writeheader()
            writer.writerow(row)
        print(f"   ID: {row['id']}")
    else:
        print(f"\n   Prediction is confident. No action needed.")
    print("=" * 60)


# ────────────────────────────────────────────
#  2. SHOW PENDING UNKNOWNS
# ────────────────────────────────────────────
def show_pending():
    if not os.path.exists(UNKNOWN_ATTACKS_PATH):
        print("No unknown attacks found.")
        return

    df = pd.read_csv(UNKNOWN_ATTACKS_PATH)
    pending = df[df["status"] == "pending"]

    print(f"\n{'='*70}")
    print(f"UNKNOWN ATTACKS PENDING REVIEW ({len(pending)} / {len(df)} total)")
    print(f"{'='*70}")

    for _, row in pending.iterrows():
        print(f"\n  ID          : {row['id']}")
        print(f"  Payload     : {str(row['raw_log'])[:80]}...")
        print(f"  Predicted   : {row['predicted_label']} (conf={row['confidence']})")
        print(f"  Source      : {row['log_source']}")
        print(f"  Timestamp   : {row['timestamp']}")

    print(f"\n{'='*70}")
    print("To approve:  python continual_learning.py --approve <ID> <LABEL>")
    print("To reject:   python continual_learning.py --reject <ID>")

    # Show available labels
    config_path = os.path.join(MODEL_DIR, "config.json")
    if os.path.exists(config_path):
        with open(config_path) as f:
            config = json.load(f)
        labels = sorted(config.get("id2label", {}).values())
        print(f"\nKnown labels: {labels}")
        print("You can also use a NEW label name for entirely new attack types.")


# ────────────────────────────────────────────
#  3. APPROVE AN UNKNOWN ATTACK
# ────────────────────────────────────────────
def approve_attack(attack_id: str, true_label: str):
    if not os.path.exists(UNKNOWN_ATTACKS_PATH):
        print("No unknown_attacks.csv found.")
        return

    df = pd.read_csv(UNKNOWN_ATTACKS_PATH, dtype=str)
    mask = df["id"].astype(str) == str(attack_id)

    if not mask.any():
        print(f"ID '{attack_id}' not found.")
        return

    df["status"] = df["status"].astype(str)
    df["reviewed_label"] = df["reviewed_label"].astype(str)

    df.loc[mask, "status"] = "approved"
    df.loc[mask, "reviewed_label"] = true_label
    df.to_csv(UNKNOWN_ATTACKS_PATH, index=False)

    approved_count = len(df[df["status"] == "approved"])
    print(f"Attack {attack_id} APPROVED as '{true_label}'.")
    print(f"Total approved: {approved_count}")
    print(f"\nWhen ready, export with: python continual_learning.py --export")
    print(f"Then retrain on Google Colab with retrain_model.ipynb")


# ────────────────────────────────────────────
#  4. REJECT A FALSE POSITIVE
# ────────────────────────────────────────────
def reject_attack(attack_id: str):
    if not os.path.exists(UNKNOWN_ATTACKS_PATH):
        print("No unknown_attacks.csv found.")
        return

    df = pd.read_csv(UNKNOWN_ATTACKS_PATH)
    mask = df["id"].astype(str) == str(attack_id)

    if not mask.any():
        print(f"ID '{attack_id}' not found.")
        return

    df.loc[mask, "status"] = "rejected"
    df.to_csv(UNKNOWN_ATTACKS_PATH, index=False)
    print(f"Attack {attack_id} REJECTED (false positive).")


# ────────────────────────────────────────────
#  5. EXPORT APPROVED SAMPLES
# ────────────────────────────────────────────
def export_approved():
    if not os.path.exists(UNKNOWN_ATTACKS_PATH):
        print("No unknown_attacks.csv found.")
        return

    df = pd.read_csv(UNKNOWN_ATTACKS_PATH)
    approved = df[df["status"] == "approved"]

    if len(approved) == 0:
        print("No approved samples to export.")
        return

    # Create reviewed_unknown_attacks.csv
    export_df = approved[["raw_log", "reviewed_label", "confidence", "log_source", "timestamp", "status"]].copy()
    export_df.columns = ["text", "label", "confidence", "log_source", "timestamp", "status"]
    export_df.to_csv(REVIEWED_ATTACKS_PATH, index=False)

    print(f"Exported {len(export_df)} approved samples to {REVIEWED_ATTACKS_PATH}")
    print(f"Labels: {export_df['label'].unique().tolist()}")
    print(f"\nNext steps:")
    print(f"  1. Upload {REVIEWED_ATTACKS_PATH} to Google Colab")
    print(f"  2. Upload enterprise_security_dataset.csv to Google Colab")
    print(f"  3. Run retrain_model.ipynb")


# ────────────────────────────────────────────
#  6. WEEKLY REPORT
# ────────────────────────────────────────────
def weekly_report():
    if not os.path.exists(UNKNOWN_ATTACKS_PATH):
        print("No unknown attacks recorded.")
        return

    df = pd.read_csv(UNKNOWN_ATTACKS_PATH)
    df["timestamp"] = pd.to_datetime(df["timestamp"])
    week_ago = datetime.now() - timedelta(days=7)
    df_week = df[df["timestamp"] >= week_ago]

    print(f"\n{'='*60}")
    print(f"WEEKLY UNKNOWN ATTACKS REPORT")
    print(f"Period: {week_ago.strftime('%Y-%m-%d')} to {datetime.now().strftime('%Y-%m-%d')}")
    print(f"{'='*60}")
    print(f"\nTotal unknown attacks this week: {len(df_week)}")
    print(f"Pending review  : {len(df_week[df_week['status'] == 'pending'])}")
    print(f"Approved        : {len(df_week[df_week['status'] == 'approved'])}")
    print(f"Rejected        : {len(df_week[df_week['status'] == 'rejected'])}")

    if len(df_week) > 0:
        print(f"\nTop predicted labels:")
        for label, count in df_week["predicted_label"].value_counts().head(10).items():
            print(f"  {label:<30} {count}")

        print(f"\nTop log sources:")
        for src, count in df_week["log_source"].value_counts().head(5).items():
            print(f"  {src:<30} {count}")

    print(f"{'='*60}")


# ────────────────────────────────────────────
#  7. STATS
# ────────────────────────────────────────────
def show_stats():
    print(f"\n{'='*60}")
    print(f"ENTERPRISE VPS SECURITY AI - STATUS")
    print(f"{'='*60}")

    # Model info
    config_path = os.path.join(MODEL_DIR, "config.json")
    if os.path.exists(config_path):
        with open(config_path) as f:
            config = json.load(f)
        labels = sorted(config.get("id2label", {}).values())
        print(f"\nModel classes: {len(labels)}")
        print(f"Labels: {labels}")
    else:
        print("Model config not found.")

    # Dataset info
    if os.path.exists(DATASET_PATH):
        df = pd.read_csv(DATASET_PATH)
        print(f"\nDataset: {len(df)} samples, {df['label'].nunique()} classes")
    else:
        print(f"\nDataset {DATASET_PATH} not found.")

    # Unknown attacks
    if os.path.exists(UNKNOWN_ATTACKS_PATH):
        df_u = pd.read_csv(UNKNOWN_ATTACKS_PATH)
        print(f"\nUnknown attacks: {len(df_u)} total")
        print(f"  Pending  : {len(df_u[df_u['status'] == 'pending'])}")
        print(f"  Approved : {len(df_u[df_u['status'] == 'approved'])}")
        print(f"  Rejected : {len(df_u[df_u['status'] == 'rejected'])}")
    else:
        print("\nNo unknown attacks recorded.")

    print(f"{'='*60}")


# ────────────────────────────────────────────
#  MAIN CLI
# ────────────────────────────────────────────
if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Enterprise VPS Security AI - Safe Continual Learning CLI"
    )
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--predict", type=str, metavar="PAYLOAD",
                       help="Test a payload. Flags unknowns automatically.")
    group.add_argument("--show", action="store_true",
                       help="Show all pending unknown attacks.")
    group.add_argument("--approve", nargs=2, metavar=("ID", "LABEL"),
                       help="Approve and label an unknown attack.")
    group.add_argument("--reject", type=str, metavar="ID",
                       help="Reject a false positive.")
    group.add_argument("--export", action="store_true",
                       help="Export approved samples to reviewed_unknown_attacks.csv.")
    group.add_argument("--weekly", action="store_true",
                       help="Generate weekly unknown attacks report.")
    group.add_argument("--stats", action="store_true",
                       help="Show model and dataset statistics.")

    args = parser.parse_args()

    if args.predict:
        predict_and_flag(args.predict)
    elif args.show:
        show_pending()
    elif args.approve:
        approve_attack(args.approve[0], args.approve[1])
    elif args.reject:
        reject_attack(args.reject)
    elif args.export:
        export_approved()
    elif args.weekly:
        weekly_report()
    elif args.stats:
        show_stats()
