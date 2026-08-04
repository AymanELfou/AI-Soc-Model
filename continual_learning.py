"""
continual_learning.py
======================
Système d'apprentissage continu pour le modèle de cybersécurité.

Fonctionnement :
  1. Le modèle prédit chaque requête entrante.
  2. Si la confiance est < CONFIDENCE_THRESHOLD, la requête est loggée
     dans 'pending_review.csv' pour révision humaine.
  3. Quand suffisamment de nouvelles attaques sont étiquetées, le script
     AUTO_RETRAIN les ajoute au dataset et relance le fine-tuning.

Usage :
  - Tester une requête                  : python continual_learning.py --predict "<payload>"
  - Voir les attaques en attente        : python continual_learning.py --show-pending
  - Labéliser une attaque inconnue      : python continual_learning.py --label <id> <LABEL>
  - Réentraîner avec les nouvelles data : python continual_learning.py --retrain
"""

import argparse
import os
import json
import pandas as pd
from datetime import datetime
from transformers import (
    AutoTokenizer,
    AutoModelForSequenceClassification,
    TrainingArguments,
    Trainer,
    DataCollatorWithPadding,
)
from sklearn.preprocessing import LabelEncoder
from torch.utils.data import Dataset
import torch
import numpy as np

# ──────────────────────────────────────────────
#  CONFIG
# ──────────────────────────────────────────────
MODEL_DIR            = "./trained_model"
MAIN_DATASET_PATH    = "./balanced_attack_dataset.csv"
PENDING_REVIEW_PATH  = "./pending_review.csv"
RETRAIN_LOG_PATH     = "./retrain_log.json"
CONFIDENCE_THRESHOLD = 0.75   # En dessous → attaque INCONNUE / incertaine
MIN_SAMPLES_TO_RETRAIN = 50   # Minimum de nouveaux exemples avant de relancer l'entraînement


# ──────────────────────────────────────────────
#  DATASET CLASS
# ──────────────────────────────────────────────
class AttackDataset(Dataset):
    def __init__(self, texts, labels, tokenizer, max_len=128):
        self.encodings = tokenizer(
            texts, truncation=True, padding=True, max_length=max_len
        )
        self.labels = labels

    def __len__(self):
        return len(self.labels)

    def __getitem__(self, idx):
        item = {k: torch.tensor(v[idx]) for k, v in self.encodings.items()}
        item["labels"] = torch.tensor(self.labels[idx])
        return item


# ──────────────────────────────────────────────
#  1. PREDICT + DETECT UNKNOWN ATTACKS
# ──────────────────────────────────────────────
def predict_and_flag(text: str):
    """
    Prédit le label d'un payload.
    Si confiance < CONFIDENCE_THRESHOLD → flagge comme 'UNKNOWN' et sauvegarde
    dans pending_review.csv pour révision humaine.
    """
    from transformers import pipeline

    tokenizer = AutoTokenizer.from_pretrained(MODEL_DIR)
    model     = AutoModelForSequenceClassification.from_pretrained(MODEL_DIR)
    classifier = pipeline(
        "text-classification", model=model, tokenizer=tokenizer,
        top_k=3, device=-1
    )

    results = classifier(text)[0]
    best    = results[0]
    label   = best["label"]
    conf    = best["score"]
    top3    = [(r["label"], round(r["score"], 4)) for r in results]

    print(f"\n{'='*60}")
    print(f"Input      : {text}")
    print(f"Prediction : {label}")
    print(f"Confidence : {conf:.4f}")
    print(f"Top 3      : {top3}")

    if conf < CONFIDENCE_THRESHOLD:
        print(f"\n⚠️  ALERTE : Confiance faible ({conf:.4f} < {CONFIDENCE_THRESHOLD})")
        print("   → Attaque INCONNUE ou NOUVELLE détectée !")
        print(f"   → Loggée dans '{PENDING_REVIEW_PATH}' pour révision humaine.")

        # Sauvegarde dans pending_review.csv
        row = {
            "id"           : datetime.now().strftime("%Y%m%d%H%M%S%f"),
            "text"         : text,
            "predicted"    : label,
            "confidence"   : round(conf, 4),
            "true_label"   : "UNKNOWN",    # À remplir manuellement ou via --label
            "timestamp"    : datetime.now().isoformat(),
        }
        df_pending = pd.DataFrame([row])
        if os.path.exists(PENDING_REVIEW_PATH):
            df_pending.to_csv(PENDING_REVIEW_PATH, mode="a", header=False, index=False)
        else:
            df_pending.to_csv(PENDING_REVIEW_PATH, index=False)

        print(f"   → ID attribué : {row['id']}")
    else:
        print(f"\n✅  Confiance OK. Prédiction fiable.")

    print("="*60)
    return label, conf


# ──────────────────────────────────────────────
#  2. SHOW PENDING ATTACKS
# ──────────────────────────────────────────────
def show_pending():
    if not os.path.exists(PENDING_REVIEW_PATH):
        print("Aucune attaque en attente de révision.")
        return

    df = pd.read_csv(PENDING_REVIEW_PATH)
    unlabeled = df[df["true_label"] == "UNKNOWN"]

    print(f"\n{'='*70}")
    print(f"📋 ATTAQUES EN ATTENTE DE RÉVISION ({len(unlabeled)} / {len(df)} total)")
    print(f"{'='*70}")
    for _, row in unlabeled.iterrows():
        print(f"\nID        : {row['id']}")
        print(f"Payload   : {str(row['text'])[:80]}...")
        print(f"Prédit    : {row['predicted']} (conf={row['confidence']})")
        print(f"Horodatage: {row['timestamp']}")
    print(f"{'='*70}")
    print(f"\nPour labéliser: python continual_learning.py --label <ID> <LABEL>")

    # Afficher les labels disponibles depuis la config du modèle
    config_path = os.path.join(MODEL_DIR, "config.json")
    if os.path.exists(config_path):
        with open(config_path) as f:
            config = json.load(f)
        labels = list(config.get("id2label", {}).values())
        print(f"\nLabels disponibles: {labels}")
        print("Si la nouvelle attaque est d'un type entièrement nouveau, utilise un nouveau nom.")


# ──────────────────────────────────────────────
#  3. LABEL A PENDING ATTACK
# ──────────────────────────────────────────────
def label_attack(attack_id: str, true_label: str):
    if not os.path.exists(PENDING_REVIEW_PATH):
        print("Aucun fichier pending_review.csv trouvé.")
        return

    df = pd.read_csv(PENDING_REVIEW_PATH)
    mask = df["id"].astype(str) == str(attack_id)

    if not mask.any():
        print(f"ID '{attack_id}' introuvable.")
        return

    df.loc[mask, "true_label"] = true_label
    df.to_csv(PENDING_REVIEW_PATH, index=False)

    labeled_count = len(df[df["true_label"] != "UNKNOWN"])
    print(f"✅ Attaque {attack_id} labélisée comme '{true_label}'.")
    print(f"   {labeled_count} attaques labélisées. Minimum pour réentraîner : {MIN_SAMPLES_TO_RETRAIN}")

    if labeled_count >= MIN_SAMPLES_TO_RETRAIN:
        print(f"\n🚀 Seuil atteint ! Lance le réentraînement avec:")
        print(f"   python continual_learning.py --retrain")


# ──────────────────────────────────────────────
#  4. AUTO-RETRAIN
# ──────────────────────────────────────────────
def retrain_model():
    print("\n" + "="*60)
    print("🔁 DÉMARRAGE DU RÉENTRAÎNEMENT DU MODÈLE")
    print("="*60)

    # ── Charger les nouvelles données labélisées
    if not os.path.exists(PENDING_REVIEW_PATH):
        print("Aucune donnée en attente. Réentraînement annulé.")
        return

    df_new = pd.read_csv(PENDING_REVIEW_PATH)
    df_new = df_new[df_new["true_label"] != "UNKNOWN"][["text", "true_label"]]
    df_new.columns = ["text", "label"]
    df_new = df_new.dropna()

    if len(df_new) < 1:
        print("Aucune nouvelle donnée labélisée. Réentraînement annulé.")
        return

    print(f"Nouvelles données labélisées : {len(df_new)} exemples")
    print(f"Nouvelles classes : {df_new['label'].unique().tolist()}")

    # ── Charger le dataset principal
    if not os.path.exists(MAIN_DATASET_PATH):
        print(f"Dataset principal '{MAIN_DATASET_PATH}' introuvable. Arrêt.")
        return

    df_main = pd.read_csv(MAIN_DATASET_PATH)[["text", "label"]].dropna()
    print(f"Dataset principal : {len(df_main)} exemples, {df_main['label'].nunique()} classes")

    # ── Fusion
    df_combined = pd.concat([df_main, df_new], ignore_index=True)
    df_combined = df_combined.drop_duplicates(subset=["text"]).sample(frac=1, random_state=42).reset_index(drop=True)

    print(f"\nDataset combiné : {len(df_combined)} exemples, {df_combined['label'].nunique()} classes")

    # ── Label Encoding
    le = LabelEncoder()
    df_combined["label_id"] = le.fit_transform(df_combined["label"])
    all_labels = le.classes_.tolist()
    num_labels = len(all_labels)

    print(f"Classes totales : {num_labels}")
    print(f"Labels : {all_labels}")

    # ── Train / Val split (90/10)
    val_df   = df_combined.sample(frac=0.10, random_state=42)
    train_df = df_combined.drop(val_df.index).reset_index(drop=True)
    val_df   = val_df.reset_index(drop=True)

    print(f"\nSplit: Train={len(train_df)}, Val={len(val_df)}")

    # ── Charger tokenizer + modèle existant
    print(f"\nChargement du modèle depuis '{MODEL_DIR}'...")
    tokenizer = AutoTokenizer.from_pretrained(MODEL_DIR)

    # ── Reconstruire le modèle avec le bon nombre de labels
    import json
    config_path = os.path.join(MODEL_DIR, "config.json")
    with open(config_path) as f:
        config_data = json.load(f)

    id2label = {str(i): l for i, l in enumerate(all_labels)}
    label2id = {l: i for i, l in enumerate(all_labels)}

    model = AutoModelForSequenceClassification.from_pretrained(
        MODEL_DIR,
        num_labels=num_labels,
        id2label=id2label,
        label2id=label2id,
        ignore_mismatched_sizes=True   # Important : accepte les nouveaux labels
    )

    # ── Datasets
    train_dataset = AttackDataset(
        train_df["text"].tolist(), train_df["label_id"].tolist(), tokenizer
    )
    val_dataset = AttackDataset(
        val_df["text"].tolist(), val_df["label_id"].tolist(), tokenizer
    )

    # ── Training Arguments
    training_args = TrainingArguments(
        output_dir          = "./retrained_model",
        num_train_epochs    = 3,
        per_device_train_batch_size = 16,
        per_device_eval_batch_size  = 32,
        warmup_ratio        = 0.1,
        learning_rate       = 2e-5,
        weight_decay        = 0.01,
        logging_dir         = "./logs",
        logging_steps       = 50,
        eval_strategy       = "epoch",
        save_strategy       = "epoch",
        load_best_model_at_end = True,
        metric_for_best_model  = "eval_loss",
        report_to           = "none",
        disable_tqdm        = False,
    )

    def compute_metrics(eval_pred):
        logits, labels = eval_pred
        preds = np.argmax(logits, axis=-1)
        acc = (preds == labels).mean()
        return {"accuracy": acc}

    data_collator = DataCollatorWithPadding(tokenizer=tokenizer)

    trainer = Trainer(
        model           = model,
        args            = training_args,
        train_dataset   = train_dataset,
        eval_dataset    = val_dataset,
        data_collator   = data_collator,
        compute_metrics = compute_metrics,
    )

    print("\n🚀 Réentraînement en cours...\n")
    trainer.train()

    # ── Sauvegarder le nouveau modèle
    print("\n💾 Sauvegarde du modèle mis à jour...")
    model.save_pretrained(MODEL_DIR)
    tokenizer.save_pretrained(MODEL_DIR)
    print(f"✅ Modèle mis à jour sauvegardé dans '{MODEL_DIR}'.")

    # ── Mettre à jour le dataset principal
    df_combined.to_csv(MAIN_DATASET_PATH, index=False)
    print(f"✅ Dataset principal mis à jour : {len(df_combined)} exemples.")

    # ── Vider le fichier pending_review (garder l'historique des labélisés)
    df_pending = pd.read_csv(PENDING_REVIEW_PATH)
    df_pending.to_csv("./retrain_history.csv", mode="a",
                      header=not os.path.exists("retrain_history.csv"), index=False)
    os.remove(PENDING_REVIEW_PATH)
    print("✅ Fichier pending_review.csv archivé dans retrain_history.csv et réinitialisé.")

    # ── Logger le réentraînement
    log = {
        "timestamp"      : datetime.now().isoformat(),
        "new_samples"    : len(df_new),
        "total_samples"  : len(df_combined),
        "total_classes"  : num_labels,
        "new_classes"    : df_new["label"].unique().tolist(),
        "all_labels"     : all_labels,
    }
    history = []
    if os.path.exists(RETRAIN_LOG_PATH):
        with open(RETRAIN_LOG_PATH) as f:
            history = json.load(f)
    history.append(log)
    with open(RETRAIN_LOG_PATH, "w") as f:
        json.dump(history, f, indent=2)

    print(f"\n{'='*60}")
    print("🎉 RÉENTRAÎNEMENT TERMINÉ AVEC SUCCÈS !")
    print(f"   Nouvelles classes intégrées : {df_new['label'].unique().tolist()}")
    print(f"   Total classes supportées    : {num_labels}")
    print(f"{'='*60}")


# ──────────────────────────────────────────────
#  MAIN CLI
# ──────────────────────────────────────────────
if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Système d'apprentissage continu pour le modèle de cybersécurité."
    )
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--predict",      type=str, metavar="PAYLOAD",
                       help="Prédit la classe d'un payload et détecte s'il est inconnu.")
    group.add_argument("--show-pending", action="store_true",
                       help="Affiche les attaques en attente de révision humaine.")
    group.add_argument("--label",        nargs=2, metavar=("ID", "LABEL"),
                       help="Labélise une attaque en attente. Ex: --label 20260804123456 SQL_Injection")
    group.add_argument("--retrain",      action="store_true",
                       help="Réentraîne le modèle avec toutes les nouvelles données labélisées.")
    group.add_argument("--status",       action="store_true",
                       help="Affiche l'historique des réentraînements.")

    args = parser.parse_args()

    if args.predict:
        predict_and_flag(args.predict)

    elif args.show_pending:
        show_pending()

    elif args.label:
        label_attack(args.label[0], args.label[1])

    elif args.retrain:
        retrain_model()

    elif args.status:
        if os.path.exists(RETRAIN_LOG_PATH):
            with open(RETRAIN_LOG_PATH) as f:
                logs = json.load(f)
            print(f"\n📊 Historique des réentraînements ({len(logs)} sessions) :")
            for i, log in enumerate(logs, 1):
                print(f"\n  [{i}] {log['timestamp']}")
                print(f"      Nouveaux exemples : {log['new_samples']}")
                print(f"      Total dataset     : {log['total_samples']}")
                print(f"      Classes totales   : {log['total_classes']}")
                print(f"      Nouvelles classes : {log['new_classes']}")
        else:
            print("Aucun historique de réentraînement trouvé.")
