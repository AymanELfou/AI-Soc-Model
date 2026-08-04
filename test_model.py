"""
test_model.py
=============
Test script pour valider le modèle entraîné.
Affiche le label prédit + les top-5 scores par classe.
"""

from transformers import pipeline
import torch
from transformers import AutoTokenizer, AutoModelForSequenceClassification

MODEL_DIR = "./trained_model"

# Chargement du modèle et tokenizer
print(f"Loading model from: {MODEL_DIR}\n")
tokenizer = AutoTokenizer.from_pretrained(MODEL_DIR)
model = AutoModelForSequenceClassification.from_pretrained(MODEL_DIR)
model.eval()

# Pipeline pour affichage simple
classifier = pipeline(
    "text-classification",
    model=model,
    tokenizer=tokenizer,
    top_k=None,               # retourne les scores de toutes les classes
    device=-1,                # CPU
)

tests = [
    ("SQL Injection",       "' OR 1=1 --"),
    ("SQL Drop Table",      "DROP TABLE users"),
    ("XSS",                 "<script>alert(1)</script>"),
    ("Path Traversal",      "../../etc/passwd"),
    ("Command Injection",   "cmd.exe /c whoami"),
    ("Malware/PowerShell",  "powershell -enc AAA"),
    ("HTTP Traffic",        "POST /login HTTP/1.1"),
    ("SQL Select",          "SELECT * FROM users"),
    ("Benign",              "Hello world"),
    ("Benign URL",          "https://example.com"),
]

print("=" * 70)
print(f"{'CATEGORY':<22} {'INPUT':<35} {'PREDICTION':<22} {'CONF':>6}")
print("=" * 70)

for category, text in tests:
    scores = classifier(text)[0]
    # Sort by score descending
    scores_sorted = sorted(scores, key=lambda x: x['score'], reverse=True)
    best = scores_sorted[0]
    top3 = [(s['label'], round(s['score'], 4)) for s in scores_sorted[:3]]

    print(f"\n[{category}]")
    print(f"  Input      : {text}")
    print(f"  Prediction : {best['label']:<22}  confidence: {best['score']:.4f}")
    print(f"  Top 3      : {top3}")

print("\n" + "=" * 70)
print("Test completed!")
