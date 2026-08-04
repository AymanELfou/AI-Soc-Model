import pandas as pd
from transformers import pipeline, AutoModelForSequenceClassification, AutoTokenizer
import random

MODEL_DIR = "./trained_model"
TEST_DATASET = "test_dataset.csv"

print(f"Loading model from: {MODEL_DIR}...")
tokenizer = AutoTokenizer.from_pretrained(MODEL_DIR)
model = AutoModelForSequenceClassification.from_pretrained(MODEL_DIR)

classifier = pipeline(
    "text-classification",
    model=model,
    tokenizer=tokenizer,
    top_k=3,
    device=-1
)

print(f"Loading dataset from: {TEST_DATASET}...")
df = pd.read_csv(TEST_DATASET)

print("\n" + "="*50)
print("🔍 MODE DE TEST INTERACTIF SUR LE DATASET 🔍")
print("="*50)
print("1. Appuie sur [ENTRÉE] pour tirer un payload aléatoire du dataset.")
print("2. Tape un payload personnalisé pour le tester.")
print("3. Tape 'quit' ou 'exit' pour quitter.")
print("="*50 + "\n")

while True:
    try:
        user_input = input("Payload (ou Entrée pour aléatoire) > ").strip()
        
        if user_input.lower() in ['quit', 'exit']:
            print("Fin du test interactif.")
            break
            
        if not user_input:
            # Tire un payload aléatoire du dataset
            row = df.sample(1).iloc[0]
            text = str(row['text'])
            true_label = row['label']
            print(f"\n[Depuis le dataset - Vrai Label: {true_label}]")
        else:
            text = user_input
            print(f"\n[Payload Personnalisé]")
            
        print(f"Input : {text}")
        
        # Prédiction
        scores = classifier(text)[0]
        best = scores[0]
        top3 = [(s['label'], round(s['score'], 4)) for s in scores]
        
        print(f"Prédiction : {best['label']} (Confiance: {best['score']:.4f})")
        print(f"Top 3      : {top3}\n")
        
    except KeyboardInterrupt:
        print("\nFin du test interactif.")
        break
