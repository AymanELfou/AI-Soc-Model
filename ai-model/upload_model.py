"""
upload_model.py
===============
Script d'upload automatique du modèle IA SOC Security (DistilBERT 48 classes)
sur le Hub Hugging Face (compte: AymanElFou).
"""

import os
import sys
from huggingface_hub import HfApi, login

# 1. Identifiants Hugging Face (Utilise la variable d'environnement HF_TOKEN pour la sécurité)
HF_TOKEN = os.getenv("HF_TOKEN", "ENTRER_VOTRE_TOKEN_ICI")
HF_USERNAME = os.getenv("HF_USERNAME", "AymanElFou")
REPO_NAME = "AI-SOC-Upload"
REPO_ID = f"{HF_USERNAME}/{REPO_NAME}"

# 2. Localisation du dossier contenant le modèle entraîné
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
MODEL_DIR = os.path.join(BASE_DIR, "..", "ai-security-agent", "trained_model")
if not os.path.exists(MODEL_DIR):
    MODEL_DIR = os.path.join(BASE_DIR, "trained_model")
if not os.path.exists(MODEL_DIR):
    MODEL_DIR = os.path.join(os.path.dirname(BASE_DIR), "ai-security-agent", "trained_model")

def upload():
    print("=" * 65)
    print("PUBLICATION DU MODELE SUR HUGGING FACE HUB")
    print(f"   Compte    : {HF_USERNAME}")
    print(f"   Depot     : {REPO_ID}")
    print(f"   Source    : {MODEL_DIR}")
    print("=" * 65)

    if not os.path.exists(MODEL_DIR):
        print(f"ERREUR: Le dossier du modele est introuvable a : {MODEL_DIR}")
        sys.exit(1)

    print("\n1. Connexion a Hugging Face...")
    login(token=HF_TOKEN)

    api = HfApi()
    print(f"\n2. Creation/Verification du depot '{REPO_ID}'...")
    api.create_repo(repo_id=REPO_ID, repo_type="model", exist_ok=True, private=False)

    print(f"\n3. Televersement des fichiers du modele en cours...")
    api.upload_folder(
        folder_path=MODEL_DIR,
        repo_id=REPO_ID,
        repo_type="model",
        commit_message="Upload fine-tuned DistilBERT 48-class AI SOC security model weights"
    )

    print("\n" + "=" * 65)
    print("SUCCES ! Votre modele est publie et accessible sur :")
    print(f"https://huggingface.co/{REPO_ID}")
    print("=" * 65)

if __name__ == "__main__":
    upload()
