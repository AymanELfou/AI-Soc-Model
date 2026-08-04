"""
interactive_test.py
===================
Interactive CLI Testing Tool for Enterprise VPS Security AI (48 Classes).
Allows testing both Web Attacks and Linux/Server Attacks interactively.
"""

import pandas as pd
import os
import random
from transformers import pipeline, AutoModelForSequenceClassification, AutoTokenizer

MODEL_DIR = "./trained_model"

# Try loading enterprise_security_dataset.csv, fallback to test_dataset.csv
DATASET_PATH = "./enterprise_security_dataset.csv"
if not os.path.exists(DATASET_PATH):
    DATASET_PATH = "./test_dataset.csv"

# Severity weights for risk calculation
ATTACK_SEVERITY_WEIGHTS = {
    "RCE": 1.00, "ReverseShell": 1.00, "Kernel_Exploit": 0.98, "Command_Injection": 0.98,
    "Linux_Command_Injection": 0.98, "Malicious_System_Command": 0.97, "PrivilegeEscalation": 0.96,
    "SQL_Injection": 0.95, "Malware": 0.95, "Linux_Malware": 0.95, "Ransomware": 0.95,
    "WebShell": 0.94, "Docker_Abuse": 0.93, "Persistence": 0.92, "XXE": 0.90,
    "Insecure_Deserialization": 0.90, "PathTraversal": 0.88, "FileUpload_Attack": 0.88,
    "XPATH_Injection": 0.88, "SSTI": 0.87, "Lateral_Movement": 0.87, "NoSQL_Injection": 0.85,
    "Cron_Abuse": 0.85, "Unauthorized_File_Modification": 0.84, "Root_Login_Attempt": 0.82,
    "Cryptomining": 0.80, "XSS": 0.80, "SSRF": 0.80, "GraphQL_Injection": 0.80,
    "Prototype_Pollution": 0.78, "LDAP_Injection": 0.78, "System_Enumeration": 0.76,
    "CSRF": 0.75, "OpenRedirect": 0.75, "Header_Injection": 0.72, "CRLF_Injection": 0.70,
    "Suspicious_Bash_Command": 0.70, "Suspicious_Process": 0.68, "SSH_BruteForce": 0.65,
    "BruteForce": 0.65, "CredentialStuffing": 0.65, "SSH_Login_Attack": 0.63,
    "PortScanning": 0.60, "DDoS": 0.60, "Failed_Login": 0.55, "Malicious_HTTP": 0.55,
    "Suspicious_Input": 0.50, "Benign": 0.00
}

def calculate_risk(prediction_label: str, confidence: float):
    severity = ATTACK_SEVERITY_WEIGHTS.get(prediction_label, 0.50)
    if prediction_label == "Benign":
        risk_pct = round((1.0 - confidence) * 15.0, 2)
        risk_lvl = "SAFE"
    else:
        raw_risk = (confidence * 0.70 + severity * 0.30) * 100.0
        risk_pct = round(min(raw_risk, 99.99), 2)
        if risk_pct >= 85.0:
            risk_lvl = "CRITICAL"
        elif risk_pct >= 65.0:
            risk_lvl = "HIGH"
        elif risk_pct >= 40.0:
            risk_lvl = "MEDIUM"
        else:
            risk_lvl = "LOW"
    return risk_pct, risk_lvl

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

df = None
if os.path.exists(DATASET_PATH):
    print(f"Loading dataset from: {DATASET_PATH}...")
    df = pd.read_csv(DATASET_PATH)
    print(f"Dataset loaded: {len(df)} samples across {df['label'].nunique()} categories.")

num_classes = model.config.num_labels
print("\n" + "="*70)
print(f"🛡️  INTERACTIVE TEST MODE — ENTERPRISE VPS SECURITY AI ({num_classes} Classes)")
print("="*70)
print("  - Press [ENTER] to pull a random payload from the dataset.")
print("  - Type any custom string (web attack, log line, bash command) to evaluate.")
print("  - Type 'quit' or 'exit' to stop.")
print("="*70 + "\n")

while True:
    try:
        user_input = input("Payload / Log (or Press ENTER for random sample) > ").strip()
        
        if user_input.lower() in ['quit', 'exit']:
            print("\nExiting interactive test. Goodbye!")
            break
            
        if not user_input:
            if df is not None:
                row = df.sample(1).iloc[0]
                text = str(row['text'])
                true_label = row['label']
                print(f"\n[Random Dataset Sample — Ground Truth Label: {true_label}]")
            else:
                print("No dataset loaded. Please enter a custom payload.")
                continue
        else:
            text = user_input
            print(f"\n[Custom Input Evaluation]")
            
        print(f"Input : {text}")
        
        scores = classifier(text)[0]
        best = scores[0]
        top3 = [(s['label'], round(s['score'], 4)) for s in scores]
        
        pred_label = best['label']
        conf_score = best['score']
        risk_pct, risk_lvl = calculate_risk(pred_label, conf_score)
        
        print(f"Prediction : {pred_label:<25} (Confidence: {conf_score:.4f})")
        print(f"Risk Score : {risk_pct:>6.2f}% [{risk_lvl}]")
        print(f"Top 3      : {top3}\n")
        
    except KeyboardInterrupt:
        print("\nExiting interactive test. Goodbye!")
        break
