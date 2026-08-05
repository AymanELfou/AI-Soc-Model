"""
vps_inference.py
=================
Enterprise VPS Security AI — Production Inference Engine (FastAPI)

Features:
  - 48 attack categories (26 web + 22 server/Linux)
  - Risk severity scoring with percentage
  - Unknown attack detection (saves to unknown_attacks.csv)
  - Email notification for unknown/critical attacks
  - Weekly report generation
  - Health check endpoint
"""

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
import torch
from transformers import AutoTokenizer, AutoModelForSequenceClassification
import time
import os
import csv
import json
import smtplib
from email.mime.text import MIMEText
from datetime import datetime, timedelta
from typing import Optional
import pandas as pd

app = FastAPI(
    title="Enterprise VPS Security AI",
    description="DistilBERT-based attack detection engine for Linux VPS servers. Supports 48 attack categories.",
    version="2.0.0"
)

# ════════════════════════════════════════════════════════
#  CONFIGURATION
# ════════════════════════════════════════════════════════
MODEL_DIR = "./trained_model"
UNKNOWN_ATTACKS_PATH = "./unknown_attacks.csv"
CONFIDENCE_THRESHOLD = 0.60  # Below this = unknown/uncertain attack

# Email config (set via environment variables)
SMTP_HOST     = os.getenv("SMTP_HOST", "")
SMTP_PORT     = int(os.getenv("SMTP_PORT", "587"))
SMTP_USER     = os.getenv("SMTP_USER", "")
SMTP_PASS     = os.getenv("SMTP_PASS", "")
ADMIN_EMAIL   = os.getenv("ADMIN_EMAIL", "")
EMAIL_ENABLED = bool(SMTP_HOST and SMTP_USER and ADMIN_EMAIL)

tokenizer = None
model = None

# ════════════════════════════════════════════════════════
#  RISK SEVERITY WEIGHTS (48 CLASSES)
# ════════════════════════════════════════════════════════
ATTACK_SEVERITY_WEIGHTS = {
    # === CRITICAL (0.90 - 1.00) ===
    "RCE":                          1.00,
    "ReverseShell":                 1.00,
    "Kernel_Exploit":               0.98,
    "Command_Injection":            0.98,
    "Linux_Command_Injection":      0.98,
    "Malicious_System_Command":     0.97,
    "PrivilegeEscalation":          0.96,
    "SQL_Injection":                0.95,
    "Malware":                      0.95,
    "Linux_Malware":                0.95,
    "Ransomware":                   0.95,
    "WebShell":                     0.94,
    "Docker_Abuse":                 0.93,
    "Persistence":                  0.92,
    "XXE":                          0.90,
    "Insecure_Deserialization":     0.90,

    # === HIGH (0.75 - 0.89) ===
    "PathTraversal":                0.88,
    "FileUpload_Attack":            0.88,
    "XPATH_Injection":              0.88,
    "SSTI":                         0.87,
    "Lateral_Movement":             0.87,
    "NoSQL_Injection":              0.85,
    "Cron_Abuse":                   0.85,
    "Unauthorized_File_Modification": 0.84,
    "Root_Login_Attempt":           0.82,
    "Cryptomining":                 0.80,
    "XSS":                          0.80,
    "SSRF":                         0.80,
    "GraphQL_Injection":            0.80,
    "Prototype_Pollution":          0.78,
    "LDAP_Injection":               0.78,
    "System_Enumeration":           0.76,
    "CSRF":                         0.75,
    "OpenRedirect":                 0.75,

    # === MEDIUM (0.55 - 0.74) ===
    "Header_Injection":             0.72,
    "CRLF_Injection":               0.70,
    "Suspicious_Bash_Command":      0.70,
    "Suspicious_Process":           0.68,
    "SSH_BruteForce":               0.65,
    "BruteForce":                   0.65,
    "CredentialStuffing":           0.65,
    "SSH_Login_Attack":             0.63,
    "PortScanning":                 0.60,
    "DDoS":                         0.60,
    "Failed_Login":                 0.55,
    "Malicious_HTTP":               0.55,

    # === LOW ===
    "Suspicious_Input":             0.50,
    "Benign":                       0.00,
}


# ════════════════════════════════════════════════════════
#  RISK CALCULATION
# ════════════════════════════════════════════════════════
def calculate_risk(prediction_label: str, confidence: float):
    severity = ATTACK_SEVERITY_WEIGHTS.get(prediction_label, 0.50)

    if prediction_label == "Benign":
        risk_percentage = round((1.0 - confidence) * 15.0, 2)
        risk_level = "SAFE"
    else:
        raw_risk = (confidence * 0.70 + severity * 0.30) * 100.0
        risk_percentage = round(min(raw_risk, 99.99), 2)

        if risk_percentage >= 85.0:
            risk_level = "CRITICAL"
        elif risk_percentage >= 65.0:
            risk_level = "HIGH"
        elif risk_percentage >= 40.0:
            risk_level = "MEDIUM"
        else:
            risk_level = "LOW"

    return risk_percentage, risk_level


# ════════════════════════════════════════════════════════
#  UNKNOWN ATTACK LOGGING
# ════════════════════════════════════════════════════════
def log_unknown_attack(text: str, prediction: str, confidence: float, log_source: str = "api"):
    """Save low-confidence predictions to unknown_attacks.csv for admin review."""
    file_exists = os.path.exists(UNKNOWN_ATTACKS_PATH)
    row = {
        "id": datetime.now().strftime("%Y%m%d%H%M%S%f"),
        "timestamp": datetime.now().isoformat(),
        "raw_log": text,
        "predicted_label": prediction,
        "confidence": round(confidence, 4),
        "log_source": log_source,
        "status": "pending",
        "reviewed_label": "",
    }

    with open(UNKNOWN_ATTACKS_PATH, "a", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=row.keys())
        if not file_exists:
            writer.writeheader()
        writer.writerow(row)

    return row["id"]


# ════════════════════════════════════════════════════════
#  EMAIL NOTIFICATION
# ════════════════════════════════════════════════════════
def send_email_alert(subject: str, body: str):
    """Send email notification to admin."""
    if not EMAIL_ENABLED:
        return False
    try:
        msg = MIMEText(body, "plain")
        msg["Subject"] = subject
        msg["From"] = SMTP_USER
        msg["To"] = ADMIN_EMAIL

        with smtplib.SMTP(SMTP_HOST, SMTP_PORT) as server:
            server.starttls()
            server.login(SMTP_USER, SMTP_PASS)
            server.send_message(msg)
        return True
    except Exception:
        return False


# ════════════════════════════════════════════════════════
#  MODEL LOADING
# ════════════════════════════════════════════════════════
@app.on_event("startup")
def load_model():
    global tokenizer, model
    print("Loading Enterprise VPS Security AI model...")
    tokenizer = AutoTokenizer.from_pretrained(MODEL_DIR)
    model = AutoModelForSequenceClassification.from_pretrained(MODEL_DIR)
    model.eval()

    # CPU quantization for fast VPS inference
    model_q = torch.quantization.quantize_dynamic(
        model, {torch.nn.Linear}, dtype=torch.qint8
    )
    # Replace global reference
    globals()["model"] = model_q

    num_labels = model.config.num_labels
    print(f"Model loaded: {num_labels} classes, quantized for CPU")


# ════════════════════════════════════════════════════════
#  API SCHEMAS
# ════════════════════════════════════════════════════════
class PredictionRequest(BaseModel):
    text: str
    log_source: Optional[str] = "api"

class PredictionResponse(BaseModel):
    text: str
    prediction: str
    confidence: float
    high_risk_percentage: float
    risk_level: str
    is_malicious: bool
    is_unknown: bool
    inference_time_ms: float

class LogAnalysisRequest(BaseModel):
    log_line: str
    source: Optional[str] = "unknown"

class WeeklyReportResponse(BaseModel):
    total_unknown: int
    pending_review: int
    top_predicted_labels: dict
    period: str


# ════════════════════════════════════════════════════════
#  API ENDPOINTS
# ════════════════════════════════════════════════════════

@app.post("/api/v1/predict", response_model=PredictionResponse)
def predict_attack(request: PredictionRequest):
    """Classify an incoming request/payload/log line."""
    if not request.text or not request.text.strip():
        raise HTTPException(status_code=400, detail="Input text cannot be empty.")

    start_time = time.time()

    inputs = tokenizer(
        request.text, return_tensors="pt", truncation=True, max_length=256, padding=True
    )

    with torch.no_grad():
        outputs = model(**inputs)
        probabilities = torch.softmax(outputs.logits, dim=-1)
        confidence, predicted_class_id = torch.max(probabilities, dim=-1)

    predicted_label = model.config.id2label[predicted_class_id.item()]
    conf_score = round(confidence.item(), 4)
    risk_percentage, risk_level = calculate_risk(predicted_label, conf_score)
    is_malicious = predicted_label != "Benign"
    is_unknown = conf_score < CONFIDENCE_THRESHOLD and is_malicious
    elapsed_ms = round((time.time() - start_time) * 1000, 2)

    # Log unknown attacks
    if is_unknown:
        attack_id = log_unknown_attack(request.text, predicted_label, conf_score, request.log_source)
        # Send email alert
        send_email_alert(
            subject=f"[VPS AI] Unknown Attack Detected - {predicted_label} ({conf_score:.2%})",
            body=f"Unknown/low-confidence attack detected:\n\n"
                 f"Payload: {request.text[:500]}\n"
                 f"Prediction: {predicted_label}\n"
                 f"Confidence: {conf_score:.4f}\n"
                 f"Risk Level: {risk_level}\n"
                 f"Log Source: {request.log_source}\n"
                 f"ID: {attack_id}\n"
                 f"Timestamp: {datetime.now().isoformat()}\n\n"
                 f"Review and label this attack in the admin console."
        )

    return PredictionResponse(
        text=request.text,
        prediction=predicted_label,
        confidence=conf_score,
        high_risk_percentage=risk_percentage,
        risk_level=risk_level,
        is_malicious=is_malicious,
        is_unknown=is_unknown,
        inference_time_ms=elapsed_ms
    )


@app.post("/api/v1/analyze-log", response_model=PredictionResponse)
def analyze_log(request: LogAnalysisRequest):
    """Analyze a raw log line (auth.log, syslog, nginx, etc.)."""
    return predict_attack(PredictionRequest(text=request.log_line, log_source=request.source))


@app.get("/api/v1/weekly-report", response_model=WeeklyReportResponse)
def weekly_report():
    """Generate a weekly summary of unknown attacks."""
    if not os.path.exists(UNKNOWN_ATTACKS_PATH):
        return WeeklyReportResponse(
            total_unknown=0, pending_review=0, top_predicted_labels={},
            period=f"{(datetime.now() - timedelta(days=7)).strftime('%Y-%m-%d')} to {datetime.now().strftime('%Y-%m-%d')}"
        )

    df = pd.read_csv(UNKNOWN_ATTACKS_PATH)
    # Filter last 7 days
    df["timestamp"] = pd.to_datetime(df["timestamp"])
    week_ago = datetime.now() - timedelta(days=7)
    df_week = df[df["timestamp"] >= week_ago]

    pending = len(df_week[df_week["status"] == "pending"])
    top_labels = df_week["predicted_label"].value_counts().head(10).to_dict()

    return WeeklyReportResponse(
        total_unknown=len(df_week),
        pending_review=pending,
        top_predicted_labels=top_labels,
        period=f"{week_ago.strftime('%Y-%m-%d')} to {datetime.now().strftime('%Y-%m-%d')}"
    )


@app.get("/api/v1/health")
def health_check():
    """Health check endpoint."""
    return {
        "status": "healthy",
        "model_loaded": model is not None,
        "num_classes": model.config.num_labels if model else 0,
        "timestamp": datetime.now().isoformat(),
        "version": "2.0.0"
    }


@app.get("/api/v1/labels")
def get_labels():
    """Return all supported attack labels."""
    if model is None:
        raise HTTPException(status_code=503, detail="Model not loaded.")
    return {
        "labels": list(model.config.id2label.values()),
        "count": model.config.num_labels
    }


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
