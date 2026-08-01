"""
VPS Lightweight CPU Inference Service (FastAPI + PyTorch / ONNX)
Enhanced with Threat Risk Scoring & High Risk Percentage Calculation.
"""

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
import torch
from transformers import AutoTokenizer, AutoModelForSequenceClassification
import time

app = FastAPI(
    title="Cybersecurity Attack Detection API",
    description="Lightweight DistilBERT CPU inference engine with Risk Percentage Assessment",
    version="1.1.0"
)

MODEL_DIR = "./trained_model"

tokenizer = None
model = None

# Risk Severity Weight Matrix per Attack Category (0.0 to 1.0)
ATTACK_SEVERITY_WEIGHTS = {
    "RCE": 1.00,                # Critical: Remote Code Execution
    "Command_Injection": 0.98,  # Critical: OS Command Execution
    "SQL_Injection": 0.95,      # Critical: Database Compromise
    "Malware": 0.95,            # Critical: Shell / PowerShell malware
    "XXE": 0.90,                # High: XML External Entity
    "PathTraversal": 0.88,      # High: Arbitrary File Read
    "FileUpload_Attack": 0.88,  # High: Malicious Code Upload
    "NoSQL_Injection": 0.85,    # High: NoSQL Database Bypass
    "XSS": 0.80,                # High: Cross-Site Scripting
    "SSRF": 0.80,               # High: Server-Side Request Forgery
    "LDAP_Injection": 0.78,     # High: Directory Service Exploit
    "CSRF": 0.75,               # Medium-High: Cross-Site Forgery
    "BruteForce": 0.65,         # Medium: High-frequency Auth Attempt
    "CredentialStuffing": 0.65, # Medium: Account Takeover Attempt
    "DDoS": 0.60,               # Medium: Traffic Flood / Slowloris
    "Malicious_HTTP": 0.55,     # Medium: Scanner / Exploit Headers
    "Suspicious_Input": 0.50,   # Low-Medium: Anomaly Input
    "Benign": 0.00              # Safe: Legitimate Traffic
}

def calculate_risk(prediction_label: str, confidence: float):
    severity = ATTACK_SEVERITY_WEIGHTS.get(prediction_label, 0.50)
    
    if prediction_label == "Benign":
        risk_percentage = round((1.0 - confidence) * 15.0, 2)
        risk_level = "SAFE"
    else:
        # Base risk percentage calculated from Severity Weight & Model Confidence
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

@app.on_event("startup")
def load_model():
    global tokenizer, model
    print("Loading DistilBERT model into CPU memory...")
    tokenizer = AutoTokenizer.from_pretrained(MODEL_DIR)
    model = AutoModelForSequenceClassification.from_pretrained(MODEL_DIR)
    model.eval()
    
    # Apply PyTorch CPU Dynamic Quantization for fast VPS execution
    model = torch.quantization.quantize_dynamic(
        model, {torch.nn.Linear}, dtype=torch.qint8
    )
    print("Model loaded & quantized successfully!")

class PredictionRequest(BaseModel):
    text: str

class PredictionResponse(BaseModel):
    text: str
    prediction: str
    confidence: float
    high_risk_percentage: float
    risk_level: str
    is_malicious: bool
    inference_time_ms: float

@app.post("/api/v1/predict", response_model=PredictionResponse)
def predict_attack(request: PredictionRequest):
    if not request.text or not request.text.strip():
        raise HTTPException(status_code=400, detail="Input text cannot be empty.")
    
    start_time = time.time()
    
    inputs = tokenizer(
        request.text,
        return_tensors="pt",
        truncation=True,
        max_length=128,
        padding=True
    )
    
    with torch.no_grad():
        outputs = model(**inputs)
        logits = outputs.logits
        probabilities = torch.softmax(logits, dim=-1)
        confidence, predicted_class_id = torch.max(probabilities, dim=-1)
    
    predicted_label = model.config.id2label[predicted_class_id.item()]
    conf_score = round(confidence.item(), 4)
    
    risk_percentage, risk_level = calculate_risk(predicted_label, conf_score)
    is_malicious = predicted_label != "Benign"
    elapsed_ms = round((time.time() - start_time) * 1000, 2)
    
    return PredictionResponse(
        text=request.text,
        prediction=predicted_label,
        confidence=conf_score,
        high_risk_percentage=risk_percentage,
        risk_level=risk_level,
        is_malicious=is_malicious,
        inference_time_ms=elapsed_ms
    )

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
