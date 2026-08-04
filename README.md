# 🛡️ AI SOC Model: Multi-Class Cybersecurity Attack Classifier

An advanced AI-powered web attack classifier based on fine-tuned **DistilBERT**. This model is designed for Next-Gen SOC (Security Operations Center) platforms to inspect incoming web traffic payloads, classify threat categories in real time, and calculate threat severity risk percentages.

---

## 🌟 Features

- **26 Attack Categories Supported**: SQL Injection, XSS, Path Traversal, SSRF, Command Injection, XXE, LDAP Injection, NoSQL Injection, File Upload Attacks, Brute Force, Credential Stuffing, CSRF, RCE, Malware, and Benign traffic.
- **Fast Execution**: Optimized for CPU/VPS inference with PyTorch dynamic quantization.
- **Interactive CLI Testing**: Interactively test unseen attack strings or pull random samples from test datasets.
- **Evaluation Suite**: Automated generation of 3,000+ unseen test samples to measure Accuracy, Precision, Recall, F1-Score, and Confusion Matrix.
- **REST API Endpoint**: FastAPI server ready to be integrated into any SOC pipeline or web firewall.

---

## 📁 Repository Structure

```
├── train_model.py                  # Standalone training script for DistilBERT
├── test_model.py                   # Quick test script for verifying model predictions
├── interactive_test.py             # Interactive CLI tool for manual payload testing
├── generate_test_dataset.py        # Generates unseen synthetic test payloads
├── evaluate_model.py               # Complete evaluation suite (Accuracy, Precision, Recall, F1)
├── vps_inference.py                # FastAPI REST API service with Risk Engine
├── cybersecurity_attack_classifier.ipynb  # Google Colab / Jupyter notebook for GPU training
└── README.md                       # Documentation
```

---

## ⚙️ Installation & Setup

### 1. Clone the Repository
```bash
git clone https://github.com/AymanELfou/AI-Soc-Model.git
cd AI-Soc-Model
```

### 2. Install Dependencies
Make sure you have Python 3.8+ installed. Install the required dependencies:
```bash
pip install torch transformers pandas scikit-learn fastapi uvicorn pydantic accelerate
```

---

## 🚀 How to Run & Test

### 1. Quick Model Test
To quickly verify that the trained model is loaded and working correctly:
```bash
python test_model.py
```

### 2. Interactive Manual Payload Tester
Run the interactive CLI tester to test your own custom attack strings or pull random samples from the test dataset:
```bash
python interactive_test.py
```
- Press **[ENTER]** to test a random payload from `test_dataset.csv`.
- Type any custom string (e.g. `<script>alert('test')</script>`) to evaluate it.
- Type `quit` or `exit` to exit.

### 3. Generate Test Dataset & Full Evaluation
To generate 3,300+ unseen synthetic test payloads and evaluate the model's accuracy, precision, recall, and F1-score:

```bash
# 1. Generate unseen test payloads
python generate_test_dataset.py

# 2. Evaluate model performance
python evaluate_model.py
```
Outputs generated:
- `predictions.csv`: Detailed model outputs and confidence scores.
- `misclassified_samples.csv`: List of misclassified samples for debugging.

---

## 🏋️ Model Training

To retrain or fine-tune the model locally on your dataset (`balanced_attack_dataset.csv`):
```bash
python train_model.py
```
> **Note for Google Colab Users**: Use `cybersecurity_attack_classifier.ipynb` on Google Colab with a T4 GPU for faster training (~10 minutes).

---

## 🌐 Deploying VPS REST API Server

To start the FastAPI REST server for live integration with your SOC platform or web firewall:

```bash
python vps_inference.py
```
or using Uvicorn:
```bash
uvicorn vps_inference:app --host 0.0.0.0 --port 8000
```

### Example API Request (cURL)
```bash
curl -X POST "http://localhost:8000/predict" \
     -H "Content-Content-Type: application/json" \
     -d '{"text": "' OR 1=1 --"}'
```

### Example API Response
```json
{
  "label": "SQL_Injection",
  "confidence": 0.9965,
  "high_risk_percentage": 99.76,
  "risk_level": "CRITICAL",
  "is_malicious": true,
  "inference_time_ms": 12.45
}
```

---

## 📊 Threat Risk Level Scale

| Risk Level | Risk Percentage | Action / Mitigation |
|------------|-----------------|---------------------|
| **CRITICAL** | ≥ 85.0% | Block Request & Trigger Immediate SOC Alert |
| **HIGH** | 65.0% - 84.9% | Block Request & Log Event |
| **MEDIUM** | 40.0% - 64.9% | Flag for Inspection / CAPTCHA |
| **LOW** / **SAFE** | < 40.0% | Allow Traffic |

---

## 📄 License
This project is for educational and cybersecurity research purposes.
---

## Continual Learning: Detecting and Learning New Attacks

The AI SOC Model includes a Continual Learning system (continual_learning.py) that automatically detects new or unknown attacks, flags them for human review, and retrains the model to stay up-to-date.

### How It Works
1. Unknown Attack Detection: When confidence is below 0.75, the payload is flagged and saved to pending_review.csv.
2. Human Labeling: A security expert labels the unknown samples.
3. Auto-Retraining: Once >= 50 new samples are labeled, the model retrains and integrates them.

### Commands

#### Test a payload:
```bash
python continual_learning.py --predict 'SUSPICIOUS PAYLOAD'
```n
#### View pending attacks:
```bash
python continual_learning.py --show-pending
```n
#### Label an attack:
```bash
python continual_learning.py --label <ID> <LABEL>
```n
#### Retrain with new data:
```bash
python continual_learning.py --retrain
```n
#### View retraining history:
```bash
python continual_learning.py --status
```n
---

## License
This project is for educational and cybersecurity research purposes.

