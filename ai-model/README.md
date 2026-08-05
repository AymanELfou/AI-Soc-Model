# Enterprise VPS Security AI

An advanced AI-powered security engine based on fine-tuned DistilBERT, designed to protect entire Linux VPS servers by analyzing web traffic, system logs, SSH events, Docker activity, and shell commands in real time.

## Features

- 48 Attack Categories: 26 web attacks + 22 Linux/server attacks
- Real-time Classification: FastAPI REST API with sub-20ms inference
- Risk Scoring Engine: CRITICAL / HIGH / MEDIUM / LOW / SAFE risk levels
- Unknown Attack Detection: Auto-flags low-confidence predictions for admin review
- Safe Continual Learning: Admin-supervised retraining workflow (no auto-retrain)
- Email Alerts: SMTP notifications for unknown/critical attacks
- Weekly Reports: Automated summary of unknown attacks
- CPU Optimized: PyTorch INT8 dynamic quantization for fast VPS execution

## Supported Attack Categories

### Web Attacks (26 classes)
SQL_Injection, XSS, SSRF, XXE, LDAP_Injection, NoSQL_Injection, PathTraversal, Command_Injection, FileUpload_Attack, BruteForce, CredentialStuffing, Malware, RCE, CSRF, Malicious_HTTP, Suspicious_Input, DDoS, SSTI, CRLF_Injection, Header_Injection, GraphQL_Injection, Insecure_Deserialization, OpenRedirect, Prototype_Pollution, XPATH_Injection, Benign

### Server/Linux Attacks (22 classes)
SSH_BruteForce, SSH_Login_Attack, ReverseShell, PrivilegeEscalation, Suspicious_Bash_Command, Linux_Command_Injection, WebShell, PortScanning, Docker_Abuse, Cron_Abuse, Persistence, Malicious_System_Command, Unauthorized_File_Modification, Suspicious_Process, System_Enumeration, Kernel_Exploit, Linux_Malware, Ransomware, Cryptomining, Failed_Login, Root_Login_Attempt, Lateral_Movement

## Installation

```bash
git clone https://github.com/AymanELfou/AI-Soc-Model.git
cd AI-Soc-Model
pip install -r requirements.txt
```

## Quick Start

### 1. Generate Enterprise Dataset
```bash
python generate_enterprise_dataset.py
```
Generates `enterprise_security_dataset.csv` (34,000+ samples, 48 classes).

### 2. Train the Model (Google Colab)
Upload `train_model.ipynb` and `enterprise_security_dataset.csv` to Google Colab.
Run all cells. Download `attack_model.zip` when complete.

### 3. Deploy on VPS
```bash
# Extract model
unzip attack_model.zip -d ./trained_model/

# Start inference server
python vps_inference.py
# or
uvicorn vps_inference:app --host 0.0.0.0 --port 8000
```

### 4. Test the API
```bash
# Web attack
curl -X POST "http://localhost:8000/api/v1/predict" \
     -H "Content-Type: application/json" \
     -d '{"text": "' OR 1=1 --", "log_source": "nginx"}'

# Server attack
curl -X POST "http://localhost:8000/api/v1/analyze-log" \
     -H "Content-Type: application/json" \
     -d '{"log_line": "Failed password for root from 192.168.1.100 port 22 ssh2", "source": "auth.log"}'

# Health check
curl http://localhost:8000/api/v1/health

# Weekly report
curl http://localhost:8000/api/v1/weekly-report
```

## Log Sources Supported

The model can analyze logs from:
- Nginx / Apache access logs
- auth.log (SSH, sudo, login events)
- syslog / journalctl
- Docker logs
- Shell commands / bash history
- HTTP requests
- Auditd logs

## Risk Level Scale

| Risk Level | Percentage | Action |
|------------|-----------|--------|
| CRITICAL | >= 85% | Block + Immediate SOC Alert |
| HIGH | 65-84% | Block + Log Event |
| MEDIUM | 40-64% | Flag for Inspection |
| LOW | < 40% | Monitor |
| SAFE | ~0% | Allow Traffic |

## Safe Continual Learning

When the model encounters an unknown attack (confidence < 60%):

1. The event is saved to `unknown_attacks.csv`
2. An email alert is sent to the administrator
3. The admin reviews and labels the attack using the CLI:

```bash
# View pending unknown attacks
python continual_learning.py --show

# Approve and label
python continual_learning.py --approve <ID> SSH_BruteForce

# Reject false positive
python continual_learning.py --reject <ID>

# Export approved samples
python continual_learning.py --export

# Generate weekly report
python continual_learning.py --weekly
```

4. Upload `reviewed_unknown_attacks.csv` to Google Colab
5. Run `retrain_model.ipynb` to retrain with new data
6. Deploy the updated model

## Project Structure

```
├── generate_enterprise_dataset.py  # Dataset generator (48 classes)
├── train_model.ipynb               # Google Colab training notebook
├── retrain_model.ipynb             # Safe retraining notebook
├── vps_inference.py                # FastAPI production inference server
├── continual_learning.py           # Admin CLI for unknown attack management
├── enterprise_security_dataset.csv # Main dataset (34K+ samples)
├── enterprise_security_dataset.json
├── dataset_statistics.csv
├── requirements.txt
├── trained_model/                  # Model weights and tokenizer
└── README.md
```

## Environment Variables (Email Alerts)

```bash
export SMTP_HOST="smtp.gmail.com"
export SMTP_PORT="587"
export SMTP_USER="your-email@gmail.com"
export SMTP_PASS="your-app-password"
export ADMIN_EMAIL="admin@yourdomain.com"
```

## License

This project is for educational and cybersecurity research purposes.
