# 🛡️ Enterprise VPS Security AI & Autonomous Security Agent

An enterprise-grade, end-to-end AI SOC Security Solution for Linux VPS servers. This project combines a fine-tuned Hugging Face **DistilBERT** transformer model capable of classifying **48 categories of Web and Linux Server attacks** with an autonomous **Real-Time AI Security Agent** that continuously monitors VPS logs, evaluates threat risks, logs incidents to SQLite, and sends automated HTML email alerts to administrators.

---

## 📌 Project Architecture & Workflow

```
[ Linux Server Logs ] ---> (/var/log/auth.log, syslog, Nginx, Apache, Docker, Fail2ban)
         │
         ▼
[ Log Monitor (monitor.py) ] ---> Non-blocking tail -F seek stream
         │
         ▼
[ Noise Filter (log_parser.py) ] ---> Filters systemd/cron noise & extracts clean payload
         │
         ▼
[ AI Predictor (predictor.py) ] ---> Single-load DistilBERT INT8 CPU Quantized Model (48 Classes)
         │
         ▼
[ Risk Engine (risk_engine.py) ] ---> Calculates Risk Level (SAFE, LOW, MEDIUM, HIGH, CRITICAL)
         │
         ├───> [ SQLite Storage (database.py) ] ---> Persists to database/incidents.db
         │
         └───> [ Email Alert (email_service.py) ] ---> Sends HTML report if Risk == HIGH or CRITICAL
```

---

## 📂 Repository Structure & Folder Explanation

The repository is organized into two main dedicated components:

```
AI-Soc-Model/
├── ai-model/                     # AI Model Training, Dataset Generation & Evaluation
│   ├── generate_enterprise_dataset.py # Synthesizes 34,231 samples across 48 attack categories
│   ├── train_model.ipynb         # Universal training notebook (Kaggle / Google Colab / Local GPU)
│   ├── retrain_model.ipynb       # Safe continual learning retraining notebook
│   ├── evaluate_model.py         # Full evaluation suite (Accuracy, Precision, Recall, F1, Confusion Matrix)
│   ├── vps_inference.py          # Standalone FastAPI inference server
│   ├── continual_learning.py     # Admin-supervised feedback loop CLI for unknown attack payloads
│   ├── interactive_test.py       # Interactive CLI test script with mixed attack payloads
│   ├── test_model.py             # Validation test script across all 48 classes
│   └── trained_model/            # Model weights and tokenizer artifacts
│
├── ai-security-agent/            # Autonomous Production AI Security Agent Daemon
│   ├── app/
│   │   ├── __init__.py           # Package initialization
│   │   ├── main.py               # Main entrypoint & REST API server (FastAPI)
│   │   ├── config.py             # Centralized configuration & environment settings
│   │   ├── predictor.py          # DistilBERT model loader & inference engine (Loaded ONCE)
│   │   ├── monitor.py            # Non-blocking real-time log tailer (tail -F behavior)
│   │   ├── log_parser.py         # Noise filter and clean payload extractor
│   │   ├── risk_engine.py        # 5-tier risk severity calculator (SAFE to CRITICAL)
│   │   ├── email_service.py      # HTML email alert service with anti-spam deduplication
│   │   ├── database.py           # SQLite incident database manager (incidents.db)
│   │   ├── logger.py             # Structured application logger (logs/agent.log)
│   │   ├── scheduler.py          # Background maintenance & hourly reporting tasks
│   │   ├── health.py             # Diagnostic health checker (Model, Logs, DB, SMTP, CPU/RAM)
│   │   └── utils.py              # Actionable remediation steps & sanitization helpers
│   ├── trained_model/            # Local pre-trained model weights for the agent
│   ├── logs/                     # Operational agent log files
│   ├── database/                 # SQLite incidents database storage
│   ├── ai-security-agent.service # Systemd service unit for VPS auto-boot startup
│   ├── Dockerfile                # Production container image definition
│   ├── docker-compose.yml        # Docker Compose orchestration definition
│   ├── test_logs.py              # Automated test script sending 3 sample attack logs to agent
│   └── requirements.txt          # Python dependencies
│
├── .gitignore                    # Global git ignore configuration
└── README.md                     # Project documentation
```

---

## 🤖 How the AI Model Works

The core detection engine is based on `distilbert-base-uncased`, fine-tuned for multi-class sequence classification across **48 distinct categories**:

### Supported Attack Classes (48 Total):
- **26 Web Attack Categories**: `SQL_Injection`, `XSS`, `SSRF`, `XXE`, `NoSQL_Injection`, `PathTraversal`, `Command_Injection`, `FileUpload_Attack`, `BruteForce`, `CredentialStuffing`, `Malware`, `RCE`, `CSRF`, `Malicious_HTTP`, `Suspicious_Input`, `DDoS`, `SSTI`, `CRLF_Injection`, `Header_Injection`, `GraphQL_Injection`, `Insecure_Deserialization`, `OpenRedirect`, `Prototype_Pollution`, `XPATH_Injection`, `LDAP_Injection`, `Benign`.
- **22 Linux/Server Attack Categories**: `SSH_BruteForce`, `SSH_Login_Attack`, `ReverseShell`, `PrivilegeEscalation`, `Suspicious_Bash_Command`, `Linux_Command_Injection`, `WebShell`, `PortScanning`, `Docker_Abuse`, `Cron_Abuse`, `Persistence`, `Malicious_System_Command`, `Unauthorized_File_Modification`, `Suspicious_Process`, `System_Enumeration`, `Kernel_Exploit`, `Linux_Malware`, `Ransomware`, `Cryptomining`, `Failed_Login`, `Root_Login_Attempt`, `Lateral_Movement`.

### Single-Load & INT8 CPU Quantization Architecture:
- **Zero Reload Overhead**: `app/predictor.py` loads the model weights into memory **once** on application startup.
- **CPU Optimization**: Automatically applies PyTorch **INT8 Dynamic Quantization** (`torch.quantization.quantize_dynamic`) on CPU, keeping RAM footprint under **300 MB** and inference latency under **20 ms** per log line.

---

## 🚀 How to Pull, Run, and Deploy

### 1. Pulling / Cloning the Repository

```bash
git clone https://github.com/AymanELfou/AI-Soc-Model.git
cd AI-Soc-Model
```

---

### 2. Running the AI Security Agent (Python)

```bash
cd ai-security-agent

# Install dependencies
pip install -r requirements.txt

# Start the agent
python -m app.main
```

---

### 3. Deploying as a Linux Systemd Service (Auto-Boot on VPS Restart)

To run the agent continuously in the background and ensure it automatically restarts on server reboot:

```bash
# 1. Copy service file to systemd directory
sudo cp ai-security-agent/ai-security-agent.service /etc/systemd/system/

# 2. Reload systemd daemon
sudo systemctl daemon-reload

# 3. Enable and start the service
sudo systemctl enable ai-security-agent
sudo systemctl start ai-security-agent

# 4. Check service status & live logs
sudo systemctl status ai-security-agent
sudo journalctl -u ai-security-agent -f
```

---

### 4. Deploying with Docker Compose

```bash
cd ai-security-agent

# Build and start container in detached mode
docker-compose up -d --build

# Check logs
docker-compose logs -f
```

---

### 5. Testing the Agent with Sample Logs

While the agent is running on `http://localhost:8000`, test it by sending sample logs:

#### Option A: Run the test script
```bash
python ai-security-agent/test_logs.py
```

#### Option B: Send cURL requests directly
```bash
# Test SSH Brute Force
curl -X POST "http://localhost:8000/api/v1/analyze" \
     -H "Content-Type: application/json" \
     -d '{"log_line": "Aug 06 14:30:00 server sshd[1234]: Failed password for root from 192.168.1.100 port 54321 ssh2", "source_log": "/var/log/auth.log"}'

# Test Docker Abuse
curl -X POST "http://localhost:8000/api/v1/analyze" \
     -H "Content-Type: application/json" \
     -d '{"log_line": "Aug 06 15:35:00 server dockerd[8888]: docker run -v /:/mnt --rm -it alpine chroot /mnt sh", "source_log": "/var/log/syslog"}'
```

---

### 6. Working with the AI Model Training (`ai-model/`)

To generate datasets or train/retrain the model:

```bash
cd ai-model

# Generate enterprise dataset (34,231 samples across 48 classes)
python generate_enterprise_dataset.py

# Evaluate trained model
python evaluate_model.py
```

For GPU fine-tuning, upload `ai-model/train_model.ipynb` and `enterprise_security_dataset.csv` to **Kaggle Notebooks** or **Google Colab**.

---

## 📄 License

This project is developed for cybersecurity research, SOC automation, and enterprise VPS defense.
