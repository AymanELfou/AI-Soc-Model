# 🛡️ Enterprise VPS Security AI & Autonomous Security Agent

An enterprise-grade, end-to-end AI SOC Security Solution for Linux VPS servers. This project combines a fine-tuned Hugging Face **DistilBERT** transformer model (48 attack classes) with an autonomous **Real-Time AI Security Agent** that continuously monitors VPS logs, detects **DDoS traffic anomalies**, monitors **host CPU/RAM/Disk resources**, coordinates alerts through a **Centralized Alert Manager**, persists events to SQLite, and delivers automated HTML email notifications to server administrators.

---

## 📌 Extended System Architecture

```
                    VPS Server
                        │
       ┌────────────────┼────────────────┐
       ▼                ▼                ▼
  System Logs       Resources         Network
 (/var/log)       (CPU, RAM, Disk)  (HTTP Traffic)
       │                │                │
       ▼                ▼                ▼
   Log Parser       Resource        DDoS Traffic
  (log_parser)       Monitor          Detector
       │          (resource_mon)    (ddos_detector)
       │                │                │
       └────────────────┼────────────────┘
                        │
                        ▼
                AI Security Agent
                        │
             ┌──────────┼──────────┐
             ▼          ▼          ▼
         AI Model  Risk Engine   Health
        (DistilBERT) (risk_engine) (health)
             │          │          │
             └──────────┼──────────┘
                        │
                        ▼
                 Alert Manager
                (alert_manager)
                        │
                        ▼
                  Email Service
                 (email_service)
                        │
                        ▼
                   ADMIN EMAIL
```

---

## 📁 Repository Structure

```
AI-Soc-Model/
├── ai-model/                     # AI Model Training, Dataset Generation & Evaluation
│   ├── generate_enterprise_dataset.py # Synthesizes 34,231 samples across 48 attack categories
│   ├── train_model.ipynb         # Universal training notebook (Kaggle / Google Colab / Local GPU)
│   ├── retrain_model.ipynb       # Safe continual learning retraining notebook
│   ├── evaluate_model.py         # Full evaluation suite (Accuracy, Precision, Recall, F1)
│   ├── vps_inference.py          # Standalone FastAPI inference server
│   ├── continual_learning.py     # Admin-supervised feedback loop CLI
│   └── trained_model/            # Model weights and tokenizer artifacts
│
├── ai-security-agent/            # Autonomous Production AI Security Agent Daemon
│   ├── app/
│   │   ├── __init__.py           # Package initialization
│   │   ├── main.py               # Main entrypoint & REST API server (FastAPI)
│   │   ├── config.py             # Centralized configuration & environment settings
│   │   ├── predictor.py          # DistilBERT model loader (Loaded ONCE)
│   │   ├── monitor.py            # Non-blocking real-time log tailer
│   │   ├── log_parser.py         # Noise filter and clean payload extractor
│   │   ├── ddos_detector.py      # Real-time traffic volume & DDoS anomaly detector
│   │   ├── resource_monitor.py   # VPS CPU, RAM, Disk, System Load, Network monitor
│   │   ├── alert_manager.py      # Centralized alert coordinator & cooldown manager
│   │   ├── risk_engine.py        # 5-tier risk severity calculator (SAFE to CRITICAL)
│   │   ├── email_service.py      # HTML email alert service with anti-spam deduplication
│   │   ├── database.py           # SQLite database manager (incidents.db)
│   │   ├── logger.py             # Structured logger (logs to stdout & logs/agent.log)
│   │   ├── scheduler.py          # Periodic resource check & heartbeat tasks
│   │   ├── health.py             # Diagnostic health checker & resource metrics
│   │   └── utils.py              # Actionable remediation steps & sanitization helpers
│   ├── trained_model/            # Local pre-trained model weights for the agent
│   ├── logs/                     # Operational agent log files
│   ├── database/                 # SQLite incidents database storage
│   ├── ai-security-agent.service # Systemd service unit for VPS auto-boot startup
│   ├── Dockerfile                # Production container image definition
│   ├── docker-compose.yml        # Docker Compose orchestration definition
│   ├── test_ddos.py              # Unit tests for DDoS traffic detector
│   ├── test_resources.py         # Unit tests for resource monitor
│   ├── test_alerts.py            # Unit tests for AlertManager & cooldown
│   ├── test_health.py           # Unit tests for health endpoints
│   ├── test_logs.py              # End-to-end integration test script
│   └── requirements.txt          # Python dependencies
│
├── .gitignore                    # Global git ignore configuration
└── README.md                     # Project documentation
```

---

## 🧪 Running Unit & Integration Tests

```bash
cd ai-security-agent

# Run DDoS Traffic Detector Unit Tests
python test_ddos.py

# Run VPS Resource Monitor Unit Tests
python test_resources.py

# Run Central Alert Manager Unit Tests
python test_alerts.py

# Run Health Check & Heartbeat Unit Tests
python test_health.py

# Run Integration Log Test
python test_logs.py
```

---

## 🌐 Health Endpoint Response (`GET /health`)

```json
{
  "status": "healthy",
  "agent": "running",
  "model": "loaded",
  "database": "connected",
  "log_monitor": "running",
  "last_heartbeat": "2026-08-07 18:15:00",
  "hostname": "vps-prod-01",
  "uptime": 12345,
  "cpu": 12.5,
  "ram": 42.1,
  "disk": 55.8
}
```

---

## 🚀 Deployment Options

### Systemd Auto-Boot Service:
```bash
sudo cp ai-security-agent/ai-security-agent.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable ai-security-agent
sudo systemctl start ai-security-agent
```

### Docker Compose Container:
```bash
cd ai-security-agent
docker-compose up -d --build
```

---

## 🔄 Continual Learning & Admin Authorization Commands

The project includes an admin-supervised feedback loop CLI (`continual_learning.py`) to manage unknown zero-day attacks and maintain model accuracy:

```bash
cd ai-model

# 1. Predict & Flag Unknown Payloads
python continual_learning.py --predict "GET /api/v1/k8s/exec?cmd=kubectl..."

# 2. Show Pending Unknown Attacks Requiring Admin Review
python continual_learning.py --show

# 3. Admin Authorization / Approval Command (Label new attack type)
python continual_learning.py --approve <ATTACK_ID> "<LABEL_NAME>"
# Example:
python continual_learning.py --approve 20260815121041234152 "Kubernetes_Token_Theft"

# 4. Admin Rejection Command (Reject false positive logs)
python continual_learning.py --reject <ATTACK_ID>

# 5. Export Approved Samples for Model Retraining
python continual_learning.py --export

# 6. View Model & Dataset Statistics
python continual_learning.py --stats
```
