# 🛡️ Autonomous AI Security Agent for Linux VPS Servers

An enterprise-grade, autonomous real-time AI Security Agent designed to protect entire Linux VPS servers. Powered by a fine-tuned Hugging Face **DistilBERT** multi-class model capable of detecting and classifying **48 categories of Web and Linux System attacks**.

---

## 📁 Project Structure & File Explanation

```
AI-Security-Agent/
├── app/
│   ├── __init__.py         # Package initialization
│   ├── main.py             # Application entrypoint & REST API server
│   ├── config.py           # Centralized configuration & environment variables
│   ├── predictor.py        # Hugging Face DistilBERT inference engine (loaded ONCE)
│   ├── monitor.py          # Real-time non-blocking tailing monitor for log sources
│   ├── log_parser.py       # Noise filter and clean payload extractor
│   ├── risk_engine.py      # Centralized risk severity calculator (5 levels)
│   ├── email_service.py    # HTML email alerts with anti-spam deduplication
│   ├── database.py         # SQLite manager for incidents and statistics
│   ├── logger.py           # Structured application logger (logs/agent.log)
│   ├── scheduler.py        # Background task scheduler & periodic reporting
│   ├── health.py           # Diagnostic health checker & resource metrics
│   └── utils.py            # Remediation recommendations & text sanitization
├── trained_model/          # Pre-trained DistilBERT model & tokenizer files
│   ├── config.json
│   ├── label_mapping.json
│   ├── model.safetensors
│   ├── tokenizer.json
│   └── tokenizer_config.json
├── logs/                   # Agent operational logs (logs/agent.log)
├── database/               # SQLite incidents database (database/incidents.db)
├── ai-security-agent.service # Systemd service unit file for VPS startup
├── requirements.txt        # Python package dependencies
├── Dockerfile              # Production Docker build specification
├── docker-compose.yml      # Docker Compose orchestration
└── README.md               # Enterprise documentation
```

---

## ⚙️ 1. Linux Permissions & Setup

To read sensitive Linux log files (`/var/log/auth.log`, `/var/log/syslog`, `/var/log/audit/audit.log`), the AI Security Agent process requires elevated read permissions.

### Granting Log Read Access:
```bash
# Add application user to the 'adm' and 'systemd-journal' groups:
sudo usermod -aG adm $USER
sudo usermod -aG systemd-journal $USER

# Set readable permissions on log files if needed:
sudo chmod 644 /var/log/auth.log /var/log/syslog
```

---

## 🐍 2. Python Setup & Manual Execution

### Step 1: Create Virtual Environment
```bash
cd ai-security-agent
python3 -m venv venv
source venv/bin/activate
```

### Step 2: Install Dependencies
```bash
pip install --upgrade pip
pip install -r requirements.txt
```

### Step 3: Configure Environment Variables (Optional)
```bash
export SERVER_HOSTNAME="vps-prod-01"
export CONFIDENCE_THRESHOLD="0.55"
export SMTP_HOST="smtp.gmail.com"
export SMTP_PORT="587"
export SMTP_USER="your-email@gmail.com"
export SMTP_PASS="your-app-password"
export ADMIN_EMAIL="admin@yourdomain.com"
export EMAIL_ENABLED="true"
```

### Step 4: Run Manually
```bash
python -m app.main
```
Or start with Uvicorn:
```bash
uvicorn app.main:app --host 0.0.0.0 --port 8000
```

---

## 🐳 3. Docker & Docker Compose Deployment

Deploy the AI Security Agent as an isolated, containerized daemon:

### Build and Start with Docker Compose:
```bash
docker-compose up -d --build
```

### Check Logs & Status:
```bash
# Check container status
docker-compose ps

# View live container logs
docker-compose logs -f
```

---

## ⚙️ 4. Systemd Setup (Automatic VPS Reboot Startup)

To ensure the AI Security Agent automatically starts whenever the Linux VPS boots up:

### Step 1: Copy Service File
```bash
sudo cp ai-security-agent.service /etc/systemd/system/
```

### Step 2: Edit Service Paths & SMTP Settings
```bash
sudo nano /etc/systemd/system/ai-security-agent.service
```
Update `WorkingDirectory`, `ExecStart`, and SMTP environment variables.

### Step 3: Enable and Start Service
```bash
sudo systemctl daemon-reload
sudo systemctl enable ai-security-agent
sudo systemctl start ai-security-agent
```

### Step 4: Check Service Status
```bash
sudo systemctl status ai-security-agent
sudo journalctl -u ai-security-agent -f
```

---

## 📧 5. SMTP Email Configuration

The agent uses a built-in anti-spam deduplication engine. Alerts are triggered only for `HIGH` or `CRITICAL` risk incidents. Duplicate alerts for the same attack pattern on the same log source within 15 minutes are suppressed.

To enable Gmail SMTP:
1. Enable 2-Factor Authentication on your Google Account.
2. Generate an **App Password** at https://myaccount.google.com/apppasswords.
3. Set the environment variables:
   - `SMTP_HOST=smtp.gmail.com`
   - `SMTP_PORT=587`
   - `SMTP_USER=your-email@gmail.com`
   - `SMTP_PASS=xxxx-xxxx-xxxx-xxxx`
   - `ADMIN_EMAIL=admin@yourdomain.com`
   - `EMAIL_ENABLED=true`

---

## 🌐 6. REST API Endpoints & Health Check

| Endpoint | Method | Description |
|---|---|---|
| `GET /api/v1/health` | GET | Comprehensive Health Check (Model Loaded, Logs Connected, DB Connected, SMTP Connected) |
| `POST /api/v1/analyze` | POST | Manually analyze a custom log line or payload |
| `GET /api/v1/incidents` | GET | Retrieve recent attack incidents with optional `min_risk` filter |
| `GET /api/v1/stats` | GET | Retrieve aggregated incident counts and risk breakdown |

### Health Check Example (`curl http://localhost:8000/api/v1/health`):
```json
{
  "status": "HEALTHY",
  "summary": {
    "Model Loaded": true,
    "Logs Connected": true,
    "Database Connected": true,
    "SMTP Connected": true
  },
  "system": {
    "hostname": "vps-production-01",
    "cpu": { "percent_used": 2.5, "cores": 4 },
    "memory": { "total_mb": 8192, "used_mb": 1250, "percent_used": 15.2 }
  }
}
```

---

## 🔧 7. Troubleshooting

### Issue 1: `PermissionDenied` reading `/var/log/auth.log`
- **Cause**: The user running the script does not have read access to system log files.
- **Fix**: Run `sudo usermod -aG adm $USER` or execute the service under `root` / `adm` group.

### Issue 2: `SMTPAuthenticationError`
- **Cause**: Incorrect SMTP username/password or App Password not configured.
- **Fix**: Verify `SMTP_USER` and `SMTP_PASS`. For Gmail, ensure you use an App Password, not your standard login password.

### Issue 3: `Model directory not found at ./trained_model`
- **Cause**: `MODEL_DIR` path is misconfigured or model files are missing.
- **Fix**: Ensure `trained_model/` containing `model.safetensors`, `config.json`, `label_mapping.json`, and tokenizer files exists in the working directory or set `MODEL_DIR=/absolute/path/to/trained_model`.

### Issue 4: High CPU Usage
- **Cause**: Multiple unquantized models running.
- **Fix**: The agent automatically applies PyTorch INT8 CPU Dynamic Quantization on startup (`torch.quantization.quantize_dynamic`) to keep CPU utilization under 5%.
