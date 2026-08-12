# 🛡️ Autonomous AI Security Agent for Linux VPS Servers

An enterprise-grade, autonomous real-time AI Security Agent designed to protect entire Linux VPS servers. Powered by a fine-tuned Hugging Face **DistilBERT** multi-class model (48 attack classes), a **Security Decision Engine** with configurable confidence thresholds, a **Benign Log Pre-Filter**, a real-time **DDoS Traffic Volume Anomaly Detector**, a **VPS Resource Monitor** (CPU, RAM, Disk), a **Centralized Alert Manager**, and an automated **SMTP Email Alert System**.

---

## 🏗️ Security Decision Architecture

```
                    VPS Server
                        │
       ┌────────────────┼────────────────┐
       ▼                ▼                ▼
  System Logs       Resources         Network
 (/var/log)       (CPU, RAM, Disk)  (HTTP Traffic)
       │                │                │
       ▼                │                ▼
  Log Pre-Filter        │           DDoS Traffic
       │                │            Detector
       ├─ BENIGN ──► IGNORE          (ddos_detector)
       │                │                │
       ▼                │                │
  Log Parser            │                │
 (log_parser)           │                │
       │                │                │
       ▼                │                │
  AI Model              │                │
 (DistilBERT)           │                │
       │                │                │
       ▼                │                │
  Security Decision     │                │
    Engine              │                │
       │                │                │
  ┌────┼────┐           │                │
  │    │    │           │                │
IGNORE LOG  ALERT       │                │
  │  ONLY    │          │                │
  │    │     ▼          ▼                ▼
  │    │  Risk Engine  Resource        DDoS
  │    │     │         Monitor         Alert
  │    │     ▼          │                │
  │    │  Alert Manager◄┘────────────────┘
  │    │     │
  │    │     ▼
  │    │   EMAIL
  │    │
  ▼    ▼
 (No Email — logged to security_decisions table)
```

### Decision Logic

| Condition | Decision | Severity | Email? |
|-----------|----------|----------|--------|
| Benign prediction | `IGNORE` | SAFE | ❌ |
| Attack + confidence < 40% | `IGNORE` | SAFE | ❌ |
| Attack + confidence 40-70% | `LOG_ONLY` | UNKNOWN | ❌ |
| Attack + confidence 70-85% | `ALERT` | MEDIUM/HIGH | ⚠️ Only if CRITICAL category |
| Attack + confidence 85-95% | `ALERT` | HIGH | ✅ |
| Attack + confidence ≥ 95% | `ALERT` | CRITICAL | ✅ |

**Example — False Positive Prevention:**
```
Input:  systemd[1950]: run-docker-runtime...mount: Succeeded.
Step 1: Log Pre-Filter → BENIGN → SKIP AI entirely → NO EMAIL

Input:  Prediction=Insecure_Deserialization, Confidence=9.74%
Step 2: Security Decision Engine → IGNORE (confidence < 40%) → NO EMAIL
```

**Example — Real Attack Detection:**
```
Input:  Failed password for root from 192.168.1.100
Step 1: Log Pre-Filter → PASS_TO_AI
Step 2: AI Model → SSH_BruteForce (96% confidence)
Step 3: Security Decision Engine → ALERT (confidence ≥ 95%)
Step 4: Risk Engine → CRITICAL
Step 5: Alert Manager → EMAIL SENT ✅
```

---

## 🌟 Major Capabilities & Architecture

1. **Multi-Source Real-Time Log Monitoring**: Tails `/var/log/auth.log`, `/var/log/syslog`, Nginx, Apache, Fail2ban, Auditd, and Docker logs in real time using non-blocking seek tailing (`monitor.py`).
2. **Benign Log Pre-Filter (`log_pre_filter.py`)**: Contextual pattern matching to identify clearly benign Linux/Docker/systemd events before the AI model, with suspicious keyword overrides to prevent filtering legitimate security events.
3. **AI ML Prediction Engine**: Loads DistilBERT transformer weights **once** at startup with PyTorch INT8 CPU quantization (<300MB RAM, <20ms inference latency).
4. **Security Decision Engine (`security_decision.py`)**: Central intelligence gate between AI model output and alerting. Evaluates confidence thresholds (configurable, default 70%) and category severity to prevent false positive email alerts.
5. **DDoS / High-Traffic Detector (`ddos_detector.py`)**:
   - Independent sliding time-window traffic volume monitor.
   - Detects single-IP floods, distributed multi-IP DDoS, targeted endpoint spikes, and HTTP error rate anomalies.
   - Assigns traffic risk levels (`NORMAL`, `SUSPICIOUS`, `HIGH`, `CRITICAL`).
6. **Server Resource Monitoring (`resource_monitor.py`)**:
   - Monitors CPU %, RAM %, Disk %, System Load Average, and Network I/O metrics.
   - Evaluates warning and critical thresholds (`CPU_WARNING=80`, `CPU_CRITICAL=95`, etc.).
   - Tracks state transitions and sends **RECOVERY** notifications when metric levels normalize.
7. **Centralized Alert Manager (`alert_manager.py`)**:
   - Coordinates alerts across Security Attacks, DDoS events, Resource warnings/criticals, and Health failures.
   - Manages alert cooldown windows (`ALERT_COOLDOWN_SECONDS=900`) and suppresses duplicate emails.
   - Only dispatches email for confirmed attacks that pass the Security Decision Engine.
8. **Unified Email Alert System (`email_service.py`)**:
   - Sends formatted HTML & plain-text incident alerts for `SECURITY_ATTACK`, `DDOS_DETECTED`, `CPU_HIGH`, `CPU_CRITICAL`, `RAM_HIGH`, `RAM_CRITICAL`, `DISK_HIGH`, `DISK_CRITICAL`, `AGENT_FAILURE`, and `RECOVERY`.
9. **Extended SQLite Storage (`database.py`)**:
   - Stores logs and alerts across tables: `attack_logs`, `alerts`, `security_events`, `resource_alerts`, `ddos_events`, `system_health`, `security_decisions`.
   - The `security_decisions` table provides full audit trail of every decision made by the engine.
10. **Health Check & Heartbeat API (`health.py` & `main.py`)**:
    - Exposes `GET /health` returning `agent_status`, `model_status`, `database_status`, `log_monitor_status`, `last_heartbeat`, `uptime`, `cpu`, `ram`, `disk`.

---

## 📁 Project Structure

```
AI-Security-Agent/
├── app/
│   ├── __init__.py             # Package initialization
│   ├── main.py                 # FastAPI server entrypoint & REST API endpoints
│   ├── config.py               # Configuration parameters & environment settings
│   ├── predictor.py            # Hugging Face DistilBERT model loader (Loaded ONCE)
│   ├── monitor.py              # Non-blocking seek log tailer with decision pipeline
│   ├── log_parser.py           # Noise filter and clean payload extractor
│   ├── log_pre_filter.py       # [NEW] Benign log contextual pre-filter
│   ├── security_decision.py    # [NEW] Security Decision Engine (confidence gate)
│   ├── ddos_detector.py        # Real-time traffic volume & DDoS anomaly detector
│   ├── resource_monitor.py     # VPS CPU, RAM, Disk, System Load, Network monitor
│   ├── alert_manager.py        # Centralized alert coordinator, cooldown & recovery
│   ├── risk_engine.py          # 5-tier risk severity calculator (SAFE to CRITICAL)
│   ├── email_service.py        # HTML email alert service with anti-spam deduplication
│   ├── database.py             # SQLite database manager (incidents.db)
│   ├── logger.py               # Structured logger (logs to stdout & logs/agent.log)
│   ├── scheduler.py            # Periodic resource check, heartbeat & hourly reporting
│   ├── health.py               # Diagnostic health checker & resource metrics
│   └── utils.py                # Actionable remediation steps & sanitization helpers
├── trained_model/              # Local pre-trained model weights & tokenizer
├── logs/                       # Operational agent logs
├── database/                   # SQLite database storage (incidents.db)
├── ai-security-agent.service   # Systemd service unit for VPS auto-boot startup
├── Dockerfile                  # Production container build definition
├── docker-compose.yml          # Docker Compose orchestration
├── test_false_positives.py     # [NEW] False positive prevention test suite (41 tests)
├── test_ddos.py                # Unit tests for DDoS traffic detector
├── test_resources.py           # Unit tests for resource monitor
├── test_alerts.py              # Unit tests for AlertManager & cooldown
├── test_health.py              # Unit tests for health endpoints
├── test_logs.py                # End-to-end integration test script
├── test_global.py              # Comprehensive global test suite
├── requirements.txt            # Python dependencies
└── README.md                   # Documentation
```

---

## ⚙️ Environment Configuration (`app/config.py`)

All settings are fully configurable via environment variables:

```bash
# Security Decision Engine (NEW)
export AI_CONFIDENCE_THRESHOLD=0.70        # Minimum AI confidence to trigger attack alert
export AI_LOW_CONFIDENCE_ACTION=IGNORE     # Action for low confidence: IGNORE or LOG_ONLY
export BENIGN_LOG_FILTER_ENABLED=true      # Enable/disable benign log pre-filter
export SECURITY_DECISION_ENGINE_ENABLED=true  # Enable/disable decision engine

# DDoS Detection
export DDOS_ENABLED=true
export DDOS_REQUEST_THRESHOLD=100
export DDOS_WINDOW_SECONDS=10
export DDOS_IP_THRESHOLD=50
export DDOS_ENDPOINT_THRESHOLD=200

# Resource Thresholds (%)
export CPU_WARNING=80.0
export CPU_CRITICAL=95.0
export RAM_WARNING=80.0
export RAM_CRITICAL=90.0
export DISK_WARNING=80.0
export DISK_CRITICAL=90.0

# Alert Cooldown & Monitoring
export ALERT_COOLDOWN_SECONDS=900
export RESOURCE_CHECK_INTERVAL=10
export HEARTBEAT_INTERVAL=30

# SMTP Email Settings
export SMTP_HOST=smtp.gmail.com
export SMTP_PORT=587
export SMTP_USER=aymaneelfounti@gmail.com
export SMTP_PASS=xxxx-xxxx-xxxx-xxxx
export ADMIN_EMAIL=aymaneelfounti@gmail.com
export EMAIL_ENABLED=true
```

---

## 🧪 Running Automated Test Suites

```bash
cd ai-security-agent

# 1. False Positive Prevention Tests (41 tests)
python -m unittest test_false_positives -v

# 2. DDoS Detector Test Suite
python test_ddos.py

# 3. Resource Monitor Test Suite
python test_resources.py

# 4. Alert Manager & Cooldown Test Suite
python test_alerts.py

# 5. Health Endpoint & Heartbeat Test Suite
python test_health.py

# 6. Integration Test
python test_logs.py

# 7. Global Comprehensive Test Suite
python test_global.py
```

---

## 🌐 REST API Endpoints

| Endpoint | Method | Description |
|---|---|---|
| `GET /health` | GET | Standard clean Health Check (`agent`, `model`, `database`, `log_monitor`, `last_heartbeat`, `cpu`, `ram`, `disk`) |
| `GET /api/v1/health` | GET | Full diagnostic health check and subsystem breakdown |
| `GET /api/v1/resources` | GET | Current VPS CPU, RAM, Disk, System Load, and Network I/O metrics |
| `GET /api/v1/ddos` | GET | Current DDoS traffic volume metrics and sliding window status |
| `GET /api/v1/alerts` | GET | Active alerts currently tracked in SQLite database |
| `POST /api/v1/analyze` | POST | Manually evaluate custom log lines (includes Security Decision Engine) |
| `GET /api/v1/incidents` | GET | Query stored security attack incidents |
| `GET /api/v1/decisions` | GET | Query Security Decision Engine audit trail (NEW) |
| `GET /api/v1/stats` | GET | Retrieve aggregated incident statistics and risk breakdown |
