"""
config.py
=========
Centralized configuration management for the AI Security Agent.
Supports environment variables with production defaults.
"""

import os
import socket
from typing import List

# Base directories
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# Hostname
HOSTNAME = os.getenv("SERVER_HOSTNAME", socket.gethostname())

# Model Configuration
MODEL_DIR = os.getenv("MODEL_DIR", os.path.join(BASE_DIR, "trained_model"))
CONFIDENCE_THRESHOLD = float(os.getenv("CONFIDENCE_THRESHOLD", "0.55"))

# Risk Threshold for Alerting (SAFE, LOW, MEDIUM, HIGH, CRITICAL)
MIN_ALERT_RISK_THRESHOLD = os.getenv("MIN_ALERT_RISK_THRESHOLD", "HIGH").upper()

# Database Configuration
DATABASE_DIR = os.getenv("DATABASE_DIR", os.path.join(BASE_DIR, "database"))
DB_PATH = os.path.join(DATABASE_DIR, "incidents.db")

# Agent Log Directory
LOG_DIR = os.getenv("LOG_DIR", os.path.join(BASE_DIR, "logs"))

# Target Security Log Sources to Monitor on Linux VPS
DEFAULT_LOG_SOURCES: List[str] = [
    "/var/log/auth.log",
    "/var/log/secure",          # RedHat/CentOS auth log
    "/var/log/syslog",
    "/var/log/messages",
    "/var/log/nginx/access.log",
    "/var/log/nginx/error.log",
    "/var/log/apache2/access.log",
    "/var/log/apache2/error.log",
    "/var/log/httpd/access_log",
    "/var/log/httpd/error_log",
    "/var/log/fail2ban.log",
    "/var/log/audit/audit.log",
]

# Custom log paths from env (comma-separated)
CUSTOM_LOG_SOURCES = os.getenv("CUSTOM_LOG_SOURCES", "")
if CUSTOM_LOG_SOURCES:
    ADDITIONAL = [s.strip() for s in CUSTOM_LOG_SOURCES.split(",") if s.strip()]
    DEFAULT_LOG_SOURCES.extend(ADDITIONAL)

# Ignored Log Patterns (Noise Filter)
IGNORED_LOG_PATTERNS = [
    r"systemd\[\d+\]:\s+(Started|Starting|Stopped|Stopping|Reached target|Created slice|Listening on)",
    r"CRON\[\d+\]:\s+\(root\)\s+CMD\s+\(/usr/lib/php/sessionclean\)",
    r"apt-dscp|dpkg-exec|unattended-upgrades",
    r"logrotate:\s+ALERT",
    r"dhclient\[\d+\]:\s+DHCP(ACK|OFFER|REQUEST)",
    r"systemd-resolved\[\d+\]:\s+Using DNS server",
]

# Email Service & SMTP Configuration
SMTP_HOST = os.getenv("SMTP_HOST", "smtp.gmail.com")
SMTP_PORT = int(os.getenv("SMTP_PORT", "587"))
SMTP_USER = os.getenv("SMTP_USER", "aymaneelfounti@gmail.com")
SMTP_PASS = os.getenv("SMTP_PASS", "dcfp ukju lgmp eczr")
ADMIN_EMAIL = os.getenv("ADMIN_EMAIL", "aymaneelfounti@gmail.com")
EMAIL_ENABLED = os.getenv("EMAIL_ENABLED", "true").lower() in ("true", "1", "yes")

# Anti-Spam / Email Deduplication Window (Minutes)
ALERT_DEDUPLICATION_WINDOW_MINUTES = int(os.getenv("ALERT_DEDUPLICATION_WINDOW_MINUTES", "15"))

# Real-time Monitoring Settings
POLL_INTERVAL_SECONDS = float(os.getenv("POLL_INTERVAL_SECONDS", "0.5"))
MAX_LOG_LINE_LENGTH = int(os.getenv("MAX_LOG_LINE_LENGTH", "1000"))

# Health Check & Web Server API
API_HOST = os.getenv("API_HOST", "0.0.0.0")
API_PORT = int(os.getenv("API_PORT", "8000"))
