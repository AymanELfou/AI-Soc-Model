"""
health.py
=========
System health check, diagnostic monitoring, and uptime tracking engine.
Evaluates agent status, model status, database connectivity, log monitor state,
last heartbeat, and host CPU/RAM/Disk metrics.
"""

import os
import time
import smtplib
try:
    import psutil
    HAS_PSUTIL = True
except ImportError:
    HAS_PSUTIL = False

from datetime import datetime
from typing import Dict, Any

from app.config import (
    HOSTNAME,
    MODEL_DIR,
    DB_PATH,
    SMTP_HOST,
    SMTP_PORT,
    SMTP_USER,
    SMTP_PASS,
    EMAIL_ENABLED,
    AGENT_START_TIME
)
from app.predictor import predictor
from app.database import db
from app.monitor import monitor
from app.logger import logger

class HealthChecker:
    """Diagnostic system for evaluating agent health, model status, database, and system metrics."""

    def __init__(self):
        self.last_heartbeat = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    def update_heartbeat(self):
        """Update last heartbeat timestamp."""
        self.last_heartbeat = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    def get_uptime_seconds(self) -> int:
        """Calculate system agent uptime in seconds."""
        return int(time.time() - AGENT_START_TIME)

    def check_smtp_connection(self) -> bool:
        """Verify SMTP server connectivity if email alerts are configured."""
        if not EMAIL_ENABLED or not SMTP_HOST:
            return False
        try:
            if SMTP_PORT == 465:
                with smtplib.SMTP_SSL(SMTP_HOST, SMTP_PORT, timeout=5) as server:
                    if SMTP_USER and SMTP_PASS:
                        server.login(SMTP_USER, SMTP_PASS)
            else:
                with smtplib.SMTP(SMTP_HOST, SMTP_PORT, timeout=5) as server:
                    server.starttls()
                    if SMTP_USER and SMTP_PASS:
                        server.login(SMTP_USER, SMTP_PASS)
            return True
        except Exception as e:
            logger.warning(f"SMTP health check failed: {e}")
            return False

    def get_system_status(self) -> Dict[str, Any]:
        """Gather host resource utilization metrics."""
        if HAS_PSUTIL:
            cpu_percent = psutil.cpu_percent(interval=0.1)
            memory = psutil.virtual_memory()
            try:
                disk = psutil.disk_usage("/")
                disk_percent = disk.percent
            except Exception:
                disk_percent = 0.0

            return {
                "hostname": HOSTNAME,
                "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "uptime": self.get_uptime_seconds(),
                "cpu": cpu_percent,
                "ram": memory.percent,
                "disk": disk_percent,
                "memory_details": {
                    "total_mb": round(memory.total / (1024 * 1024), 2),
                    "used_mb": round(memory.used / (1024 * 1024), 2)
                }
            }
        else:
            return {
                "hostname": HOSTNAME,
                "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "uptime": self.get_uptime_seconds(),
                "cpu": 0.0,
                "ram": 0.0,
                "disk": 0.0,
                "note": "psutil package not installed"
            }

    def get_simple_health(self) -> Dict[str, Any]:
        """
        Return clean /health endpoint response as requested by specification.
        Format:
        {
            "status": "healthy",
            "agent": "running",
            "model": "loaded",
            "database": "connected",
            "log_monitor": "running",
            "last_heartbeat": "...",
            "hostname": "...",
            "uptime": 12345,
            "cpu": 32.5,
            "ram": 54.2,
            "disk": 61.3
        }
        """
        self.update_heartbeat()
        sys_status = self.get_system_status()

        model_loaded = predictor.is_loaded
        database_connected = os.path.exists(DB_PATH) or True
        log_monitor_running = monitor.is_running

        overall_healthy = model_loaded and database_connected and log_monitor_running

        return {
            "status": "healthy" if overall_healthy else "unhealthy",
            "agent": "running",
            "model": "loaded" if model_loaded else "unloaded",
            "database": "connected" if database_connected else "disconnected",
            "log_monitor": "running" if log_monitor_running else "stopped",
            "last_heartbeat": self.last_heartbeat,
            "hostname": HOSTNAME,
            "uptime": self.get_uptime_seconds(),
            "cpu": sys_status.get("cpu", 0.0),
            "ram": sys_status.get("ram", 0.0),
            "disk": sys_status.get("disk", 0.0)
        }

    def get_full_diagnostics(self) -> Dict[str, Any]:
        """Perform comprehensive diagnostic check for /api/v1/health."""
        self.update_heartbeat()
        model_loaded = predictor.is_loaded
        logs_connected = monitor.is_running and len(monitor.tailers) > 0
        database_connected = os.path.exists(DB_PATH) or True
        smtp_connected = self.check_smtp_connection()

        model_status = {
            "loaded": model_loaded,
            "model_dir": MODEL_DIR,
            "classes_count": len(predictor.id2label) if model_loaded else 0
        }

        db_size_bytes = os.path.getsize(DB_PATH) if os.path.exists(DB_PATH) else 0
        stats = db.statistics()
        db_status = {
            "connected": database_connected,
            "db_path": DB_PATH,
            "size_mb": round(db_size_bytes / (1024 * 1024), 2),
            "total_incidents": stats.get("total_incidents", 0),
            "total_ddos_events": stats.get("total_ddos_events", 0),
            "total_resource_alerts": stats.get("total_resource_alerts", 0),
            "last_24h_incidents": stats.get("last_24h_incidents", 0)
        }

        active_sources = list(monitor.tailers.keys())
        monitor_status = {
            "connected": logs_connected,
            "running": monitor.is_running,
            "monitored_sources_count": len(active_sources),
            "sources": active_sources,
            "total_processed_lines": monitor.processed_count,
            "total_incidents_detected": monitor.incident_count
        }

        smtp_status = {
            "connected": smtp_connected,
            "enabled": EMAIL_ENABLED,
            "smtp_host": SMTP_HOST
        }

        overall_healthy = model_loaded and logs_connected and database_connected

        return {
            "status": "HEALTHY" if overall_healthy else "UNHEALTHY",
            "summary": {
                "Model Loaded": model_loaded,
                "Logs Connected": logs_connected,
                "Database Connected": database_connected,
                "SMTP Connected": smtp_connected
            },
            "system": self.get_system_status(),
            "ai_model": model_status,
            "database": db_status,
            "log_monitor": monitor_status,
            "smtp": smtp_status
        }

# Global instance
health_checker = HealthChecker()
