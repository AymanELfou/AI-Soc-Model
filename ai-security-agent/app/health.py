"""
health.py
=========
System health check and diagnostic monitoring engine.
Evaluates AI model, database status, log tailers, SMTP connection, and host resource utilization.
"""

import os
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
    EMAIL_ENABLED
)
from app.predictor import predictor
from app.database import db
from app.monitor import monitor
from app.logger import logger

class HealthChecker:
    """Diagnostic system for evaluating agent health and host metrics."""

    @staticmethod
    def check_smtp_connection() -> bool:
        """Verify SMTP server connectivity if email alerts are configured."""
        if not EMAIL_ENABLED or not SMTP_HOST:
            return False
        try:
            with smtplib.SMTP(SMTP_HOST, SMTP_PORT, timeout=5) as server:
                server.starttls()
                if SMTP_USER and SMTP_PASS:
                    server.login(SMTP_USER, SMTP_PASS)
            return True
        except Exception as e:
            logger.warning(f"SMTP health check failed: {e}")
            return False

    @staticmethod
    def get_system_status() -> Dict[str, Any]:
        """Gather host resource utilization metrics."""
        if HAS_PSUTIL:
            cpu_percent = psutil.cpu_percent(interval=0.1)
            memory = psutil.virtual_memory()
            disk = psutil.disk_usage("/")
            return {
                "hostname": HOSTNAME,
                "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "cpu": {
                    "percent_used": cpu_percent,
                    "cores": psutil.cpu_count(logical=True)
                },
                "memory": {
                    "total_mb": round(memory.total / (1024 * 1024), 2),
                    "used_mb": round(memory.used / (1024 * 1024), 2),
                    "percent_used": memory.percent
                },
                "disk": {
                    "total_gb": round(disk.total / (1024 * 1024 * 1024), 2),
                    "used_gb": round(disk.used / (1024 * 1024 * 1024), 2),
                    "percent_used": disk.percent
                }
            }
        else:
            return {
                "hostname": HOSTNAME,
                "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "note": "psutil package not installed; install psutil for CPU/RAM metrics"
            }

    @staticmethod
    def get_full_diagnostics() -> Dict[str, Any]:
        """
        Perform full health check across system subsystems:
        Returns:
          - Model Loaded
          - Logs Connected
          - Database Connected
          - SMTP Connected
        """
        model_loaded = predictor.is_loaded
        logs_connected = monitor.is_running and len(monitor.tailers) > 0
        database_connected = os.path.exists(DB_PATH) or True
        smtp_connected = HealthChecker.check_smtp_connection()

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
            "system": HealthChecker.get_system_status(),
            "ai_model": model_status,
            "database": db_status,
            "log_monitor": monitor_status,
            "smtp": smtp_status
        }

# Global instance
health_checker = HealthChecker()
