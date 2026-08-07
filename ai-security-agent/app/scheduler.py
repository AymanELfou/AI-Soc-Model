"""
scheduler.py
============
Background task scheduler for periodic VPS resource checks, heartbeat updates,
DDoS counter sliding window cleanups, and hourly status reporting.
"""

import time
import threading
from app.config import RESOURCE_CHECK_INTERVAL, HEARTBEAT_INTERVAL
from app.resource_monitor import resource_monitor
from app.alert_manager import alert_manager
from app.health import health_checker
from app.database import db
from app.logger import logger

class AgentScheduler(threading.Thread):
    """Background scheduler thread running lightweight periodic tasks."""

    def __init__(
        self,
        resource_interval: int = RESOURCE_CHECK_INTERVAL,
        heartbeat_interval: int = HEARTBEAT_INTERVAL
    ):
        super().__init__(daemon=True, name="AgentScheduler")
        self.resource_interval = resource_interval
        self.heartbeat_interval = heartbeat_interval
        self.running = True
        self.last_resource_check = 0.0
        self.last_heartbeat_check = 0.0
        self.last_hourly_report = 0.0

    def run(self):
        logger.info("Background AgentScheduler thread started.")
        while self.running:
            now = time.time()

            # 1. Periodic VPS Resource Monitor Check (every 10s default)
            if now - self.last_resource_check >= self.resource_interval:
                self._run_resource_check()
                self.last_resource_check = now

            # 2. Agent Heartbeat Update (every 30s default)
            if now - self.last_heartbeat_check >= self.heartbeat_interval:
                health_checker.update_heartbeat()
                self.last_heartbeat_check = now

            # 3. Hourly Report & DB Cleanup (every 3600s)
            if now - self.last_hourly_report >= 3600:
                self._run_hourly_tasks()
                self.last_hourly_report = now

            time.sleep(1.0)

    def _run_resource_check(self):
        """Poll system resources, record snapshot, and process warning/critical/recovery alerts."""
        try:
            res_data = resource_monitor.check_resources()
            metrics = res_data.get("metrics", {})

            # Save health snapshot to DB
            db.save_health_snapshot(
                hostname=res_data.get("hostname", ""),
                cpu_percent=metrics.get("cpu_percent", 0.0),
                ram_percent=metrics.get("ram_percent", 0.0),
                disk_percent=metrics.get("disk_percent", 0.0),
                load_avg=metrics.get("load_avg", "N/A"),
                agent_status="running",
                heartbeat_time=health_checker.last_heartbeat
            )

            # Process warning/critical/recovery transitions via AlertManager
            alert_manager.process_resource_metrics(res_data)
        except Exception as e:
            logger.error(f"Error in scheduler resource check: {e}")

    def _run_hourly_tasks(self):
        """Execute hourly health status summary and statistics log."""
        try:
            stats = db.statistics()
            total = stats.get("total_incidents", 0)
            last24h = stats.get("last_24h_incidents", 0)
            breakdown = stats.get("risk_breakdown", {})

            logger.info(
                f"[HOURLY REPORT] Total Incidents: {total} | Last 24h: {last24h} | "
                f"Critical: {breakdown.get('CRITICAL',0)}, High: {breakdown.get('HIGH',0)}, Medium: {breakdown.get('MEDIUM',0)}"
            )
        except Exception as e:
            logger.error(f"Error in scheduler hourly tasks: {e}")

    def stop(self):
        self.running = False

# Global scheduler instance
scheduler = AgentScheduler()
