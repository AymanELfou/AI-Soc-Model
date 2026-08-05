"""
scheduler.py
============
Background task scheduler for periodic maintenance, statistics reporting, and cleanup.
"""

import time
import threading
from datetime import datetime, timedelta
from app.database import db
from app.logger import logger

class AgentScheduler(threading.Thread):
    """Background scheduler thread running periodic jobs."""

    def __init__(self, interval_seconds: int = 3600):
        super().__init__(daemon=True, name="AgentScheduler")
        self.interval_seconds = interval_seconds
        self.running = True

    def run(self):
        logger.info("Background AgentScheduler thread started.")
        while self.running:
            time.sleep(self.interval_seconds)
            if not self.running:
                break
            self._run_hourly_tasks()

    def _run_hourly_tasks(self):
        """Execute hourly health status summary and statistics gathering."""
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
