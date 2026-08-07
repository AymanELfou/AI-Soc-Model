"""
resource_monitor.py
===================
Real-time Linux VPS system resource monitor using psutil.
Monitors CPU %, RAM %, Disk %, System Load Average, and Network Traffic metrics.
Evaluates resource states against WARNING and CRITICAL thresholds, tracking state transitions and recoveries.
"""

import os
try:
    import psutil
    HAS_PSUTIL = True
except ImportError:
    HAS_PSUTIL = False

from datetime import datetime
from typing import Dict, Any, Optional
from app.config import (
    HOSTNAME,
    CPU_WARNING,
    CPU_CRITICAL,
    RAM_WARNING,
    RAM_CRITICAL,
    DISK_WARNING,
    DISK_CRITICAL
)
from app.logger import logger

class ResourceMonitor:
    """Monitors host hardware resource utilization and tracks metric warnings, criticals, and recoveries."""

    def __init__(self):
        self.hostname = HOSTNAME
        # Tracks last known metric state for transition/recovery detection
        self.last_states: Dict[str, str] = {
            "CPU": "NORMAL",
            "RAM": "NORMAL",
            "DISK": "NORMAL"
        }

    def _get_load_average(self) -> str:
        """Get system load average (1m, 5m, 15m) if supported by OS."""
        try:
            if hasattr(os, "getloadavg"):
                load1, load5, load15 = os.getloadavg()
                return f"{load1:.2f}, {load5:.2f}, {load15:.2f}"
        except Exception:
            pass
        return "N/A"

    def _get_network_io(self) -> Dict[str, float]:
        """Get network bytes sent and received."""
        if HAS_PSUTIL:
            try:
                net = psutil.net_io_counters()
                return {
                    "bytes_sent_mb": round(net.bytes_sent / (1024 * 1024), 2),
                    "bytes_recv_mb": round(net.bytes_recv / (1024 * 1024), 2)
                }
            except Exception:
                pass
        return {"bytes_sent_mb": 0.0, "bytes_recv_mb": 0.0}

    def evaluate_metric_state(self, current: float, warning_val: float, critical_val: float) -> str:
        """Evaluate resource level against WARNING and CRITICAL thresholds."""
        if current >= critical_val:
            return "CRITICAL"
        elif current >= warning_val:
            return "WARNING"
        return "NORMAL"

    def check_resources(self) -> Dict[str, Any]:
        """
        Poll CPU, RAM, Disk, System Load, and Network I/O metrics.
        Returns metric measurements, current risk state per metric, and state transitions.
        """
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        if HAS_PSUTIL:
            cpu_percent = psutil.cpu_percent(interval=0.1)
            memory = psutil.virtual_memory()
            ram_percent = memory.percent
            ram_used_mb = round(memory.used / (1024 * 1024), 2)
            ram_total_mb = round(memory.total / (1024 * 1024), 2)
            try:
                disk = psutil.disk_usage("/")
                disk_percent = disk.percent
            except Exception:
                disk_percent = 0.0
        else:
            cpu_percent = 5.0
            ram_percent = 30.0
            disk_percent = 40.0
            ram_used_mb = 2048.0
            ram_total_mb = 8192.0

        load_avg = self._get_load_average()
        net_io = self._get_network_io()

        # Evaluate states
        cpu_state = self.evaluate_metric_state(cpu_percent, CPU_WARNING, CPU_CRITICAL)
        ram_state = self.evaluate_metric_state(ram_percent, RAM_WARNING, RAM_CRITICAL)
        disk_state = self.evaluate_metric_state(disk_percent, DISK_WARNING, DISK_CRITICAL)

        metric_states = {
            "CPU": {"current": cpu_percent, "warning": CPU_WARNING, "critical": CPU_CRITICAL, "state": cpu_state},
            "RAM": {"current": ram_percent, "warning": RAM_WARNING, "critical": RAM_CRITICAL, "state": ram_state},
            "DISK": {"current": disk_percent, "warning": DISK_WARNING, "critical": DISK_CRITICAL, "state": disk_state}
        }

        # Determine overall severity level
        overall_severity = "NORMAL"
        if "CRITICAL" in (cpu_state, ram_state, disk_state):
            overall_severity = "CRITICAL"
        elif "WARNING" in (cpu_state, ram_state, disk_state):
            overall_severity = "WARNING"

        # Detect transitions & recoveries
        transitions = []
        for metric_name, data in metric_states.items():
            new_state = data["state"]
            old_state = self.last_states[metric_name]

            if new_state != old_state:
                if new_state in ("WARNING", "CRITICAL"):
                    transitions.append({
                        "metric": metric_name,
                        "event_type": f"{metric_name}_{new_state}",
                        "old_state": old_state,
                        "new_state": new_state,
                        "current_value": data["current"],
                        "threshold": data["critical"] if new_state == "CRITICAL" else data["warning"]
                    })
                elif old_state in ("WARNING", "CRITICAL") and new_state == "NORMAL":
                    transitions.append({
                        "metric": metric_name,
                        "event_type": "RECOVERY",
                        "old_state": old_state,
                        "new_state": new_state,
                        "current_value": data["current"],
                        "threshold": data["warning"]
                    })
                self.last_states[metric_name] = new_state

        return {
            "timestamp": timestamp,
            "hostname": self.hostname,
            "overall_severity": overall_severity,
            "metrics": {
                "cpu_percent": cpu_percent,
                "ram_percent": ram_percent,
                "disk_percent": disk_percent,
                "ram_used_mb": ram_used_mb,
                "ram_total_mb": ram_total_mb,
                "load_avg": load_avg,
                "network_io": net_io
            },
            "metric_states": metric_states,
            "transitions": transitions
        }

# Global instance
resource_monitor = ResourceMonitor()
