"""
alert_manager.py
================
Centralized Alert Manager coordinating alert dispatch, deduplication, cooldown windows,
active alert tracking, recovery notifications, database storage, and email delivery.
"""

import time
from datetime import datetime, timedelta
from typing import Dict, Any, Tuple, Optional
from app.config import (
    HOSTNAME,
    ALERT_COOLDOWN_SECONDS,
    MIN_ALERT_RISK_THRESHOLD
)
from app.database import db
from app.email_service import email_service
from app.logger import logger

class AlertManager:
    """
    Central dispatcher and state manager for all security, DDoS, resource, and health alerts.
    
    Architecture Flow:
    Security Detection ──┐
    DDoS Detection ──────┼──► Alert Manager ──► Database & Email Service
    Resource Monitoring ─┤
    Health Monitoring ───┘
    """

    def __init__(self, cooldown_seconds: int = ALERT_COOLDOWN_SECONDS):
        self.cooldown_seconds = cooldown_seconds
        # Cooldown tracking: key = (alert_type, source_key), value = timestamp_last_sent
        self._cooldown_cache: Dict[Tuple[str, str], float] = {}
        # Active resource alert state: key = metric_name (CPU/RAM/DISK), value = active_severity
        self.active_resource_states: Dict[str, str] = {
            "CPU": "NORMAL",
            "RAM": "NORMAL",
            "DISK": "NORMAL"
        }

    def _is_in_cooldown(self, alert_type: str, source_key: str) -> bool:
        """Check if an alert of given type and source is currently within cooldown window."""
        key = (alert_type, source_key)
        now = time.time()
        if key in self._cooldown_cache:
            last_time = self._cooldown_cache[key]
            if now - last_time < self.cooldown_seconds:
                logger.info(f"Alert suppressed: [{alert_type}] for '{source_key}' is in cooldown ({int(self.cooldown_seconds - (now - last_time))}s remaining)")
                return True
        self._cooldown_cache[key] = now
        return False

    # ════════════════════════════════════════════════════════
    # 1. AI SECURITY ATTACK ALERTS
    # ════════════════════════════════════════════════════════

    def dispatch_security_attack(
        self,
        prediction: str,
        confidence: float,
        risk: str,
        source_log: str,
        raw_log: str
    ) -> bool:
        """Process and dispatch an AI Security Attack alert."""
        if risk not in ("HIGH", "CRITICAL"):
            return False

        if self._is_in_cooldown("SECURITY_ATTACK", f"{prediction}:{source_log}"):
            return False

        description = f"Security threat '{prediction}' detected with {confidence*100:.2f}% confidence in '{source_log}'."
        metrics = {
            "prediction": prediction,
            "confidence_percent": round(confidence * 100, 2),
            "risk": risk,
            "raw_log": raw_log
        }

        # Save to DB
        db.save_alert(
            hostname=HOSTNAME,
            alert_type="SECURITY_ATTACK",
            severity=risk,
            description=description,
            source=source_log,
            metrics=metrics
        )

        # Trigger Email
        timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
        return email_service.send_alert(
            hostname=HOSTNAME,
            timestamp=timestamp,
            prediction=prediction,
            confidence=confidence,
            risk=risk,
            source_log=source_log,
            raw_log=raw_log
        )

    # ════════════════════════════════════════════════════════
    # 2. DDOS / HIGH TRAFFIC ALERTS
    # ════════════════════════════════════════════════════════

    def dispatch_ddos_alert(self, ddos_info: Dict[str, Any]) -> bool:
        """Process and dispatch a DDoS / Traffic Spike alert."""
        risk_level = ddos_info.get("risk_level", "NORMAL")
        if risk_level not in ("HIGH", "CRITICAL"):
            return False

        top_ip = ddos_info.get("top_ip", "N/A")
        if self._is_in_cooldown("DDOS_DETECTED", f"{top_ip}"):
            return False

        patterns = ", ".join(ddos_info.get("patterns_detected", ["Traffic Anomaly"]))
        description = f"Possible DDoS Attack detected: {patterns}. Total requests: {ddos_info.get('total_requests_in_window')} in {ddos_info.get('window_seconds')}s."

        # Save DDoS event to DB
        db.save_ddos_event(
            hostname=HOSTNAME,
            pattern_type="; ".join(ddos_info.get("patterns_detected", [])),
            requests_count=ddos_info.get("total_requests_in_window", 0),
            window_seconds=ddos_info.get("window_seconds", 10),
            top_ip=top_ip,
            top_endpoint=ddos_info.get("top_endpoint", "N/A"),
            risk_level=risk_level,
            metrics=ddos_info
        )

        # Save Central Alert
        db.save_alert(
            hostname=HOSTNAME,
            alert_type="DDOS_DETECTED",
            severity=risk_level,
            description=description,
            source="DDoSDetector",
            metrics=ddos_info
        )

        # Trigger Email
        timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
        return email_service.send_alert_event(
            alert_type="DDOS_DETECTED",
            severity=risk_level,
            hostname=HOSTNAME,
            timestamp=timestamp,
            description=description,
            metrics=ddos_info,
            source="DDoSDetector",
            recommendation="Investigate traffic volume, review top source IP address, and apply firewall/rate-limiting rules if appropriate."
        )

    # ════════════════════════════════════════════════════════
    # 3. VPS RESOURCE ALERTS (CPU, RAM, DISK) & RECOVERIES
    # ════════════════════════════════════════════════════════

    def process_resource_metrics(self, resource_data: Dict[str, Any]):
        """Evaluate resource monitor transitions and dispatch warning, critical, or recovery alerts."""
        transitions = resource_data.get("transitions", [])
        current_metrics = resource_data.get("metrics", {})

        for trans in transitions:
            metric = trans["metric"]
            event_type = trans["event_type"]
            new_state = trans["new_state"]
            curr_val = trans["current_value"]

            if event_type == "RECOVERY":
                self.dispatch_recovery_alert(
                    metric_name=metric,
                    current_val=curr_val,
                    metrics=current_metrics
                )
            elif new_state in ("WARNING", "CRITICAL"):
                alert_type_name = f"{metric}_HIGH" if new_state == "WARNING" else f"{metric}_CRITICAL"
                self.dispatch_resource_alert(
                    metric_name=metric,
                    severity=new_state,
                    alert_type_name=alert_type_name,
                    current_val=curr_val,
                    threshold_val=trans["threshold"],
                    metrics=current_metrics
                )

    def dispatch_resource_alert(
        self,
        metric_name: str,
        severity: str,
        alert_type_name: str,
        current_val: float,
        threshold_val: float,
        metrics: Dict[str, Any]
    ) -> bool:
        """Dispatch CPU/RAM/Disk Warning or Critical alert."""
        if self._is_in_cooldown(alert_type_name, metric_name):
            return False

        description = f"{metric_name} usage reached {severity} state: {current_val:.1f}% (Threshold: {threshold_val:.1f}%)."

        # Save to DB
        db.save_resource_alert(
            hostname=HOSTNAME,
            metric_name=metric_name,
            current_value=current_val,
            threshold_value=threshold_val,
            severity=severity,
            status="ACTIVE"
        )
        db.save_alert(
            hostname=HOSTNAME,
            alert_type=alert_type_name,
            severity=severity,
            description=description,
            source=f"ResourceMonitor:{metric_name}",
            metrics=metrics
        )

        self.active_resource_states[metric_name] = severity

        timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
        return email_service.send_alert_event(
            alert_type=alert_type_name,
            severity=severity,
            hostname=HOSTNAME,
            timestamp=timestamp,
            description=description,
            metrics=metrics,
            source=f"ResourceMonitor ({metric_name})",
            recommendation=f"Inspect high-resource processes using 'top' or 'ps aux', free up memory/disk, or scale host resources."
        )

    def dispatch_recovery_alert(self, metric_name: str, current_val: float, metrics: Dict[str, Any]) -> bool:
        """Dispatch resource recovery alert when metric returns to normal state."""
        description = f"{metric_name} usage returned to NORMAL state: {current_val:.1f}%."

        # Mark active alerts as RESOLVED in DB
        db.resolve_alert(alert_type=f"{metric_name}_HIGH", source=f"ResourceMonitor:{metric_name}")
        db.resolve_alert(alert_type=f"{metric_name}_CRITICAL", source=f"ResourceMonitor:{metric_name}")

        db.save_alert(
            hostname=HOSTNAME,
            alert_type="RECOVERY",
            severity="NORMAL",
            description=description,
            source=f"ResourceMonitor:{metric_name}",
            metrics=metrics,
            status="RESOLVED"
        )

        self.active_resource_states[metric_name] = "NORMAL"

        timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
        return email_service.send_alert_event(
            alert_type="RECOVERY",
            severity="NORMAL",
            hostname=HOSTNAME,
            timestamp=timestamp,
            description=description,
            metrics=metrics,
            source=f"ResourceMonitor ({metric_name})",
            recommendation=f"{metric_name} resource usage is back within normal operational limits."
        )

    # ════════════════════════════════════════════════════════
    # 4. HEALTH / AGENT FAILURE ALERTS
    # ════════════════════════════════════════════════════════

    def dispatch_agent_failure(self, reason: str) -> bool:
        """Dispatch Agent Failure alert."""
        if self._is_in_cooldown("AGENT_FAILURE", "agent"):
            return False

        description = f"AI Security Agent subsystem failure: {reason}"
        db.save_alert(
            hostname=HOSTNAME,
            alert_type="AGENT_FAILURE",
            severity="CRITICAL",
            description=description,
            source="HealthChecker",
            metrics={"reason": reason}
        )

        timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
        return email_service.send_alert_event(
            alert_type="AGENT_FAILURE",
            severity="CRITICAL",
            hostname=HOSTNAME,
            timestamp=timestamp,
            description=description,
            metrics={"reason": reason},
            source="HealthChecker",
            recommendation="Inspect agent system logs at 'logs/agent.log' and restart the service via 'sudo systemctl restart ai-security-agent'."
        )

# Global instance
alert_manager = AlertManager()
