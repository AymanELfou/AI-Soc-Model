"""
email_service.py
================
Automated email notification service with anti-spam deduplication logic.
Sends structured HTML incident reports for:
- SECURITY_ATTACK
- DDOS_DETECTED
- CPU_HIGH / CPU_CRITICAL
- RAM_HIGH / RAM_CRITICAL
- DISK_HIGH / DISK_CRITICAL
- AGENT_FAILURE
- RECOVERY
"""

import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from datetime import datetime, timedelta
from typing import Dict, Tuple, Any
import app.config as config
from app.utils import get_recommendation
from app.logger import logger

class EmailService:
    """Manages security & system alert email generation, SMTP transport, and anti-spam suppression."""

    def __init__(self):
        # Deduplication cache: key = (alert_type, source_log), value = last_sent_datetime
        self._dedup_cache: Dict[Tuple[str, str], datetime] = {}

    def _should_suppress(self, alert_type: str, source_key: str) -> bool:
        """Check if an alert for the same alert type and source key was sent recently."""
        key = (alert_type, source_key)
        now = datetime.now()
        dedup_window = timedelta(seconds=config.ALERT_COOLDOWN_SECONDS)

        if key in self._dedup_cache:
            last_sent = self._dedup_cache[key]
            if now - last_sent < dedup_window:
                logger.info(
                    f"Email alert suppressed (anti-spam dedup window active for {alert_type} on {source_key})"
                )
                return True

        self._dedup_cache[key] = now
        return False

    def _send_smtp_message(self, subject: str, text_body: str, html_body: str) -> bool:
        """Transport formatted email message over SMTP or SMTP_SSL."""
        enabled = config.EMAIL_ENABLED or bool(config.SMTP_HOST and config.ADMIN_EMAIL)
        if not enabled:
            logger.debug("Email alert skipped: Email service is disabled or unconfigured.")
            return False

        admin_recipient = config.ADMIN_EMAIL or "aymaneelfounti@gmail.com"
        smtp_user = config.SMTP_USER or admin_recipient
        smtp_host = config.SMTP_HOST or "smtp.gmail.com"
        smtp_port = config.SMTP_PORT or 587
        smtp_pass = config.SMTP_PASS or ""

        try:
            msg = MIMEMultipart("alternative")
            msg["Subject"] = subject
            msg["From"] = smtp_user
            msg["To"] = admin_recipient

            msg.attach(MIMEText(text_body, "plain"))
            msg.attach(MIMEText(html_body, "html"))

            if smtp_port == 465:
                with smtplib.SMTP_SSL(smtp_host, smtp_port, timeout=10) as server:
                    if smtp_user and smtp_pass:
                        server.login(smtp_user, smtp_pass)
                    server.send_message(msg)
            else:
                with smtplib.SMTP(smtp_host, smtp_port, timeout=10) as server:
                    server.starttls()
                    if smtp_user and smtp_pass:
                        server.login(smtp_user, smtp_pass)
                    server.send_message(msg)

            logger.info(f"Email report successfully sent to {admin_recipient} for '{subject}'")
            return True
        except Exception as e:
            logger.error(f"Failed to send email report to {admin_recipient}: {e}")
            return False

    # ════════════════════════════════════════════════════════
    # 1. SECURITY ATTACK EMAIL ALERTS (Preserved API)
    # ════════════════════════════════════════════════════════

    def send_alert(
        self,
        hostname: str,
        timestamp: str,
        prediction: str,
        confidence: float,
        risk: str,
        source_log: str,
        raw_log: str
    ) -> bool:
        """Send automated email alert for HIGH or CRITICAL security incidents."""
        if risk not in ("HIGH", "CRITICAL"):
            return False

        if self._should_suppress("SECURITY_ATTACK", f"{prediction}:{source_log}"):
            return False

        recommendation = get_recommendation(prediction)
        subject = f"🚨 [{risk}] Threat Alert: {prediction} on {hostname}"

        text_body = f"""
======================================================================
🛡️ ENTERPRISE VPS SECURITY AI — SHORT INCIDENT REPORT
======================================================================

[INCIDENT SUMMARY]
Server Hostname : {hostname}
Timestamp       : {timestamp}
Attack Category : {prediction}
AI Confidence   : {confidence * 100:.2f}%
Risk Level      : {risk}
Log Source      : {source_log}

[INTERCEPTED RAW LOG]
{raw_log}

[RECOMMENDED ACTION]
{recommendation}
"""

        html_body = f"""
<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8">
    <style>
        body {{ font-family: Arial, sans-serif; background-color: #f4f6f9; color: #212529; margin: 0; padding: 20px; }}
        .card {{ background-color: #ffffff; border-radius: 8px; box-shadow: 0 4px 12px rgba(0,0,0,0.12); max-width: 650px; margin: 0 auto; overflow: hidden; border: 1px solid #e9ecef; }}
        .header-critical {{ background: linear-gradient(135deg, #dc3545, #b02a37); color: #ffffff; padding: 20px 25px; }}
        .header-high {{ background: linear-gradient(135deg, #fd7e14, #d9480f); color: #ffffff; padding: 20px 25px; }}
        .header-title {{ margin: 0; font-size: 20px; font-weight: 700; }}
        .header-sub {{ margin: 5px 0 0 0; font-size: 13px; opacity: 0.9; }}
        .content {{ padding: 25px; }}
        .section-title {{ font-size: 14px; font-weight: 700; text-transform: uppercase; color: #6c757d; margin-bottom: 12px; border-bottom: 2px solid #e9ecef; padding-bottom: 5px; }}
        .field {{ margin-bottom: 8px; font-size: 13px; }}
        .label {{ font-weight: 600; color: #495057; display: inline-block; width: 140px; }}
        .badge {{ padding: 4px 10px; border-radius: 4px; font-weight: 700; font-size: 12px; color: #ffffff; text-transform: uppercase; }}
        .badge-critical {{ background-color: #dc3545; }}
        .badge-high {{ background-color: #fd7e14; }}
        .raw-box {{ background-color: #1e1e1e; color: #00ff66; font-family: monospace; padding: 14px; border-radius: 6px; font-size: 12px; white-space: pre-wrap; word-break: break-all; margin: 10px 0 20px 0; border-left: 4px solid #00ff66; }}
        .recom-box {{ background-color: #e7f5ff; border-left: 4px solid #1c7ed6; padding: 15px; border-radius: 4px; font-size: 13px; color: #1864ab; }}
        .footer {{ background-color: #f8f9fa; text-align: center; padding: 15px; font-size: 12px; color: #868e96; }}
    </style>
</head>
<body>
    <div class="card">
        <div class="{ 'header-critical' if risk == 'CRITICAL' else 'header-high' }">
            <h2 class="header-title">🚨 [{risk}] Threat Alert: {prediction}</h2>
            <p class="header-sub">Enterprise VPS Security Agent &bull; Server: {hostname}</p>
        </div>
        <div class="content">
            <div class="section-title">📌 Incident Summary</div>
            <div class="field"><span class="label">Server Hostname:</span> {hostname}</div>
            <div class="field"><span class="label">Timestamp:</span> {timestamp}</div>
            <div class="field"><span class="label">Attack Category:</span> <strong>{prediction}</strong></div>
            <div class="field"><span class="label">AI Confidence:</span> <strong>{confidence * 100:.2f}%</strong></div>
            <div class="field"><span class="label">Risk Severity:</span> <span class="badge { 'badge-critical' if risk == 'CRITICAL' else 'badge-high' }">{risk}</span></div>
            <div class="field"><span class="label">Source Log:</span> <code>{source_log}</code></div>

            <div class="section-title" style="margin-top:20px;">📜 Intercepted Log Snippet</div>
            <div class="raw-box">{raw_log}</div>

            <div class="section-title">💡 Actionable Remediation Steps</div>
            <div class="recom-box">
                <strong>Recommended Action:</strong><br>
                {recommendation}
            </div>
        </div>
        <div class="footer">Automated Incident Report &bull; AI Security Agent</div>
    </div>
</body>
</html>
"""
        return self._send_smtp_message(subject, text_body, html_body)

    # ════════════════════════════════════════════════════════
    # 2. UNIFIED EVENT ALERTS (DDoS, Resource, Failure, Recovery)
    # ════════════════════════════════════════════════════════

    def send_alert_event(
        self,
        alert_type: str,
        severity: str,
        hostname: str,
        timestamp: str,
        description: str,
        metrics: Dict[str, Any],
        source: str,
        recommendation: str
    ) -> bool:
        """Send formatted alert event email for DDoS, Resource Warning/Critical, or Recovery events."""

        if alert_type != "RECOVERY" and self._should_suppress(alert_type, source):
            return False

        header_class = "header-recovery" if alert_type == "RECOVERY" else ("header-critical" if severity == "CRITICAL" else "header-high")
        badge_class = "badge-recovery" if alert_type == "RECOVERY" else ("badge-critical" if severity == "CRITICAL" else "badge-high")
        icon = "✅" if alert_type == "RECOVERY" else "🚨"

        subject = f"{icon} [{severity}] {alert_type} Notification - {hostname}"

        # Format metrics nicely for body
        formatted_metrics = ""
        if isinstance(metrics, dict):
            for k, v in metrics.items():
                formatted_metrics += f"{k}: {v}\n"
        else:
            formatted_metrics = str(metrics)

        text_body = f"""
======================================================================
🛡️ VPS SECURITY AGENT NOTIFICATION: {alert_type}
======================================================================

Hostname    : {hostname}
Alert Type  : {alert_type}
Severity    : {severity}
Timestamp   : {timestamp}
Source      : {source}

Description:
{description}

Current Metrics:
{formatted_metrics}

Recommended Action:
{recommendation}
"""

        html_body = f"""
<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8">
    <style>
        body {{ font-family: Arial, sans-serif; background-color: #f4f6f9; color: #212529; margin: 0; padding: 20px; }}
        .card {{ background-color: #ffffff; border-radius: 8px; box-shadow: 0 4px 12px rgba(0,0,0,0.12); max-width: 650px; margin: 0 auto; overflow: hidden; border: 1px solid #e9ecef; }}
        .header-critical {{ background: linear-gradient(135deg, #dc3545, #b02a37); color: #ffffff; padding: 20px 25px; }}
        .header-high {{ background: linear-gradient(135deg, #fd7e14, #d9480f); color: #ffffff; padding: 20px 25px; }}
        .header-recovery {{ background: linear-gradient(135deg, #198754, #146c43); color: #ffffff; padding: 20px 25px; }}
        .header-title {{ margin: 0; font-size: 20px; font-weight: 700; }}
        .header-sub {{ margin: 5px 0 0 0; font-size: 13px; opacity: 0.9; }}
        .content {{ padding: 25px; }}
        .section-title {{ font-size: 14px; font-weight: 700; text-transform: uppercase; color: #6c757d; margin-bottom: 12px; border-bottom: 2px solid #e9ecef; padding-bottom: 5px; }}
        .field {{ margin-bottom: 8px; font-size: 13px; }}
        .label {{ font-weight: 600; color: #495057; display: inline-block; width: 140px; }}
        .badge {{ padding: 4px 10px; border-radius: 4px; font-weight: 700; font-size: 12px; color: #ffffff; text-transform: uppercase; }}
        .badge-critical {{ background-color: #dc3545; }}
        .badge-high {{ background-color: #fd7e14; }}
        .badge-recovery {{ background-color: #198754; }}
        .metrics-box {{ background-color: #f8f9fa; color: #212529; font-family: monospace; padding: 14px; border-radius: 6px; font-size: 12px; white-space: pre-wrap; margin: 10px 0 20px 0; border: 1px solid #dee2e6; }}
        .recom-box {{ background-color: #e7f5ff; border-left: 4px solid #1c7ed6; padding: 15px; border-radius: 4px; font-size: 13px; color: #1864ab; }}
        .footer {{ background-color: #f8f9fa; text-align: center; padding: 15px; font-size: 12px; color: #868e96; }}
    </style>
</head>
<body>
    <div class="card">
        <div class="{header_class}">
            <h2 class="header-title">{icon} [{severity}] {alert_type} Notification</h2>
            <p class="header-sub">Server: {hostname} &bull; Source: {source}</p>
        </div>
        <div class="content">
            <div class="section-title">📌 Event Details</div>
            <div class="field"><span class="label">Server Hostname:</span> {hostname}</div>
            <div class="field"><span class="label">Timestamp:</span> {timestamp}</div>
            <div class="field"><span class="label">Alert Type:</span> <strong>{alert_type}</strong></div>
            <div class="field"><span class="label">Severity Level:</span> <span class="badge {badge_class}">{severity}</span></div>
            <div class="field"><span class="label">Description:</span> {description}</div>

            <div class="section-title" style="margin-top:20px;">📊 Current Metrics & Metrics Breakdown</div>
            <div class="metrics-box">{formatted_metrics}</div>

            <div class="section-title">💡 Actionable Recommendation</div>
            <div class="recom-box">
                <strong>Recommended Action:</strong><br>
                {recommendation}
            </div>
        </div>
        <div class="footer">Automated Notification &bull; AI Security Agent</div>
    </div>
</body>
</html>
"""
        return self._send_smtp_message(subject, text_body, html_body)

# Global instance
email_service = EmailService()
