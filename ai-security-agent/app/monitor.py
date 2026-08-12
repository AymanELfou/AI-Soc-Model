"""
monitor.py
==========
Real-time tail monitoring engine for Linux log files and sources.
Uses non-blocking tail -F style streaming without rereading whole files.
Integrates ML content analysis and DDoS traffic rate anomaly detection.
"""

import os
import time
import threading
from typing import List, Callable, Dict, Optional

from app.config import DEFAULT_LOG_SOURCES, HOSTNAME, POLL_INTERVAL_SECONDS
from app.log_pre_filter import log_pre_filter
from app.log_parser import log_parser
from app.predictor import predictor
from app.risk_engine import risk_engine, CATEGORY_BASE_SEVERITY
from app.security_decision import make_decision, get_category_base_severity
from app.database import db
from app.ddos_detector import ddos_detector
from app.alert_manager import alert_manager
from app.logger import logger

class LogTailerThread(threading.Thread):
    """
    Background worker thread that tails a single log file (tail -F behavior).
    Tracks seek offsets to process ONLY newly appended lines.
    """

    def __init__(self, file_path: str, callback: Callable[[str, str], None]):
        super().__init__(daemon=True, name=f"Tailer-{os.path.basename(file_path)}")
        self.file_path = file_path
        self.callback = callback
        self.running = True
        self.current_offset = 0

    def run(self):
        logger.info(f"Started real-time monitoring thread for: '{self.file_path}'")

        # Wait until file exists
        while self.running and not os.path.exists(self.file_path):
            time.sleep(2.0)

        if not self.running:
            return

        # Move seek pointer to END of file on startup (do not process old logs)
        try:
            with open(self.file_path, "r", encoding="utf-8", errors="replace") as f:
                f.seek(0, os.SEEK_END)
                self.current_offset = f.tell()
        except Exception as e:
            logger.error(f"Error opening '{self.file_path}': {e}")

        while self.running:
            try:
                if not os.path.exists(self.file_path):
                    time.sleep(POLL_INTERVAL_SECONDS)
                    continue

                with open(self.file_path, "r", encoding="utf-8", errors="replace") as f:
                    f.seek(self.current_offset)
                    lines = f.readlines()
                    self.current_offset = f.tell()

                    for line in lines:
                        if line and line.strip():
                            self.callback(line.strip(), self.file_path)

            except Exception as e:
                logger.error(f"Error reading tail of '{self.file_path}': {e}")

            time.sleep(POLL_INTERVAL_SECONDS)

    def stop(self):
        self.running = False


class LogMonitorManager:
    """
    Manager coordinating multiple log tailers and handling event processing pipeline.
    
    NEW Pipeline Architecture:
    Raw Log ──► Pre-Filter ──► Parser ──► AI Model ──► Security Decision Engine ──► Risk Engine ──► DB & AlertManager
                   │                                         │
                   └─ BENIGN → skip AI                       ├─ IGNORE → log only
                                                             ├─ LOG_ONLY → save decision, no alert
                                                             └─ ALERT → Risk Engine → AlertManager → Email
    """

    def __init__(self, log_sources: List[str] = None):
        self.log_sources = log_sources or DEFAULT_LOG_SOURCES
        self.tailers: Dict[str, LogTailerThread] = {}
        self.is_running = False
        self.processed_count = 0
        self.incident_count = 0
        self.benign_filtered_count = 0

    def process_log_line(self, raw_line: str, source_log: str):
        """Pipeline handler triggered for every newly appended log line."""
        self.processed_count += 1

        # ── Step 1: Traffic Volume DDoS Detection (for Nginx/Apache Web access logs) ──
        # DDoS detection operates independently from the NLP pipeline
        ddos_info = ddos_detector.process_log_line(raw_line, source_log=source_log)
        if ddos_info and ddos_info.get("is_anomaly"):
            alert_manager.dispatch_ddos_alert(ddos_info)

        # ── Step 2: Log Pre-Filter — identify clearly benign events ──
        pre_filter_result = log_pre_filter.classify(raw_line)
        if pre_filter_result["decision"] == "BENIGN":
            self.benign_filtered_count += 1
            return  # Skip AI model entirely — clearly benign log

        # ── Step 3: Parse and extract clean security payload for ML model ──
        clean_text = log_parser.extract_clean_text(raw_line, source_log=source_log)
        if not clean_text:
            return  # Ignored by parser (noise filter)

        # ── Step 4: Send to AI Model for Prediction ──
        prediction, confidence, top3 = predictor.predict(clean_text)

        # ── Step 5: Security Decision Engine ──
        category_severity = CATEGORY_BASE_SEVERITY.get(prediction, "MEDIUM")
        decision = make_decision(
            predicted_label=prediction,
            confidence=confidence,
            raw_log=raw_line,
            source_log=source_log,
            category_base_severity=category_severity
        )

        # ── Step 6: Save security decision to audit trail ──
        db.save_security_decision(
            hostname=HOSTNAME,
            source_log=source_log,
            raw_log=raw_line,
            predicted_label=prediction,
            confidence=confidence,
            decision=decision["decision"],
            severity=decision["severity"],
            reason=decision["reason"],
            email_sent=decision["email_required"]
        )

        # ── Step 7: Handle decision outcomes ──
        if decision["decision"] == "IGNORE":
            # Low confidence or benign — do not save as attack, do not alert
            return

        if decision["decision"] == "LOG_ONLY":
            # Suspicious but below threshold — save to attack_logs for review, no alert
            db.save_attack(
                hostname=HOSTNAME,
                source_log=source_log,
                raw_log=raw_line,
                clean_text=clean_text,
                prediction=prediction,
                confidence=confidence,
                risk="SAFE",
                status="low_confidence"
            )
            return

        # ── Step 8: ALERT — confirmed attack with sufficient confidence ──
        # Calculate final risk using the Risk Engine
        risk = risk_engine.calculate_risk(prediction, confidence, clean_text=clean_text)

        # Use the higher severity between risk engine and decision engine
        final_risk = decision["severity"]
        risk_order = {"SAFE": 0, "LOW": 1, "UNKNOWN": 2, "MEDIUM": 3, "HIGH": 4, "CRITICAL": 5}
        if risk_order.get(risk, 0) > risk_order.get(final_risk, 0):
            final_risk = risk

        # Save to database as a confirmed incident
        self.incident_count += 1
        incident_id = db.save_attack(
            hostname=HOSTNAME,
            source_log=source_log,
            raw_log=raw_line,
            clean_text=clean_text,
            prediction=prediction,
            confidence=confidence,
            risk=final_risk,
            status="new"
        )

        logger.info(
            f"Incident #{incident_id} [{final_risk}] {prediction} (conf: {confidence*100:.1f}%) on {source_log}"
        )

        # ── Step 9: Dispatch Alert via Centralized AlertManager if email required ──
        if decision["email_required"] and final_risk in ("HIGH", "CRITICAL"):
            alert_manager.dispatch_security_attack(
                prediction=prediction,
                confidence=confidence,
                risk=final_risk,
                source_log=source_log,
                raw_log=raw_line
            )

    def add_log_source(self, log_path: str):
        """Dynamically add a new log source to monitor at runtime."""
        if log_path in self.tailers:
            logger.warning(f"Log source already monitored: {log_path}")
            return

        tailer = LogTailerThread(log_path, callback=self.process_log_line)
        self.tailers[log_path] = tailer
        if self.is_running:
            tailer.start()
        logger.info(f"Added new log source to monitor: {log_path}")

    def start(self):
        """Start all monitoring threads."""
        if self.is_running:
            return

        self.is_running = True
        logger.info(f"Starting AI Security Agent real-time monitoring for {len(self.log_sources)} log sources...")

        for source in self.log_sources:
            tailer = LogTailerThread(source, callback=self.process_log_line)
            self.tailers[source] = tailer
            tailer.start()

    def stop(self):
        """Stop all monitoring threads gracefully."""
        logger.info("Stopping log monitor manager...")
        self.is_running = False
        for path, tailer in self.tailers.items():
            tailer.stop()
        logger.info("All log tailer threads stopped.")

# Global instance
monitor = LogMonitorManager()
