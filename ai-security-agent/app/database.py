"""
database.py
===========
SQLite Database manager for saving attack incidents, DDoS events, resource alerts,
system health snapshots, and centralized alert tracking.
"""

import os
import json
import sqlite3
from typing import List, Dict, Any, Optional
from datetime import datetime, timedelta
from app.config import DB_PATH, DATABASE_DIR
from app.logger import logger

class DatabaseManager:
    """Manages SQLite storage for incidents, DDoS traffic, resource alerts, and system health."""

    def __init__(self, db_path: str = DB_PATH):
        self.db_path = db_path
        os.makedirs(os.path.dirname(self.db_path), exist_ok=True)
        self._init_db()

    def _get_connection(self) -> sqlite3.Connection:
        """Create and return a database connection with dictionary rows."""
        conn = sqlite3.connect(self.db_path, timeout=10.0)
        conn.row_factory = sqlite3.Row
        return conn

    def _init_db(self):
        """Initialize all required SQLite tables and performance indexes."""
        with self._get_connection() as conn:
            cursor = conn.cursor()

            # 1. Existing Attack Logs Table (Preserved 100%)
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS attack_logs (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT NOT NULL,
                    hostname TEXT NOT NULL,
                    source_log TEXT NOT NULL,
                    raw_log TEXT NOT NULL,
                    clean_text TEXT NOT NULL,
                    prediction TEXT NOT NULL,
                    confidence REAL NOT NULL,
                    risk TEXT NOT NULL,
                    status TEXT NOT NULL DEFAULT 'new'
                );
            """)

            # 2. Centralized Alerts Table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS alerts (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT NOT NULL,
                    hostname TEXT NOT NULL,
                    alert_type TEXT NOT NULL,
                    severity TEXT NOT NULL,
                    description TEXT NOT NULL,
                    source TEXT NOT NULL,
                    metrics TEXT,
                    status TEXT NOT NULL DEFAULT 'ACTIVE',
                    resolved_at TEXT
                );
            """)

            # 3. Security Events Table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS security_events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT NOT NULL,
                    hostname TEXT NOT NULL,
                    source_log TEXT NOT NULL,
                    raw_log TEXT NOT NULL,
                    clean_text TEXT NOT NULL,
                    prediction TEXT NOT NULL,
                    confidence REAL NOT NULL,
                    risk TEXT NOT NULL,
                    status TEXT NOT NULL DEFAULT 'new'
                );
            """)

            # 4. Resource Alerts Table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS resource_alerts (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT NOT NULL,
                    hostname TEXT NOT NULL,
                    metric_name TEXT NOT NULL,
                    current_value REAL NOT NULL,
                    threshold_value REAL NOT NULL,
                    severity TEXT NOT NULL,
                    status TEXT NOT NULL DEFAULT 'ACTIVE',
                    resolved_at TEXT
                );
            """)

            # 5. DDoS Events Table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS ddos_events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT NOT NULL,
                    hostname TEXT NOT NULL,
                    pattern_type TEXT NOT NULL,
                    requests_count INTEGER NOT NULL,
                    window_seconds INTEGER NOT NULL,
                    top_ip TEXT,
                    top_endpoint TEXT,
                    risk_level TEXT NOT NULL,
                    metrics_json TEXT
                );
            """)

            # 6. System Health Snapshots Table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS system_health (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT NOT NULL,
                    hostname TEXT NOT NULL,
                    cpu_percent REAL NOT NULL,
                    ram_percent REAL NOT NULL,
                    disk_percent REAL NOT NULL,
                    load_avg TEXT,
                    agent_status TEXT NOT NULL,
                    heartbeat_time TEXT NOT NULL
                );
            """)

            # 7. Security Decisions Table (Decision Engine audit trail)
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS security_decisions (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT NOT NULL,
                    hostname TEXT NOT NULL,
                    source_log TEXT NOT NULL,
                    raw_log TEXT NOT NULL,
                    predicted_label TEXT NOT NULL,
                    confidence REAL NOT NULL,
                    decision TEXT NOT NULL,
                    severity TEXT NOT NULL,
                    reason TEXT NOT NULL,
                    email_sent INTEGER NOT NULL DEFAULT 0
                );
            """)

            # Indexes for high performance
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_timestamp ON attack_logs(timestamp);")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_risk ON attack_logs(risk);")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_alerts_status ON alerts(status);")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_alerts_type ON alerts(alert_type);")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_ddos_time ON ddos_events(timestamp);")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_resource_status ON resource_alerts(status);")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_decisions_time ON security_decisions(timestamp);")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_decisions_decision ON security_decisions(decision);")

            conn.commit()
            logger.info(f"Database initialized with all tables at {self.db_path}")

    # ════════════════════════════════════════════════════════
    # ATTACK LOGS METHODS (Preserved)
    # ════════════════════════════════════════════════════════

    def save_attack(
        self,
        hostname: str,
        source_log: str,
        raw_log: str,
        clean_text: str,
        prediction: str,
        confidence: float,
        risk: str,
        status: str = "new",
        timestamp: Optional[str] = None
    ) -> int:
        """Save an incident log entry into attack_logs and security_events tables."""
        if not timestamp:
            timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        query = """
            INSERT INTO attack_logs 
            (timestamp, hostname, source_log, raw_log, clean_text, prediction, confidence, risk, status)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?);
        """
        try:
            with self._get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute(
                    query,
                    (timestamp, hostname, source_log, raw_log, clean_text, prediction, confidence, risk, status)
                )
                cursor.execute(
                    """INSERT INTO security_events 
                       (timestamp, hostname, source_log, raw_log, clean_text, prediction, confidence, risk, status)
                       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?);""",
                    (timestamp, hostname, source_log, raw_log, clean_text, prediction, confidence, risk, status)
                )
                conn.commit()
                incident_id = cursor.lastrowid
                logger.debug(f"Saved incident #{incident_id}: [{risk}] {prediction} from {source_log}")
                return incident_id
        except Exception as e:
            logger.error(f"Error saving attack to database: {e}")
            return -1

    def get_recent_attacks(self, limit: int = 50, min_risk: Optional[str] = None) -> List[Dict[str, Any]]:
        """Retrieve recent attack logs with optional risk filtering."""
        query = "SELECT * FROM attack_logs"
        params = []

        if min_risk:
            risk_levels = ["SAFE", "LOW", "MEDIUM", "HIGH", "CRITICAL"]
            if min_risk in risk_levels:
                allowed_risks = risk_levels[risk_levels.index(min_risk):]
                placeholders = ",".join("?" for _ in allowed_risks)
                query += f" WHERE risk IN ({placeholders})"
                params.extend(allowed_risks)

        query += " ORDER BY id DESC LIMIT ?;"
        params.append(limit)

        try:
            with self._get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute(query, params)
                rows = cursor.fetchall()
                return [dict(row) for row in rows]
        except Exception as e:
            logger.error(f"Error fetching recent attacks: {e}")
            return []

    # ════════════════════════════════════════════════════════
    # ALERTS & RECOVERY METHODS
    # ════════════════════════════════════════════════════════

    def save_alert(
        self,
        hostname: str,
        alert_type: str,
        severity: str,
        description: str,
        source: str,
        metrics: Dict[str, Any],
        status: str = "ACTIVE"
    ) -> int:
        """Save a centralized alert record into the alerts table."""
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        metrics_json = json.dumps(metrics) if isinstance(metrics, dict) else str(metrics)
        query = """
            INSERT INTO alerts (timestamp, hostname, alert_type, severity, description, source, metrics, status)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?);
        """
        try:
            with self._get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute(query, (timestamp, hostname, alert_type, severity, description, source, metrics_json, status))
                conn.commit()
                return cursor.lastrowid
        except Exception as e:
            logger.error(f"Error saving alert to database: {e}")
            return -1

    def resolve_alert(self, alert_type: str, source: str) -> bool:
        """Mark active alerts of a given type and source as RESOLVED."""
        resolved_at = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        query = """
            UPDATE alerts SET status = 'RESOLVED', resolved_at = ?
            WHERE alert_type = ? AND source = ? AND status = 'ACTIVE';
        """
        try:
            with self._get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute(query, (resolved_at, alert_type, source))
                conn.commit()
                return True
        except Exception as e:
            logger.error(f"Error resolving alert: {e}")
            return False

    def get_active_alerts(self) -> List[Dict[str, Any]]:
        """Retrieve all currently active alerts."""
        try:
            with self._get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute("SELECT * FROM alerts WHERE status = 'ACTIVE' ORDER BY id DESC;")
                return [dict(row) for row in cursor.fetchall()]
        except Exception as e:
            logger.error(f"Error fetching active alerts: {e}")
            return []

    # ════════════════════════════════════════════════════════
    # DDOS & RESOURCE METRIC METHODS
    # ════════════════════════════════════════════════════════

    def save_ddos_event(
        self,
        hostname: str,
        pattern_type: str,
        requests_count: int,
        window_seconds: int,
        top_ip: str,
        top_endpoint: str,
        risk_level: str,
        metrics: Dict[str, Any]
    ) -> int:
        """Save a DDoS event record into ddos_events table."""
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        metrics_json = json.dumps(metrics) if isinstance(metrics, dict) else str(metrics)
        query = """
            INSERT INTO ddos_events 
            (timestamp, hostname, pattern_type, requests_count, window_seconds, top_ip, top_endpoint, risk_level, metrics_json)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?);
        """
        try:
            with self._get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute(
                    query,
                    (timestamp, hostname, pattern_type, requests_count, window_seconds, top_ip, top_endpoint, risk_level, metrics_json)
                )
                conn.commit()
                return cursor.lastrowid
        except Exception as e:
            logger.error(f"Error saving DDoS event to database: {e}")
            return -1

    def save_resource_alert(
        self,
        hostname: str,
        metric_name: str,
        current_value: float,
        threshold_value: float,
        severity: str,
        status: str = "ACTIVE"
    ) -> int:
        """Save a resource usage alert into resource_alerts table."""
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        query = """
            INSERT INTO resource_alerts 
            (timestamp, hostname, metric_name, current_value, threshold_value, severity, status)
            VALUES (?, ?, ?, ?, ?, ?, ?);
        """
        try:
            with self._get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute(query, (timestamp, hostname, metric_name, current_value, threshold_value, severity, status))
                conn.commit()
                return cursor.lastrowid
        except Exception as e:
            logger.error(f"Error saving resource alert to database: {e}")
            return -1

    def save_health_snapshot(
        self,
        hostname: str,
        cpu_percent: float,
        ram_percent: float,
        disk_percent: float,
        load_avg: str,
        agent_status: str,
        heartbeat_time: str
    ) -> int:
        """Save a periodic health snapshot into system_health table."""
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        query = """
            INSERT INTO system_health 
            (timestamp, hostname, cpu_percent, ram_percent, disk_percent, load_avg, agent_status, heartbeat_time)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?);
        """
        try:
            with self._get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute(query, (timestamp, hostname, cpu_percent, ram_percent, disk_percent, load_avg, agent_status, heartbeat_time))
                conn.commit()
                return cursor.lastrowid
        except Exception as e:
            logger.error(f"Error saving system health snapshot: {e}")
            return -1

    # ════════════════════════════════════════════════════════
    # SECURITY DECISIONS METHODS
    # ════════════════════════════════════════════════════════

    def save_security_decision(
        self,
        hostname: str,
        source_log: str,
        raw_log: str,
        predicted_label: str,
        confidence: float,
        decision: str,
        severity: str,
        reason: str,
        email_sent: bool = False
    ) -> int:
        """Save a Security Decision Engine result for audit trail."""
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        query = """
            INSERT INTO security_decisions
            (timestamp, hostname, source_log, raw_log, predicted_label, confidence, decision, severity, reason, email_sent)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
        """
        try:
            with self._get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute(query, (
                    timestamp, hostname, source_log, raw_log,
                    predicted_label, confidence, decision, severity,
                    reason, 1 if email_sent else 0
                ))
                conn.commit()
                return cursor.lastrowid
        except Exception as e:
            logger.error(f"Error saving security decision to database: {e}")
            return -1

    def get_recent_decisions(self, limit: int = 50, decision_filter: Optional[str] = None) -> List[Dict[str, Any]]:
        """Retrieve recent security decisions with optional decision type filtering."""
        query = "SELECT * FROM security_decisions"
        params = []

        if decision_filter:
            query += " WHERE decision = ?"
            params.append(decision_filter)

        query += " ORDER BY id DESC LIMIT ?;"
        params.append(limit)

        try:
            with self._get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute(query, params)
                rows = cursor.fetchall()
                return [dict(row) for row in rows]
        except Exception as e:
            logger.error(f"Error fetching recent decisions: {e}")
            return []

    # ════════════════════════════════════════════════════════
    # AGGREGATED STATISTICS
    # ════════════════════════════════════════════════════════

    def statistics(self) -> Dict[str, Any]:
        """Compute aggregated statistics across security, DDoS, and resources."""
        try:
            with self._get_connection() as conn:
                cursor = conn.cursor()

                # Total attack count
                cursor.execute("SELECT COUNT(*) FROM attack_logs;")
                total_attacks = cursor.fetchone()[0]

                # Count by Risk Level
                cursor.execute("SELECT risk, COUNT(*) FROM attack_logs GROUP BY risk;")
                risk_counts = {row[0]: row[1] for row in cursor.fetchall()}

                # Top 10 Predictions
                cursor.execute("""
                    SELECT prediction, COUNT(*) as cnt 
                    FROM attack_logs 
                    WHERE prediction != 'Benign'
                    GROUP BY prediction 
                    ORDER BY cnt DESC 
                    LIMIT 10;
                """)
                top_attacks = {row[0]: row[1] for row in cursor.fetchall()}

                # Total DDoS Events
                cursor.execute("SELECT COUNT(*) FROM ddos_events;")
                total_ddos = cursor.fetchone()[0]

                # Total Resource Alerts
                cursor.execute("SELECT COUNT(*) FROM resource_alerts;")
                total_resource_alerts = cursor.fetchone()[0]

                # Count in last 24h
                twenty_four_hours_ago = (datetime.now() - timedelta(hours=24)).strftime("%Y-%m-%d %H:%M:%S")
                cursor.execute("SELECT COUNT(*) FROM attack_logs WHERE timestamp >= ?;", (twenty_four_hours_ago,))
                last_24h_count = cursor.fetchone()[0]

                return {
                    "total_incidents": total_attacks,
                    "total_ddos_events": total_ddos,
                    "total_resource_alerts": total_resource_alerts,
                    "last_24h_incidents": last_24h_count,
                    "risk_breakdown": {
                        "CRITICAL": risk_counts.get("CRITICAL", 0),
                        "HIGH": risk_counts.get("HIGH", 0),
                        "MEDIUM": risk_counts.get("MEDIUM", 0),
                        "LOW": risk_counts.get("LOW", 0),
                        "SAFE": risk_counts.get("SAFE", 0)
                    },
                    "top_attack_types": top_attacks
                }
        except Exception as e:
            logger.error(f"Error gathering database statistics: {e}")
            return {
                "total_incidents": 0,
                "total_ddos_events": 0,
                "total_resource_alerts": 0,
                "last_24h_incidents": 0,
                "risk_breakdown": {},
                "top_attack_types": {}
            }

# Default global instance
db = DatabaseManager()
