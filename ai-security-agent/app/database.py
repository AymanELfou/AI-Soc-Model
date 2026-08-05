"""
database.py
===========
SQLite Database manager for saving incidents, querying recent attacks, and computing statistics.
"""

import os
import sqlite3
from typing import List, Dict, Any, Optional
from datetime import datetime, timedelta
from app.config import DB_PATH, DATABASE_DIR
from app.logger import logger

class DatabaseManager:
    """Manages SQLite storage for attack incidents and security events."""

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
        """Initialize attack_logs table and performance indexes."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
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
            # Create indexes for fast querying
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_timestamp ON attack_logs(timestamp);")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_risk ON attack_logs(risk);")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_prediction ON attack_logs(prediction);")
            conn.commit()
            logger.info(f"Database initialized at {self.db_path}")

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
        """Save an incident log entry into the attack_logs table."""
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

    def statistics(self) -> Dict[str, Any]:
        """Compute aggregated statistics for dashboard and reporting."""
        try:
            with self._get_connection() as conn:
                cursor = conn.cursor()

                # Total count
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

                # Count in last 24h
                twenty_four_hours_ago = (datetime.now() - timedelta(hours=24)).strftime("%Y-%m-%d %H:%M:%S")
                cursor.execute("SELECT COUNT(*) FROM attack_logs WHERE timestamp >= ?;", (twenty_four_hours_ago,))
                last_24h_count = cursor.fetchone()[0]

                return {
                    "total_incidents": total_attacks,
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
                "last_24h_incidents": 0,
                "risk_breakdown": {},
                "top_attack_types": {}
            }

# Default global instance
db = DatabaseManager()
