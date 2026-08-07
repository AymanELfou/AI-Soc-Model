"""
main.py
=======
Production Entrypoint for Enterprise VPS Security AI Agent.
Initializes AI Predictor, SQLite Database, Real-Time Log Monitor, DDoS Detector,
Resource Monitor, Alert Manager, Email Alerting, and exposes FastAPI endpoints.
"""

import sys
import time
from fastapi import FastAPI, HTTPException, Query
from pydantic import BaseModel
from typing import Optional, List, Dict, Any

from app.config import HOSTNAME, API_HOST, API_PORT
from app.logger import logger
from app.predictor import predictor
from app.risk_engine import risk_engine
from app.database import db
from app.email_service import email_service
from app.log_parser import log_parser
from app.monitor import monitor
from app.ddos_detector import ddos_detector
from app.resource_monitor import resource_monitor
from app.alert_manager import alert_manager
from app.scheduler import scheduler
from app.health import health_checker

# FastAPI App Instance
app = FastAPI(
    title="Enterprise VPS Security AI Agent",
    description="Autonomous Real-Time Security & VPS Monitoring Agent powered by fine-tuned DistilBERT (48 Attack Classes), DDoS Traffic Detector, and Resource Monitor.",
    version="2.0.0"
)

# API Schemas
class LogAnalyzeRequest(BaseModel):
    log_line: str
    source_log: Optional[str] = "manual_api"

class IncidentResponse(BaseModel):
    id: int
    timestamp: str
    hostname: str
    source_log: str
    raw_log: str
    clean_text: str
    prediction: str
    confidence: float
    risk: str
    status: str

# Startup Lifecycle
@app.on_event("startup")
def startup_event():
    """Application startup initialization handler."""
    logger.info("=" * 70)
    logger.info(f"🛡️ STARTING ENTERPRISE VPS SECURITY AI AGENT on '{HOSTNAME}'")
    logger.info("=" * 70)

    # 1. Check AI Predictor model
    if not predictor.is_loaded:
        logger.critical("Failed to load AI model on startup. Aborting.")
        sys.exit(1)

    # 2. Start Real-time Monitoring Threads
    monitor.start()

    # 3. Start Scheduler (Resources, Heartbeat, Hourly tasks)
    scheduler.start()

    logger.info("✅ All Security Agent subsystems started successfully.")
    logger.info(f"🌐 REST API & Health Endpoint available at http://{API_HOST}:{API_PORT}/health")

# Shutdown Lifecycle
@app.on_event("shutdown")
def shutdown_event():
    """Graceful shutdown handler."""
    logger.info("Stopping Security Agent subsystems...")
    monitor.stop()
    scheduler.stop()
    logger.info("Security Agent stopped cleanly.")

# ════════════════════════════════════════════════════════
# REST API ENDPOINTS
# ════════════════════════════════════════════════════════

@app.get("/")
def root():
    """Root status summary."""
    return {
        "agent": "Enterprise VPS Security AI Agent",
        "hostname": HOSTNAME,
        "status": "RUNNING" if monitor.is_running else "STOPPED",
        "model_loaded": predictor.is_loaded,
        "classes_supported": len(predictor.id2label),
        "health_endpoint": "/health",
        "diagnostics_endpoint": "/api/v1/health",
        "incidents_endpoint": "/api/v1/incidents"
    }

@app.get("/health")
def get_health_simple():
    """
    Standard clean Health Check endpoint returning:
    agent_status, model_status, database_status, log_monitor_status, last_heartbeat, cpu, ram, disk.
    """
    return health_checker.get_simple_health()

@app.get("/api/v1/health")
def get_health_diagnostics():
    """Full comprehensive health diagnostics and host resource metrics."""
    return health_checker.get_full_diagnostics()

@app.get("/api/v1/resources")
def get_resources():
    """Current VPS resource monitoring metrics (CPU, RAM, Disk, System Load, Network I/O)."""
    return resource_monitor.check_resources()

@app.get("/api/v1/ddos")
def get_ddos_status():
    """Current DDoS traffic anomaly analysis and sliding window metrics."""
    return ddos_detector.analyze_traffic()

@app.get("/api/v1/alerts")
def get_active_alerts():
    """Retrieve currently active alerts from database."""
    return db.get_active_alerts()

@app.post("/api/v1/analyze")
def analyze_custom_log(request: LogAnalyzeRequest):
    """
    Manually evaluate a custom log line or payload.
    Processes text through Parser -> AI Predictor -> Risk Engine -> Database -> AlertManager.
    """
    if not request.log_line or not request.log_line.strip():
        raise HTTPException(status_code=400, detail="log_line cannot be empty.")

    # 1. DDoS / Web Traffic Analysis
    ddos_info = ddos_detector.process_log_line(request.log_line, source_log=request.source_log)
    if ddos_info and ddos_info.get("is_anomaly"):
        alert_manager.dispatch_ddos_alert(ddos_info)

    # 2. ML Content Analysis
    clean_text = log_parser.extract_clean_text(request.log_line, source_log=request.source_log)
    if not clean_text:
        clean_text = request.log_line.strip()

    prediction, confidence, top3 = predictor.predict(clean_text)
    risk = risk_engine.calculate_risk(prediction, confidence, clean_text=clean_text)

    # Save to DB
    incident_id = db.save_attack(
        hostname=HOSTNAME,
        source_log=request.source_log,
        raw_log=request.log_line,
        clean_text=clean_text,
        prediction=prediction,
        confidence=confidence,
        risk=risk,
        status="manual_eval"
    )

    # Dispatch alert via AlertManager if High or Critical
    alert_sent = False
    if risk in ("HIGH", "CRITICAL"):
        alert_sent = alert_manager.dispatch_security_attack(
            prediction=prediction,
            confidence=confidence,
            risk=risk,
            source_log=request.source_log,
            raw_log=request.log_line
        )

    return {
        "incident_id": incident_id,
        "source_log": request.source_log,
        "raw_log": request.log_line,
        "clean_text": clean_text,
        "prediction": prediction,
        "confidence": confidence,
        "high_risk_percentage": round(confidence * 100, 2),
        "risk_level": risk,
        "top3": top3,
        "email_alert_sent": alert_sent,
        "ddos_analysis": ddos_info
    }

@app.get("/api/v1/incidents", response_model=List[IncidentResponse])
def get_incidents(
    limit: int = Query(50, ge=1, le=500),
    min_risk: Optional[str] = Query(None, description="Filter by minimum risk level: SAFE, LOW, MEDIUM, HIGH, CRITICAL")
):
    """Retrieve recent security incident records from SQLite database."""
    return db.get_recent_attacks(limit=limit, min_risk=min_risk)

@app.get("/api/v1/stats")
def get_statistics():
    """Retrieve aggregated incident statistics, DDoS counts, and risk breakdown."""
    return db.statistics()

def main():
    """CLI execution entrypoint."""
    import uvicorn
    uvicorn.run("app.main:app", host=API_HOST, port=API_PORT, reload=False)

if __name__ == "__main__":
    main()
