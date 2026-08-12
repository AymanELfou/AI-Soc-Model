"""
security_decision.py
====================
Security Decision Engine — the central intelligence gate between AI model predictions
and the alerting system. Evaluates predictions with confidence thresholds to prevent
false positive email alerts from low-confidence AI predictions.

Architecture:
    AI Prediction + Confidence → Security Decision Engine → IGNORE / LOG_ONLY / ALERT

Decision Matrix:
    Benign prediction             → IGNORE (SAFE, no email)
    Attack + confidence < 40%     → IGNORE (SAFE, no email)
    Attack + confidence 40-70%    → LOG_ONLY (UNKNOWN, no email)
    Attack + confidence 70-85%    → ALERT (MEDIUM/HIGH based on category, email only for HIGH+)
    Attack + confidence 85-95%    → ALERT (HIGH, email sent)
    Attack + confidence >= 95%    → ALERT (CRITICAL, email sent)
"""

from typing import Dict, Any, Optional
from app.config import AI_CONFIDENCE_THRESHOLD, SECURITY_DECISION_ENGINE_ENABLED
from app.logger import logger

# Risk severity hierarchy for comparisons
_SEVERITY_ORDER = {"SAFE": 0, "LOW": 1, "UNKNOWN": 2, "MEDIUM": 3, "HIGH": 4, "CRITICAL": 5}

# Category base severity mapping (mirrors risk_engine.py for decision-making)
_CRITICAL_CATEGORIES = {
    "ReverseShell", "Kernel_Exploit", "PrivilegeEscalation", "Ransomware",
    "Linux_Command_Injection", "Command_Injection", "Malicious_System_Command",
    "WebShell", "Persistence", "XXE", "Insecure_Deserialization"
}
_HIGH_CATEGORIES = {
    "SQL_Injection", "XSS", "PathTraversal", "Docker_Abuse", "SSH_BruteForce",
    "SSH_Login_Attack", "FileUpload_Attack", "NoSQL_Injection", "SSTI",
    "Cryptomining", "Linux_Malware", "Malware", "Cron_Abuse",
    "Unauthorized_File_Modification"
}


def normalize_confidence(confidence: float) -> float:
    """
    Normalize confidence value to a consistent 0.0-1.0 range.
    
    Handles cases where confidence might be represented as:
    - 0.974 (already normalized, 97.4%)
    - 97.4 (percentage, needs division by 100)
    - 9.74 (percentage, needs division by 100)
    
    Returns:
        Float in range [0.0, 1.0]
    """
    if confidence > 1.0:
        # Value is in percentage form (e.g. 97.4 or 9.74)
        return confidence / 100.0
    return max(0.0, min(1.0, confidence))


def make_decision(
    predicted_label: str,
    confidence: float,
    raw_log: str = "",
    source_log: str = "",
    category_base_severity: str = "MEDIUM"
) -> Dict[str, Any]:
    """
    Core Security Decision Engine.
    
    Takes AI model prediction output and returns a structured security decision
    determining whether to IGNORE, LOG_ONLY, or ALERT.
    
    Args:
        predicted_label: The attack category predicted by the AI model
        confidence: Raw confidence score from the model
        raw_log: Original raw log line (for context logging)
        source_log: Source log file path
        category_base_severity: Base severity from risk_engine CATEGORY_BASE_SEVERITY
        
    Returns:
        SecurityDecision dict with keys:
            decision: "IGNORE" | "LOG_ONLY" | "ALERT"
            is_attack: bool
            label: str (final label)
            confidence: float (normalized 0.0-1.0)
            severity: str (SAFE|LOW|UNKNOWN|MEDIUM|HIGH|CRITICAL)
            reason: str (human-readable explanation)
            email_required: bool
    """
    # Normalize confidence to 0.0-1.0 range
    conf = normalize_confidence(confidence)
    
    # If engine is disabled, pass through with original behavior
    if not SECURITY_DECISION_ENGINE_ENABLED:
        is_attack = predicted_label != "Benign"
        return {
            "decision": "ALERT" if is_attack else "IGNORE",
            "is_attack": is_attack,
            "label": predicted_label,
            "confidence": conf,
            "severity": category_base_severity if is_attack else "SAFE",
            "reason": "Security Decision Engine disabled — passthrough mode",
            "email_required": is_attack and category_base_severity in ("HIGH", "CRITICAL")
        }

    # ── Rule 1: Benign prediction ──
    if predicted_label == "Benign":
        return _decision(
            decision="IGNORE",
            is_attack=False,
            label="Benign",
            confidence=conf,
            severity="SAFE",
            reason="AI model classified as Benign",
            email_required=False
        )

    # ── Rule 2: Very low confidence (< 40%) → IGNORE ──
    if conf < 0.40:
        return _decision(
            decision="IGNORE",
            is_attack=False,
            label=predicted_label,
            confidence=conf,
            severity="SAFE",
            reason=f"Very low confidence ({conf*100:.1f}%) — prediction unreliable, ignoring",
            email_required=False
        )

    # ── Rule 3: Low confidence (40-70%) → LOG_ONLY ──
    if conf < AI_CONFIDENCE_THRESHOLD:
        return _decision(
            decision="LOG_ONLY",
            is_attack=False,
            label=predicted_label,
            confidence=conf,
            severity="UNKNOWN",
            reason=f"Confidence ({conf*100:.1f}%) below threshold ({AI_CONFIDENCE_THRESHOLD*100:.0f}%) — logged for review only",
            email_required=False
        )

    # ── Above threshold: confidence >= AI_CONFIDENCE_THRESHOLD ──
    # Determine final severity based on confidence bands AND category base severity
    
    # Rule 4: confidence 70-85% → MEDIUM (email only if base severity is CRITICAL)
    if conf < 0.85:
        final_severity = "MEDIUM"
        # Escalate to HIGH if the category is inherently CRITICAL
        if category_base_severity == "CRITICAL":
            final_severity = "HIGH"
        
        email_needed = final_severity in ("HIGH", "CRITICAL")
        return _decision(
            decision="ALERT",
            is_attack=True,
            label=predicted_label,
            confidence=conf,
            severity=final_severity,
            reason=f"Moderate confidence attack ({conf*100:.1f}%) — category: {predicted_label}",
            email_required=email_needed
        )

    # Rule 5: confidence 85-95% → HIGH
    if conf < 0.95:
        final_severity = "HIGH"
        # Escalate to CRITICAL if category is CRITICAL
        if category_base_severity == "CRITICAL":
            final_severity = "CRITICAL"
        
        return _decision(
            decision="ALERT",
            is_attack=True,
            label=predicted_label,
            confidence=conf,
            severity=final_severity,
            reason=f"High confidence attack ({conf*100:.1f}%) — category: {predicted_label}",
            email_required=True
        )

    # Rule 6: confidence >= 95% → CRITICAL
    final_severity = "CRITICAL"
    # For non-critical categories at extreme confidence, keep at HIGH minimum
    if category_base_severity in ("LOW", "MEDIUM"):
        final_severity = "HIGH"
    
    return _decision(
        decision="ALERT",
        is_attack=True,
        label=predicted_label,
        confidence=conf,
        severity=final_severity,
        reason=f"Very high confidence attack ({conf*100:.1f}%) — category: {predicted_label}",
        email_required=True
    )


def _decision(
    decision: str,
    is_attack: bool,
    label: str,
    confidence: float,
    severity: str,
    reason: str,
    email_required: bool
) -> Dict[str, Any]:
    """Build and log a structured SecurityDecision dict."""
    result = {
        "decision": decision,
        "is_attack": is_attack,
        "label": label,
        "confidence": confidence,
        "severity": severity,
        "reason": reason,
        "email_required": email_required
    }

    # Structured decision logging for traceability
    log_level = "info" if decision == "ALERT" else "debug"
    log_msg = (
        f"[DECISION] Prediction: {label} | Confidence: {confidence*100:.1f}% | "
        f"Decision: {decision} | Severity: {severity} | "
        f"Email: {'SENT' if email_required else 'NOT_SENT'} | "
        f"Reason: {reason}"
    )
    
    if log_level == "info":
        logger.info(log_msg)
    else:
        logger.debug(log_msg)

    return result


def get_category_base_severity(predicted_label: str) -> str:
    """Get the base severity for a predicted attack category."""
    if predicted_label in _CRITICAL_CATEGORIES:
        return "CRITICAL"
    elif predicted_label in _HIGH_CATEGORIES:
        return "HIGH"
    elif predicted_label == "Benign":
        return "SAFE"
    else:
        return "MEDIUM"
