"""
risk_engine.py
==============
Centralized Risk Engine evaluating Attack Category, Confidence Score, and Custom Rules.
Returns risk level: SAFE, LOW, MEDIUM, HIGH, CRITICAL.
"""

from typing import Dict, Tuple

# Base severity matrix for 48 attack categories
CATEGORY_BASE_SEVERITY: Dict[str, str] = {
    # === CRITICAL ===
    "ReverseShell": "CRITICAL",
    "Kernel_Exploit": "CRITICAL",
    "PrivilegeEscalation": "CRITICAL",
    "Ransomware": "CRITICAL",
    "Linux_Command_Injection": "CRITICAL",
    "Command_Injection": "CRITICAL",
    "Malicious_System_Command": "CRITICAL",
    "WebShell": "CRITICAL",
    "Persistence": "CRITICAL",
    "XXE": "CRITICAL",
    "Insecure_Deserialization": "CRITICAL",

    # === HIGH ===
    "SQL_Injection": "HIGH",
    "XSS": "HIGH",
    "PathTraversal": "HIGH",
    "Docker_Abuse": "HIGH",
    "SSH_BruteForce": "HIGH",
    "SSH_Login_Attack": "HIGH",
    "FileUpload_Attack": "HIGH",
    "NoSQL_Injection": "HIGH",
    "SSTI": "HIGH",
    "Cryptomining": "HIGH",
    "Linux_Malware": "HIGH",
    "Malware": "HIGH",
    "Cron_Abuse": "HIGH",
    "Unauthorized_File_Modification": "HIGH",

    # === MEDIUM ===
    "PortScanning": "MEDIUM",
    "BruteForce": "MEDIUM",
    "Failed_Login": "MEDIUM",
    "CredentialStuffing": "MEDIUM",
    "Root_Login_Attempt": "MEDIUM",
    "Lateral_Movement": "MEDIUM",
    "Suspicious_Bash_Command": "MEDIUM",
    "Suspicious_Process": "MEDIUM",
    "CSRF": "MEDIUM",
    "Header_Injection": "MEDIUM",
    "CRLF_Injection": "MEDIUM",
    "GraphQL_Injection": "MEDIUM",
    "OpenRedirect": "MEDIUM",
    "Prototype_Pollution": "MEDIUM",
    "LDAP_Injection": "MEDIUM",
    "XPATH_Injection": "MEDIUM",
    "DDoS": "MEDIUM",

    # === LOW ===
    "System_Enumeration": "LOW",
    "Suspicious_Input": "LOW",
    "Malicious_HTTP": "LOW",

    # === SAFE ===
    "Benign": "SAFE",
}

class RiskEngine:
    """Evaluates security events and computes normalized risk ratings."""

    @staticmethod
    def calculate_risk(prediction: str, confidence: float, clean_text: str = "") -> str:
        """
        Calculates final risk level considering:
        - Category base severity
        - Prediction confidence score
        - Custom heuristic rules
        
        Returns:
            One of ['SAFE', 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL']
        """
        if prediction == "Benign":
            # If AI classified as Benign with high confidence -> SAFE
            if confidence >= 0.70:
                return "SAFE"
            else:
                return "LOW"

        base_risk = CATEGORY_BASE_SEVERITY.get(prediction, "MEDIUM")

        # Custom Rule 1: High-confidence escalation
        # If prediction is HIGH risk and confidence >= 90%, escalate to CRITICAL if payload contains system paths
        if base_risk == "HIGH" and confidence >= 0.90:
            if any(path in clean_text.lower() for path in ["/etc/shadow", "/etc/passwd", "root", "/var/run/docker.sock"]):
                base_risk = "CRITICAL"

        # Custom Rule 2: Confidence penalty adjustment
        # If confidence is below 50%, reduce risk level by 1 tier to avoid false positive alarms
        if confidence < 0.50:
            risk_downgrade = {
                "CRITICAL": "HIGH",
                "HIGH": "MEDIUM",
                "MEDIUM": "LOW",
                "LOW": "SAFE",
                "SAFE": "SAFE"
            }
            base_risk = risk_downgrade.get(base_risk, base_risk)

        return base_risk

# Global RiskEngine helper
risk_engine = RiskEngine()
