"""
log_pre_filter.py
=================
Contextual pre-filter for identifying clearly benign Linux/Docker/systemd log events
BEFORE sending them to the AI model. Uses full-pattern matching with suspicious overrides
to avoid filtering out legitimate security events.

Architecture:
    Raw Log → Log Pre-Filter → BENIGN (skip AI) / PASS_TO_AI / SUSPICIOUS (fast-track AI)
"""

import re
from typing import Dict, Any
from app.config import BENIGN_LOG_FILTER_ENABLED
from app.logger import logger

# ════════════════════════════════════════════════════════
# BENIGN LOG PATTERNS (contextual, not simple substring)
# ════════════════════════════════════════════════════════
# Each pattern must match a complete, clearly benign context.
# NEVER filter on just a service name like "systemd" — always match the full action.

BENIGN_PATTERNS = [
    # systemd lifecycle events
    re.compile(r"systemd\[\d+\]:\s+\S+\.mount:\s+Succeeded", re.IGNORECASE),
    re.compile(r"systemd\[\d+\]:\s+Started\s+", re.IGNORECASE),
    re.compile(r"systemd\[\d+\]:\s+Finished\s+", re.IGNORECASE),
    re.compile(r"systemd\[\d+\]:\s+Stopped\s+", re.IGNORECASE),
    re.compile(r"systemd\[\d+\]:\s+Stopping\s+", re.IGNORECASE),
    re.compile(r"systemd\[\d+\]:\s+Starting\s+", re.IGNORECASE),
    re.compile(r"systemd\[\d+\]:\s+Reached target\s+", re.IGNORECASE),
    re.compile(r"systemd\[\d+\]:\s+Created slice\s+", re.IGNORECASE),
    re.compile(r"systemd\[\d+\]:\s+Listening on\s+", re.IGNORECASE),
    re.compile(r"systemd\[\d+\]:\s+Mounted\s+", re.IGNORECASE),
    re.compile(r"systemd\[\d+\]:\s+Deactivated successfully", re.IGNORECASE),
    re.compile(r"systemd\[\d+\]:\s+.*startup finished", re.IGNORECASE),
    re.compile(r"systemd\[\d+\]:\s+Closed\s+", re.IGNORECASE),
    re.compile(r"systemd\[\d+\]:\s+Removed slice\s+", re.IGNORECASE),

    # Docker runtime mount events (the specific problem pattern)
    re.compile(r"run-docker-runtime.*\.mount:\s+Succeeded", re.IGNORECASE),
    re.compile(r"run-docker-runtime.*runc\.\w+\.mount", re.IGNORECASE),

    # CRON normal execution
    re.compile(r"CRON\[\d+\]:\s+\(root\)\s+CMD\s+", re.IGNORECASE),
    re.compile(r"CRON\[\d+\]:\s+\(\w+\)\s+CMD\s+\(/usr/lib/php/sessionclean\)", re.IGNORECASE),

    # Network Manager normal operations
    re.compile(r"NetworkManager.*:\s+.*successfully activated", re.IGNORECASE),
    re.compile(r"NetworkManager.*:\s+.*state change.*connected", re.IGNORECASE),

    # SSH accepted (normal successful auth, not attacks)
    re.compile(r"sshd\[\d+\]:\s+Accepted\s+(publickey|keyboard-interactive)\s+for\s+\w+\s+from\s+", re.IGNORECASE),
    re.compile(r"sshd\[\d+\]:\s+pam_unix\(sshd:session\):\s+session (opened|closed)", re.IGNORECASE),

    # DHCP normal operations
    re.compile(r"dhclient\[\d+\]:\s+DHCP(ACK|OFFER|REQUEST|RELEASE)", re.IGNORECASE),

    # DNS resolver normal operations
    re.compile(r"systemd-resolved\[\d+\]:\s+Using DNS server", re.IGNORECASE),
    re.compile(r"systemd-resolved\[\d+\]:\s+Grace period over", re.IGNORECASE),

    # Package manager normal operations
    re.compile(r"apt-dscp|dpkg-exec|unattended-upgrades", re.IGNORECASE),

    # Logrotate normal operations
    re.compile(r"logrotate.*:\s+(rotating|moving|compressing|creating)", re.IGNORECASE),

    # Docker container lifecycle (normal)
    re.compile(r"docker.*container\s+(started|stopped|created|removed|paused|unpaused)", re.IGNORECASE),

    # Kernel normal informational messages
    re.compile(r"kernel:.*\s+audit:.*type=\d+\s+audit.*res=success", re.IGNORECASE),
]

# ════════════════════════════════════════════════════════
# SUSPICIOUS OVERRIDE KEYWORDS
# ════════════════════════════════════════════════════════
# If a log matches a benign pattern BUT ALSO contains any of these keywords,
# it must NOT be filtered — it should still be analyzed by the AI model.
# This prevents an attacker from hiding malicious activity in benign-looking logs.

SUSPICIOUS_OVERRIDE_KEYWORDS = [
    "reverse", "shell", "exploit", "payload", "/dev/tcp", "nc -e",
    "mkfifo", "base64 -d", "/bin/sh -i", "/bin/bash -i", 
    "wget http", "curl.*|.*bash", "chmod 4755", "rm -rf /",
    "dd if=", ":(){ :|:& };:", "python -c", "perl -e",
    "nmap", "masscan", "nikto", "sqlmap", "hydra", "gobuster",
    "xmrig", "minerd", "stratum+tcp",
    "/etc/shadow", "/etc/passwd", "docker.sock",
    "CVE-", "dirty_cow", "dirtycow",
]

# Pre-compile suspicious keyword patterns for performance
_SUSPICIOUS_PATTERNS = [re.compile(re.escape(kw), re.IGNORECASE) for kw in SUSPICIOUS_OVERRIDE_KEYWORDS]


class LogPreFilter:
    """
    Contextual pre-filter for identifying clearly benign log events.
    
    Returns:
        - "BENIGN": Log is clearly benign, skip AI model entirely
        - "PASS_TO_AI": Log is not clearly benign, send to AI for analysis
        - "SUSPICIOUS": Log contains suspicious keywords, fast-track to AI
    """

    def __init__(self, enabled: bool = BENIGN_LOG_FILTER_ENABLED):
        self.enabled = enabled
        self.benign_count = 0
        self.suspicious_count = 0
        self.pass_count = 0

    def classify(self, raw_log: str) -> Dict[str, Any]:
        """
        Classify a raw log line as BENIGN, PASS_TO_AI, or SUSPICIOUS.
        
        Args:
            raw_log: The raw log line from the VPS
            
        Returns:
            Dict with keys: decision, reason, matched_pattern (if any)
        """
        if not self.enabled:
            self.pass_count += 1
            return {
                "decision": "PASS_TO_AI",
                "reason": "Pre-filter disabled",
                "matched_pattern": None
            }

        if not raw_log or not raw_log.strip():
            self.benign_count += 1
            return {
                "decision": "BENIGN",
                "reason": "Empty log line",
                "matched_pattern": None
            }

        # Step 1: Check if the log matches any benign pattern
        matched_benign = False
        matched_pattern_str = None

        for pattern in BENIGN_PATTERNS:
            if pattern.search(raw_log):
                matched_benign = True
                matched_pattern_str = pattern.pattern
                break

        if matched_benign:
            # Step 2: Check suspicious override — even if benign pattern matched,
            # suspicious keywords take priority
            for susp_pattern in _SUSPICIOUS_PATTERNS:
                if susp_pattern.search(raw_log):
                    self.suspicious_count += 1
                    logger.debug(
                        f"[PRE-FILTER] SUSPICIOUS override: benign pattern matched but "
                        f"suspicious keyword '{susp_pattern.pattern}' found in log"
                    )
                    return {
                        "decision": "SUSPICIOUS",
                        "reason": f"Benign pattern matched but suspicious keyword detected: {susp_pattern.pattern}",
                        "matched_pattern": matched_pattern_str
                    }

            # Confirmed benign — skip AI
            self.benign_count += 1
            logger.debug(f"[PRE-FILTER] BENIGN: {raw_log[:80]}...")
            return {
                "decision": "BENIGN",
                "reason": f"Matched benign pattern: {matched_pattern_str}",
                "matched_pattern": matched_pattern_str
            }

        # Step 3: No benign pattern matched — pass to AI
        self.pass_count += 1
        return {
            "decision": "PASS_TO_AI",
            "reason": "No benign pattern matched, requires AI analysis",
            "matched_pattern": None
        }

    def get_stats(self) -> Dict[str, int]:
        """Return pre-filter statistics."""
        return {
            "benign_filtered": self.benign_count,
            "suspicious_overrides": self.suspicious_count,
            "passed_to_ai": self.pass_count,
            "total_processed": self.benign_count + self.suspicious_count + self.pass_count
        }


# Global instance
log_pre_filter = LogPreFilter()
