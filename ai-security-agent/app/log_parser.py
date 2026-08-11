"""
log_parser.py
=============
Intelligent security log parser.
Filters out noisy informational lines (cron ticks, systemd startup/mounts, apt updates)
and extracts clean, high-value security events for AI prediction.
"""

import re
from typing import Optional, Dict, Any
from app.config import IGNORED_LOG_PATTERNS
from app.utils import sanitize_text

# Regex patterns to ignore normal noise
IGNORE_PATTERNS = [
    re.compile(r"systemd\[\d+\]:", re.IGNORECASE),
    re.compile(r"run-docker-runtime", re.IGNORECASE),
    re.compile(r"\.mount:?\s+", re.IGNORECASE),
    re.compile(r"runc\.", re.IGNORECASE),
    re.compile(r"CRON\[\d+\]:\s+\(root\)\s+CMD\s+\(/usr/lib/php/sessionclean\)", re.IGNORECASE),
    re.compile(r"apt-dscp|dpkg-exec|unattended-upgrades", re.IGNORECASE),
    re.compile(r"logrotate:\s+ALERT", re.IGNORECASE),
    re.compile(r"dhclient\[\d+\]:\s+DHCP(ACK|OFFER|REQUEST)", re.IGNORECASE),
    re.compile(r"systemd-resolved\[\d+\]:\s+Using DNS server", re.IGNORECASE),
]

# Add any custom patterns from config.py
for pat in IGNORED_LOG_PATTERNS:
    try:
        IGNORE_PATTERNS.append(re.compile(pat, re.IGNORECASE))
    except Exception:
        pass

# Patterns for high-value security events (with strict word boundaries)
SECURITY_PATTERNS = [
    re.compile(r"Failed password", re.IGNORECASE),
    re.compile(r"Invalid user", re.IGNORECASE),
    re.compile(r"Accepted (password|publickey)", re.IGNORECASE),
    re.compile(r"sudo:\s+.*:\s+TTY=.*COMMAND=", re.IGNORECASE),
    re.compile(r"su:\s+.*:\s+session opened for user root", re.IGNORECASE),
    re.compile(r"\b(GET|POST|PUT|DELETE|HEAD|OPTIONS|CONNECT)\b", re.IGNORECASE),
    re.compile(r"\b(nmap|masscan|nikto|sqlmap|gobuster|hydra)\b", re.IGNORECASE),
    re.compile(r"\bdocker\s+(run|exec|build)\b", re.IGNORECASE),
    re.compile(r"xmrig|minerd|stratum\+tcp", re.IGNORECASE),
    re.compile(r"bash -i|/dev/tcp/|nc -e|mkfifo|python.*socket", re.IGNORECASE),
    re.compile(r"chmod \+x|chmod 4755|chown root|useradd|usermod", re.IGNORECASE),
    re.compile(r"wget|curl.*\|.*bash|openssl enc|dirty_cow|CVE-", re.IGNORECASE),
    re.compile(r"fail2ban\.actions.*\[(Ban|Unban)\]", re.IGNORECASE),
    re.compile(r"type=EXECVE|type=SYSCALL|type=PATH", re.IGNORECASE),
]

class LogParser:
    """Parses raw Linux log lines and extracts security-relevant text."""

    @staticmethod
    def is_noisy(line: str) -> bool:
        """Check if a log line is noisy or informational and should be ignored."""
        if not line or not line.strip():
            return True

        # Ignore any systemd, docker runtime, or mount status lines immediately
        line_lower = line.lower()
        if "systemd[" in line_lower or "run-docker-runtime" in line_lower or ".mount:" in line_lower or "runc." in line_lower:
            return True

        # Check ignore list
        for pattern in IGNORE_PATTERNS:
            if pattern.search(line):
                return True
        return False

    @staticmethod
    def extract_clean_text(raw_line: str, source_log: str = "syslog") -> Optional[str]:
        """
        Extract and clean security payload text from a raw log line.
        
        Returns:
            Cleaned text for AI model input, or None if line should be ignored.
        """
        if LogParser.is_noisy(raw_line):
            return None

        line = raw_line.strip()

        # 1. Web Access Logs (Nginx / Apache)
        if "access" in source_log.lower() or "nginx" in source_log.lower() or "apache" in source_log.lower():
            request_match = re.search(r'"([^"]+)"', line)
            if request_match:
                return sanitize_text(request_match.group(1))

        # 2. SSH / Authentication Logs (auth.log / secure)
        if "auth" in source_log.lower() or "secure" in source_log.lower() or "sshd" in line:
            prefix_match = re.search(r'sshd\[\d+\]:\s*(.*)', line)
            if prefix_match:
                return sanitize_text(prefix_match.group(1))

            sudo_match = re.search(r'sudo:\s*(.*)', line)
            if sudo_match:
                return sanitize_text(sudo_match.group(1))

        # 3. Fail2ban logs
        if "fail2ban" in source_log.lower():
            f2b_match = re.search(r'fail2ban\..*\]\s*(.*)', line)
            if f2b_match:
                return sanitize_text(f2b_match.group(1))

        # 4. Auditd logs
        if "audit" in source_log.lower():
            cmd_match = re.search(r'exe="([^"]+)"', line)
            if cmd_match:
                return sanitize_text(f"Executed binary: {cmd_match.group(1)}")

        # 5. Check explicitly for high-value security attack patterns
        for pattern in SECURITY_PATTERNS:
            if pattern.search(line):
                clean_line = re.sub(r'^[A-Za-z]{3}\s+\d+\s+\d{2}:\d{2}:\d{2}\s+[^\s]+\s+', '', line)
                return sanitize_text(clean_line)

        return None

# Global Parser Helper
log_parser = LogParser()
