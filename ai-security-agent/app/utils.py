"""
utils.py
========
Utility functions for remediation recommendations, text formatting, and system helpers.
"""

from datetime import datetime
from typing import Dict

# Actionable remediation recommendations per attack category
RECOMMENDATIONS: Dict[str, str] = {
    "ReverseShell": "CRITICAL: Immediate action required! Kill process tree, inspect network sockets (netstat/ss), check crontabs and systemd services, and isolate the server if necessary.",
    "Kernel_Exploit": "CRITICAL: Potential privilege escalation exploit execution. Check /tmp and /var/tmp for compiled binaries, apply Linux kernel security patches immediately.",
    "PrivilegeEscalation": "CRITICAL: Unauthorized root escalation attempt detected. Inspect sudoers configuration, check setuid binaries (find / -perm -4000), and review active root sessions.",
    "Ransomware": "CRITICAL: Potential file encryption activity detected. Immediately freeze disk I/O, isolate host from network, and inspect modified files.",
    "Linux_Command_Injection": "CRITICAL: Arbitrary system command execution detected. Inspect web app inputs, review web user permissions (www-data/nginx), and check /tmp for dropped payloads.",
    "Malicious_System_Command": "CRITICAL: Destructive system command executed (e.g. dd/rm/mkfs). Inspect user terminal history and suspend compromised user accounts.",
    "WebShell": "HIGH: Web shell execution detected. Search for uploaded PHP/ASP/JSP scripts in web roots, inspect web server access logs, and restrict file upload permissions.",
    "Docker_Abuse": "HIGH: Suspicious Docker container breakout or privileged container execution. Inspect running containers (docker ps), review docker socket permissions, and check mounted host paths.",
    "Persistence": "HIGH: System persistence mechanism established (SSH authorized_keys, bash profile, systemd). Inspect /root/.ssh/authorized_keys and system startup scripts.",
    "XXE": "HIGH: XML External Entity injection. Disable external entity resolution (DTD) in XML parsers and sanitize web inputs.",
    "Insecure_Deserialization": "HIGH: Untrusted object deserialization attempt. Review application endpoint parsers and update vulnerable dependencies.",
    "SQL_Injection": "HIGH: Database query injection attempt. Ensure parameterized queries (prepared statements) are used and review WAF rules.",
    "XSS": "HIGH: Cross-site scripting payload detected. Ensure output encoding and CSP headers are active on web applications.",
    "PathTraversal": "HIGH: Arbitrary file access attempt (e.g. /etc/passwd). Restrict web application directory permissions and sanitize file paths.",
    "FileUpload_Attack": "HIGH: Malicious file upload attempt. Restrict executable extensions in upload directories (.php, .phtml, .sh) and enforce mime-type verification.",
    "NoSQL_Injection": "HIGH: NoSQL query manipulation. Validate type inputs and avoid using raw JSON input in database queries.",
    "SSTI": "HIGH: Server-Side Template Injection. Sanitize user inputs passed to template engines (Jinja2, Twig, etc.).",
    "Lateral_Movement": "HIGH: Internal network lateral movement attempt via SSH/SCP. Audit internal SSH keys and restrict inter-host communication.",
    "Cron_Abuse": "HIGH: Unauthorized crontab entry modified or created. Check /etc/crontab, /etc/cron.d/, and user crontabs (crontab -l).",
    "Unauthorized_File_Modification": "HIGH: Sensitive file modified (e.g. /etc/passwd, /etc/shadow, /etc/sudoers). Revert unauthorized file changes and audit file permissions.",
    "Root_Login_Attempt": "HIGH: Direct root login attempt detected. Ensure 'PermitRootLogin no' is set in /etc/ssh/sshd_config.",
    "Cryptomining": "HIGH: Unauthorized cryptomining process detected (e.g. xmrig). Kill high-CPU processes, inspect network connections to mining pools, and clean /tmp.",
    "Linux_Malware": "HIGH: Dropped malware executable or script detected. Isolate process, delete downloaded binary, and scan system with ClamAV/rkhunter.",
    "SSH_BruteForce": "MEDIUM: Repeated SSH authentication failures. Consider enabling Fail2ban or SSH key-only authentication, and block offending IP address.",
    "SSH_Login_Attack": "MEDIUM: Suspicious SSH login attempt. Verify source IP address and enforce multi-factor authentication (MFA).",
    "PortScanning": "MEDIUM: Network port scanning activity (nmap/masscan). Review firewall rules (iptables/ufw) and block scanner IP.",
    "Failed_Login": "MEDIUM: Authentication failure recorded. Monitor for brute force patterns.",
    "CredentialStuffing": "MEDIUM: Automated login attempts with leaked credentials. Enforce rate limiting and CAPTCHA on login endpoints.",
    "BruteForce": "MEDIUM: Brute force password attack. Rate limit authentication endpoints.",
    "Suspicious_Bash_Command": "MEDIUM: Suspicious shell activity (history wiping, environment tampering). Inspect audit log and active user sessions.",
    "Suspicious_Process": "MEDIUM: Unrecognized background process running. Inspect process tree (`ps auxf`) and binary path (`ls -l /proc/<PID>/exe`).",
    "System_Enumeration": "LOW: Reconnaissance commands executed (uname, id, ifconfig). Monitor user activity for escalation.",
    "Benign": "SAFE: Normal benign activity. No action required."
}

def get_recommendation(prediction: str) -> str:
    """Return actionable security recommendation for a predicted attack category."""
    return RECOMMENDATIONS.get(
        prediction,
        "MEDIUM: Inspect event details, review system logs around timestamp, and verify user authorization."
    )

def format_timestamp(dt: datetime = None) -> str:
    """Format datetime object into standard ISO string."""
    if dt is None:
        dt = datetime.now()
    return dt.strftime("%Y-%m-%d %H:%M:%S")

def sanitize_text(text: str, max_length: int = 1000) -> str:
    """Sanitize and truncate raw text for clean processing and storage."""
    if not text:
        return ""
    # Strip null bytes and normalize whitespace
    cleaned = text.replace("\0", "").strip()
    if len(cleaned) > max_length:
        return cleaned[:max_length] + " [TRUNCATED]"
    return cleaned
