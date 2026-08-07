"""
ddos_detector.py
================
Real-time traffic volume monitoring and DDoS anomaly detection module.
Operates independently from the ML model to detect request rate spikes,
single-IP floods, distributed DDoS attacks, and targeted endpoint abuse.
"""

import re
import time
from collections import defaultdict, deque
from typing import Dict, Any, List, Optional, Tuple
from app.config import (
    DDOS_ENABLED,
    DDOS_REQUEST_THRESHOLD,
    DDOS_WINDOW_SECONDS,
    DDOS_IP_THRESHOLD,
    DDOS_ENDPOINT_THRESHOLD,
    HOSTNAME
)
from app.logger import logger

class DDoSDetector:
    """
    Traffic volume anomaly detector for HTTP web access logs (Nginx / Apache).
    Tracks sliding time window metrics and identifies suspicious DDoS patterns.
    """

    def __init__(
        self,
        enabled: bool = DDOS_ENABLED,
        window_seconds: int = DDOS_WINDOW_SECONDS,
        request_threshold: int = DDOS_REQUEST_THRESHOLD,
        ip_threshold: int = DDOS_IP_THRESHOLD,
        endpoint_threshold: int = DDOS_ENDPOINT_THRESHOLD
    ):
        self.enabled = enabled
        self.window_seconds = window_seconds
        self.request_threshold = request_threshold
        self.ip_threshold = ip_threshold
        self.endpoint_threshold = endpoint_threshold

        # Sliding window buffer: deque of (timestamp, ip, endpoint, method, status_code)
        self.request_window = deque()
        self.requests_last_minute = deque()

        # Regex pattern to parse Nginx/Apache Combined Log Format
        # Example: 192.168.1.50 - - [07/Aug/2026:12:00:00 +0000] "GET /index.php HTTP/1.1" 200 4523
        self.web_log_pattern = re.compile(
            r'^(?P<ip>\S+)\s+\S+\s+\S+\s+\[[^\]]+\]\s+"(?P<method>[A-Z]+)\s+(?P<endpoint>\S+)\s+HTTP/[0-9.]+"\s+(?P<status>\d+)'
        )

    def parse_web_log(self, raw_line: str) -> Optional[Tuple[str, str, str, int]]:
        """Extract (ip, endpoint, method, status_code) from Nginx/Apache access log line."""
        match = self.web_log_pattern.search(raw_line)
        if match:
            ip = match.group("ip")
            endpoint = match.group("endpoint").split("?")[0]  # Strip query string for grouping
            method = match.group("method")
            status_code = int(match.group("status"))
            return ip, endpoint, method, status_code
        return None

    def _cleanup_old_records(self, now: float):
        """Remove events outside the current sliding time window."""
        cutoff_window = now - self.window_seconds
        cutoff_minute = now - 60.0

        while self.request_window and self.request_window[0][0] < cutoff_window:
            self.request_window.popleft()

        while self.requests_last_minute and self.requests_last_minute[0][0] < cutoff_minute:
            self.requests_last_minute.popleft()

    def record_request(
        self,
        ip: str,
        endpoint: str,
        method: str = "GET",
        status_code: int = 200,
        now: Optional[float] = None
    ) -> Dict[str, Any]:
        """
        Record a single HTTP request and analyze window metrics for DDoS traffic anomalies.
        Returns a dictionary containing detection results and risk state.
        """
        if not self.enabled:
            return {"risk_level": "NORMAL", "is_anomaly": False}

        if now is None:
            now = time.time()

        # Add to sliding window buffers
        record = (now, ip, endpoint, method, status_code)
        self.request_window.append(record)
        self.requests_last_minute.append(record)

        self._cleanup_old_records(now)

        return self.analyze_traffic(now)

    def analyze_traffic(self, now: Optional[float] = None) -> Dict[str, Any]:
        """
        Analyze all requests in the current sliding window across multiple dimensions.
        Returns detailed traffic metrics, detected patterns, and risk state.
        """
        if now is None:
            now = time.time()
        self._cleanup_old_records(now)

        total_window_requests = len(self.request_window)
        total_minute_requests = len(self.requests_last_minute)

        req_per_second = round(total_window_requests / max(self.window_seconds, 1), 2)
        req_per_minute = total_minute_requests

        ip_counts: Dict[str, int] = defaultdict(int)
        endpoint_counts: Dict[str, int] = defaultdict(int)
        status_counts: Dict[int, int] = defaultdict(int)

        for ts, ip, endpoint, method, status in self.request_window:
            ip_counts[ip] += 1
            endpoint_counts[endpoint] += 1
            status_counts[status] += 1

        unique_ips_count = len(ip_counts)
        top_ip = max(ip_counts.items(), key=lambda x: x[1])[0] if ip_counts else "N/A"
        top_ip_requests = ip_counts.get(top_ip, 0)

        top_endpoint = max(endpoint_counts.items(), key=lambda x: x[1])[0] if endpoint_counts else "N/A"
        top_endpoint_requests = endpoint_counts.get(top_endpoint, 0)

        # Detect specific DDoS patterns
        patterns_detected: List[str] = []

        # 1. High request rate from one single IP
        if top_ip_requests >= self.ip_threshold:
            patterns_detected.append(f"Single IP Flood ({top_ip} sent {top_ip_requests} req/{self.window_seconds}s)")

        # 2. High request rate from many distributed IPs
        if total_window_requests >= self.request_threshold and unique_ips_count >= 15:
            patterns_detected.append(f"Distributed DDoS ({unique_ips_count} unique IPs sent {total_window_requests} req/{self.window_seconds}s)")

        # 3. Abnormal request rate to one single endpoint
        if top_endpoint_requests >= self.endpoint_threshold:
            patterns_detected.append(f"Targeted Endpoint Flood ({top_endpoint} received {top_endpoint_requests} req/{self.window_seconds}s)")

        # 4. Sudden traffic spike
        if total_window_requests >= self.request_threshold * 2:
            patterns_detected.append(f"Sudden Traffic Spike ({total_window_requests} req/{self.window_seconds}s)")

        # 5. Repeated suspicious error requests (4xx/5xx flood)
        error_requests = sum(cnt for status, cnt in status_counts.items() if status >= 400)
        if error_requests >= self.request_threshold / 2 and total_window_requests > 0:
            patterns_detected.append(f"High HTTP Error Rate ({error_requests} error responses in window)")

        # Determine Risk State: NORMAL, SUSPICIOUS, HIGH, CRITICAL
        risk_level = "NORMAL"
        if patterns_detected:
            if total_window_requests >= self.request_threshold * 2 or len(patterns_detected) >= 2:
                risk_level = "CRITICAL"
            elif total_window_requests >= self.request_threshold or top_ip_requests >= self.ip_threshold:
                risk_level = "HIGH"
            else:
                risk_level = "SUSPICIOUS"

        is_anomaly = risk_level in ("HIGH", "CRITICAL")

        return {
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
            "hostname": HOSTNAME,
            "window_seconds": self.window_seconds,
            "total_requests_in_window": total_window_requests,
            "requests_per_second": req_per_second,
            "requests_per_minute": req_per_minute,
            "unique_ips_count": unique_ips_count,
            "top_ip": top_ip,
            "top_ip_requests": top_ip_requests,
            "top_endpoint": top_endpoint,
            "top_endpoint_requests": top_endpoint_requests,
            "patterns_detected": patterns_detected,
            "risk_level": risk_level,
            "is_anomaly": is_anomaly
        }

    def process_log_line(self, raw_line: str, source_log: str = "nginx/access.log") -> Optional[Dict[str, Any]]:
        """Parse raw log line and record request if it matches web access format."""
        parsed = self.parse_web_log(raw_line)
        if parsed:
            ip, endpoint, method, status_code = parsed
            return self.record_request(ip, endpoint, method, status_code)
        return None

# Global instance
ddos_detector = DDoSDetector()
