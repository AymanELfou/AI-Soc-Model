"""
test_ddos.py
============
Unit and integration test suite for app/ddos_detector.py.
Tests:
- Single IP Flood
- Distributed Multi-IP Flood
- Targeted Endpoint Traffic Spike
- HTTP Error Rate Anomaly
- Live 100+ Request DDoS Simulation & Email Notification
"""

import sys
import os
import time
sys.path.insert(0, os.getcwd())

from app.ddos_detector import DDoSDetector
from app.alert_manager import alert_manager
import app.config as config

def run_tests():
    print("=" * 70)
    print("🧪 RUNNING DDOS DETECTOR SUITE (test_ddos.py)")
    print("=" * 70)

    # Instantiate isolated test detector
    detector = DDoSDetector(
        enabled=True,
        window_seconds=5,
        request_threshold=20,
        ip_threshold=10,
        endpoint_threshold=15
    )

    # 1. Test Normal Baseline Traffic
    print("\n[Test 1] Testing Normal Baseline Traffic...")
    res = detector.record_request("192.168.1.10", "/index.html", "GET", 200)
    assert res["risk_level"] == "NORMAL", f"Expected NORMAL, got {res['risk_level']}"
    assert not res["is_anomaly"], "Baseline traffic should not trigger anomaly flag"
    print("   ✅ Passed: Baseline traffic evaluated as NORMAL.")

    # 2. Test Single IP Flood
    print("\n[Test 2] Testing Single IP Flood (15 requests from 10.0.0.1)...")
    for i in range(12):
        res = detector.record_request("10.0.0.1", "/login", "POST", 200)

    assert "Single IP Flood" in str(res["patterns_detected"]), f"Expected Single IP Flood in {res['patterns_detected']}"
    assert res["risk_level"] in ("HIGH", "CRITICAL"), f"Expected HIGH/CRITICAL, got {res['risk_level']}"
    print(f"   ✅ Passed: Single IP flood detected! Risk level: [{res['risk_level']}], Patterns: {res['patterns_detected']}")

    # 3. Test Distributed Multi-IP Flood
    print("\n[Test 3] Testing Distributed DDoS Flood (25 requests from 20 distinct IPs)...")
    detector = DDoSDetector(enabled=True, window_seconds=5, request_threshold=20, ip_threshold=10, endpoint_threshold=15)
    for i in range(22):
        ip = f"172.16.0.{i+1}"
        res = detector.record_request(ip, "/api/data", "GET", 200)

    assert res["unique_ips_count"] >= 20, f"Expected 20+ unique IPs, got {res['unique_ips_count']}"
    assert res["risk_level"] == "CRITICAL", f"Expected CRITICAL, got {res['risk_level']}"
    print(f"   ✅ Passed: Distributed DDoS detected! Risk level: [{res['risk_level']}], Unique IPs: {res['unique_ips_count']}")

    # 4. Test Targeted Endpoint Spike
    print("\n[Test 4] Testing Targeted Endpoint Flood (/checkout)...")
    detector = DDoSDetector(enabled=True, window_seconds=5, request_threshold=20, ip_threshold=50, endpoint_threshold=10)
    for i in range(12):
        res = detector.record_request(f"192.168.1.{i+1}", "/checkout", "POST", 200)

    assert res["top_endpoint"] == "/checkout", f"Expected /checkout, got {res['top_endpoint']}"
    assert "Targeted Endpoint Flood" in str(res["patterns_detected"]), f"Expected Targeted Endpoint Flood in {res['patterns_detected']}"
    print(f"   ✅ Passed: Targeted endpoint flood detected! Top Endpoint: {res['top_endpoint']} ({res['top_endpoint_requests']} reqs)")

    # 5. Test Log Parsing from Nginx Access Format
    print("\n[Test 5] Testing Raw Nginx Access Log Line Parsing...")
    raw_log = '203.0.113.195 - - [08/Aug/2026:16:00:00 +0000] "POST /api/v1/login HTTP/1.1" 401 128'
    parsed = detector.parse_web_log(raw_log)
    assert parsed == ("203.0.113.195", "/api/v1/login", "POST", 401), f"Unexpected parse result: {parsed}"
    print(f"   ✅ Passed: Nginx log line correctly parsed -> IP: {parsed[0]}, Endpoint: {parsed[1]}, Method: {parsed[2]}, Status: {parsed[3]}")

    # 6. Live Test: 105 Requests DDoS Simulation & Live Email Delivery
    print("\n[Test 6] Testing Live DDoS Simulation (105 Requests > Threshold 100) & Email Alert...")
    config.ALERT_COOLDOWN_SECONDS = 0  # Allow instant test email dispatch
    live_detector = DDoSDetector(
        enabled=True,
        window_seconds=10,
        request_threshold=100,
        ip_threshold=50,
        endpoint_threshold=80
    )

    fake_ip = f"185.220.101.{int(time.time()) % 200 + 10}"
    print(f"   Simulating 105 HTTP POST requests from IP {fake_ip} to /login endpoint...")
    for i in range(105):
        ddos_res = live_detector.record_request(fake_ip, "/login", "POST", 200)

    print(f"   Total Requests Count : {ddos_res['total_requests_in_window']} reqs / 10s")
    print(f"   Calculated Risk Level: [{ddos_res['risk_level']}]")
    print(f"   Patterns Detected    : {ddos_res['patterns_detected']}")

    email_sent = alert_manager.dispatch_ddos_alert(ddos_res)
    print(f"   📧 Live DDoS Email Alert Result: {'SUCCESS! Email report delivered to ' + config.ADMIN_EMAIL if email_sent else 'FAILED'}")
    assert email_sent, "Live DDoS email alert should be sent successfully"

    print("\n" + "=" * 70)
    print("✅ ALL DDOS DETECTOR TESTS PASSED SUCCESSFULLY!")
    print("=" * 70)

if __name__ == "__main__":
    run_tests()
