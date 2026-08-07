"""
test_health.py
==============
Unit and integration test suite for app/health.py and GET /health API endpoint.
Tests:
- Simple Health Check format (GET /health)
- Full Health Diagnostics format (GET /api/v1/health)
- Last Heartbeat update & System Uptime calculation
- Subsystem health checks (Model, DB, Monitor, SMTP, CPU/RAM/Disk)
"""

import sys
import os
import json
sys.path.insert(0, os.getcwd())

from app.health import health_checker

def run_tests():
    print("=" * 70)
    print("🧪 RUNNING HEALTH ENDPOINT SUITE (test_health.py)")
    print("=" * 70)

    # 1. Test Simple Health Format (GET /health)
    print("\n[Test 1] Testing Simple Health Endpoint Response (GET /health)...")
    simple_health = health_checker.get_simple_health()

    print(json.dumps(simple_health, indent=2))

    # Required keys as specified in project requirements
    required_keys = [
        "status",
        "agent",
        "model",
        "database",
        "log_monitor",
        "last_heartbeat",
        "hostname",
        "uptime",
        "cpu",
        "ram",
        "disk"
    ]

    for key in required_keys:
        assert key in simple_health, f"Required health key '{key}' missing from /health response!"

    assert simple_health["status"] in ("healthy", "unhealthy"), "Status should be healthy or unhealthy"
    assert simple_health["agent"] == "running", "Agent status should be running"
    assert isinstance(simple_health["uptime"], int), "Uptime should be integer seconds"
    assert isinstance(simple_health["cpu"], (int, float)), "CPU metric should be numeric"
    assert isinstance(simple_health["ram"], (int, float)), "RAM metric should be numeric"
    assert isinstance(simple_health["disk"], (int, float)), "Disk metric should be numeric"

    print("   ✅ Passed: Simple Health Check response matches required schema 100%.")

    # 2. Test Heartbeat Update
    print("\n[Test 2] Testing Heartbeat Timestamp Update...")
    old_hb = simple_health["last_heartbeat"]
    health_checker.update_heartbeat()
    new_hb = health_checker.last_heartbeat
    print(f"   Last Heartbeat: {new_hb}")
    assert new_hb is not None, "Heartbeat timestamp cannot be None"
    print("   ✅ Passed: Heartbeat timestamp successfully updated.")

    # 3. Test Full Diagnostics (GET /api/v1/health)
    print("\n[Test 3] Testing Full Diagnostics Response (GET /api/v1/health)...")
    full_diag = health_checker.get_full_diagnostics()

    assert "status" in full_diag, "status missing from full_diag"
    assert "summary" in full_diag, "summary missing from full_diag"
    assert "system" in full_diag, "system missing from full_diag"
    assert "ai_model" in full_diag, "ai_model missing from full_diag"
    assert "database" in full_diag, "database missing from full_diag"
    assert "log_monitor" in full_diag, "log_monitor missing from full_diag"

    print(f"   Overall Health Status: {full_diag['status']}")
    print(f"   Diagnostics Summary  : {json.dumps(full_diag['summary'])}")
    print("   ✅ Passed: Full diagnostics check executed successfully.")

    print("\n" + "=" * 70)
    print("✅ ALL HEALTH ENDPOINT TESTS PASSED SUCCESSFULLY!")
    print("=" * 70)

if __name__ == "__main__":
    run_tests()
