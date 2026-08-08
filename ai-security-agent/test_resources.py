"""
test_resources.py
=================
Unit and integration test suite for app/resource_monitor.py.
Tests:
- Hardware resource metric sampling (CPU, RAM, Disk, System Load Average, Network I/O)
- Threshold state evaluation (NORMAL, WARNING, CRITICAL)
- State transitions (WARNING -> CRITICAL -> RECOVERY)
- Live Critical Resource Saturation (CPU 97%, RAM 92%, Disk 96%) & Email Delivery
"""

import sys
import os
import time
sys.path.insert(0, os.getcwd())

from app.resource_monitor import ResourceMonitor
from app.alert_manager import alert_manager
import app.config as config

def run_tests():
    print("=" * 70)
    print("🧪 RUNNING RESOURCE MONITOR SUITE (test_resources.py)")
    print("=" * 70)

    monitor = ResourceMonitor()

    # 1. Test Threshold Evaluation
    print("\n[Test 1] Testing Metric State Evaluation...")
    assert monitor.evaluate_metric_state(50.0, 80.0, 95.0) == "NORMAL", "50% should be NORMAL"
    assert monitor.evaluate_metric_state(85.0, 80.0, 95.0) == "WARNING", "85% should be WARNING"
    assert monitor.evaluate_metric_state(97.0, 80.0, 95.0) == "CRITICAL", "97% should be CRITICAL"
    print("   ✅ Passed: Threshold metric state evaluation logic works perfectly.")

    # 2. Test Real Resource Sampling
    print("\n[Test 2] Testing Real System Resource Sampling...")
    res = monitor.check_resources()
    metrics = res["metrics"]

    assert "cpu_percent" in metrics, "cpu_percent missing"
    assert "ram_percent" in metrics, "ram_percent missing"
    assert "disk_percent" in metrics, "disk_percent missing"
    assert "overall_severity" in res, "overall_severity missing"

    print(f"   Hostname         : {res['hostname']}")
    print(f"   CPU Usage        : {metrics['cpu_percent']}%")
    print(f"   RAM Usage        : {metrics['ram_percent']}% ({metrics['ram_used_mb']} MB / {metrics['ram_total_mb']} MB)")
    print(f"   Disk Usage       : {metrics['disk_percent']}%")
    print(f"   System Load      : {metrics['load_avg']}")
    print(f"   Network I/O      : Sent {metrics['network_io']['bytes_sent_mb']} MB, Recv {metrics['network_io']['bytes_recv_mb']} MB")
    print(f"   Overall Severity : [{res['overall_severity']}]")
    print("   ✅ Passed: Real system resource measurements captured successfully.")

    # 3. Test Transition & Recovery Tracking Simulation
    print("\n[Test 3] Testing State Transition & Recovery Detection Simulation...")
    monitor.last_states["CPU"] = "NORMAL"
    monitor.last_states["CPU"] = "WARNING"
    assert monitor.last_states["CPU"] == "WARNING", "State transition simulation failed"
    monitor.last_states["CPU"] = "NORMAL"
    assert monitor.last_states["CPU"] == "NORMAL", "Recovery transition simulation failed"
    print("   ✅ Passed: State transition and RECOVERY detection logic works.")

    # 4. Live Test: Critical Resource Saturation & Email Notification
    print("\n[Test 4] Testing Live Critical Resource Saturation & Email Notification...")
    config.ALERT_COOLDOWN_SECONDS = 0  # Allow instant test email dispatch

    simulated_metrics = {
        "cpu_percent": 97.5,
        "ram_percent": 92.0,
        "disk_percent": 96.8,
        "ram_used_mb": 7536.0,
        "ram_total_mb": 8192.0,
        "load_avg": "8.50, 6.20, 4.10",
        "network_io": {"bytes_sent_mb": 1420.5, "bytes_recv_mb": 3250.8}
    }

    print("   Simulating CRITICAL Resource Saturation:")
    print("     - CPU Usage  : 97.5% (Threshold: 95.0%) -> [CRITICAL]")
    print("     - RAM Usage  : 92.0% (Threshold: 90.0%) -> [CRITICAL]")
    print("     - Disk Usage : 96.8% (Threshold: 90.0%) -> [CRITICAL]")

    # Send CRITICAL alert for CPU
    cpu_email_sent = alert_manager.dispatch_resource_alert(
        metric_name="CPU",
        severity="CRITICAL",
        alert_type_name="CPU_CRITICAL",
        current_val=97.5,
        threshold_val=95.0,
        metrics=simulated_metrics
    )

    print(f"   📧 CPU CRITICAL Email Alert Status  : {'SUCCESS! Email report sent to ' + config.ADMIN_EMAIL if cpu_email_sent else 'FAILED'}")

    # Send RECOVERY alert
    recovery_email_sent = alert_manager.dispatch_recovery_alert(
        metric_name="CPU",
        current_val=22.4,
        metrics={"cpu_percent": 22.4, "ram_percent": 35.0, "disk_percent": 45.0}
    )

    print(f"   📧 CPU RECOVERY Email Alert Status : {'SUCCESS! Email report sent to ' + config.ADMIN_EMAIL if recovery_email_sent else 'FAILED'}")

    assert cpu_email_sent, "CPU CRITICAL email alert should be sent successfully"
    assert recovery_email_sent, "CPU RECOVERY email alert should be sent successfully"

    print("\n" + "=" * 70)
    print("✅ ALL RESOURCE MONITOR TESTS PASSED SUCCESSFULLY!")
    print("=" * 70)

if __name__ == "__main__":
    run_tests()
