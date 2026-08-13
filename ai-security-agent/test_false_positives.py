"""
test_false_positives.py
=======================
Comprehensive test suite for the Security Decision Engine, Log Pre-Filter,
and false positive prevention system.

Tests cover all 8 required scenarios:
1. systemd normal log → IGNORE, no email
2. Docker normal log → IGNORE, no email
3. CRON normal log → IGNORE, no email
4. SSH normal login → IGNORE, no email
5. Low confidence attack prediction → IGNORE, no email
6. Real SSH brute force attack → ALERT, HIGH, email
7. SQL Injection attack → ALERT, email
8. DDoS traffic spike → ALERT, email
"""

import sys
import os
import unittest

# Ensure project root is in path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))


# ════════════════════════════════════════════════════════
# TEST 1-4: LOG PRE-FILTER TESTS
# ════════════════════════════════════════════════════════

class TestLogPreFilter(unittest.TestCase):
    """Test the Log Pre-Filter module for benign log identification."""

    def setUp(self):
        from app.log_pre_filter import LogPreFilter
        self.pre_filter = LogPreFilter(enabled=True)

    # ── Test 1: systemd normal mount log ──
    def test_systemd_mount_succeeded_is_benign(self):
        """The exact problem log that caused false positive emails MUST be filtered."""
        log = (
            "Aug 11 11:06:28 ubuntu systemd[1950]: "
            "run-docker-runtime\\x2drunc-moby-7fdc7b268c7ecc41c0370983b1f32d1813f4d7e2af5d40789e5e35c93d753407-runc.u0UJak.mount: Succeeded."
        )
        result = self.pre_filter.classify(log)
        self.assertEqual(result["decision"], "BENIGN", f"systemd mount Succeeded should be BENIGN, got {result}")

    def test_systemd_started_is_benign(self):
        log = "Aug 11 10:00:00 ubuntu systemd[1]: Started Docker Application Container Engine."
        result = self.pre_filter.classify(log)
        self.assertEqual(result["decision"], "BENIGN")

    def test_systemd_finished_is_benign(self):
        log = "Aug 11 10:00:00 ubuntu systemd[1]: Finished Daily apt download activities."
        result = self.pre_filter.classify(log)
        self.assertEqual(result["decision"], "BENIGN")

    def test_systemd_stopped_is_benign(self):
        log = "Aug 11 10:00:00 ubuntu systemd[1]: Stopped target Swap."
        result = self.pre_filter.classify(log)
        self.assertEqual(result["decision"], "BENIGN")

    def test_systemd_reached_target_is_benign(self):
        log = "Aug 11 10:00:00 ubuntu systemd[1]: Reached target Multi-User System."
        result = self.pre_filter.classify(log)
        self.assertEqual(result["decision"], "BENIGN")

    # ── Test 2: Docker normal log ──
    def test_docker_container_started_is_benign(self):
        log = "Aug 11 10:00:00 ubuntu docker: container started successfully"
        result = self.pre_filter.classify(log)
        self.assertEqual(result["decision"], "BENIGN", f"Docker container started should be BENIGN, got {result}")

    def test_docker_runtime_mount_is_benign(self):
        log = "Aug 11 11:04:56 ubuntu systemd[1950]: run-docker-runtime-runc-moby.mount: Succeeded."
        result = self.pre_filter.classify(log)
        self.assertEqual(result["decision"], "BENIGN")

    # ── Test 3: CRON normal log ──
    def test_cron_normal_is_benign(self):
        log = "Aug 11 10:17:01 ubuntu CRON[1234]: (root) CMD (/usr/lib/php/sessionclean)"
        result = self.pre_filter.classify(log)
        self.assertEqual(result["decision"], "BENIGN", f"Normal CRON should be BENIGN, got {result}")

    def test_cron_generic_cmd_is_benign(self):
        log = "Aug 11 10:17:01 ubuntu CRON[5678]: (root) CMD (some normal scheduled task)"
        result = self.pre_filter.classify(log)
        self.assertEqual(result["decision"], "BENIGN")

    # ── Test 4: SSH normal login ──
    def test_ssh_accepted_publickey_is_benign(self):
        log = "Aug 11 10:00:00 ubuntu sshd[12345]: Accepted publickey for deploy from 10.0.0.1 port 22 ssh2"
        result = self.pre_filter.classify(log)
        self.assertEqual(result["decision"], "BENIGN", f"SSH accepted publickey should be BENIGN, got {result}")

    # ── Test: Attack logs must NOT be filtered ──
    def test_failed_password_passes_to_ai(self):
        """Attack-like logs must NOT be classified as BENIGN."""
        log = "Aug 11 10:00:00 ubuntu sshd[12345]: Failed password for root from 192.168.1.100 port 22 ssh2"
        result = self.pre_filter.classify(log)
        self.assertNotEqual(result["decision"], "BENIGN", "Failed password should NOT be filtered as BENIGN")

    def test_suspicious_override_works(self):
        """A log matching a benign pattern BUT containing suspicious keywords should NOT be BENIGN."""
        log = "Aug 11 10:00:00 ubuntu systemd[1]: Started /bin/bash -i reverse shell exploit"
        result = self.pre_filter.classify(log)
        self.assertEqual(result["decision"], "SUSPICIOUS", f"Suspicious override should trigger, got {result}")

    def test_empty_log_is_benign(self):
        result = self.pre_filter.classify("")
        self.assertEqual(result["decision"], "BENIGN")

    def test_unknown_log_passes_to_ai(self):
        """An unknown log line should be passed to AI for analysis."""
        log = "Some unknown application log line that doesn't match any pattern"
        result = self.pre_filter.classify(log)
        self.assertEqual(result["decision"], "PASS_TO_AI")


# ════════════════════════════════════════════════════════
# TEST 5-7: SECURITY DECISION ENGINE TESTS
# ════════════════════════════════════════════════════════

class TestSecurityDecisionEngine(unittest.TestCase):
    """Test the Security Decision Engine module for correct confidence-based decisions."""

    def setUp(self):
        from app.security_decision import make_decision, normalize_confidence
        self.make_decision = make_decision
        self.normalize_confidence = normalize_confidence

    # ── Test: Confidence normalization ──
    def test_normalize_confidence_already_normalized(self):
        self.assertAlmostEqual(self.normalize_confidence(0.974), 0.974)

    def test_normalize_confidence_percentage(self):
        self.assertAlmostEqual(self.normalize_confidence(97.4), 0.974)

    def test_normalize_confidence_low_percentage(self):
        self.assertAlmostEqual(self.normalize_confidence(9.74), 0.0974)

    # ── Test: Benign prediction ──
    def test_benign_prediction_is_ignored(self):
        decision = self.make_decision("Benign", 0.95)
        self.assertEqual(decision["decision"], "IGNORE")
        self.assertFalse(decision["is_attack"])
        self.assertEqual(decision["severity"], "SAFE")
        self.assertFalse(decision["email_required"])

    # ── Test 5: Low confidence attack prediction ──
    def test_low_confidence_insecure_deserialization(self):
        """The EXACT false positive scenario: Insecure_Deserialization at 9.74% must be IGNORED."""
        decision = self.make_decision(
            predicted_label="Insecure_Deserialization",
            confidence=0.0974,
            category_base_severity="CRITICAL"
        )
        self.assertEqual(decision["decision"], "IGNORE",
                         f"9.74% confidence should be IGNORED, got {decision['decision']}")
        self.assertFalse(decision["is_attack"])
        self.assertEqual(decision["severity"], "SAFE")
        self.assertFalse(decision["email_required"],
                         "NO EMAIL should be sent for 9.74% confidence prediction")

    def test_medium_confidence_is_log_only(self):
        """Confidence between 40-70% should be LOG_ONLY (no email)."""
        decision = self.make_decision(
            predicted_label="SQL_Injection",
            confidence=0.55,
            category_base_severity="HIGH"
        )
        self.assertEqual(decision["decision"], "LOG_ONLY")
        self.assertFalse(decision["email_required"])

    def test_confidence_35_percent_is_ignored(self):
        """Confidence at 35% should be IGNORED (below 40% threshold)."""
        decision = self.make_decision(
            predicted_label="XSS",
            confidence=0.35,
            category_base_severity="HIGH"
        )
        self.assertEqual(decision["decision"], "IGNORE")
        self.assertFalse(decision["email_required"])

    # ── Test 6: Real SSH brute force with high confidence ──
    def test_high_confidence_ssh_bruteforce(self):
        """SSH_BruteForce at 78.9% confidence must trigger ALERT + HIGH + email."""
        decision = self.make_decision(
            predicted_label="SSH_BruteForce",
            confidence=0.789,
            category_base_severity="HIGH"
        )
        self.assertEqual(decision["decision"], "ALERT",
                         f"78.9% confidence should be ALERT, got {decision['decision']}")
        self.assertTrue(decision["is_attack"])
        self.assertEqual(decision["severity"], "HIGH",
                         f"78.9% SSH_BruteForce should be HIGH, got {decision['severity']}")
        self.assertTrue(decision["email_required"],
                        "Email MUST be sent for 78.9% confidence SSH_BruteForce")

    # ── Test 7: SQL Injection with high confidence ──
    def test_high_confidence_sql_injection(self):
        """SQL_Injection at 92% confidence must trigger ALERT + email."""
        decision = self.make_decision(
            predicted_label="SQL_Injection",
            confidence=0.92,
            category_base_severity="HIGH"
        )
        self.assertEqual(decision["decision"], "ALERT")
        self.assertTrue(decision["is_attack"])
        self.assertTrue(decision["email_required"],
                        "Email MUST be sent for 92% confidence SQL_Injection")

    def test_critical_category_at_75_percent(self):
        """CRITICAL category (e.g. ReverseShell) at 75% should alert with CRITICAL severity."""
        decision = self.make_decision(
            predicted_label="ReverseShell",
            confidence=0.75,
            category_base_severity="CRITICAL"
        )
        self.assertEqual(decision["decision"], "ALERT")
        self.assertTrue(decision["is_attack"])
        self.assertEqual(decision["severity"], "CRITICAL",
                         "CRITICAL category at 70-85% confidence should preserve CRITICAL severity")
        self.assertTrue(decision["email_required"])

    def test_critical_category_at_95_percent(self):
        """CRITICAL category at 95% should be CRITICAL severity with email."""
        decision = self.make_decision(
            predicted_label="ReverseShell",
            confidence=0.96,
            category_base_severity="CRITICAL"
        )
        self.assertEqual(decision["decision"], "ALERT")
        self.assertEqual(decision["severity"], "CRITICAL")
        self.assertTrue(decision["email_required"])

    def test_medium_category_at_high_confidence(self):
        """MEDIUM category at 90% should be HIGH severity."""
        decision = self.make_decision(
            predicted_label="PortScanning",
            confidence=0.90,
            category_base_severity="MEDIUM"
        )
        self.assertEqual(decision["decision"], "ALERT")
        self.assertEqual(decision["severity"], "HIGH")
        self.assertTrue(decision["email_required"])


# ════════════════════════════════════════════════════════
# TEST: RISK ENGINE WITH NEW THRESHOLD
# ════════════════════════════════════════════════════════

class TestRiskEngineUpdated(unittest.TestCase):
    """Test the updated Risk Engine with the AI_CONFIDENCE_THRESHOLD gate."""

    def test_low_confidence_attack_is_safe(self):
        """Any attack prediction below AI_CONFIDENCE_THRESHOLD must return SAFE."""
        from app.risk_engine import RiskEngine
        risk = RiskEngine.calculate_risk("Insecure_Deserialization", 0.0974)
        self.assertEqual(risk, "SAFE",
                         f"9.74% Insecure_Deserialization should be SAFE, got {risk}")

    def test_low_confidence_ssh_is_safe(self):
        from app.risk_engine import RiskEngine
        risk = RiskEngine.calculate_risk("SSH_BruteForce", 0.55)
        self.assertEqual(risk, "SAFE",
                         f"55% SSH_BruteForce should be SAFE (below 70% threshold), got {risk}")

    def test_high_confidence_attack_keeps_risk(self):
        from app.risk_engine import RiskEngine
        risk = RiskEngine.calculate_risk("SQL_Injection", 0.92)
        self.assertEqual(risk, "HIGH",
                         f"92% SQL_Injection should be HIGH, got {risk}")

    def test_benign_high_confidence_is_safe(self):
        from app.risk_engine import RiskEngine
        risk = RiskEngine.calculate_risk("Benign", 0.95)
        self.assertEqual(risk, "SAFE")

    def test_benign_low_confidence_is_low(self):
        from app.risk_engine import RiskEngine
        risk = RiskEngine.calculate_risk("Benign", 0.50)
        self.assertEqual(risk, "LOW")

    def test_critical_category_at_95_is_critical(self):
        from app.risk_engine import RiskEngine
        risk = RiskEngine.calculate_risk("ReverseShell", 0.95)
        self.assertEqual(risk, "CRITICAL")


# ════════════════════════════════════════════════════════
# TEST 8: DDOS DETECTOR (INDEPENDENT FROM NLP)
# ════════════════════════════════════════════════════════

class TestDDoSDetectorIndependent(unittest.TestCase):
    """Test that DDoS detection continues to work independently from the NLP pipeline."""

    def test_ddos_single_ip_flood(self):
        """Flooding from a single IP must still trigger DDoS alert."""
        from app.ddos_detector import DDoSDetector
        detector = DDoSDetector(
            enabled=True,
            window_seconds=10,
            request_threshold=100,
            ip_threshold=50,
            endpoint_threshold=200
        )
        import time
        now = time.time()
        # Simulate 60 requests from same IP in 10 seconds
        for i in range(60):
            result = detector.record_request(
                ip="192.168.1.100",
                endpoint="/api/data",
                method="GET",
                status_code=200,
                now=now + (i * 0.1)
            )
        self.assertEqual(result["risk_level"], "HIGH",
                         f"60 requests from single IP should be HIGH, got {result['risk_level']}")
        self.assertTrue(result["is_anomaly"])

    def test_ddos_distributed_attack(self):
        """Distributed DDoS with many IPs must still trigger alert."""
        from app.ddos_detector import DDoSDetector
        detector = DDoSDetector(
            enabled=True,
            window_seconds=10,
            request_threshold=50,
            ip_threshold=50,
            endpoint_threshold=200
        )
        import time
        now = time.time()
        # Simulate 60 requests from 20 different IPs
        for i in range(60):
            result = detector.record_request(
                ip=f"192.168.1.{i % 20 + 1}",
                endpoint="/login",
                method="POST",
                status_code=200,
                now=now + (i * 0.05)
            )
        self.assertIn(result["risk_level"], ("HIGH", "CRITICAL"),
                      f"Distributed DDoS should be HIGH or CRITICAL, got {result['risk_level']}")
        self.assertTrue(result["is_anomaly"])

    def test_normal_traffic_is_not_anomaly(self):
        """Normal low-volume traffic should not trigger DDoS."""
        from app.ddos_detector import DDoSDetector
        detector = DDoSDetector(
            enabled=True,
            window_seconds=10,
            request_threshold=100,
            ip_threshold=50,
            endpoint_threshold=200
        )
        import time
        now = time.time()
        # Simulate 5 normal requests
        for i in range(5):
            result = detector.record_request(
                ip=f"10.0.0.{i+1}",
                endpoint="/index.html",
                method="GET",
                status_code=200,
                now=now + i
            )
        self.assertEqual(result["risk_level"], "NORMAL")
        self.assertFalse(result["is_anomaly"])


# ════════════════════════════════════════════════════════
# INTEGRATION TESTS: FULL PIPELINE
# ════════════════════════════════════════════════════════

class TestFullPipelineIntegration(unittest.TestCase):
    """Integration tests verifying the complete Pre-Filter → Decision Engine pipeline."""

    def test_systemd_mount_no_email(self):
        """
        CRITICAL END-TO-END TEST: 
        The systemd Docker mount log that caused the original false positive 
        must be filtered at the pre-filter level and NEVER reach the AI model.
        """
        from app.log_pre_filter import LogPreFilter
        from app.security_decision import make_decision

        pre_filter = LogPreFilter(enabled=True)
        log = (
            "Aug 11 11:06:28 ubuntu systemd[1950]: "
            "run-docker-runtime\\x2drunc-moby-7fdc7b268c7ecc41c0370983b1f32d1813f4d7e2af5d40789e5e35c93d753407-runc.u0UJak.mount: Succeeded."
        )

        # Pre-filter should catch it
        result = pre_filter.classify(log)
        self.assertEqual(result["decision"], "BENIGN",
                         "systemd mount Succeeded MUST be caught by pre-filter as BENIGN")

        # Even if it somehow passes to Decision Engine, low confidence should block it
        decision = make_decision(
            predicted_label="Insecure_Deserialization",
            confidence=0.0974,
            category_base_severity="CRITICAL"
        )
        self.assertEqual(decision["decision"], "IGNORE")
        self.assertFalse(decision["email_required"],
                         "NO EMAIL must be sent for the systemd mount false positive")

    def test_real_attack_produces_email(self):
        """A real attack with high confidence must produce ALERT + email."""
        from app.security_decision import make_decision

        decision = make_decision(
            predicted_label="SSH_BruteForce",
            confidence=0.96,
            raw_log="Failed password for root from 192.168.1.100 port 22 ssh2",
            category_base_severity="HIGH"
        )
        self.assertEqual(decision["decision"], "ALERT")
        self.assertTrue(decision["is_attack"])
        self.assertTrue(decision["email_required"],
                        "Email MUST be sent for real high-confidence attacks")

    def test_confidence_boundary_at_threshold(self):
        """Confidence exactly at threshold (70%) should trigger ALERT."""
        from app.security_decision import make_decision

        decision = make_decision(
            predicted_label="XSS",
            confidence=0.70,
            category_base_severity="HIGH"
        )
        self.assertEqual(decision["decision"], "ALERT",
                         "Confidence at exactly 70% should be ALERT")

    def test_confidence_just_below_threshold(self):
        """Confidence just below threshold (69.9%) should be LOG_ONLY."""
        from app.security_decision import make_decision

        decision = make_decision(
            predicted_label="XSS",
            confidence=0.699,
            category_base_severity="HIGH"
        )
        self.assertEqual(decision["decision"], "LOG_ONLY",
                         "Confidence at 69.9% should be LOG_ONLY, not ALERT")
        self.assertFalse(decision["email_required"])


# ════════════════════════════════════════════════════════
# DATABASE TESTS
# ════════════════════════════════════════════════════════

class TestSecurityDecisionsDatabase(unittest.TestCase):
    """Test the security_decisions table in the database."""

    def setUp(self):
        """Create a temporary database for testing."""
        import tempfile
        from app.database import DatabaseManager
        self.tmp_dir = tempfile.mkdtemp()
        self.db_path = os.path.join(self.tmp_dir, "test_incidents.db")
        self.db = DatabaseManager(db_path=self.db_path)

    def tearDown(self):
        """Clean up temporary database."""
        import shutil
        try:
            shutil.rmtree(self.tmp_dir, ignore_errors=True)
        except Exception:
            pass

    def test_save_and_retrieve_decision(self):
        decision_id = self.db.save_security_decision(
            hostname="test-host",
            source_log="/var/log/syslog",
            raw_log="test log line",
            predicted_label="Insecure_Deserialization",
            confidence=0.0974,
            decision="IGNORE",
            severity="SAFE",
            reason="Low confidence prediction",
            email_sent=False
        )
        self.assertGreater(decision_id, 0)

        decisions = self.db.get_recent_decisions(limit=10)
        self.assertEqual(len(decisions), 1)
        self.assertEqual(decisions[0]["decision"], "IGNORE")
        self.assertEqual(decisions[0]["email_sent"], 0)

    def test_filter_decisions_by_type(self):
        # Save IGNORE decision
        self.db.save_security_decision(
            hostname="test", source_log="/var/log/syslog",
            raw_log="test1", predicted_label="Benign",
            confidence=0.95, decision="IGNORE", severity="SAFE",
            reason="Benign", email_sent=False
        )
        # Save ALERT decision
        self.db.save_security_decision(
            hostname="test", source_log="/var/log/auth.log",
            raw_log="test2", predicted_label="SSH_BruteForce",
            confidence=0.96, decision="ALERT", severity="HIGH",
            reason="High confidence", email_sent=True
        )

        ignore_decisions = self.db.get_recent_decisions(decision_filter="IGNORE")
        alert_decisions = self.db.get_recent_decisions(decision_filter="ALERT")

        self.assertEqual(len(ignore_decisions), 1)
        self.assertEqual(len(alert_decisions), 1)
        self.assertEqual(alert_decisions[0]["email_sent"], 1)


if __name__ == "__main__":
    unittest.main(verbosity=2)
