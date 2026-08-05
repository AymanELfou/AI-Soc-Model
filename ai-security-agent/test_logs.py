"""
test_logs.py
============
Script de test automatique pour envoyer 3 logs de test à l'AI Security Agent.
Usage: python test_logs.py
"""

import requests
import json
import sys

API_URL = "http://localhost:8000/api/v1/analyze"

test_cases = [
    {
        "name": "1. Attaque SSH Brute Force",
        "payload": {
            "log_line": "Aug 05 14:30:00 server sshd[1234]: Failed password for root from 192.168.1.100 port 54321 ssh2",
            "source_log": "/var/log/auth.log"
        }
    },
    {
        "name": "2. Attaque Web SQL Injection",
        "payload": {
            "log_line": '192.168.1.50 - - [05/Aug/2026:15:32:00 +0000] "GET /index.php?id=-1%20UNION%20SELECT%201,username,password%20FROM%20users-- HTTP/1.1" 200 4523',
            "source_log": "/var/log/nginx/access.log"
        }
    },
    {
        "name": "3. Attaque Docker Abuse / Privilege Escalation",
        "payload": {
            "log_line": "Aug 05 15:35:00 server dockerd[8888]: docker run -v /:/mnt --rm -it alpine chroot /mnt sh",
            "source_log": "/var/log/syslog"
        }
    }
]

print("=" * 70)
print("🚀 ENVOI DES LOGS DE TEST À L'AI SECURITY AGENT")
print("=" * 70)

for test in test_cases:
    print(f"\n[+] Envoi de : {test['name']}...")
    try:
        response = requests.post(API_URL, json=test["payload"], timeout=10)
        if response.status_code == 200:
            data = response.json()
            print(f"    ✅ Résultat    : ID #{data['incident_id']}")
            print(f"    🎯 Prédiction  : {data['prediction']} (Confiance: {data['high_risk_percentage']}%)")
            print(f"    ⚠️ Niveau Risque: [{data['risk_level']}]")
            print(f"    📧 Email Alerte : {'Envoyé' if data['email_alert_sent'] else 'Non requis / Supprimé'}")
        else:
            print(f"    ❌ Erreur API  : Code {response.status_code} - {response.text}")
    except Exception as e:
        print(f"    ❌ Erreur de connexion : L'agent n'est pas démarré sur http://localhost:8000 ({e})")

print("\n" + "=" * 70)
print("✅ Test des 3 logs terminé !")
