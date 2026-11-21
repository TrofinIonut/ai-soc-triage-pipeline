import json
import os
import random
from datetime import datetime, timedelta

OUTPUT_FILE = os.path.join("data", "raw_security_logs.jsonl")
TOTAL_NORMAL_LOGS = 49200

NORMAL_IPS = [f"192.168.1.{i}" for i in range(10, 150)] + [f"10.0.0.{i}" for i in range(5, 80)]
NORMAL_ENDPOINTS = [
    ("GET", "/index.html", 200),
    ("GET", "/api/products", 200),
    ("GET", "/api/profile", 200),
    ("POST", "/api/login", 200),
    ("GET", "/assets/app.js", 200),
    ("GET", "/api/orders", 200),
    ("GET", "/about", 200),
    ("GET", "/api/search?q=laptop", 200),
]
USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/128.0.0.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_5) Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64) Firefox/129.0",
]


def generate_dataset():
    os.makedirs("data", exist_ok=True)
    start_time = datetime.now() - timedelta(hours=2)
    logs = []

    # 1. Trafic legitim (zgomot de fond)
    for _ in range(TOTAL_NORMAL_LOGS):
        method, path, status = random.choice(NORMAL_ENDPOINTS)
        ts = start_time + timedelta(seconds=random.randint(0, 7200))
        logs.append({
            "timestamp": ts.isoformat(),
            "src_ip": random.choice(NORMAL_IPS),
            "method": method,
            "endpoint": path,
            "status_code": status,
            "bytes_sent": random.randint(400, 15000),
            "user_agent": random.choice(USER_AGENTS),
        })

    # 2. Atac 1: Credential Brute-Force pe /api/login
    attacker_bf = "185.220.101.42"
    bf_start = start_time + timedelta(minutes=35)
    for i in range(320):
        logs.append({
            "timestamp": (bf_start + timedelta(milliseconds=i * 400)).isoformat(),
            "src_ip": attacker_bf,
            "method": "POST",
            "endpoint": "/api/login",
            "status_code": 401,
            "bytes_sent": 280,
            "user_agent": "python-requests/2.31.0",
        })

    # 3. Atac 2: SQL Injection Probing
    attacker_sqli = "45.133.1.99"
    sqli_payloads = [
        "/api/products?id=1'%20OR%20'1'='1",
        "/api/products?id=1%20UNION%20SELECT%20username,password%20FROM%20users--",
        "/api/search?q=';DROP%20TABLE%20orders;--",
        "/api/products?id=1'%20AND%20SLEEP(5)--",
    ]
    sqli_start = start_time + timedelta(minutes=60)
    for i in range(180):
        logs.append({
            "timestamp": (sqli_start + timedelta(seconds=i * 2)).isoformat(),
            "src_ip": attacker_sqli,
            "method": "GET",
            "endpoint": random.choice(sqli_payloads),
            "status_code": random.choice([403, 500]),
            "bytes_sent": 512,
            "user_agent": "sqlmap/1.8.4#stable",
        })

    # 4. Atac 3: Directory & Sensitive File Enumeration (Recon)
    attacker_recon = "91.240.118.17"
    recon_paths = ["/.env", "/wp-admin", "/.git/config", "/etc/passwd", "/backup.zip", "/admin/login"]
    recon_start = start_time + timedelta(minutes=80)
    for i in range(250):
        logs.append({
            "timestamp": (recon_start + timedelta(milliseconds=i * 600)).isoformat(),
            "src_ip": attacker_recon,
            "method": "GET",
            "endpoint": random.choice(recon_paths),
            "status_code": 404,
            "bytes_sent": 320,
            "user_agent": "Gobuster/3.6",
        })

    # 5. Atac 4: Data Exfiltration / API Scraping masiv
    attacker_exfil = "103.85.24.11"
    exfil_start = start_time + timedelta(minutes=100)
    for i in range(50):
        logs.append({
            "timestamp": (exfil_start + timedelta(seconds=i * 3)).isoformat(),
            "src_ip": attacker_exfil,
            "method": "GET",
            "endpoint": f"/api/export/users?page={i+1}",
            "status_code": 200,
            "bytes_sent": random.randint(4_500_000, 8_000_000),
            "user_agent": "curl/8.4.0",
        })

    random.shuffle(logs)

    with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
        for entry in logs:
            f.write(json.dumps(entry) + "\n")

    print(f"[OK] Generat {len(logs)} loguri in {OUTPUT_FILE}")


if __name__ == "__main__":
    generate_dataset()