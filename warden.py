import os
import time
import hashlib
import psutil
import shutil
import requests # Need: pip install requests
from datetime import datetime

# CONFIGURATION
WATCH_DIR = os.path.abspath("./canary_vault")
BACKUP_DIR = os.path.abspath("./secure_backups")
CANARY_FILES = ["financial_report.xlsx", "passwords.txt", "private_key.pem"]

# ALERTING CONFIG (Discord/Slack/Teams Webhook)
# To test: Create a Discord server -> Settings -> Integrations -> Webhooks -> Copy URL
WEBHOOK_URL = "" 

def notify(message):
    """Sends a real-time alert to a SOC channel via Webhook."""
    if not WEBHOOK_URL:
        print("[!] Alerting: Webhook URL not configured. Skipping remote notification.")
        return

    payload = {
        "content": f"🚨 **WARDEN HIDS ALERT** 🚨\n{message}",
        "username": "Endpoint Warden"
    }
    
    try:
        # Exponential backoff/retry logic would go here in production
        response = requests.post(WEBHOOK_URL, json=payload, timeout=5)
        if response.status_code == 204 or response.status_code == 200:
            print("[+] Remote Alert Sent Successfully.")
    except Exception as e:
        print(f"[!] Alerting Failed: {e}")

def setup_environment():
    """Initializes the environment and golden images."""
    for d in [WATCH_DIR, BACKUP_DIR]:
        if not os.path.exists(d):
            os.makedirs(d)
    
    for filename in CANARY_FILES:
        path = os.path.join(WATCH_DIR, filename)
        backup_path = os.path.join(BACKUP_DIR, filename)
        content = f"CONFIDENTIAL DATA - {filename}\nGenerated: {datetime.now()}"
        with open(path, "w") as f: f.write(content)
        shutil.copy2(path, backup_path)
    
    print(f"[*] Warden HIDS Online. Monitoring: {WATCH_DIR}")

def get_file_hash(filepath):
    """SHA-256 integrity check."""
    hasher = hashlib.sha256()
    try:
        with open(filepath, 'rb') as f:
            buf = f.read()
            hasher.update(buf)
        return hasher.hexdigest()
    except FileNotFoundError:
        return "deleted"

def active_response(malicious_file):
    """Forensics, Remediation, and Notification."""
    filename = os.path.basename(malicious_file)
    print(f"\n[!!!] TAMPER DETECTED: {filename}")
    
    # 1. Forensic Lookup
    try:
        suspect = sorted(psutil.process_iter(['pid', 'name', 'username']), 
                        key=lambda x: x.info['pid'], reverse=True)[0]
        source = f"Process: {suspect.info['name']} (PID: {suspect.info['pid']})"
    except:
        source = "Unknown Source"

    # 2. Automated Remediation
    shutil.copy2(os.path.join(BACKUP_DIR, filename), malicious_file)
    
    # 3. Trigger Alerting
    alert_msg = (
        f"**Event:** File Integrity Violation\n"
        f"**File:** `{filename}`\n"
        f"**Source:** `{source}`\n"
        f"**Action:** Auto-Restored from Backup\n"
        f"**Timestamp:** `{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}`"
    )
    notify(alert_msg)

def monitor():
    baselines = {f: get_file_hash(os.path.join(WATCH_DIR, f)) for f in CANARY_FILES}
    try:
        while True:
            for filename in CANARY_FILES:
                path = os.path.join(WATCH_DIR, filename)
                if get_file_hash(path) != baselines[filename]:
                    active_response(path)
                    baselines[filename] = get_file_hash(path)
            time.sleep(0.5)
    except KeyboardInterrupt:
        print("\n[*] Shutting down...")

if __name__ == "__main__":
    setup_environment()
    monitor()
