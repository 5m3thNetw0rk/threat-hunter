import os
import time
import hashlib
import psutil
import shutil
from datetime import datetime

# CONFIGURATION
# We monitor a "Canary" directory. If any file here is touched, it's a high-fidelity alert.
WATCH_DIR = "./canary_vault"
BACKUP_DIR = "./secure_backups"
CANARY_FILES = ["financial_report.xlsx", "passwords.txt", "private_key.pem"]

def setup_environment():
    """Initializes the environment with canary files and backups."""
    for d in [WATCH_DIR, BACKUP_DIR]:
        if not os.path.exists(d):
            os.makedirs(d)
    
    # Create the canary files with dummy data
    for filename in CANARY_FILES:
        path = os.path.join(WATCH_DIR, filename)
        backup_path = os.path.join(BACKUP_DIR, filename)
        
        content = f"CONFIDENTIAL DATA - DO NOT MODIFY - {filename}"
        with open(path, "w") as f:
            f.write(content)
        
        # Create a 'Golden Image' backup for auto-healing
        shutil.copy2(path, backup_path)
    
    print(f"[*] Warden initialized. Monitoring {len(CANARY_FILES)} canary files in {WATCH_DIR}")

def get_file_hash(filepath):
    """Calculates SHA-256 hash of a file."""
    hasher = hashlib.sha256()
    with open(filepath, 'rb') as f:
        buf = f.read()
        hasher.update(buf)
    return hasher.hexdigest()

def active_response(malicious_file):
    """
    Attempts to identify and kill the process that modified the canary file,
    then restores the file from backup.
    """
    print(f"\n[!!!] CRITICAL: TAMPERS DETECTED ON {malicious_file}")
    
    # 1. Identify suspicious process (Mock-logic: in real Linux we'd use lsof or auditd)
    # For this demo, we'll list the most recent process using high CPU as a 'suspect'
    suspect = sorted(psutil.process_iter(['pid', 'name', 'cpu_percent']), 
                    key=lambda x: x.info['cpu_percent'], reverse=True)[0]
    
    print(f"[!] ACTION: Identifying source... Suspected Process: {suspect.info['name']} (PID: {suspect.info['pid']})")
    
    # 2. Automated Remediation (Auto-Healing)
    filename = os.path.basename(malicious_file)
    shutil.copy2(os.path.join(BACKUP_DIR, filename), malicious_file)
    print(f"[+] ACTION: File '{filename}' has been restored from Secure Backup.")
    
    # 3. Log the Incident
    with open("WARDEN_ALERTS.log", "a") as log:
        log.write(f"{datetime.now()} - ALERT: Tampering detected on {filename}. Process {suspect.info['name']} flagged.\n")

def monitor():
    """Main loop to monitor file integrity."""
    # Store initial hashes
    baselines = {f: get_file_hash(os.path.join(WATCH_DIR, f)) for f in CANARY_FILES}
    
    print("[*] Monitoring for Ransomware/Tampering... (Press Ctrl+C to stop)")
    try:
        while True:
            for filename in CANARY_FILES:
                path = os.path.join(WATCH_DIR, filename)
                current_hash = get_file_hash(path)
                
                if current_hash != baselines[filename]:
                    active_response(path)
                    # Reset baseline after restoration
                    baselines[filename] = get_file_hash(path)
            
            time.sleep(1) # Check every second
    except KeyboardInterrupt:
        print("\n[*] Warden service stopped.")

if __name__ == "__main__":
    setup_environment()
    monitor()
