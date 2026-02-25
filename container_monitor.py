import json
import os
import re
from datetime import datetime

def analyze_docker_logs(log_file):
    """
    Scans Docker/Containerd logs for escape techniques and suspicious mounts.
    """
    # Patterns indicating a 'Container Escape' or 'Host Information Gathering'
    DANGER_PATTERNS = {
        r"--privileged": "CRITICAL: Privileged container launch (Escape risk)",
        r"mount.*/proc": "HIGH: Attempted procfs mount (Information Leak)",
        r"mount.*/etc/shadow": "CRITICAL: Host password file access attempt",
        r"docker.sock": "CRITICAL: Docker-in-Docker socket mounting (Takeover risk)",
        r"cap_add=SYS_ADMIN": "HIGH: Dangerous capability (SYS_ADMIN) granted"
    }

    if not os.path.exists(log_file):
        print(f"[!] Log file {log_file} not found. Create a mock log to test.")
        return

    print(f"[*] Analyzing Container Logs: {log_file}")
    print("=" * 60)

    try:
        with open(log_file, "r") as f:
            lines = f.readlines()

        threats = 0
        for line in lines:
            for pattern, description in DANGER_PATTERNS.items():
                if re.search(pattern, line):
                    threats += 1
                    print(f"[🚨] ALERT: {description}")
                    print(f"    - Raw Log: {line.strip()}")
                    print(f"    - Timestamp: {datetime.now().strftime('%H:%M:%S')}")
                    print("-" * 30)

        if threats == 0:
            print("[+] No container escape patterns detected.")
        else:
            print(f"[!] Total Container Threats Detected: {threats}")

    except Exception as e:
        print(f"[!] Error: {e}")

if __name__ == "__main__":
    analyze_docker_logs("container_audit.log")
