import re
import sys
import json
from datetime import datetime

def send_soc_alert(threat_type, ip):
    """Simulates an API call to a Slack or Discord Webhook for high-priority threats."""
    timestamp = datetime.now().strftime("%H:%M:%S")
    print(f"\n[📡 🚨 ESCALATION SENT] {timestamp} - ALERT: {threat_type} detected from {ip}")
    print(f"[*] ACTION: Incident Response team notified via Webhook.")

def analyze_logs(filepath):
    print(f"[*] Starting Threat Hunt on: {filepath}...\n")
    
    signatures = {
        "SQL_Injection": r"('|%27|OR 1=1|SELECT|UNION)",
        "XSS_Attempt": r"(<script>|%3Cscript%3E)",
        "Dirb_Reconnaissance": r"dirb",
        "Nmap_Scanning": r"Nmap"
    }

    threat_intel = []

    try:
        with open(filepath, 'r') as file:
            for line in file:
                for attack_type, pattern in signatures.items():
                    if re.search(pattern, line, re.IGNORECASE):
                        ip_address = line.split(' ')[0]
                        
                        # Categorize Severity
                        severity = "CRITICAL" if attack_type in ["SQL_Injection", "XSS_Attempt"] else "LOW"
                        
                        alert_data = {
                            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                            "source_ip": ip_address,
                            "threat_type": attack_type,
                            "severity": severity,
                            "evidence": line.strip()
                        }
                        threat_intel.append(alert_data)

                        # Logic: Only escalate CRITICAL threats to the SOC channel
                        if severity == "CRITICAL":
                            send_soc_alert(attack_type, ip_address)
        
        # Export findings
        with open("detected_threats.json", "w") as jf:
            json.dump(threat_intel, jf, indent=4)
            
        print(f"\n[+] Hunt Complete. {len(threat_intel)} events logged to detected_threats.json")

    except FileNotFoundError:
        print("[!] Error: Log file not found.")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python3 threat_hunter.py <logfile>")
    else:
        analyze_logs(sys.argv[1])
