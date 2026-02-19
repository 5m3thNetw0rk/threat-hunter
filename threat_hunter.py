import re
import sys
import json
from datetime import datetime

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
                        threat_intel.append({
                            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                            "source_ip": ip_address,
                            "threat_type": attack_type,
                            "severity": "High" if attack_type in ["SQL_Injection", "XSS_Attempt"] else "Medium",
                            "evidence": line.strip()
                        })
        
        # 1. Print to console for immediate visibility
        for alert in threat_intel:
            print(f"[!] {alert['threat_type']} detected from {alert['source_ip']}")

        # 2. Export to JSON for system integration
        output_file = "detected_threats.json"
        with open(output_file, 'w') as jf:
            json.dump(threat_intel, jf, indent=4)
            
        print(f"\n[+] Success: {len(threat_intel)} threats exported to {output_file}")

    except FileNotFoundError:
        print("[!] Error: Log file not found.")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python3 threat_hunter.py <logfile>")
    else:
        analyze_logs(sys.argv[1])
