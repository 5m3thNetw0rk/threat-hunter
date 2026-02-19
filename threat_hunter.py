import re
import sys

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
                            "IP": ip_address,
                            "Attack_Type": attack_type,
                            "Raw_Log": line.strip()
                        })
                        
        print("--- 🚨 ACTIONABLE INTELLIGENCE REPORT 🚨 ---")
        for alert in threat_intel:
            print(f"[!] THREAT DETECTED: {alert['Attack_Type']} from IP {alert['IP']}")
            print(f"    Evidence: {alert['Raw_Log']}\n")
            
        print(f"[*] Total Threats Identified: {len(threat_intel)}")

    except FileNotFoundError:
        print("[!] Error: Log file not found.")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python3 threat_hunter.py <logfile>")
    else:
        analyze_logs(sys.argv[1])
