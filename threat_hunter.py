import re
import sys
import json
import os
from datetime import datetime
from dotenv import load_dotenv
from OTXv2 import OTXv2
import IndicatorTypes

# 1. Load Environment & API Key
load_dotenv()
OTX_API_KEY = os.getenv('OTX_KEY')

# Initialize OTX (Only if key exists)
if OTX_API_KEY:
    otx = OTXv2(OTX_API_KEY)
else:
    print("[!] Warning: OTX_KEY not found in .env. Reputation checks will fail.")

# 2. Local Intelligence Database (Context)
GEO_INTEL = {
    "192.168.1.5": "Internal Network (UK)",
    "10.0.0.9": "Internal Network (UK)",
    "172.16.0.4": "Cloud Provider (US-East)",
    "10.10.10.50": "Research Lab (DE)"
}

def get_geo_context(ip):
    return GEO_INTEL.get(ip, "High-Risk/Unknown Region")

def check_reputation(ip):
    """Queries AlienVault OTX for live reputation data."""
    if not OTX_API_KEY:
        return "No API Key"
    try:
        # Check general IP reputation
        result = otx.get_indicator_details_full(IndicatorTypes.IPv4, ip)
        pulse_count = result['general']['pulse_info']['count']
        
        if pulse_count > 0:
            return f"MALICIOUS ({pulse_count} Pulses found)"
        return "Neutral/Safe"
    except Exception:
        return "Lookup Error (Check Connection/API Key)"

def send_soc_alert(threat_type, ip, reputation):
    timestamp = datetime.now().strftime("%H:%M:%S")
    print(f"\n[📡 🚨 ESCALATION SENT] {timestamp}")
    print(f"[*] ALERT: {threat_type} from {ip}")
    print(f"[*] INTEL: Reputation is {reputation}")

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
                        
                        # --- ENRICHMENT BLOCK ---
                        location = get_geo_context(ip_address)
                        reputation = check_reputation(ip_address)
                        
                        # DEBUG PRINT (Helps you see it in the terminal)
                        print(f"[🔍] Identified: {attack_type} | IP: {ip_address} | Intel: {reputation}")

                        # SEVERITY LOGIC: Critical if attack is high-tier OR if IP is known malicious
                        is_malicious = "MALICIOUS" in reputation
                        severity = "CRITICAL" if attack_type in ["SQL_Injection", "XSS_Attempt"] or is_malicious else "LOW"
                        
                        alert_data = {
                            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                            "source_ip": ip_address,
                            "location": location,
                            "reputation": reputation,
                            "threat_type": attack_type,
                            "severity": severity,
                            "evidence": line.strip()
                        }
                        threat_intel.append(alert_data)

                        if severity == "CRITICAL":
                            send_soc_alert(attack_type, ip_address, reputation)
        
        # Save results
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
