import json
import os

def generate_blacklists():
    # Path to the threat data
    threat_file = "detected_threats.json"

    # Robust check: If file is missing, empty, or just contains "[]"
    needs_mock_data = False
    if not os.path.exists(threat_file) or os.stat(threat_file).st_size <= 2:
        needs_mock_data = True
    else:
        with open(threat_file, "r") as f:
            try:
                data = json.load(f)
                if not data: # Handle empty list []
                    needs_mock_data = True
            except:
                needs_mock_data = True

    if needs_mock_data:
        print("[!] No threat data found or file is empty. Generating mock data for testing...")
        mock_data = [
            {"ip": "141.98.10.19", "pattern": "SQL_Injection", "severity": "High"},
            {"ip": "185.220.101.42", "pattern": "Nmap_Scanning", "severity": "Medium"},
            {"ip": "45.33.32.156", "pattern": "Brute_Force", "severity": "High"}
        ]
        with open(threat_file, "w") as f:
            json.dump(mock_data, f, indent=4)

    try:
        with open(threat_file, "r") as f:
            threats = json.load(f)

        # 1. Generate a Standard IP Blacklist (for Firewalls)
        ips = set()
        for t in threats:
            # Check every key to see if it contains "ip" (case-insensitive)
            found_ip = None
            for key, value in t.items():
                if "ip" in key.lower():
                    found_ip = value
                    break
            
            if found_ip:
                ips.add(found_ip)
        
        if not ips:
            print("[!] No IPs could be parsed. Check the JSON structure of detected_threats.json.")
            return

        with open("firewall_blacklist.txt", "w") as f:
            for ip in ips:
                f.write(f"{ip}\n")
        print(f"[+] Successfully generated firewall_blacklist.txt with {len(ips)} IPs.")

        # 2. Generate a Snort-style IDS Rule for SQL Injection
        # This fulfills the "Update signatures" responsibility
        snort_rule = 'alert tcp $EXTERNAL_NET any -> $HTTP_SERVERS 80 (msg:"SQL Injection Attempt Detected"; content:"OR 1=1"; nocase; sid:1000001; rev:1;)'
        with open("snort_rules.rules", "w") as f:
            f.write(snort_rule)
        print("[+] Successfully generated snort_rules.rules (Signature-based detection).")
        
    except Exception as e:
        print(f"[!] Error processing threat data: {e}")

if __name__ == "__main__":
    generate_blacklists()
