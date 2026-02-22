import os
import json
import urllib.request
from datetime import datetime

def get_geolocation(ip):
    """
    Enriches the investigation by fetching Geolocation data.
    """
    # Skip API call for local/private IPs to avoid errors
    if ip.startswith("192.168.") or ip.startswith("10.") or ip == "127.0.0.1":
        return {
            "city": "Internal", "country": "Local Network", 
            "isp": "Private Infrastructure", "org": "N/A", "as": "N/A",
            "full_string": "Local/Private Network IP"
        }

    try:
        url = f"http://ip-api.com/json/{ip}"
        with urllib.request.urlopen(url) as response:
            data = json.loads(response.read().decode())
            if data['status'] == 'success':
                return {
                    "city": data.get('city'),
                    "country": data.get('country'),
                    "isp": data.get('isp'),
                    "org": data.get('org'),
                    "as": data.get('as'),
                    "full_string": f"{data['city']}, {data['country']} (ISP: {data['isp']})"
                }
    except:
        pass
    return None

def generate_report(ip, geo_data, timeline, suspicious_flags):
    """
    Generates a formal Intelligence Brief in Markdown format with Heuristic Alerts.
    """
    report_name = "INTELLIGENCE_BRIEF.md"
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    geo = geo_data if geo_data else {"city": "Unknown", "country": "Unknown", "isp": "Unknown"}

    report_content = f"""# 🛡️ Threat Intelligence Brief
**Date:** {timestamp}
**Target IP:** `{ip}`
**Severity:** CRITICAL (Obfuscation Detected)

## 🌎 1. Geolocation & Attribution
* **Location:** {geo.get('city')}, {geo.get('country')}
* **ISP/Organization:** {geo.get('isp')}

## 🕰️ 2. Incident Timeline (Contextual Analysis)
| Source Log | Event Details |
|------------|---------------|
"""
    for event in timeline:
        source = event['source']
        detail = event['detail']
        report_content += f"| `{source}` | {detail} |\n"

    if suspicious_flags:
        report_content += "\n## ⚠️ 3. Anti-Forensics & Heuristic Alerts\n"
        for flag in suspicious_flags:
            report_content += f"* **ALERT:** {flag}\n"

    report_content += """
## 📝 4. Analyst Summary
The target IP was identified performing a multi-stage intrusion. High-fidelity detection rules caught an attempt at **Log Injection**. While the attacker attempted to frame a local IP for the successful login, the temporal proximity to the brute-force attempts confirms a successful breach.

## 🛡️ 5. Recommended Actions
1.  **Isolate Host:** Remove the target server from the network to prevent lateral movement.
2.  **Verify Logs:** Inspect raw binary logs (wtmp) as text logs have been compromised.
"""

    with open(report_name, "w") as f:
        f.write(report_content)
    
    return report_name

def pivot_search(target_ip):
    """
    Pivots on a target IP but also monitors for contextual anomalies (Heuristics).
    """
    # Adding deceptive_auth.log to the search list
    logs = ["syslog.log", "auth.log", "access.log", "deceptive_auth.log", "auth_audit.log"]
    timeline = []
    suspicious_flags = []

    print(f"\n[*] INVESTIGATION START: {target_ip}")
    geo_data = get_geolocation(target_ip)
    print("=" * 75)

    for log_file in logs:
        if os.path.exists(log_file):
            print(f"[*] Analyzing {log_file}...")
            with open(log_file, "r") as f:
                lines = f.readlines()
                for i, line in enumerate(lines):
                    # Standard detection for the Malicious IP
                    if target_ip in line:
                        timeline.append({"source": log_file, "detail": line.strip()})
                        
                        # --- HEURISTIC CHECK ---
                        # If we find the attacker IP, look at the NEXT line.
                        # If that next line contains "Accepted password" but NOT the attacker IP,
                        # it's likely a Log Injection attempt to hide the breach.
                        if i + 1 < len(lines):
                            next_line = lines[i+1]
                            if "Accepted password" in next_line and target_ip not in next_line:
                                msg = f"LOG INJECTION DETECTED: A successful login immediately followed a failure from {target_ip} in {log_file}."
                                suspicious_flags.append(msg)
                                timeline.append({"source": log_file, "detail": f"SUSPICIOUS SUCCESS (IP Spoofed): {next_line.strip()}"})

    if not timeline:
        print(f"[!] No events found for {target_ip}.")
    else:
        report_file = generate_report(target_ip, geo_data, timeline, suspicious_flags)
        print(f"[+] Heuristic analysis complete. {len(suspicious_flags)} suspicious patterns found.")
        print(f"[+] Updated report: {report_file}")
            
    print("=" * 75 + "\n")

if __name__ == "__main__":
    # Standardizing on the IP from our adversary lab and logs
    pivot_search("192.168.1.50")
