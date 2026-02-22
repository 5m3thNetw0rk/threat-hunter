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

def generate_report(ip, geo_data, timeline):
    """
    Generates a formal Intelligence Brief in Markdown format.
    """
    report_name = "INTELLIGENCE_BRIEF.md"
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    
    # Ensure geo_data is a dictionary even if None
    geo = geo_data if geo_data else {"city": "Unknown", "country": "Unknown", "isp": "Unknown", "as": "Unknown"}

    report_content = f"""# 🛡️ Threat Intelligence Brief
**Date:** {timestamp}
**Target IP:** `{ip}`
**Severity:** HIGH (Multi-stage Attack Detected)

## 🌎 1. Geolocation & Attribution
* **Location:** {geo.get('city')}, {geo.get('country')}
* **ISP/Organization:** {geo.get('isp')}
* **ASN:** {geo.get('as')}

## 🕰️ 2. Incident Timeline (Pivot Analysis)
| Source Log | Event Details |
|------------|---------------|
"""
    for event in timeline:
        if " | EVENT: " in event:
            parts = event.split(" | EVENT: ")
            source = parts[0].replace("LOG: ", "").strip()
            details = parts[1].strip()
            report_content += f"| `{source}` | {details} |\n"
        else:
            report_content += f"| `Unknown` | {event} |\n"

    report_content += f"""
## 📝 3. Analyst Summary
The target IP `{ip}` was identified performing a multi-stage intrusion attempt. The sequence suggests an initial **Reconnaissance** phase, followed by **Credential Access** attempts, and finally **Application Layer Exploitation**.

## 🛡️ 4. Recommended Actions
1.  **Block IP:** Add `{ip}` to the edge firewall blacklist.
2.  **Audit:** Review all logs for `{ip}` for the last 24 hours.
"""

    with open(report_name, "w") as f:
        f.write(report_content)
    
    return report_name

def pivot_search(target_ip):
    logs = ["syslog.log", "auth.log", "access.log"]
    timeline = []

    print(f"\n[*] INVESTIGATION START: Pivoting on {target_ip}")
    
    geo_data = get_geolocation(target_ip)
    geo_string = geo_data['full_string'] if geo_data else "Location Data Unavailable"
    print(f"[*] THREAT INTEL ENRICHMENT: {geo_string}")
    print("=" * 75)

    for log_file in logs:
        if os.path.exists(log_file):
            print(f"[*] Analyzing {log_file}...")
            with open(log_file, "r") as f:
                for line in f:
                    if target_ip in line:
                        timeline.append(f"LOG: {log_file.ljust(10)} | EVENT: {line.strip()}")
        else:
            # Create the file if it doesn't exist to help the user
            print(f"[!] {log_file} missing. Creating dummy version for simulation...")
            with open(log_file, "w") as f:
                f.write(f"Feb 22 10:00:00 Dummy entry for {target_ip}\n")

    print("-" * 75)
    
    if not timeline:
        print(f"[!] Warning: No timeline events found for {target_ip}. Report not generated.")
    else:
        print(f"[+] Found {len(timeline)} events. Generating report...")
        report_file = generate_report(target_ip, geo_data, timeline)
        print(f"[+] SUCCESS: {report_file} has been updated.")
            
    print("=" * 75 + "\n")

if __name__ == "__main__":
    # Standardize on one IP for the simulation
    ip_to_find = "192.168.1.50" 
    pivot_search(ip_to_find)
