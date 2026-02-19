import json
from collections import Counter

def generate_trends(json_file):
    try:
        with open(json_file, 'r') as f:
            data = json.load(f)
        
        ips = [event['source_ip'] for event in data]
        threat_types = [event['threat_type'] for event in data]
        
        ip_counts = Counter(ips)
        type_counts = Counter(threat_types)
        
        print("--- 📊 THREAT TREND ANALYSIS REPORT 📊 ---")
        
        print("\n[+] Top Attacking IP Addresses:")
        for ip, count in ip_counts.most_common(3):
            print(f"    - {ip}: {count} attempts")
            
        print("\n[+] Most Frequent Attack Tactics:")
        for t_type, count in type_counts.most_common(3):
            print(f"    - {t_type}: {count} hits")
            
        top_ip = ip_counts.most_common(1)[0][0]
        print(f"\n[!] STRATEGIC RECOMMENDATION: Focus investigative resources on {top_ip}.")

    except FileNotFoundError:
        print("[!] Error: detected_threats.json not found. Run threat_hunter.py first.")

if __name__ == "__main__":
    generate_trends("detected_threats.json")
