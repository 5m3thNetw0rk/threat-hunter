🛡️ Threat Hunter: Advanced Detection & Response Suite

This repository is a comprehensive Cyber Defense suite designed to automate the lifecycle of security operations: from vulnerability scanning and threat intelligence enrichment to Active Endpoint Response and Adversary Emulation.

🏗️ Technical Architecture

The suite operates across multiple layers of the OSI model, integrating local system telemetry with global threat intelligence.

       [ TELEMETRY SOURCES ]                 [ DETECTION ENGINE ]               [ ACTIVE RESPONSE ]
    +-------------------------+          +-------------------------+        +-------------------------+
    |  Network / System Logs  | -------> |    threat_hunter.py     | -----> |   rule_generator.py     |
    +-------------------------+          +-------------------------+        +------------+------------+
                                                    ^                                    |
                                                    |                                    v
    +-------------------------+          +----------+--------------+        +------------+------------+
    |  Endpoint Canary Vault  | <------> |      warden.py (HIDS)   |        | firewall_blacklist.txt  |
    +-------------------------+          +----------+--------------+        +------------+------------+
                                                    |                                    |
                                                    v                                    v
    +-------------------------+          +-------------------------+        +-------------------------+
    |    Adversary Simulation | <------> |     adversary_lab.py    |        |    snort_rules.rules    |
    +-------------------------+          +-------------------------+        +-------------------------+



🛠️ Project Components

1. Active Endpoint Defense (warden.py)

Domain: Host-Based Intrusion Detection (HIDS) & Incident Response.

Function: Monitors "Canary Files" using SHA-256 hashing.

Active Response: Upon detecting tampering (e.g., Ransomware simulation), it identifies the offending Process ID (PID) via psutil and executes Automated Remediation by restoring the file from a secure "Golden Image" backup.

2. Adversary Simulation Lab (adversary_lab.py)

Domain: Red Teaming & Security Validation.

Function: Emulates multi-stage attacks including SSH Brute Force, Log Injection (to frame decoy IPs), and Ransomware file encryption. This ensures the detection scripts are calibrated correctly.

3. Threat Intelligence & Triage (threat_hunter.py)

Domain: CTI & Log Analysis.

Function: Parses system logs to detect patterns like SQLi/XSS. Enriches data via AlienVault OTX API to identify known-malicious actors based on global reputation.

4. Network Forensics (net_sniffer.py)

Domain: Traffic Analysis & DPI.

Function: Utilizes Scapy for Deep Packet Inspection (DPI) at Layer 7. Identifies unencrypted credential leaks and logs traffic to .pcap format for Wireshark analysis.

5. Automated Defense (rule_generator.py)

Domain: Collaborative Defense & Security Automation (SOAR).

Function: Translates intelligence from threat_hunter.py into actionable firewall blacklists and Snort-compatible IDS rules.

⚖️ Compliance & NIST Mapping

This suite aligns with the NIST Cybersecurity Framework (CSF):

Identify: vuln_parser.py (Vulnerability scanning)

Protect: net_sniffer.py (Monitoring insecure protocols)

Detect: threat_hunter.py (Log monitoring)

Respond/Recover: warden.py (Auto-healing and file restoration)

🚀 Getting Started

Clone the repository:

git clone [https://github.com/5m3thNetw0rk/threat-hunter](https://github.com/5m3thNetw0rk/threat-hunter)
cd threat-hunter


Initialize the Defense:

python3 warden.py


Simulate an Attack:
In a separate terminal, run python3 adversary_lab.py and select an attack profile to see the Warden and Hunter respond in real-time.
