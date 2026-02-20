🛡️ Threat Hunter: Advanced Detection & Response Suite

This repository is a collection of Python-based security tools designed to automate the lifecycle of cyber defense: from vulnerability scanning and real-time threat detection to automated incident response.

🏗️ Technical Architecture

The following diagram illustrates how the components of this suite interact to provide a defense-in-depth posture:

graph TD
    A[Data Sources: Logs, Packets, Process] --> B{Normalization Engine}
    B -->|Structured Data| C[Active Hunting Layer]
    B -->|Unstructured Feed| D[Passive Hunting Layer]
    subgraph "Analysis Core"
    C --> C1[Anomaly Detection]
    C --> C2[Least Frequency Analysis]
    C --> C3[Behavioral Analytics]
    end
    subgraph "Intelligence & Mapping"
    D --> D1[IOC Correlation]
    D1 --> D2[Pyramid of Pain Mapping]
    D2 --> E[MITRE ATT&CK TTPs]
    end
    C --> F[Hunt Blueprint / Reporting]
    D --> F
    F --> G[Incident Response / Remediation]
        
🛠️ Project Components

1. Threat Intelligence & Triage (threat_hunter.py)

Domain: Threat Intelligence Analysis

Function: Parses system logs using Regex to detect SQLi/XSS. Enriches data by querying the AlienVault OTX API to identify known malicious IP addresses.

2. Network Forensics (net_sniffer.py)

Domain: Traffic Analysis & DPI

Function: Utilizes Scapy to perform Deep Packet Inspection (DPI) at Layer 7. Detects unencrypted credential leaks and logs traffic to .pcap format for Wireshark analysis.

3. Vulnerability Management (vuln_parser.py)

Domain: Vulnerability Scanning

Function: Automates the parsing of Nmap XML results to isolate critical CVEs and prioritize remediation tasks for engineering teams.

4. Host Integrity & Auto-Healing (fim.py)

Domain: Host-Based Intrusion Detection (HIDS)

Function: Monitors critical system files using SHA-256 hashing. Includes "Active Response" logic to automatically restore tampered files from a secure backup.

5. Automated Defense (rule_generator.py)

Domain: Collaborative Defense & Signatures

Function: Translates intelligence gathered from local logs into actionable firewall blacklists and Snort-compatible IDS rules.

⚖️ Compliance & Reporting

Every project in this suite is designed to align with industry frameworks:

NIST CSF: Maps to Identify, Protect, Detect, and Respond.

GDPR Article 32: Demonstrates technical measures for regular security testing and assessment.

Incident Documentation: See INCIDENT_REPORT_001.md for a sample post-mortem analysis.
