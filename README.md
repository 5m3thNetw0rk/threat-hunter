# 🛡️ Automated Threat Hunter & Intel Enriched Parser

A Python-based security tool designed to parse server access logs, detect common attack patterns, and enrich findings with live Geographic and Reputation intelligence.

## 🚀 Key Features
* **Signature-Based Detection:** Identifies SQL Injection, XSS, and Reconnaissance (Nmap/Dirb).
* **Live CTI Integration:** Connects to **AlienVault OTX API** to check for known malicious actors (IoCs).
* **Contextual Enrichment:** Maps IP addresses to geographic regions and internal network zones.
* **Conditional Alerting:** Logic-driven escalation that prioritizes "Critical" threats for SOC notification.
* **Secure Development:** Implements Python Virtual Environments and Environment Variable masking for API security.
* **Active Response HIDS:** A File Integrity Monitor that uses SHA-256 hashing to baseline critical files and automatically restores them from a secure backup if unauthorized tampering is detected.

## 🛠️ Tech Stack
* **Language:** Python 3.x
* **Libraries:** OTXv2, python-dotenv, re, json
* **Threat Intel:** AlienVault Open Threat Exchange (OTX)
