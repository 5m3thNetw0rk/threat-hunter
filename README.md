# 🛡️ Automated Threat Hunter & Intel Enriched Parser

A Python-based security tool designed to parse server access logs, detect common attack patterns, and enrich findings with live Geographic and Reputation intelligence.

## 🚀 Key Features
* **Signature-Based Detection:** Identifies SQL Injection, XSS, and Reconnaissance (Nmap/Dirb).
* **Live CTI Integration:** Connects to **AlienVault OTX API** to check for known malicious actors (IoCs).
* **Contextual Enrichment:** Maps IP addresses to geographic regions and internal network zones.
* **Conditional Alerting:** Logic-driven escalation that prioritizes "Critical" threats for SOC notification.
* **Secure Development:** Implements Python Virtual Environments and Environment Variable masking for API security.

## 🛠️ Tech Stack
* **Language:** Python 3.x
* **Libraries:** OTXv2, python-dotenv, re, json
* **Threat Intel:** AlienVault Open Threat Exchange (OTX)
