hreat-Hunter: Automated Log Analysis Tool

**Threat-Hunter** is a Python-based security utility designed to parse raw web server logs and identify indicators of compromise (IoCs). 

Purpose
Developed to support **Cyber Threat Intelligence (CTI)** and **Incident Response** workflows, this tool acts as a lightweight SIEM parser. It uses regular expressions to hunt for common adversary Tactics, Techniques, and Procedures (TTPs) within standard HTTP traffic.

eatures & Detection Capabilities
* **SQL Injection (SQLi):** Detects payload syntax (`OR 1=1`, `UNION`, `SELECT`).
* **Cross-Site Scripting (XSS):** Identifies malicious `<script>` tags in URL parameters.
* **Automated Reconnaissance:** Flags aggressive directory brute-forcing (e.g., Dirb) and automated port scanning (e.g., Nmap NSE scripts).

Usage
```bash
python3 threat_hunter.py <path_to_log_file>
