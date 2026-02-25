import re
import os
import hashlib
from email import policy
from email.parser import BytesParser

def extract_phishing_artifacts(eml_file):
    """
    Parses an .eml file to extract URLs, sender reputation, and attachment hashes.
    """
    if not os.path.exists(eml_file):
        # Create a mock phishing email for testing if it doesn't exist
        print(f"[!] {eml_file} not found. Generating mock phishing email...")
        mock_content = (
            "From: support@micros0ft-security.com\n"
            "To: victim@company.com\n"
            "Subject: Urgent: Unusual sign-in activity\n\n"
            "We detected a login from Russia. Please verify your account here: "
            "http://login-microsoft-secure.ru/auth\n\n"
            "See attached invoice for details."
        )
        with open(eml_file, "w") as f:
            f.write(mock_content)

    print(f"[*] Analyzing Email: {eml_file}")
    print("-" * 60)

    with open(eml_file, 'rb') as f:
        msg = BytesParser(policy=policy.default).parse(f)

    # 1. Header Analysis
    sender = msg.get('From')
    subject = msg.get('Subject')
    print(f"[i] Sender: {sender}")
    print(f"[i] Subject: {subject}")

    # 2. URL Extraction (Heuristic: Look for suspicious TLDs or typosquatting)
    body = msg.get_body(preferencelist=('plain')).get_content()
    urls = re.findall(r'http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\(\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+', body)
    
    suspicious_tlds = ['.ru', '.xyz', '.zip', '.tk']
    for url in urls:
        is_suspicious = any(tld in url for tld in suspicious_tlds)
        status = "[🚨] HIGH RISK URL" if is_suspicious else "[?] Neutral URL"
        print(f"{status}: {url}")

    # 3. Attachment Forensic Simulation (Hash calculation)
    # In a real scenario, we'd iterate over msg.iter_attachments()
    print("\n[*] Attachment Forensics:")
    attachments = ["invoice.pdf.exe"] # Mocking an attachment for this demo
    for adj in attachments:
        # Generate a mock hash for the "attachment"
        file_hash = hashlib.sha256(adj.encode()).hexdigest()
        print(f"    - Filename: {adj}")
        print(f"    - SHA-256: {file_hash}")
        if adj.endswith(".exe"):
            print("    - [!] WARNING: Executable masquerading as PDF detected.")

    print("-" * 60)
    print("[+] Phishing Analysis Complete.")

if __name__ == "__main__":
    extract_phishing_artifacts("suspicious_email.eml")
