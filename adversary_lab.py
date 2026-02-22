import os
import time
from datetime import datetime

def log_injection_demo():
    """
    Simulates Log Injection by inserting a 'fake' successful login 
    into a log file to mislead investigators.
    """
    log_file = "deceptive_auth.log"
    attacker_ip = "192.168.1.50"
    fake_ip = "10.0.0.99" # Framing an innocent internal IP
    
    print(f"[*] Starting Log Injection on {log_file}...")
    
    with open(log_file, "w") as f:
        # 1. Real malicious activity (Attacker IP)
        f.write(f"Feb 22 10:00:01 [SSHD] Failed password for root from {attacker_ip}\n")
        
        # 2. THE INJECTION: Using a newline character to hide a fake entry
        # This makes it look like the admin logged in from a different IP
        injection = f"\nFeb 22 10:05:00 [SSHD] Accepted password for admin from {fake_ip}"
        f.write(f"Feb 22 10:02:45 [SSHD] Failed password for root from {attacker_ip}{injection}\n")

    print(f"[!] Injection Complete. Check {log_file} to see how the lines look.")

def time_stomp_demo():
    """
    Simulates Time-Stomping by changing the 'Modified' time of a file
    to a date in the past to move it outside the investigation window.
    """
    target_file = "deceptive_auth.log"
    
    # We want to set the file time to 2 years ago
    past_year = 2024
    past_date = datetime(past_year, 1, 1, 12, 0, 0)
    past_timestamp = time.mktime(past_date.timetuple())
    
    print(f"[*] Current File Time: {datetime.fromtimestamp(os.path.getmtime(target_file))}")
    print(f"[*] Time-Stomping {target_file} to {past_year}...")
    
    # os.utime(path, (atime, mtime))
    os.utime(target_file, (past_timestamp, past_timestamp))
    
    new_time = datetime.fromtimestamp(os.path.getmtime(target_file))
    print(f"[!] Success: {target_file} now reports a modified date of: {new_time}")

if __name__ == "__main__":
    print("--- ADVERSARY ANTI-FORENSICS LAB ---")
    log_injection_demo()
    print("-" * 40)
    time_stomp_demo()
    print("-" * 40)
    print("\n[PRO TIP] Now run 'ls -l deceptive_auth.log' in your terminal.")
    print("Then run 'python3 investigator.py' and see if it catches the injected line!")
