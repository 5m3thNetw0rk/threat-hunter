import time
import os

def simulate_log_injection():
    """Simulates a multi-stage attack for investigator.py and threat_hunter.py"""
    log_file = "deceptive_auth.log"
    attacker_ip = "192.168.1.50"
    victim_user = "admin"
    decoy_ip = "10.0.0.99"

    print(f"[*] Starting Adversary Simulation against {log_file}...")

    # Stage 1: The Brute Force Stress Test
    # This generates volume to trigger threshold-based alerts (like in threat_hunter.py)
    print("[!] Stage 1: Initiating High-Volume Brute Force...")
    with open(log_file, "a") as f:
        for i in range(1, 11):
            timestamp = f"Feb 22 10:04:{i:02d}"
            f.write(f"{timestamp} [SSHD] Failed password for {victim_user} from {attacker_ip} port 49282 ssh2\n")
            time.sleep(0.05)

    # Stage 2: The Log Injection & Framing
    # We use a \n (newline) to create a fake 'Success' entry that looks like it came from a local IP
    print("[!] Stage 2: Executing Log Injection & Framing...")
    
    injection_payload = (
        f"Feb 22 10:05:00 [SSHD] Failed password for {victim_user} from {attacker_ip} port 49282 ssh2\n"
        f"Feb 22 10:05:01 [SSHD] Accepted password for {victim_user} from {decoy_ip} port 49282 ssh2"
    )

    with open(log_file, "a") as f:
        f.write(injection_payload + "\n")

    print(f"[+] Attack complete. Log file '{log_file}' is now ready for investigation.")

def simulate_ransomware_tamper():
    """
    Simulates a Ransomware-style attack targeting the Canary Vault.
    This is designed to trigger warden.py.
    """
    target_file = "./canary_vault/passwords.txt"
    
    if not os.path.exists(target_file):
        print("[!] Error: Canary file not found. Ensure warden.py is running first!")
        return

    print(f"[!] INITIATING STRESS TEST: Attempting to encrypt {target_file}...")
    
    # Simulate malicious encryption by overwriting with 'random' data
    with open(target_file, "w") as f:
        f.write("0xDEADBEEF_ENCRYPTED_DATA_SHADOW_LOCK")
    
    print("[+] File modified. Check the Warden terminal for the Active Response alert!")

if __name__ == "__main__":
    print("--- 🛡️ ADVERSARY SIMULATION MENU ---")
    print("1. Multi-Stage Log Attack (Target: investigator.py / threat_hunter.py)")
    print("2. Ransomware Simulation (Target: warden.py)")
    
    choice = input("\nSelect attack profile (1/2): ")
    
    if choice == "1":
        simulate_log_injection()
    elif choice == "2":
        simulate_ransomware_tamper()
    else:
        print("[!] Invalid choice.")
