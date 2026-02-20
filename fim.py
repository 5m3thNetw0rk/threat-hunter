import hashlib
import os
import time

# Files we want to protect
WATCHED_FILES = ["server_access.log", ".env"]

def calculate_hash(filepath):
    """Creates a SHA-256 fingerprint of a file."""
    sha256_hash = hashlib.sha256()
    with open(filepath, "rb") as f:
        # Read the file in chunks so it doesn't crash if the file is huge
        for byte_block in iter(lambda: f.read(4096), b""):
            sha256_hash.update(byte_block)
    return sha256_hash.hexdigest()

def monitor():
    # 1. Take initial baseline "fingerprints"
    baseline = {f: calculate_hash(f) for f in WATCHED_FILES if os.path.exists(f)}
    print(f"[*] Baseline established for {len(baseline)} files. Monitoring...")

    try:
        while True:
            time.sleep(3) # Check every 3 seconds
            for filepath in WATCHED_FILES:
                if os.path.exists(filepath):
                    current_hash = calculate_hash(filepath)
                    if current_hash != baseline[filepath]:
                        print(f"\n[🚨] ALERT: UNEXPECTED FILE CHANGE DETECTED!")
                        print(f"    [!] FILE: {filepath}")
                        print(f"    [!] NEW HASH: {current_hash}")
                        # Update baseline so we don't alert forever
                        baseline[filepath] = current_hash
    except KeyboardInterrupt:
        print("\n[*] Monitoring stopped.")

if __name__ == "__main__":
    monitor()
    
