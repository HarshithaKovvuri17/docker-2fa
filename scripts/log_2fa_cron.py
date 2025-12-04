import os
import time
import sys
import datetime
import base64
import hashlib
import pyotp

# Define paths (Docker absolute paths)
SEED_FILE = "/data/seed.txt"

def main():
    # 1. Check if seed exists
    if not os.path.exists(SEED_FILE):
        print(f"[{datetime.datetime.utcnow()}] Seed file not found at {SEED_FILE}", file=sys.stderr)
        return

    # 2. Read seed
    try:
        with open(SEED_FILE, "r") as f:
            hex_seed = f.read().strip()
            
        # 3. Convert to Base32
        seed_bytes = bytes.fromhex(hex_seed)
        base32_seed = base64.b32encode(seed_bytes).decode('utf-8')
        
        # 4. Generate Code
        # Use hashlib.sha1 to match main.py logic
        totp = pyotp.TOTP(base32_seed, digits=6, interval=30, digest=hashlib.sha1)
        current_code = totp.now()
        
        # 5. Log with UTC timestamp
        # Format: YYYY-MM-DD HH:MM:SS - 2FA Code: XXXXXX
        timestamp = datetime.datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")
        print(f"{timestamp} - 2FA Code: {current_code}")
        
    except Exception as e:
        print(f"Error generating code: {e}", file=sys.stderr)

if __name__ == "__main__":
    main()