import requests
import json
import sys

# CONFIGURATION
# Replace these with your actual details
STUDENT_ID = "23MH1A05Q8"  # e.g., "2023001"
GITHUB_REPO_URL = "https://github.com/HarshithaKovvuri17/docker-2fa" # e.g., "https://github.com/username/repo"
API_URL = "https://eajeyq4r3zljoq4rpovy2nthda0vtjqf.lambda-url.ap-south-1.on.aws"

def get_encrypted_seed():
    print(f"🔹 preparing request for Student ID: {STUDENT_ID}")
    
    # 1. Read your public key
    try:
        with open("student_public.pem", "r") as f:
            public_key_content = f.read()
    except FileNotFoundError:
        print("❌ Error: student_public.pem not found. Did you run Step 2?")
        return

    # 2. Prepare the payload
    # The API expects the key to be a string. Python's JSON library handles 
    # the newlines automatically, converting them to \n in the JSON string.
    payload = {
        "student_id": STUDENT_ID,
        "github_repo_url": GITHUB_REPO_URL,
        "public_key": public_key_content
    }

    # 3. Send the request
    print("🔹 Sending request to Instructor API...")
    try:
        response = requests.post(API_URL, json=payload, timeout=10)
        response.raise_for_status() # Raise error for bad status codes (4xx, 5xx)
    except requests.exceptions.RequestException as e:
        print(f"❌ API Request Failed: {e}")
        if hasattr(e, 'response') and e.response is not None:
             print(f"   Server response: {e.response.text}")
        return

    # 4. Parse response
    try:
        data = response.json()
        if "encrypted_seed" not in data:
            print("❌ Error: Response did not contain 'encrypted_seed'")
            print(f"Full response: {data}")
            return
            
        encrypted_seed = data["encrypted_seed"]
        print("✅ Received encrypted seed successfully!")
        
    except json.JSONDecodeError:
        print("❌ Error: Could not parse server response as JSON.")
        return

    # 5. Save to file
    # Important: Save exactly as received (base64 string)
    with open("encrypted_seed.txt", "w") as f:
        f.write(encrypted_seed)
    
    print("✅ Saved to encrypted_seed.txt")
    print("⚠️  REMINDER: Do NOT commit encrypted_seed.txt to your repository.")

if __name__ == "__main__":
    get_encrypted_seed()