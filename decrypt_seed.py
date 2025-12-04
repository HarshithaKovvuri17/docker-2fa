import base64
import os
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding

app = FastAPI()

# --- CONFIGURATION ---
PRIVATE_KEY_PATH = "student_private.pem"
DATA_DIR = "." # This will be mapped to a Docker volume later
SEED_FILE = os.path.join(DATA_DIR, "seed.txt")

# Ensure data directory exists (for local testing)
os.makedirs(DATA_DIR, exist_ok=True)

# --- DATA MODELS ---
class DecryptRequest(BaseModel):
    encrypted_seed: str

# --- CORE LOGIC ---
def decrypt_seed_logic(encrypted_seed_b64: str):
    """
    Decrypts the base64 encrypted seed using the student private key.
    Algorithm: RSA/OAEP/SHA256/MGF1-SHA256
    """
    try:
        # 1. Load Private Key
        with open(PRIVATE_KEY_PATH, "rb") as key_file:
            private_key = serialization.load_pem_private_key(
                key_file.read(),
                password=None
            )

        # 2. Decode Base64 Input
        ciphertext = base64.b64decode(encrypted_seed_b64)

        # 3. Decrypt using RSA-OAEP
        # Strict requirement: SHA-256 for both hashing and MGF1 
        decrypted_bytes = private_key.decrypt(
            ciphertext,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )

        # 4. Decode to String and Validate
        decrypted_seed = decrypted_bytes.decode('utf-8')
        
        # Validation: Must be 64-char hex string 
        if len(decrypted_seed) != 64:
            raise ValueError("Decrypted seed length is not 64 characters")
        
        # Simple check for hex characters
        int(decrypted_seed, 16) 

        return decrypted_seed

    except Exception as e:
        print(f"Decryption Error: {str(e)}")
        raise e

# --- ENDPOINTS ---

@app.post("/decrypt-seed")
async def decrypt_seed_endpoint(request: DecryptRequest):
    """
    Endpoint 1: Accept encrypted seed, decrypt it, and save to disk.
    """
    try:
        # Perform decryption
        seed = decrypt_seed_logic(request.encrypted_seed)
        
        # Save to persistent storage [cite: 32]
        with open(SEED_FILE, "w") as f:
            f.write(seed)
            
        return {"status": "ok"}
        
    except Exception as e:
        # Return HTTP 500 on failure [cite: 32]
        raise HTTPException(status_code=500, detail="Decryption failed")

@app.get("/")
def health_check():
    return {"status": "running"}