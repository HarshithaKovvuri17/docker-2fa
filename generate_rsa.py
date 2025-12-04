from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization

def generate_rsa_keypair():
    print("Generating 4096-bit RSA key pair... this may take a moment.")
    
    # 1. Generate the Private Key
    # Standard security requires 4096 bits and public exponent 65537 
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=4096,
    )

    # 2. Serialize Private Key to PEM format
    # NoEncryption is used here because this key will be inside a container
    # and needs to be read automatically without a password prompt.
    pem_private = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )

    # 3. Generate the Public Key from the Private Key
    public_key = private_key.public_key()

    # 4. Serialize Public Key to PEM format
    pem_public = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    # 5. Save files to disk 
    with open("student_private.pem", "wb") as f:
        f.write(pem_private)
    print("✅ Saved student_private.pem")

    with open("student_public.pem", "wb") as f:
        f.write(pem_public)
    print("✅ Saved student_public.pem")

if __name__ == "__main__":
    generate_rsa_keypair()