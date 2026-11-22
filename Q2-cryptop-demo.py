from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Random import get_random_bytes
import base64


# ---------------------------------------------------------
# 1. CLIENT SIDE: HASH THE TRANSACTION FILE
# ---------------------------------------------------------

def hash_file(data: bytes):
    h = SHA256.new(data)
    return h


# ---------------------------------------------------------
# 2. CLIENT SIDE: DIGITAL SIGNATURE (AUTHENTICITY + NON-REPUDIATION)
# ---------------------------------------------------------

def generate_rsa_keypair():
    key = RSA.generate(2048)
    private_key = key
    public_key = key.publickey()
    return private_key, public_key


def sign_hash(hash_obj, private_key):
    signature = pkcs1_15.new(private_key).sign(hash_obj)
    return signature


# ---------------------------------------------------------
# 3. CLIENT SIDE: AES ENCRYPTION (CONFIDENTIALITY)
# ---------------------------------------------------------

def aes_encrypt(data: bytes, aes_key: bytes):
    cipher = AES.new(aes_key, AES.MODE_EAX)
    ciphertext, tag = cipher.encrypt_and_digest(data)
    return cipher.nonce, ciphertext, tag


# ---------------------------------------------------------
# 4. CLIENT SIDE: RSA KEY EXCHANGE (ENCRYPT AES KEY)
# ---------------------------------------------------------

def encrypt_aes_key_with_rsa(aes_key: bytes, server_public_key):
    cipher_rsa = PKCS1_OAEP.new(server_public_key)
    encrypted_key = cipher_rsa.encrypt(aes_key)
    return encrypted_key


# ---------------------------------------------------------
# 5. SERVER SIDE: RSA DECRYPT AES KEY
# ---------------------------------------------------------

def decrypt_aes_key_with_rsa(encrypted_key: bytes, server_private_key):
    cipher_rsa = PKCS1_OAEP.new(server_private_key)
    aes_key = cipher_rsa.decrypt(encrypted_key)
    return aes_key


# ---------------------------------------------------------
# 6. SERVER SIDE: AES DECRYPTION
# ---------------------------------------------------------

def aes_decrypt(nonce, ciphertext, tag, aes_key):
    cipher = AES.new(aes_key, AES.MODE_EAX, nonce=nonce)
    plaintext = cipher.decrypt_and_verify(ciphertext, tag)
    return plaintext


# ---------------------------------------------------------
# 7. SERVER SIDE: VERIFY DIGITAL SIGNATURE
# ---------------------------------------------------------

def verify_signature(hash_obj, signature, client_public_key):
    try:
        pkcs1_15.new(client_public_key).verify(hash_obj, signature)
        return True
    except (ValueError, TypeError):
        return False


# ---------------------------------------------------------
# MAIN DEMO WORKFLOW
# ---------------------------------------------------------

if __name__ == "__main__":

    print("\n=== Secure Banking Transaction Demo ===\n")

    # Simulated transaction file
    transaction_data = b"User A sends GBP500 to User B\nUser C sends GBP1200 to User D"

    # CLIENT generates RSA keys (for signing)
    client_private, client_public = generate_rsa_keypair()

    # SERVER generates RSA keys (for decrypting AES key)
    server_private, server_public = generate_rsa_keypair()

    print("[1] Hashing transaction file...")
    file_hash = hash_file(transaction_data)

    print("[2] Creating digital signature...")
    signature = sign_hash(file_hash, client_private)

    print("[3] AES encrypting transaction file...")
    aes_key = get_random_bytes(32)  # AES-256
    nonce, ciphertext, tag = aes_encrypt(transaction_data, aes_key)

    print("[4] Encrypting AES key using server's RSA public key...")
    encrypted_aes_key = encrypt_aes_key_with_rsa(aes_key, server_public)

    print("\n--- Data sent to server ---")
    print("Encrypted AES key:", base64.b64encode(encrypted_aes_key).decode())
    print("Ciphertext:", base64.b64encode(ciphertext).decode())
    print("Signature:", base64.b64encode(signature).decode())
    print("----------------------------\n")

    print("[5] Server decrypts AES key...")
    recovered_aes_key = decrypt_aes_key_with_rsa(encrypted_aes_key, server_private)

    print("[6] Server decrypts transaction file...")
    decrypted_data = aes_decrypt(nonce, ciphertext, tag, recovered_aes_key)

    print("[7] Server verifies digital signature...")
    new_hash = hash_file(decrypted_data)
    valid = verify_signature(new_hash, signature, client_public)

    print("\n=== RESULTS ===")
    print("Decrypted transaction file:\n", decrypted_data.decode())
    print("Signature valid:", valid)
