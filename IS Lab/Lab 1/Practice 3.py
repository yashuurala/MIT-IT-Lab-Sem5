from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes
import os

# Function to generate ECC key pair
def generate_ecc_key_pair():
    private_key = ec.generate_private_key(ec.SECP256R1())
    public_key = private_key.public_key()
    return private_key, public_key

# Function to serialize the public key to PEM format
def serialize_public_key(public_key):
    pem_public_key = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    return pem_public_key

# Function to derive the shared secret using ECDH
def derive_shared_secret(private_key, peer_public_key):
    shared_secret = private_key.exchange(ec.ECDH(), peer_public_key)
    # Use SHA-256 to hash the shared secret and get a 256-bit key for AES
    aes_key = hashes.Hash(hashes.SHA256())
    aes_key.update(shared_secret)
    aes_key = aes_key.finalize()[:32]  # AES-256 requires a 32-byte key
    return aes_key

# Function to encrypt data using AES-GCM
def encrypt_data(aes_key, message):
    nonce = os.urandom(12)  # Generate a random nonce
    cipher = Cipher(algorithms.AES(aes_key), modes.GCM(nonce))
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(message) + encryptor.finalize()
    tag = encryptor.tag
    return ciphertext, nonce, tag

# Function to decrypt data using AES-GCM
def decrypt_data(aes_key, ciphertext, nonce, tag):
    cipher = Cipher(algorithms.AES(aes_key), modes.GCM(nonce, tag))
    decryptor = cipher.decryptor()
    decrypted_message = decryptor.update(ciphertext) + decryptor.finalize()
    return decrypted_message

# Example Usage
def main():
    # Generate ECC key pairs for both parties
    private_key, public_key = generate_ecc_key_pair()
    other_private_key, other_public_key = generate_ecc_key_pair()

    # Serialize public key to PEM format (for demonstration)
    pem_public_key = serialize_public_key(public_key)
    print("Public Key (PEM):")
    print(pem_public_key.decode())

    # Derive shared secret
    aes_key = derive_shared_secret(other_private_key, public_key)

    # Example message to encrypt
    message = input("Enter your message: ").encode()

    # Encrypt the message
    ciphertext, nonce, tag = encrypt_data(aes_key, message)
    print("Ciphertext:", ciphertext.hex())
    print("Nonce:", nonce.hex())
    print("Tag:", tag.hex())

    # Decrypt the message
    decrypted_message = decrypt_data(aes_key, ciphertext, nonce, tag)
    print("Decrypted message:", decrypted_message.decode())

if __name__ == "__main__":
    main()
