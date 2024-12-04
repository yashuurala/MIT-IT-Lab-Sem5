from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
import os


def generate_ecc_keys():
    """Generate ECC private and public keys."""
    private_key = ec.generate_private_key(ec.SECP256R1(), default_backend())
    public_key = private_key.public_key()
    return private_key, public_key


def serialize_keys(private_key, public_key):
    """Serialize public and private keys to PEM format."""
    pem_public = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    pem_private = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    )

    return pem_public, pem_private


def derive_shared_key(private_key, public_key):
    """Derive a shared key using ECDH."""
    return private_key.exchange(ec.ECDH(), public_key)


def derive_symmetric_key(shared_key):
    """Derive a symmetric key for AES encryption using KDF."""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=os.urandom(16),  # Random salt for KDF
        iterations=100000,
        backend=default_backend()
    )
    return kdf.derive(shared_key)


def encrypt_message(message, symmetric_key):
    """Encrypt the message using AES."""
    iv = os.urandom(16)  # Generate a random initialization vector
    cipher = Cipher(algorithms.AES(symmetric_key), modes.CFB(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(message) + encryptor.finalize()
    return iv, ciphertext


def decrypt_message(ciphertext, symmetric_key, iv):
    """Decrypt the ciphertext using the same symmetric key."""
    cipher = Cipher(algorithms.AES(symmetric_key), modes.CFB(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    decrypted_message = decryptor.update(ciphertext) + decryptor.finalize()
    return decrypted_message


def main():
    # Generate ECC keys
    private_key, public_key = generate_ecc_keys()

    # Serialize keys
    pem_public, pem_private = serialize_keys(private_key, public_key)

    # Message to encrypt
    message = input("Enter the message: ").encode()

    # Derive a shared key from the private key and the public key
    shared_key = derive_shared_key(private_key, public_key)

    # Derive a symmetric key for AES encryption
    symmetric_key = derive_symmetric_key(shared_key)

    # Encrypt the message using AES
    iv, ciphertext = encrypt_message(message, symmetric_key)

    print("Ciphertext:", ciphertext.hex())

    # Decrypt the message using the same symmetric key
    decrypted_message = decrypt_message(ciphertext, symmetric_key, iv)

    print("Decrypted Message:", decrypted_message.decode())


if __name__ == "__main__":
    main()
