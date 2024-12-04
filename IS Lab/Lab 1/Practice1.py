import random
from Crypto.Util.number import getPrime
import time
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import os

class DiffieHellman:
    def __init__(self, p, g):
        self.p = p
        self.g = g
        self.private_key = random.randint(1, self.p - 1)
        self.public_key = pow(self.g, self.private_key, self.p)

    def generate_shared_key(self, other_public_key):
        return pow(other_public_key, self.private_key, self.p)


def main():
    message = None
    ciphertext = None
    nonce = None
    tag = None

    while True:
        print("\nMenu driven Program\nEnter 1 for Diffie-Hellman Key exchange between Alice and Bob\nEnter 2 for ECC encryption\n3 for ECC decryption\nExit\n")
        choice = int(input("Enter your choice here: "))

        if choice == 1:
            start = time.time()
            key_size = 256
            p = getPrime(key_size)
            g = random.randint(2, p - 1)  # Shared base

            # Create Alice and Bob with the same p and g values
            alice = DiffieHellman(p, g)
            bob = DiffieHellman(p, g)

            # Exchange public keys and generate shared keys
            alice_shared_key = alice.generate_shared_key(bob.public_key)
            bob_shared_key = bob.generate_shared_key(alice.public_key)
            end = time.time()

            print(f"Alice's public key: {alice.public_key}")
            print(f"Bob's public key: {bob.public_key}")
            print(f"Alice's shared key: {alice_shared_key}")
            print(f"Bob's shared key: {bob_shared_key}")
            print(f"Keys match: {alice_shared_key == bob_shared_key}")
            print(f"Total time taken: {end - start}")

        elif choice == 2:
            # Generate ECC key pairs
            private_key = ec.generate_private_key(ec.SECP256R1())
            public_key = private_key.public_key()

            # Serialize public key for use in key exchange
            pem_public_key = public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
            print("Public Key (PEM):")
            print(pem_public_key.decode())

            # Derive shared secret using ECDH
            other_private_key = ec.generate_private_key(ec.SECP256R1())
            other_public_key = other_private_key.public_key()
            shared_secret = other_private_key.exchange(ec.ECDH(), public_key)

            # Derive AES key from the shared secret
            aes_key = hashes.Hash(hashes.SHA256())
            aes_key.update(shared_secret)
            aes_key = aes_key.finalize()[:32]  # AES-256 requires a 32-byte key

            # Example message to encrypt
            message = input("Enter your message:\n").encode()

            # Encrypt data with AES-GCM
            nonce = os.urandom(12)
            cipher = Cipher(algorithms.AES(aes_key), modes.GCM(nonce))
            encryptor = cipher.encryptor()
            ciphertext = encryptor.update(message) + encryptor.finalize()
            tag = encryptor.tag

            print("Ciphertext:", ciphertext)
            print("Nonce:", nonce)
            print("Tag:", tag)

        elif choice == 3:
            if message and ciphertext and nonce and tag:
                # Decrypt data with AES-GCM
                cipher = Cipher(algorithms.AES(aes_key), modes.GCM(nonce, tag))
                decryptor = cipher.decryptor()
                decrypted_message = decryptor.update(ciphertext) + decryptor.finalize()

                print("Decrypted message:", decrypted_message.decode())
            else:
                print("No encrypted message found. Please encrypt a message first.")

        else:
            break


if __name__ == "__main__":
    main()
