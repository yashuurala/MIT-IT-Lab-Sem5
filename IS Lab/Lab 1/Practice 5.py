from Crypto.Util.number import getPrime, inverse, bytes_to_long, long_to_bytes, GCD
import random
import random
from Crypto.Util.number import getPrime
import time
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes
import os

class DiffieHellman:
    def __init__(self, p, g):
        self.p = p
        self.g = g
        self.private_key = random.randint(1, self.p - 1)
        self.public_key = pow(self.g, self.private_key, self.p)

    def generate_shared_key(self, other_public_key):
        return pow(other_public_key, self.private_key, self.p)

# ---------------- ElGamal Key Generation ----------------
def generate_elgamal_keys():
    """Generate ElGamal keys."""
    p = getPrime(256)  # Large prime number
    g = random.randint(2, p - 1)  # Generator
    x = random.randint(1, p - 2)  # Private key
    h = pow(g, x, p)  # Public key
    return (p, g, h, x)


# ---------------- ElGamal Signing Function ----------------
def elgamal_sign(message, p, g, x):
    """Sign a message using ElGamal."""
    while True:
        k = random.randint(1, p - 2)  # Random ephemeral key
        if GCD(k, p - 1) == 1:  # Check if `k` is coprime with `p-1`
            break

    r = pow(g, k, p)  # Compute r = g^k mod p
    m = bytes_to_long(message)  # Convert message to a long integer
    s = (m - x * r) * inverse(k, p - 1) % (p - 1)  # Compute s
    return (r, s)


# ---------------- ElGamal Verification Function ----------------
def elgamal_verify(message, r, s, p, g, h):
    """Verify an ElGamal signature."""
    if not (0 < r < p):
        return False
    m = bytes_to_long(message)
    v1 = pow(g, m, p)  # v1 = g^m mod p
    v2 = (pow(h, r, p) * pow(r, s, p)) % p  # v2 = (h^r * r^s) mod p
    return v1 == v2

def main():
    private_key = ec.generate_private_key(ec.SECP256R1())
    public_key = private_key.public_key()

    # Serialize public key for use in key exchange
    pem_public_key = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    # Display generated keys (for demonstration purposes)
    print("Public Key (PEM):")
    print(pem_public_key.decode())

    # 2. Derive shared secret using ECDH
    # Generate another key pair for demonstration
    other_private_key = ec.generate_private_key(ec.SECP256R1())
    other_public_key = other_private_key.public_key()

    # Derive shared secret from the other party's public key
    shared_secret = other_private_key.exchange(ec.ECDH(), public_key)

    # Derive AES key from the shared secret
    # Using PBKDF2HMAC or other key derivation function
    aes_key = hashes.Hash(hashes.SHA256())
    aes_key.update(shared_secret)
    aes_key = aes_key.finalize()[:32]

    message=None
    ciphertext=None
    signature=None

    p, g, h, x = generate_elgamal_keys()

    while True:
        print("Menu driven Program\n1 for Elgamal sign\n2 for Elgamal sign verify\n3 for Diffie hellman exchange\n4 for ECC encrypt\n5 for ECC dec\n6 for Exit\n")
        c=int(input("Enter your choice: "))

        if c==1:
            print("Elgamal sign\n")
            message=input("Enter the message ").encode()
            r, s = elgamal_sign(message, p, g, x)
            print(f"\nMessage: {message.decode()}")
            print(f"ElGamal Signature: (r: {r}, s: {s})")
        elif c==2:
            message = input("Enter the message to be verified using ElGamal: ").encode()
            try:
                r = int(input("Enter the value of r: "))
                s = int(input("Enter the value of s: "))
                verification_result = elgamal_verify(message, r, s, p, g, h)
                if verification_result:
                    print("\nElGamal Signature verified successfully! The message is authentic.")
                else:
                    print("\nElGamal Signature verification failed! The message may be tampered.")
            except ValueError:
                print("Invalid input for r or s. Please enter integer values.")
        elif c==3:
            print("Diffie hellman key ex\n")
            start=time.time()
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

        elif c==4:
            print("ECC encryption\n")
            message = input("Enter you message\n").encode()

            # 3. Encrypt data with AES-GCM
            # Generate a random nonce
            nonce = os.urandom(12)
            cipher = Cipher(algorithms.AES(aes_key), modes.GCM(nonce))
            encryptor = cipher.encryptor()
            ciphertext = encryptor.update(message) + encryptor.finalize()
            tag = encryptor.tag

            print("Ciphertext:", ciphertext.hex())
            print("Nonce:", nonce.hex())
            print("Tag:", tag.hex())

        elif c==5:
            cipher = Cipher(algorithms.AES(aes_key), modes.GCM(nonce, tag))
            decryptor = cipher.decryptor()
            decrypted_message = decryptor.update(ciphertext) + decryptor.finalize()

            print("Decrypted message:", decrypted_message.decode())

        else :
            break

if __name__=="__main__":
    main()

