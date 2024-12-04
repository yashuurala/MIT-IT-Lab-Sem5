import time
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

# Generate DH parameters (this is common for both parties)
parameters = dh.generate_parameters(generator=2, key_size=2048)

# Function to generate private-public key pair for Diffie-Hellman
def generate_dh_keys(parameters):
    private_key = parameters.generate_private_key()
    public_key = private_key.public_key()
    return private_key, public_key

# Function to derive shared key using DH private key and peer's public key
def derive_shared_key(private_key, peer_public_key):
    shared_key = private_key.exchange(peer_public_key)
    # Derive a key from the shared key using HKDF
    derived_key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,  # AES-256 key length
        salt=None,
        info=b'handshake data'
    ).derive(shared_key)
    return derived_key

# Function to serialize a public key for exchange
def serialize_public_key(public_key):
    return public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

# Function to deserialize the public key
def deserialize_public_key(public_key_bytes):
    return serialization.load_pem_public_key(public_key_bytes)

# Simulating Diffie-Hellman exchange between Alice and Bob
def main():
    # Start timing the key exchange process
    start_time = time.time()

    # Alice generates her DH key pair
    alice_private_key, alice_public_key = generate_dh_keys(parameters)

    # Bob generates his DH key pair
    bob_private_key, bob_public_key = generate_dh_keys(parameters)

    # Exchange public keys (serialization/deserialization not shown here, but would be needed in practice)
    alice_shared_key = derive_shared_key(alice_private_key, bob_public_key)
    bob_shared_key = derive_shared_key(bob_private_key, alice_public_key)

    # Ensure that both keys match
    assert alice_shared_key == bob_shared_key, "Key exchange failed. Shared keys do not match!"

    # End timing
    end_time = time.time()
    exchange_time = end_time - start_time

    print("Shared key derived successfully!")
    print(f"Shared Key (hex): {alice_shared_key.hex()}")
    print(f"Time taken for Diffie-Hellman key exchange: {exchange_time} seconds")

if __name__ == "__main__":
    main()
