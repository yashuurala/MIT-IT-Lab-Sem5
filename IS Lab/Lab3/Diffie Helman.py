import time
import random
from sympy import isprime

# Function to generate a large prime number
def generate_large_prime(bits=512):
    p = random.getrandbits(bits)
    while not isprime(p):
        p = random.getrandbits(bits)
    return p

# Function to generate a private key
def generate_private_key(prime):
    return random.randint(1, prime - 1)

# Function to compute the public key
def compute_public_key(private_key, base, prime):
    return pow(base, private_key, prime)

# Function to generate public and private keys
def generate_keys(base, prime):
    private_key = generate_private_key(prime)
    public_key = compute_public_key(private_key, base, prime)
    return private_key, public_key

# Function to compute the shared secret key
def compute_shared_secret(public_key, private_key, prime):
    return pow(public_key, private_key, prime)

# Get user input for parameters
bits = int(input("Enter the size of the prime number in bits (e.g., 512): "))
base = int(input("Enter the common base (generator) (e.g., 2): "))

# Generate a large prime number for the prime modulus
print("Generating large prime number...")
prime = generate_large_prime(bits)

# Generate keys for two peers
print("Generating keys for two peers...")
start_time = time.time()
private_key_peer1, public_key_peer1 = generate_keys(base, prime)
private_key_peer2, public_key_peer2 = generate_keys(base, prime)
end_time = time.time()
print(f"Time taken for key generation: {end_time - start_time:.5f} seconds")

# Compute shared secrets
start_time = time.time()
shared_secret_peer1 = compute_shared_secret(public_key_peer2, private_key_peer1, prime)
shared_secret_peer2 = compute_shared_secret(public_key_peer1, private_key_peer2, prime)
end_time = time.time()
print(f"Time taken for shared secret computation: {end_time - start_time:.5f} seconds")

# Print results
print(f"\nPrime: {prime}")
print(f"Base: {base}")
print(f"Private Key Peer 1: {private_key_peer1}")
print(f"Private Key Peer 2: {private_key_peer2}")
print(f"Public Key Peer 1: {public_key_peer1}")
print(f"Public Key Peer 2: {public_key_peer2}")
print(f"Shared Secret (Peer 1): {shared_secret_peer1}")
print(f"Shared Secret (Peer 2): {shared_secret_peer2}")

# Verify if both computed shared secrets match
if shared_secret_peer1 == shared_secret_peer2:
    print("Key exchange successful. Shared secrets match!")
else:
    print("Key exchange failed. Shared secrets do not match.")
