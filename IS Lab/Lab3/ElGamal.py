import random
from sympy import isprime, mod_inverse

# Helper function to generate a large prime number (for real applications, use a cryptographic library)
def generate_large_prime(bits):
    while True:
        p = random.getrandbits(bits)
        if isprime(p):
            return p

# Generate the public and private keys
def generate_keys(bits=512):
    p = generate_large_prime(bits)
    g = random.randint(2, p - 2)
    x = random.randint(2, p - 2)
    h = pow(g, x, p)
    return (p, g, h), (p, g, x)

# Encrypt a message
def encrypt(message, public_key):
    p, g, h = public_key
    k = random.randint(2, p - 2)
    c1 = pow(g, k, p)
    c2 = (pow(h, k, p) * int.from_bytes(message.encode(), 'big')) % p
    return (c1, c2)

# Decrypt a message
def decrypt(ciphertext, private_key):
    p, g, x = private_key
    c1, c2 = ciphertext
    s = pow(c1, x, p)
    s_inv = mod_inverse(s, p)
    decrypted_message = (c2 * s_inv) % p
    return decrypted_message.to_bytes((decrypted_message.bit_length() + 7) // 8, 'big').decode()

# Example usage
public_key, private_key = generate_keys()

# Take user input for the message
message = input("Enter the message to encrypt: ")

# Encrypt the message
ciphertext = encrypt(message, public_key)
print(f"Ciphertext: {ciphertext}")

# Decrypt the message
decrypted_message = decrypt(ciphertext, private_key)
print(f"Decrypted Message: {decrypted_message}")
