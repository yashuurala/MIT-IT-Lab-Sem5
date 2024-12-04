import random
from math import gcd
from sympy import randprime


# Function to calculate modular inverse
def modinv(a, m):
    m0, x0, x1 = m, 0, 1
    if m == 1:
        return 0
    while a > 1:
        q = a // m
        m, a = a % m, m
        x0, x1 = x1 - q * x0, x0
    if x1 < 0:
        x1 += m0
    return x1


# RSA key generation with prime generation
def generate_rsa_keypair(bit_length=512):
    # Generate two large prime numbers p and q using sympy's randprime
    p = randprime(2 ** (bit_length - 1), 2 ** bit_length)
    q = randprime(2 ** (bit_length - 1), 2 ** bit_length)

    # Compute n = p * q
    n = p * q

    # Compute phi(n) = (p-1) * (q-1)
    phi_n = (p - 1) * (q - 1)

    # Choose e such that 1 < e < phi_n and gcd(e, phi_n) = 1
    e = random.randint(1, phi_n)
    while gcd(e, phi_n) != 1:
        e = random.randint(1, phi_n)

    # Compute d such that d ≡ e^(-1) (mod phi_n)
    d = modinv(e, phi_n)

    public_key = (e, n)
    private_key = (d, n)

    return public_key, private_key


# RSA encryption
def rsa_encrypt(public_key, plaintext):
    e, n = public_key
    # c = m^e mod n
    ciphertext = pow(plaintext, e, n)
    return ciphertext


# RSA decryption
def rsa_decrypt(private_key, ciphertext):
    d, n = private_key
    # m = c^d mod n
    plaintext = pow(ciphertext, d, n)
    return plaintext


# Homomorphic multiplication (multiplying two ciphertexts)
def rsa_multiply(public_key, ciphertext1, ciphertext2):
    _, n = public_key
    # Perform c1 * c2 mod n (homomorphic multiplication in ciphertexts)
    return (ciphertext1 * ciphertext2) % n


# Main code
if __name__ == "__main__":
    # Generate RSA keypair
    public_key, private_key = generate_rsa_keypair()

    # Take user input for two integers to encrypt
    m1 = int(input("Enter the first integer to encrypt: "))
    m2 = int(input("Enter the second integer to encrypt: "))

    # Encrypt the integers
    c1 = rsa_encrypt(public_key, m1)
    c2 = rsa_encrypt(public_key, m2)
    print(f"Ciphertext of {m1}: {c1}")
    print(f"Ciphertext of {m2}: {c2}")

    # Perform homomorphic multiplication on encrypted integers
    encrypted_product = rsa_multiply(public_key, c1, c2)
    print(f"Encrypted product: {encrypted_product}")

    # Decrypt the result of the multiplication
    decrypted_product = rsa_decrypt(private_key, encrypted_product)
    print(f"Decrypted product: {decrypted_product}")

    # Verify if the decrypted product matches the actual product
    assert decrypted_product == m1 * m2, "Decryption failed!"
    print("The decrypted product matches the original product.")
