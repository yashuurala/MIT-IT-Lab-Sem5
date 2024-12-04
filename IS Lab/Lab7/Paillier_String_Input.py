import random
from math import gcd
from sympy import nextprime


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


# Paillier key generation
def generate_paillier_keypair(bit_length=512):
    p = nextprime(random.getrandbits(bit_length))
    q = nextprime(random.getrandbits(bit_length))

    n = p * q
    nsq = n * n
    lambda_value = (p - 1) * (q - 1) // gcd(p - 1, q - 1)

    g = n + 1
    x = pow(g, lambda_value, nsq)
    L = (x - 1) // n
    mu = modinv(L, n)

    public_key = (n, g)
    private_key = (lambda_value, mu)

    return public_key, private_key


# Paillier encryption for a single character's ASCII
def paillier_encrypt(public_key, plaintext):
    n, g = public_key
    nsq = n * n

    r = random.randint(1, n - 1)
    while gcd(r, n) != 1:
        r = random.randint(1, n - 1)

    c = (pow(g, plaintext, nsq) * pow(r, n, nsq)) % nsq
    return c


# Paillier decryption for a single character's ASCII
def paillier_decrypt(public_key, private_key, ciphertext):
    n, g = public_key
    lambda_value, mu = private_key
    nsq = n * n

    x = pow(ciphertext, lambda_value, nsq)
    L = (x - 1) // n
    plaintext = (L * mu) % n
    return plaintext


# Encrypt an entire string by encrypting each character's ASCII value
def encrypt_string(public_key, plaintext_str):
    encrypted_values = [paillier_encrypt(public_key, ord(char)) for char in plaintext_str]
    return encrypted_values


# Decrypt an entire string by decrypting each encrypted ASCII value
def decrypt_string(public_key, private_key, encrypted_values):
    decrypted_chars = [chr(paillier_decrypt(public_key, private_key, c)) for c in encrypted_values]
    return ''.join(decrypted_chars)


# Main code
if __name__ == "__main__":
    # Generate Paillier keypair
    public_key, private_key = generate_paillier_keypair()

    # Take user input for a string
    plaintext_str = input("Enter the string to encrypt: ")

    # Encrypt the string
    encrypted_values = encrypt_string(public_key, plaintext_str)
    print("Encrypted values:", encrypted_values)

    # Decrypt the string
    decrypted_str = decrypt_string(public_key, private_key, encrypted_values)
    print("Decrypted string:", decrypted_str)

    # Verify if the decrypted string matches the original string
    assert decrypted_str == plaintext_str, "Decryption failed!"
    print("The decrypted string matches the original string.")
