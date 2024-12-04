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
    p = randprime(2 ** (bit_length - 1), 2 ** bit_length)
    q = randprime(2 ** (bit_length - 1), 2 ** bit_length)
    n = p * q
    phi_n = (p - 1) * (q - 1)
    e = random.randint(1, phi_n)
    while gcd(e, phi_n) != 1:
        e = random.randint(1, phi_n)
    d = modinv(e, phi_n)
    public_key = (e, n)
    private_key = (d, n)
    return public_key, private_key

# RSA encryption
def rsa_encrypt(public_key, plaintext_int):
    e, n = public_key
    ciphertext = pow(plaintext_int, e, n)
    return ciphertext

# RSA decryption
def rsa_decrypt(private_key, ciphertext):
    d, n = private_key
    plaintext_int = pow(ciphertext, d, n)
    return plaintext_int

# String to integer conversion (UTF-8 encoding)
def string_to_int(string):
    return int.from_bytes(string.encode('utf-8'), 'big')

# Integer to string conversion
def int_to_string(integer):
    return integer.to_bytes((integer.bit_length() + 7) // 8, 'big').decode('utf-8')

# Main code
if __name__ == "__main__":
    # Generate RSA keypair
    public_key, private_key = generate_rsa_keypair()

    # Take user input for a string
    input_string = input("Enter a string to encrypt: ")

    # Convert the string to an integer
    plaintext_int = string_to_int(input_string)

    # Encrypt the integer representation of the string
    ciphertext = rsa_encrypt(public_key, plaintext_int)
    print(f"Ciphertext: {ciphertext}")

    # Decrypt the ciphertext back to an integer
    decrypted_int = rsa_decrypt(private_key, ciphertext)

    # Convert the decrypted integer back to a string
    decrypted_string = int_to_string(decrypted_int)
    print(f"Decrypted string: {decrypted_string}")

    # Verify if the decrypted string matches the original string
    assert decrypted_string == input_string, "Decryption failed!"
    print("The decrypted string matches the original input.")
