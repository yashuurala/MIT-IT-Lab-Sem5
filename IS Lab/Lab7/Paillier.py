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
    # Generate two large prime numbers p and q using sympy's nextprime
    p = nextprime(random.getrandbits(bit_length))
    q = nextprime(random.getrandbits(bit_length))

    # Compute n = p * q
    n = p * q
    nsq = n * n  # n^2

    # Compute lambda = lcm(p-1, q-1)
    lambda_value = (p - 1) * (q - 1) // gcd(p - 1, q - 1)

    # Generate g such that g is in Zn^2*
    g = n + 1

    # mu = (L(g^lambda mod n^2))^-1 mod n, where L(x) = (x-1) // n
    x = pow(g, lambda_value, nsq)
    L = (x - 1) // n
    mu = modinv(L, n)

    public_key = (n, g)
    private_key = (lambda_value, mu)

    return public_key, private_key


# Paillier encryption
def paillier_encrypt(public_key, plaintext):
    n, g = public_key
    nsq = n * n

    # Random r in Zn*
    r = random.randint(1, n - 1)
    while gcd(r, n) != 1:
        r = random.randint(1, n - 1)

    # c = g^m * r^n mod n^2
    c = (pow(g, plaintext, nsq) * pow(r, n, nsq)) % nsq
    return c


# Paillier decryption
def paillier_decrypt(public_key, private_key, ciphertext):
    n, g = public_key
    lambda_value, mu = private_key
    nsq = n * n

    # Compute m = L(c^lambda mod n^2) * mu mod n
    x = pow(ciphertext, lambda_value, nsq)
    L = (x - 1) // n
    plaintext = (L * mu) % n
    return plaintext


# Homomorphic addition (adding two ciphertexts)
def paillier_add(public_key, ciphertext1, ciphertext2):
    n, _ = public_key
    nsq = n * n

    # Perform ciphertext1 * ciphertext2 mod n^2
    return (ciphertext1 * ciphertext2) % nsq


# Main code
if __name__ == "__main__":
    # Generate Paillier keypair
    public_key, private_key = generate_paillier_keypair()

    # Take user input for integers
    m1 = int(input("Enter the first integer to encrypt: "))
    m2 = int(input("Enter the second integer to encrypt: "))

    # Encrypt the integers
    c1 = paillier_encrypt(public_key, m1)
    c2 = paillier_encrypt(public_key, m2)
    print(f"Ciphertext of {m1}: {c1}")
    print(f"Ciphertext of {m2}: {c2}")

    # Perform homomorphic addition on encrypted integers
    encrypted_sum = paillier_add(public_key, c1, c2)
    print(f"Encrypted sum: {encrypted_sum}")

    # Decrypt the result of the addition
    decrypted_sum = paillier_decrypt(public_key, private_key, encrypted_sum)
    print(f"Decrypted sum: {decrypted_sum}")

    # Verify if the decrypted sum matches the actual sum
    assert decrypted_sum == m1 + m2, "Decryption failed!"
    print("The decrypted sum matches the original sum.")
