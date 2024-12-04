import random
from sympy import mod_inverse, isprime, gcd  # Import gcd function

def genprime(bits=16):
    """ Generate a prime number with the specified bit length. """
    while True:
        p = random.getrandbits(bits)
        if isprime(p):
            return p

def genkeypair(bits=16):
    """ Generate RSA public and private key pair. """
    p = genprime(bits)
    q = genprime(bits)
    n = p * q
    phi_n = (p - 1) * (q - 1)

    # Choose e such that 1 < e < phi_n and gcd(e, phi_n) = 1
    e = random.randint(2, phi_n - 1)
    while gcd(e, phi_n) != 1:  # Use gcd from sympy
        e = random.randint(2, phi_n - 1)

    d = mod_inverse(e, phi_n)

    return (n, e), (n, d)  # Public key and private key

def encrypt(pubkey, plaintext):
    """ Encrypt a plaintext message using the public key. """
    n, e = pubkey
    return pow(plaintext, e, n)

def decrypt(privkey, ciphertext):
    """ Decrypt a ciphertext message using the private key. """
    n, d = privkey
    return pow(ciphertext, d, n)

def homomorphic_multiply(c1, c2, n):
    """ Multiply two ciphertexts under RSA encryption. """
    return (c1 * c2) % n

def main_menu():
    print("\nRSA Encryption Scheme Menu")
    print("1. Generate Key Pair")
    print("2. Encrypt Integer")
    print("3. Multiply Encrypted Integers")
    print("4. Decrypt Integer")
    print("5. Exit")

def main():
    pubkey, privkey = None, None
    encrypted_numbers = []

    while True:
        main_menu()
        choice = input("Choose an option: ")

        if choice == '1':
            pubkey, privkey = genkeypair()
            print(f"Public Key: {pubkey}")
            print(f"Private Key: {privkey}")

        elif choice == '2':
            if pubkey is None:
                print("Please generate keys first.")
                continue
            try:
                num = int(input("Enter an integer to encrypt: "))
                c = encrypt(pubkey, num)
                encrypted_numbers.append(c)
                print(f"Ciphertext: {c}")
            except ValueError:
                print("Please enter a valid integer.")

        elif choice == '3':
            if len(encrypted_numbers) < 2:
                print("You need at least two encrypted numbers to multiply.")
                continue
            try:
                c1_index = int(input("Enter the index of the first ciphertext (0): "))
                c2_index = int(input("Enter the index of the second ciphertext (1): "))
                c_product = homomorphic_multiply(encrypted_numbers[c1_index], encrypted_numbers[c2_index], pubkey[0])
                print(f"Encrypted product: {c_product}")
            except ValueError:
                print("Please enter valid indices.")
            except IndexError:
                print("Invalid index. Please ensure the indices are correct.")

        elif choice == '4':
            if privkey is None:
                print("Please generate keys first.")
                continue
            try:
                c = int(input("Enter the ciphertext to decrypt: "))
                dec = decrypt(privkey, c)
                print(f"Decrypted value: {dec}")
            except ValueError:
                print("Please enter a valid integer for the ciphertext.")
            except Exception as e:
                print(f"An error occurred during decryption: {e}")

        elif choice == '5':
            print("Exiting...")
            break

        else:
            print("Invalid choice. Please select again.")

if __name__ == "__main__":
    main()

