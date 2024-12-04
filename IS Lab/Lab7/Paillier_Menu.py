import random
import sympy
from sympy import mod_inverse

def genprime(bits=16):
    while True:
        p = random.getrandbits(bits)
        if sympy.isprime(p):
            return p

def L(u, n):
    return (u - 1) // n

def genkeypair():
    p = genprime()
    q = genprime()
    n = p * q
    lam = sympy.lcm(p - 1, q - 1)
    g = random.randint(1, n * n)

    lam = int(lam)
    mu = mod_inverse(L(pow(g, lam, n * n), n), n)

    return (n, g), (lam, mu)

def encrypt(pubk, msg):
    n, g = pubk
    while True:
        r = random.randint(1, n - 1)
        if sympy.gcd(r, n) == 1:
            break
    c = (pow(g, msg, n * n) * pow(r, n, n * n)) % (n * n)
    return c

def decrypt(prik, ct, pubk):
    n, _ = pubk
    lam, mu = prik
    msg = (L(pow(ct, lam, n * n), n) * mu) % n
    return msg

def homadd(c1, c2, pubk):
    n, _ = pubk
    return (c1 * c2) % (n * n)

def main_menu():
    print("Paillier Encryption Scheme Menu")
    print("1. Generate Key Pair")
    print("2. Encrypt Integer")
    print("3. Add Encrypted Integers")
    print("4. Decrypt Integer")
    print("5. Exit")

def main():
    pubk, prik = None, None
    encrypted_numbers = []

    while True:
        main_menu()
        choice = input("Choose an option: ")

        if choice == '1':
            pubk, prik = genkeypair()
            print(f"Public Key: {pubk}")
            print(f"Private Key: {prik}")

        elif choice == '2':
            if pubk is None:
                print("Please generate keys first.")
                continue
            num = int(input("Enter an integer to encrypt: "))
            c = encrypt(pubk, num)
            encrypted_numbers.append(c)
            print(f"Ciphertext: {c}")

        elif choice == '3':
            if len(encrypted_numbers) < 2:
                print("You need at least two encrypted numbers to add.")
                continue
            c1 = int(input("Enter the index of the first ciphertext (0): "))
            c2 = int(input("Enter the index of the second ciphertext (1): "))
            c_sum = homadd(encrypted_numbers[c1], encrypted_numbers[c2], pubk)
            print(f"Encrypted sum: {c_sum}")

        elif choice == '4':
            if prik is None:
                print("Please generate keys first.")
                continue
            c = int(input("Enter the ciphertext to decrypt: "))
            dec = decrypt(prik, c, pubk)
            print(f"Decrypted value: {dec}")

        elif choice == '5':
            print("Exiting...")
            break

        else:
            print("Invalid choice. Please select again.")

if __name__ == "__main__":
    main()

