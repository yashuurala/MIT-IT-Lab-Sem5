import os
from Crypto.Util.number import inverse, getPrime
import logging
from datetime import datetime

# Logging for auditing
logging.basicConfig(filename='key_management.log', level=logging.INFO)

# Rabin Cryptosystem
class RabinCryptosystem:
    def __init__(self, key_size=1024):
        self.key_size = key_size

    def generate_key_pair(self):
        p, q = getPrime(self.key_size // 2), getPrime(self.key_size // 2)
        return p * q, (p, q)

    def encrypt(self, public_key, message):
        return pow(message, 2, public_key)

    def decrypt(self, private_key, ciphertext):
        p, q = private_key
        mp, mq = pow(ciphertext, (p + 1) // 4, p), pow(ciphertext, (q + 1) // 4, q)
        q_inv, N = inverse(q, p), p * q
        h = (q_inv * (mp - mq)) % p
        return (mq + h * q) % N, (mq - h * q) % N

# Key Management Service
class KeyManagementService:
    def __init__(self):
        self.key_store = 'key_store'
        os.makedirs(self.key_store, exist_ok=True)

    def generate_key_pair(self, name):
        public_key, private_key = RabinCryptosystem().generate_key_pair()
        self._save_key(name, public_key, private_key)
        self._log(f"Generated key pair for {name}")
        return public_key, private_key

    def _save_key(self, name, public_key, private_key):
        with open(os.path.join(self.key_store, f"{name}_keys.pem"), "w") as f:
            f.write(f"{public_key}\n{private_key[0]} {private_key[1]}")

    def revoke_key(self, name):
        try:
            os.remove(os.path.join(self.key_store, f"{name}_keys.pem"))
            self._log(f"Revoked keys for {name}")
            print(f"Keys for {name} have been revoked.")
        except FileNotFoundError:
            print(f"Keys for {name} not found.")

    def renew_keys(self, name):
        self.generate_key_pair(name)
        self._log(f"Renewed keys for {name}")

    def distribute_keys(self, name):
        try:
            with open(os.path.join(self.key_store, f"{name}_keys.pem")) as f:
                keys = f.read()
            self._log(f"Distributed keys for {name}")
            return keys
        except FileNotFoundError:
            print(f"Keys for {name} not found.")
            return None

    def _log(self, message):
        log_msg = f"{datetime.now().isoformat()} - {message}"
        logging.info(log_msg)

def menu():
    kms = KeyManagementService()

    while True:
        print("\n=== Key Management System Menu ===")
        print("1. Generate Key Pair")
        print("2. Distribute Keys")
        print("3. Revoke Keys")
        print("4. Renew Keys")
        print("5. Exit")

        choice = input("Select an option (1-5): ")

        if choice == '1':
            name = input("Enter a name for the key pair: ")
            public_key, _ = kms.generate_key_pair(name)
            print("Public Key:", public_key)

        elif choice == '2':
            name = input("Enter the name for which you want to distribute keys: ")
            keys = kms.distribute_keys(name)
            if keys:
                print("Distributed Keys:\n", keys)

        elif choice == '3':
            name = input("Enter the name for which you want to revoke keys: ")
            kms.revoke_key(name)

        elif choice == '4':
            name = input("Enter the name for which you want to renew keys: ")
            kms.renew_keys(name)

        elif choice == '5':
            print("Exiting the Key Management System.")
            break

        else:
            print("Invalid choice. Please select a valid option.")

if __name__ == "__main__":
    menu()
