import os
from cryptography.hazmat.primitives.asymmetric import rsa, dh, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.backends import default_backend
import base64


# Key management system
class KeyManagementSystem:
    def __init__(self):
        self.keys = {}

    def generate_rsa_key(self, name):
        """Generate and save RSA key pair."""
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048, backend=default_backend())
        public_key = private_key.public_key()
        self.keys[name] = {'private_key': private_key, 'public_key': public_key}
        self._save_key(name, private_key, 'private')
        self._save_key(name, public_key, 'public')

    def _save_key(self, name, key, key_type):
        """Save key to file."""
        key_bytes = key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        ) if key_type == 'private' else key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        with open(f'{name}_{key_type}_key.pem', 'wb') as f:
            f.write(key_bytes)

    def load_keys(self, name):
        """Load private and public keys from file."""
        with open(f'{name}_private_key.pem', 'rb') as f:
            private_key = serialization.load_pem_private_key(f.read(), password=None, backend=default_backend())
        with open(f'{name}_public_key.pem', 'rb') as f:
            public_key = serialization.load_pem_public_key(f.read(), backend=default_backend())
        self.keys[name] = {'private_key': private_key, 'public_key': public_key}

    def revoke_key(self, name):
        """Revoke and delete keys."""
        if name in self.keys:
            del self.keys[name]
            os.remove(f'{name}_private_key.pem')
            os.remove(f'{name}_public_key.pem')


# Diffie-Hellman key exchange
def diffie_hellman_key_exchange():
    parameters = dh.generate_parameters(generator=2, key_size=2048, backend=default_backend())
    private_key_A = parameters.generate_private_key()
    private_key_B = parameters.generate_private_key()
    shared_key_A = private_key_A.exchange(private_key_B.public_key())
    return HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=b'handshake', backend=default_backend()).derive(
        shared_key_A)


# RSA Encryption/Decryption
def rsa_encrypt(public_key, message):
    return base64.b64encode(public_key.encrypt(message, padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()),
                                                                     algorithm=hashes.SHA256(), label=None)))


def rsa_decrypt(private_key, ciphertext):
    return private_key.decrypt(base64.b64decode(ciphertext),
                               padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(),
                                            label=None))


# Menu-driven user interface
def main():
    kms = KeyManagementSystem()

    while True:
        print("\n--- Key Management System Menu ---")
        print("1. Generate RSA Key")
        print("2. Load Existing Keys")
        print("3. Encrypt a Message")
        print("4. Decrypt a Message")
        print("5. Perform Diffie-Hellman Key Exchange")
        print("6. Revoke Keys")
        print("7. Exit")

        choice = input("Select an option (1-7): ")

        if choice == '1':
            name = input("Enter a name for the key: ")
            kms.generate_rsa_key(name)
            print(f"RSA keys generated and saved for {name}.")

        elif choice == '2':
            name = input("Enter the name of the key to load: ")
            try:
                kms.load_keys(name)
                print(f"Keys loaded for {name}.")
            except Exception as e:
                print(f"Error loading keys: {e}")

        elif choice == '3':
            name = input("Enter the name of the key to use for encryption: ")
            if name in kms.keys:
                message = input("Enter the message to encrypt: ").encode()
                encrypted_message = rsa_encrypt(kms.keys[name]['public_key'], message)
                print("Encrypted message:", encrypted_message.decode())
            else:
                print("No keys found for the given name.")

        elif choice == '4':
            name = input("Enter the name of the key to use for decryption: ")
            if name in kms.keys:
                ciphertext = input("Enter the encrypted message: ").encode()
                try:
                    decrypted_message = rsa_decrypt(kms.keys[name]['private_key'], ciphertext)
                    print("Decrypted message:", decrypted_message.decode())
                except Exception as e:
                    print(f"Error decrypting message: {e}")
            else:
                print("No keys found for the given name.")

        elif choice == '5':
            shared_key = diffie_hellman_key_exchange()
            print("Shared DH key:", base64.b64encode(shared_key).decode())

        elif choice == '6':
            name = input("Enter the name of the key to revoke: ")
            kms.revoke_key(name)
            print(f"Keys for {name} have been revoked.")

        elif choice == '7':
            print("Exiting the program.")
            break

        else:
            print("Invalid choice . Please select a valid option.")


if __name__ == "__main__":
    main()
