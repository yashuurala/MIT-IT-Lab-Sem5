from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature, decode_dss_signature
from cryptography.hazmat.backends import default_backend

# Global variables for storing keys
private_key = None
public_key = None

# ---------------- Key Generation ----------------
def generate_ecc_keys():
    """Generate ECC private and public keys."""
    global private_key, public_key
    private_key = ec.generate_private_key(ec.SECP256R1(), default_backend())
    public_key = private_key.public_key()
    print("ECC keys generated successfully.")

# ---------------- Signing Function ----------------
def sign_message(message):
    """Sign a message using an ECC private key."""
    if private_key is None:
        print("Please generate ECC keys first.")
        return None, None
    # Sign the message
    signature = private_key.sign(
        message,
        ec.ECDSA(hashes.SHA256())
    )
    # Decode to r, s format for easier handling
    r, s = decode_dss_signature(signature)
    print("Message signed successfully.")
    return r, s

# ---------------- Verification Function ----------------
def verify_signature(message, r, s):
    """Verify an ECC signature using the public key."""
    if public_key is None:
        print("Please generate ECC keys first.")
        return False
    # Encode r, s back into signature
    signature = encode_dss_signature(r, s)
    try:
        # Verify the signature
        public_key.verify(
            signature,
            message,
            ec.ECDSA(hashes.SHA256())
        )
        print("Signature is valid and verified.")
        return True
    except Exception:
        print("Signature verification failed.")
        return False

# ---------------- Menu-Driven Program ----------------
def main():

    while True:
        print("\nECC Signature Menu")
        print("1: Generate ECC Keys")
        print("2: Sign a Message")
        print("3: Verify a Signature")
        print("4: Exit")
        choice = input("Enter your choice: ")

        if choice == '1':
            generate_ecc_keys()

        elif choice == '2':
            message = input("Enter the message to sign: ").encode()
            r, s = sign_message(message)
            if r and s:
                print(f"Signature (r, s): ({r}, {s})")

        elif choice == '3':
            message = input("Enter the message to verify: ").encode()
            try:
                r = int(input("Enter the value of r: "))
                s = int(input("Enter the value of s: "))
                verify_signature(message, r, s)
            except ValueError:
                print("Invalid input for r or s. Please enter integer values.")

        elif choice == '4':
            print("Exiting program.")
            break

        else:
            print("Invalid choice. Please enter a number between 1 and 4.")

if __name__ == "__main__":
    main()
