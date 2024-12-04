from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature, decode_dss_signature
from cryptography.hazmat.backends import default_backend
from Crypto.Util.number import getPrime, inverse, bytes_to_long, long_to_bytes, GCD
import random
from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15

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
    return private_key,public_key

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

def generate_elgamal_keys():
    """Generate ElGamal keys."""
    p = getPrime(256)  # Large prime number
    g = random.randint(2, p - 1)  # Generator
    x = random.randint(1, p - 2)  # Private key
    h = pow(g, x, p)  # Public key
    return (p, g, h, x)


def el_en(message,p,g,h):
    k = random.randint(1, p - 2)  # Ephemeral key
    c1 = pow(g, k, p)
    m = bytes_to_long(message)
    c2 = (m * pow(h, k, p)) % p
    return c1,c2

def el_dec(ciphertext,p,g,x):
    s = pow(ciphertext[0], x, p)
    s_inv = inverse(s, p)
    m_decrypted = (ciphertext[1] * s_inv) % p
    decrypted_message = long_to_bytes(m_decrypted)
    return decrypted_message


def main():
    generate_ecc_keys()
    message=None
    prescription=None
    ciphertext=None
    r,s=None,None
    p, g, h, x = generate_elgamal_keys()

    while True:
        print("Menu driven hospital program\n1 to register a patient and encrypt details using elgamal\n2 to sign the prescription using ecc\n3 to decrypt the patient details using elgamal\n4 to verify the prescription using ecc\n5 to exit\n")
        c=int(input("Enter your choice: "))

        if c==1:
            print("Patient Reg\n")
            message=input("Enter the details of the patient: ").encode()
            ciphertext = el_en(message, p, g, h)
            print(f"The encrypted msg is {ciphertext}\n")

        elif c==2:
            prescription=input("enter the prescription to be signed\n").encode()
            r, s = sign_message(prescription)
            if r and s:
                print(f"Signature (r, s): ({r}, {s})")
        elif c==3:
            decrypted_text = el_dec(ciphertext, p, g, x)
            print(f"Decrypted message : {decrypted_text.decode()}\n")

        elif c==4:
            prescription = input("Enter the message to verify: ").encode()
            try:
                r = int(input("Enter the value of r: "))
                s = int(input("Enter the value of s: "))
                verify_signature(prescription, r, s)
            except ValueError:
                print("Invalid input for r or s. Please enter integer values.")
        else:
            break


if __name__=="__main__":
    main()

