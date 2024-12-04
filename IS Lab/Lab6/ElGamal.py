from Crypto.PublicKey import ElGamal
from Crypto.Random import get_random_bytes
from Crypto.Util import number
from Crypto.Hash import SHA256
import binascii


# Function to generate ElGamal private and public keys
def generate_elgamal_keys(bits=256):
    key = ElGamal.generate(bits, get_random_bytes)
    return key


# Function to sign a message
def sign_message(message, private_key):
    # Hash the message
    hash_obj = SHA256.new(message.encode())
    h = int(binascii.hexlify(hash_obj.digest()), 16)

    # Generate random integer k such that it is coprime to p-1
    p = private_key.p  # Extract the modulus p as an integer
    g = private_key.g
    x = private_key.x
    p_int = int(p)  # Ensure p is a native integer
    k = 0
    while True:
        k = number.getRandomRange(1, p_int - 2)  # Ensure k is in the correct range
        if number.GCD(k, p_int - 1) == 1:  # Check if k is coprime to p-1
            break

    # Calculate the signature components
    r = pow(g, k, p_int)
    k_inv = number.inverse(k, p_int - 1)  # Modular inverse of k

    # Convert all to int for arithmetic
    h_int = int(h)  # Ensure h is an int
    r_int = int(r)  # Ensure r is an int
    x_int = int(x)  # Ensure x is an int

    s = (k_inv * (h_int - x_int * r_int)) % (p_int - 1)

    # Return the signature
    return r, s


# Function to verify the signature
def verify_signature(message, signature, public_key):
    r, s = signature
    # Hash the message
    hash_obj = SHA256.new(message.encode())
    h = int(binascii.hexlify(hash_obj.digest()), 16)

    # Verify the signature
    p = public_key.p
    g = public_key.g
    y = public_key.y

    if r < 1 or r >= p:
        return False

    v1 = pow(g, h, p)
    v2 = (pow(y, r, p) * pow(r, s, p)) % p

    return v1 == v2


# Main function to demonstrate ElGamal signing and verification
def main():
    # Generate ElGamal keys
    private_key = generate_elgamal_keys()
    public_key = private_key.publickey()

    # Take user input for the message
    message = input("Enter your message: ")

    # Sign the message
    signature = sign_message(message, private_key)

    # Verify the signature
    is_valid = verify_signature(message, signature, public_key)

    # Output the results
    print("\n--- ElGamal Signature ---")
    print("Message:", message)
    print("Signature (r, s):", signature)
    print("Signature valid:", is_valid)


# Run the main function
if __name__ == "__main__":
    main()
