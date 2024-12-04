from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256
import hashlib

# Function to generate RSA private and public keys
def generate_rsa_keys():
    key = RSA.generate(2048)
    private_key = key
    public_key = key.publickey()
    return private_key, public_key

# Function to sign a message using RSA private key
def sign_message(message, private_key):
    # Hash the message using SHA-256
    message_hash = SHA256.new(message.encode())
    # Generate the signature
    signature = pkcs1_15.new(private_key).sign(message_hash)
    return signature

# Function to verify the RSA signature
def verify_signature(message, signature, public_key):
    # Hash the message
    message_hash = SHA256.new(message.encode())
    try:
        # Verify the signature
        pkcs1_15.new(public_key).verify(message_hash, signature)
        return True
    except (ValueError, TypeError):
        return False

# Main function to demonstrate RSA signature
def main():
    # Generate RSA keys
    private_key, public_key = generate_rsa_keys()

    # Take user input for the message
    message = input("Enter your message: ")

    # Sign the message
    signature = sign_message(message, private_key)

    # Verify the signature
    is_valid = verify_signature(message, signature, public_key)

    # Output the results
    print("\n--- RSA Signature ---")
    print("Message:", message)
    print("Signature (hex):", signature.hex())  # Print signature in hexadecimal format
    print("Signature valid:", is_valid)  # Print if the signature is valid or not

# Run the main function
if __name__ == "__main__":
    main()
