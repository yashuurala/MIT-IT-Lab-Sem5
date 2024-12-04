from ecdsa import SigningKey, NIST256p, BadSignatureError
import hashlib

# Function to generate Schnorr private and public keys
def generate_schnorr_keys():
    private_key = SigningKey.generate(curve=NIST256p)  # Generate private key
    public_key = private_key.verifying_key  # Generate corresponding public key
    return private_key, public_key

# Function to hash a message using SHA-256
def hash_message(message):
    return hashlib.sha256(message.encode()).digest()  # Return the SHA-256 hash of the message

# Function to sign a message using a private key
def sign_message(message, private_key):
    message_hash = hash_message(message)  # Hash the message
    signature = private_key.sign(message_hash, hashfunc=hashlib.sha256)  # Sign the message hash
    return signature

# Function to verify the signature of a message using the public key
def verify_signature(message, signature, public_key):
    try:
        message_hash = hash_message(message)  # Hash the message
        return public_key.verify(signature, message_hash, hashfunc=hashlib.sha256)  # Verify the signature
    except BadSignatureError:
        return False

# Main function to demonstrate Schnorr signature
def main():
    # Generate Schnorr keys
    private_key, public_key = generate_schnorr_keys()

    # Take user input for the message
    message = input("Enter your message: ")

    # Sign the message
    signature = sign_message(message, private_key)

    # Verify the signature
    is_valid = verify_signature(message, signature, public_key)

    # Output the results
    print("\n--- Schnorr Signature ---")
    print("Message:", message)
    print("Signature (hex):", signature.hex())  # Print signature in hexadecimal format
    print("Signature valid:", is_valid)  # Print if the signature is valid or not

# Run the main function
if __name__ == "__main__":
    main()
