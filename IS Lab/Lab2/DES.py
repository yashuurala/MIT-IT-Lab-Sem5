from Crypto.Cipher import DES
from Crypto.Util.Padding import pad, unpad

# Function to format the key to exactly 8 bytes
def format_key(input_key):
    # Convert the key to bytes
    key_bytes = input_key.encode('utf-8')

    # Ensure the key is exactly 8 bytes long
    if len(key_bytes) > 8:
        # Truncate if too long
        key_bytes = key_bytes[:8]
    elif len(key_bytes) < 8:
        # Pad if too short
        key_bytes = key_bytes.ljust(8, b'\0')

    return key_bytes

# Function to encrypt the plaintext
def encrypt(plaintext, key):
    # Create a DES cipher object with the key
    cipher = DES.new(key, DES.MODE_ECB)

    # Encode the plaintext to bytes and pad it to a multiple of the DES block size (8 bytes)
    padded_plaintext = pad(plaintext.encode('utf-8'), DES.block_size)

    # Encrypt the padded plaintext
    ciphertext = cipher.encrypt(padded_plaintext)

    # Convert the ciphertext to a hexadecimal string for easy viewing
    return ciphertext.hex()

# Function to decrypt the ciphertext
def decrypt(ciphertext_hex, key):
    # Create a new DES cipher object for decryption
    decipher = DES.new(key, DES.MODE_ECB)

    # Convert hex ciphertext back to bytes
    ciphertext = bytes.fromhex(ciphertext_hex)

    # Decrypt the ciphertext
    decrypted_padded_plaintext = decipher.decrypt(ciphertext)

    # Remove the padding from the decrypted plaintext
    decrypted_plaintext = unpad(decrypted_padded_plaintext, DES.block_size).decode('utf-8')

    return decrypted_plaintext

# Main execution
if __name__ == "__main__":
    # Take user input for the plaintext and key
    plaintext = input("Enter the plaintext to encrypt: ")
    input_key = input("Enter the key (8 characters or fewer): ")

    # Format the key
    key = format_key(input_key)

    # Encrypt the plaintext
    ciphertext_hex = encrypt(plaintext, key)

    # Decrypt the ciphertext
    decrypted_plaintext = decrypt(ciphertext_hex, key)

    # Display the ciphertext and decrypted plaintext
    print("\nCiphertext (hex):", ciphertext_hex)
    print("Decrypted Text:", decrypted_plaintext)
