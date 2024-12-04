from Crypto.Cipher import DES
from Crypto.Util.Padding import pad, unpad


# Function to format the key to exactly 8 bytes
def format_key(input_key):
    # Convert the key to bytes
    key_bytes = bytes.fromhex(input_key)

    # Ensure the key is exactly 8 bytes long
    if len(key_bytes) != 8:
        raise ValueError("Key must be exactly 8 bytes long (16 hex characters).")

    return key_bytes


# Function to encrypt using Double DES
def encrypt_2des(plaintext, key1, key2):
    # Format the keys
    key1 = format_key(key1)
    key2 = format_key(key2)

    # Encrypt with the first key
    cipher1 = DES.new(key1, DES.MODE_ECB)
    padded_plaintext = pad(plaintext.encode('utf-8'), DES.block_size)
    intermediate = cipher1.encrypt(padded_plaintext)

    # Encrypt with the second key
    cipher2 = DES.new(key2, DES.MODE_ECB)
    ciphertext = cipher2.encrypt(intermediate)

    return ciphertext.hex()


# Function to decrypt using Double DES
def decrypt_2des(ciphertext_hex, key1, key2):
    # Format the keys
    key1 = format_key(key1)
    key2 = format_key(key2)

    # Convert hex ciphertext back to bytes
    ciphertext = bytes.fromhex(ciphertext_hex)

    # Decrypt with the second key
    decipher2 = DES.new(key2, DES.MODE_ECB)
    intermediate = decipher2.decrypt(ciphertext)

    # Decrypt with the first key
    decipher1 = DES.new(key1, DES.MODE_ECB)
    decrypted_padded_plaintext = decipher1.decrypt(intermediate)

    # Remove the padding from the decrypted plaintext
    decrypted_plaintext = unpad(decrypted_padded_plaintext, DES.block_size).decode('utf-8')

    return decrypted_plaintext


# Main execution
if __name__ == "__main__":
    # Take user input for the plaintext and 32-bit key
    plaintext = input("Enter the plaintext to encrypt: ")
    key_input = input("Enter a 32-character hexadecimal key (for 2DES): ")

    # Validate the key length
    if len(key_input) != 32:
        raise ValueError("Key must be exactly 32 hexadecimal characters (16 bytes).")

    # Split the key into two 16-character keys for 2DES
    key1_input = key_input[:16]  # First 16 characters
    key2_input = key_input[16:]  # Second 16 characters

    # Encrypt the plaintext
    ciphertext_hex = encrypt_2des(plaintext, key1_input, key2_input)

    # Decrypt the ciphertext
    decrypted_plaintext = decrypt_2des(ciphertext_hex, key1_input, key2_input)

    # Display the ciphertext and decrypted plaintext
    print("\nCiphertext (hex):", ciphertext_hex)
    print("Decrypted Text:", decrypted_plaintext)
