from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

def encrypt_aes(plaintext, key_input):
    """Encrypts the plaintext using AES with the provided hex key."""
    # Ensure the key is exactly 32 hex characters (128 bits)
    if len(key_input) != 32:
        raise ValueError("Key must be 32 hexadecimal characters (128 bits).")

    # Convert the key from hex string to bytes
    key = bytes.fromhex(key_input)

    # Create a new AES cipher object in ECB mode
    cipher = AES.new(key, AES.MODE_ECB)

    # Convert plaintext to bytes and pad it to match AES block size
    padded_plaintext = pad(plaintext.encode('utf-8'), AES.block_size)

    # Encrypt the padded plaintext
    ciphertext = cipher.encrypt(padded_plaintext)

    return ciphertext

def decrypt_aes(ciphertext, key_input):
    """Decrypts the ciphertext using AES with the provided hex key."""
    # Ensure the key is exactly 32 hex characters (128 bits)
    if len(key_input) != 32:
        raise ValueError("Key must be 32 hexadecimal characters (128 bits).")

    # Convert the key from hex string to bytes
    key = bytes.fromhex(key_input)

    # Create a new AES cipher object for decryption
    decipher = AES.new(key, AES.MODE_ECB)

    # Decrypt the ciphertext
    decrypted_padded_plaintext = decipher.decrypt(ciphertext)

    # Unpad the decrypted plaintext and convert it back to a string
    decrypted_plaintext = unpad(decrypted_padded_plaintext, AES.block_size).decode('utf-8')

    return decrypted_plaintext

# Take user input for the plaintext and key
plaintext = input("Enter the plaintext to encrypt: ")
key_input = input("Enter a 32-character hexadecimal key (for AES-128): ")

# Encrypt the plaintext
ciphertext = encrypt_aes(plaintext, key_input)

# Print the ciphertext in hex format
print("Ciphertext (hex):", ciphertext.hex())

# Decrypt the ciphertext
decrypted_text = decrypt_aes(ciphertext, key_input)

# Print the decrypted text
print("Decrypted Text:", decrypted_text)
