from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

# Function to encrypt plaintext using AES-192
def aes192_encrypt(plaintext, key):
    cipher = AES.new(key, AES.MODE_ECB)
    padded_plaintext = pad(plaintext.encode('utf-8'), AES.block_size)
    ciphertext = cipher.encrypt(padded_plaintext)
    return ciphertext

# Function to decrypt ciphertext using AES-192
def aes192_decrypt(ciphertext, key):
    decipher = AES.new(key, AES.MODE_ECB)
    decrypted_padded_plaintext = decipher.decrypt(ciphertext)
    decrypted_plaintext = unpad(decrypted_padded_plaintext, AES.block_size).decode('utf-8')
    return decrypted_plaintext

# Main execution for AES-192
if __name__ == "__main__":
    plaintext = input("Enter the plaintext to encrypt: ")
    key_input = input("Enter a 48-character hexadecimal key for AES-192: ")

    # Check the key length
    if len(key_input) != 48:
        raise ValueError("Key must be 48 hexadecimal characters (192 bits).")

    # Convert the key from hex string to bytes
    key = bytes.fromhex(key_input)

    # Encrypt the plaintext
    ciphertext = aes192_encrypt(plaintext, key)

    # Decrypt the ciphertext
    decrypted_plaintext = aes192_decrypt(ciphertext, key)

    # Print the results
    print("Ciphertext (hex):", ciphertext.hex())
    print("Decrypted Text:", decrypted_plaintext)
