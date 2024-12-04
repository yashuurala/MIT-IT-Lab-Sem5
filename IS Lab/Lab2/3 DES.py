from Crypto.Cipher import DES3
from Crypto.Util.Padding import pad, unpad


# Function to encrypt the message
def encrypt_3des(message, key):
    cipher = DES3.new(key, DES3.MODE_ECB)
    padded_message = pad(message.encode(), DES3.block_size)
    ciphertext = cipher.encrypt(padded_message)
    return ciphertext


# Function to decrypt the ciphertext
def decrypt_3des(ciphertext, key):
    decipher = DES3.new(key, DES3.MODE_ECB)
    decrypted_padded_message = decipher.decrypt(ciphertext)
    decrypted_message = unpad(decrypted_padded_message, DES3.block_size).decode()
    return decrypted_message


# Main execution
if __name__ == "__main__":
    # Take user input for the message
    message = input("Enter the message to encrypt: ")

    # Take the 3DES key input in hexadecimal form
    key_input = input("Enter a 48-character hexadecimal key (24 bytes): ")
    if len(key_input) != 48:
        raise ValueError("The key must be exactly 48 hex characters for 24 bytes.")

    # Convert hex key to bytes
    key = bytes.fromhex(key_input)

    # Ensure the key is valid for 3DES
    if len(key) != 24:
        raise ValueError("The key must be 24 bytes long.")

    # Encrypt the message
    ciphertext = encrypt_3des(message, key)

    # Decrypt the ciphertext
    decrypted_message = decrypt_3des(ciphertext, key)

    # Display results
    print("Ciphertext (in hex):", ciphertext.hex())
    print("Decrypted message:", decrypted_message)

