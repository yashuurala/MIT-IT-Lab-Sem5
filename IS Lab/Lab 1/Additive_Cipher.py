# Function to encrypt the message
def encrypt_caesar_cipher(message, key):
    result = ""
    for char in message:
        if 'a' <= char <= 'z':  # Check for lowercase characters
            new_char = chr(((ord(char) - 97 + key) % 26) + 97)
            result += new_char
    return result

# Function to decrypt the message
def decrypt_caesar_cipher(encrypted_message, key):
    result = ""
    for char in encrypted_message:
        if 'a' <= char <= 'z':  # Check for lowercase characters
            new_char = chr(((ord(char) - 97 - key) % 26) + 97)
            result += new_char
    return result

# Main program
if __name__ == "__main__":
    # Take user input for the message and key
    message = input("Enter the message to encrypt (ignore spaces): ").replace(" ", "").lower()
    key = int(input("Enter the key: "))

    # Encrypt the message
    encrypted_message = encrypt_caesar_cipher(message, key)
    print("Encoded message is::")
    print(encrypted_message)

    # Decrypt the message
    decrypted_message = decrypt_caesar_cipher(encrypted_message, key)
    print("Decoded message is::")
    print(decrypted_message)
