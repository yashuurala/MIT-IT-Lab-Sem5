# Function to generate a repeated key to match the length of the message
def generate_key(message, key_input):
    key = ""
    n = len(message)
    n1 = len(key_input)

    # Generating the repeated key to match the length of the message
    for i in range(n):
        key += key_input[i % n1]
    return key

# Function for encryption
def vigenere_encrypt(message, key):
    result = ""
    n = len(message)

    # Encryption process
    for i in range(n):
        result += chr(((ord(message[i]) - 97 + ord(key[i]) - 97) % 26) + 97)
    return result

# Function for decryption
def vigenere_decrypt(ciphertext, key):
    result = ""
    n = len(ciphertext)

    # Decryption process
    for i in range(n):
        result += chr(((ord(ciphertext[i]) - 97 - (ord(key[i]) - 97)) % 26) + 97)
    return result

# Main program
if __name__ == "__main__":
    # Taking user input for message and key
    message = input("Enter the message to encrypt: ").replace(" ", "").lower()
    key_input = input("Enter the key: ").replace(" ", "").lower()

    # Generating the key to match the message length
    key = generate_key(message, key_input)
    print(f"Generated key: {key}")

    # Encrypting the message
    encrypted_message = vigenere_encrypt(message, key)
    print(f"Encrypted message is: {encrypted_message}")

    # Decrypting the message
    decrypted_message = vigenere_decrypt(encrypted_message, key)
    print(f"Decrypted message is: {decrypted_message}")
