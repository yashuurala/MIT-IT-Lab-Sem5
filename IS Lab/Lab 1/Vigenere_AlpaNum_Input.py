# Function to generate the repeating key based on the message length
def generate_key(message, key_input):
    key = ""
    n = len(message)
    n1 = len(key_input)

    # Generating the repeated key to match the length of the message
    for i in range(n):
        if key_input[i % n1].isdigit():
            # Map digits 0-9 to letters a-j
            key += chr(ord('a') + int(key_input[i % n1]))
        else:
            key += key_input[i % n1]

    return key


# Function for encryption using the Vigenère cipher
def vigenere_encrypt(message, key):
    result = ""
    n = len(message)

    # Encryption process
    for i in range(n):
        if message[i].isalpha():  # Only encrypt alphabetic characters
            # Convert both message and key to lowercase, and apply the cipher
            result += chr(((ord(message[i].lower()) - 97 + ord(key[i].lower()) - 97) % 26) + 97)
        else:
            # Keep non-alphabetic characters unchanged in the result
            result += message[i]

    return result


# Function for decryption using the Vigenère cipher
def vigenere_decrypt(encrypted_message, key):
    result = ""
    n = len(encrypted_message)

    # Decryption process
    for i in range(n):
        if encrypted_message[i].isalpha():  # Only decrypt alphabetic characters
            # Reverse the encryption by subtracting the key value
            result += chr(((ord(encrypted_message[i].lower()) - 97 - (ord(key[i].lower()) - 97)) % 26) + 97)
        else:
            # Keep non-alphabetic characters unchanged in the result
            result += encrypted_message[i]

    return result

# Example usage
message = "hello123world"
key_input = "key123"

# Generate the repeating key
key = generate_key(message, key_input)

# Encrypt the message
encrypted_message = vigenere_encrypt(message, key)
# Decrypt the message back
decrypted_message = vigenere_decrypt(encrypted_message, key)

print("Original Message:", message)
print("Generated Key:", key)
print("Encrypted Message:", encrypted_message)
print("Decrypted Message:", decrypted_message)