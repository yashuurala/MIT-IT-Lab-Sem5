

# Function to encrypt a message using Autokey cipher
def autokey_encrypt(message, k):
    # Convert the message to lowercase and remove spaces
    message = message.lower().replace(" ", "")

    # Initial key
    key = chr(k + 97)  # Create initial key character
    n = len(message)

    # Build the full key
    for i in range(n):
        key += message[i]  # Append the message characters to the key

    # Encryption process
    result = ""
    for i in range(n):
        result += chr((((ord(message[i]) - 97) + (ord(key[i]) - 97)) % 26) + 97)

    return result


# Function to decrypt a message using Autokey cipher
def autokey_decrypt(encrypted_message, k):
    # Initial key
    key = chr(k + 97)  # Create initial key character
    n = len(encrypted_message)

    # Decryption process
    decrypted = ""
    for i in range(n):
        decrypted_char = chr((((ord(encrypted_message[i]) - ord(key[i])) % 26) + 97))
        decrypted += decrypted_char
        key += decrypted_char  # Append decrypted char to key for future characters

    return decrypted


# Taking user input
message = input("Enter the message to encrypt: ")
k = int(input("Enter the key (number from 0 to 25): "))

# Encrypt the message
encrypted_message = autokey_encrypt(message, k)
print(f"Encrypted message: {encrypted_message}")

# Decrypt the message
decrypted_message = autokey_decrypt(encrypted_message, k)
print(f"Decrypted message: {decrypted_message}")
