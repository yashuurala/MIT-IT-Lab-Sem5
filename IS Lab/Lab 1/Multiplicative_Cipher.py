# List of valid multiplicative keys for the cipher
valid_multiplicative_keys = [1, 3, 5, 7, 9, 11, 15, 17, 19, 21, 23, 25]


# Function to encrypt the message using Multiplicative Cipher
def multiplicative_encrypt(message, key):
    result = ""
    for char in message:
        if 'a' <= char <= 'z':  # Ensure the character is a lowercase alphabet
            new_char = chr((((ord(char) - 97) * key) % 26) + 97)
            result += new_char
    return result


# Function to find the multiplicative inverse of the key
def mod_inverse(key, m=26):
    for i in valid_multiplicative_keys:
        if (key * i) % m == 1:
            return i
    return None


# Function to decrypt the message using Multiplicative Cipher
def multiplicative_decrypt(ciphertext, key):
    # Find the multiplicative inverse of the key
    inverse_key = mod_inverse(key)
    if inverse_key is None:
        raise ValueError(f"No multiplicative inverse found for key {key}")

    result = ""
    for char in ciphertext:
        if 'a' <= char <= 'z':  # Ensure the character is a lowercase alphabet
            new_char = chr((((ord(char) - 97) * inverse_key) % 26) + 97)
            result += new_char
    return result


# Main Program
if __name__ == "__main__":
    # Taking user input for key
    key = int(input("Enter the multiplicative key (choose from 1, 3, 5, 7, 9, 11, 15, 17, 19, 21, 23, 25): "))

    # Validate if the key is in the valid list
    if key not in valid_multiplicative_keys:
        print("Invalid key! Please choose a valid multiplicative key.")
    else:
        # Taking user input for the message to encrypt
        message = input("Enter the message to encrypt (lowercase letters, no spaces): ").replace(" ", "").lower()

        # Encrypt the message
        encrypted_message = multiplicative_encrypt(message, key)
        print("Multiplicative encoded message is::")
        print(encrypted_message)

        # Decrypt the message
        decrypted_message = multiplicative_decrypt(encrypted_message, key)
        print("Multiplicative decoded message is::")
        print(decrypted_message)
