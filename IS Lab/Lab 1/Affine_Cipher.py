# List of valid multiplicative keys for the Affine cipher
valid_multiplicative_keys = [1, 3, 5, 7, 9, 11, 15, 17, 19, 21, 23, 25]


# Function to find the multiplicative inverse of 'a' under modulo 'm'
def mod_inverse(a, m):
    for i in range(1, m):
        if (a * i) % m == 1:
            return i
    return None


# Function to encrypt the message using Affine Cipher
def affine_encrypt(message, key1, key2):
    result = ""
    for char in message:
        if 'a' <= char <= 'z':  # Ensure it's a lowercase alphabet
            new_char = chr(((((ord(char) - 97) * key2) + key1) % 26) + 97)
            result += new_char
    return result


# Function to decrypt the message using Affine Cipher
def affine_decrypt(ciphertext, key1, key2):
    # Finding the multiplicative inverse of key2
    inverse_key2 = mod_inverse(key2, 26)
    if inverse_key2 is None:
        raise ValueError(f"No multiplicative inverse exists for {key2} mod 26.")

    result = ""
    for char in ciphertext:
        if 'a' <= char <= 'z':  # Ensure it's a lowercase alphabet
            new_char = chr(((((ord(char) - 97 - key1) * inverse_key2) % 26) + 97))
            result += new_char
    return result


# Main program
if __name__ == "__main__":
    # Taking user input
    key1 = int(input("Enter additive key (key1): "))
    key2 = int(input("Enter multiplicative key (key2): "))

    if key2 not in valid_multiplicative_keys:
        print("Invalid multiplicative key. Choose a valid key from:", valid_multiplicative_keys)
    else:
        message = input("Enter the message to encrypt: ").replace(" ", "").lower()

        # Encrypt the message
        encrypted_message = affine_encrypt(message, key1, key2)
        print("Affine cipher encoded message is:")
        print(encrypted_message)

        # Decrypt the message
        decrypted_message = affine_decrypt(encrypted_message, key1, key2)
        print("Affine cipher decoded message is:")
        print(decrypted_message)
