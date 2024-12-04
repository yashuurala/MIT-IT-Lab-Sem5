import numpy as np
from math import gcd


def get_key_matrix(key):
    size = int(len(key) ** 0.5)  # Calculate the size of the matrix (2x2, 3x3, or 4x4)
    key_matrix = np.array(key).reshape(size, size)  # Create a square matrix from the key
    return key_matrix


def encryption(message, key):
    message = message.replace(" ", "").upper()  # Remove spaces and convert to uppercase
    key_size = int(len(key) ** 0.5)

    # Pad the message if its length is not a multiple of key size
    while len(message) % key_size != 0:
        message += "X"  # Padding character

    key_matrix = get_key_matrix(key)
    message_vector = np.array([ord(char) - 65 for char in message]).reshape(-1,
                                                                            key_size)  # Convert characters to numbers

    ciphertext_vector = np.dot(message_vector, key_matrix) % 26  # Multiply the key matrix with the message vector
    ciphertext = ''.join(chr(num + 65) for num in ciphertext_vector.flatten())  # Convert back to characters
    return ciphertext


def decryption(ciphertext, key):
    key_matrix = get_key_matrix(key)

    # Calculate the determinant and check coprimality
    det = int(round(np.linalg.det(key_matrix)))
    if gcd(det, 26) != 1:  # Check if the determinant is coprime with 26
        raise ValueError("The determinant is not coprime with 26. Decryption is not possible with this key matrix.")

    # Calculate the inverse of the key matrix modulo 26
    adjugate = np.round(det * np.linalg.inv(key_matrix)).astype(int) % 26
    inverse_key_matrix = (adjugate * pow(det, -1, 26)) % 26

    key_size = int(len(key) ** 0.5)
    ciphertext_vector = np.array([ord(char) - 65 for char in ciphertext]).reshape(-1,
                                                                                  key_size)  # Convert ciphertext to vector

    decrypted_matrix = np.dot(ciphertext_vector, inverse_key_matrix) % 26  # Multiply inverse key matrix by ciphertext
    decrypted_text = ''.join(chr(int(num) + 65) for num in decrypted_matrix.flatten())  # Convert back to text

    return decrypted_text


# User input
key = list(map(int, input("Enter the key as a list of numbers (2x2, 3x3, or 4x4 matrix): ").split()))
message = input("Enter the message to encrypt: ")

# Encrypt the message
ciphertext = encryption(message, key)
print("Ciphertext:", ciphertext)

# Decrypt the message
decrypted_message = decryption(ciphertext, key)
print("Decrypted message:", decrypted_message)
