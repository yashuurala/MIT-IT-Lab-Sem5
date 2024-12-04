# Function to create the Playfair cipher matrix
def create_playfair_matrix(secret_key):
    # Define the alphabet without 'j'
    ch = ['a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w',
          'x', 'y', 'z']
    cols = 5
    rows = 5

    # Create a 5x5 matrix for the key
    matrix = [['' for _ in range(cols)] for _ in range(rows)]

    # Prepare the key by adding the secret key and the rest of the alphabet
    key = ""
    for char in secret_key.lower():
        if char in ch and char not in key:  # Only include unique characters
            key += char
    for char in ch:  # Fill with remaining letters
        if char not in key:
            key += char

    # Fill the matrix
    k = 0
    for i in range(rows):
        for j in range(cols):
            matrix[i][j] = key[k]
            k += 1

    return matrix


# Function to find the position of a character in the Playfair matrix
def find_positions(matrix, char):
    for i in range(5):
        for j in range(5):
            if matrix[i][j] == char:
                return (i, j)
    return None


# Function to encrypt a message using the Playfair cipher
def playfair_encrypt(message, secret_key):
    matrix = create_playfair_matrix(secret_key)

    # Prepare the message
    message = message.lower().replace(" ", "")  # Remove spaces
    to_array = list(message)

    # Replace double letters and ensure even length
    i = 1
    while i < len(to_array):
        if to_array[i] == to_array[i - 1]:
            to_array.insert(i, 'x')  # Insert 'x' as filler
        i += 2  # Move by two to avoid infinite loop
    if len(to_array) % 2 != 0:  # If odd length, append 'x'
        to_array.append('x')

    # Encryption process
    encrypted_text = ""
    for i in range(0, len(to_array), 2):
        row1, col1 = find_positions(matrix, to_array[i])
        row2, col2 = find_positions(matrix, to_array[i + 1])

        if row1 == row2:  # Same row
            encrypted_text += matrix[row1][(col1 + 1) % 5]
            encrypted_text += matrix[row2][(col2 + 1) % 5]
        elif col1 == col2:  # Same column
            encrypted_text += matrix[(row1 + 1) % 5][col1]
            encrypted_text += matrix[(row2 + 1) % 5][col2]
        else:  # Rectangle case
            encrypted_text += matrix[row1][col2]
            encrypted_text += matrix[row2][col1]

    return encrypted_text


# Function to decrypt a message using the Playfair cipher
def playfair_decrypt(encrypted_message, secret_key):
    matrix = create_playfair_matrix(secret_key)

    # Decryption process
    decrypted_text = ""
    for i in range(0, len(encrypted_message), 2):
        row1, col1 = find_positions(matrix, encrypted_message[i])
        row2, col2 = find_positions(matrix, encrypted_message[i + 1])

        if row1 == row2:  # Same row
            decrypted_text += matrix[row1][(col1 - 1) % 5]
            decrypted_text += matrix[row2][(col2 - 1) % 5]
        elif col1 == col2:  # Same column
            decrypted_text += matrix[(row1 - 1) % 5][col1]
            decrypted_text += matrix[(row2 - 1) % 5][col2]
        else:  # Rectangle case
            decrypted_text += matrix[row1][col2]
            decrypted_text += matrix[row2][col1]

    return decrypted_text


# Take user input
message = input("Enter the message to encrypt: ")
secret_key = input("Enter the secret key (e.g., GUIDANCE): ")

# Encrypt the message using Playfair cipher
encrypted_message = playfair_encrypt(message, secret_key)
print("Encrypted text:", encrypted_message)

# Decrypt the message using Playfair cipher
decrypted_message = playfair_decrypt(encrypted_message, secret_key)
print("Decrypted text:", decrypted_message)
