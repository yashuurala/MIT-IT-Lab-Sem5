def shift_cipher(text, shift):
    result = ""
    for char in text:
        if char.isalpha():
            base = ord('A') if char.isupper() else ord('a')
            shifted_char = chr((ord(char) - base + shift) % 26 + base)
            result += shifted_char
        else:
            result += char
    return result


def find_shift(plaintext, ciphertext):
    if len(plaintext) != len(ciphertext):
        raise ValueError("Plaintext and ciphertext lengths must be equal")

    shift = (ord(ciphertext[0].upper()) - ord(plaintext[0].upper())) % 26
    return shift


# Get user input for the first ciphertext and its corresponding plaintext
ciphertext1 = input("Enter the first ciphertext (e.g., 'CIW'): ")
plaintext1 = input("Enter the corresponding plaintext (e.g., 'yes'): ")

# Get user input for the second ciphertext to decrypt
ciphertext2 = input("Enter the second ciphertext to decrypt (e.g., 'XVIEWYWI'): ")

# Calculate the shift and decrypt the second ciphertext
shift = find_shift(plaintext1, ciphertext1)
plaintext2 = shift_cipher(ciphertext2, -shift)

# Output the results
print("Attack type: Known-plaintext attack")
print("Plaintext for '{}': {}".format(ciphertext2, plaintext2))
