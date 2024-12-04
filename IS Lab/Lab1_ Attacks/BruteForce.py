from string import ascii_uppercase


def mod_inverse(a, m):
    """Find the modular inverse of a under modulo m."""
    for x in range(1, m):
        if (a * x) % m == 1:
            return x
    return None


def affine_decrypt(ciphertext, a, b):
    """Decrypt the ciphertext using the affine cipher."""
    m = 26
    a_inv = mod_inverse(a, m)
    if a_inv is None:
        return None

    plaintext = ""
    for char in ciphertext:
        if char in ascii_uppercase:
            y = ord(char) - ord('A')  # Convert char to 0-25
            x = (a_inv * (y - b)) % m  # Apply the affine decryption formula
            plaintext += chr(x + ord('A'))  # Convert back to character
        else:
            plaintext += char  # Preserve non-alphabetic characters
    return plaintext


def brute_force_affine(ciphertext, known_plaintext, known_ciphertext):
    """Brute-force attack to find keys a and b for the affine cipher."""
    valid_a_values = [1, 3, 5, 7, 9, 11, 15, 17, 19, 21, 23, 25]

    for a in valid_a_values:
        for b in range(26):
            decrypted_text = affine_decrypt(known_ciphertext, a, b)
            if decrypted_text == known_plaintext:
                print(f"Possible key found: a = {a}, b = {b}")
                print("Decrypted message:")
                print(affine_decrypt(ciphertext, a, b))
                return  # Exit after finding the first valid key


# Get user input for the known plaintext and its corresponding ciphertext
known_plaintext = input("Enter the known plaintext (e.g., 'AB'): ").strip().upper()
known_ciphertext = input("Enter the corresponding ciphertext (e.g., 'GL'): ").strip().upper()

# Get user input for the ciphertext to decrypt
ciphertext = input("Enter the ciphertext to decrypt: ").strip().upper()
# Perform brute-force attack
brute_force_affine(ciphertext, known_plaintext, known_ciphertext)
