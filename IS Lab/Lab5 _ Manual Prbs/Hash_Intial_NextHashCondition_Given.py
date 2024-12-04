def hash_function(s, initial_hash):
    # Initialize hash value with the user-provided initial value
    hash_value = initial_hash

    # Iterate through each character in the string
    for char in s:
        # Update hash value: hash_value * 33 + ord(char)
        hash_value = (hash_value * 33 + ord(char)) & 0xFFFFFFFF  # Mask to keep within 32-bit range

    return hash_value

# Take user input for the initial hash value and the string to hash
try:
    initial_hash = int(input("Enter an initial hash value (integer): "))
    input_string = input("Enter a string to hash: ")
    print(f"Hash value for '{input_string}': {hash_function(input_string, initial_hash)}")
except ValueError:
    print("Please enter a valid integer for the initial hash value.")
