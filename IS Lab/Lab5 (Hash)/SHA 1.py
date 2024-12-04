import hashlib


def compute_sha1_hash(data):
    """Compute the SHA-1 hash of the data."""
    return hashlib.sha1(data.encode()).hexdigest()


def main():
    """Main function to take user input and compute SHA-1 hashes."""
    print("Enter strings to compute their SHA-1 hashes. Type 'exit' to stop.")

    while True:
        input_string = input("Enter a string: ")
        if input_string.lower() == 'exit':
            break

        # Compute the SHA-1 hash
        sha1_hash = compute_sha1_hash(input_string)
        print(f"SHA-1 Hash for '{input_string}': {sha1_hash}")


if __name__ == "__main__":
    main()
