import hashlib


def compute_sha256_hash(data):
    """Compute the SHA-256 hash of the data."""
    return hashlib.sha256(data.encode()).hexdigest()


def main():
    """Main function to take user input and compute SHA-256 hashes."""
    print("Enter strings to compute their SHA-256 hashes. Type 'exit' to stop.")

    while True:
        input_string = input("Enter a string: ")
        if input_string.lower() == 'exit':
            break

        # Compute the SHA-256 hash
        sha256_hash = compute_sha256_hash(input_string)
        print(f"SHA-256 Hash for '{input_string}': {sha256_hash}")


if __name__ == "__main__":
    main()
