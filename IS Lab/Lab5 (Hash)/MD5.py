import hashlib


def compute_md5_hash(data):
    """Compute the MD5 hash of the data."""
    return hashlib.md5(data.encode()).hexdigest()


def main():
    """Main function to take user input and compute MD5 hashes."""
    print("Enter strings to compute their MD5 hashes. Type 'exit' to stop.")

    while True:
        input_string = input("Enter a string: ")
        if input_string.lower() == 'exit':
            break

        # Compute the MD5 hash
        md5_hash = compute_md5_hash(input_string)
        print(f"MD5 Hash for '{input_string}': {md5_hash}")


if __name__ == "__main__":
    main()
