import hashlib

def compute_md5_hash(data):
    """Compute the MD5 hash of the data."""
    return hashlib.md5(data.encode()).hexdigest()

def hash_file(input_file_path, output_file_path):
    """Read lines from the input file, compute MD5 hashes, and write to the output file."""
    try:
        with open(input_file_path, 'r') as input_file, open(output_file_path, 'w') as output_file:
            for line in input_file:
                # Strip whitespace and compute the MD5 hash
                line = line.strip()
                if line:  # Skip empty lines
                    md5_hash = compute_md5_hash(line)
                    # Write the original line and its hash to the output file
                    output_file.write(f"{line} -> {md5_hash}\n")
        print(f"MD5 hashes written to '{output_file_path}' successfully.")

    except FileNotFoundError:
        print(f"Error: The file '{input_file_path}' was not found.")
    except Exception as e:
        print(f"An error occurred: {e}")

def main():
    """Main function to get file paths from the user and perform hashing."""
    input_file_path = input("Enter the path of the input file: ")
    output_file_path = input("Enter the path for the output hash file (e.g., 'hash_file.txt'): ")

    hash_file(input_file_path, output_file_path)

if __name__ == "__main__":
    main()
