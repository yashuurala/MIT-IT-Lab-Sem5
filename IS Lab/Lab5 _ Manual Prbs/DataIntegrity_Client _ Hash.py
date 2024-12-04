import socket
import hashlib

def compute_hash(data):
    """Compute the SHA-256 hash of the data."""
    return hashlib.sha256(data).hexdigest()

def main():
    # Client setup
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client_socket.connect(('localhost', 65432))  # Connect to the server on port 65432

    # Take user input for data to send
    data = input("Enter a message to send to the server: ").encode()  # Encode to bytes
    client_socket.sendall(data)

    # Receive the hash from the server
    received_hash = client_socket.recv(64).decode()

    # Compute hash of the sent data for verification
    computed_hash = compute_hash(data)

    # Verify data integrity
    if received_hash == computed_hash:
        print("Data integrity verified. Hashes match!")
    else:
        print("Data integrity check failed. Hashes do not match!")

    client_socket.close()

if __name__ == "__main__":
    main()

