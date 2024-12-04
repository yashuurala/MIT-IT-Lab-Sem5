import socket
import hashlib


def compute_hash(data):
    """Compute the SHA-256 hash of the data."""
    return hashlib.sha256(data).hexdigest()


def main():
    # Server setup
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind(('localhost', 65432))  # Bind to localhost on port 65432
    server_socket.listen()

    print("Server is listening for incoming connections...")

    while True:
        conn, addr = server_socket.accept()
        print(f"Connected by {addr}")

        data = conn.recv(1024)
        if not data:
            break

        # Compute hash of received data
        data_hash = compute_hash(data)

        # Send data hash back to client
        conn.sendall(data_hash.encode())

        conn.close()


if __name__ == "__main__":
    main()