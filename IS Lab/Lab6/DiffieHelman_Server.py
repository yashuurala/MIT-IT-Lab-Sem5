import socket
import random
from sympy import isprime

# Function to generate a large prime number
def generate_large_prime(bits=256):
    return next(n for n in iter(lambda: random.getrandbits(bits), None) if isprime(n))

# Allow user to input number of bits for prime generation
bits = int(input("Enter the number of bits for prime generation (e.g., 256): "))

# Generate DH parameters
p = generate_large_prime(bits)
g = random.randint(2, p - 2)

# Generate server's private and public keys
b = random.randint(1, p - 2)
B = pow(g, b, p)

# Server setup
server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server_socket.bind(("localhost", 12346))
server_socket.listen(1)
print("Server listening on port 12345...")

client_socket, addr = server_socket.accept()
print(f"Connected to client: {addr}")

# Send p, g, B to client
client_socket.send(f"{p},{g},{B}".encode())

# Receive client's public key A
A = int(client_socket.recv(1024).decode())

# Calculate shared secret
shared_secret_server = pow(A, b, p)
print(f"Server's Shared Secret: {shared_secret_server}")

client_socket.close()
server_socket.close()
