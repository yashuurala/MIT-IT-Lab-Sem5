import socket
import random

# Allow user to input private key for user A
a = int(input("Enter private key for user A (a): "))

# Client setup
client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
client_socket.connect(("localhost", 12346))

# Receive p, g, B from server
p, g, B = map(int, client_socket.recv(1024).decode().split(","))

# Generate client's public key
A = pow(g, a, p)

# Send public key A to server
client_socket.send(str(A).encode())

# Calculate shared secret
shared_secret_client = pow(B, a, p)
print(f"Client's Shared Secret: {shared_secret_client}")

client_socket.close()
