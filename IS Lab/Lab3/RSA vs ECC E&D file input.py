import time
from Crypto.PublicKey import RSA, ECC
from Crypto.Cipher import PKCS1_OAEP, AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
import os


# Generate RSA and ECC keys
def generate_keys():
    rsa_key = RSA.generate(2048)
    ecc_key = ECC.generate(curve="P-256")
    return rsa_key, ecc_key


# Encrypt and decrypt file using RSA
def rsa_encrypt_decrypt(file_path, rsa_key):
    start = time.time()
    cipher_rsa = PKCS1_OAEP.new(rsa_key.publickey())
    aes_key = get_random_bytes(16)

    with open(file_path, "rb") as f:
        plaintext = f.read()

    # Encrypt the AES key with RSA
    enc_session_key = cipher_rsa.encrypt(aes_key)

    # Encrypt the file with AES
    cipher_aes = AES.new(aes_key, AES.MODE_EAX)
    ciphertext, tag = cipher_aes.encrypt_and_digest(pad(plaintext, AES.block_size))
    rsa_encryption_time = time.time() - start

    start = time.time()
    # Decrypt the AES key using RSA
    cipher_rsa = PKCS1_OAEP.new(rsa_key)
    aes_key = cipher_rsa.decrypt(enc_session_key)

    # Decrypt the file with AES
    cipher_aes = AES.new(aes_key, AES.MODE_EAX, nonce=cipher_aes.nonce)
    plaintext = unpad(cipher_aes.decrypt_and_verify(ciphertext, tag), AES.block_size)
    rsa_decryption_time = time.time() - start

    return rsa_encryption_time, rsa_decryption_time


# Encrypt and decrypt file using ECC
def ecc_encrypt_decrypt(file_path, ecc_key):
    start = time.time()
    aes_key = get_random_bytes(16)

    with open(file_path, "rb") as f:
        plaintext = f.read()

    # Encrypt the file with AES
    cipher_aes = AES.new(aes_key, AES.MODE_EAX)
    ciphertext, tag = cipher_aes.encrypt_and_digest(pad(plaintext, AES.block_size))
    ecc_encryption_time = time.time() - start

    start = time.time()
    # Decrypt the file with AES
    cipher_aes = AES.new(aes_key, AES.MODE_EAX, nonce=cipher_aes.nonce)
    plaintext = unpad(cipher_aes.decrypt_and_verify(ciphertext, tag), AES.block_size)
    ecc_decryption_time = time.time() - start

    return ecc_encryption_time, ecc_decryption_time


# Measure performance for a specified file path
def measure_performance(file_path):
    print(f"Checking file at: {file_path}")  # Debugging line
    if not os.path.isfile(file_path):
        print(f"File {file_path} does not exist.")
        return

    rsa_key, ecc_key = generate_keys()
    rsa_enc_time, rsa_dec_time = rsa_encrypt_decrypt(file_path, rsa_key)
    ecc_enc_time, ecc_dec_time = ecc_encrypt_decrypt(file_path, ecc_key)

    print(f"File Size: {os.path.getsize(file_path) / (1024 * 1024):.2f} MB")
    print(
        f"RSA Encryption Time: {rsa_enc_time:.6f} s, Decryption Time: {rsa_dec_time:.6f} s"
    )
    print(
        f"ECC Encryption Time: {ecc_enc_time:.6f} s, Decryption Time: {ecc_dec_time:.6f} s\n"
    )


# User input for file path
file_path = input("Enter the path of the file to encrypt and decrypt: ")
measure_performance(file_path)
