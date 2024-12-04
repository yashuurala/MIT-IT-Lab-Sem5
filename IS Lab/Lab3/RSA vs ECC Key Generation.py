from cryptography.hazmat.primitives.asymmetric import rsa, ec
from cryptography.hazmat.backends import default_backend
import time

def generate_rsa_key():
    """Generate RSA private and public keys and measure the generation time."""
    start_time = time.time()
    rsa_private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    rsa_public_key = rsa_private_key.public_key()
    rsa_key_gen_time = time.time() - start_time
    return rsa_private_key, rsa_public_key, rsa_key_gen_time

def generate_ecc_key():
    """Generate ECC private and public keys and measure the generation time."""
    start_time = time.time()
    ecc_private_key = ec.generate_private_key(
        ec.SECP256R1(),
        default_backend()
    )
    ecc_public_key = ecc_private_key.public_key()
    ecc_key_gen_time = time.time() - start_time
    return ecc_private_key, ecc_public_key, ecc_key_gen_time

def compare_key_generation_times():
    """Compare the time taken to generate RSA and ECC keys."""
    rsa_private_key, rsa_public_key, rsa_time = generate_rsa_key()
    ecc_private_key, ecc_public_key, ecc_time = generate_ecc_key()

    print(f"RSA Key Generation Time: {rsa_time:.4f} seconds")
    print(f"ECC Key Generation Time: {ecc_time:.4f} seconds")

def main():
    """Main function to execute key generation comparison."""
    compare_key_generation_times()

if __name__ == "__main__":
    main()
