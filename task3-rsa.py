import os
import time
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256
from Crypto.Random import get_random_bytes

# Define the base directory for storing keys and files
BASE = os.path.dirname(os.path.abspath(__file__))

# File paths
plaintext_file = os.path.join(BASE, 'task3.txt')
ciphertext_file = os.path.join(BASE, 'ciphertext.txt')
decrypted_file = os.path.join(BASE, 'decrypted_output.txt')
signature_file = os.path.join(BASE, 'signature.txt')

# Function to generate RSA keys
def generate_rsa_keys(key_size, key_name):
    private_key = RSA.generate(key_size)
    public_key = private_key.publickey()

    # Save the private key
    with open(os.path.join(BASE, f'{key_name}_private.pem'), 'wb') as priv_file:
        priv_file.write(private_key.export_key())

    # Save the public key
    with open(os.path.join(BASE, f'{key_name}_public.pem'), 'wb') as pub_file:
        pub_file.write(public_key.export_key())
    
    print(f"{key_size}-bit RSA keys generated and stored.")

# Function to load RSA keys from file
def load_rsa_keys(key_name):
    with open(os.path.join(BASE, f'{key_name}_private.pem'), 'rb') as priv_file:
        private_key = RSA.import_key(priv_file.read())

    with open(os.path.join(BASE, f'{key_name}_public.pem'), 'rb') as pub_file:
        public_key = RSA.import_key(pub_file.read())
    
    return private_key, public_key

# Function to encrypt a plaintext using RSA public key
def encrypt_rsa(public_key, plaintext):
    cipher = PKCS1_OAEP.new(public_key)
    ciphertext = cipher.encrypt(plaintext)
    
    # Save the ciphertext
    with open(ciphertext_file, 'wb') as file:
        file.write(ciphertext)
    
    print("Encryption complete. Ciphertext saved.")

# Function to decrypt a ciphertext using RSA private key
def decrypt_rsa(private_key):
    # Load the ciphertext from file
    with open(ciphertext_file, 'rb') as file:
        ciphertext = file.read()
    
    cipher = PKCS1_OAEP.new(private_key)
    decrypted_data = cipher.decrypt(ciphertext)

    # Save the decrypted output
    with open(decrypted_file, 'wb') as file:
        file.write(decrypted_data)
    
    print("Decryption complete. Plaintext saved.")

# Function to sign a message using RSA private key
def sign_message(private_key, message):
    h = SHA256.new(message)
    signature = pkcs1_15.new(private_key).sign(h)

    # Save the signature to a file
    with open(signature_file, 'wb') as file:
        file.write(signature)
    
    print("Message signed. Signature saved.")
    return signature

# Function to verify a signature using RSA public key
def verify_signature(public_key, message, signature):
    h = SHA256.new(message)
    try:
        pkcs1_15.new(public_key).verify(h, signature)
        print("Signature is valid.")
    except (ValueError, TypeError):
        print("Signature is invalid.")

# Function to measure encryption and decryption time
def measure_performance(key_size):
    # Generate keys for the given key size
    generate_rsa_keys(key_size, f'rsa_{key_size}')
    private_key, public_key = load_rsa_keys(f'rsa_{key_size}')

    # Load plaintext
    with open(plaintext_file, 'rb') as file:
        plaintext = file.read()

    # Measure encryption time
    start_time = time.time()
    encrypt_rsa(public_key, plaintext)
    encryption_time = time.time() - start_time

    # Measure decryption time
    start_time = time.time()
    decrypt_rsa(private_key)
    decryption_time = time.time() - start_time

    print(f"Encryption time for {key_size}-bit key: {encryption_time} seconds")
    print(f"Decryption time for {key_size}-bit key: {decryption_time} seconds")

# Main function to run the entire task
def main():
    # Step 1: Generate 1024-bit RSA keys
    generate_rsa_keys(1024, 'rsa_1024')
    
    # Step 2: Load the 1024-bit keys
    private_key_1024, public_key_1024 = load_rsa_keys('rsa_1024')

    # Step 3: Encrypt the plaintext using the public key
    with open(plaintext_file, 'rb') as file:
        plaintext = file.read()
    
    encrypt_rsa(public_key_1024, plaintext)

    # Step 4: Decrypt the ciphertext using the private key
    decrypt_rsa(private_key_1024)

    # Step 5: Sign the plaintext and verify the signature
    signature = sign_message(private_key_1024, plaintext)
    verify_signature(public_key_1024, plaintext, signature)

    # Step 6: Measure encryption and decryption time for 1024-bit and 2048-bit keys
    print("\nPerformance measurement for 1024-bit RSA keys:")
    measure_performance(1024)
    
    print("\nPerformance measurement for 2048-bit RSA keys:")
    measure_performance(2048)

if __name__ == "__main__":
    main()