import os
import time
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256
from Crypto.Random import get_random_bytes

# Set up base directory to store keys and files
base_directory = os.path.dirname(os.path.abspath(__file__))

# File paths
plaintext_file_path = os.path.join(base_directory, 'task3.txt')
ciphertext_file_path = os.path.join(base_directory, 'ciphertext.txt')
decrypted_file_path = os.path.join(base_directory, 'decrypted_output.txt')
signature_file_path = os.path.join(base_directory, 'signature.txt')

# Function to generate RSA keys and save them to files
def generate_rsa_keys(key_size, key_name):
    # Generate the private and public keys
    private_key = RSA.generate(key_size)
    public_key = private_key.publickey()

    # Save the private key to a file
    with open(os.path.join(base_directory, f'{key_name}_private.pem'), 'wb') as priv_file:
        priv_file.write(private_key.export_key())

    # Save the public key to a file
    with open(os.path.join(base_directory, f'{key_name}_public.pem'), 'wb') as pub_file:
        pub_file.write(public_key.export_key())
    
    print(f"{key_size}-bit RSA keys generated and saved as {key_name}_private.pem and {key_name}_public.pem.")

# Function to load RSA keys from files
def load_rsa_keys(key_name):
    with open(os.path.join(base_directory, f'{key_name}_private.pem'), 'rb') as priv_file:
        private_key = RSA.import_key(priv_file.read())

    with open(os.path.join(base_directory, f'{key_name}_public.pem'), 'rb') as pub_file:
        public_key = RSA.import_key(pub_file.read())
    
    return private_key, public_key

# Function to encrypt a plaintext using the RSA public key
def encrypt_rsa(public_key, plaintext):
    cipher = PKCS1_OAEP.new(public_key)
    ciphertext = cipher.encrypt(plaintext)
    
    # Save the ciphertext to a file
    with open(ciphertext_file_path, 'wb') as file:
        file.write(ciphertext)
    
    print("Encryption complete. Ciphertext saved to file.")

# Function to decrypt a ciphertext using the RSA private key
def decrypt_rsa(private_key):
    # Load the ciphertext from file
    with open(ciphertext_file_path, 'rb') as file:
        ciphertext = file.read()
    
    cipher = PKCS1_OAEP.new(private_key)
    decrypted_data = cipher.decrypt(ciphertext)

    # Save the decrypted plaintext to a file
    with open(decrypted_file_path, 'wb') as file:
        file.write(decrypted_data)
    
    print("Decryption complete. Plaintext saved to file.")

# Function to sign a message using the RSA private key
def sign_message(private_key, message):
    hash_of_message = SHA256.new(message)
    signature = pkcs1_15.new(private_key).sign(hash_of_message)

    # Save the signature to a file
    with open(signature_file_path, 'wb') as file:
        file.write(signature)
    
    print("Message signed. Signature saved to file.")
    return signature

# Function to verify a signature using the RSA public key
def verify_signature(public_key, message, signature):
    hash_of_message = SHA256.new(message)
    try:
        pkcs1_15.new(public_key).verify(hash_of_message, signature)
        print("Signature is valid.")
    except (ValueError, TypeError):
        print("Signature is invalid.")

# Function to measure encryption and decryption time for RSA keys
def measure_performance(key_size):
    # Generate RSA keys
    generate_rsa_keys(key_size, f'rsa_{key_size}')
    private_key, public_key = load_rsa_keys(f'rsa_{key_size}')

    # Load plaintext from file
    with open(plaintext_file_path, 'rb') as file:
        plaintext = file.read()

    # Measure the time it takes to encrypt the plaintext
    start_time = time.time()
    encrypt_rsa(public_key, plaintext)
    encryption_time = time.time() - start_time

    # Measure the time it takes to decrypt the ciphertext
    start_time = time.time()
    decrypt_rsa(private_key)
    decryption_time = time.time() - start_time

    print(f"Encryption time with {key_size}-bit RSA key: {encryption_time:.6f} seconds")
    print(f"Decryption time with {key_size}-bit RSA key: {decryption_time:.6f} seconds")

# Main function that runs the tasks
def main():
    # Step 1: Generate 1024-bit RSA keys
    generate_rsa_keys(1024, 'rsa_1024')
    
    # Step 2: Load the 1024-bit RSA keys
    private_key_1024, public_key_1024 = load_rsa_keys('rsa_1024')

    # Step 3: Encrypt the plaintext file with the public key
    with open(plaintext_file_path, 'rb') as file:
        plaintext = file.read()
    
    encrypt_rsa(public_key_1024, plaintext)

    # Step 4: Decrypt the ciphertext with the private key
    decrypt_rsa(private_key_1024)

    # Step 5: Sign the plaintext and verify the signature
    signature = sign_message(private_key_1024, plaintext)
    verify_signature(public_key_1024, plaintext, signature)

    # Step 6: Measure encryption and decryption times for 1024-bit and 2048-bit keys
    print("\nPerformance measurement for 1024-bit RSA keys:")
    measure_performance(1024)
    
    print("\nPerformance measurement for 2048-bit RSA keys:")
    measure_performance(2048)

# Run the main function when this script is executed
if __name__ == "__main__":
    main()
