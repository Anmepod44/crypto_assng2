from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
import os

# Paths to the necessary files, dynamically set to work on any OS
base_directory = os.path.dirname(os.path.abspath(__file__))
input_file_path = os.path.join(base_directory, "task1.txt")
encrypted_file_path = os.path.join(base_directory, "encrypted_task1.txt")
decrypted_file_path = os.path.join(base_directory, "decrypted_task1.txt")

# Constants for key and block sizes
AES_KEY_SIZE = 16  # 16 bytes = 128 bits
AES_BLOCK_SIZE = 16  # Block size for AES

# Function to handle encryption of the file
def encrypt_file(file_path, encryption_key):
    # Open and read the file to be encrypted
    with open(file_path, 'rb') as file:
        file_data = file.read()

    # Generate a random initialization vector (IV)
    iv = get_random_bytes(AES_BLOCK_SIZE)
    
    # Set up AES cipher in CBC mode
    cipher = AES.new(encryption_key, AES.MODE_CBC, iv)
    
    # Add padding to the file data to make it a multiple of the block size
    padded_data = pad(file_data, AES_BLOCK_SIZE)
    
    # Encrypt the padded data
    encrypted_data = cipher.encrypt(padded_data)
    
    # Return the IV concatenated with the ciphertext (we need the IV to decrypt later)
    return iv + encrypted_data

# Function to handle decryption of the encrypted data
def decrypt_file(encrypted_data, decryption_key):
    # Extract the initialization vector from the encrypted data
    iv = encrypted_data[:AES_BLOCK_SIZE]
    ciphertext = encrypted_data[AES_BLOCK_SIZE:]

    # Set up the AES cipher for decryption using the same IV
    cipher = AES.new(decryption_key, AES.MODE_CBC, iv)
    
    # Decrypt the ciphertext
    decrypted_padded_data = cipher.decrypt(ciphertext)
    
    # Remove padding to retrieve the original plaintext
    decrypted_data = unpad(decrypted_padded_data, AES_BLOCK_SIZE)
    
    return decrypted_data

def main():
    # Generate a random AES key (16 bytes)
    aes_key = get_random_bytes(AES_KEY_SIZE)
    print(f"Generated AES Key (hex): {aes_key.hex()}")

    # Encrypt the contents of the input file
    encrypted_content = encrypt_file(input_file_path, aes_key)
    print(f"Encrypted content (hex): {encrypted_content.hex()}")

    # Write the encrypted content to a new file
    with open(encrypted_file_path, 'wb') as encrypted_file:
        encrypted_file.write(encrypted_content)

    # Decrypt the encrypted content
    decrypted_content = decrypt_file(encrypted_content, aes_key)
    print(f"Decrypted content (as string): {decrypted_content.decode('utf-8')}")

    # Write the decrypted content to a new file
    with open(decrypted_file_path, 'wb') as decrypted_file:
        decrypted_file.write(decrypted_content)

if __name__ == "__main__":
    main()