import os
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
import binascii

# Base directory for project files (adjusted dynamically for different OS)
base_directory = os.path.dirname(os.path.abspath(__file__))

# Path to the file that contains the AES key and ciphertext
input_file_path = os.path.join(base_directory, 'task2.txt')

# Path where the decrypted plaintext will be saved
output_file_path = os.path.join(base_directory, 'decrypted_output.txt')

# Function to read the AES key and ciphertext from the input file
def read_input_file(file_path):
    with open(file_path, 'r') as file:
        # Read the AES key and ciphertext from the file (key and ciphertext in hex format)
        key_in_hex = file.readline().strip()
        ciphertext_in_hex = file.readline().strip()
    return key_in_hex, ciphertext_in_hex

# Function to decrypt the ciphertext using AES in CBC mode with PKCS7 padding
def decrypt_aes_cbc(key_in_hex, ciphertext_in_hex):
    # Convert the hex-encoded key and ciphertext to raw bytes
    key = binascii.unhexlify(key_in_hex)
    ciphertext = binascii.unhexlify(ciphertext_in_hex)
    
    # Extract the initialization vector (IV) from the first 16 bytes of the ciphertext
    iv = ciphertext[:16]
    
    # The actual encrypted data starts after the IV
    encrypted_data = ciphertext[16:]
    
    # Create an AES cipher object in CBC mode using the key and IV
    cipher = AES.new(key, AES.MODE_CBC, iv)
    
    # Decrypt the encrypted data
    decrypted_data = cipher.decrypt(encrypted_data)
    
    # Remove the PKCS7 padding from the decrypted data
    plaintext = unpad(decrypted_data, AES.block_size)
    
    # Return the plaintext as a UTF-8 encoded string
    return plaintext.decode('utf-8')

# Function to write the decrypted plaintext to a file
def write_output_file(file_path, plaintext):
    with open(file_path, 'w') as file:
        file.write(plaintext)

# Main function to handle the complete decryption process
def main():
    # Read the key and ciphertext from the input file
    key_in_hex, ciphertext_in_hex = read_input_file(input_file_path)
    
    # Decrypt the ciphertext to get the original plaintext
    decrypted_plaintext = decrypt_aes_cbc(key_in_hex, ciphertext_in_hex)
    
    # Print the decrypted plaintext to the console
    print("Decrypted Plaintext: ")
    print(decrypted_plaintext)
    
    # Save the decrypted plaintext to the output file
    write_output_file(output_file_path, decrypted_plaintext)

# Run the main function if the script is executed directly
if __name__ == "__main__":
    main()
