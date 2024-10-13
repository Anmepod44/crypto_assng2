import os
import binascii
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad

# Define the base directory for the project
BASE = os.path.dirname(os.path.abspath(__file__))

# Path to the input file containing the AES key and ciphertext
input_file_path = os.path.join(BASE, 'inputs/task2.txt')

# Output file path for storing the decrypted plaintext
output_file_path = os.path.join(BASE, 'outputs/decrypted_output.txt')

# Function to read the key and ciphertext from the input file
def read_input_file(file_path):
    with open(file_path, 'r') as file:
        lines = file.readlines()
        # Extract key and ciphertext, stripping out labels and extra spaces
        key_hex = lines[0].split(":")[1].strip()
        ciphertext_hex = lines[2].strip()  # Ciphertext is on line 3
    return key_hex, ciphertext_hex

# Function to decrypt AES CBC with PKCS7 padding
def decrypt_aes_cbc(key_hex, ciphertext_hex):
    # Convert the hex-encoded key and ciphertext to raw bytes
    key = binascii.unhexlify(key_hex)
    ciphertext = binascii.unhexlify(ciphertext_hex)
    
    # Extract the IV (first 16 bytes of the ciphertext)
    iv = ciphertext[:16]
    
    # The actual ciphertext is the remaining part after the IV
    actual_ciphertext = ciphertext[16:]
    
    # Create the AES cipher object in CBC mode
    cipher = AES.new(key, AES.MODE_CBC, iv)
    
    # Decrypt the ciphertext
    decrypted_data = cipher.decrypt(actual_ciphertext)
    
    # Unpad the decrypted data to remove PKCS7 padding
    plaintext = unpad(decrypted_data, AES.block_size)
    
    return plaintext.decode('utf-8')

# Function to write the decrypted output to a file
def write_output_file(file_path, plaintext):
    with open(file_path, 'w') as file:
        file.write(plaintext)

# Main function to handle the decryption process
def main():
    # Read the key and ciphertext from the input file
    key_hex, ciphertext_hex = read_input_file(input_file_path)
    
    # Decrypt the ciphertext
    decrypted_plaintext = decrypt_aes_cbc(key_hex, ciphertext_hex)
    
    # Display the decrypted output to the user
    print("Decrypted Plaintext: ")
    print(decrypted_plaintext)
    
    # Write the decrypted output to a file
    write_output_file(output_file_path, decrypted_plaintext)

# Execute the main function
if __name__ == "__main__":
    main()