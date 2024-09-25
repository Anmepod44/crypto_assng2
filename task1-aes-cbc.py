from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
import os

# BASE variable to ensure compatibility across different OS
BASE = os.path.dirname(os.path.abspath(__file__))
INPUT_FILE = os.path.join(BASE, "task1.txt")
ENCRYPTED_FILE = os.path.join(BASE, "encrypted_task1.txt")
DECRYPTED_FILE = os.path.join(BASE, "decrypted_task1.txt")

KEY_SIZE = 16
BLOCK_SIZE = 16

def encrypt_file(file_path, key):
    # Read the content of the file
    with open(file_path, 'rb') as file:
        plaintext = file.read()

    iv = get_random_bytes(BLOCK_SIZE)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    padded_plaintext = pad(plaintext, BLOCK_SIZE)
    ciphertext = cipher.encrypt(padded_plaintext)
    return iv + ciphertext

def decrypt_file(ciphertext, key):
    iv = ciphertext[:BLOCK_SIZE]
    ciphertext = ciphertext[BLOCK_SIZE:]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    padded_plaintext = cipher.decrypt(ciphertext)
    plaintext = unpad(padded_plaintext, BLOCK_SIZE)
    return plaintext

def main():
    key = get_random_bytes(KEY_SIZE)
    print(f"Generated AES Key: {key.hex()}")
    encrypted_content = encrypt_file(INPUT_FILE, key)
    print(f"Encrypted content: {encrypted_content.hex()}")
    with open(ENCRYPTED_FILE, 'wb') as enc_file:
        enc_file.write(encrypted_content)
    decrypted_content = decrypt_file(encrypted_content, key)
    print(f"Decrypted content: {decrypted_content.decode('utf-8')}")

    with open(DECRYPTED_FILE, 'wb') as dec_file:
        dec_file.write(decrypted_content)

if __name__ == "__main__":
    main()