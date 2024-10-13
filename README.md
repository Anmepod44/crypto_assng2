# Cryptography Tasks - README

This repository contains three cryptography tasks that demonstrate different techniques in file encryption, decryption, and message signing using Python and the `pycryptodome` library. Each task showcases an important concept in modern cryptography such as symmetric encryption, public-key cryptography, and digital signatures.

## Table of Contents

1. [Task 1: AES File Encryption and Decryption](#task-1-aes-file-encryption-and-decryption)
2. [Task 2: AES CBC Decryption](#task-2-aes-cbc-decryption)
3. [Task 3: RSA Encryption, Decryption, and Signature](#task-3-rsa-encryption-decryption-and-signature)
4. [Installation and Setup](#installation-and-setup)

---

## Task 1: AES File Encryption and Decryption

In  **Task 1** , the goal is to encrypt and decrypt a file using AES (Advanced Encryption Standard) in CBC (Cipher Block Chaining) mode.

### Features:

* **AES Key Generation** : A random 128-bit AES key is generated.
* **File Encryption** : The contents of `task1.txt` are encrypted using the AES key.
* **File Decryption** : The encrypted data is then decrypted back to its original plaintext.
* **Padding** : PKCS7 padding is used to ensure the plaintext is aligned to the block size of AES.

### Files:

* `task1.txt`: The input file containing the plaintext to be encrypted.
* `encrypted_task1.txt`: The output file containing the AES-encrypted ciphertext.
* `decrypted_task1.txt`: The output file containing the decrypted plaintext.

## Task 2: AES CBC Decryption

**Task 2** focuses on decrypting a ciphertext that was encrypted using AES in CBC mode. In this task, the AES key and the ciphertext are provided in a file (`task2.txt`), and the goal is to decrypt the ciphertext to obtain the original plaintext.

### Features:

* **Hex Input** : Reads the AES key and ciphertext in hexadecimal format from a file.
* **Decryption** : The ciphertext is decrypted using the AES key and the initialization vector (IV) is extracted from the ciphertext.
* **Padding Removal** : PKCS7 padding is used and removed after decryption to retrieve the original plaintext.

### Files:

* `task2.txt`: The input file containing the AES key and the ciphertext (both in hexadecimal format).
* `decrypted_output.txt`: The output file where the decrypted plaintext is saved.

## Task 3: RSA Encryption, Decryption, and Signature

**Task 3** demonstrates the use of RSA (Rivest-Shamir-Adleman) cryptography for public-key encryption, decryption, and digital signatures. This task performs the following operations using RSA:

### Features:

1. **RSA Key Generation** : Generate a pair of RSA public and private keys.
2. **File Encryption** : Encrypt the contents of `task3.txt` using the RSA public key.
3. **File Decryption** : Decrypt the ciphertext using the corresponding RSA private key.
4. **Digital Signature** : Sign the plaintext using the RSA private key to generate a signature.
5. **Signature Verification** : Verify the integrity of the message using the RSA public key and the generated signature.
6. **Performance Measurement** : Measure the encryption and decryption time for 1024-bit and 2048-bit RSA keys.

### Files:

* `task3.txt`: The input file containing the plaintext to be encrypted.
* `ciphertext.txt`: The output file containing the RSA-encrypted ciphertext.
* `decrypted_output.txt`: The output file containing the decrypted plaintext.
* `signature.txt`: The output file containing the digital signature for the plaintext.
