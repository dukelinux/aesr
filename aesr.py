#!/usr/bin/python3

import argparse
import sys
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from base64 import urlsafe_b64encode, urlsafe_b64decode
from os import urandom

# Define a default key seed for key derivation
key_seed = "your_constant_password"

def derive_key(seed, salt):
    # Derives a 32-byte key from the given seed and salt using PBKDF2.
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    return kdf.derive(seed.encode())

def encrypt(data, seed):
    # Encrypts the given data using AES in CTR mode with a key derived from the seed.
    
    # Generate a random salt and derive the key from the seed and salt
    salt = urandom(16)
    key = derive_key(seed, salt)
    
    # Generate a random nonce for CTR mode
    nonce = urandom(16)
    
    # Set up AES encryption in CTR mode
    cipher = Cipher(algorithms.AES(key), modes.CTR(nonce), backend=default_backend())
    encryptor = cipher.encryptor()
    
    # Encrypt the data
    encrypted_data = encryptor.update(data) + encryptor.finalize()
    
    # Return the concatenated salt, nonce, and encrypted data, encoded in URL-safe Base64 for strings
    return salt + nonce + encrypted_data

def decrypt(data, seed):
    # Decrypts the given data using AES in CTR mode with a key derived from the seed.
    
    # Extract the salt and nonce from the encrypted data
    salt = data[:16]
    nonce = data[16:32]
    
    # Derive the key from the seed and extracted salt
    key = derive_key(seed, salt)
    
    # Set up AES decryption in CTR mode
    cipher = Cipher(algorithms.AES(key), modes.CTR(nonce), backend=default_backend())
    decryptor = cipher.decryptor()
    
    # Decrypt the data
    decrypted_data = decryptor.update(data[32:]) + decryptor.finalize()
    
    return decrypted_data

def process_file(input_file, seed, decrypt_mode=False, in_place=False, use_base64=False):
    # Processes the input file, either encrypting or decrypting it.
    
    # Read the file content
    with open(input_file, 'rb') as f:
        data = f.read()

    # Encrypt or decrypt the data based on the mode
    if decrypt_mode:
        if use_base64:
            data = urlsafe_b64decode(data)
        processed_data = decrypt(data, seed)
    else:
        processed_data = encrypt(data, seed)
        if use_base64:
            processed_data = urlsafe_b64encode(processed_data)

    # Write the processed data back to the file if in-place, otherwise output to stdout
    if in_place:
        with open(input_file, 'wb') as f:
            f.write(processed_data)
        print(f"File {input_file} has been {'decrypted' if decrypt_mode else 'encrypted'} in place.")
    else:
        sys.stdout.buffer.write(processed_data)

def main():
    # Create the argument parser
    parser = argparse.ArgumentParser(description="AES CTR encryption/decryption tool.")
    
    # Add argument to specify a file to process
    parser.add_argument(
        "-f", "--file", 
        help="Specify the file to process. If provided, the file will be encrypted or decrypted based on other options."
    )
    
    # Add argument to enable decryption mode
    parser.add_argument(
        "-d", "--decrypt", 
        action="store_true", 
        help="Decrypt the input instead of encrypting. This option works with both files and strings."
    )
    
    # Add argument to modify the file in place
    parser.add_argument(
        "-i", "--in-place", 
        action="store_true", 
        help="Modify the file in place, overwriting the original file with the encrypted or decrypted content."
    )

    # Add argument to use Base64 encoding for files
    parser.add_argument(
        "--base64",
        action="store_true",
        help="Use Base64 encoding for file input/output."
    )
    
    # Add argument to specify a custom seed for key derivation
    parser.add_argument(
        "-s", "--seed", 
        help="Specify a custom seed to override the default key seed used for encryption and decryption."
    )
    
    # Add positional argument for input text to encrypt or decrypt
    parser.add_argument(
        "text", 
        nargs='?', 
        help="Text to encrypt or decrypt, depending on flags. If provided, this text will be processed instead of a file."
    )

    # Parse the command-line arguments
    args = parser.parse_args()

    # Use the provided seed or fall back to the default key seed
    seed = args.seed if args.seed else key_seed

    # Determine whether to process a file or a string
    if args.file:
        # Process the file with the given options
        process_file(args.file, seed, decrypt_mode=args.decrypt, in_place=args.in_place, use_base64=args.base64)
    elif args.text:
        # Process the string based on the provided options
        data = args.text.encode()
        if args.decrypt:
            # Decode and decrypt the text
            decoded_data = urlsafe_b64decode(data)
            decrypted_data = decrypt(decoded_data, seed)
            print(decrypted_data.decode())
        else:
            # Encrypt and encode the text
            encrypted_data = encrypt(data, seed)
            encoded_data = urlsafe_b64encode(encrypted_data)
            print(encoded_data.decode())
    else:
        # If no input is provided, display the help message
        parser.print_help()

if __name__ == "__main__":
    main()
