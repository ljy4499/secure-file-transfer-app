import socket
import os
import hashlib
from aes_encrypt import encrypt_file
from rsa_encrypt import encrypt_aes_key, load_public_key

def calculate_file_hash(file_path):
    """Calculate SHA-256 hash of a file."""
    sha256 = hashlib.sha256()
    with open(file_path, 'rb') as f:
        while chunk := f.read(8192):  # Read in chunks to handle large files
            sha256.update(chunk)
    return sha256.hexdigest()

def send_file(server_ip, server_port, file_path, aes_key, public_key_path):
    # Extract the filename from the file path
    filename = os.path.basename(file_path)

    # Calculate the file hash
    file_hash = calculate_file_hash(file_path)
    print(f"Calculated file hash (SHA-256): {file_hash}")

    # Encrypt the file using the provided AES key
    encrypted_file = encrypt_file(file_path, aes_key)
    print(f"File '{filename}' encrypted. Encrypted file length: {len(encrypted_file)} bytes.")
    print(f"First 50 bytes of encrypted file: {encrypted_file[:50]}")

    # Load the server's public RSA key from a file
    public_key = load_public_key(public_key_path)

    # Encrypt the AES key using the public RSA key
    encrypted_aes_key = encrypt_aes_key(aes_key, public_key)
    print(f"Encrypted AES key length: {len(encrypted_aes_key)} bytes.")
    print(f"First 50 bytes of encrypted AES key: {encrypted_aes_key[:50]}")

    # Connect to the server
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client_socket:
        try:
            client_socket.connect((server_ip, server_port))
            print(f"Connected to server at {server_ip}:{server_port}")
        except Exception as e:
            print(f"Error connecting to server: {e}")
            return

        # Send the filename length and the filename itself
        encoded_filename = filename.encode('utf-8')
        client_socket.sendall(len(encoded_filename).to_bytes(4, 'big'))  # Send filename length
        client_socket.sendall(encoded_filename)  # Send filename
        print(f"Sending filename: {filename}, length: {len(encoded_filename)} bytes.")

        # Send the file hash
        encoded_file_hash = file_hash.encode('utf-8')
        client_socket.sendall(len(encoded_file_hash).to_bytes(4, 'big'))  # Send hash length
        client_socket.sendall(encoded_file_hash)  # Send file hash
        print(f"Sending file hash: {file_hash}, length: {len(encoded_file_hash)} bytes.")

        # Send the encrypted AES key
        client_socket.sendall(len(encrypted_aes_key).to_bytes(4, 'big'))  # Send the length of the AES key
        client_socket.sendall(encrypted_aes_key)  # Send the AES key as bytes
        print(f"Sending encrypted AES key, length: {len(encrypted_aes_key)} bytes.")

        # Send the encrypted file
        client_socket.sendall(len(encrypted_file).to_bytes(4, 'big'))  # Send encrypted file length
        client_socket.sendall(encrypted_file)  # Send the encrypted file
        print(f"Sending encrypted file, length: {len(encrypted_file)} bytes.")
        print("File transmission completed.")

# Main function to select and send multiple files
if __name__ == "__main__":
    SERVER_IP = input("Enter the server IP address (default: 127.0.0.1): ").strip() or '127.0.0.1'
    SERVER_PORT = input("Enter the server port (default: 12345): ").strip()
    SERVER_PORT = int(SERVER_PORT) if SERVER_PORT else 12345

    # Allow the user to select multiple files
    from tkinter import filedialog
    FILE_PATHS = filedialog.askopenfilenames(title="Select Files to Send")  # Select multiple files

    if not FILE_PATHS:
        print("No files selected.")
        exit(1)

    # Get the AES key input from the user
    aes_key_input = input("Enter the AES key (32 bytes for AES-256, in hex format): ")
    try:
        aes_key = bytes.fromhex(aes_key_input)  # Convert hex input to bytes
        if len(aes_key) != 32:
            raise ValueError("AES key must be 32 bytes for AES-256.")
    except ValueError as e:
        print(f"Error: {e}")
        exit(1)
    print(f"AES key (32 bytes): {aes_key.hex()[:50]}...")

    # Path to the server's public key file
    PUBLIC_KEY_PATH = input("Enter the path of the Receiver's public key: ")

    if not os.path.isfile(PUBLIC_KEY_PATH):
        print(f"Error: The public key file '{PUBLIC_KEY_PATH}' does not exist.")
        exit(1)

    # Loop over the selected files and send each one
    for file_path in FILE_PATHS:
        if not os.path.isfile(file_path):
            print(f"Error: The file '{file_path}' does not exist.")
            continue
        send_file(SERVER_IP, SERVER_PORT, file_path, aes_key, PUBLIC_KEY_PATH)
