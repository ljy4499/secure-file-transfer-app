import socket
import os
from aes_encrypt import encrypt_file
from rsa_encrypt import encrypt_aes_key
from rsa_encrypt import load_public_key

def send_file(server_ip, server_port, file_path, aes_key, public_key_path):
    # Extract the filename from the file path
    filename = os.path.basename(file_path)

    # Encrypt the file using the provided AES key
    encrypted_file = encrypt_file(file_path, aes_key)

    # Load the server's public RSA key from a file
    public_key = load_public_key(public_key_path)

    # Encrypt the AES key using the public RSA key
    encrypted_aes_key = encrypt_aes_key(aes_key, public_key)
    print(f"Client encrypted AES key length: {len(encrypted_aes_key)} bytes")

    # Connect to the server
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client_socket:
        client_socket.connect((server_ip, server_port))

        # Send the filename length and the filename itself
        encoded_filename = filename.encode('utf-8')
        client_socket.sendall(len(encoded_filename).to_bytes(4, 'big'))  # Send filename length
        client_socket.sendall(encoded_filename)  # Send filename

        # Send the encrypted AES key
        client_socket.sendall(len(encrypted_aes_key).to_bytes(4, 'big'))  # Send the length of the AES key
        client_socket.sendall(encrypted_aes_key)  # Send the AES key as bytes

        # Send the encrypted file
        client_socket.sendall(encrypted_file)
        print("Encrypted file sent.")

if __name__ == "__main__":
    SERVER_IP = '127.0.0.1'  # Change to server's IP address if needed
    SERVER_PORT = 12345       # Ensure this matches the server port

    # Get the file path input from the user
    FILE_PATH = input("Enter the path of the file you want to send: ")

    # Get the AES key input from the user
    aes_key_input = input("Enter the AES key (32 bytes for AES-256, in hex format): ")
    aes_key = bytes.fromhex(aes_key_input)  # Convert hex input to bytes

    # Path to the server's public key file
    PUBLIC_KEY_PATH = input("Enter the path of the Receiver's public key: ")  

    # Verify that the file exists
    if not os.path.isfile(FILE_PATH):
        print(f"Error: The file '{FILE_PATH}' does not exist.")
    else:
        send_file(SERVER_IP, SERVER_PORT, FILE_PATH, aes_key, PUBLIC_KEY_PATH)