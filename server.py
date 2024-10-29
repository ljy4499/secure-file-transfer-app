import socket
import os
import getpass
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

def load_private_key(private_key_path):
    # Prompt the user for the password
    password = getpass.getpass("Enter the private key password: ").encode()
    
    # Load the private key using the provided password
    with open(private_key_path, "rb") as key_file:
        private_key = serialization.load_pem_private_key(
            key_file.read(),
            password=password,
            backend=default_backend()
        )
    return private_key

def decrypt_aes_key(encrypted_aes_key, private_key):
    aes_key = private_key.decrypt(
        encrypted_aes_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return aes_key

def decrypt_file(encrypted_data, aes_key):
    iv = encrypted_data[:16]  # The first 16 bytes are the IV
    cipher = Cipher(algorithms.AES(aes_key), modes.CFB(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    decrypted_data = decryptor.update(encrypted_data[16:]) + decryptor.finalize()
    return decrypted_data

def save_file(filename, data):
    with open(filename, "wb") as f:
        f.write(data)

def main():
    # Load the server's private key
    PRIVATE_KEY_PATH = input("Enter the path of the Receiver's private key: ")  
    private_key = load_private_key(PRIVATE_KEY_PATH)

    # Set up the server
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind(('0.0.0.0', 12345))  # Change port as needed
    server_socket.listen(1)
    print("Server listening on port 12345...")

    while True:
        conn, addr = server_socket.accept()
        print(f"Connection from {addr} accepted.")

        # Receive the filename length and filename
        filename_length = int.from_bytes(conn.recv(4), 'big')
        filename = conn.recv(filename_length).decode('utf-8')
        
        # Receive the length of the encrypted AES key and then the encrypted AES key
        encrypted_aes_key_length = int.from_bytes(conn.recv(4), 'big')
        encrypted_aes_key = conn.recv(encrypted_aes_key_length)
        
        print(f"Server received encrypted AES key length: {len(encrypted_aes_key)} bytes")

        # Decrypt the AES key
        aes_key = decrypt_aes_key(encrypted_aes_key, private_key)

        # Receive the encrypted file data length and encrypted file data
        encrypted_data_length = int.from_bytes(conn.recv(4), 'big')
        encrypted_data = conn.recv(encrypted_data_length)

        # Decrypt the file data
        decrypted_data = decrypt_file(encrypted_data, aes_key)

        # Save the decrypted file
        save_file(filename, decrypted_data)
        print(f"File '{filename}' received and hhhhhhjhuuuuuuuuudecrypted successfully.")

        conn.close()

if __name__ == "__main__":
    main()
