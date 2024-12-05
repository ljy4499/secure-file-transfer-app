import socket
import os
import getpass
import hashlib
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

def load_private_key(private_key_path, privkey_pwd):
    # Load the private key using the provided password
    with open(private_key_path, "rb") as key_file:
        private_key = serialization.load_pem_private_key(
            key_file.read(),
            password=privkey_pwd.encode(),
            backend=default_backend()
        )
    return private_key

def decrypt_aes_key(encrypted_aes_key, private_key):
    # Decrypt the AES key using the private RSA key
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

def calculate_file_hash(data):
    """Calculate SHA-256 hash of the given data."""
    sha256 = hashlib.sha256()
    sha256.update(data)
    return sha256.hexdigest()

def save_file(filename, data):
    os.makedirs('./download', exist_ok=True)
    file_path = os.path.join('./download', filename)
    with open(file_path, "wb") as f:
        f.write(data)

def main(port=12345, privkey_entry=None, privkey_pwd=None):  # Default to 12345 if no port is provided
    try:
        # Load the server's private key
        private_key = load_private_key(privkey_entry, privkey_pwd)
    except Exception as e:
        print(f"Error loading private key: {e}")
        return

    # Set up the server socket
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind(('0.0.0.0', port))  # Bind to all available IP addresses on the local machine
    server_socket.listen(1)  # Listen for incoming connections
    print(f"Server listening on port {port}...")

    while True:
        conn, addr = server_socket.accept()
        print(f"Connection from {addr} accepted.")

        try:
            while True:  # Loop to handle multiple file transfers
                # Receive the filename length and filename
                filename_length = int.from_bytes(conn.recv(4), 'big')
                if not filename_length:  # If the filename length is 0, break the loop
                    break
                filename = conn.recv(filename_length).decode('utf-8')
                print(f"Received filename: {filename}")

                # Receive the file hash length and the hash itself
                file_hash_length = int.from_bytes(conn.recv(4), 'big')
                file_hash = conn.recv(file_hash_length).decode('utf-8')
                print(f"Received file hash: {file_hash}")

                # Receive the length of the encrypted AES key and then the encrypted AES key
                encrypted_aes_key_length = int.from_bytes(conn.recv(4), 'big')
                encrypted_aes_key = conn.recv(encrypted_aes_key_length)
                print(f"Server received encrypted AES key length: {len(encrypted_aes_key)} bytes")

                # Decrypt the AES key
                aes_key = decrypt_aes_key(encrypted_aes_key, private_key)
                print(f"Decrypted AES key: {aes_key.hex()[:50]}...")  # Log part of the AES key for debug

                # Receive the length of the encrypted file data
                encrypted_data_length = int.from_bytes(conn.recv(4), 'big')
                encrypted_data = conn.recv(encrypted_data_length)
                print(f"Received encrypted data, length: {len(encrypted_data)} bytes.")

                # Decrypt the file data
                decrypted_data = decrypt_file(encrypted_data, aes_key)
                print(f"Decrypted data preview: {decrypted_data[:50]}")  # First 50 bytes of decrypted data for check

                # Verify the file's integrity
                calculated_hash = calculate_file_hash(decrypted_data)
                print(f"Calculated hash: {calculated_hash}")
                if calculated_hash == file_hash:
                    print("Hash verification successful. File integrity confirmed.")
                else:
                    print("Hash verification failed. File integrity compromised.")

                # Save the decrypted file
                save_file(filename, decrypted_data)
                print(f"File '{filename}' received and decrypted successfully.")

        except Exception as e:
            print(f"Error during transmission or decryption: {e}")
        finally:
            conn.close()

if __name__ == "__main__":
    # Prompt user for private key password and path
    privkey_entry = input("Enter the path to the private key: ")
    privkey_pwd = getpass.getpass("Enter the private key password: ")  # securely get the password
    main(privkey_entry=privkey_entry, privkey_pwd=privkey_pwd)