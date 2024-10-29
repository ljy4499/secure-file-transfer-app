# secure-file-transfer-app

## Project Description
This project implements a Secure File Transfer Protocol using symmetric (AES) and asymmetric (RSA) encryption techniques. It aims to ensure the confidentiality, integrity, and authenticity of files transmitted between two systems. 

## Features
- **Symmetric Encryption (AES)**: Encrypts file contents before transmission.
- **Asymmetric Encryption (RSA)**: Securely exchanges the symmetric AES key between the client and server.
- **File Transfer Protocol**: Implements a basic client-server architecture using TCP sockets for transmitting encrypted files.
- **Integrity Check**: Utilizes hashing algorithms (e.g., SHA-256) to verify that files have not been tampered with during transmission.

## Requirements
- Python 3.x
- Required libraries:
  - `cryptography` for AES and RSA implementations
  - `hashlib` for SHA-256 hashing
  - `socket` for client-server communication

## Installation
1. Clone the repository:
   ```bash
   git clone https://github.com/yourusername/secure-file-transfer-protocol.git
   cd secure-file-transfer-protocol

2. Install the required libraries:
    pip install cryptography

testesttest