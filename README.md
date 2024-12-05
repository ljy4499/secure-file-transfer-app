# Secure File Transfer App

## Project Description

This project is a **Secure File Transfer Application** that leverages **AES** (Advanced Encryption Standard) and **RSA** (Rivest-Shamir-Adleman) encryption techniques to ensure secure, confidential, and tamper-proof file transfers between two systems. The application features a user-friendly GUI for ease of use, allowing users to send and receive files securely.

---

## Features

- **Symmetric Encryption (AES)**: Encrypts file contents before transmission for confidentiality.
- **Asymmetric Encryption (RSA)**: Securely encrypts the AES key using RSA public keys.
- **File Transfer Protocol**: Uses a client-server model with TCP sockets for reliable file transfer.
- **Integrity Check**: Ensures data integrity using secure hashing algorithms (e.g., SHA-256).
- **Cross-Device Communication**: Works across local and public networks (requires proper configuration).
- **Graphical User Interface (GUI)**: Simplifies the user experience with distinct sections for sending and receiving files.

---

## Requirements

- **Python Version**: Python 3.7 or higher
- **Required Libraries**: 
  - `cryptography`
  - `hashlib`
  - `socket`
  - `tkinter`

---

## Installation and Setup

### 1. Clone the Repository
To download the application, run one of the following commands:

  ```bash
  git clone https://github.com/ljy4499/secure-file-transfer-app.git
  cd ~/secure-file-transfer-app
  ```

### 2. Install Dependencies
  ```bash
  pip install -r requirements.txt
  ```

### 3. Build Application
  ```bash
  pyinstall --onefile SecureFileTransfer_gui.py
  ```