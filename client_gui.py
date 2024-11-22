import os
import tkinter as tk
from tkinter import filedialog, messagebox
from client import send_file  # Reuse the existing `send_file` function

def browse_file():
    file_path = filedialog.askopenfilename(initialdir=os.getcwd())
    file_entry.delete(0, tk.END)
    file_entry.insert(0, file_path)

def browse_pubkey():
    pubkey_path = filedialog.askopenfilename(initialdir=os.getcwd())
    pubkey_entry.delete(0, tk.END)
    pubkey_entry.insert(0, pubkey_path)

def send():
    server_ip = ip_entry.get()
    server_port = int(port_entry.get())
    aes_key = aes_key_entry.get()
    file_path = file_entry.get()
    public_key_path = pubkey_entry.get()

    if not (server_ip and server_port and aes_key and file_path and public_key_path):
        messagebox.showerror("Error", "All fields are required!")
        return
    
    try:
        aes_key_bytes = bytes.fromhex(aes_key)
        send_file(server_ip, server_port, file_path, aes_key_bytes, public_key_path)
        messagebox.showinfo("Success", "File sent successfully!")
    except Exception as e:
        messagebox.showerror("Error", str(e))

root = tk.Tk()
root.title("Secure File Sender")

tk.Label(root, text="Server IP:").grid(row=0, column=0, padx=10, pady=5)
ip_entry = tk.Entry(root)
ip_entry.grid(row=0, column=1, padx=10, pady=5)

tk.Label(root, text="Server Port:").grid(row=1, column=0, padx=10, pady=5)
port_entry = tk.Entry(root)
port_entry.insert(0, "12345")
port_entry.grid(row=1, column=1, padx=10, pady=5)

tk.Label(root, text="AES Key (hex):").grid(row=2, column=0, padx=10, pady=5)
aes_key_entry = tk.Entry(root)
aes_key_entry.grid(row=2, column=1, padx=10, pady=5)

tk.Label(root, text="File Path:").grid(row=3, column=0, padx=10, pady=5)
file_entry = tk.Entry(root, width=40)
file_entry.grid(row=3, column=1, padx=10, pady=5)
tk.Button(root, text="Browse", command=browse_file).grid(row=3, column=2, padx=10, pady=5)

tk.Label(root, text="Public Key Path:").grid(row=4, column=0, padx=10, pady=5)
pubkey_entry = tk.Entry(root, width=40)
pubkey_entry.grid(row=4, column=1, padx=10, pady=5)
tk.Button(root, text="Browse", command=browse_pubkey).grid(row=4, column=2, padx=10, pady=5)

tk.Button(root, text="Send File", command=send).grid(row=5, column=1, pady=10)

root.mainloop()