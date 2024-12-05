import os
import customtkinter as ctk
from tkinter import filedialog, messagebox
from threading import Thread
from server import main  # Reuse your existing server logic
from client import send_file  # Reuse the existing `send_file` function

# Function for browsing private key
def browse_privkey():
    privkey_path = filedialog.askopenfilename(initialdir=os.getcwd())
    privkey_entry.delete(0, ctk.END)
    privkey_entry.insert(0, privkey_path)

# Function to browse and add files to a textbox
def browse_file():
    file_paths = filedialog.askopenfilenames(initialdir=os.getcwd())
    if file_paths:
        # Insert each selected file path into the textbox
        for path in file_paths:
            file_listbox.insert(ctk.END, path + "\n")  # Add each file path in a new line

# Function for browsing public key
def browse_pubkey():
    pubkey_path = filedialog.askopenfilename(initialdir=os.getcwd())
    pubkey_entry.delete(0, ctk.END)
    pubkey_entry.insert(0, pubkey_path)

# Function to start the server (Receive section)
def start_server():
    port = int(port_entry_server.get())
    privkey_ent = privkey_entry.get()
    privkey_pass = privkey_pwd.get()

    if not (port and privkey_ent and privkey_pass):
        messagebox.showerror("Error", "All fields are required!")
        return

    thread = Thread(target=main, args=(port, privkey_ent, privkey_pass))
    thread.daemon = True
    thread.start()
    status_label.configure(text=f"Server running on port {port}...")

# Function to send the file (Send section)
def send():
    server_ip = ip_entry.get()
    server_port = int(port_entry.get())
    aes_key = aes_key_entry.get()
    public_key_path = pubkey_entry.get()
    file_paths = file_listbox.get(1.0, ctk.END).strip().split("\n")

    if not (server_ip and server_port and aes_key and file_paths and public_key_path):
        messagebox.showerror("Error", "All fields are required!")
        return

    try:
        aes_key_bytes = bytes.fromhex(aes_key)
        for file_path in file_paths:
            if file_path:
                send_file(server_ip, server_port, file_path, aes_key_bytes, public_key_path)
        messagebox.showinfo("Success", "Files sent successfully!")
    except Exception as e:
        messagebox.showerror("Error", str(e))




# Function to reset the Receive (Server) section
def reset_receive():
    port_entry_server.delete(0, ctk.END)
    port_entry_server.insert(0, "12345")
    privkey_entry.delete(0, ctk.END)
    privkey_pwd.delete(0, ctk.END)
    status_label.configure(text="Server not running.")

# Function to reset the Send (Client) section
def reset_send():
    ip_entry.delete(0, ctk.END)
    port_entry.delete(0, ctk.END)
    port_entry.insert(0, "12345")
    aes_key_entry.delete(0, ctk.END)
    file_listbox.delete(1.0, ctk.END)  # Reset the Textbox
    pubkey_entry.delete(0, ctk.END)
    progress_label.configure(text="Idle...")

# Main GUI setup
ctk.set_appearance_mode("System")  # Use system appearance (light/dark mode)
ctk.set_default_color_theme("blue")  # Set default color theme

root = ctk.CTk()  # Use CTk instead of Tk
root.title("Secure File Transfer")

# Frame for the entire window
main_frame = ctk.CTkFrame(root)
main_frame.pack(fill='both', expand=True, padx=20, pady=20)

# Frame for Receive (Server) section (Top portion)
receive_frame = ctk.CTkFrame(main_frame)
receive_frame.pack(fill='both', padx=10, pady=10)

ctk.CTkLabel(receive_frame, text="Receive File (Server)", font=("Arial", 20, "bold")).grid(row=0, column=1, pady=5)
ctk.CTkLabel(receive_frame, text="Server Port:").grid(row=1, column=0, padx=10, pady=5)
port_entry_server = ctk.CTkEntry(receive_frame)
port_entry_server.insert(0, "12345")
port_entry_server.grid(row=1, column=1, padx=10, pady=5)

ctk.CTkLabel(receive_frame, text="Private Key Path:").grid(row=2, column=0, padx=10, pady=5)
privkey_entry = ctk.CTkEntry(receive_frame, width=300)
privkey_entry.grid(row=2, column=1, padx=10, pady=5)
ctk.CTkButton(receive_frame, text="Browse", command=browse_privkey, width=10).grid(row=2, column=2, padx=10, pady=5)

ctk.CTkLabel(receive_frame, text="Private Key Password:").grid(row=3, column=0, padx=10, pady=5)
privkey_pwd = ctk.CTkEntry(receive_frame, show="*")
privkey_pwd.grid(row=3, column=1, padx=10, pady=5)

start_button_server = ctk.CTkButton(receive_frame, text="Start Server", command=start_server, width=15)
start_button_server.grid(row=4, column=1, pady=10)

status_label = ctk.CTkLabel(receive_frame, text="Server not running.")
status_label.grid(row=5, column=1, pady=5)

# Add Reset button for Receive section
reset_button_receive = ctk.CTkButton(receive_frame, text="Reset", command=reset_receive, width=15)
reset_button_receive.grid(row=4, column=2, padx=0, pady=10)

# Frame for Send (Client) section (Bottom portion)
send_frame = ctk.CTkFrame(main_frame)
send_frame.pack(fill='both', padx=10, pady=10)

ctk.CTkLabel(send_frame, text="Send File (Client)", font=("Arial", 20, "bold")).grid(row=0, column=1, pady=5)
ctk.CTkLabel(send_frame, text="Server IP:").grid(row=1, column=0, padx=10, pady=5)
ip_entry = ctk.CTkEntry(send_frame)
ip_entry.grid(row=1, column=1, padx=10, pady=5)

ctk.CTkLabel(send_frame, text="Server Port:").grid(row=2, column=0, padx=10, pady=5)
port_entry = ctk.CTkEntry(send_frame)
port_entry.insert(0, "12345")
port_entry.grid(row=2, column=1, padx=10, pady=5)

ctk.CTkLabel(send_frame, text="AES Key 32 Bytes (hex):").grid(row=3, column=0, padx=10, pady=5)
aes_key_entry = ctk.CTkEntry(send_frame, width=300)
aes_key_entry.grid(row=3, column=1, padx=10, pady=5)

ctk.CTkLabel(send_frame, text="Public Key Path:").grid(row=5, column=0, padx=10, pady=5)
pubkey_entry = ctk.CTkEntry(send_frame, width=300)
pubkey_entry.grid(row=5, column=1, padx=10, pady=5)
ctk.CTkButton(send_frame, text="Browse", command=browse_pubkey, width=10).grid(row=5, column=2, padx=10, pady=5)

ctk.CTkLabel(send_frame, text="File Path(s):").grid(row=4, column=0, padx=10, pady=5)
file_listbox = ctk.CTkTextbox(send_frame, width=300)  # Use Textbox instead of Listbox
file_listbox.grid(row=4, column=1, padx=10, pady=5)
ctk.CTkButton(send_frame, text="Browse", command=browse_file, width=10).grid(row=4, column=2, padx=10, pady=5)

send_button_file = ctk.CTkButton(send_frame, text="Send File", command=send, width=15)
send_button_file.grid(row=6, column=1, pady=10)

# Add Reset button for Send section
reset_button_send = ctk.CTkButton(send_frame, text="Reset", command=reset_send, width=15)
reset_button_send.grid(row=6, column=2, padx=10, pady=10)

# Add progress label in the Send frame
progress_label = ctk.CTkLabel(send_frame, text="Idle...")
progress_label.grid(row=7, column=1, padx=10, pady=5)

root.mainloop()
