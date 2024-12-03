import os
import tkinter as tk
from tkinter import filedialog, messagebox
from threading import Thread
from server import main  # Reuse your existing server logic

def browse_privkey():
    privkey_path = filedialog.askopenfilename(initialdir=os.getcwd())
    privkey_entry.delete(0, tk.END)
    privkey_entry.insert(0, privkey_path)

def start_server():
    port = int(port_entry.get())
    privkey_ent = privkey_entry .get()
    privkey_pass = privkey_pwd.get()

    if not (port and privkey_ent and privkey_pass):
        messagebox.showerror("Error", "All fields are required!")
        return

    thread = Thread(target=main, args=(port, privkey_ent, privkey_pass))
    thread.daemon = True
    thread.start()
    status_label.config(text=f"Server running on port {port}...")

root = tk.Tk()
root.title("Secure File Receiver")

tk.Label(root, text="Server Port:").grid(row=0, column=0, padx=10, pady=5)
port_entry = tk.Entry(root)
port_entry.insert(0, "12345")
port_entry.grid(row=0, column=1, padx=10, pady=5)

tk.Label(root, text="Private Key Path:").grid(row=1, column=0, padx=10, pady=5)
privkey_entry = tk.Entry(root, width=40)
privkey_entry.grid(row=1, column=1, padx=10, pady=5)
tk.Button(root, text="Browse", command=browse_privkey).grid(row=1, column=2, padx=10, pady=5)

tk.Label(root, text="Private Key Password:").grid(row=2, column=0, padx=10, pady=5)
privkey_pwd = tk.Entry(root, show="*")
privkey_pwd.grid(row=2, column=1, padx=10, pady=5)

start_button = tk.Button(root, text="Start Server", command=start_server)
start_button.grid(row=3, column=0, columnspan=2, pady=10)

status_label = tk.Label(root, text="Server not running.")
status_label.grid(row=4, column=0, columnspan=2, pady=5)

root.mainloop()