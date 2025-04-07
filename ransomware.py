import tkinter as tk
from tkinter import filedialog, messagebox
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.fernet import Fernet
import base64

def derive_key(password):
    kdf = Scrypt(salt=b"", length=32, n=2**14, r=8, p=1)
    return base64.urlsafe_b64encode(kdf.derive(password.encode()))

def encrypt(filename, key):
    try:
        f = Fernet(key)
        with open(filename, "rb") as file:
            file_data = file.read()
        encrypted_data = f.encrypt(file_data)
        with open(filename, "wb") as file:
            file.write(encrypted_data)
        messagebox.showinfo("Success", "File encrypted successfully!")
    except Exception as e:
        messagebox.showerror("Error", f"Encryption failed: {e}")

def decrypt(filename, key):
    try:
        f = Fernet(key)
        with open(filename, "rb") as file:
            encrypted_data = file.read()
        decrypted_data = f.decrypt(encrypted_data)
        with open(filename, "wb") as file:
            file.write(decrypted_data)
        messagebox.showinfo("Success", "File decrypted successfully!")
    except Exception as e:
        messagebox.showerror("Error", f"Decryption failed: {e}")

def choose_file():
    file_path = filedialog.askopenfilename()
    return file_path

def handle_encrypt():
    filename = choose_file()
    if filename:
        password = password_entry.get()
        key = derive_key(password)
        encrypt(filename, key)

def handle_decrypt():
    filename = choose_file()
    if filename:
        password = password_entry.get()
        key = derive_key(password)
        decrypt(filename, key)

root = tk.Tk()
root.title("File Encryptor/Decryptor")

tk.Label(root, text="Password:").grid(row=0, column=0, padx=10, pady=10)
password_entry = tk.Entry(root, show="*", width=30)
password_entry.grid(row=0, column=1, padx=10, pady=10)

encrypt_button = tk.Button(root, text="Encrypt File", command=handle_encrypt)
encrypt_button.grid(row=1, column=0, padx=10, pady=10)

decrypt_button = tk.Button(root, text="Decrypt File", command=handle_decrypt)
decrypt_button.grid(row=1, column=1, padx=10, pady=10)

root.mainloop()