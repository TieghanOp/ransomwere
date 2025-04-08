import ctypes
import sys
from tkinter import messagebox, Tk, Button
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.fernet import Fernet
import base64
import os

def is_admin():
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except:
        return False

if not is_admin():
    ctypes.windll.shell32.ShellExecuteW(
        None, "runas", sys.executable, " ".join(sys.argv), None, 1
    )
    sys.exit()

password = "password"

def derive_key(password):
    kdf = Scrypt(salt=b"", length=32, n=2**14, r=8, p=1)
    return base64.urlsafe_b64encode(kdf.derive(password.encode()))

key = derive_key(password)

def encrypt_directory(directory, key):
    try:
        f = Fernet(key)
        for root, _, files in os.walk(directory):
            for file in files:
                filepath = os.path.join(root, file)
                with open(filepath, "rb") as file_obj:
                    file_data = file_obj.read()
                encrypted_data = f.encrypt(file_data)
                with open(filepath, "wb") as file_obj:
                    file_obj.write(encrypted_data)
        messagebox.showinfo("Success", "All files encrypted successfully!")
    except Exception as e:
        messagebox.showerror("Error", f"Encryption failed: {e}")

def decrypt_directory(directory, key):
    try:
        f = Fernet(key)
        for root, _, files in os.walk(directory):
            for file in files:
                filepath = os.path.join(root, file)
                with open(filepath, "rb") as file_obj:
                    encrypted_data = file_obj.read()
                decrypted_data = f.decrypt(encrypted_data)
                with open(filepath, "wb") as file_obj:
                    file_obj.write(decrypted_data)
        messagebox.showinfo("Success", "All files decrypted successfully!")
    except Exception as e:
        messagebox.showerror("Error", f"Decryption failed: {e}")

def encrypt_desktop():
    desktop_path = os.path.join(os.environ["USERPROFILE"], "Desktop")  # Desktop path
    encrypt_directory(desktop_path, key)

def decrypt_desktop():
    desktop_path = os.path.join(os.environ["USERPROFILE"], "Desktop")  # Desktop path
    decrypt_directory(desktop_path, key)

root = Tk()
root.title("File Encryptor/Decryptor")

# Set window size explicitly to ensure visibility
root.geometry("300x150")  # Adjust the width and height as needed

encrypt_button = Button(root, text="Encrypt All in Desktop", command=encrypt_desktop)
encrypt_button.pack(pady=10)

decrypt_button = Button(root, text="Decrypt All in Desktop", command=decrypt_desktop)
decrypt_button.pack(pady=10)

root.mainloop()