from tkinter import messagebox, Tk, Button
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.fernet import Fernet
import base64
import os
import ctypes
import sys


def is_admin():
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except:
        return False

def run_as_admin():
    script = sys.argv[0]
    params = " ".join([f'"{arg}"' for arg in sys.argv[1:]])
    try:
        ctypes.windll.shell32.ShellExecuteW(
            None, "runas", sys.executable, f'"{script}" {params}', None, 1
        )
    except Exception as e:
        print("Failed to elevate:", e)

if __name__ == "__main__":
    if not is_admin():
        print("Not running as admin. Elevating...")
        run_as_admin()
        sys.exit()
    
    print("Running as administrator.")
    
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

def encrypt_localuser():
    localuser_path = os.path.expanduser("~")
    encrypt_directory(localuser_path, key)

def decrypt_localuser():
    localuser_path = os.path.expanduser("~")
    decrypt_directory(localuser_path, key)

root = Tk()
root.title("File Encryptor/Decryptor")

encrypt_button = Button(root, text="Encrypt All in %USERPROFILE%", command=encrypt_localuser)
encrypt_button.pack(pady=10)

decrypt_button = Button(root, text="Decrypt All in %USERPROFILE%", command=decrypt_localuser)
decrypt_button.pack(pady=10)

root.mainloop()
