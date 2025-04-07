from tkinter import filedialog, messagebox, Tk, Button
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.fernet import Fernet
import base64

password = "password"

def derive_key(password):
    kdf = Scrypt(salt=b"", length=32, n=2**14, r=8, p=1)
    return base64.urlsafe_b64encode(kdf.derive(password.encode()))

key = derive_key(password)

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

def choose_file_and_encrypt():
    file_path = filedialog.askopenfilename()
    if file_path:
        encrypt(file_path, key)

def choose_file_and_decrypt():
    file_path = filedialog.askopenfilename()
    if file_path:
        decrypt(file_path, key)

root = Tk()
root.title("File Encryptor/Decryptor")

encrypt_button = Button(root, text="Encrypt File", command=choose_file_and_encrypt)
encrypt_button.pack(pady=10)

decrypt_button = Button(root, text="Decrypt File", command=choose_file_and_decrypt)
decrypt_button.pack(pady=10)

root.mainloop()