from tkinter import Tk, Button, Label, filedialog, simpledialog, messagebox



from Crypto.Cipher import AES
from Crypto.Hash import SHA256
from Crypto.Random import get_random_bytes
from Crypto.Protocol.KDF import PBKDF2
import os
# Constants
KEY_SIZE = 32  # 256 bits
SALT_SIZE = 16
IV_SIZE = 16
CHUNK_SIZE = 64 * 1024

# Derive key
def derive_key(password, salt):
    return PBKDF2(password, salt, dkLen=KEY_SIZE)

# Encrypt a file
def encrypt_file(file_path, password):
    salt = get_random_bytes(SALT_SIZE)
    key = derive_key(password.encode(), salt)
    iv = get_random_bytes(IV_SIZE)
    cipher = AES.new(key, AES.MODE_CFB, iv)

    output_path = file_path + ".enc"

    with open(file_path, 'rb') as f_in, open(output_path, 'wb') as f_out:
        f_out.write(salt)
        f_out.write(iv)

        while chunk := f_in.read(CHUNK_SIZE):
            f_out.write(cipher.encrypt(chunk))
    
    return output_path

# Decrypt a file
def decrypt_file(file_path, password):
    with open(file_path, 'rb') as f_in:
        salt = f_in.read(SALT_SIZE)
        iv = f_in.read(IV_SIZE)
        key = derive_key(password.encode(), salt)
        cipher = AES.new(key, AES.MODE_CFB, iv)

        output_path = file_path.replace(".enc", ".dec")

        with open(output_path, 'wb') as f_out:
            while chunk := f_in.read(CHUNK_SIZE):
                f_out.write(cipher.decrypt(chunk))

    return output_path

# GUI App
def select_file_encrypt():
    path = filedialog.askopenfilename()
    if path:
        password = simpledialog.askstring("Password", "Enter password for encryption:")

        if password:
            enc_path = encrypt_file(path, password)
            messagebox.showinfo("Success", f"File encrypted:\n{enc_path}")

def select_file_decrypt():
    path = filedialog.askopenfilename()
    if path:
        password = simpledialog.askstring("Password", "Enter password for decryption:")

        if password:
            try:
                dec_path = decrypt_file(path, password)
                messagebox.showinfo("Success", f"File decrypted:\n{dec_path}")
            except Exception as e:
                messagebox.showerror("Error", "Incorrect password or file is corrupted.")

# Main GUI Window
def create_gui():
    root = Tk()
    root.title("AES-256 Encryption Tool")
    root.geometry("400x200")

    Label(root, text="Advanced Encryption Tool (AES-256)", font=("Arial", 14)).pack(pady=20)

    Button(root, text="Encrypt File", width=20, command=select_file_encrypt).pack(pady=10)
    Button(root, text="Decrypt File", width=20, command=select_file_decrypt).pack(pady=10)

    root.mainloop()

if __name__ == "__main__":
    create_gui()