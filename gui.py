import tkinter as tk
from tkinter import messagebox, font
import base64
from cryptography_utils import encrypt_aes, decrypt_aes, hash_sha256, generate_rsa_keypair, encrypt_rsa, decrypt_rsa

class SecureTextGUI:
    def __init__(self, master):
        self.master = master
        self.master.title("SecureText")
        self.master.geometry("600x400")
        self.master.configure(bg="#f0f0f0")

        self.title_font = font.Font(family='Helvetica', size=16, weight='bold')
        self.label_font = font.Font(family='Helvetica', size=12)
        self.entry_font = font.Font(family='Helvetica', size=10)

        # Title Label
        self.title_label = tk.Label(master, text="SecureText Encryption Tool", font=self.title_font, bg="#f0f0f0")
        self.title_label.grid(row=0, column=1, columnspan=2, pady=10)

        # Encryption Method Section
        self.method_frame = tk.Frame(master, bg="#f0f0f0", padx=10, pady=10, relief="solid", borderwidth=1)
        self.method_frame.grid(row=1, column=0, rowspan=7, sticky="ns", padx=10, pady=10)

        tk.Label(self.method_frame, text="Encryption Method:", font=self.label_font, bg="#f0f0f0").pack(pady=(0, 10))

        self.encryption_method = tk.StringVar()
        self.encryption_method.set("AES")  # Default method

        tk.Radiobutton(self.method_frame, text="AES", variable=self.encryption_method, value="AES", bg="#f0f0f0", command=self.update_labels).pack(anchor="w", pady=2)
        tk.Radiobutton(self.method_frame, text="RSA", variable=self.encryption_method, value="RSA", bg="#f0f0f0", command=self.update_labels).pack(anchor="w", pady=2)
        tk.Radiobutton(self.method_frame, text="SHA-256", variable=self.encryption_method, value="SHA-256", bg="#f0f0f0", command=self.update_labels).pack(anchor="w", pady=2)

        # Fields for Message, Key, and IV
        tk.Label(master, text="Message:", font=self.label_font, bg="#f0f0f0").grid(row=1, column=1, padx=10, pady=(10, 5), sticky="w")
        self.message_entry = tk.Entry(master, font=self.entry_font, width=40)
        self.message_entry.grid(row=2, column=1, padx=10, pady=(0, 10))

        self.key_label = tk.Label(master, text="Key (16, 24, or 32 bytes):", font=self.label_font, bg="#f0f0f0")
        self.key_label.grid(row=3, column=1, padx=10, pady=(10, 5), sticky="w")
        self.key_entry = tk.Entry(master, font=self.entry_font, width=40)
        self.key_entry.grid(row=4, column=1, padx=10, pady=(0, 10))

        self.iv_label = tk.Label(master, text="IV (16 bytes):", font=self.label_font, bg="#f0f0f0")
        self.iv_label.grid(row=5, column=1, padx=10, pady=(10, 5), sticky="w")
        self.iv_entry = tk.Entry(master, font=self.entry_font, width=40)
        self.iv_entry.grid(row=6, column=1, padx=10, pady=(0, 10))

        # Buttons
        button_frame = tk.Frame(master, bg="#f0f0f0")
        button_frame.grid(row=7, column=1, columnspan=2, pady=10)

        self.encrypt_button = tk.Button(button_frame, text="Encrypt", command=self.encrypt_text, bg="#4CAF50", fg="white", font=self.label_font)
        self.encrypt_button.grid(row=0, column=0, padx=5)
        self.decrypt_button = tk.Button(button_frame, text="Decrypt", command=self.decrypt_text, bg="#f44336", fg="white", font=self.label_font)
        self.decrypt_button.grid(row=0, column=1, padx=5)

        # Result
        self.result_label = tk.Label(master, text="", font=self.label_font, bg="#f0f0f0", wraplength=400)
        self.result_label.grid(row=8, column=1, columnspan=2, pady=(10, 0))

        # Generate RSA keypair
        self.private_key, self.public_key = generate_rsa_keypair()

        # Update labels based on the default method
        self.update_labels()

    def update_labels(self):
        method = self.encryption_method.get()
        if method == "AES":
            self.key_label.config(text="Key (16, 24, or 32 bytes):")
            self.iv_label.config(text="IV (16 bytes):")
        elif method == "RSA":
            self.key_label.config(text="Public Key (RSA):")
            self.iv_label.config(text="Private Key (RSA):")
        elif method == "SHA-256":
            self.key_label.config(text="Key (not used in SHA-256):")
            self.iv_label.config(text="IV (not used in SHA-256):")

    def encrypt_text(self):
        try:
            method = self.encryption_method.get()
            key = self.key_entry.get().encode() if method in {"AES", "RSA"} else b''
            iv = self.iv_entry.get().encode() if method in {"AES", "RSA"} else b''
            message = self.message_entry.get().encode()

            if method == "AES":
                if len(key) not in {16, 24, 32}:
                    raise ValueError("Key must be 16, 24, or 32 bytes long")
                if len(iv) != 16:
                    raise ValueError("IV must be 16 bytes long")
                encrypted_message = encrypt_aes(message, key, iv)
                self.result_label.config(text=f"Encrypted: {encrypted_message.decode(errors='ignore')}")
                print(f"Encrypted: {encrypted_message.decode(errors='ignore')}")
            elif method == "RSA":
                encrypted_message = encrypt_rsa(message, self.public_key)
                self.result_label.config(text=f"Encrypted (RSA): {base64.b64encode(encrypted_message).decode(errors='ignore')}")
                print(f"Encrypted (RSA): {base64.b64encode(encrypted_message).decode(errors='ignore')}")
            elif method == "SHA-256":
                hashed_message = hash_sha256(message)
                encrypted_message = base64.b64encode(hashed_message)
                self.result_label.config(text=f"Hash: {encrypted_message.decode(errors='ignore')}")
                print(f"Hash: {encrypted_message.decode(errors='ignore')}")

        except Exception as e:
            print(f"Error in encryption: {e}")
            messagebox.showerror("Error", f"An error occurred during encryption: {e}")

    def decrypt_text(self):
        try:
            method = self.encryption_method.get()
            key = self.key_entry.get().encode() if method in {"AES", "RSA"} else b''
            iv = self.iv_entry.get().encode() if method in {"AES", "RSA"} else b''
            message = self.message_entry.get().encode()

            if method == "AES":
                if len(key) not in {16, 24, 32}:
                    raise ValueError("Key must be 16, 24, or 32 bytes long")
                if len(iv) != 16:
                    raise ValueError("IV must be 16 bytes long")
                decrypted_message = decrypt_aes(message, key, iv)
                self.result_label.config(text=f"Decrypted: {decrypted_message.decode(errors='ignore')}")
                print(f"Decrypted: {decrypted_message.decode(errors='ignore')}")
            elif method == "RSA":
                encrypted_message = base64.b64decode(message)
                decrypted_message = decrypt_rsa(encrypted_message, self.private_key)
                self.result_label.config(text=f"Decrypted (RSA): {decrypted_message.decode(errors='ignore')}")
                print(f"Decrypted (RSA): {decrypted_message.decode(errors='ignore')}")
            elif method == "SHA-256":
                self.result_label.config(text="Hashing is not reversible.")
                print("Hashing is not reversible.")

        except Exception as e:
            print(f"Error in decryption: {e}")
            messagebox.showerror("Error", f"An error occurred during decryption: {e}")

if __name__ == "__main__":
    root = tk.Tk()
    app = SecureTextGUI(root)
    root.mainloop()
