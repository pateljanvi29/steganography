import tkinter as tk
from tkinter import ttk, filedialog, messagebox
from PIL import Image, ImageTk
import os
import logging
import re
from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import base64

class ImageSteganographyGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("CyberSteg - Secure Image Steganography")
        self.root.geometry("750x600")
        self.root.resizable(False, False)

        self.image_path = None
        self.output_image_path = None
        self.setup_logging()
        self.create_cybersecurity_widgets()

    def setup_logging(self):
        logging.basicConfig(
            filename='steg_audit.log',
            level=logging.INFO,
            format='%(asctime)s - %(message)s'
        )

    def create_cybersecurity_widgets(self):
        self.notebook = ttk.Notebook(self.root)
        self.tab1 = ttk.Frame(self.notebook)
        self.tab2 = ttk.Frame(self.notebook)
        self.notebook.add(self.tab1, text="Steganography")
        self.notebook.add(self.tab2, text="Security Tools")
        self.notebook.pack(expand=True, fill="both")

        self.create_steg_widgets(self.tab1)
        self.create_security_widgets(self.tab2)

    def create_steg_widgets(self, parent):
        ttk.Label(parent, text="Image Steganography", font=("Arial", 16)).pack(pady=10)

        ttk.Button(parent, text="Select Image", command=self.select_image).pack(pady=5)

        self.image_label = ttk.Label(parent, text="No Image Selected", background="gray", width=80)
        self.image_label.pack(pady=10)

        ttk.Label(parent, text="Secret Message:").pack()
        self.message_entry = ttk.Entry(parent, width=50)
        self.message_entry.pack(pady=5)

        ttk.Label(parent, text="Password:").pack()
        self.password_entry = ttk.Entry(parent, width=30, show="*")
        self.password_entry.pack(pady=5)

        ttk.Button(parent, text="Encrypt Message", command=self.encrypt_message).pack(pady=5)
        ttk.Button(parent, text="Decrypt Message", command=self.decrypt_message).pack(pady=5)

    def create_security_widgets(self, parent):
        ttk.Label(parent, text="Cybersecurity Tools", font=("Arial", 16)).pack(pady=10)

        ttk.Button(parent, text="Detect Hidden Data", command=self.detect_steg).pack(pady=10)
        ttk.Button(parent, text="Brute-force Attack", command=self.brute_force_attack).pack(pady=10)

        ttk.Label(parent, text="Predefined Payloads:").pack()
        self.payload_var = tk.StringVar()
        self.payload_menu = ttk.Combobox(parent, textvariable=self.payload_var,
                                         values=["XSS", "SQLi", "CSRF", "Custom"])
        self.payload_menu.pack(pady=5)
        self.payload_menu.bind("<<ComboboxSelected>>", self.load_payload)

    def is_valid_password(self, password):
        pattern = r'^[A-Za-z]+@[0-9]{4}$'
        return re.match(pattern, password) is not None

    def load_payload(self, event):
        payloads = {
            "XSS": "<script>alert('XSS Attack!')</script>",
            "SQLi": "' OR 1=1 --",
            "CSRF": "<img src='http://malicious.site/action'>"
        }
        selected = self.payload_var.get()
        self.message_entry.delete(0, tk.END)
        self.message_entry.insert(0, payloads.get(selected, ""))

    def generate_key(self, password):
        salt = b'cyber_security_salt'
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000
        )
        return base64.urlsafe_b64encode(kdf.derive(password.encode()))

    def encrypt_message(self):
        message = self.message_entry.get()
        password = self.password_entry.get()
        if not self.image_path:
            messagebox.showerror("Error", "No image selected.")
            return
        if not message:
            messagebox.showerror("Error", "No message entered.")
            return
        if not password:
            messagebox.showerror("Error", "Password required for encryption.")
            return
        if not self.is_valid_password(password):
            messagebox.showerror("Invalid Password", "Password must be in the format: Letters@4digits (e.g., Shristi@2510)")
            return

        self.output_image_path = filedialog.asksaveasfilename(defaultextension=".png", filetypes=[("PNG files", "*.png")])
        if not self.output_image_path:
            return

        try:
            key = self.generate_key(password)
            cipher = Fernet(key)
            encrypted_message = cipher.encrypt(message.encode())
            self.steganography_encrypt(encrypted_message, self.image_path, self.output_image_path)
            messagebox.showinfo("Success", "Encrypted message saved.")
            logging.info(f"ENCRYPTION SUCCESS - {self.output_image_path}")
        except Exception as e:
            messagebox.showerror("Error", f"Encryption failed: {str(e)}")
            logging.error(f"ENCRYPTION FAILED - {str(e)}")

    def decrypt_message(self):
        password = self.password_entry.get()
        if not self.image_path:
            messagebox.showerror("Error", "No image selected.")
            return
        if not password:
            messagebox.showerror("Error", "Password required.")
            return
        if not self.is_valid_password(password):
            messagebox.showerror("Invalid Password", "Password must be in the format: Letters@4digits (e.g., Shristi@2510)")
            return
        try:
            encrypted_data = self.steganography_decrypt(self.image_path)
            key = self.generate_key(password)
            cipher = Fernet(key)
            decrypted_message = cipher.decrypt(encrypted_data).decode()
            messagebox.showinfo("Decrypted Message", f"Hidden Message: {decrypted_message}")
            logging.info(f"DECRYPTION SUCCESS - {self.image_path}")
        except Exception as e:
            messagebox.showerror("Error", "Decryption failed - wrong password or corrupted data.")
            logging.error(f"DECRYPTION FAILED - {str(e)}")

    def detect_steg(self):
        try:
            image = Image.open(self.image_path)
            pixels = list(image.getdata())
            lsb_bits = [str(pixel[i] & 1) for pixel in pixels for i in range(3)]
            lsb_string = ''.join(lsb_bits)

            zero_count = lsb_string.count('0')
            one_count = lsb_string.count('1')
            ratio = abs(zero_count - one_count) / len(lsb_string)

            if ratio < 0.1:
                messagebox.showinfo("Steg Detection", "Hidden data likely detected!")
            else:
                messagebox.showinfo("Steg Detection", "No hidden data detected.")
            logging.info(f"STEGANALYSIS PERFORMED - {self.image_path}")
        except Exception as e:
            messagebox.showerror("Error", f"Detection failed: {str(e)}")

    def brute_force_attack(self):
        common_users = ["Shristi", "Admin", "User", "Test", "Guest", "shristi", "guest", "user", "test", "admin"]
        common_numbers = ["1510", "1234", "0000", "1111", "2023", "4444"]
        password_list = [f"{user}@{number}" for user in common_users for number in common_numbers]
        password_list += [
            "Admin@1234", "User@0000", "Test@1111",
            "Shristi@2023", "Guest@4444", "Shristi@1510",
            "shristi@1234", "user@1510", "test@1111",
            "admin@0000", "guest@2023", "user@4444"
        ]

        try:
            encrypted_data = self.steganography_decrypt(self.image_path)
            found = False

            progress = tk.Toplevel()
            progress.title("Brute-force Progress")
            tk.Label(progress, text="Attempting common passwords...").pack(padx=20, pady=5)
            progress_text = tk.Text(progress, height=10, width=40)
            progress_text.pack(padx=10, pady=10)

            for pwd in password_list:
                progress_text.insert(tk.END, f"Trying: {pwd}\n")
                progress_text.see(tk.END)
                progress.update()

                try:
                    key = self.generate_key(pwd)
                    cipher = Fernet(key)
                    decrypted = cipher.decrypt(encrypted_data).decode()
                    progress.destroy()
                    messagebox.showinfo("Brute-force Success", f"Password cracked: {pwd}\nMessage: {decrypted}")
                    logging.warning(f"BRUTE-FORCE SUCCESS - Password: {pwd}")
                    found = True
                    break
                except InvalidToken:
                    continue
                except Exception as e:
                    progress_text.insert(tk.END, f"Error with {pwd}: {str(e)}\n")
                    continue

            if not found:
                progress.destroy()
                messagebox.showinfo("Brute-force Failed", "No matching passwords found")
                logging.info("BRUTE-FORCE FAILED - No matches found")

        except Exception as e:
            messagebox.showerror("Error", f"Brute-force failed: {str(e)}")
            logging.error(f"BRUTE-FORCE ERROR - {str(e)}")

    def steganography_encrypt(self, data_bytes, image_path, output_image_path):
        image = Image.open(image_path).convert('RGB')
        pixels = list(image.getdata())

        binary_data = ''.join(format(byte, '08b') for byte in data_bytes)
        binary_length = format(len(binary_data), '032b')
        full_binary = binary_length + binary_data

        if len(full_binary) > len(pixels) * 3:
            raise ValueError("Data too large for image.")

        new_pixels = []
        bit_index = 0

        for pixel in pixels:
            r, g, b = pixel
            if bit_index < len(full_binary):
                r = (r & ~1) | int(full_binary[bit_index])
                bit_index += 1
            if bit_index < len(full_binary):
                g = (g & ~1) | int(full_binary[bit_index])
                bit_index += 1
            if bit_index < len(full_binary):
                b = (b & ~1) | int(full_binary[bit_index])
                bit_index += 1
            new_pixels.append((r, g, b))

        new_image = Image.new('RGB', image.size)
        new_image.putdata(new_pixels)
        new_image.save(output_image_path)

    def steganography_decrypt(self, image_path):
        image = Image.open(image_path).convert('RGB')
        pixels = list(image.getdata())

        binary_data = []
        for pixel in pixels:
            r, g, b = pixel
            binary_data.append(str(r & 1))
            binary_data.append(str(g & 1))
            binary_data.append(str(b & 1))
        binary_data = ''.join(binary_data)

        if len(binary_data) < 32:
            raise ValueError("Insufficient data to extract length.")

        length_bits = binary_data[:32]
        message_length = int(length_bits, 2)

        if (32 + message_length) > len(binary_data):
            raise ValueError("Corrupted or invalid message length.")

        message_bits = binary_data[32:32 + message_length]
        byte_data = bytearray()
        for i in range(0, len(message_bits), 8):
            byte_data.append(int(message_bits[i:i+8], 2))
        return bytes(byte_data)

    def select_image(self):
        file_path = filedialog.askopenfilename(filetypes=[("Image files", "*.png;*.jpg;*.jpeg")])
        if file_path:
            self.image_path = file_path
            self.show_image(file_path)

    def show_image(self, image_path):
        image = Image.open(image_path)
        image.thumbnail((300, 300))
        photo = ImageTk.PhotoImage(image)
        self.image_label.config(image=photo, text="")
        self.image_label.image = photo

if __name__ == "__main__":
    root = tk.Tk()
    app = ImageSteganographyGUI(root)
    root.mainloop()
