# 🛡️ CyberSteg - Secure Image Steganography GUI

A Python-based steganography desktop application with a modern GUI that hides encrypted messages inside images. Also features built-in cybersecurity tools like steg detection and brute-force decryption.

---

## 🚀 Features

- 🔐 **Encrypt & Hide Message** in an image using AES-like encryption (Fernet).
- 🔓 **Decrypt Hidden Message** with password validation.
- 🖼️ User-friendly **Tkinter GUI** with real-time image preview.
- 🛡️ **Steganalysis** tool to detect presence of hidden data.
- 🗝️ **Brute-force Attack** option to simulate password cracking.
- ✅ Password validation with regex (e.g., `Name@1234` format).
- 🧠 Predefined **cyber payloads**: XSS, SQLi, CSRF (for demonstration only).

---

## 📸 Demo

> Coming soon — add screenshots or GIF here.

---

## 🧑‍💻 How to Run

1. **Clone the repo**
   ```bash
   git clone https://github.com/your-username/image-steganography-app.git
   cd image-steganography-app


2. **Install dependencies**
   ```bash
   pip install pillow cryptography


3. **Run the app**
   ```bash
   python ImageStegnopraphy.py

---

📦 Requirements
• Python 3.x
• Tkinter (comes pre-installed with Python)
• Pillow
• Cryptography

---

🔐 Password Format
Letters@4Digits
Example: Shristi@2510

---

⚠️ Disclaimer
This tool is intended for educational and ethical use only.
The brute-force and cyber attack payloads are for learning/demo purposes and must not be used maliciously.

---

📂 Log File
All critical actions (encrypt, decrypt, brute-force) are logged into:
steg_audit.log

---

💡 Future Improvements
• Add drag-and-drop support
• Export decrypted message to text file
• Add support for more image formats (e.g., BMP, TIFF)
• Add CLI or web version (Flask or Streamlit)

---

📜 License
MIT License – feel free to use, modify, and contribute.

---

🙋‍♀️ Author
Janvi Patel
B.Tech CSE Student | Passionate about Cybersecurity & Digital Tools
