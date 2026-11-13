import base64, hashlib, hmac, json, os
import tkinter as tk
from tkinter import ttk, filedialog, messagebox
import cv2
import qrcode
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

MAGIC = "SECURE_QR_V1"
ITERATIONS = 600_000

def derive_key(password, salt, iterations=ITERATIONS):
    if not password:
        raise ValueError("Password cannot be empty.")
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32,
                     salt=salt, iterations=iterations)
    return kdf.derive(password.encode("utf-8"))

def encrypt_message(message, password):
    if not message:
        raise ValueError("Enter a message first.")
    salt, nonce = os.urandom(16), os.urandom(12)
    key = derive_key(password, salt)
    raw = message.encode("utf-8")
    inner = json.dumps({
        "message": message,
        "sha256": hashlib.sha256(raw).hexdigest()
    }, ensure_ascii=False).encode("utf-8")
    encrypted = AESGCM(key).encrypt(nonce, inner, MAGIC.encode())
    return json.dumps({
        "format": MAGIC, "cipher": "AES-256-GCM",
        "iterations": ITERATIONS,
        "salt": base64.b64encode(salt).decode(),
        "nonce": base64.b64encode(nonce).decode(),
        "ciphertext": base64.b64encode(encrypted).decode()
    }, separators=(",", ":"))

def decrypt_message(payload, password):
    try:
        data = json.loads(payload)
        if data.get("format") != MAGIC or data.get("cipher") != "AES-256-GCM":
            raise ValueError("Unsupported QR code format.")
        iterations = int(data["iterations"])
        if not 100_000 <= iterations <= 2_000_000:
            raise ValueError("Invalid key derivation settings.")
        salt = base64.b64decode(data["salt"], validate=True)
        nonce = base64.b64decode(data["nonce"], validate=True)
        encrypted = base64.b64decode(data["ciphertext"], validate=True)
        if len(salt) != 16 or len(nonce) != 12:
            raise ValueError("Invalid QR encryption parameters.")
        key = derive_key(password, salt, iterations)
        plain = AESGCM(key).decrypt(nonce, encrypted, MAGIC.encode())
        result = json.loads(plain.decode("utf-8"))
        message = result["message"]
        digest = hashlib.sha256(message.encode("utf-8")).hexdigest()
        if not hmac.compare_digest(digest, result["sha256"]):
            raise ValueError("SHA-256 verification failed.")
        return message
    except ValueError:
        raise
    except Exception as exc:
        raise ValueError("Decryption failed. Check the password and QR image.") from exc

def decode_qr(path):
    image = cv2.imread(path)
    if image is None:
        raise ValueError("Could not open this image.")
    text, points, _ = cv2.QRCodeDetector().detectAndDecode(image)
    if not text:
        raise ValueError("No readable QR code found.")
    return text

class App:
    def __init__(self, root):
        self.root = root
        root.title("Secure QR Code Generator")
        root.geometry("800x650")
        root.minsize(680, 560)
        root.configure(bg="#eef2f7")
        self.password = tk.StringVar()
        self.status = tk.StringVar(value="Ready")
        self.build_ui()

    def build_ui(self):
        head = tk.Frame(self.root, bg="#172554", padx=22, pady=18)
        head.pack(fill="x")
        tk.Label(head, text="SECURE QR CODE GENERATOR",
                 bg="#172554", fg="white",
                 font=("Segoe UI", 20, "bold")).pack(anchor="w")
        tk.Label(head, text="AES-256-GCM encryption  |  SHA-256 verification",
                 bg="#172554", fg="#c7d2fe").pack(anchor="w", pady=(5, 0))

        body = tk.Frame(self.root, bg="#eef2f7", padx=22, pady=18)
        body.pack(fill="both", expand=True)
        tk.Label(body, text="Message to protect", bg="#eef2f7",
                 font=("Segoe UI", 11, "bold")).pack(anchor="w")
        self.message = tk.Text(body, height=7, wrap="word",
                               font=("Consolas", 11), padx=9, pady=8)
        self.message.pack(fill="x", pady=(5, 12))

        tk.Label(body, text="Password (minimum 8 characters)",
                 bg="#eef2f7", font=("Segoe UI", 11, "bold")).pack(anchor="w")
        row = tk.Frame(body, bg="#eef2f7")
        row.pack(fill="x", pady=5)
        self.pass_entry = ttk.Entry(row, textvariable=self.password, show="*")
        self.pass_entry.pack(side="left", fill="x", expand=True)
        self.show = tk.BooleanVar(value=False)
        ttk.Checkbutton(row, text="Show password", variable=self.show,
                        command=lambda: self.pass_entry.config(
                            show="" if self.show.get() else "*")).pack(side="left", padx=8)

        buttons = tk.Frame(body, bg="#eef2f7")
        buttons.pack(fill="x", pady=12)
        ttk.Button(buttons, text="Generate Secure QR",
                   command=self.generate).pack(side="left", padx=(0, 8))
        ttk.Button(buttons, text="Scan QR & Decrypt",
                   command=self.decrypt).pack(side="left", padx=8)
        ttk.Button(buttons, text="Clear", command=self.clear).pack(side="right")

        tk.Label(body, text="Decrypted message", bg="#eef2f7",
                 font=("Segoe UI", 11, "bold")).pack(anchor="w", pady=(5, 5))
        self.output = tk.Text(body, height=7, wrap="word",
                              font=("Consolas", 11), padx=9, pady=8)
        self.output.pack(fill="both", expand=True)
        tk.Label(body, textvariable=self.status, bg="#eef2f7",
                 fg="#475569").pack(anchor="w", pady=(10, 0))
        tk.Label(body,
                 text="Keep the password separate from the QR image. AES-GCM authenticates ciphertext; SHA-256 is additionally checked after decryption. This is an educational project.",
                 bg="#eef2f7", fg="#92400e", wraplength=740,
                 justify="left").pack(anchor="w", pady=(8, 0))

    def generate(self):
        msg, password = self.message.get("1.0", "end-1c"), self.password.get()
        if not msg.strip():
            messagebox.showwarning("Missing message", "Enter a message.")
            return
        if len(password) < 8:
            messagebox.showwarning("Password too short",
                                   "Use at least 8 characters; a longer passphrase is better.")
            return
        try:
            payload = encrypt_message(msg, password)
            qr = qrcode.QRCode(error_correction=qrcode.constants.ERROR_CORRECT_M,
                               box_size=10, border=4)
            qr.add_data(payload)
            qr.make(fit=True)
            image = qr.make_image(fill_color="black", back_color="white").convert("RGB")
            path = filedialog.asksaveasfilename(
                defaultextension=".png", initialfile="secure_message_qr.png",
                filetypes=[("PNG image", "*.png")])
            if path:
                image.save(path)
                self.status.set("Secure QR code saved.")
                messagebox.showinfo("Success", "QR code created successfully.")
        except Exception as e:
            messagebox.showerror("Error", str(e))

    def decrypt(self):
        password = self.password.get()
        if not password:
            messagebox.showwarning("Missing password", "Enter the password.")
            return
        path = filedialog.askopenfilename(
            filetypes=[("Image files", "*.png *.jpg *.jpeg *.bmp"), ("All files", "*.*")])
        if not path:
            return
        try:
            payload = decode_qr(path)
            msg = decrypt_message(payload, password)
            self.output.delete("1.0", "end")
            self.output.insert("1.0", msg)
            self.status.set("Decrypted successfully — SHA-256 verification passed.")
            messagebox.showinfo("Verified", "Message decrypted and SHA-256 verified.")
        except Exception as e:
            self.output.delete("1.0", "end")
            self.status.set("Decryption or verification failed.")
            messagebox.showerror("Decryption failed", str(e))

    def clear(self):
        self.message.delete("1.0", "end")
        self.output.delete("1.0", "end")
        self.password.set("")
        self.status.set("Ready")

if __name__ == "__main__":
    root = tk.Tk()
    App(root)
    root.mainloop()
