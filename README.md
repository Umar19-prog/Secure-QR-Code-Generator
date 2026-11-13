# Secure QR Code Generator

Python GUI mini-project using AES-256-GCM, PBKDF2-HMAC-SHA256 and SHA-256.

## Features
- Encrypt a message and save it as a QR code PNG.
- Scan a saved QR image and decrypt it using the same password.
- AES-GCM authentication detects wrong passwords and tampered ciphertext.
- SHA-256 digest is stored inside the encrypted message and checked after decryption.
- Tkinter graphical interface.

## Install and run (Windows / VS Code)

```powershell
python -m venv .venv
.venv\Scripts\activate
python -m pip install -r requirements.txt
python main.py
```

If `python` is not recognized, try `py` instead.

## How to use
1. Enter a message and a password of at least 8 characters.
2. Click **Generate Secure QR** and save the PNG.
3. To recover the message, enter the same password.
4. Click **Scan QR & Decrypt** and select the saved PNG.
5. The message appears only if AES-GCM authentication and SHA-256 verification succeed.

## Cryptography
- **AES-256-GCM:** encrypts and authenticates the message.
- **PBKDF2-HMAC-SHA256:** derives a 256-bit key from the password and a random salt.
- **SHA-256:** verifies the original message digest after decryption.
- **QR code:** transports the encrypted envelope.

AES-GCM already includes an authentication tag. The separate SHA-256 digest is included as a syllabus demonstration, not as a replacement for the GCM tag.

## Files
- `main.py` — application source code
- `requirements.txt` — required packages
- `README.md` — project instructions

Keep the password separate from the QR image. Anyone with both can decrypt the message. Very long messages may create dense QR codes. This is an educational project, not a complete production key-management system.
