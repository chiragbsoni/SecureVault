from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import os
import base64

# 32-byte (256-bit) AES key (hardcoded for now — we'll move to environment variable later)
AES_KEY = b'MyVeryStrongSecretKey1234567890!'  # Exactly 32 bytes
  # Must be exactly 32 bytes

def encrypt_password(plaintext):
    # Generate a random 16-byte IV
    iv = os.urandom(16)

    # Set up AES cipher
    cipher = Cipher(algorithms.AES(AES_KEY), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()

    # Pad plaintext to 16-byte boundary (PKCS7)
    pad_len = 16 - len(plaintext.encode()) % 16
    padded = plaintext + chr(pad_len) * pad_len

    ciphertext = encryptor.update(padded.encode()) + encryptor.finalize()

    return base64.b64encode(ciphertext), base64.b64encode(iv)

def decrypt_password(ciphertext_b64, iv_b64):
    # Decode base64
    ciphertext = base64.b64decode(ciphertext_b64)
    iv = base64.b64decode(iv_b64)

    # Set up AES cipher
    cipher = Cipher(algorithms.AES(AES_KEY), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()

    padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()

    # Remove PKCS7 padding
    pad_len = padded_plaintext[-1]
    plaintext = padded_plaintext[:-pad_len].decode()

    return plaintext
