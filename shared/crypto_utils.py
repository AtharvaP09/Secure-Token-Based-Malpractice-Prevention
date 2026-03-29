import os
import hashlib
import hmac
import base64
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend

class CryptoUtils:
    def __init__(self, key: bytes):
        """
        Initialize with a 32-byte AES key.
        """
        if len(key) != 32:
            raise ValueError("Key must be 32 bytes for AES-256")
        self.key = key

    def encrypt(self, plain_text: str) -> dict:
        """
        Encrypts text using AES-256-GCM. Returns iv, ciphertext, tag.
        """
        iv = os.urandom(12) # GCM recommended IV size
        cipher = Cipher(algorithms.AES(self.key), modes.GCM(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(plain_text.encode()) + encryptor.finalize()
        
        return {
            "iv": base64.b64encode(iv).decode(),
            "ciphertext": base64.b64encode(ciphertext).decode(),
            "tag": base64.b64encode(encryptor.tag).decode()
        }

    def decrypt(self, iv_b64: str, ciphertext_b64: str, tag_b64: str) -> str:
        """
        Decrypts AES-256-GCM ciphertext.
        """
        iv = base64.b64decode(iv_b64)
        ciphertext = base64.b64decode(ciphertext_b64)
        tag = base64.b64decode(tag_b64)

        cipher = Cipher(algorithms.AES(self.key), modes.GCM(iv, tag), backend=default_backend())
        decryptor = cipher.decryptor()
        return (decryptor.update(ciphertext) + decryptor.finalize()).decode()

    @staticmethod
    def generate_hmac(key: bytes, message: str) -> str:
        """
        Generates HMAC-SHA256 signature for integrity.
        """
        h = hmac.new(key, message.encode(), hashlib.sha256)
        return h.hexdigest()

    @staticmethod
    def generate_key() -> bytes:
        return os.urandom(32)
