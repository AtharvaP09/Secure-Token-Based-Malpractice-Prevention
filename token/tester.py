import hashlib
import hmac
import base64
import json
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend

def encrypt(plaintext: str, key: bytes, iv: bytes) -> str:
    # Pad plaintext to AES block size (16 bytes)
    padder = padding.PKCS7(128).padder()
    padded_data = padder.update(plaintext.encode("utf-8")) + padder.finalize()

    # AES CBC mode
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(padded_data) + encryptor.finalize()

    # Encode to Base64 so it's JSON-safe
    return base64.b64encode(ciphertext).decode("utf-8")


# ---------------- Main Code ---------------- #
data  = "{\"start\":7687638787,\"id\":\"YGD65363\",\"name\":\"Cruise\",\"sessionid\":\"ILU5U\"}"

# Generate key (SHA-256 hash of "hackathon25") → 32 bytes AES-256 key
key = hashlib.sha256(b"hackathon25").digest()

# Generate IV (MD5 hash of "Its a fun world") → 16 bytes
iv_string = "Its a fun world"
iv = hashlib.md5(iv_string.encode()).digest()

config = {}
config["iv"] = iv_string

# Encrypt the data (not the HMAC)
encrypted_data = encrypt(data, key, iv)

# Compute HMAC-SHA256 of (IV + encrypted data)
newkey = "hackathon25"
hmac_input = iv_string.encode() + data.encode()
hmac_value = hmac.new(newkey.encode(), hmac_input, hashlib.sha256).hexdigest()

config["data"] = encrypted_data
config["hmac"] = hmac_value

print(config)
print(json.dumps(config, indent=4))

with open('config.json', 'w') as f:
    json.dump(config, f, indent=4)

