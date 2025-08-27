import json
import hashlib
import hmac
import base64
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend

def encrypt(data, key, iv):
    # Derive AES key (32 bytes) and IV (16 bytes) - match your Node.js implementation
    key_bytes = hashlib.sha256(key.encode()).digest()   # 32 bytes key
    iv_bytes = hashlib.md5(iv.encode()).digest()        # 16 bytes IV (match Node.js)
    
    # Pad the data using PKCS7 padding
    padder = padding.PKCS7(128).padder()
    padded_data = padder.update(data.encode()) + padder.finalize()
    
    # Create cipher and encrypt
    cipher = Cipher(algorithms.AES(key_bytes), modes.CBC(iv_bytes), backend=default_backend())
    encryptor = cipher.encryptor()
    encrypted = encryptor.update(padded_data) + encryptor.finalize()
    
    # Return base64 encoded (to match Node.js output)
    return base64.b64encode(encrypted).decode('utf-8')

# Input data
name = "John"
roomid = "12345678"
userid = "42"

data = {
    "name": name,
    "roomid": roomid,
    "userid": userid
}

keystring = "hackathon25"
iv = "I am the king"

# Encrypt
ciphertext = encrypt(json.dumps(data), keystring, iv)

# HMAC - match your Node.js implementation
hmac_input = iv.encode() + ciphertext.encode()
hmac_value = hmac.new(keystring.encode(), hmac_input, hashlib.sha256).hexdigest()

config = {
    "iv": iv,
    "data": ciphertext,
    "hmac": hmac_value
}

print("Generated config:")
print(json.dumps(config, indent=4))

# Save to file
with open('config.json', 'w') as f:
    json.dump(config, f, indent=4)

print("\nConfig saved to config.json")

# Test decryption to verify
def decrypt(ciphertext_b64, key, iv):
    # Derive same key and IV
    key_bytes = hashlib.sha256(key.encode()).digest()
    iv_bytes = hashlib.md5(iv.encode()).digest()
    
    # Decode base64
    encrypted = base64.b64decode(ciphertext_b64)
    
    # Decrypt
    cipher = Cipher(algorithms.AES(key_bytes), modes.CBC(iv_bytes), backend=default_backend())
    decryptor = cipher.decryptor()
    padded_data = decryptor.update(encrypted) + decryptor.finalize()
    
    # Unpad
    unpadder = padding.PKCS7(128).unpadder()
    data = unpadder.update(padded_data) + unpadder.finalize()
    
    return data.decode('utf-8')

# Test decryption
try:
    decrypted = decrypt(ciphertext, keystring, iv)
    print(f"\nDecryption test successful: {decrypted}")
except Exception as e:
    print(f"\nDecryption test failed: {e}")