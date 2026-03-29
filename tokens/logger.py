import os
import json
import time
from datetime import datetime
# Handle import from shared if running from source, or local if bundled
try:
    from shared.crypto_utils import CryptoUtils
except ImportError:
    # Fallback for when bundled or if shared is not in path
    # For now, simplistic mock or we need to copy shared to tokens during build
    # I will assume shared is copied to tokens/shared for now
    import sys
    sys.path.append(os.path.join(os.path.dirname(__file__), '..'))
    from shared.crypto_utils import CryptoUtils

class EncryptedLogger:
    def __init__(self, student_id, exam_id, encryption_key_hex=None):
        self.student_id = student_id
        self.exam_id = exam_id
        self.filepath = f"exam_ledger_{student_id}_{exam_id}.enc"
        
        if encryption_key_hex:
            self.key = bytes.fromhex(encryption_key_hex)
        else:
            # Fallback for testing/legacy
            self.key = b'0'*32 
            
        self.crypto = CryptoUtils(self.key)
        self.logs = []
        self.buffer_size = 10
        self.upload_queue = []

    def log(self, log_type, content, is_suspicious=False):
        entry = {
            "timestamp": datetime.utcnow().isoformat(),
            "log_type": log_type,  # Changed from "type" to match Pydantic schema
            "content": content,
            "is_suspicious": is_suspicious # Changed from "suspicious" to match Pydantic schema
        }
        self.logs.append(entry)
        if len(self.logs) >= self.buffer_size:
            self.flush()

    def flush(self):
        if not self.logs:
            return
        
        # Add to upload queue before clearing
        self.upload_queue.extend(self.logs)

        data = json.dumps(self.logs)
        encrypted = self.crypto.encrypt(data)
        
        # Append to file
        with open(self.filepath, "ab") as f:
            # Format: Length(4 bytes) + JSON(IV, Ciphertext, Tag)
            payload = json.dumps(encrypted).encode()
            f.write(len(payload).to_bytes(4, byteorder='big'))
            f.write(payload)
        
        self.logs = []

    def finalize(self):
        self.flush()
