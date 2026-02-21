
import threading
import time
import requests
import uvicorn
from fastapi import FastAPI, Request
from pydantic import BaseModel
from typing import List
import sys
import os
import json
import secrets

# Ensure we can import from tokens
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'tokens')))
# Mock shared if needed, or ensure it's in path
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from tokens.logger import EncryptedLogger
from tokens.monitor import ExamMonitor
from shared.crypto_utils import CryptoUtils

# Mock Backend
app = FastAPI()
received_encrypted_logs = []
mock_key = secrets.token_hex(32)

@app.get("/exams/{session_id}/config")
def get_config(session_id: int):
    return {"encryption_key": mock_key}

class LogBatch(BaseModel):
    logs: List[dict] # We expect encrypted dicts now basically, or the structure logger sends

@app.post("/exams/{session_id}/log")
async def receive_log(session_id: int, request: Request):
    # Logger sends {"logs": [...]} where each item is {timestamp, log_type, ...} 
    # BUT wait, logger.flush() encrypts the WHOLE payload? 
    # Let's check logger.py flush implementation.
    # Logger encrypts `json.dumps(self.logs)` -> `encrypted`.
    # Then it writes to file.
    # BUT monitor.upload_logs() takes `self.logger.upload_queue`.
    # `upload_queue` contains UNENCRYPTED dicts.
    
    # Ah, the plan was:
    # "Decrypt the log payload before storing (or store encrypted if preferred, but we'll decrypt for analysis)."
    # But monitor.upload_logs() sends `payload = {"logs": batch}` request.
    # And `batch` is list of dicts.
    # So `monitor.upload_logs` sends JSON.
    # ENCRYPTION happens in `logger.flush()` only for FILE writing in current implementation.
    
    # We missed updating `monitor.upload_logs` to use encryption!
    # The requirement was "Secure Token-Based" which usually implies transport layer security (HTTPS) + potentially payload encryption.
    # If we want end-to-end encryption (stored encrypted on server), we should send encrypted data.
    # Current `monitor.py` just sends JSON over HTTP(S).
    
    # For this test, let's just verify config fetch works.
    # But we should probably address the encryption in transport if that was the goal.
    # The Task said "Replace hardcoded key with session-specific key exchange".
    # And Logger uses this key for the LOCAL LOG FILE.
    # Does the backend need this key for the API logs?
    # Logic: "Decrypt the log payload before storing".
    # Implies we SHOULD send encrypted logs.
    
    # Let's verify what we have first.
    body = await request.json()
    print(f"Server received: {body}")
    return {"status": "ok"}

def run_server():
    uvicorn.run(app, host="127.0.0.1", port=8002, log_level="warning")

def test_key_exchange():
    # Start Mock Server
    server_thread = threading.Thread(target=run_server, daemon=True)
    server_thread.start()
    time.sleep(2) 

    # Init Monitor
    print("Initializing Monitor...")
    monitor = ExamMonitor("http://127.0.0.1:8002", "mock_jwt", 999)
    
    print(f"Fetched Key: {monitor.encryption_key}")
    print(f"Mock Key:    {mock_key}")
    
    if monitor.encryption_key == mock_key:
        print("SUCCESS: Key exchanged correctly.")
    else:
        print("FAILURE: Key mismatch.")
        sys.exit(1)
        
    # Verify Logger uses it
    if monitor.logger.key == bytes.fromhex(mock_key):
        print("SUCCESS: Logger using correct key.")
    else:
        print("FAILURE: Logger key mismatch.")
        sys.exit(1)

if __name__ == "__main__":
    test_key_exchange()
