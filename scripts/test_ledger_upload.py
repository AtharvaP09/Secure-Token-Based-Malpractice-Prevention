import requests
import json
import os
import sys
import datetime

# Add project root to sys.path to allow importing from shared
sys.path.append(os.path.join(os.path.dirname(__file__), '..'))
from shared.crypto_utils import CryptoUtils

API_URL = "http://127.0.0.1:8000"

def test_ledger_upload(token, session_id):
    print(f"Testing ledger upload for session {session_id}...")
    
    # 1. Get Config (Encryption Key)
    headers = {"Authorization": f"Bearer {token}"}
    resp = requests.get(f"{API_URL}/exams/{session_id}/config", headers=headers)
    if resp.status_code != 200:
        print(f"Failed to get config: {resp.text}")
        return False
    
    key_hex = resp.json()["encryption_key"]
    print(f"Got key: {key_hex}")
    
    # 2. Create Dummy Ledger
    crypto = CryptoUtils(bytes.fromhex(key_hex))
    logs = [
        {
            "timestamp": datetime.datetime.utcnow().isoformat(),
            "log_type": "system",
            "content": "Offline Log 1: Monitor started offline",
            "is_suspicious": False
        },
        {
            "timestamp": datetime.datetime.utcnow().isoformat(),
            "log_type": "alert",
            "content": "Offline Log 2: Suspicious process detected",
            "is_suspicious": True
        }
    ]
    
    data = json.dumps(logs)
    encrypted = crypto.encrypt(data)
    
    # Format payload
    payload = json.dumps(encrypted).encode()
    file_content = len(payload).to_bytes(4, byteorder='big') + payload
    
    # Write to temp file
    ledger_path = "temp_test_ledger.enc"
    with open(ledger_path, "wb") as f:
        f.write(file_content)
        
    # 3. Upload Ledger
    print("Uploading ledger...")
    with open(ledger_path, "rb") as f:
        files = {"file": f}
        resp = requests.post(f"{API_URL}/exams/{session_id}/upload_ledger", headers=headers, files=files)
        
    if resp.status_code != 200:
        print(f"Upload failed: {resp.text}")
        return False
        
    print(f"Upload success: {resp.json()}")
    
    # 4. Verify Logs
    print("Verifying logs...")
    resp = requests.get(f"{API_URL}/exams/{session_id}/logs?source=ledger", headers=headers)
    if resp.status_code != 200:
         print(f"Failed to fetch logs: {resp.text}")
         return False
         
    fetched_logs = resp.json()
    print(f"Fetched {len(fetched_logs)} ledger logs.")
    
    found = False
    for log in fetched_logs:
        if "Offline Log 1" in log["content"]:
            found = True
            break
            
    if found:
        print("SUCCESS: Found offline log in response.")
    else:
        print("FAILURE: Did not find offline log.")
        
    # Cleanup
    if os.path.exists(ledger_path):
        os.remove(ledger_path)
        
    return True

if __name__ == "__main__":
    # Note: Requires a valid JWT and Session ID to run against a real backend.
    # For now, this script serves as a template/tool for manual verification or
    # incorporated into a larger test suite that generates these tokens.
    
    if len(sys.argv) < 3:
        print("Usage: python test_ledger_upload.py <jwt_token> <session_id>")
    else:
        test_ledger_upload(sys.argv[1], int(sys.argv[2]))
