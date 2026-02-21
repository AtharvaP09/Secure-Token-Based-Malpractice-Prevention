
import threading
import time
import requests
import uvicorn
from fastapi import FastAPI, Request
from pydantic import BaseModel
from typing import List
import sys
import os

# Ensure we can import from tokens
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'tokens')))
# Mock shared if needed, or ensure it's in path
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from tokens.logger import EncryptedLogger
from tokens.monitor import ExamMonitor

# Mock Backend
app = FastAPI()
logs_received = []

class LogEntry(BaseModel):
    log_type: str
    content: str
    timestamp: str
    is_suspicious: bool

class LogBatch(BaseModel):
    logs: List[LogEntry]

@app.post("/exams/{session_id}/log")
async def receive_log(session_id: int, batch: LogBatch):
    print(f"Server received {len(batch.logs)} logs for session {session_id}")
    logs_received.extend(batch.logs)
    return {"status": "ok"}

def run_server():
    uvicorn.run(app, host="127.0.0.1", port=8001, log_level="warning")

def test_monitor():
    # Start Mock Server
    server_thread = threading.Thread(target=run_server, daemon=True)
    server_thread.start()
    time.sleep(2) # Wait for server

    # Init Monitor
    print("Initializing Monitor...")
    # Mock JWT and Session ID
    monitor = ExamMonitor("http://127.0.0.1:8001", "mock_jwt", 123)
    
    # We don't want to start the full monitor loop because it blocks and runs system watchers
    # We just want to test upload_logs
    
    # 1. Inject a log
    print("Injecting log...")
    monitor.logger.log("TEST", "This is a test log")
    
    # 2. Trigger Upload (manually, since we aren't calling start())
    print("Triggering upload...")
    monitor.upload_logs()
    
    # 3. Verify
    time.sleep(1)
    if len(logs_received) > 0:
        print("SUCCESS: Logs received by server!")
        print(f"Log content: {logs_received[0].content}")
    else:
        print("FAILURE: No logs received.")
        sys.exit(1)

if __name__ == "__main__":
    test_monitor()
