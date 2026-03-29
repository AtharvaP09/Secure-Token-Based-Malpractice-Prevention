
import sys
import os
import time
import subprocess
import requests
import signal

# Add paths for tokens
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'tokens')))
# Also add root for backend imports if needed (though we use subprocess for backend)
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from monitor import ExamMonitor

# Configuration
API_URL = "http://127.0.0.1:8004"
DB_PATH = "exam_monitor.db" # using the default db which we will reset

def test_full_flow():
    print(">>> Starting Full Flow Integration Test")
    
    # 0. Kill any existing instances of backend on port 8004 (manual check or just hope)
    
    # 1. Start Backend in Subprocess
    print("[1] Starting Backend Server...")
    # We use the existing database (which we should reset)
    if os.path.exists(DB_PATH):
        try:
            os.remove(DB_PATH) # Reset DB
            print("    Reset database.")
        except:
             print("    Could not remove DB (might be in use), continuing...")

    # Set env var if needed? No, just run
    env = os.environ.copy()
    with open("backend_output.log", "w") as out, open("backend_error.log", "w") as err:
        server_process = subprocess.Popen(
            [sys.executable, "-m", "uvicorn", "backend.main:app", "--host", "127.0.0.1", "--port", "8004"],
            cwd=os.path.abspath(os.path.join(os.path.dirname(__file__), '..')),
            env=env,
            stdout=out,
            stderr=err
        )
    
    try:
        time.sleep(5) # Wait for startup
        
        # 2. Register Teacher
        print("[2] Registering Teacher...")
        resp = requests.post(f"{API_URL}/auth/register", json={
            "username": "teacher1", "email": "t@t.com", "password": "pass", "role": "teacher"
        })
        if resp.status_code != 200:
            msg = f"FAILED Register Teacher: {resp.status_code} - {resp.text}"
            print(msg)
            with open("test_error.log", "w") as f: f.write(msg)
        assert resp.status_code == 200
        teacher_token = requests.post(f"{API_URL}/auth/token", data={"username": "teacher1", "password": "pass"}).json()["access_token"]
        
        # 3. Register Student
        print("[3] Registering Student...")
        resp = requests.post(f"{API_URL}/auth/register", json={
            "username": "student1", "email": "s@s.com", "password": "pass", "role": "student"
        })
        if resp.status_code != 200:
            msg = f"FAILED Register Student: {resp.status_code} - {resp.text}"
            print(msg)
            with open("test_error.log", "w") as f: f.write(msg)
        assert resp.status_code == 200
        student_token = requests.post(f"{API_URL}/auth/token", data={"username": "student1", "password": "pass"}).json()["access_token"]
        
        # 4. Create Exam Room
        print("[4] Creating Exam Room...")
        headers_t = {"Authorization": f"Bearer {teacher_token}"}
        resp = requests.post(f"{API_URL}/exams/create", headers=headers_t)
        assert resp.status_code == 200
        room_code = resp.json()["room_code"]
        print(f"    Room Code: {room_code}")
        
        # 5. Join Exam
        print("[5] Student Joining Exam...")
        headers_s = {"Authorization": f"Bearer {student_token}"}
        resp = requests.post(f"{API_URL}/exams/join/{room_code}", headers=headers_s)
        assert resp.status_code == 200
        session_id = resp.json()["session_id"]
        print(f"    Session ID: {session_id}")
        
        # 6. Initialize Monitor (Config Fetch)
        print("[6] Initializing Monitor...")
        # Monitor hits the API_URL
        monitor = ExamMonitor(API_URL, student_token, session_id)
        
        if len(monitor.encryption_key) == 64: # 32 bytes hex
             print("    Key fetched successfully.")
        else:
            raise Exception("Key fetch failed")
        
        # 7. Upload Logs
        print("[7] Uploading Logs...")
        monitor.logger.log("TEST", "Integration Test Log 1")
        monitor.logger.log("TEST", "Integration Test Log 2")
        monitor.upload_logs()
        
        # 8. Verify using API (We need an endpoint to view logs? Or we can just check directly via sqlite if we want)
        # But for full BLACK BOX test, we should use API.
        # But we don't have a "view logs" endpoint yet for teachers? 
        # Ah, we didn't implement it in this task.
        # So we have to check SQLite directly using python sqlite3 lib (no backend imports!)
        
        print("[8] Verifying in DB (Direct SQLite)...")
        import sqlite3
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        cursor.execute("SELECT content FROM log_entries WHERE session_id=?", (session_id,))
        rows = cursor.fetchall()
        conn.close()
        
        print(f"    Logs found: {len(rows)}")
        assert len(rows) >= 2
        assert rows[0][0] == "Integration Test Log 1"
        
        print(">>> SUCCESS: Full flow verified!")
        
    finally:
        print("Shutting down server...")
        server_process.terminate()
        server_process.wait()

if __name__ == "__main__":
    test_full_flow()

