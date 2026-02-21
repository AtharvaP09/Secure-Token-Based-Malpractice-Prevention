import sys
import os
import threading
import time
import requests
import uvicorn
from sqlalchemy.orm import Session

# Add project root to sys.path
sys.path.append(os.path.join(os.path.dirname(__file__), '..'))

from backend import models, database, auth
from backend.main import app
from scripts.test_ledger_upload import test_ledger_upload

# Setup Test Data
def setup_test_data():
    db = database.SessionLocal()
    try:
        # 1. Create Teacher
        teacher = db.query(models.User).filter(models.User.username == "test_teacher").first()
        if not teacher:
            teacher = models.User(
                username="test_teacher",
                email="teacher@test.com",
                hashed_password=auth.get_password_hash("password"),
                role="teacher"
            )
            db.add(teacher)
            db.commit()
            db.refresh(teacher)
            print(f"Created teacher: {teacher.id}")
        else:
            print(f"Teacher exists: {teacher.id}")

        # 2. Create Student
        student = db.query(models.User).filter(models.User.username == "test_student").first()
        if not student:
            student = models.User(
                username="test_student",
                email="student@test.com",
                hashed_password=auth.get_password_hash("password"),
                role="student"
            )
            db.add(student)
            db.commit()
            db.refresh(student)
            print(f"Created student: {student.id}")
        else:
            print(f"Student exists: {student.id}")
            
        # 3. Create Exam Room
        room = db.query(models.ExamRoom).filter(models.ExamRoom.room_code == "TEST01").first()
        if not room:
            room = models.ExamRoom(
                room_code="TEST01",
                teacher_id=teacher.id,
                duration_minutes=60
            )
            db.add(room)
            db.commit()
            db.refresh(room)
            print(f"Created room: {room.id}")
        else:
            print(f"Room exists: {room.id}")
            
        # 4. Create Session
        session = db.query(models.ExamSession).filter(
            models.ExamSession.student_id == student.id,
            models.ExamSession.room_id == room.id
        ).first()
        
        if not session:
            session = models.ExamSession(
                student_id=student.id,
                room_id=room.id,
                encryption_key="0"*64 # Mock hex key
            )
            db.add(session)
            db.commit()
            db.refresh(session)
            print(f"Created session: {session.id}")
        else:
            print(f"Session exists: {session.id}")
            
        # Generate Token for Student (Simulate Monitor)
        access_token = auth.create_access_token(data={"sub": student.username})
        
        return access_token, session.id, teacher.id
        
    finally:
        db.close()

def run_server():
    uvicorn.run(app, host="127.0.0.1", port=8000, log_level="warning")

if __name__ == "__main__":
    # Start Server in background
    print("Starting server...")
    server_thread = threading.Thread(target=run_server, daemon=True)
    server_thread.start()
    time.sleep(5) # Wait for server startup
    
    print("Setting up test data...")
    token, session_id, teacher_id = setup_test_data()
    
    print(f"Ready to test. Token: {token[:10]}... Session: {session_id}")
    
    # Run Verification
    success = test_ledger_upload(token, session_id)
    
    if success:
        print("\n✅ VERIFICATION PASSED: Ledger upload and viewing works!")
        sys.exit(0)
    else:
        print("\n❌ VERIFICATION FAILED.")
        sys.exit(1)
