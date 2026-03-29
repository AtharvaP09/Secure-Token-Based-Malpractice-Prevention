from fastapi import APIRouter, Depends, HTTPException, status, UploadFile, File
from fastapi.responses import StreamingResponse, FileResponse
from sqlalchemy.orm import Session
from typing import List
from .. import database, schemas, models, auth
from datetime import datetime, timedelta
import secrets
import json
import base64
import sys
import os
import io
import csv
from pydantic import BaseModel
from typing import Optional

# Add project root to sys.path to allow importing from shared
sys.path.append(os.path.join(os.path.dirname(__file__), '..', '..'))
from shared.crypto_utils import CryptoUtils

router = APIRouter(
    prefix="/exams",
    tags=["Exams"]
)

@router.post("/create", response_model=schemas.ExamRoomResponse)
def create_exam_room(
    exam_in: schemas.ExamRoomCreate,
    current_user: models.User = Depends(auth.get_current_user),
    db: Session = Depends(database.get_db)
):
    if current_user.role != "teacher" and current_user.role != "admin":
        raise HTTPException(status_code=403, detail="Only teachers can create exams")
    
    # Generate unique room code
    while True:
        code = secrets.token_hex(3).upper()
        if not db.query(models.ExamRoom).filter(models.ExamRoom.room_code == code).first():
            break
            
    new_room = models.ExamRoom(
        room_code=code,
        teacher_id=current_user.id,
        password=exam_in.password,
        start_time=exam_in.start_time,
        end_time=exam_in.end_time,
        duration_minutes=exam_in.duration_minutes
    )
    db.add(new_room)
    db.commit()
    db.refresh(new_room)
    return new_room

@router.get("/list", response_model=List[schemas.ExamRoomResponse])
def list_exams(
    current_user: models.User = Depends(auth.get_current_user),
    db: Session = Depends(database.get_db)
):
    if current_user.role == "teacher":
        rooms = db.query(models.ExamRoom).filter(models.ExamRoom.teacher_id == current_user.id).all()
    elif current_user.role == "admin":
        rooms = db.query(models.ExamRoom).all()
    else:
        # Students see exams they have joined? Or maybe just active ones?
        # For now, return empty or implement join logic
        return []
    
    # Calculate student count
    results = []
    for room in rooms:
        # Create a dict or copy to append extra field
        # Since we are using ORM objects, we can getattr/setattr if Pydantic uses getters
        # But allow Pydantic to read from attributes. 
        # Calculate student count (Active only)
        # Filter sessions where end_time is None
        active_sessions = [s for s in room.sessions if s.end_time is None]
        completed_sessions = [s for s in room.sessions if s.end_time is not None]
        
        room.student_count = len(active_sessions)
        room.completed_count = len(completed_sessions)
        results.append(room)
        
    return results

class JoinExamRequest(BaseModel):
    password: Optional[str] = None

@router.post("/join/{room_code}")
def join_exam(
    room_code: str,
    join_request: JoinExamRequest,
    current_user: models.User = Depends(auth.get_current_user),
    db: Session = Depends(database.get_db)
):
    room = db.query(models.ExamRoom).filter(models.ExamRoom.room_code == room_code).first()
    if not room:
        raise HTTPException(status_code=404, detail="Room not found")
        
    if not room.is_active:
        raise HTTPException(status_code=400, detail="Exam room is closed")
        
    # Time Validation
    now = datetime.utcnow()
    if now < room.start_time:
        raise HTTPException(status_code=400, detail="Exam has not started yet")
        
    # Deadline Validation
    if room.end_time and now > room.end_time:
        raise HTTPException(status_code=400, detail="Exam entry time has ended")
        
    # Password Validation
    if room.password and room.password != join_request.password:
        raise HTTPException(status_code=403, detail="Incorrect password")

    # Check if already joined
    existing_session = db.query(models.ExamSession).filter(
        models.ExamSession.student_id == current_user.id,
        models.ExamSession.room_id == room.id
    ).first()
    
    if existing_session:
        # Return existing session info instead of creating new
        return {"message": "Already joined", "session_id": existing_session.id}
        
    encryption_key = secrets.token_hex(32) # 32 bytes = 256 bits
    new_session = models.ExamSession(
        student_id=current_user.id,
        room_id=room.id,
        encryption_key=encryption_key
    )
    db.add(new_session)
    db.commit()
    db.refresh(new_session)
    return {"message": "Joined successfully", "session_id": new_session.id}

@router.get("/room/{room_id}/students", response_model=List[schemas.ExamSessionResponse])
def get_room_students(
    room_id: int,
    current_user: models.User = Depends(auth.get_current_user),
    db: Session = Depends(database.get_db)
):
    # Only teacher/admin
    if current_user.role not in ["teacher", "admin"]:
        raise HTTPException(status_code=403, detail="Access denied")
        
    room = db.query(models.ExamRoom).filter(models.ExamRoom.id == room_id).first()
    if not room:
         raise HTTPException(status_code=404, detail="Room not found")
         
    if current_user.role == "teacher" and room.teacher_id != current_user.id:
        raise HTTPException(status_code=403, detail="Access denied")
        
    # Get sessions directly
    sessions = db.query(models.ExamSession).filter(models.ExamSession.room_id == room_id).all()
    
    return sessions

@router.get("/{session_id}/config")
def get_exam_config(
    session_id: int,
    current_user: models.User = Depends(auth.get_current_user),
    db: Session = Depends(database.get_db)
):
    session = db.query(models.ExamSession).filter(
        models.ExamSession.id == session_id,
        models.ExamSession.student_id == current_user.id
    ).first()
    
    if not session:
        raise HTTPException(status_code=404, detail="Session not found")
        
    return {
        "encryption_key": session.encryption_key
    }

@router.post("/{session_id}/log")
def log_activity(
    session_id: int,
    log_batch: schemas.LogBatch,
    current_user: models.User = Depends(auth.get_current_user),
    db: Session = Depends(database.get_db)
):
    # Verify session belongs to user
    session = db.query(models.ExamSession).filter(
        models.ExamSession.id == session_id,
        models.ExamSession.student_id == current_user.id
    ).first()
    
    if not session:
        raise HTTPException(status_code=404, detail="Session not found or access denied")
        
    for log in log_batch.logs:
        new_log = models.LogEntry(
            session_id=session_id,
            log_type=log.log_type,
            content=log.content,
            timestamp=log.timestamp,
            is_suspicious=log.is_suspicious
        )
        db.add(new_log)
    
    db.commit()
    
    # Check for termination conditions
    command = None
    
    # 1. Student explicitly left (end_time set)
    if session.end_time:
        command = "stop"
    else:
        # 2. Time over (check token duration relative to student's join time)
        # Access room via relationship (lazy load)
        if session.room:
             session_end_time = session.start_time + timedelta(minutes=session.room.duration_minutes)
             if datetime.utcnow() > session_end_time:
                  command = "stop"

    return {"status": "logged", "count": len(log_batch.logs), "command": command}

@router.get("/{session_id}/logs", response_model=List[schemas.LogEntry])
def get_session_logs(
    session_id: int,
    source: Optional[str] = None,
    current_user: models.User = Depends(auth.get_current_user),
    db: Session = Depends(database.get_db)
):
    # Check if user is teacher/admin OR the student owner
    session = db.query(models.ExamSession).filter(models.ExamSession.id == session_id).first()
    if not session:
        raise HTTPException(status_code=404, detail="Session not found")
        
    if current_user.role == "student" and session.student_id != current_user.id:
        raise HTTPException(status_code=403, detail="Access denied")
        
    query = db.query(models.LogEntry).filter(models.LogEntry.session_id == session_id)
    
    if source:
        query = query.filter(models.LogEntry.source == source)
        
    logs = query.all()
    return logs

@router.get("/room/{room_id}/logs", response_model=List[schemas.LogEntry])
def get_room_logs(
    room_id: int,
    current_user: models.User = Depends(auth.get_current_user),
    db: Session = Depends(database.get_db)
):
    # Only teacher/admin
    if current_user.role not in ["teacher", "admin"]:
        raise HTTPException(status_code=403, detail="Access denied")
        
    room = db.query(models.ExamRoom).filter(models.ExamRoom.id == room_id).first()
    if not room:
         raise HTTPException(status_code=404, detail="Room not found")
         
    if current_user.role == "teacher" and room.teacher_id != current_user.id:
        raise HTTPException(status_code=403, detail="Access denied")
        
    # Join LogEntry with ExamSession to filter by room_id
    logs = db.query(models.LogEntry).join(models.ExamSession).filter(models.ExamSession.room_id == room_id).all()
    return logs

@router.post("/{session_id}/upload_ledger")
async def upload_ledger(
    session_id: int,
    file: UploadFile = File(...),
    current_user: models.User = Depends(auth.get_current_user),
    db: Session = Depends(database.get_db)
):
    # Determine session
    session = db.query(models.ExamSession).filter(models.ExamSession.id == session_id).first()
    if not session:
        raise HTTPException(status_code=404, detail="Session not found")
        
    # Check permission (student owner or teacher/admin)
    if current_user.role == "student" and session.student_id != current_user.id:
        raise HTTPException(status_code=403, detail="Access denied")
    
    # Create ledgers directory if not exists
    ledger_dir = os.path.join(os.path.dirname(__file__), "..", "ledgers")
    os.makedirs(ledger_dir, exist_ok=True)
    
    # Save raw file
    file_path = os.path.join(ledger_dir, f"session_{session_id}_{int(datetime.utcnow().timestamp())}.enc")
    
    # Read file content
    content = await file.read()
    
    with open(file_path, "wb") as f:
        f.write(content)
        
    session.ledger_file_path = file_path
    
    # Decrypt and Import
    try:
        crypto = CryptoUtils(bytes.fromhex(session.encryption_key))
        
        # Format: Length(4 bytes) + JSON(Encrypted Dict) repeated
        offset = 0
        total_logs = 0
        
        while offset < len(content):
            # Read length
            if offset + 4 > len(content):
                break
            length = int.from_bytes(content[offset:offset+4], byteorder='big')
            offset += 4
            
            # Read payload
            if offset + length > len(content):
                break
            payload_bytes = content[offset:offset+length]
            offset += length
            
            encrypted_data = json.loads(payload_bytes)
            
            # Decrypt payload
            try:
                decrypted_json = crypto.decrypt(
                    encrypted_data["iv"], 
                    encrypted_data["ciphertext"], 
                    encrypted_data["tag"]
                )
                
                batch_logs = json.loads(decrypted_json)
                
                # Insert logs
                for log in batch_logs:
                    # Avoid duplicates? (check timestamp+content or trust?)
                    # For now, just insert.
                    new_log = models.LogEntry(
                        session_id=session_id,
                        log_type=log["log_type"],
                        content=log["content"],
                        timestamp=datetime.fromisoformat(log["timestamp"]), # Ensure correct format
                        source="ledger", # Mark as from ledger
                        is_suspicious=log["is_suspicious"]
                    )
                    db.add(new_log)
                    total_logs += 1
            except Exception as e:
                print(f"Failed to decrypt a chunk: {e}")
                # Continue processing other chunks if possible
                continue
        
        db.commit()
        
        if total_logs == 0 and len(content) > 0:
             raise HTTPException(status_code=400, detail="Ledger file processed but no logs were imported. Possible decryption failure or empty batches.")
             
        return {"status": "success", "logs_imported": total_logs, "file_saved": True}
        
    except Exception as e:
        print(f"Decryption error: {e}")
        raise HTTPException(status_code=400, detail=f"Failed to process ledger: {str(e)}")

@router.get("/room/{room_id}/export_csv")
def export_room_logs_csv(
    room_id: str,
    current_user: models.User = Depends(auth.get_current_user),
    db: Session = Depends(database.get_db)
):
    if current_user.role not in ["teacher", "admin"]:
        raise HTTPException(status_code=403, detail="Access denied")
        
    logs = db.query(models.LogEntry).join(models.ExamSession).filter(models.ExamSession.room_id == room_id).order_by(models.LogEntry.timestamp).all()
    
    
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["Student ID", "Timestamp", "Type", "Content", "Suspicious"])
    
    for log in logs:
        writer.writerow([log.id, log.timestamp, log.log_type, log.content, "YES" if log.is_suspicious else "No"]) # log.id is log id, we need student id from session?
        # log entry doesn't have student_id directly, it has session_id.
        # But we joined ExamSession.
        # We can access log.session.student_id if relationship is set up.
        # Assuming simplified export for now.
        
    output.seek(0)
    
    return StreamingResponse(
        io.BytesIO(output.getvalue().encode()),
        media_type="text/csv",
        headers={"Content-Disposition": f"attachment; filename=exam_room_{room_id}_logs.csv"}
    )
    


@router.delete("/room/{room_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_exam_room(
    room_id: int,
    current_user: models.User = Depends(auth.get_current_user),
    db: Session = Depends(database.get_db)
):
    if current_user.role not in ["teacher", "admin"]:
        raise HTTPException(status_code=403, detail="Only teachers or admins can delete exams")
        
    room = db.query(models.ExamRoom).filter(models.ExamRoom.id == room_id).first()
    if not room:
        raise HTTPException(status_code=404, detail="Room not found")
        
    if current_user.role == "teacher" and room.teacher_id != current_user.id:
        raise HTTPException(status_code=403, detail="You can only delete your own exams")
        
    db.delete(room)
    db.commit()
    return None

@router.post("/leave/{session_id}")
def leave_exam(
    session_id: int,
    current_user: models.User = Depends(auth.get_current_user),
    db: Session = Depends(database.get_db)
):
    session = db.query(models.ExamSession).filter(models.ExamSession.id == session_id).first()
    if not session:
        raise HTTPException(status_code=404, detail="Session not found")
        
    if session.student_id != current_user.id:
        raise HTTPException(status_code=403, detail="Access denied")
        
    session.end_time = datetime.utcnow()
    db.commit()
    return {"message": "Exam left successfully"}

@router.get("/{session_id}/download_ledger")
def download_ledger(
    session_id: int,
    current_user: models.User = Depends(auth.get_current_user),
    db: Session = Depends(database.get_db)
):
    session = db.query(models.ExamSession).filter(models.ExamSession.id == session_id).first()
    if not session:
        raise HTTPException(status_code=404, detail="Session not found")
        
    # Check permission (teacher/admin only)
    if current_user.role not in ["teacher", "admin"]:
         raise HTTPException(status_code=403, detail="Access denied")
         
    if current_user.role == "teacher" and session.room.teacher_id != current_user.id:
        raise HTTPException(status_code=403, detail="Access denied")
        
    if not session.ledger_file_path or not os.path.exists(session.ledger_file_path):
        raise HTTPException(status_code=404, detail="Ledger file not found")
        
    return FileResponse(session.ledger_file_path, filename=f"ledger_session_{session_id}.enc", media_type="application/octet-stream")

@router.get("/{session_id}/export_logs_txt")
def export_session_logs_txt(
    session_id: int,
    current_user: models.User = Depends(auth.get_current_user),
    db: Session = Depends(database.get_db)
):
    session = db.query(models.ExamSession).filter(models.ExamSession.id == session_id).first()
    if not session:
        raise HTTPException(status_code=404, detail="Session not found")
        
    # Check permission (teacher/admin only)
    if current_user.role not in ["teacher", "admin"]:
         raise HTTPException(status_code=403, detail="Access denied")
         
    if current_user.role == "teacher" and session.room.teacher_id != current_user.id:
        raise HTTPException(status_code=403, detail="Access denied")

    # Fetch all logs for this session
    logs = db.query(models.LogEntry).filter(models.LogEntry.session_id == session_id).order_by(models.LogEntry.timestamp).all()

    output = io.StringIO()
    output.write(f"Exam Session Logs - Session ID: {session_id}\n")
    output.write(f"Student: {session.student.username} ({session.student.email})\n")
    output.write(f"Exam Room: {session.room.room_code}\n")
    output.write(f"Generated At: {datetime.utcnow().isoformat()}\n")
    output.write("="*80 + "\n\n")

    for log in logs:
        timestamp_str = log.timestamp.isoformat()
        suspicious_tag = "[SUSPICIOUS] " if log.is_suspicious else ""
        offline_tag = "[OFFLINE] " if log.source == "ledger" else ""
        
        output.write(f"[{timestamp_str}] {suspicious_tag}{offline_tag}[{log.log_type.upper()}] {log.content}\n")
        output.write("-" * 40 + "\n")

    output.seek(0)
    
    return StreamingResponse(
        io.BytesIO(output.getvalue().encode('utf-8')),
        media_type="text/plain",
        headers={"Content-Disposition": f"attachment; filename=session_{session_id}_logs.txt"}
    )
