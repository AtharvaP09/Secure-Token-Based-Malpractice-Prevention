from sqlalchemy import Column, Integer, String, Boolean, DateTime, ForeignKey, Text
from sqlalchemy.orm import relationship
from sqlalchemy.ext.declarative import declarative_base
import datetime

Base = declarative_base()

class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, unique=True, index=True)
    email = Column(String, unique=True, index=True)
    hashed_password = Column(String)
    role = Column(String) # "admin", "teacher", "student"
    is_active = Column(Boolean, default=True)

class ExamRoom(Base):
    __tablename__ = "exam_rooms"
    id = Column(Integer, primary_key=True, index=True)
    room_code = Column(String, unique=True, index=True)
    teacher_id = Column(Integer, ForeignKey("users.id"))
    created_at = Column(DateTime, default=datetime.datetime.utcnow)
    is_active = Column(Boolean, default=True)
    
    # New Fields
    password = Column(String, nullable=True)
    start_time = Column(DateTime, default=datetime.datetime.utcnow)
    duration_minutes = Column(Integer, default=60)
    
    teacher = relationship("User", back_populates="exams")
    sessions = relationship("ExamSession", back_populates="room", cascade="all, delete-orphan")

User.exams = relationship("ExamRoom", back_populates="teacher")

class ExamSession(Base):
    __tablename__ = "exam_sessions"
    id = Column(Integer, primary_key=True, index=True)
    student_id = Column(Integer, ForeignKey("users.id"))
    room_id = Column(Integer, ForeignKey("exam_rooms.id"))
    start_time = Column(DateTime, default=datetime.datetime.utcnow)
    end_time = Column(DateTime, nullable=True)
    ledger_file_path = Column(String, nullable=True)
    encryption_key = Column(String, nullable=True) # Hex encoded 32-byte key
    
    student = relationship("User")
    room = relationship("ExamRoom", back_populates="sessions")
    logs = relationship("LogEntry", back_populates="session", cascade="all, delete-orphan")

    @property
    def ledger_uploaded(self):
        return bool(self.ledger_file_path)

class LogEntry(Base):
    __tablename__ = "log_entries"
    id = Column(Integer, primary_key=True, index=True)
    session_id = Column(Integer, ForeignKey("exam_sessions.id"))
    timestamp = Column(DateTime, default=datetime.datetime.utcnow)
    log_type = Column(String) # "process", "url", "system", "alert"
    content = Column(Text)
    source = Column(String, default="realtime") # "realtime" or "ledger"
    is_suspicious = Column(Boolean, default=False)
    
    session = relationship("ExamSession", back_populates="logs")
