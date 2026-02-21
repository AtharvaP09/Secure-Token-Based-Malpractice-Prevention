from pydantic import BaseModel, EmailStr
from typing import Optional, List
from datetime import datetime

class UserBase(BaseModel):
    username: str
    email: EmailStr
    role: str # "admin", "teacher", "student"

class UserCreate(UserBase):
    password: str

class UserResponse(UserBase):
    id: int
    is_active: bool

    class Config:
        from_attributes = True

class Token(BaseModel):
    access_token: str
    token_type: str

class TokenData(BaseModel):
    username: Optional[str] = None
    role: Optional[str] = None

class ExamRoomBase(BaseModel):
    room_code: str
    is_active: bool = True
    start_time: datetime
    duration_minutes: int

class ExamRoomCreate(BaseModel):
    password: str
    start_time: datetime
    duration_minutes: int

class ExamRoomResponse(ExamRoomBase):
    id: int
    teacher_id: int
    created_at: datetime
    student_count: Optional[int] = 0
    completed_count: Optional[int] = 0
    # We do NOT return the password in the response for security (unless specifically requested for teacher)
    # But for TeacherDashboard, they might want to see it? Let's hide it for now.

    class Config:
        from_attributes = True

class LogEntryCreate(BaseModel):
    log_type: str
    content: str
    timestamp: datetime
    is_suspicious: bool = False

class LogEntry(BaseModel):
    log_type: str
    content: str
    timestamp: datetime
    is_suspicious: bool = False

    class Config:
        from_attributes = True

class LogBatch(BaseModel):
    logs: List[LogEntry]

class ExamSessionResponse(BaseModel):
    id: int
    student: UserResponse
    start_time: datetime
    end_time: Optional[datetime] = None
    ledger_uploaded: bool = False
    # We can add derived fields later if needed
    
    class Config:
        from_attributes = True
