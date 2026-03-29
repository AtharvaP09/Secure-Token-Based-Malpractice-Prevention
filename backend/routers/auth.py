from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session
from fastapi.security import OAuth2PasswordRequestForm
from .. import database, schemas, models, auth
from ..auth import get_current_user

router = APIRouter(
    prefix="/auth",
    tags=["Authentication"]
)

@router.post("/register", response_model=schemas.UserResponse)
def register(user: schemas.UserCreate, db: Session = Depends(database.get_db)):
    db_user = db.query(models.User).filter(models.User.username == user.username).first()
    if db_user:
        raise HTTPException(status_code=400, detail="Username already registered")
    
    hashed_password = auth.get_password_hash(user.password)
    # Enforce student role by default (ignore user input for role)
    new_user = models.User(
        username=user.username,
        email=user.email,
        hashed_password=hashed_password,
        role="student"
    )
    db.add(new_user)
    db.commit()
    db.refresh(new_user)
    return new_user

@router.get("/admin/users", response_model=list[schemas.UserResponse])
def get_all_users(
    current_user: models.User = Depends(auth.get_current_user),
    db: Session = Depends(database.get_db)
):
    if current_user.role != "admin":
        raise HTTPException(status_code=403, detail="Admin privileges required")
    return db.query(models.User).all()

@router.put("/admin/users/{user_id}/role")
def update_user_role(
    user_id: int,
    role: str,
    current_user: models.User = Depends(auth.get_current_user),
    db: Session = Depends(database.get_db)
):
    if current_user.role != "admin":
        raise HTTPException(status_code=403, detail="Admin privileges required")
        
    if role not in ["student", "teacher", "admin"]:
        raise HTTPException(status_code=400, detail="Invalid role")

    user_to_update = db.query(models.User).filter(models.User.id == user_id).first()
    if not user_to_update:
        raise HTTPException(status_code=404, detail="User not found")
        
    user_to_update.role = role
    db.commit()
    return {"message": f"User role updated to {role}"}

@router.delete("/admin/users/{user_id}")
def delete_user(
    user_id: int,
    current_user: models.User = Depends(auth.get_current_user),
    db: Session = Depends(database.get_db)
):
    if current_user.role != "admin":
        raise HTTPException(status_code=403, detail="Admin privileges required")
        
    user = db.query(models.User).filter(models.User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
        
    if user.id == current_user.id:
        raise HTTPException(status_code=400, detail="Cannot delete your own admin account")

    # Delete all exam rooms created by this user (if teacher)
    # This should cascade to sessions and logs if models are configured with cascade="all, delete-orphan"
    # Checking models.py: 
    # ExamRoom.sessions = relationship(..., cascade="all, delete-orphan")
    # User.exams = relationship(...) -> NO CASCADE SPECIFIED on User.exams for delete?
    # Actually User.exams backref might not have cascade.
    # Let's manually delete to be safe and explicit.
    
    # 1. Delete associated exam rooms (as teacher)
    rooms = db.query(models.ExamRoom).filter(models.ExamRoom.teacher_id == user_id).all()
    for room in rooms:
        db.delete(room) # Sessions cascade from room
        
    # 2. Delete associated sessions (as student)
    sessions = db.query(models.ExamSession).filter(models.ExamSession.student_id == user_id).all()
    for session in sessions:
        db.delete(session) # Logs cascade from session
        
    db.delete(user)
    db.commit()
    return {"message": "User deleted successfully"}

@router.post("/token", response_model=schemas.Token)
def login_for_access_token(form_data: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(database.get_db)):
    user = db.query(models.User).filter(models.User.username == form_data.username).first()
    if not user or not auth.verify_password(form_data.password, user.hashed_password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    access_token = auth.create_access_token(
        data={"sub": user.username, "role": user.role}
    )
    return {"access_token": access_token, "token_type": "bearer"}

@router.post("/admin/users", response_model=schemas.UserResponse)
def create_user(
    user: schemas.UserCreate,
    current_user: models.User = Depends(auth.get_current_user),
    db: Session = Depends(database.get_db)
):
    if current_user.role != "admin":
        raise HTTPException(status_code=403, detail="Admin privileges required")
    
    db_user = db.query(models.User).filter(models.User.username == user.username).first()
    if db_user:
        raise HTTPException(status_code=400, detail="Username already registered")
    
    hashed_password = auth.get_password_hash(user.password)
    # Allow admin to set role directly from input
    new_user = models.User(
        username=user.username,
        email=user.email,
        hashed_password=hashed_password,
        role=user.role 
    )
    db.add(new_user)
    db.commit()
    db.refresh(new_user)
    return new_user

@router.get("/me", response_model=schemas.UserResponse)
def read_users_me(current_user: models.User = Depends(get_current_user)):
    return current_user
