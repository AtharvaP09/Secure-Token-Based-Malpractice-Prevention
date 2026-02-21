from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from .database import engine
from .models import Base
from .routers import auth, exam

# Create tables
Base.metadata.create_all(bind=engine)

app = FastAPI(title="Secure Exam Monitor API")

# CORS Configuration
origins = [
    "http://localhost:5173",  # Vite default
    "http://127.0.0.1:5173",
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"], # Allow all origins for dev
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

from fastapi.staticfiles import StaticFiles
import os

app.include_router(auth.router)
app.include_router(exam.router)

# Ensure static directory exists
os.makedirs("backend/static", exist_ok=True)
app.mount("/static", StaticFiles(directory="backend/static"), name="static")

@app.on_event("startup")
def startup_event():
    # Seed Admin User
    from .database import SessionLocal
    from . import models, auth
    
    db = SessionLocal()
    try:
        admin = db.query(models.User).filter(models.User.username == "admin").first()
        if not admin:
            hashed_password = auth.get_password_hash("123456")
            admin_user = models.User(
                username="admin",
                email="admin@secure.exam",
                hashed_password=hashed_password,
                role="admin",
                is_active=True
            )
            db.add(admin_user)
            db.commit()
            print("Admin user created: admin / 123456")
    except Exception as e:
        print(f"Error seeding admin: {e}")
    finally:
        db.close()

@app.get("/")
def read_root():
    return {"message": "Secure Exam Monitor API is running"}
