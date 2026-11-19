import os
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

# ------------------------------------------------------------------
# Database URL resolution
# ------------------------------------------------------------------
# In production (Render / any cloud), set the DATABASE_URL environment
# variable to your PostgreSQL connection string, e.g.:
#   postgresql://user:password@host/dbname
#
# Locally it falls back to SQLite (no extra setup needed).
# ------------------------------------------------------------------
DATABASE_URL = os.environ.get("DATABASE_URL", "sqlite:///./exam_monitor_v2.db")

# Neon / Supabase / Railway give URLs starting with "postgres://" —
# SQLAlchemy 1.4+ requires "postgresql://".
if DATABASE_URL.startswith("postgres://"):
    DATABASE_URL = DATABASE_URL.replace("postgres://", "postgresql://", 1)

# SQLite needs check_same_thread=False; PostgreSQL does not accept it.
connect_args = {"check_same_thread": False} if DATABASE_URL.startswith("sqlite") else {}

engine = create_engine(DATABASE_URL, connect_args=connect_args)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
